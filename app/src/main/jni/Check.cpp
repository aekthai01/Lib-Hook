// Check.cpp
#include "Check.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <signal.h>

static bool g_logEnabled = false;
#define LOG_TAG "CheckLib"
#define LOGI(fmt, ...) do { if (g_logEnabled) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##__VA_ARGS__); } while(0)
#define LOGE(fmt, ...) do { if (g_logEnabled) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__); } while(0)

static void die(const char* reason) {
    LOGE("!!! SECURITY VIOLATION: %s !!!", reason);
    kill(getpid(), SIGKILL);
    _exit(1);
}

static bool check_su_binaries() {
    const char* paths[] = {
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/vendor/bin/su", "/data/local/su", "/data/local/bin/su",
        "/data/local/xbin/su"
    };
    for (int i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        if (access(paths[i], F_OK) == 0) {
            LOGI("Found su: %s", paths[i]);
            return false;
        }
    }
    return true;
}

static bool check_magisk() {
    const char* paths[] = {
        "/sbin/magisk", "/data/adb/magisk", "/data/adb/modules"
    };
    for (int i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        if (access(paths[i], F_OK) == 0) {
            LOGI("Magisk artefact: %s", paths[i]);
            return false;
        }
    }
    return true;
}

static bool check_zygisk() {
    if (access("/data/adb/modules/zygisk", F_OK) == 0) {
        LOGI("Zygisk module found");
        return false;
    }
    return true;
}

static bool check_kernelsu() {
    if (access("/data/adb/ksud", F_OK) == 0) {
        LOGI("KernelSU detected");
        return false;
    }
    return true;
}

static bool check_busybox() {
    const char* paths[] = { "/system/xbin/busybox", "/system/bin/busybox" };
    for (int i = 0; i < 2; ++i) {
        if (access(paths[i], F_OK) == 0) {
            LOGI("Busybox found: %s", paths[i]);
            return false;
        }
    }
    return true;
}

static bool check_rw_system() {
    FILE* f = fopen("/proc/mounts", "r");
    if (!f) return true;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char mount_path[128], options[128];
        if (sscanf(line, "%*s %127s %*s %127s", mount_path, options) >= 2) {
            if (strcmp(mount_path, "/system") == 0 &&
                (strstr(options, "rw,") || strstr(options, ",rw"))) {
                LOGI("/system mounted read-write");
                fclose(f);
                return false;
            }
        }
    }
    fclose(f);
    return true;
}

static bool check_root_processes() {
    const char* keywords[] = { "su", "magisk", "daemonsu", "kernelsu" };
    for (int k = 0; k < 4; ++k) {
        for (int pid = 1; pid < 32768; ++pid) {
            char path[32];
            snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            char cmd[256] = {0};
            ssize_t n = read(fd, cmd, sizeof(cmd)-1);
            close(fd);
            if (n > 0 && strstr(cmd, keywords[k])) {
                LOGI("Root process: %s", cmd);
                return false;
            }
        }
    }
    return true;
}

static bool check_root_overall() {
    if (!check_su_binaries()) die("ROOT: su binary found");
    if (!check_magisk())       die("ROOT: Magisk detected");
    if (!check_zygisk())       die("ROOT: Zygisk found");
    if (!check_kernelsu())     die("ROOT: KernelSU found");
    if (!check_busybox())      die("ROOT: Busybox found");
    if (!check_rw_system())    die("ROOT: /system is writable");
    if (!check_root_processes()) die("ROOT: suspicious process");
    return true;
}

static bool check_frida_maps() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return true;
    char line[512];
    const char* kw[] = {
        "frida", "gum-js", "linjector", "agent", "gadget",
        "frida-agent", "frida-server", "re.frida.server"
    };
    while (fgets(line, sizeof(line), f)) {
        char path[256] = {0};
        sscanf(line, "%*lx-%*lx %*4s %*s %*s %*s %255s", path);
        for (int i = 0; i < 8; ++i) {
            if (strcasestr(path, kw[i])) {
                LOGI("Frida mapping: %s", path);
                fclose(f);
                return false;
            }
        }
     /*   uintptr_t s, e; char perms[8]; char p[256]={0};
        sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &s, &e, perms, p);
        if (p[0]==0 && strchr(perms,'w') && strchr(perms,'x')) {
            LOGI("Anonymous RWX at 0x%lx", s);
            fclose(f);
            return false;
        }
 */   }
    fclose(f);
    return true;
}

static bool check_frida_ports() {
    FILE* f = fopen("/proc/net/tcp", "r");
    if (!f) return true;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned int local_port;
        if (sscanf(line, "%*d: %*x:%x", &local_port) >= 1) {
            if (local_port == 0x6A7A || local_port == 0x6A7B) {
                LOGI("Frida port open: %x", local_port);
                fclose(f);
                return false;
            }
        }
    }
    fclose(f);
    return true;
}

static bool check_frida_fd() {
    DIR* d = opendir("/proc/self/fd");
    if (!d) return true;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0]=='.') continue;
        char linkpath[64], link[128];
        snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%s", e->d_name);
        ssize_t len = readlink(linkpath, link, sizeof(link)-1);
        if (len > 0) {
            link[len] = 0;
            if (strstr(link, "socket:[") &&
                (strstr(link, "27042") || strstr(link, "27043"))) {
                LOGI("Frida socket fd: %s", link);
                closedir(d);
                return false;
            }
        }
    }
    closedir(d);
    return true;
}

static bool check_frida_threads() {
    DIR* d = opendir("/proc/self/task");
    if (!d) return true;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0]=='.') continue;
        char commpath[64];
        snprintf(commpath, sizeof(commpath), "/proc/self/task/%s/comm", e->d_name);
        int fd = open(commpath, O_RDONLY);
        if (fd < 0) continue;
        char comm[64] = {0};
        read(fd, comm, sizeof(comm)-1);
        close(fd);
        size_t len = strlen(comm);
        if (len > 0 && comm[len-1]=='\n') comm[len-1]=0;
        if (strstr(comm, "gum-js") || strstr(comm, "frida") || strstr(comm, "gmain")) {
            LOGI("Suspicious thread: %s", comm);
            closedir(d);
            return false;
        }
    }
    closedir(d);
    return true;
}

static bool check_frida_overall() {
   /* if (!check_frida_maps())    die("FRIDA: mapping found");
    if (!check_frida_ports())   die("FRIDA: port open");
    if (!check_frida_fd())      die("FRIDA: socket fd");
    if (!check_frida_threads()) die("FRIDA: suspicious thread");
   */ return true;
}

static bool check_vpn_interfaces_native() {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) != 0) return true;
    const char* prefixes[] = {"tun", "ppp", "wg", "utun", "tap"};
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;
        for (int i = 0; i < 5; ++i) {
            if (strstr(ifa->ifa_name, prefixes[i])) {
                freeifaddrs(ifaddr);
                LOGI("VPN interface: %s", ifa->ifa_name);
                return false;
            }
        }
    }
    freeifaddrs(ifaddr);
    return true;
}

static bool check_vpn_routing_native() {
    FILE* f = fopen("/proc/net/route", "r");
    if (!f) return true;
    char line[256], iface[16];
    unsigned int dest;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%15s %x", iface, &dest) >= 2) {
            if (dest == 0 && strcmp(iface, "wlan0") && strcmp(iface, "rmnet_data") &&
                strcmp(iface, "rmnet_ipa") && strcmp(iface, "eth0")) {
                LOGI("Suspicious default route via %s", iface);
                fclose(f);
                return false;
            }
        }
    }
    fclose(f);
    return true;
}

static bool check_proxy_env() {
    const char* vars[] = {"http_proxy","HTTP_PROXY","https_proxy","HTTPS_PROXY","all_proxy","ALL_PROXY"};
    for (int i = 0; i < 6; ++i) {
        const char* val = getenv(vars[i]);
        if (val && val[0]) {
            LOGI("Proxy env %s=%s", vars[i], val);
            return false;
        }
    }
    return true;
}

static bool check_proxy_ports() {
    FILE* f = fopen("/proc/net/tcp", "r");
    if (!f) return true;
    char line[256];
    unsigned int ports[] = {0x0C38, 0x1F90, 0x0438, 0x1FB6}; 
    while (fgets(line, sizeof(line), f)) {
        unsigned int local_port;
        if (sscanf(line, "%*d: %*x:%x", &local_port) >= 1) {
            for (int i = 0; i < 4; ++i) {
                if (local_port == ports[i]) {
                    LOGI("Proxy port open: %u", ntohs(local_port));
                    fclose(f);
                    return false;
                }
            }
        }
    }
    fclose(f);
    return true;
}

    static jobject get_context_fallback(JNIEnv *env) {
        jclass activityThread = env->FindClass("android/app/ActivityThread");
        if (!activityThread) return nullptr;
        jmethodID currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
        jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
        if (!at) return nullptr;
        jmethodID getApplication = env->GetMethodID(activityThread, "getApplication", "()Landroid/app/Application;");
        jobject context = env->CallObjectMethod(at, getApplication);
        env->DeleteLocalRef(activityThread);
        env->DeleteLocalRef(at);
        return context;
    }



static bool check_vpn_java(JavaVM* vm) {
    if (!vm) return true;

    JNIEnv* env = nullptr;
    jint res = vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    bool attached = false;
    if (res != JNI_OK) {
        res = vm->AttachCurrentThread(&env, nullptr);
        if (res != JNI_OK) {
            LOGI("Cannot attach thread for VPN Java check");
            return true;
        }
        attached = true;
    }

    auto leave = [&](bool vpn) -> bool {
        if (attached) vm->DetachCurrentThread();
        return !vpn;   
    };
    jobject context = get_context_fallback(env);
    if (!context) return leave(false); 
    jclass ctxClass = env->FindClass("android/content/Context");
    if (!ctxClass) return leave(false);   
    jclass connClass = env->FindClass("android/net/ConnectivityManager");
    if (!connClass) return leave(false);
    jclass capClass = env->FindClass("android/net/NetworkCapabilities");
    if (!capClass) return leave(false);

    

    jmethodID getSystemService = env->GetMethodID(ctxClass, "getSystemService",
                                                  "(Ljava/lang/String;)Ljava/lang/Object;");
    jstring connStr = env->NewStringUTF("connectivity");
    jobject connService = env->CallObjectMethod(context, getSystemService, connStr);
    env->DeleteLocalRef(connStr);
    if (!connService) return leave(false);

    jmethodID getActiveNetwork = env->GetMethodID(connClass, "getActiveNetwork",
                                                  "()Landroid/net/Network;");
    jobject activeNetwork = env->CallObjectMethod(connService, getActiveNetwork);
    if (!activeNetwork) return leave(true);   // no active network → not VPN

    jmethodID getCaps = env->GetMethodID(connClass, "getNetworkCapabilities",
                                         "(Landroid/net/Network;)Landroid/net/NetworkCapabilities;");
    jobject capabilities = env->CallObjectMethod(connService, getCaps, activeNetwork);
    if (!capabilities) return leave(false);

    jmethodID hasTransport = env->GetMethodID(capClass, "hasTransport", "(I)Z");
    jboolean vpnTransport = env->CallBooleanMethod(capabilities, hasTransport, 4); 

    env->DeleteLocalRef(capabilities);
    env->DeleteLocalRef(activeNetwork);
    env->DeleteLocalRef(connService);

    return leave(vpnTransport == JNI_TRUE);
}

static bool check_vpn_proxy_overall(JavaVM* vm) {
if (!check_vpn_interfaces_native()) die("VPN: native interface found");
    if (!check_vpn_routing_native())    die("VPN: suspicious routing");
    if (!check_proxy_env())             die("PROXY: environment variable set");
    if (!check_proxy_ports())           die("PROXY: port open");
    if (!check_vpn_java(vm))            die("VPN: Android system reports VPN");
 return true;
}

static bool check_debugger_attached() {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        LOGI("ptrace(TRACEME) failed – debugger present");
        return false;
    }
    ptrace(PTRACE_DETACH, 0, 0, 0);
    return true;
}

static bool check_tracerpid() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return true;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line+10);
            if (pid != 0) {
                LOGI("TracerPid=%d", pid);
                fclose(f);
                return false;
            }
            break;
        }
    }
    fclose(f);
    return true;
}

static bool check_parent_zygote() {
    FILE* f = fopen("/proc/self/stat", "r");
    if (!f) return true;
    char comm[256];
    int ppid;
    if (fscanf(f, "%*d %255s %*c %d", comm, &ppid) >= 2) {
        char cmdpath[64];
        snprintf(cmdpath, sizeof(cmdpath), "/proc/%d/cmdline", ppid);
        int fd = open(cmdpath, O_RDONLY);
        if (fd >= 0) {
            char cmd[256]={0};
            read(fd, cmd, sizeof(cmd)-1);
            close(fd);
            if (!strstr(cmd, "zygote")) {
                LOGI("Parent not zygote: %s", cmd);
                fclose(f);
                return false;
            }
        }
    }
    fclose(f);
    return true;
}

static bool check_jdwp_port() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return true;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    for (int port = 8600; port <= 8700; ++port) {
        addr.sin_port = htons(port);
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            LOGI("JDWP debug port open: %d", port);
            close(sock);
            return false;
        }
    }
    close(sock);
    return true;
}

static bool check_gdbserver_port() {
    FILE* f = fopen("/proc/net/tcp", "r");
    if (!f) return true;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned int local_port;
        if (sscanf(line, "%*d: %*x:%x", &local_port) >= 1) {
            if (local_port == 0x13AF) { // 5039
                LOGI("gdbserver port open");
                fclose(f);
                return false;
            }
        }
    }
    fclose(f);
    return true;
}

static bool anti_dump() {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    return true;
}

static bool check_breakpoint_canary() {
    volatile const void* func = (void*)&check_breakpoint_canary;
    uint32_t first = *((volatile uint32_t*)func);
    if (first == 0xD4200000) {
        LOGI("Breakpoint on canary");
        return false;
    }
    return true;
}

static bool check_anti_debug_overall() {
  /*  if (!check_debugger_attached()) die("DEBUG: ptrace failed");
    if (!check_tracerpid())         die("DEBUG: TracerPid non‑zero");
    if (!check_parent_zygote())     die("DEBUG: parent not zygote");
   if (!check_jdwp_port())         die("DEBUG: JDWP port open");
    if (!check_gdbserver_port())    die("DEBUG: gdbserver port");
   if (!anti_dump())               die("DUMP: prctl failed");
   if (!check_breakpoint_canary()) die("DEBUG: breakpoint inserted");
    */return true;
}

namespace Check {

extern JavaVM* g_vm;
void InitLogging() {
    char prop[PROP_VALUE_MAX];
    __system_property_get("persist.check.log", prop);
    g_logEnabled = (prop[0] == '1');
}
    static void* SecurityWatcherLoop(void* arg) {
        JavaVM* vm = (JavaVM*)arg;
        
        int tick = 0; 
        
        while (true) {
            sleep(1); 
            tick++;

            check_vpn_proxy_overall(vm);   
            check_anti_debug_overall();    

            if (tick % 2 == 0) {
                check_frida_overall();         
            }

            if (tick % 3 == 0) {
                check_root_overall();          
            }

            if (tick >= 60) {
                tick = 0;
            }
        }
        return nullptr;
    }

    void StartWatcher(JavaVM* vm) {
        pthread_t security_thread;
        int ret = pthread_create(&security_thread, nullptr, SecurityWatcherLoop, vm);
        if (ret == 0) {
            pthread_detach(security_thread);
            LOGI("[🛡️ SECURITY] Background watcher started (Staggered Mode).");
        } else {
            LOGE("[⚠️ SECURITY] Failed to start background watcher.");
        }
    }
    

bool RunAll(JavaVM* vm) {
    InitLogging();
    LOGI("Security checks starting (log=%d)", g_logEnabled);

  //  check_root_overall();          
  //  check_frida_overall();         
    check_vpn_proxy_overall(vm);   
  //  check_anti_debug_overall();    

    LOGI("All security checks passed.");
    return true;
}

} 
