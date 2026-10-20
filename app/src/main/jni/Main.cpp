#include <jni.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <link.h>
#include <sys/mman.h>
#include <android/log.h>
#include <atomic>
#include <map>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <exception>
#include <stdexcept>
#include <unordered_set>

#include "dobby.h"
#include "Check.h"
#define TAG "CHU"
#define LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO, TAG, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN, TAG, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, TAG, fmt, ##__VA_ARGS__)

/* ═══════════════════════════════════════════════════════════
   CONFIG – hook เฉพาะเป้าหมาย + หน่วงเวลา 20 วินาที
   ═══════════════════════════════════════════════════════════ */

static const char *TARGET_PATHS[] = {
    "/api/client/login",
    "/api/client/heartbeat",
    "/api/lib/",
    NULL
};
//POST
//https://zxx.spwz.online/connect/api-rov
#define TARGET_HOST     "zxx.alwaysdata.net"
#define TARGET_PATH     "/api/client/login"

#define TARGET_URL1     "https://zxx.spwz.online/connect"
#define TARGET_URL2     "https://zxx.alwaysdata.net/connect"
#define CURLOPT_URL     10002

static const char *WHITELIST[] = {
    "google.com", "googleapis.com", "gstatic.com", "ggpht.com", "youtube.com",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "unity3d.com", "apple.com", "icloud.com", "microsoft.com", "live.com",
    "twitter.com", "twimg.com", "tiktok.com", "byteoversea.com",
    "gcloud.com", "tencent.com", "qq.com", "firebase",
    "alwaysdata.net", "spwz.online",
    NULL
};

static const char *EXCLUDED_LIBS[] = {
    "libPixFFmpeg.so", "libanogs.so", "libPxKit3.so", "libgcloud.so",
    "libunity.so", "libAkSoundEngine.so", "libMSDKPIXCore.so", "libGCloudVoice.so",
    "libgame-BPM-GooglePlay-Gold-Release-Module-3902.so", "libanybrainSDK.so",
    NULL
};

JavaVM *g_vm = NULL;

// URL rotation
static char g_url1_buf[256] = TARGET_URL1;
static char g_url2_buf[256] = TARGET_URL2;
static char* g_current_url = g_url1_buf;
static int g_url_index = 0;
static std::atomic<int> g_rotation_counter{0};

static void rotate_url(void) {
    g_url_index ^= 1;
    g_current_url = (g_url_index == 0) ? g_url1_buf : g_url2_buf;
    LOGI("[URL] 🔄 Rotated to: %s", g_current_url);
    g_rotation_counter++;
}

// Whitelist logic
static bool is_whitelisted(const char* host) {
    if (!host) return false;
    for (int i = 0; WHITELIST[i]; i++) {
        if (strstr(host, WHITELIST[i])) return true;
    }
    return false;
}

static bool contains_target_path(const char* url_or_path) {
    if (!url_or_path) return false;
    for (int i = 0; TARGET_PATHS[i]; i++) {
        if (strstr(url_or_path, TARGET_PATHS[i])) return true;
    }
    return false;
}

// 🔥 FLAG ควบคุม – เริ่มเป็น false → หลัง 20 วิจะเป็น true
static std::atomic<bool> g_hooks_enabled{false};

// ฟังก์ชันเดิม
static int (*orig_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = nullptr;

typedef int (*SSL_set_tlsext_host_name_t)(void*, const char*);
typedef int (*SSL_write_t)(void*, const void*, int);

static SSL_set_tlsext_host_name_t orig_SSL_set_tlsext_host_name = nullptr;
static SSL_write_t                orig_SSL_write                = nullptr;

typedef void CURL; typedef long CURLoption; typedef int CURLcode;
static CURLcode (*orig_curl_easy_setopt)(CURL*, CURLoption, ...) = nullptr;

static std::atomic<int> g_hooks_done{0};

static int is_numeric_ip(const char *s) {
    struct in_addr addr; struct in6_addr addr6;
    return inet_pton(AF_INET, s, &addr) == 1 || inet_pton(AF_INET6, s, &addr6) == 1;
}

// ==================== HOOK FUNCTIONS ====================
static int my_getaddrinfo(const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res) {
    if (!g_hooks_enabled.load(std::memory_order_acquire))
        return orig_getaddrinfo(node, service, hints, res);

    if (!node || is_numeric_ip(node))
        return orig_getaddrinfo(node, service, hints, res);

    if (!strstr(node, "cry4me"))
        return orig_getaddrinfo(node, service, hints, res);

    LOGI("[DNS] 🎯 Hijacking %s -> %s", node, TARGET_HOST);
    return orig_getaddrinfo(TARGET_HOST, service, hints, res);
}

static int my_SSL_set_tlsext_host_name(void *ssl, const char *name) {
    if (!g_hooks_enabled.load(std::memory_order_acquire))
        return orig_SSL_set_tlsext_host_name(ssl, name);

    if (!name)
        return orig_SSL_set_tlsext_host_name(ssl, name);

    bool should_hijack = false;
    if (strstr(name, "cry4me")) {
        should_hijack = true;
    }

    if (should_hijack) {
        LOGI("[SNI] 🎯 Hijacking TLS SNI %s -> %s", name, TARGET_HOST);
        return orig_SSL_set_tlsext_host_name(ssl, TARGET_HOST);
    }

    return orig_SSL_set_tlsext_host_name(ssl, name);
}

static int is_http_method(const char *b, int n) {
    if (n < 10) return 0;
    if (strncasecmp(b, "GET ", 4) == 0 || strncasecmp(b, "POST ", 5) == 0 ||
        strncasecmp(b, "PUT ", 4) == 0 || strncasecmp(b, "PATCH ", 6) == 0 ||
        strncasecmp(b, "DELETE ", 7) == 0 || strncasecmp(b, "HEAD ", 5) == 0)
        return 1;
    return 0;
}

static int my_SSL_write(void *ssl, const void *buf, int num) {
    return orig_SSL_write(ssl, buf, num);
}

static CURLcode my_curl_easy_setopt(CURL *curl, CURLoption option, void *arg) {
    if (!g_hooks_enabled.load(std::memory_order_acquire))
        return orig_curl_easy_setopt(curl, option, arg);

    if (option == CURLOPT_URL && arg) {
        const char *url = (const char*)arg;
        if (strstr(url, "cry4me.best")) {
            const char *p = strstr(url, "://");
            p = (p != nullptr) ? (p + 3) : url;
            const char *path = strchr(p, '/');
            if (path == nullptr) path = "/";
            static __thread char newurl[1024];
            snprintf(newurl, sizeof(newurl), "https://%s%s", TARGET_HOST, path);
            LOGI("[CURL] URL %s -> %s", url, newurl);
            return orig_curl_easy_setopt(curl, option, (void*)newurl);
        }
    }
    return orig_curl_easy_setopt(curl, option, arg);
}

// ==================== HOOK INSTALLATION ====================
static int hook_lib(void *handle, const char *path, uintptr_t base) {
    int success_count = 0;

    void *p_sni = dlsym(handle, "SSL_set_tlsext_host_name");
    void *p_write = dlsym(handle, "SSL_write");

    if (p_sni && !orig_SSL_set_tlsext_host_name) {
        if (DobbyHook(p_sni, (void*)my_SSL_set_tlsext_host_name,
                      (void**)&orig_SSL_set_tlsext_host_name) == 0) {
            LOGI("[HOOK] SSL_set_tlsext_host_name OK in %s", path);
            success_count++;
        } else {
            LOGE("[HOOK] FAILED SSL_set_tlsext_host_name in %s", path);
        }
    }
    if (p_write && !orig_SSL_write) {
        if (DobbyHook(p_write, (void*)my_SSL_write,
                      (void**)&orig_SSL_write) == 0) {
            LOGI("[HOOK] SSL_write OK in %s", path);
            success_count++;
        } else {
            LOGE("[HOOK] FAILED SSL_write in %s", path);
        }
    }

    void *p_setopt = dlsym(handle, "curl_easy_setopt");
    if (p_setopt && !orig_curl_easy_setopt) {
        if (DobbyHook(p_setopt, (void*)my_curl_easy_setopt,
                      (void**)&orig_curl_easy_setopt) == 0) {
            LOGI("[HOOK] curl_easy_setopt OK in %s", path);
            success_count++;
        } else {
            LOGE("[HOOK] FAILED curl_easy_setopt in %s", path);
        }
    }

    return (success_count > 0) ? 1 : 0;
}

static void scan_and_hook(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end, file_off = 0;
        char perms[5];
        char path[256] = {0};
        if (sscanf(line, "%lx-%lx %4s %lx %*s %*s %255s", &start, &end, perms, &file_off, path) < 4)
            continue;
        if (perms[0] != 'r' || perms[2] != 'x' || !strstr(path, ".so"))
            continue;

        int excluded = 0;
        for (int i = 0; EXCLUDED_LIBS[i]; i++) {
            if (strstr(path, EXCLUDED_LIBS[i])) {
                excluded = 1;
                break;
            }
        }
        if (excluded || strstr(path, "libdobby"))
            continue;

        void *handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
        if (!handle) continue;

        uintptr_t base = (start >= file_off) ? (start - file_off) : 0;
        if (hook_lib(handle, path, base))
            g_hooks_done.store(1, std::memory_order_release);

        dlclose(handle);
    }
    fclose(fp);
}

static void *ssl_watcher(void *arg) {
    (void)arg;
    for (int i = 0; i < 120; i++) {
        scan_and_hook();
        if (g_hooks_done.load())
            return nullptr;
        usleep(500000);
    }
    return nullptr;
}

// ⏳ หน่วงเวลา 20 วินาที (เพราะตรวจแค่ตอนเริ่ม)
static void *delayed_enable_hooks(void *arg) {
    LOGI("[DELAY] ⏳ รอ 20 วินาที (ช่วงที่แอปสแกน)...");
    sleep(5);
    pthread_t th;
    pthread_create(&th, nullptr, curl_hook_thread, nullptr);
    pthread_detach(th);

    g_hooks_enabled.store(true, std::memory_order_release);
    LOGI("[DELAY] ✅ Hook เปิดการทำงานแล้ว");
    return nullptr;
}

/* ═══════════════════════════════════════════════════════════
   ENTRY
   ═══════════════════════════════════════════════════════════ */
static void write_marker(const char *msg) {
    FILE *f = fopen("/sdcard/Download/hook_alive.txt", "a");
    if (!f) f = fopen("/data/local/tmp/hook_alive.txt", "a");
    if (f) { fprintf(f, "[%d] %s\n", getpid(), msg); fclose(f); }
}

/* ---- curl_easy_setopt hook by address (static curl inside libpd267) ---- */
static void *g_curl_setopt = nullptr;

static CURLcode my_curl_setopt_addr(void *curl, int option, void *arg) {
    typedef CURLcode (*fn_t)(void *, int, void *);
    fn_t orig = (fn_t)g_curl_setopt;

    if (option == 64) {                       // CURLOPT_SSL_VERIFYPEER
        LOGI("[CURL] force VERIFYPEER=0");
        return orig(curl, option, (void *)0L);
    }
    if (option == 81) {                       // CURLOPT_SSL_VERIFYHOST
        LOGI("[CURL] force VERIFYHOST=0");
        return orig(curl, option, (void *)0L);
    }
    if (option == 10002 && arg != nullptr) {  // CURLOPT_URL
        const char *url = (const char *)arg;
        if (strstr(url, "cry4me")) {
            const char *p = strstr(url, "://");
            p = (p != nullptr) ? (p + 3) : url;
            const char *path = strchr(p, '/');
            if (path == nullptr) path = "/";
            static __thread char nu[1024];
            snprintf(nu, sizeof(nu), "https://%s%s", TARGET_HOST, path);
            LOGI("[CURL] URL %s -> %s", url, nu);
            return orig(curl, option, (void *)nu);
        }
    }
    return orig(curl, option, arg);
}

static uintptr_t module_base(const char *needle) {
    struct Ctx { const char *n; uintptr_t base; };
    Ctx ctx{needle, 0};
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t, void *data) -> int {
        Ctx *c = (Ctx *)data;
        if (info->dlpi_name && strstr(info->dlpi_name, c->n)) {
            c->base = info->dlpi_addr;
            return 1;
        }
        return 0;
    }, &ctx);
    return ctx.base;
}

static void *curl_hook_thread(void *) {
    for (int i = 0; i < 900; ++i) {
        uintptr_t base = module_base("libpd267");
        if (base != 0) {
            void *target = (void *)(base + 0x620b71c);
            if (DobbyHook(target, (void *)my_curl_setopt_addr, &g_curl_setopt) == 0) {
                LOGI("[CURL] hooked curl_easy_setopt at %p (base %p)", target, (void *)base);
                write_marker("curl_easy_setopt hooked");
                return nullptr;
            }
            write_marker("DobbyHook(curl_easy_setopt) FAILED");
            return nullptr;
        }
        usleep(200 * 1000);
    }
    write_marker("libpd267 never appeared");
    return nullptr;
}

static void *curl_hook_thread(void *);

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_vm = vm;

    char buf[256];
    snprintf(buf, sizeof(buf), "JNI_OnLoad pid=%d", getpid());
    write_marker(buf);

    // 1) DNS: cry4me.best -> our host, at the moment any request is sent
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (libc) {
        void *p1 = dlsym(libc, "getaddrinfo");
        if (p1 && DobbyHook(p1, (void*)my_getaddrinfo, (void**)&orig_getaddrinfo) == 0) {
            LOGI("[INIT] getaddrinfo hooked");
            write_marker("getaddrinfo hooked");
        } else {
            write_marker("getaddrinfo hook FAILED");
        }
        dlclose(libc);
    }

    // 2) SNI (only if a shared libssl exposes it; the menu lib statically links openssl)
    void *ssl = dlopen("libssl.so", RTLD_NOW);
    if (ssl) {
        void *p = dlsym(ssl, "SSL_set_tlsext_host_name");
        if (p && !orig_SSL_set_tlsext_host_name &&
            DobbyHook(p, (void*)my_SSL_set_tlsext_host_name, (void**)&orig_SSL_set_tlsext_host_name) == 0) {
            LOGI("[INIT] SNI hooked");
            write_marker("SNI hooked");
        }
        dlclose(ssl);
    } else {
        write_marker("libssl.so not loadable (static openssl in menu lib)");
    }

    pthread_t th;
    pthread_create(&th, nullptr, curl_hook_thread, nullptr);
    pthread_detach(th);

    g_hooks_enabled.store(true, std::memory_order_release);
    write_marker("hooks armed");
    return JNI_VERSION_1_6;
}
