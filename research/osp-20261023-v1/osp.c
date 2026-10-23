#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <link.h>
#include "osp_config.h"
/* Experimental dependency interposer. No TLS override, code patch, signal handler,
 * memory-permission changes, file logging or external communication. */
static __thread int busy;
static size_t (*r_strlen)(const char*);
static char *(*r_strstr)(const char*,const char*);
static char *(*r_strchr)(const char*,int);
static int (*r_gai)(const char*,const char*,const struct addrinfo*,struct addrinfo**);
static struct hostent *(*r_ghbn)(const char*);
static int (*r_connect)(int,const struct sockaddr*,socklen_t);
static int (*r_logv)(int,const char*,const char*,va_list);
static int (*r_logw)(int,const char*,const char*);
static pthread_mutex_t edit_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned long counters[8];
enum { C_STRLEN,C_STRSTR,C_STRCHR,C_DNS,C_HOST,C_KEY,C_SKIP,C_OUTSIDE };
static void tick(unsigned i){__atomic_add_fetch(&counters[i],1,__ATOMIC_RELAXED);}
static size_t rawlen(const char*s){size_t n=0;while(s[n])++n;return n;}
static int equal(const void*a,const void*b,size_t n){const unsigned char*x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static int same(const char*a,const char*b){size_t n=rawlen(a);return n==rawlen(b)&&equal(a,b,n);}
static void copybytes(void*d,const void*s,size_t n){unsigned char*x=d;const unsigned char*y=s;for(size_t i=0;i<n;i++)x[i]=y[i];}
static void movebytes(char*d,const char*s,size_t n){if(d<s)for(size_t i=0;i<n;i++)d[i]=s[i];else while(n){--n;d[n]=s[n];}}
static int target_caller(void*ret){Dl_info i;if(!dladdr(ret,&i)||!i.dli_fname)return 0;const char*n=i.dli_fname,*b=n;for(;*n;n++)if(*n=='/')b=n+1;return same(b,OSP_MAIN_NAME)||same(b,"libosp_fixture.so");}
static int writable(const void*p,size_t n){
 uintptr_t a=(uintptr_t)p;if(!n||a>UINTPTR_MAX-n)return 0;
 FILE*f=fopen("/proc/self/maps","r");if(!f)return 0;
 char line[512],mode[5];unsigned long long lo,hi;int ok=0;
 while(fgets(line,sizeof(line),f))if(sscanf(line,"%llx-%llx %4s",&lo,&hi,mode)==3&&a>=lo&&a+n<=hi){ok=mode[0]=='r'&&mode[1]=='w';break;}
 fclose(f);return ok;
}
static const char*hosts[]={"panel.cry4me.best","ru.cry4me.best","eu.cry4me.best","cry4me.kir-in.com"};
/* Explicit-capacity transform: caller supplies ownership/capacity. Exact full keys;
 * URL replacement requires a hostname boundary; no substring rewrite of lookalikes. */
int osp_transform(char*p,size_t cap){
 if(!p||!cap||cap>8192)return -1;
 size_t n=0;while(n<cap&&p[n])n++;if(n==cap)return -2;
 int changed=0;
 pthread_mutex_lock(&edit_lock);
 for(size_t k=0;k<sizeof(key_rules)/sizeof(key_rules[0]);k++){
  const struct key_rule*r=&key_rules[k];
  if(n==r->size&&equal(p,r->src,n)){copybytes(p,r->dst,n);tick(C_KEY);changed=2;goto done;}
 }
 for(size_t k=0;k<sizeof(hosts)/sizeof(hosts[0]);k++){
  const char*old=hosts[k];size_t a=rawlen(old),b=rawlen(OSP_TARGET_HOST);
  size_t pos=0;
  if(n>=8&&equal(p,"https://",8))pos=8;
  if(n<pos+a||!equal(p+pos,old,a))continue;
  if(p[pos+a]&&p[pos+a]!='/'&&p[pos+a]!=':'&&p[pos+a]!='?'&&p[pos+a]!='#')continue;
  size_t next=n-a+b;if(next>=cap){tick(C_SKIP);changed=-3;goto done;}
  movebytes(p+pos+b,p+pos+a,n-pos-a+1);copybytes(p+pos,OSP_TARGET_HOST,b);tick(C_HOST);changed=1;goto done;
 }
 done:pthread_mutex_unlock(&edit_lock);return changed;
}
/* Automatic growth is restricted to verified 1.0.11 data slots, never to the
 * remainder of a heap mapping. Arbitrary writable strings use n+1 capacity. */
static size_t known_capacity(const char*p,size_t n){
 Dl_info i;if(dladdr(p,&i)&&i.dli_fname){const char*s=i.dli_fname,*b=s;for(;*s;s++)if(*s=='/')b=s+1;
  if(same(b,OSP_MAIN_NAME)){
   uintptr_t rel=(uintptr_t)p-(uintptr_t)i.dli_fbase;
   for(size_t k=0;k<sizeof(url_slots)/sizeof(url_slots[0]);k++)if(rel==url_slots[k].begin)return url_slots[k].size;
  }
 }return n+1;
}
static void attempt(const char*p,size_t n){
 if(!n||n>8191)return;
 /* Do not parse maps for every unrelated string. */
 int candidate=(n==392||n==398||n==451)&&(p[0]=='M'||p[0]=='-');
 if(p[0]=='h'||p[0]=='p'||p[0]=='r'||p[0]=='e'||p[0]=='c')candidate=1;
 if(!candidate)return;
 size_t cap=known_capacity(p,n);
 if(cap<n+1||!writable(p,cap)){tick(C_SKIP);return;}
 osp_transform((char*)p,cap);
}
static const char*maphost(const char*s){if(!s)return s;for(size_t i=0;i<sizeof(hosts)/sizeof(hosts[0]);i++)if(same(s,hosts[i])){tick(C_DNS);return OSP_TARGET_HOST;}return s;}
const char*osp_map_host(const char*s){return maphost(s);}
void osp_stats(unsigned long*out,size_t count){if(count>8)count=8;for(size_t i=0;i<count;i++)out[i]=__atomic_load_n(&counters[i],__ATOMIC_RELAXED);}
const char*osp_target_host(void){return OSP_TARGET_HOST;}
__attribute__((constructor)) static void setup(void){
 busy=1;r_strlen=dlsym(RTLD_NEXT,"strlen");r_strstr=dlsym(RTLD_NEXT,"strstr");r_strchr=dlsym(RTLD_NEXT,"strchr");r_gai=dlsym(RTLD_NEXT,"getaddrinfo");r_ghbn=dlsym(RTLD_NEXT,"gethostbyname");r_connect=dlsym(RTLD_NEXT,"connect");
 void*l=dlopen("liblog.so",RTLD_NOW|RTLD_LOCAL);if(l){r_logv=dlsym(l,"__android_log_vprint");r_logw=dlsym(l,"__android_log_write");}busy=0;
}
size_t strlen(const char*p){size_t n=r_strlen?r_strlen(p):rawlen(p);if(busy)return n;busy=1;tick(C_STRLEN);if(target_caller(__builtin_return_address(0))){attempt(p,n);n=r_strlen?r_strlen(p):rawlen(p);}else tick(C_OUTSIDE);busy=0;return n;}
char*strchr(const char*p,int c){if(!busy){busy=1;tick(C_STRCHR);if(target_caller(__builtin_return_address(0)))attempt(p,rawlen(p));busy=0;}if(r_strchr)return r_strchr(p,c);for(;;p++){if((unsigned char)*p==(unsigned char)c)return(char*)p;if(!*p)return NULL;}}
char*strstr(const char*p,const char*q){if(!busy){busy=1;tick(C_STRSTR);if(target_caller(__builtin_return_address(0)))attempt(p,rawlen(p));busy=0;}if(r_strstr)return r_strstr(p,q);size_t n=rawlen(q);if(!n)return(char*)p;for(;*p;p++){size_t j=0;while(j<n&&p[j]&&p[j]==q[j])j++;if(j==n)return(char*)p;}return NULL;}
int getaddrinfo(const char*h,const char*s,const struct addrinfo*i,struct addrinfo**r){if(!r_gai)return EAI_SYSTEM;if(busy)return r_gai(h,s,i,r);busy=1;const char*t=target_caller(__builtin_return_address(0))?maphost(h):h;busy=0;return r_gai(t,s,i,r);}
struct hostent*gethostbyname(const char*h){if(!r_ghbn)return NULL;if(busy)return r_ghbn(h);busy=1;const char*t=target_caller(__builtin_return_address(0))?maphost(h):h;busy=0;return r_ghbn(t);}
int connect(int fd,const struct sockaddr*a,socklen_t n){if(!r_connect){errno=ENOSYS;return -1;}return r_connect(fd,a,n);}
int __android_log_vprint(int p,const char*t,const char*f,va_list a){return r_logv?r_logv(p,t,f,a):0;}
int __android_log_print(int p,const char*t,const char*f,...){va_list a;va_start(a,f);int r=r_logv?r_logv(p,t,f,a):0;va_end(a);return r;}
int __android_log_write(int p,const char*t,const char*s){return r_logw?r_logw(p,t,s):0;}
