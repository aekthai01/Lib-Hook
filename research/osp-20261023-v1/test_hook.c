#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <dlfcn.h>
#include <pthread.h>
static unsigned pass,fail;
#define CHECK(x) do{if(x)pass++;else{fail++;printf("FAIL line %d: %s\n",__LINE__,#x);}}while(0)
static int(*transform)(char*,size_t);
static size_t(*fixture_len)(char*);
static char*(*fixture_chr)(char*,int);
static char*(*fixture_str)(char*,const char*);
static const unsigned char*(*source_key)(unsigned,size_t*);
static const unsigned char*(*target_key)(unsigned,size_t*);
static int thread_error;
static void*worker(void*x){(void)x;for(int n=0;n<100;n++){char b[600];size_t k;const unsigned char*p=source_key(n%6,&k);memcpy(b,p,k+1);fixture_len(b);const unsigned char*q=target_key(n%6,&k);if(memcmp(b,q,k+1))__atomic_add_fetch(&thread_error,1,__ATOMIC_RELAXED);}return NULL;}
int main(int argc,char**argv){
 if(argc!=3){fprintf(stderr,"usage: test_hook libosp.so libosp_fixture.so\n");return 2;}
 void*lib=dlopen(argv[1],RTLD_NOW|RTLD_GLOBAL);if(!lib){fprintf(stderr,"dlopen hook: %s\n",dlerror());return 2;}
 void*fix=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);if(!fix){fprintf(stderr,"dlopen fixture: %s\n",dlerror());return 2;}
 transform=dlsym(lib,"osp_transform");fixture_len=dlsym(fix,"fixture_strlen");fixture_chr=dlsym(fix,"fixture_strchr");fixture_str=dlsym(fix,"fixture_strstr");source_key=dlsym(fix,"fixture_source_key");target_key=dlsym(fix,"fixture_target_key");
 const char*(*maphost)(const char*)=dlsym(lib,"osp_map_host");void(*stats)(unsigned long*,size_t)=dlsym(lib,"osp_stats");void*(*which)(void)=dlsym(fix,"fixture_strlen_symbol");
 CHECK(transform&&fixture_len&&source_key&&maphost&&stats&&which);
 Dl_info di={0};CHECK(dladdr(which(),&di)&&di.dli_fname&&strstr(di.dli_fname,"libosp"));printf("fixture strlen resolved to: %s\n",di.dli_fname);
 const char*hosts[]={"panel.cry4me.best","ru.cry4me.best","eu.cry4me.best","cry4me.kir-in.com"};
 for(unsigned i=0;i<4;i++){
  char b[128];strcpy(b,hosts[i]);CHECK(transform(b,sizeof(b))==1);CHECK(strcmp(b,"zxx.alwaysdata.net")==0);CHECK(strcmp(maphost(hosts[i]),"zxx.alwaysdata.net")==0);
  snprintf(b,sizeof(b),"https://%s/api/client/login",hosts[i]);CHECK(transform(b,sizeof(b))==1);CHECK(strcmp(b,"https://zxx.alwaysdata.net/api/client/login")==0);
  snprintf(b,sizeof(b),"https://%s.evil.test/",hosts[i]);char old[128];strcpy(old,b);CHECK(transform(b,sizeof(b))==0);CHECK(strcmp(b,old)==0);
  strcpy(b,hosts[i]);strcpy(old,b);CHECK(transform(b,strlen(b)+1)==-3);CHECK(strcmp(b,old)==0);
 }
 CHECK(transform(NULL,40)==-1);char nozero[8];memset(nozero,'X',8);CHECK(transform(nozero,8)==-2);
 char fixed[64]="https://unrelated.example/a";CHECK(transform(fixed,sizeof(fixed))==0);
 for(unsigned i=0;i<6;i++){
  size_t n;const unsigned char*s=source_key(i,&n);const unsigned char*t=target_key(i,&n);char b[600];memcpy(b,s,n+1);CHECK(transform(b,sizeof(b))==2);CHECK(memcmp(b,t,n+1)==0);
  memcpy(b,s,n+1);CHECK(fixture_len(b)==n);CHECK(memcmp(b,t,n+1)==0);
  memcpy(b,s,n+1);b[n/2]^=1;char old[600];memcpy(old,b,n+1);fixture_len(b);CHECK(memcmp(b,old,n+1)==0);
  CHECK(fixture_len((char*)s)==n);CHECK(memcmp(s,source_key(i,&n),n+1)==0);
 }
 size_t n;const unsigned char*s=source_key(0,&n);const unsigned char*t=target_key(0,&n);char b[600];memcpy(b,s,n+1);fixture_chr(b,'I');CHECK(memcmp(b,t,n+1)==0);
 memcpy(b,s,n+1);fixture_str(b,"MIIB");CHECK(memcmp(b,t,n+1)==0);
 /* Outside the allowlisted calling module, automatic interception must not edit. */
 memcpy(b,s,n+1);size_t(*volatile plainlen)(const char*)=dlsym(lib,"strlen");CHECK(plainlen(b)==n);CHECK(memcmp(b,s,n+1)==0);
 pthread_t th[4];for(int i=0;i<4;i++)CHECK(pthread_create(&th[i],NULL,worker,NULL)==0);for(int i=0;i<4;i++)CHECK(pthread_join(th[i],NULL)==0);CHECK(thread_error==0);
 unsigned long c[8];stats(c,8);CHECK(c[0]>0&&c[1]>0&&c[2]>0&&c[3]>0&&c[4]>0&&c[5]>=400&&c[6]>0&&c[7]>0);
 printf("checks=%u passed=%u failed=%u\n",pass+fail,pass,fail);printf("counters strlen=%lu strstr=%lu strchr=%lu dns_map=%lu host=%lu key=%lu skip=%lu outside=%lu\n",c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7]);return fail?1:0;
}
