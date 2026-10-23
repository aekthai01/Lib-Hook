#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include "osp_config.h"
/* This fixture exercises real symbol calls, but contains no APK/game code. */
size_t fixture_strlen(char *p){size_t(*volatile fn)(const char*)=strlen;return fn(p);}
char *fixture_strchr(char *p,int c){char*(*volatile fn)(const char*,int)=strchr;return fn(p,c);}
char *fixture_strstr(char *p,const char*q){char*(*volatile fn)(const char*,const char*)=strstr;return fn(p,q);}
const unsigned char *fixture_source_key(unsigned idx,size_t*n){if(idx>=sizeof(key_rules)/sizeof(key_rules[0]))return NULL;*n=key_rules[idx].size;return key_rules[idx].src;}
const unsigned char *fixture_target_key(unsigned idx,size_t*n){if(idx>=sizeof(key_rules)/sizeof(key_rules[0]))return NULL;*n=key_rules[idx].size;return key_rules[idx].dst;}
void *fixture_strlen_symbol(void){return (void*)strlen;}
