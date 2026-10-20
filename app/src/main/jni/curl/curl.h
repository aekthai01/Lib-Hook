#ifndef CURL_CURL_H
#define CURL_CURL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>

typedef void CURL;

typedef int CURLcode;
typedef int CURLoption;
typedef int CURLINFO;
typedef int CURLM;
typedef int CURLMcode;
typedef int CURLSH;
typedef int CURLSHcode;

#define CURLE_OK                           0
#define CURLE_UNSUPPORTED_PROTOCOL         1
#define CURLE_FAILED_INIT                  2
#define CURLE_URL_MALFORMAT                3
#define CURLE_COULDNT_RESOLVE_HOST         6
#define CURLE_COULDNT_CONNECT              7
#define CURLE_REMOTE_ACCESS_DENIED         9
#define CURLE_OUT_OF_MEMORY               27
#define CURLE_OPERATION_TIMEDOUT          28
#define CURLE_SSL_CONNECT_ERROR           35
#define CURLE_PEER_FAILED_VERIFICATION    51
#define CURLE_GOT_NOTHING                 52
#define CURLE_SEND_ERROR                  55
#define CURLE_RECV_ERROR                  56

#define CURLOPT_WRITEDATA          10001
#define CURLOPT_URL                10002
#define CURLOPT_PORT               3
#define CURLOPT_PROXY              10004
#define CURLOPT_USERPWD            10005
#define CURLOPT_PROXYUSERPWD       10006
#define CURLOPT_RANGE              10007
#define CURLOPT_READDATA           10009
#define CURLOPT_ERRORBUFFER        10010
#define CURLOPT_WRITEFUNCTION      20011
#define CURLOPT_READFUNCTION       20012
#define CURLOPT_TIMEOUT            13
#define CURLOPT_INFILESIZE         14
#define CURLOPT_POSTFIELDS         10015
#define CURLOPT_REFERER            10016
#define CURLOPT_USERAGENT          10018
#define CURLOPT_HTTPHEADER         10023
#define CURLOPT_HTTPPOST           10024
#define CURLOPT_SSLCERT            10025
#define CURLOPT_KEYPASSWD          10026
#define CURLOPT_SSL_VERIFYPEER     64
#define CURLOPT_SSL_VERIFYHOST     81
#define CURLOPT_COOKIE             10022
#define CURLOPT_COOKIEFILE         10031
#define CURLOPT_COOKIEJAR          10082
#define CURLOPT_FOLLOWLOCATION     52
#define CURLOPT_POST               47
#define CURLOPT_GET                80
#define CURLOPT_HTTPGET            80
#define CURLOPT_UPLOAD             46
#define CURLOPT_CUSTOMREQUEST      10036
#define CURLOPT_CONNECTTIMEOUT     78
#define CURLOPT_ACCEPT_ENCODING    10102
#define CURLOPT_CAINFO             10065
#define CURLOPT_CAPATH             10097
#define CURLOPT_VERBOSE            41
#define CURLOPT_NOPROGRESS         43
#define CURLOPT_NOSIGNAL           99


#define CURLINFO_RESPONSE_CODE     0x200002
#define CURLINFO_HTTP_CODE         CURLINFO_RESPONSE_CODE
#define CURLINFO_EFFECTIVE_URL     0x100001
#define CURLINFO_TOTAL_TIME        0x300004
#define CURLINFO_NAMELOOKUP_TIME   0x300005
#define CURLINFO_CONNECT_TIME      0x300006


typedef size_t (*curl_write_callback)(
    char *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
);

typedef size_t (*curl_read_callback)(
    char *buffer,
    size_t size,
    size_t nitems,
    void *userdata
);


CURL* curl_easy_init(void);

CURLcode curl_easy_setopt(
    CURL *curl,
    CURLoption option,
    ...
);

CURLcode curl_easy_perform(
    CURL *curl
);

void curl_easy_cleanup(
    CURL *curl
);

CURLcode curl_easy_getinfo(
    CURL *curl,
    CURLINFO info,
    ...
);

const char* curl_easy_strerror(
    CURLcode errornum
);

void curl_global_init(
    long flags
);

void curl_global_cleanup(
    void
);


#define CURL_GLOBAL_SSL       (1<<0)
#define CURL_GLOBAL_WIN32     (1<<1)
#define CURL_GLOBAL_ALL       0xFFFFFFFF

#ifdef __cplusplus
}
#endif

#endif