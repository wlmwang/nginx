
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/**
 * ngx采用NGX_TIME_SLOTS(64)个时间片(数组)管理时间。其实就是time cache
 * 在锁(ngx_atomic_t)方面，考虑到现实应用读多写少，写时加锁，读不加锁。
 * 这使得非线程安全，采用时间片可很好实现以上要求，最大限度降低影响（尽量减少读访问冲突）
 */
#ifndef _NGX_TIMES_H_INCLUDED_
#define _NGX_TIMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * 每个时间片结构体
 */
typedef struct {
    time_t      sec;
    ngx_uint_t  msec;
    //本地时间与UTC时间差值，分钟单位（时区，如中国为+480）
    ngx_int_t   gmtoff;	//时区
} ngx_time_t;


void ngx_time_init(void);
void ngx_time_update(void);
void ngx_time_sigsafe_update(void);
u_char *ngx_http_time(u_char *buf, time_t t);
u_char *ngx_http_cookie_time(u_char *buf, time_t t);
void ngx_gmtime(time_t t, ngx_tm_t *tp);

time_t ngx_next_time(time_t when);
#define ngx_next_time_n      "mktime()"

/**
 * 各个功能模块下当前时间片字符串形式
 * 其他模块会引用以下变量
 * volatile很重要：信号处理函数或多线程时刻都会变更这些全局变量
 */
extern volatile ngx_time_t  *ngx_cached_time;	//当前时间片指针

#define ngx_time()           ngx_cached_time->sec
#define ngx_timeofday()      (ngx_time_t *) ngx_cached_time

extern volatile ngx_str_t    ngx_cached_err_log_time;		//error log(本地时间)
extern volatile ngx_str_t    ngx_cached_http_time;			//http(UTC时间)
extern volatile ngx_str_t    ngx_cached_http_log_time;		//http log(本地时间)
extern volatile ngx_str_t    ngx_cached_http_log_iso8601;
extern volatile ngx_str_t    ngx_cached_syslog_time;		//sys log(本地时间)

/*
 * milliseconds elapsed since epoch and truncated to ngx_msec_t,
 * used in event timers
 */
extern volatile ngx_msec_t  ngx_current_msec;		//如Igor所说^^（时间戳的毫秒表示）


#endif /* _NGX_TIMES_H_INCLUDED_ */
