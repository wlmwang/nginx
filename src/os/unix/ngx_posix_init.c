
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


ngx_int_t   ngx_ncpu;
ngx_int_t   ngx_max_sockets;
ngx_uint_t  ngx_inherited_nonblocking;
ngx_uint_t  ngx_tcp_nodelay_and_tcp_nopush;


struct rlimit  rlmt;


ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_udp_unix_recv,
    ngx_unix_send,
    ngx_writev_chain,
    0
};

/**
 *  @param [in] log 日志对象
 *  @return int NGX_OK|NGX_ERROR
 *  
 *  初始化系统相关变量，如内存页面大小ngx_pagesize,ngx_cacheline_size,最大连接数ngx_max_sockets等
 */
ngx_int_t
ngx_os_init(ngx_log_t *log)
{
    ngx_uint_t  n;

//OS特定的初始化
#if (NGX_HAVE_OS_SPECIFIC_INIT)
    if (ngx_os_specific_init(log) != NGX_OK) {  //初始化内核名称和其它信息，设置全局变量ngx_os_io
        return NGX_ERROR;
    }
#endif

    /**
     *  \file ngx_setproctitle.c
     *  计算**environ指针结尾地址到全局变量ngx_os_argv_last中
     */
    if (ngx_init_setproctitle(log) != NGX_OK) {
        return NGX_ERROR;
    }
    /**
     *  \file ngx_alloc.c
     *  \brief os页大小 x86为4096
     */
    ngx_pagesize = getpagesize();   //os页大小 x86为4096
    /**
     *  \file ngx_alloc.c
     *  \brief ngx缓存行尺寸的设置 #define NGX_CPU_CACHE_LINE 64  主要用于内存对齐
     */ 
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;

    //slab用到，计算要多少个数组 2^12=4096  ngx_pagesize_shift=12
    for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }

#if (NGX_HAVE_SC_NPROCESSORS_ONLN)
    if (ngx_ncpu == 0) {
        ngx_ncpu = sysconf(_SC_NPROCESSORS_ONLN);   //cpu实际个数，配置文件worker_processes
    }
#endif

    if (ngx_ncpu < 1) {
        ngx_ncpu = 1;
    }

    ngx_cpuinfo();  //调用汇编代码，获取cpu信息，主要设置ngx_cacheline_size的值

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {    //进程可打开最大文件描述符上限
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed");
        return NGX_ERROR;
    }

    ngx_max_sockets = (ngx_int_t) rlmt.rlim_cur;    //打开socket描述符最大数量

//socket继承设置开关
#if (NGX_HAVE_INHERITED_NONBLOCK || NGX_HAVE_ACCEPT4)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;
#endif

    srandom(ngx_time());    //设置random函数的种子

    return NGX_OK;
}

/**
 *  @param [in] log log对象
 *  @return void
 *  
 *  记录os状态日志，包括操作系统类型、版本
 */
void
ngx_os_status(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER_BUILD);

#ifdef NGX_COMPILER
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "built by " NGX_COMPILER);
#endif

#if (NGX_HAVE_OS_SPECIFIC_INIT)
    ngx_os_specific_status(log);
#endif

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %r:%r",
                  rlmt.rlim_cur, rlmt.rlim_max);
}


#if 0

ngx_int_t
ngx_posix_post_conf_init(ngx_log_t *log)
{
    ngx_fd_t  pp[2];

    if (pipe(pp) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "pipe() failed");
        return NGX_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, errno, "close() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

#endif
