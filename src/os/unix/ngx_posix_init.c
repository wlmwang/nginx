
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

/**
 * 系统相关I/O
 */
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
 *  初始化系统相关变量
 *  如内存页面大小ngx_pagesize ngx_cacheline_size ngx_max_sockets等
 *  
 *  \file ngx_os.h 申明原型
 */
ngx_int_t
ngx_os_init(ngx_log_t *log)
{
    ngx_uint_t  n;

#if (NGX_HAVE_OS_SPECIFIC_INIT)
    /**
     *  \file ngx_linux_init.c
     *  OS指定的初始化：初始化内核名称和其它信息，设置全局变量ngx_os_io，后续用于I/O操作基础（包括网络I/O）
     */
    if (ngx_os_specific_init(log) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    /**
     *  \file ngx_setproctitle.h|c
     *  移动**environ到堆上，为设置进程标题做准备
     */
    if (ngx_init_setproctitle(log) != NGX_OK) {
        return NGX_ERROR;
    }
    /**
     *  \file ngx_alloc.h|c
     *  os页大小 x86为4096
     */
    ngx_pagesize = getpagesize();   //os页大小 x86为4096
    /**
     *  \file ../../../objs/ngx_auto_config.h
     *  #define NGX_CPU_CACHE_LINE 64  
     *  主要用于内存池对齐分配。即本机cpu的cache line为64，内存池起始地址也要是64的倍数
     */ 
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;

    //slab用到，计算要多少个cache line填满一页 2^12=4096  ngx_pagesize_shift=12
    for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }

#if (NGX_HAVE_SC_NPROCESSORS_ONLN)
    if (ngx_ncpu == 0) {
        ngx_ncpu = sysconf(_SC_NPROCESSORS_ONLN);   //cpu实际个数，配置文件worker_processes
    }
#endif

    if (ngx_ncpu < 1) {
        ngx_ncpu = 1;
    }
	
	/**
	 *  \file ../../core/cpuinfo.c
	 *  调用汇编代码，获取cpu信息，主要用于根据实际cpu信息设置ngx_cacheline_size的值
	 */
    ngx_cpuinfo();

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {    //进程可打开最大文件描述符上限
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed");
        return NGX_ERROR;
    }

    ngx_max_sockets = (ngx_int_t) rlmt.rlim_cur;    //打开socket描述符最大数量

//socket是否可阻塞设置开关
#if (NGX_HAVE_INHERITED_NONBLOCK || NGX_HAVE_ACCEPT4)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;  //TODO 我的系统为0？
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
    /**
     * \file ngx_linux_init.c
     * 记录操作系统类型、版本
     */
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
