
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONFIG_H_INCLUDED_
#define _NGX_CONFIG_H_INCLUDED_

/**
 * \file ../../objs/ngx_auto_headers.h
 * 系统环境检测，定义对应符号变量。
 * 用于判断是否能包含某个库。如：
 * NGX_HAVE_SYS_PRCTL_H
 * NGX_LINUX
 * ...
 */
#include <ngx_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (NGX_FREEBSD)
#include <ngx_freebsd_config.h>


#elif (NGX_LINUX)
/**
 * \file ../os/unix/ngx_linux_config.h
 * 一般Linux下的头文件。用于包含ngx所有标准头文件
 */
#include <ngx_linux_config.h>


#elif (NGX_SOLARIS)
#include <ngx_solaris_config.h>


#elif (NGX_DARWIN)
#include <ngx_darwin_config.h>


#elif (NGX_WIN32)
#include <ngx_win32_config.h>


#else /* POSIX */
#include <ngx_posix_config.h>

#endif

/**
 * tips:
 * socket每个套接口都有一个接收低潮限度和一个发送低潮限度
 * SO_RCVLOWAT接收低潮限度：对于TCP套接口而言，接收缓冲区中的数据必须达到规定数量，内核才通知进程"可读"。比如触发select或者epoll，返回"套接口可读"(默认为1字节)
 * SO_SNDLOWAT发送低潮限度：对于TCP套接口而言，和接收低潮限度一个道理(默认为2048字节)
 */
#ifndef NGX_HAVE_SO_SNDLOWAT
#define NGX_HAVE_SO_SNDLOWAT     1
#endif


#if !(NGX_WIN32)
/* 类Unix系统信号符号*/
#define ngx_signal_helper(n)     SIG##n
#define ngx_signal_value(n)      ngx_signal_helper(n)

#define ngx_random               random

/* TODO: #ifndef */
#define NGX_SHUTDOWN_SIGNAL      QUIT
#define NGX_TERMINATE_SIGNAL     TERM
#define NGX_NOACCEPT_SIGNAL      WINCH
#define NGX_RECONFIGURE_SIGNAL   HUP

#if (NGX_LINUXTHREADS)
#define NGX_REOPEN_SIGNAL        INFO
#define NGX_CHANGEBIN_SIGNAL     XCPU
#else
#define NGX_REOPEN_SIGNAL        USR1
#define NGX_CHANGEBIN_SIGNAL     USR2
#endif

/* 清除__cdecl函数调用约定(win下使用居多)*/
#define ngx_cdecl
#define ngx_libc_cdecl

#endif
/**
 * 让int与指针变量占用字节在长度上等同
 * 
 * tips：
 * 在64位cpu中sizeof(int)=4byte，sizeof(void*)=8byte，出现了偏差！为了保持一致性，POSIX规定intptr_t在所有cpu架构中都与void*长度相同
 */
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;


#define NGX_INT32_LEN   (sizeof("-2147483648") - 1)		/* int32长度*/
#define NGX_INT64_LEN   (sizeof("-9223372036854775808") - 1) 	/* int64长度*/

/**
 * \file ../../objs/ngx_auto_config.h
 * 指针长度计算int长度
 */
#if (NGX_PTR_SIZE == 4) 	/* 32位cpu*/
#define NGX_INT_T_LEN   NGX_INT32_LEN
#define NGX_MAX_INT_T_VALUE  2147483647

#else 	/* 64位cpu*/
#define NGX_INT_T_LEN   NGX_INT64_LEN
#define NGX_MAX_INT_T_VALUE  9223372036854775807
#endif

/**
 * 字节对齐，默认大小4byte
 * 
 * tips:
 * 平台所需：某些硬件平台只能在某些地址处取某些特定类型的数据，否则抛出硬件异常。
 * 性能所需：为了访问未对齐的内存，处理器需要作两次内存访问；而对齐的内存访问仅需要一次访问。数据结构（尤其是栈）应该尽可能地在自然边界上对齐。
 */
#ifndef NGX_ALIGNMENT
#define NGX_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

/**
 * ngx_align：使d总是大于a倍数的最小值。使用上一般让a为系统CPU CACHE LINE大小，则d就总是其的倍数。
 * ngx_align_ptr：使用上，一般让a为cpu字节对齐大小(ALIGNMENT)。则d就总是在对齐首地址上。
 * 
 * a为2的n幂，有a-1为在n-1位均为1的数。~(a-1)为最后的n-1位全为0
 * d加上（a-1) 之后的值肯定要比最小的a的倍数大，再和~(a-1)相与一下之后，就把小于a的余数1部分丢掉了
 * ngx_align(d, 64)=64，只要d<64，则结果总是64。如果输入d=65，则结果为128，类推。。。
 * 
 * tips:
 * 一般intel为64或128（具体大小由ngx_cpuinfo函数调用了汇编代码获取），使之总是cpu cache line二级缓存读写行的大小倍数，从而有利cpu取速度和效率。
 */
#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define ngx_abort       abort


/* TODO: platform specific: array[NGX_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define NGX_INVALID_ARRAY_INDEX 0x80000000 	//数组长度限制


/* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
#ifndef ngx_inline
#define ngx_inline      inline
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1) 	//32位均为1的值。255.255.255.255，internet的有限广播地址
#endif

//主机名长度
#ifdef MAXHOSTNAMELEN
#define NGX_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define NGX_MAXHOSTNAMELEN  256
#endif


#if ((__GNU__ == 2) && (__GNUC_MINOR__ < 8))
#define NGX_MAX_UINT32_VALUE  (uint32_t) 0xffffffffLL 	//gcc2.8.x以下版本
#else
#define NGX_MAX_UINT32_VALUE  (uint32_t) 0xffffffff 	//gcc2.8.x以上版本
#endif

#define NGX_MAX_INT32_VALUE   (uint32_t) 0x7fffffff 	//int32最大值


#endif /* _NGX_CONFIG_H_INCLUDED_ */
