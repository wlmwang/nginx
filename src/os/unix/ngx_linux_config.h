
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LINUX_CONFIG_H_INCLUDED_
#define _NGX_LINUX_CONFIG_H_INCLUDED_


#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* pread(), pwrite(), gethostname() */
#endif

#define _FILE_OFFSET_BITS  64	//off_t 突破单文件4G大小限制，系统库sys/types.h中使用

#include <sys/types.h>			//各种类型定义，包括u_char/u_int/gid_t/pid_t/off_t/uid_t/size_t/ssize_t/mode_t/tm/clock_t
#include <sys/time.h>			//时间相关，该系统库通常会包含c标准库<time.h>
#include <unistd.h>				//POSIX标准库 win平台<windows.h>
#include <stdarg.h>				//可变参数表 
#include <stddef.h>             /* offsetof() */	//#define offsetof(s,m) (size_t)&(((s *)0)->m) 计算struct成员变量偏移量
#include <stdio.h>				//标准I/O库
#include <stdlib.h>				//公用函数 包含了C、C++语言的最常用的系统函数
#include <ctype.h>				//字符分类函数 tolower isdigit
#include <errno.h>				//定义错误码 注意没有errno=0的
#include <string.h>				//字符串处理 是C/C++的标准头文件 （一般该文件会包含头文件stddef.h）。strings.h等同于string.h（建议使用string.h）
#include <signal.h>				//信号机制支持 
#include <pwd.h>				//用户口令
#include <grp.h>				//用户组 
#include <dirent.h>				//目录处理
#include <glob.h>				//路径名模式匹配类型 
#include <sys/vfs.h>            /* statfs() */

#include <sys/uio.h>			//矢量I/O操作 
#include <sys/stat.h>			//文件状态 
#include <fcntl.h>				//文件控制

#include <sys/wait.h>			//进程控制 
#include <sys/mman.h>			//内存管理
#include <sys/resource.h>		//资源操作 
#include <sched.h>				//执行调度 sleep等

#include <sys/socket.h>			//提供socket函数及数据结构
#include <netinet/in.h>			//INTERNET地址簇（sockaddr_in）
#include <netinet/tcp.h>        /* TCP_NODELAY, TCP_CORK */
#include <arpa/inet.h>			//提供IP地址转换函数
#include <netdb.h>				//网络数据库操作 
#include <sys/un.h>				//UNIX域地址簇 

#include <time.h>               /* tzset() */	//c标准库，一般在<sys/time.h>中已包含
#include <malloc.h>             /* memalign() */
#include <limits.h>             /* IOV_MAX */
#include <sys/ioctl.h>			//I/O操作库
#include <crypt.h>				//加解密
#include <sys/utsname.h>        /* uname() */

/**
 * \file ../../../objs/ngx_auto_config.h
 * gcc编译环境相关、configure参数相关
 */
#include <ngx_auto_config.h>


#if (NGX_HAVE_POSIX_SEM)
#include <semaphore.h>		//信号量库
#endif


#if (NGX_HAVE_SYS_PRCTL_H)
#include <sys/prctl.h>		//线程控制库，支持PR_SET_NAME选项，用于设置进程名字，linux的进程一般使用lwp，所以这个函数可以设置线程名字
#endif


#if (NGX_HAVE_SENDFILE64)
#include <sys/sendfile.h>		//amd64 直接支持sendfile
#else
extern ssize_t sendfile(int s, int fd, int32_t *offset, size_t size);
#define NGX_SENDFILE_LIMIT  0x80000000 	//sendfile大小限制
#endif


#if (NGX_HAVE_POLL)
#include <poll.h>
#endif


#if (NGX_HAVE_EPOLL)
#include <sys/epoll.h>
#endif


#if (NGX_HAVE_SYS_EVENTFD_H)
#include <sys/eventfd.h>
#endif
#include <sys/syscall.h>		//系统调用库
#if (NGX_HAVE_FILE_AIO)
#include <linux/aio_abi.h>
typedef struct iocb  ngx_aiocb_t;
#endif


#define NGX_LISTEN_BACKLOG        511 	//listen socket backlog长度

#ifndef NGX_HAVE_SO_SNDLOWAT
/* setsockopt(SO_SNDLOWAT) returns ENOPROTOOPT */
#define NGX_HAVE_SO_SNDLOWAT         0
#endif


#ifndef NGX_HAVE_INHERITED_NONBLOCK
#define NGX_HAVE_INHERITED_NONBLOCK  0		//listen socketfd是否可阻塞
#endif


#define NGX_HAVE_OS_SPECIFIC_INIT    1		//特定初始化。使用uname获取os信息，包括操作系统名/操作系统版本
#define ngx_debug_init()


extern char **environ;


#endif /* _NGX_LINUX_CONFIG_H_INCLUDED_ */
