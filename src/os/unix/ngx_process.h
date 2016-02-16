
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    //当前工作进程的ID号
    ngx_pid_t           pid;
    //当前进程的退出状态
    int                 status;
    /**
     * 保存由socketpair创建的一对socket句柄，用于进程间交互。
     * ngx代码中只用它作单向通信：master进程用channel[0]描述符来接受和发送消息；worker进程用channel[1]来接收和发送消息。
     * 相对worker进程来说，channel[0]写端（主进程master侦听SIGIO事件）  和 channel[1]读端
     */
    ngx_socket_t        channel[2];

    //指向工作进程执行的函数
    ngx_spawn_proc_pt   proc;
    //通常用来指向进程的上下文结构
    void               *data;
    //为新建进程的名称，默认为"new binary process"
    char               *name;

    //退出后是否重建
    unsigned            respawn:1;
    //是否是首次创建的
    unsigned            just_spawn:1;
    //是否已分离
    unsigned            detached:1;
    //是否正在退出
    unsigned            exiting:1;
    //是否已经退出
    unsigned            exited:1;
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024  //最大master+worker数量

#define NGX_PROCESS_NORESPAWN     -1    //子进程退出时，父进程不再创建
#define NGX_PROCESS_JUST_SPAWN    -2    //用于在子进程退出并重新创建后标记是刚刚创建的新进程，防止被父进程意外终止
#define NGX_PROCESS_RESPAWN       -3    //子进程退出时，父进程需要重新创建
#define NGX_PROCESS_JUST_RESPAWN  -4    //该标记用来标记进程数组中哪些是新创建的子进程
#define NGX_PROCESS_DETACHED      -5    //热代码替换


#define ngx_getpid   getpid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
