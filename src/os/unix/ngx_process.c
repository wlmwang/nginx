
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>

//ngx服务器的启动、停止和升级都是通过信号控制的
typedef struct {
    int     signo;
    //信号的字符串表现形式，如"SIGIO"
    char   *signame;
    //信号的名称，如"stop"
    char   *name;
    //信号处理函数
    void  (*handler)(int signo);
} ngx_signal_t;



static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
static void ngx_signal_handler(int signo);
static void ngx_process_get_status(void);
static void ngx_unlock_mutexes(ngx_pid_t pid);


int              ngx_argc;
char           **ngx_argv;
char           **ngx_os_argv;

//进程表相关
ngx_int_t        ngx_process_slot;  //已分配到最后一个进程表索引
ngx_socket_t     ngx_channel;       //worker进程的channel[1]通道
ngx_int_t        ngx_last_process;  //进程表最后一个索引
ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];  //worker进程表

//ngx服务器程序将所有可能遇到的信号保存在一个结构数组中(12个)
ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),     //重新读取配置信息
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
      "reload",
      ngx_signal_handler },

    { ngx_signal_value(NGX_REOPEN_SIGNAL),          //重新运行工作进程
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),
      "reopen",
      ngx_signal_handler },

    { ngx_signal_value(NGX_NOACCEPT_SIGNAL),        //工作进程不接受事件
      "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),
      "",
      ngx_signal_handler },

    { ngx_signal_value(NGX_TERMINATE_SIGNAL),       //工作进程终止
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
      "stop",
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),        //结束网络通信，进程退出
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      "quit",
      ngx_signal_handler },

    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),       //热升级ngx运行程序
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
      "",
      ngx_signal_handler },

    { SIGALRM, "SIGALRM", "", ngx_signal_handler },

    { SIGINT, "SIGINT", "", ngx_signal_handler },

    { SIGIO, "SIGIO", "", ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }
};

/**
 *  @param [in] cycle cycle对象
 *  @param [in] proc ngx_worker_process_cycle，子进程入口函数。
 *  @param [in] data 子进程worker是主进程master启动的第几个进程，0起始
 *  @param [in] name 子进程worker名称
 *  @param [in] respawn  worker进程属性（worker退出后是否要重启）、指定重启进程表索引中哪个进程
 *  @return int 子进程pid_t
 *  
 *  生成(fork)工作[worker]子进程
 */
ngx_pid_t
ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,
    char *name, ngx_int_t respawn)
{
    u_long     on;
    ngx_pid_t  pid;
    ngx_int_t  s;	//将要创建的子进程在进程表中的位置

    if (respawn >= 0) {     //指定重启具体进程表索引中的进程
        s = respawn;

    } else {
        //找到一个空闲进程表
        for (s = 0; s < ngx_last_process; s++) {
            if (ngx_processes[s].pid == -1) {
                break;
            }
        }
		
		//超过限制
        if (s == NGX_MAX_PROCESSES) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          NGX_MAX_PROCESSES);
            return NGX_INVALID_PID;
        }
    }

    //如果类型为NGX_PROCESS_DETACHED，则说明是热代码替换，需关闭channel
    if (respawn != NGX_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */
		
		//创建一对已经连接的无名socket
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       ngx_processes[s].channel[0],
                       ngx_processes[s].channel[1]);
		
		//非阻塞
        if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        /**
         * 设置第一个描述符的异步IO通知机制（FIOASYNC现已被O_ASYNC标志位取代）
         * SIGIO用于在不想或不能使用 polling (select, epoll 等方式) 机制的情况下，异步获取 I/O 事件。
         */
        on = 1;
        if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        /**
         * 设置将要在文件描述符channel[0]上接收SIGIO 或 SIGURG事件信号的进程或进程组的标识
         * 当该描述符状态发生改变时,会向ngx_pid发送SIGIO信号。
		 * ngx_pid是master进程的进程ID
         */
        if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        /**
         * 设置两个描述符的CLOEXEC标识，
         * 在使用execl执行的进程里，此描述符被关闭，不能再使用它。
		 * 在使用fork调用的子进程中，此描述符并不关闭，仍可使用。
         */
        if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
		
		//用于监听可读时间的socket
        ngx_channel = ngx_processes[s].channel[1];  //设置当前的进程的通道

    } else {
        ngx_processes[s].channel[0] = -1;
        ngx_processes[s].channel[1] = -1;
    }

    ngx_process_slot = s;	//当前已创建到第几个worker进程


    pid = fork();

    switch (pid) {

    case -1:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
        ngx_close_channel(ngx_processes[s].channel, cycle->log);
        return NGX_INVALID_PID;

    case 0:
        ngx_pid = ngx_getpid();	//更新当前pid为worker进程pid
        /**
         *  \file ngx_process_cycle.h|c
         *  子进程入口函数，该函数应设计成死循环
         */
        proc(cycle, data);	//ngx_worker_process_cycle
        break;

    default:
        break;
    }
	
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    //父进程逻辑 主要是记录子进程信息到进程表中
    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    ngx_processes[s].proc = proc;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;

    switch (respawn) {

    case NGX_PROCESS_NORESPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_SPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_DETACHED:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 1;
        break;
    }
	
	//TODO 扩充进程表大小？？？
    if (s == ngx_last_process) {
        ngx_last_process++;
    }

    return pid;
}


ngx_pid_t
ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
}


static void
ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}

/**
 *  @param [in] log log日志对象
 *  @return NGX_OK
 *  
 *  注册ngx项目预定义信号处理函数
 */
ngx_int_t
ngx_init_signals(ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
#if (NGX_VALGRIND)
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "sigaction(%s) failed, ignored", sig->signame);
#else
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
#endif
        }
    }

    return NGX_OK;
}


void
ngx_signal_handler(int signo)
{
    char            *action;
    ngx_int_t        ignore;
    ngx_err_t        err;
    ngx_signal_t    *sig;

    ignore = 0;

    err = ngx_errno;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    ngx_time_sigsafe_update();

    action = "";

    switch (ngx_process) {

    case NGX_PROCESS_MASTER:
    case NGX_PROCESS_SINGLE:
        switch (signo) {

        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (ngx_daemonized) {
                ngx_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
            ngx_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
            if (getppid() > 1 || ngx_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not the init process, i.e. the old binary's process
                 * is still running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            ngx_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            ngx_sigalrm = 1;
            break;

        case SIGIO:
            ngx_sigio = 1;
            break;

        case SIGCHLD:
            ngx_reap = 1;
            break;
        }

        break;

    case NGX_PROCESS_WORKER:
    case NGX_PROCESS_HELPER:
        switch (signo) {

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (!ngx_daemonized) {
                break;
            }
            ngx_debug_quit = 1;
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "signal %d (%s) received%s", signo, sig->signame, action);

    if (ignore) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    if (signo == SIGCHLD) {
        ngx_process_get_status();
    }

    ngx_set_errno(err);
}


static void
ngx_process_get_status(void)
{
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_int_t        i;
    ngx_uint_t       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            if (err == NGX_ECHILD && one) {
                return;
            }

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == NGX_ECHILD) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,
                              "waitpid() failed");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                          "waitpid() failed");
            return;
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }

        ngx_unlock_mutexes(pid);
    }
}


static void
ngx_unlock_mutexes(ngx_pid_t pid)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;
    ngx_slab_pool_t  *sp;

    /*
     * unlock the accept mutex if the abnormally exited process
     * held it
     */

    if (ngx_accept_mutex_ptr) {
        (void) ngx_shmtx_force_unlock(&ngx_accept_mutex, pid);
    }

    /*
     * unlock shared memory mutexes if held by the abnormally exited
     * process
     */

    part = (ngx_list_part_t *) &ngx_cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        sp = (ngx_slab_pool_t *) shm_zone[i].shm.addr;

        if (ngx_shmtx_force_unlock(&sp->mutex, pid)) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "shared memory zone \"%V\" was locked by %P",
                          &shm_zone[i].shm.name, pid);
        }
    }
}


void
ngx_debug_point(void)
{
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    switch (ccf->debug_points) {

    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NGX_DEBUG_POINTS_ABORT:
        ngx_abort();
    }
}


ngx_int_t
ngx_os_signal_process(ngx_cycle_t *cycle, char *name, ngx_int_t pid)
{
    ngx_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (ngx_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
