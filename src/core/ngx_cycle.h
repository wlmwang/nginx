
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

/**
 * 共享内存zone
 */
struct ngx_shm_zone_s {
    //指向自定义数据结构，可能指向本地地址
    void                     *data;
    /**
     *  \file ../os/unix/ngx_shmem.h
     *  \brief 真正的共享内存
     */ 
    ngx_shm_t                 shm;
    //初始化函数
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    /**
     * 保存ngx中解析出的所有配置信息
     * 是一个指针数组（核心模块配置ngx_core_module|ngx_http_module等），其中每一个元素又指向一个指针数组（每个模块有核心结构体，管理其下所模块）
     * conf_ctx[]
     *      --ngx_core_module[]
     *                  ---main_conf*
     *                              ---create_main_conf
     *                  ---srv_conf*
     *                  ---loc_conf*
     *      --ngx_http_module[]
     */
    void                  ****conf_ctx;
    //内存池
    ngx_pool_t               *pool;

    /**
     * 日志模块中提供了生成基本ngx_log_t日志对象的功能，
     * 这里的log实际上是在还没有执行ngx_init_cycle方法前，也就是还没解析配置前，如果有信息需要输出到日志，就会暂时使用log对象，它会输出到屏幕。
     * 在ngx_init_cycle方法执行后，将会根据nginx.conf配置文件中的配置项，构造出正确的日志文件，此时会对log重新赋值
     */
    ngx_log_t                *log;
    //调用ngx_init_cycle方法后，会用new_log的地址覆盖上面的log指针
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    //fiels保存所有ngx_connection_t的指针组成的数组，files_n就是指针的总数，而文件句柄的值用来访问files数组成员
    ngx_connection_t        **files;
    //空闲连接池，与free_connection_n配合使用。它指向connections第一个空闲连接，ngx会为我们构造起了一个空的connections数组
    ngx_connection_t         *free_connections;
    //空闲连接池中连接的总数
    ngx_uint_t                free_connection_n;

    //可重复使用的双向连接队列，成员类型是ngx_connection_t
    ngx_queue_t               reusable_connections_queue;

    //存储ngx_listening_t成员
    ngx_array_t               listening;
    //保存着ngx所有要操作的目录，如果目录不存在，则会试图创建，而创建目录失败将会导致ngx启动失败。
    ngx_array_t               paths;
    //-T参数，临时打印配置信息
    ngx_array_t               config_dump;
    //保存ngx已经打开的所有文件(ngx_open_file_t结构体)的单链表。
    ngx_list_t                open_files;
    //存储ngx_shm_zone_t，每个元素表示一块共享内存。单链表
    ngx_list_t                shared_memory;

    //表示当前进程中所有连接对象的总数，与下面的connections成员配合使用
    ngx_uint_t                connection_n;
    //表示files数组中ngx_connection_t指针的总数
    ngx_uint_t                files_n;

    //连接池。指向当前进程中的所有连接对象，每个连接对象对应一个写事件和一个读事件
    ngx_connection_t         *connections;
    //指向当前进程中的所有写事件对象，connection_n同时表示所有读事件的总数
    ngx_event_t              *read_events;
    //指向当前进程中的所有写事件对象，connection_n同时表示所有写事件的总数
    ngx_event_t              *write_events;

    //旧的ngx_cycle_t对象用于引用上一个ngx_cycle_t对象中的成员，如热继承的Listen SocketFD
    ngx_cycle_t              *old_cycle;

    //配置文件相对于安装目录的路径名称
    ngx_str_t                 conf_file;
    //ngx处理配置文件时需要特殊处理的在命令行携带的参数，一般是-g选项携带的参数
    ngx_str_t                 conf_param;
    //ngx配置文件所在的路径
    ngx_str_t                 conf_prefix;
    //ngx安装目录的路径
    ngx_str_t                 prefix;
    //用于进程间同步的文件锁名称
    ngx_str_t                 lock_file;
    //使用gethostname系统调用得到的主机名
    ngx_str_t                 hostname;
};

/**
 * ngx全局配置，与配置文件中全局域一一对应
 */
typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes;
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     uint64_t                *cpu_affinity;

     char                    *username;
     ngx_uid_t                user;
     ngx_gid_t                group;

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
uint64_t ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;    //全局cycle对象
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
