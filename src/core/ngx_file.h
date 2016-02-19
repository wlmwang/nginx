
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_FILE_H_INCLUDED_
#define _NGX_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


struct ngx_file_s {
    //文件句柄描述符
    ngx_fd_t                   fd;
    //文件名称
    ngx_str_t                  name;
    //文件大小等资源信息，实际就是Linux系统定义的stat结构(typedef struct stat ngx_file_info_t)
    ngx_file_info_t            info;

    //该偏移量告诉ngx现在处理到文件何处了
    off_t                      offset;
    //当前文件系统偏移量，不支持原子pread操作时使用。在支持pread系统上，相对offset，该字段为冗余字段
    off_t                      sys_offset;

    //日志对象，相关的日志会输出到log指定的日志文件中
    ngx_log_t                 *log;

#if (NGX_THREADS)
    ngx_int_t                (*thread_handler)(ngx_thread_task_t *task,
                                               ngx_file_t *file);
    void                      *thread_ctx;
#endif

#if (NGX_HAVE_FILE_AIO)
    ngx_event_aio_t           *aio;
#endif

    //目前未使用
    unsigned                   valid_info:1;
    //与配置文件中的directio配置项相对应，在发送大文件时可以设为1
    unsigned                   directio:1;
};


#define NGX_MAX_PATH_LEVEL  3


typedef time_t (*ngx_path_manager_pt) (void *data);
typedef void (*ngx_path_loader_pt) (void *data);


typedef struct {
    //路径数据字符串
    ngx_str_t                  name;
    //子目录文件名称长度大小包括斜杠长度 /ABC/sub1/sub2/sub3/ --> 3+1+3+1+3+1=12
    size_t                     len;
    //3级子目录，每个子目录的名称长度
    size_t                     level[3];

    ngx_path_manager_pt        manager;
    ngx_path_loader_pt         loader;
    //设置为ngx_http_file_cache_t 在ngx_http_file_cache_set_slot()函数中设置
    void                      *data;

    //该路径的来源的配置文件 NULL表示默认路径
    u_char                    *conf_file;
    //该路径在来源的配置文件中的行数，主要用于记录日志，排查错误
    ngx_uint_t                 line;
} ngx_path_t;


typedef struct {
    ngx_str_t                  name;
    size_t                     level[3];
} ngx_path_init_t;


typedef struct {
    //临时文件信息
    ngx_file_t                 file;
    off_t                      offset;
    ngx_path_t                *path;
    ngx_pool_t                *pool;
    char                      *warn;

    ngx_uint_t                 access;

    //日志等级
    unsigned                   log_level:8;
    //说明临时文件是否一直存在于文件系统中
    unsigned                   persistent:1;
    //文件的清理方式（是否将文件在磁盘上删除）
    unsigned                   clean:1;
} ngx_temp_file_t;


typedef struct {
    //文件的访问权限
    ngx_uint_t                 access;
    //目录的访问权限
    ngx_uint_t                 path_access;
    //文件的最后修改时间
    time_t                     time;
    ngx_fd_t                   fd;

    //当访问的文件目录不存在时，将创建目录
    unsigned                   create_path:1;
    //删除文件
    unsigned                   delete_file:1;

    ngx_log_t                 *log;
} ngx_ext_rename_file_t;


typedef struct {
    off_t                      size;
    size_t                     buf_size;

    ngx_uint_t                 access;
    time_t                     time;

    ngx_log_t                 *log;
} ngx_copy_file_t;


typedef struct ngx_tree_ctx_s  ngx_tree_ctx_t;

typedef ngx_int_t (*ngx_tree_init_handler_pt) (void *ctx, void *prev);
typedef ngx_int_t (*ngx_tree_handler_pt) (ngx_tree_ctx_t *ctx, ngx_str_t *name);

struct ngx_tree_ctx_s {
    //文件大小
    off_t                      size;
    off_t                      fs_size;
    ngx_uint_t                 access;
    //最后修改时间
    time_t                     mtime;

    ngx_tree_init_handler_pt   init_handler;
    ngx_tree_handler_pt        file_handler;
    ngx_tree_handler_pt        pre_tree_handler;
    ngx_tree_handler_pt        post_tree_handler;
    ngx_tree_handler_pt        spec_handler;

    void                      *data;
    size_t                     alloc;

    ngx_log_t                 *log;
};


ngx_int_t ngx_get_full_name(ngx_pool_t *pool, ngx_str_t *prefix,
    ngx_str_t *name);

ssize_t ngx_write_chain_to_temp_file(ngx_temp_file_t *tf, ngx_chain_t *chain);
ngx_int_t ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path,
    ngx_pool_t *pool, ngx_uint_t persistent, ngx_uint_t clean,
    ngx_uint_t access);
void ngx_create_hashed_filename(ngx_path_t *path, u_char *file, size_t len);
ngx_int_t ngx_create_path(ngx_file_t *file, ngx_path_t *path);
ngx_err_t ngx_create_full_path(u_char *dir, ngx_uint_t access);
ngx_int_t ngx_add_path(ngx_conf_t *cf, ngx_path_t **slot);
ngx_int_t ngx_create_paths(ngx_cycle_t *cycle, ngx_uid_t user);
ngx_int_t ngx_ext_rename_file(ngx_str_t *src, ngx_str_t *to,
    ngx_ext_rename_file_t *ext);
ngx_int_t ngx_copy_file(u_char *from, u_char *to, ngx_copy_file_t *cf);
ngx_int_t ngx_walk_tree(ngx_tree_ctx_t *ctx, ngx_str_t *tree);

ngx_atomic_uint_t ngx_next_temp_number(ngx_uint_t collision);

char *ngx_conf_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_merge_path_value(ngx_conf_t *cf, ngx_path_t **path,
    ngx_path_t *prev, ngx_path_init_t *init);
char *ngx_conf_set_access_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


extern ngx_atomic_t      *ngx_temp_number;
extern ngx_atomic_int_t   ngx_random_number;


#endif /* _NGX_FILE_H_INCLUDED_ */
