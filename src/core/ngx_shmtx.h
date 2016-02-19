
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * 用于创建ngx_shmtx_t结构模板
 */
typedef struct {
    ngx_atomic_t   lock;
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;
#endif
} ngx_shmtx_sh_t;

/**
 * 进程间自旋互斥锁
 * 支持原子操作则用存放在共享内存中原子变量
 * 支持信号量，则使用信号机制
 * 否则使用文件锁
 */
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)   //是否支持原子操作
    ngx_atomic_t  *lock;
#if (NGX_HAVE_POSIX_SEM)    //是否支持信号量
    ngx_atomic_t  *wait;
    ngx_uint_t     semaphore;
    sem_t          sem;     //进程间共享信号量
#endif
#else
    ngx_fd_t       fd;
    u_char        *name;
#endif
    ngx_uint_t     spin;    //自旋锁标识
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
