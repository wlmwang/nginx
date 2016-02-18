
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

//默认创建内存池的大小
#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

//默认内存池对齐大小
#define NGX_POOL_ALIGNMENT       16
//默认内存池最小字节
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

/**
 * 回收内存池执行函数链表
 */
struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;
    void                 *data;
    ngx_pool_cleanup_t   *next;
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

/**
 * 大内存链表
 * 大于内存池结构max值是称为大内存。通常为系统一页（4k）字节
 */
struct ngx_pool_large_s {
    ngx_pool_large_t     *next;
    void                 *alloc;
};

/**
 * 内存池数据节点
 */
typedef struct {
    u_char               *last;     //本节点已分配到的地址，即下一次从该地址开始分配内存
    u_char               *end;      //节点结束地址
    ngx_pool_t           *next;     //下一个内存池地址。组成链表
    ngx_uint_t            failed;   //分配失败次数
} ngx_pool_data_t;

/**
 * 内存池表头
 */
struct ngx_pool_s {
    ngx_pool_data_t       d;        //内存池链表首个元素。构成链表的关键
    size_t                max;      //小内存块最大值，通常与可分配内存大小相同
    ngx_pool_t           *current;  //当前内存池分配到的节点地址。作为表头要记录下次分配到那个链表节点
    /**
     *  \file ngx_buf.h
     *  链表结构
     */
    ngx_chain_t          *chain;
    ngx_pool_large_t     *large;    //大内存链表地址
    ngx_pool_cleanup_t   *cleanup;  //回收内存处理器链表
    ngx_log_t            *log;      //日志
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
