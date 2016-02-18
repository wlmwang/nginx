
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * 数组
 */
typedef struct {
    //指向实际的数据存储区域起始地址
    void        *elts;
    //数组实际元素个数
    ngx_uint_t   nelts;
    //数组单个元素的大小，单位是字节
    size_t       size;
    //数组的容量
    ngx_uint_t   nalloc;
    //内存池对象
    ngx_pool_t  *pool;
} ngx_array_t;


ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
void ngx_array_destroy(ngx_array_t *a);
void *ngx_array_push(ngx_array_t *a);
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);

/**
 *  @param [out] array 数组首地址
 *  @param [in] pool 内存池，实际存放数组数据的内存
 *  @param [in] n 数组容量
 *  @param [in] size 每个数组值实际大小
 *  @return NGX_OK
 *  
 *  初始化数组
 */
static ngx_inline ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_ARRAY_H_INCLUDED_ */
