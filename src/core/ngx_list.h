
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

/**
 * 队列数据节点（真正数据在elts中，设计雷同ngx_array_t）
 */
struct ngx_list_part_s {
    //数组起始地址
    void             *elts;
    //表示数组中已经使用了多少个元素。nelts必须小于表头中的nalloc
    ngx_uint_t        nelts;
    //下一个队列元素的地址
    ngx_list_part_t  *next;
};

/**
 * 队列表头
 */
typedef struct {
    //当前队列分配到的节点地址，作为表头要记录下次分配到那个队列节点
    ngx_list_part_t  *last;
    //队列首个元素。构成链表的关键
    ngx_list_part_t   part;
    //每个元素大小
    size_t            size;
    //数组的容量 
    ngx_uint_t        nalloc;
    //内存池对象
    ngx_pool_t       *pool;
} ngx_list_t;


ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

/**
 *  @param [in/out] list 链表首地址
 *  @param [in] pool 内存池，实际存放链表数据的内存
 *  @param [in] n 链表容量
 *  @param [in] size 每个链表存放值实际大小
 *  @return NGX_OK|NGX_ERROR
 *  
 *  初始化容量为n，传入*list队列
 */
static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
