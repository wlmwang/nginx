
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

/**
 * 缓冲区
 * 应用于内存数据、磁盘数据
 * start、end|pos、last设计参考循环缓冲区
 */
struct ngx_buf_s {
    /**
     * pos通常是用来告诉使用者本次应该从pos这个位置开始处理内存中的数据，
     * 当然，pos的含义是由使用它的模块定义的
     */
    u_char          *pos;
    /**
     * last通常表示有效的内容到此为止
     * 注意，pos与last之间的内存是希望ngx处理的内容(即存放了实际数据)
     */
    u_char          *last;
    /** 
     * 偏移量
     * 处理文件时，file_pos与file_last的含义与处理内存时的pos与last相同
     * file_pos表示将要处理的文件位置，file_last表示截止的文件位置
     * 达到指向一个文件的某一部分
     */
    off_t            file_pos;
    off_t            file_last;

    //如果缓冲区用于内存，那么start指向这段内存的起始地址
    u_char          *start;         /* start of buffer */
    //与start成员对应，指向缓冲区内存的末尾
    u_char          *end;           /* end of buffer */
    /**
     * 指向当前缓冲区的类型
     * 例如由哪个模块使用就指向这个模块的ngx_module_t变量的地址
     */
    ngx_buf_tag_t    tag;
    //引用的实际文件
    ngx_file_t      *file;
    /**
     * 当这个buf完整copy了另外一个buf的所有字段的时候，
     * 那么这两个buf指向的实际上是同一块内存，或者是同一个文件的同一部分，
     * 此时这两个buf的shadow字段都是指向对方的。
     * 那么对于这样的两个buf，在释放的时候，就需要使用者特别小心，
     * 具体是由哪里释放，要提前考虑好，如果造成资源的多次释放，可能会造成程序崩溃！
     */
    /**
     * 当前缓冲区的影子缓冲区
     * 该成员很少用到，仅仅在使用缓冲区转发上游服务器的响应时才使用了shadow成员，
     * 这是因为Nginx太节约内存了，分配一块内存并使用ngx_buf_t表示接收到的上游服务器响应后，
     * 在向下游客户端转发时可能会把这块内存存储到文件中，也可能直接向下游发送，
     * 此时Nginx绝不会重新复制一份内存用于新的目的，而是再次建立一个ngx_buf_t结构体指向原内存，
     * 这样多个ngx_buf_t结构体指向了同一块内存，它们之间的关系就通过shadow成员来引用。
	 * 这种设计过于复杂，通常不建议使用
     */
    ngx_buf_t       *shadow;    /*具体设计可参考：写时拷贝*/


    /* the buf's content could be changed */
    //临时内存标志位，为1时表示该buf所包含的内容是在一个用户创建的内存块中，并且可以被在filter处理的过程中进行变更，而不会造成问题
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    //标志位，为1时表示该buf所包含的内容是在内存中，但是这些内容确不能被进行处理的filter进行变更。
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    //标志位，为1时表示该buf所包含的内容是在内存中, 是通过mmap使用内存映射从文件中映射到内存中的，这些内容确不能被进行处理的filter进行变更。
    unsigned         mmap:1;

    //标志位，为1时表示可回收
    unsigned         recycled:1;
    //标志位，为1时表示该buf所包含的内容是在文件中
    unsigned         in_file:1;
    /**
     * 标志位，为1时表示需要执行flush操作
     * 遇到有flush字段被设置为1的的buf的chain，
     * 则该chain的数据即便不是最后结束的数据（last_buf被设置，标志所有要输出的内容都完了），
     * 也会进行输出，不会受postpone_output配置的限制，但是会受到发送速率等其他条件的限制。
     */
    unsigned         flush:1;
    /**
     * 标志位，对于操作这块缓冲区时是否使用同步方式，
     * 需谨慎考虑，这可能会阻塞ngx进程，ngx中所有操作几乎都是异步的，这是它支持高并发的关键。
     * 有些框架代码在sync为1时可能会有阻塞的方式进行I/O操作，它的意义视使用它的ngx模块而定
     */  
    unsigned         sync:1;
    /**
     * 标志位，表示是否是最后一块缓冲区，
     * 因为ngx_buf_t可以由ngx_chain_t链表串联起来，因此，当last_buf为1时，表示当前是最后一块待处理的缓冲区
     * 数据被以多个chain传递给了过滤器，此字段为1表明这是最后一个buf
     */  
    unsigned         last_buf:1;
    /**
     * 在当前的chain里面，此buf是最后一个。
     * 特别要注意的是last_in_chain的buf不一定是last_buf，
     * 但是last_buf的buf一定是last_in_chain的
     * 这是因为数据会被以多个chain传递给某个filter模块。 
     */
    //标志位，表示是否是ngx_chain_t中的最后一块缓冲区 
    unsigned         last_in_chain:1;

    /**
     * 标志位，表示是否是最后一个影子缓冲区，与shadow域配合使用。
     * 通常不建议使用它
     */  
    unsigned         last_shadow:1;
    //标志位，表示当前缓冲区是否属于临时文件
    unsigned         temp_file:1;

    /* STUB */ int   num;
};

/**
 * ngx_chain_t（链表节点）与ngx_buf_t（链表数据）配合使用形成链表数据结构
 * 
 * 例如在向用户发送HTTP包体时，就要传入ngx_chain_t链表对象，注意最后一个ngx_chain_t的next指向NULL，否则永远不会发送成功
 */
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

#if (NGX_HAVE_FILE_AIO)
typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);
#endif

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
#if (NGX_HAVE_ALIGNED_DIRECTIO)
    unsigned                     unaligned:1;
#endif
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
#if (NGX_HAVE_FILE_AIO || NGX_THREADS)
    unsigned                     aio:1;
#endif

#if (NGX_HAVE_FILE_AIO)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
