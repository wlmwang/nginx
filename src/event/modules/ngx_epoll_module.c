
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400
#define EPOLLERR       0x008
#define EPOLLHUP       0x010

#define EPOLLRDHUP     0x2000

#define EPOLLET        0x80000000
#define EPOLLONESHOT   0x40000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};


int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NGX_HAVE_EVENTFD)
#define SYS_eventfd       323
#endif

#if (NGX_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247

typedef u_int  aio_context_t;

struct io_event {
    uint64_t  data;  /* the data field from the iocb */
    uint64_t  obj;   /* what iocb this event came from */
    int64_t   res;   /* result code for this event */
    int64_t   res2;  /* secondary result */
};


#endif
#endif /* NGX_TEST_BUILD_EPOLL */

/**
 *  event 配置
 */
typedef struct {
    ngx_uint_t  events;
    ngx_uint_t  aio_requests;
} ngx_epoll_conf_t;


static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
#if (NGX_HAVE_EVENTFD)
static ngx_int_t ngx_epoll_notify_init(ngx_log_t *log);
static void ngx_epoll_notify_handler(ngx_event_t *ev);
#endif
static void ngx_epoll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
#if (NGX_HAVE_EVENTFD)
static ngx_int_t ngx_epoll_notify(ngx_event_handler_pt handler);
#endif
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

#if (NGX_HAVE_FILE_AIO)
static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
#endif

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

static int                  ep = -1;
static struct epoll_event  *event_list;
static ngx_uint_t           nevents;

#if (NGX_HAVE_EVENTFD)
static int                  notify_fd = -1;
static ngx_event_t          notify_event;
static ngx_connection_t     notify_conn;
#endif

#if (NGX_HAVE_FILE_AIO)

int                         ngx_eventfd = -1;
aio_context_t               ngx_aio_ctx = 0;

static ngx_event_t          ngx_eventfd_event;
static ngx_connection_t     ngx_eventfd_conn;

#endif

static ngx_str_t      epoll_name = ngx_string("epoll");

static ngx_command_t  ngx_epoll_commands[] = {

    { ngx_string("epoll_events"),	//epoll队列长度
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, events),
      NULL },

    { ngx_string("worker_aio_requests"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, aio_requests),
      NULL },

      ngx_null_command
};

/**
 *  \file ../ngx_event.h
 *  event 上下文
 */
ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */
    ngx_epoll_init_conf,                 /* init configuration */

    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
#if (NGX_HAVE_EVENTFD)
        ngx_epoll_notify,                /* trigger a notify */
#else
        NULL,                            /* trigger a notify */
#endif
        ngx_epoll_process_events,        /* process the events */
        ngx_epoll_init,                  /* init the events */
        ngx_epoll_done,                  /* done the events */
    }
};

ngx_module_t  ngx_epoll_module = {
    NGX_MODULE_V1,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 */

static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}


static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}

//异步I/O事件初始化
static void
ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    ngx_eventfd = eventfd(0, 0);
#else
    ngx_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (ngx_eventfd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "eventfd() failed");
        ngx_file_aio = 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", ngx_eventfd);

    n = 1;

    if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "io_setup() failed");
        goto failed;
    }

    ngx_eventfd_event.data = &ngx_eventfd_conn;
    ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
    ngx_eventfd_event.log = cycle->log;
    ngx_eventfd_event.active = 1;
    ngx_eventfd_conn.fd = ngx_eventfd;
    ngx_eventfd_conn.read = &ngx_eventfd_event;
    ngx_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;	//边缘触发
    ee.data.ptr = &ngx_eventfd_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(ngx_eventfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    ngx_eventfd = -1;
    ngx_aio_ctx = 0;
    ngx_file_aio = 0;
}

#endif

/**
 *  @param [in] cycle 
 *  @param [in] timer 定时器精度ngx_timer_resolution
 *  @return NGX_OK|NGX_ERROR
 *  
 *  epoll初始化，创建epollFD
 */
static ngx_int_t
ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);

    if (ep == -1) {
        ep = epoll_create(cycle->connection_n / 2);		//创建epollFD

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }

#if (NGX_HAVE_EVENTFD)
		//初始化通知notify_fd，将其加入epoll事件中
        if (ngx_epoll_notify_init(cycle->log) != NGX_OK) {
            ngx_epoll_module_ctx.actions.notify = NULL;
        }
#endif

#if (NGX_HAVE_FILE_AIO)
		//异步事件初始化
        ngx_epoll_aio_init(cycle, epcf);

#endif
    }

    if (nevents < epcf->events) {	//默认初始化512个
        if (event_list) {
            ngx_free(event_list);
        }

        //初始化event_list数组。数组大小是配置项epoll_event的參数
        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = epcf->events;	//事件个数，epoll_wait用到。

    /**
     *  \file ../../os/unix/ngx_os.h|c
     *  指明客户端连接事件触发时，读写I/O的方法。如消息发送与接受
     *
     *  \file ../../os/unix/ngx_linux_init.h|c
     *  linux中等同于变量ngx_linux_io值
     */
    ngx_io = ngx_os_io;

    /**
     * ngx_event_actions是个全局的ngx_event_actions_t结构体
     * 用于存储不同事件模块的10个函数接口。（添加|删除|...事件、接受|删除|处理..新连接）
     */
    ngx_event_actions = ngx_epoll_module_ctx.actions;
	
	//优先使用边缘触发模式
#if (NGX_HAVE_CLEAR_EVENT)
    ngx_event_flags = NGX_USE_CLEAR_EVENT   //使用epoll的边缘触发模式 ET
#else
    ngx_event_flags = NGX_USE_LEVEL_EVENT   //使用epoll的水平触发模式 LT
#endif
                      |NGX_USE_GREEDY_EVENT
                      |NGX_USE_EPOLL_EVENT;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)

/**
 *  @param [in] log 
 *  @return NGX_OK|NGX_ERROR
 *  
 *  将进程或线程间通知描述符notify_fd加入epollFD中
 */
static ngx_int_t
ngx_epoll_notify_init(ngx_log_t *log)
{
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    notify_fd = eventfd(0, 0);	//非阻塞
#else
    notify_fd = syscall(SYS_eventfd, 0);	//非阻塞
#endif

    if (notify_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "eventfd() failed");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "notify eventfd: %d", notify_fd);

    notify_event.handler = ngx_epoll_notify_handler;	//事件回调函数
    notify_event.log = log;
    notify_event.active = 1;

    notify_conn.fd = notify_fd;
    notify_conn.read = &notify_event;
    notify_conn.log = log;

    ee.events = EPOLLIN|EPOLLET;	//可读事件，边缘触发。只会通知一次
    ee.data.ptr = &notify_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

        if (close(notify_fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                            "eventfd close() failed");
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_epoll_notify_handler(ngx_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    ngx_err_t             err;
    ngx_event_handler_pt  handler;

    if (++ev->index == NGX_MAX_UINT32_VALUE) {
        ev->index = 0;

        n = read(notify_fd, &count, sizeof(uint64_t));

        err = ngx_errno;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "read() eventfd %d: %z count:%uL", notify_fd, n, count);

        if ((size_t) n != sizeof(uint64_t)) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "read() eventfd %d failed", notify_fd);
        }
    }

    handler = ev->data;
    handler(ev);
}

#endif


static void
ngx_epoll_done(ngx_cycle_t *cycle)
{
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (NGX_HAVE_EVENTFD)

    if (close(notify_fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    notify_fd = -1;

#endif

#if (NGX_HAVE_FILE_AIO)

    if (ngx_eventfd != -1) {

        if (io_destroy(ngx_aio_ctx) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "io_destroy() failed");
        }

        if (close(ngx_eventfd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "eventfd close() failed");
        }

        ngx_eventfd = -1;
    }

    ngx_aio_ctx = 0;

#endif

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}

/**
 *  @param [in] ev 事件对象
 *  @param [in] ev 事件类型 可读、可写
 *  @param [in] flags 事件对象
 *  @return NGX_OK|NGX_ERROR
 *  把一个感兴趣的事件加入到epoll队列中
 */
static ngx_int_t
ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    //每一个事件的data成员都存放着其相应的ngx_connection_t连接
    c = ev->data;

    events = (uint32_t) event;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    //依据是否为活跃事件确定是改动还是加入事件
    if (e->active) {
        op = EPOLL_CTL_MOD; //改动epoll中的事件
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD; //加入新事件到epoll中
    }

    //设置事件类型
    ee.events = events | (uint32_t) flags;
    //data的ptr成员指向一个连接，同一时候把最低位设置为instance标志，事件分发程序将这个标志提取出来
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    //改动active标志。表示当前事件是活跃的
    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    c = ev->data;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    ev->active = 0;

    return NGX_OK;
}

/**
 * @param [in] c connect连接
 * @return int NGX_OK|NGX_ERROR
 * 
 * 添加连接到epoll事件读、写事件监听队列中
 */
static ngx_int_t
ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)

static ngx_int_t
ngx_epoll_notify(ngx_event_handler_pt handler)
{
    static uint64_t inc = 1;

    notify_event.data = handler;

    if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
        ngx_log_error(NGX_LOG_ALERT, notify_event.log, ngx_errno,
                      "write() to eventfd %d failed", notify_fd);
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif

/**
 *  @param [in] cycle cycle对象
 *  @param [in] timer 阻塞时间
 *  @param [in] flags 是否更新时间片(0/NGX_UPDATE_TIME)，是否后置处理NGX_POST_EVENTS
 *  @return NGX_OK|NGX_ERROR
 *  收集、分发事件。事件触发时，只有一个worker进入
 */
static ngx_int_t
ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_queue_t       *queue;
    ngx_connection_t  *c;

    /* NGX_TIMER_INFINITE == INFTIM */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

    //等待事件，最长等待时间为timer
    events = epoll_wait(ep, event_list, (int) nevents, timer);

    err = (events == -1) ? ngx_errno : 0;

    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();  //更新时间
    }

    if (err) {
        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {	//epoll失败是由定时器打断
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }

    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {	//非阻塞
            return NGX_OK;
        }
		
		//若epoll非阻塞方式，但却失败了，记录并返回错误
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        //提取出instance标志
        instance = (uintptr_t) c & 1;
        //屏蔽最后一位计算出真正的连接对象的地址
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        //取出读事件
        rev = c->read;

        //推断这个读事件是否过期
        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        //获得事件类型
        revents = event_list[i].events;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        if (revents & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

        if ((revents & (EPOLLERR|EPOLLHUP))
             && (revents & (EPOLLIN|EPOLLOUT)) == 0)
        {
            /*
             * if the error events were returned without EPOLLIN or EPOLLOUT,
             * then add these flags to handle the events at least in one
             * active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

        //读事件触发且该事件是活跃的
        if ((revents & EPOLLIN) && rev->active) {

#if (NGX_HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            rev->ready = 1;

            //事件需要延后处理
            if (flags & NGX_POST_EVENTS) {
                /**
                 * 如果要在post队列中延后处理该事件，首先要判断它是新连接事件还是普通事件
                 * 以确定是把它加入到ngx_posted_accept_events队列或者ngx_posted_events队列中
                 */
                queue = rev->accept ? &ngx_posted_accept_events
                                    : &ngx_posted_events;
                
                //将该事件添加到相应的延后队列中。@ngx_locked_post_event(rev, queue);
                ngx_post_event(rev, queue);

            } else {
                /**
                 * \file ngx_epoll_module.c
				 * 立即调用事件回调方法来处理这个事件
                 * Listen Socket连接为ngx_event_accept，ngx_event_process_init被赋值
                 */
                rev->handler(rev);
            }
        }

        //取出写事件
        wev = c->write;

        //写事件触发且该事件是活跃的
        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;

            //事件需要延后处理
            if (flags & NGX_POST_EVENTS) {
                //将该事件添加到相应的延后队列中，普通队列。@ngx_locked_post_event(rev, queue);
                ngx_post_event(wev, &ngx_posted_events);

            } else {
                //立即调用事件回调方法来处理这个事件
                wev->handler(wev);
            }
        }
    }

    return NGX_OK;
}


#if (NGX_HAVE_FILE_AIO)

static void
ngx_epoll_eventfd_handler(ngx_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    ngx_err_t         err;
    ngx_event_t      *e;
    ngx_event_aio_t  *aio;
    struct io_event   event[64];
    struct timespec   ts;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    n = read(ngx_eventfd, &ready, 8);

    err = ngx_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

        events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %l", events);

        if (events > 0) {
            ready -= events;

            for (i = 0; i < events; i++) {

                ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %uXL %uXL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                e = (ngx_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

                ngx_post_event(e, &ngx_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif


static void *
ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NGX_CONF_UNSET;
    epcf->aio_requests = NGX_CONF_UNSET;

    return epcf;
}

/**
 *  初始化event配置
 */
static char *
ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    ngx_conf_init_uint_value(epcf->events, 512);	//512
    ngx_conf_init_uint_value(epcf->aio_requests, 32);

    return NGX_CONF_OK;
}
