
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/**
 * 进程间通信
 * 利用socketpair创建的一对socket进行的，通信中传输的是ngx_channel_t结构变量
 */
typedef struct {
	/**
	 * command是要发送的命令，有5种： 
	 * #define NGX_CMD_OPEN_CHANNEL   1 
	 * #define NGX_CMD_CLOSE_CHANNEL  2 
	 * #define NGX_CMD_QUIT           3 
	 * #define NGX_CMD_TERMINATE      4 
	 * #define NGX_CMD_REOPEN         5 
	 */
     ngx_uint_t  command;
     ngx_pid_t   pid;	//发送方进程id
     ngx_int_t   slot;	//发送方进程表中偏移(下标)
     ngx_fd_t    fd;	//发送方ch[0]描述符
} ngx_channel_t;


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
