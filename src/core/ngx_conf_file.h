
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONF_FILE_H_INCLUDED_
#define _NGX_CONF_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 *        AAAA  number of arguments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define NGX_CONF_NOARGS      0x00000001
#define NGX_CONF_TAKE1       0x00000002
#define NGX_CONF_TAKE2       0x00000004
#define NGX_CONF_TAKE3       0x00000008
#define NGX_CONF_TAKE4       0x00000010
#define NGX_CONF_TAKE5       0x00000020
#define NGX_CONF_TAKE6       0x00000040
#define NGX_CONF_TAKE7       0x00000080

#define NGX_CONF_MAX_ARGS    8

#define NGX_CONF_TAKE12      (NGX_CONF_TAKE1|NGX_CONF_TAKE2)
#define NGX_CONF_TAKE13      (NGX_CONF_TAKE1|NGX_CONF_TAKE3)

#define NGX_CONF_TAKE23      (NGX_CONF_TAKE2|NGX_CONF_TAKE3)

#define NGX_CONF_TAKE123     (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3)
#define NGX_CONF_TAKE1234    (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3   \
                              |NGX_CONF_TAKE4)

#define NGX_CONF_ARGS_NUMBER 0x000000ff
#define NGX_CONF_BLOCK       0x00000100
#define NGX_CONF_FLAG        0x00000200
#define NGX_CONF_ANY         0x00000400
#define NGX_CONF_1MORE       0x00000800
#define NGX_CONF_2MORE       0x00001000
#define NGX_CONF_MULTI       0x00000000  /* compatibility */

#define NGX_DIRECT_CONF      0x00010000     //字符串即配置，无需执行命令处理函数

#define NGX_MAIN_CONF        0x01000000
#define NGX_ANY_CONF         0x1F000000



#define NGX_CONF_UNSET       -1
#define NGX_CONF_UNSET_UINT  (ngx_uint_t) -1
#define NGX_CONF_UNSET_PTR   (void *) -1
#define NGX_CONF_UNSET_SIZE  (size_t) -1
#define NGX_CONF_UNSET_MSEC  (ngx_msec_t) -1


#define NGX_CONF_OK          NULL
#define NGX_CONF_ERROR       (void *) -1

#define NGX_CONF_BLOCK_START 1
#define NGX_CONF_BLOCK_DONE  2
#define NGX_CONF_FILE_DONE   3

#define NGX_CORE_MODULE      0x45524F43  /* "CORE" */
#define NGX_CONF_MODULE      0x464E4F43  /* "CONF" */   //需要解析配置


#define NGX_MAX_CONF_ERRSTR  1024

/**
 * 描述某个模块支持的指令
 * 负责解析配置文件的指令，一个指令对应一个配置指令
 */
struct ngx_command_s {
    //指令名称
    ngx_str_t             name;
    /**
     * 指令类型
     * 表示该指令在配置文件中的合法位置和可接受参数个数的标示符集合。
     * 32位的无符号整型数组成。前面16位表示指令的位置，后面16位表示参数个数。
     * 合法位置：如http模块中有指令集：http块中（寻址）、在server块中（寻址）、在location块中（寻址）、在upstream块中（寻址）
     * core模块中有指令集：直接寻址方式、在全局块中（寻址）
     * ...
     * 参数个数
     */
    ngx_uint_t            type;
    /**
     * 指令解析函数
     * 把ngx配置文件该指令的参数转换为合适的数据结构类型，并将转换后的值保存到ngx模块的配置结构体（如ngx_conf_t）中
     */
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
    //指定配置文件结构体中各其他类型指令配置结构体在该结构体中的偏移量
    ngx_uint_t            conf;
    /**
     * 在父指令块中的偏移。用来指定该值保存在配置结构体（ngx_conf_t）中的具体位置的。offsetof()函数计算
     */
    ngx_uint_t            offset;
    //读取配置文件时可能使用的指令
    void                 *post;
};

#define ngx_null_command  { ngx_null_string, 0, NULL, 0, 0, NULL }

/**
 * 打开文件数据结构
 */
struct ngx_open_file_s {
    ngx_fd_t              fd;
    ngx_str_t             name;

    //刷新的句柄
    void                (*flush)(ngx_open_file_t *file, ngx_log_t *log);
    //数据
    void                 *data;
};


#define NGX_MODULE_V1          0, 0, 0, 0, 0, 0, 1
#define NGX_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0

/**
 * 模块结构体 模块化设计核心
 * ngx的每一个模块都需实现ngx_module_t结构体
 */
struct ngx_module_s {
    //分类模块计数器：在ngx_modules[]数组中，该模块在相同类型的模块中的次序。取配置时使用
    ngx_uint_t            ctx_index;
    //模块计数器：按照每个模块在ngx_modules[]数组中的声明顺序，从0开始依次给每个模块赋值
    ngx_uint_t            index;

    ngx_uint_t            spare0;
    ngx_uint_t            spare1;
    ngx_uint_t            spare2;
    ngx_uint_t            spare3;

    //版本
    ngx_uint_t            version;

    /**
     * 与模块相关的上下文。主要用于创建、初始化配置文件。
     * 不同种类的模块有不同的上下文，因此实现了四种结构体（如ngx_core_module_t/ngx_events_module_t/ngx_event_core_module_t）
     */
    void                 *ctx;
    //该模块的指令集，指向一个ngx_command_t结构数组，数组元素为每条指令集。
    ngx_command_t        *commands;
    //----该模块的种类，为core|event|http|mail中的一种宏标识
    //模块的种类，NGX_CORE_MODULE|NGX_CONF_MODULE
    ngx_uint_t            type;

    //初始化master时执行
    ngx_int_t           (*init_master)(ngx_log_t *log);

    //初始化module时执行
    ngx_int_t           (*init_module)(ngx_cycle_t *cycle);

    //初始化工作进程时执行
    ngx_int_t           (*init_process)(ngx_cycle_t *cycle);
    //初始化线程时执行
    ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);
    //退出线程时执行
    void                (*exit_thread)(ngx_cycle_t *cycle);
    //退出工作进程时执行
    void                (*exit_process)(ngx_cycle_t *cycle);

    //退出master时执行
    void                (*exit_master)(ngx_cycle_t *cycle);

    uintptr_t             spare_hook0;
    uintptr_t             spare_hook1;
    uintptr_t             spare_hook2;
    uintptr_t             spare_hook3;
    uintptr_t             spare_hook4;
    uintptr_t             spare_hook5;
    uintptr_t             spare_hook6;
    uintptr_t             spare_hook7;
};

/**
 * 全局上下文结构
 */
typedef struct {
    //模块名
    ngx_str_t             name;
    //core模块解析配置项，ngx框架会调用create_conf方法
    void               *(*create_conf)(ngx_cycle_t *cycle);
    //解析配置项完成后，ngx框架会调用init_conf方法
    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
} ngx_core_module_t;

/**
 * 配置文件处理结构体
 */
typedef struct {
    //文件属性
    ngx_file_t            file;
    //配置文件，文件式缓冲|-g字符串内容，内存式缓冲
    ngx_buf_t            *buffer;
    //-T启动参数。将要打印的配置放入该临时缓冲，与ngx_conf_dump_t中buffer指向相同。内存式缓冲
    ngx_buf_t            *dump;
    //读文件起始行，文件式缓冲时为1
    ngx_uint_t            line;
} ngx_conf_file_t;

/**
 * 临时存放程序运行时解析的配置值
 * ngx_cycle_t.config_dump使用
 */
typedef struct {
    ngx_str_t             name;     //配置文件名
    ngx_buf_t            *buffer;   //与ngx_conf_file_t中dump指向相同，内存式缓冲
} ngx_conf_dump_t;


typedef char *(*ngx_conf_handler_pt)(ngx_conf_t *cf,
    ngx_command_t *dummy, void *conf);

/*
 * ngx在解析配置文件时描述每条指令的属性
 */
struct ngx_conf_s {
    //存放当前解析到的指令
    char                 *name;
    //存放每条指令包含的所有参数（逐行解析）
    ngx_array_t          *args;

    //ngx_cycle_t指针
    ngx_cycle_t          *cycle;
    //内存池对象
    ngx_pool_t           *pool;
    //用于解析配置文件的临时内存池，解析完成后释放
    ngx_pool_t           *temp_pool;
    //存放ngx配置文件的相关信息
    ngx_conf_file_t      *conf_file;
    ngx_log_t            *log;

    //描述指令的上下文。指向各个配置结构。指向ngx_cycle_t.conf_ctx
    void                 *ctx;
    //支持该指令的模块的类型，core、http、event和mail中的一种。等同于ngx_module_t.type
    ngx_uint_t            module_type;
    //指令的类型。等同于ngx_command_t.type前16位
    ngx_uint_t            cmd_type;

    //指令自定义的处理函数
    ngx_conf_handler_pt   handler;
    //自定义处理函数需要的相关配置
    char                 *handler_conf;
};


typedef char *(*ngx_conf_post_handler_pt) (ngx_conf_t *cf,
    void *data, void *conf);

typedef struct {
    ngx_conf_post_handler_pt  post_handler;
} ngx_conf_post_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} ngx_conf_deprecated_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    ngx_int_t                 low;
    ngx_int_t                 high;
} ngx_conf_num_bounds_t;


typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                value;
} ngx_conf_enum_t;


#define NGX_CONF_BITMASK_SET  1

typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                mask;
} ngx_conf_bitmask_t;



char * ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data);
char *ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data);


#define ngx_get_conf(conf_ctx, module)  conf_ctx[module.index]



#define ngx_conf_init_value(conf, default)                                   \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define ngx_conf_init_ptr_value(conf, default)                               \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }

#define ngx_conf_init_uint_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_size_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_msec_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_merge_value(conf, prev, default)                            \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = (prev == NGX_CONF_UNSET_PTR) ? default : prev;                \
    }

#define ngx_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = (prev == NGX_CONF_UNSET_UINT) ? default : prev;               \
    }

#define ngx_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = (prev == NGX_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define ngx_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_size_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = (prev == NGX_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define ngx_conf_merge_off_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }

#define ngx_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define ngx_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }


char *ngx_conf_param(ngx_conf_t *cf);
char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);
char *ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_int_t ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name,
    ngx_uint_t conf_prefix);
ngx_open_file_t *ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name);
void ngx_cdecl ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf,
    ngx_err_t err, const char *fmt, ...);


char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


extern ngx_uint_t     ngx_max_module;
extern ngx_module_t  *ngx_modules[];


#endif /* _NGX_CONF_FILE_H_INCLUDED_ */
