# nginx
An official read-only mirror of http://hg.nginx.org/nginx/ which is updated hourly. Pull requests on GitHub cannot be accepted and will be automatically closed. The proper way to submit changes to nginx is via the nginx development mailing list, see http://nginx.org/en/docs/contributing_changes.html

#导读
文档基于Nginx官方Git的release1.9.9（2015-12-09）版本描述。分析此版本静态代码和在环境为gcc 4.1.2，64位Linux 2.6.18(Red Hat)下不带任何参数configure生成的动态代码（objs目录）。

#预备知识
c语言标准语法：出现频率比较高的，typedef、extern、static、volatile、void*等。

Linux环境编程：函数调用、系统调用（普通调用、慢调用）、exec（nginx热代码替换，二进制升级）、字节对齐、pagesize页对齐、多进程（深刻理解）、守护进程（通用作法；与进程作业命令nohup区别）、进程间通信IPC（信号量、unix本地域、共享内存、文件映射）、多线程、锁、普通I/O、标准I/O、文件描述符（最好知道系统经典实现）、I/O多路复用（重点关注epoll）、Socket相关调用、worker进程惊群及如何防止、原子操作、内存屏障，信号机制（安全信号）、定时器、argv与environ内存布局（最好知道进程经典内存布局）等。

gcc编译：auto、makefile等。

数据结构：内存池、连接池、文件池、链表、队列、红黑树等。

#目录结构

nginx/
		auto/			#自动化脚本
		
		conf/			#配置模板
		
		contrib/
		
		docs/
		
		misc/
		
		objs/			#环境相关，由auto生成
		src/			#源代码
			core/		#核心，入口
			event/	#事件相关	epoll、select
			http/		#http相关
			mail/		#mail相关
			misc/		#杂项
			mysql/	#mysql相关
			os/
				unix/		#unix系统相关接口
				win32/	#windows系统相关接口
			stream/		#流相关

