/* anet.c -- Basic TCP socket stuff made a bit less boring
 *
 * Copyright (c) 2006-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "fmacros.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "anet.h"

static void anetSetError(char *err, const char *fmt, ...) // 变参数fmt都放到err中
{
    va_list ap;

    if (!err) return;
    va_start(ap, fmt);
    vsnprintf(err, ANET_ERR_LEN, fmt, ap);
    va_end(ap);
}

int anetSetBlock(char *err, int fd, int non_block) { // 设置fd的阻塞状态
    int flags;

    /* Set the socket blocking (if non_block is zero) or non-blocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal. */
    if ((flags = fcntl(fd, F_GETFL)) == -1) { // 取得文件状态标志。比如只读、只写、可读可写等。
        anetSetError(err, "fcntl(F_GETFL): %s", strerror(errno));
        return ANET_ERR;
    }

    if (non_block)
        flags |= O_NONBLOCK; // 非阻塞IO
    else
        flags &= ~O_NONBLOCK; // 阻塞IO

    if (fcntl(fd, F_SETFL, flags) == -1) { // 设置文件状态标志
        anetSetError(err, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetNonBlock(char *err, int fd) { // fd设置为非阻塞
    return anetSetBlock(err,fd,1);
}

int anetBlock(char *err, int fd) {  // fd设置为阻塞
    return anetSetBlock(err,fd,0);
}

/* Set TCP keep alive option to detect dead peers. The interval option
 * is only used for Linux as we are using Linux-specific APIs to set
 * the probe send time, interval, and count. */
int anetKeepAlive(char *err, int fd, int interval) // 与KeepAlive有关的一些设置（有3个设置）
{
    /*
        TCP_KEEPDILE 设置连接上如果没有数据发送的话，多久后发送keepalive探测分组，单位是秒
        TCP_KEEPINTVL 前后两次探测之间的时间间隔，单位是秒
        TCP_KEEPCNT 关闭一个非活跃连接之前的最大重试次数
    */
    int val = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1) // SO_KEEPALIVE：设置心跳
    {
        anetSetError(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
        return ANET_ERR;
    }

#ifdef __linux__
    /* Default settings are more or less garbage, with the keepalive time
     * set to 7200 by default on Linux. Modify settings to make the feature
     * actually useful. */

    /* Send first probe after interval. */
    val = interval;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) { // level表示欲设置的网络层；optname表示欲设置的选项；optval为optname对应的值
        anetSetError(err, "setsockopt TCP_KEEPIDLE: %s\n", strerror(errno));
        return ANET_ERR;
    }

    /* Send next probes after the specified interval. Note that we set the
     * delay as interval / 3, as we send three probes before detecting
     * an error (see the next setsockopt call). */
    val = interval/3;
    if (val == 0) val = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {
        anetSetError(err, "setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
        return ANET_ERR;
    }

    /* Consider the socket in error state after three we send three ACK
     * probes without getting a reply. */
    val = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
        anetSetError(err, "setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
        return ANET_ERR;
    }
#else
    ((void) interval); /* Avoid unused var warning for non Linux systems. */
#endif

    return ANET_OK;
}

static int anetSetTcpNoDelay(char *err, int fd, int val)
{
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) == -1) // TCP_NODELAY：选项是用来禁用Nagle算法。Nagle算法思想：尽量多合并几个小包，并且TCP连接上最多只能有一个未被确认的小分组，在该分组的确认到达之前不能发送其他的小分组。
    {
        anetSetError(err, "setsockopt TCP_NODELAY: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetEnableTcpNoDelay(char *err, int fd) // 禁用Nagle算法
{
    return anetSetTcpNoDelay(err, fd, 1);
}

int anetDisableTcpNoDelay(char *err, int fd) // 开启Nagle算法
{
    return anetSetTcpNoDelay(err, fd, 0);
}


int anetSetSendBuffer(char *err, int fd, int buffsize) // 设置发送缓冲区的大小
{
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffsize, sizeof(buffsize)) == -1)
    {
        anetSetError(err, "setsockopt SO_SNDBUF: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetTcpKeepAlive(char *err, int fd) // 开启KeepAlive功能
{
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
        anetSetError(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

/* Set the socket send timeout (SO_SNDTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
int anetSendTimeout(char *err, int fd, long long ms) { // 设置一个发送超时值
    struct timeval tv;

    tv.tv_sec = ms/1000;
    tv.tv_usec = (ms%1000)*1000;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
        anetSetError(err, "setsockopt SO_SNDTIMEO: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

/* Set the socket receive timeout (SO_RCVTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
int anetRecvTimeout(char *err, int fd, long long ms) { // 设置一个接收超时值
    struct timeval tv;

    tv.tv_sec = ms/1000;
    tv.tv_usec = (ms%1000)*1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        anetSetError(err, "setsockopt SO_RCVTIMEO: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

/* anetGenericResolve() is called by anetResolve() and anetResolveIP() to
 * do the actual work. It resolves the hostname "host" and set the string
 * representation of the IP address into the buffer pointed by "ipbuf".
 *
 * If flags is set to ANET_IP_ONLY the function only resolves hostnames
 * that are actually already IPv4 or IPv6 addresses. This turns the function
 * into a validating / normalizing function. */
int anetGenericResolve(char *err, char *host, char *ipbuf, size_t ipbuf_len,
                       int flags) // GenericResolve：通用解析。将host的数值格式的地址，解析成点分十进制的ip地址格式
{
    /*
    struct addrinfo
    {
        int ai_flags;			// Input flags.  
        int ai_family;		// Protocol family for socket.  
        int ai_socktype;		// Socket type.  
        int ai_protocol;		// Protocol for socket.  
        socklen_t ai_addrlen;		// Length of socket address.  
        struct sockaddr *ai_addr;	// Socket address for socket.  
        char *ai_canonname;		// Canonical name for service location.  
        struct addrinfo *ai_next;	// Pointer to next in list.  
    };
    */
    struct addrinfo hints, *info;
    
    int rv;

    memset(&hints,0,sizeof(hints));
    if (flags & ANET_IP_ONLY) hints.ai_flags = AI_NUMERICHOST; // AI_NUMERICHOST：地址为数字串
    hints.ai_family = AF_UNSPEC; // AF_UNSPEC：协议无关
    hints.ai_socktype = SOCK_STREAM;  /* specify socktype to avoid dups */ // SOCK_STREAM：流

    if ((rv = getaddrinfo(host, NULL, &hints, &info)) != 0) { // hints：调用者在这个结构中填入关于期望返回的信息类型的暗示。info：返回一个addrinfo链表。
        anetSetError(err, "%s", gai_strerror(rv));
        return ANET_ERR;
    }

    /*
    struct sockaddr_in
    {
        __SOCKADDR_COMMON (sin_);
        in_port_t sin_port;			// Port number. 
        struct in_addr sin_addr;	// Internet address.  

        // Pad to size of `struct sockaddr'.  
        unsigned char sin_zero[sizeof (struct sockaddr) -
                __SOCKADDR_COMMON_SIZE -
                sizeof (in_port_t) -
                sizeof (struct in_addr)];
    };
    */
    if (info->ai_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)info->ai_addr;
        inet_ntop(AF_INET, &(sa->sin_addr), ipbuf, ipbuf_len); // 将网络传输的数值格式转化为点分十进制的ip地址格式
    } else { // ipv6
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)info->ai_addr;
        inet_ntop(AF_INET6, &(sa->sin6_addr), ipbuf, ipbuf_len);
    }

    freeaddrinfo(info); // 释放掉info链表
    return ANET_OK;
}

int anetResolve(char *err, char *host, char *ipbuf, size_t ipbuf_len) { // 根据host，获取点分十进制的ip地址格式
    return anetGenericResolve(err,host,ipbuf,ipbuf_len,ANET_NONE);
}

int anetResolveIP(char *err, char *host, char *ipbuf, size_t ipbuf_len) { // 根据host，获取点分十进制的ip地址格式
    return anetGenericResolve(err,host,ipbuf,ipbuf_len,ANET_IP_ONLY);
}

static int anetSetReuseAddr(char *err, int fd) { // 让端口释放后立即就可以被再次使用。
    int yes = 1;
    /* Make sure connection-intensive things like the redis benchmark
     * will be able to close/open sockets a zillion of times */
     
    // SO_REUSEADDR是让端口释放后立即就可以被再次使用。其意义是：
    // 如果我们终止一个已经建立连接的服务器程序，并试图立即重新启动这个服务器程序，服务器程序将不能把它的这个周知端口赋值给它的端点，因为那个端口是处于 2MSL 连接的一部分。
    // 在重新启动服务器程序前，它需要在 1~4 分钟。这就是很多网络服务器程序被杀死后不能够马上重新启动的原因（错误提示为“ Address already in use ”）。
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) { // SO_REUSEADDR是让端口释放后立即就可以被再次使用。
        anetSetError(err, "setsockopt SO_REUSEADDR: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

static int anetCreateSocket(char *err, int domain) { // 创建socket fd，并返回
    int s;
    if ((s = socket(domain, SOCK_STREAM, 0)) == -1) { // domain：ipv4或ipv6；将 protocol 的值设为 0，系统会自动推演出应该使用什么协议
        anetSetError(err, "creating socket: %s", strerror(errno));
        return ANET_ERR;
    }

    /* Make sure connection-intensive things like the redis benchmark
     * will be able to close/open sockets a zillion of times */
    if (anetSetReuseAddr(err,s) == ANET_ERR) {
        close(s);
        return ANET_ERR;
    }
    return s;
}

#define ANET_CONNECT_NONE 0
#define ANET_CONNECT_NONBLOCK 1
#define ANET_CONNECT_BE_BINDING 2 /* Best effort binding. */
static int anetTcpGenericConnect(char *err, const char *addr, int port,
                                 const char *source_addr, int flags) // 不是很明白，大概是：获取addrinfo，bind source_addr，然后connect
{
    int s = ANET_ERR, rv;
    char portstr[6];  /* strlen("65535") + 1; */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;

    snprintf(portstr,sizeof(portstr),"%d",port);
    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(addr,portstr,&hints,&servinfo)) != 0) { // 根据前3个参数，获取addrinfo信息链表
        anetSetError(err, "%s", gai_strerror(rv));
        return ANET_ERR;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        /* Try to create the socket and to connect it.
         * If we fail in the socket() call, or on connect(), we retry with
         * the next entry in servinfo. */
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1) // 根据addrinfo，创建socket
            continue;
        if (anetSetReuseAddr(err,s) == ANET_ERR) goto error;
        if (flags & ANET_CONNECT_NONBLOCK && anetNonBlock(err,s) != ANET_OK)
            goto error;
        if (source_addr) {
            int bound = 0;
            /* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
            /*
            可以导致返回多个addrinfo结构的情形有以下2个：
            1. 如果与hostname参数关联的地址有多个，那么适用于所请求地址簇的每个地址都返回一个对应的结构。
            2. 如果service参数指定的服务支持多个套接口类型，那么每个套接口类型都可能返回一个对应的结构，具体取决于hints结构的ai_socktype成员。
            */
            if ((rv = getaddrinfo(source_addr, NULL, &hints, &bservinfo)) != 0)
            {
                anetSetError(err, "%s", gai_strerror(rv));
                goto error;
            }
            for (b = bservinfo; b != NULL; b = b->ai_next) {
                if (bind(s,b->ai_addr,b->ai_addrlen) != -1) { // 对于TCP，调用bind函数可以指定一个端口号，或指定一个IP地址，也可以两者都指定，还可以都不指定。
                    bound = 1;
                    break;
                }
            }
            freeaddrinfo(bservinfo); // 用完接着释放掉
            if (!bound) { // 
                anetSetError(err, "bind: %s", strerror(errno));
                goto error;
            }
        }
        if (connect(s,p->ai_addr,p->ai_addrlen) == -1) { // 连接
            /* If the socket is non-blocking, it is ok for connect() to
             * return an EINPROGRESS error here. */
            if (errno == EINPROGRESS && flags & ANET_CONNECT_NONBLOCK)
                goto end;
            close(s);
            s = ANET_ERR;
            continue;
        }

        /* If we ended an iteration of the for loop without errors, we
         * have a connected socket. Let's return to the caller. */
        goto end;
    }
    if (p == NULL)
        anetSetError(err, "creating socket: %s", strerror(errno));

error:
    if (s != ANET_ERR) {
        close(s);
        s = ANET_ERR;
    }

end:
    freeaddrinfo(servinfo);

    /* Handle best effort binding: if a binding address was used, but it is
     * not possible to create a socket, try again without a binding address. */
    if (s == ANET_ERR && source_addr && (flags & ANET_CONNECT_BE_BINDING)) {
        return anetTcpGenericConnect(err,addr,port,NULL,flags);
    } else {
        return s;
    }
}

int anetTcpConnect(char *err, const char *addr, int port) // 阻塞连接
{
    return anetTcpGenericConnect(err,addr,port,NULL,ANET_CONNECT_NONE);
}

int anetTcpNonBlockConnect(char *err, const char *addr, int port) // 非阻塞连接
{
    return anetTcpGenericConnect(err,addr,port,NULL,ANET_CONNECT_NONBLOCK);
}

int anetTcpNonBlockBindConnect(char *err, const char *addr, int port,
                               const char *source_addr) // 应该是bind source_addr+非阻塞连接
{
    return anetTcpGenericConnect(err,addr,port,source_addr,
            ANET_CONNECT_NONBLOCK);
}

int anetTcpNonBlockBestEffortBindConnect(char *err, const char *addr, int port,
                                         const char *source_addr) // 不太懂
{
    return anetTcpGenericConnect(err,addr,port,source_addr,
            ANET_CONNECT_NONBLOCK|ANET_CONNECT_BE_BINDING);
}

int anetUnixGenericConnect(char *err, const char *path, int flags) // 用于本地连接。根据文件路径（比如/tmp/xxx）进行连接
{
    /*
    UNIX域套接字意义：
    UNIX域套接字用于在同一台机器上运行的进程之间的通信。
    虽然因特网域套接字可用于同一目的，但UNIX域套接字的效率更高。
    UNIX域套接字仅仅复制数据；它们并不执行协议处理，不需要添加或删除网络报头，无需计算检验和，不要产生顺序号，无需发送确认报文。
    */
    int s;
    struct sockaddr_un sa;

    if ((s = anetCreateSocket(err,AF_LOCAL)) == ANET_ERR)
        return ANET_ERR;

    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1); // sun_path成员也就是担任这个domain（域）的角色了，比如存储“/tmp/mydomain”这样的东西，再比如A和B之间通信，A应该有一个类似"/tmp/A"（名字可以自己随意起）的域，B应该有一个类似"/tmp/B"的域，通信时分别向对方的域发送消息，从自己的域接受消息。来自https://bbs.csdn.net/topics/390146250
    if (flags & ANET_CONNECT_NONBLOCK) {
        if (anetNonBlock(err,s) != ANET_OK) {
            close(s);
            return ANET_ERR;
        }
    }
    if (connect(s,(struct sockaddr*)&sa,sizeof(sa)) == -1) {
        if (errno == EINPROGRESS &&
            flags & ANET_CONNECT_NONBLOCK)
            return s;

        anetSetError(err, "connect: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    return s;
}

int anetUnixConnect(char *err, const char *path) // 默认下的本地连接
{
    return anetUnixGenericConnect(err,path,ANET_CONNECT_NONE);
}

int anetUnixNonBlockConnect(char *err, const char *path) // 非阻塞的本地连接
{
    return anetUnixGenericConnect(err,path,ANET_CONNECT_NONBLOCK);
}

/* Like read(2) but make sure 'count' is read before to return
 * (unless error or EOF condition is encountered) */
int anetRead(int fd, char *buf, int count) // 从fd中读取count个字符到buf中
{
    ssize_t nread, totlen = 0;
    while(totlen != count) {
        nread = read(fd,buf,count-totlen); // 从fd中读取count-totlen个字符到buf中
        if (nread == 0) return totlen;
        if (nread == -1) return -1;
        // 可能没有读完，再读剩下的那一部分
        totlen += nread; 
        buf += nread;
    }
    return totlen;
}

/* Like write(2) but make sure 'count' is written before to return
 * (unless error is encountered) */
int anetWrite(int fd, char *buf, int count) // 将buf中的count个字符写入fd中
{
    ssize_t nwritten, totlen = 0;
    while(totlen != count) { // 同上
        nwritten = write(fd,buf,count-totlen);
        if (nwritten == 0) return totlen;
        if (nwritten == -1) return -1;
        totlen += nwritten;
        buf += nwritten;
    }
    return totlen;
}

static int anetListen(char *err, int s, struct sockaddr *sa, socklen_t len, int backlog) { // 先bind fd，然后listen fd
    if (bind(s,sa,len) == -1) {
        anetSetError(err, "bind: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }

    if (listen(s, backlog) == -1) {
        anetSetError(err, "listen: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    return ANET_OK;
}

static int anetV6Only(char *err, int s) { // 只有ipv6，不兼容ipv4
    int yes = 1;
    if (setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,&yes,sizeof(yes)) == -1) { //setsockopt：获取或者设置与某个套接字关联的选项。IPPROTO_IPV6：IPV6相关选项。IPV6_V6ONLY：不兼容ipv4
        anetSetError(err, "setsockopt: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    return ANET_OK;
}

static int _anetTcpServer(char *err, int port, char *bindaddr, int af, int backlog) // 创建并监听套接字s，然后返回s
{
    int s = -1, rv;
    char _port[6];  /* strlen("65535") */
    struct addrinfo hints, *servinfo, *p;

    snprintf(_port,6,"%d",port);
    memset(&hints,0,sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;    /* No effect if bindaddr != NULL */

    if ((rv = getaddrinfo(bindaddr,_port,&hints,&servinfo)) != 0) { // 获取addrinfo列表
        anetSetError(err, "%s", gai_strerror(rv));
        return ANET_ERR;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1) // 创建socket
            continue;

        if (af == AF_INET6 && anetV6Only(err,s) == ANET_ERR) goto error; // 如果是AF_INET6，则设置成仅ipv6
        if (anetSetReuseAddr(err,s) == ANET_ERR) goto error; // 设置端口重用
        if (anetListen(err,s,p->ai_addr,p->ai_addrlen,backlog) == ANET_ERR) s = ANET_ERR; // 监听套接字s
        goto end;
    }
    if (p == NULL) {
        anetSetError(err, "unable to bind socket, errno: %d", errno);
        goto error;
    }

error:
    if (s != -1) close(s);
    s = ANET_ERR;
end:
    freeaddrinfo(servinfo);
    return s;
}

int anetTcpServer(char *err, int port, char *bindaddr, int backlog) // 创建socket，然后监听
{
    return _anetTcpServer(err, port, bindaddr, AF_INET, backlog);
}

int anetTcp6Server(char *err, int port, char *bindaddr, int backlog)
{
    return _anetTcpServer(err, port, bindaddr, AF_INET6, backlog); // 创建ipv6 socket，然后监听
}

int anetUnixServer(char *err, char *path, mode_t perm, int backlog) // 创建本地socket，并且监听s
{
    int s;
    struct sockaddr_un sa;

    if ((s = anetCreateSocket(err,AF_LOCAL)) == ANET_ERR)
        return ANET_ERR;

    memset(&sa,0,sizeof(sa));
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    if (anetListen(err,s,(struct sockaddr*)&sa,sizeof(sa),backlog) == ANET_ERR)
        return ANET_ERR;
    if (perm)
        chmod(sa.sun_path, perm); // 改变文件权限
    return s;
}

static int anetGenericAccept(char *err, int s, struct sockaddr *sa, socklen_t *len) { // 就是accept，返回fd
    int fd;
    while(1) {
        fd = accept(s,sa,len);
        if (fd == -1) {
            if (errno == EINTR)
                continue;
            else {
                anetSetError(err, "accept: %s", strerror(errno));
                return ANET_ERR;
            }
        }
        break;
    }
    return fd;
}

int anetTcpAccept(char *err, int s, char *ip, size_t ip_len, int *port) { // accept s，然后将数值格式转化为点分十进制的ip地址格式
    int fd;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err,s,(struct sockaddr*)&sa,&salen)) == -1)
        return ANET_ERR;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET,(void*)&(s->sin_addr),ip,ip_len); // 将数值格式转化为点分十进制的ip地址格式
        if (port) *port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sa;
        if (ip) inet_ntop(AF_INET6,(void*)&(s->sin6_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin6_port);
    }
    return fd;
}

int anetUnixAccept(char *err, int s) { // 就是accept
    int fd;
    struct sockaddr_un sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err,s,(struct sockaddr*)&sa,&salen)) == -1)
        return ANET_ERR;

    return fd;
}

int anetPeerToString(int fd, char *ip, size_t ip_len, int *port) { // 获取对方地址
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);

    if (getpeername(fd,(struct sockaddr*)&sa,&salen) == -1) goto error; // getpeername()用来获取对方地址
    if (ip_len == 0) goto error;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET,(void*)&(s->sin_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin_port);
    } else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sa;
        if (ip) inet_ntop(AF_INET6,(void*)&(s->sin6_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin6_port);
    } else if (sa.ss_family == AF_UNIX) {
        if (ip) strncpy(ip,"/unixsocket",ip_len);
        if (port) *port = 0;
    } else {
        goto error;
    }
    return 0;

error:
    if (ip) {
        if (ip_len >= 2) {
            ip[0] = '?';
            ip[1] = '\0';
        } else if (ip_len == 1) {
            ip[0] = '\0';
        }
    }
    if (port) *port = 0;
    return -1;
}

/* Format an IP,port pair into something easy to parse. If IP is IPv6
 * (matches for ":"), the ip is surrounded by []. IP and port are just
 * separated by colons. This the standard to display addresses within Redis. */
int anetFormatAddr(char *buf, size_t buf_len, char *ip, int port) { // 主要是区分ip和port。因为ip中如果有：，那么与port分离再用：就会混乱了。
    return snprintf(buf,buf_len, strchr(ip,':') ?
           "[%s]:%d" : "%s:%d", ip, port);
}

/* Like anetFormatAddr() but extract ip and port from the socket's peer. */
int anetFormatPeer(int fd, char *buf, size_t buf_len) { // 对对方ip的冒号问题进行处理，以区分ip和port
    char ip[INET6_ADDRSTRLEN];
    int port;

    anetPeerToString(fd,ip,sizeof(ip),&port);
    return anetFormatAddr(buf, buf_len, ip, port);
}

int anetSockName(int fd, char *ip, size_t ip_len, int *port) { // getsockname用于获取本端的地址，并将ip转换成点分十进制的形式
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);

    if (getsockname(fd,(struct sockaddr*)&sa,&salen) == -1) { // getsockname用于获取本端的地址。与getpeername相对
        if (port) *port = 0;
        ip[0] = '?';
        ip[1] = '\0';
        return -1;
    }
    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET,(void*)&(s->sin_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sa;
        if (ip) inet_ntop(AF_INET6,(void*)&(s->sin6_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin6_port);
    }
    return 0;
}

int anetFormatSock(int fd, char *fmt, size_t fmt_len) {  // 获取本地ip，然后将ip和port连接在一起
    char ip[INET6_ADDRSTRLEN];
    int port;

    anetSockName(fd,ip,sizeof(ip),&port);
    return anetFormatAddr(fmt, fmt_len, ip, port);
}
