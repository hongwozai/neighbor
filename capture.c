/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：capture.c
 ** 创建人：路泽亚
 ** 描  述：抓包模块，所有抓包的模块应该在这里封装
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-13
 ********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "capture.h"
#include "define.h"
#include "error.h"
#include "mem.h"
#include "utils.h"

/********************************************************************
 ** 函数名：cap_init
 ** 创建人：路泽亚
 ** 描述：创建AF_PACKET套接字，并绑定地址，打开混杂模式
 ** 参数：dev 网卡名称，promisc 1为混杂模式，0不打开混杂模式
 ********************************************************************/
cap_t *cap_init(char *dev, int promisc)
{
    int fd = -1;
    cap_t *cap = NULL;
    int optval = 0, optlen = 0;
    struct sockaddr_ll addr;

    if (!dev)
        goto error;
    if (!NEW0(cap)) {
        ERR("cap_init new0 error.");
        goto error;
    }
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        ERR("cap_init socket error.");
        FREE(cap);
        goto error;
    }
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = cap_getdev_index(fd, dev);

    /* 绑定地址，仅从该地址接受包 */
    if (-1 == bind(fd, (struct sockaddr*)&addr, sizeof(addr))) {
        ERR("cap_init bind error.");
        FREE(cap);
        close(fd);
        goto error;
    }
    strcpy(cap->ifdevice, dev);
    cap->ifindex  = addr.sll_ifindex;
    cap->sockfd   = fd;

    optlen = 4;
    /* 检查是否有错，例如网卡是否打开（处于RUNNING状态） */
    if (-1 == getsockopt(cap->sockfd, SOL_SOCKET, SO_ERROR,
                         &optval, (socklen_t*)&optlen)) {
        ERR("cap_init getsockopt error.");
    }
    if (optval) {
        ERROR("cap_init SO_ERROR.(%s)", strerror(optval));
        goto error;
    }

    /* 打开混杂模式 */
    if (promisc)
        if (-1 == cap_setdev_promisc(cap->sockfd, cap->ifindex))
            ERR("can't open promisc mode.");
    return cap;
error:
    return NULL;
}

/********************************************************************
 ** 函数名：cap_capture
 ** 创建人：路泽亚
 ** 描述：抓包，抓包返回的是原始数据包
 ** 参数：cap 句柄， packet 包的缓冲区，len 包的长度
 **      成功返回0， 失败返回-1
 ********************************************************************/
int cap_capture(cap_t *cap, uint8_t *packet, uint16_t *len)
{
    int flag;

    assert(cap);
    flag = recv(cap->sockfd, packet, PACKET_MAX_LEN, 0);
    if (flag == -1) {
        ERR("cap_capture read error.");
        return -1;
    }
    *len = flag;
    return 0;
}

/********************************************************************
 ** 函数名：cap_send
 ** 创建人：路泽亚
 ** 描述：发送包，发送的端口是之前绑定的
 ** 参数：cap 句柄，packet 指向包头的指针，size 包的长度
 ********************************************************************/
int cap_send(cap_t *cap, uint8_t *packet, uint16_t size)
{
    int len;

    if (!cap || !packet)
        return -1;
    len = send(cap->sockfd, packet, size, 0);
    if (len == -1) {
        ERR("cap_send write error.");
        return -1;
    }
    return len;
}

/********************************************************************
 ** 函数名：cap_close
 ** 创建人：路泽亚
 ** 描述：关闭套接字，并释放句柄
 ** 参数：cap 句柄
 ********************************************************************/
void cap_close(cap_t *cap)
{
    if (!cap)
        return;
    close(cap->sockfd);
    FREE(cap->ifdevice);
    FREE(cap);
}

/********************************************************************
 ** 函数名：cap_getdev_index
 ** 创建人：路泽亚
 ** 描述：获得对应网络设备的序号
 ** 参数：fd 套接字，dev 设备名称
 ********************************************************************/
int cap_getdev_index(int fd, char *dev)
{
    int index;
    struct ifreq interface;

    strncpy(interface.ifr_name, dev, sizeof(interface.ifr_name));
    /* any代表所有网卡 */
    if (0 == strncmp(dev, "any", 3)) {
        index = 0;
    } else {
        if (-1 == ioctl(fd, SIOCGIFINDEX, &interface)) {
            ERR("cap_getdev_index ioctl error.");
            return -1;
        }
        index = interface.ifr_ifindex;
    }
    return index;
}

/********************************************************************
 ** 函数名：cap_getdev_ifaddr
 ** 创建人：路泽亚
 ** 描述：获得接口的ip地址
 ** 参数：fd 套接字， device 设备名称
 **      返回0失败，返回非0则为正常ip
 ********************************************************************/
uint32_t cap_getdev_ifaddr(int fd, char *device)
{
    struct ifreq req;

    strncpy(req.ifr_name, device, sizeof(req.ifr_name));
    if (-1 == ioctl(fd, SIOCGIFADDR, &req)) {
        ERR("cap_getdev_ifaddr error.");
        return 0;
    }
    return ((struct sockaddr_in*)(&req.ifr_addr))->sin_addr.s_addr;
}

/********************************************************************
 ** 函数名：cap_getdev_ifnetmask
 ** 创建人：路泽亚
 ** 描述：获得接口对应的子网掩码
 ** 参数：fd 套接字，device 设备名称
 **      返回0失败，返回非0则为正常netmask
 ********************************************************************/
uint32_t cap_getdev_ifnetmask(int fd, char *device)
{
    struct ifreq req;

    strncpy(req.ifr_name, device, sizeof(req.ifr_name));
    if (-1 == ioctl(fd, SIOCGIFNETMASK, &req)) {
        ERR("cap_getdev_ifaddr error.");
        return 0;
    }
    return ((struct sockaddr_in*)(&req.ifr_addr))->sin_addr.s_addr;
}

/********************************************************************
 ** 函数名：cap_getdev_ifhwaddr
 ** 创建人：路泽亚
 ** 描述：获得接口的mac地址
 ** 参数：fd 套接字，device 设备名称
 ********************************************************************/
int cap_getdev_ifhwaddr(int fd, char *device, uint8_t *mac)
{
    struct ifreq req;

    if (!mac)
        return -1;
    strncpy(req.ifr_name, device, sizeof(req.ifr_name));
    if (-1 == ioctl(fd, SIOCGIFHWADDR, &req)) {
        ERR("cap_getdev_ifhwaddr error.");
        return -1;
    }
    memcpy(mac, req.ifr_hwaddr.sa_data, 6);
    return 0;
}

/********************************************************************
 ** 函数名：cap_getdev_name
 ** 创建人：路泽亚
 ** 描述：根据索引获得名称
 ** 参数：fd 套接字，ifindex 设备索引，device 传出参数（名称长度固定IFNAMSIZ）
 ********************************************************************/
int cap_getdev_name(int fd, int ifindex, char *device)
{
    struct ifreq req;

    req.ifr_ifindex = ifindex;
    if (-1 == ioctl(fd, SIOCGIFNAME, &req)) {
        ERR("cap_getdev_name error.");
        return -1;
    }
    strncpy(device, req.ifr_name, sizeof(req.ifr_name));
    return 0;
}

/********************************************************************
 ** 函数名：cap_setdev_promisc
 ** 创建人：路泽亚
 ** 描述：设置设置混杂模式
 ** 参数：fd 套接字，index 设备的索引编号
 ********************************************************************/
int cap_setdev_promisc(int fd, int index)
{
    struct packet_mreq member;

    member.mr_ifindex = index;
    member.mr_type    = PACKET_MR_PROMISC;
    if (-1 == setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                         &member, sizeof(member))) {
        ERR("cap_setdev_promisc setsockopt error.");
        return -1;
    }
    return 0;
}