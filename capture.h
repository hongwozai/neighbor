/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：capture.h
 ** 创建人：路泽亚
 ** 描  述：抓包模块的头文件，输出接口,相当于第0层
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-13
 ********************************************************************/
#ifndef CAPTURE_H
#define CAPTURE_H

#include "define.h"

typedef struct cap {
    char ifdevice[IFDEVICE_LEN];
    int ifindex;
    int sockfd;
} cap_t;

extern cap_t* cap_init(char *dev, int promisc);
extern int    cap_capture(cap_t *cap, uint8_t *packet, uint16_t *len);
extern int    cap_send(cap_t *cap, uint8_t *packet, uint16_t size);
extern void   cap_close(cap_t *cap);

/* 获得和设置设备信息 */
extern int      cap_getdev_index(int fd, char *dev);
extern int      cap_getdev_name(int fd, int ifindex, char *device);
extern uint32_t cap_getdev_ifaddr(int fd, char *device);
extern uint32_t cap_getdev_ifnetmask(int fd, char *device);
extern int      cap_getdev_ifhwaddr(int fd, char *device, uint8_t *mac);
extern int      cap_setdev_promisc(int fd, int ifindex);

#endif /* CAPTURE_H */
