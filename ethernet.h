/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：ethernet.h
 ** 创建人：路泽亚
 ** 描  述：以太网模块
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-17
 ********************************************************************/
#ifndef ETHERNET_H
#define ETHERNET_H

#include "define.h"

/* 使用需要转换 */
#define ETHTYPE_IP                   0x0800
#define ETHTYPE_ARP                  0x0806
#define ETHTYPE_RARP                 0x8035
#define ETHTYPE_IPV6                 0x86dd
#define ETHTYPE_VLAN                 0x8100
/* pppoe发现阶段 */
#define ETHTYPE_PPPOE_DISCOVERY      0x8863
/* pppoe会话阶段 */
#define ETHTYPE_PPPOE_SESSION        0x8864

/* 以太网长度14B */
struct ETHER {
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    /* 上层协议类型 */
    uint16_t ether_type;
} __attribute__((packed));

typedef struct ETHER ETHER;

/**
 * 以太网包60字节时无需crc32校验,
 * 遇到udp,icmp,tcp等有校验的无需crc32校验
 * 其余大于64字节的时候需要校验
 */

#endif /* ETHERNET_H */

