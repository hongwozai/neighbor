/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：arp.h
 ** 创建人：路泽亚
 ** 描  述：arp模块:arp结构，arp响应,arp探测
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-17
 ********************************************************************/
#ifndef ARP_H
#define ARP_H

#include "define.h"

/* 使用需要转换 */
#define ARPHRDTYPE_ETHER   0x0001
#define ARPPROTYPE_IP      0x0800
#define ARPOPCODE_REQUEST  0x0001
#define ARPOPCODE_REPLY    0x0002

/* 长度8B */
struct ARP {
    /* 硬件地址类型 */
    uint16_t arp_hrd;
    /* arp承载协议类型 */
    uint16_t arp_pro;
    /* 硬件地址长度，就是6B */
    uint8_t  arp_hln;
    /* 协议地址长度，是ip长度 */
    uint8_t  arp_pln;
    /* arp操作吗，0x0001, 0x0002分别为请求与响应 */
    uint16_t arp_op;
};

/* 长度20B */
struct ARP_V4BODY {
    uint8_t  arp_shwaddr[6];
    uint32_t arp_sipaddr;
    uint8_t  arp_dhwaddr[6];
    uint32_t arp_dipaddr;
} __attribute__((packed));

typedef struct ARP ARP;
typedef struct ARP_V4BODY ARP_V4BODY;

#endif /* ARP_H */