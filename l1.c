/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：l1.c
 ** 创建人：路泽亚
 ** 描  述：l1层主逻辑
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-19
 ********************************************************************/
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#include "arp.h"
#include "ethernet.h"

void build_arp_request(uint8_t *buf, int size, uint8_t *src_mac,
                       uint32_t src_ip, uint32_t dst_ip)
{
    ETHER *mac = NULL;
    ARP *arp = NULL;
    ARP_V4BODY *body = NULL;

    assert(buf);
    assert(src_mac);
    mac  = (ETHER*)buf;
    arp  = (ARP*)(buf + sizeof(ETHER));
    body = (ARP_V4BODY*)(buf + sizeof(ETHER) + sizeof(ARP));
    /* 构造包 */
    memcpy(mac->ether_src, src_mac, 6);
    memset(mac->ether_dst, 0xff, 6);
    mac->ether_type = hton16(ETHTYPE_ARP);
    arp->arp_hrd    = hton16(ARPHRDTYPE_ETHER);
    arp->arp_pro    = hton16(ARPPROTYPE_IP);
    arp->arp_hln    = 0x6;
    arp->arp_pln    = 0x4;
    arp->arp_op     = hton16(ARPOPCODE_REQUEST);
    memcpy(body->arp_shwaddr, mac->ether_src, 6);
    memset(body->arp_dhwaddr, 0, 6);
    body->arp_dipaddr = dst_ip;
    body->arp_sipaddr = src_ip;
    /* 填充剩余字节 */
    /* TODO: 长于64字节的进行crc校验 */
    memset(buf + sizeof(ETHER) + sizeof(ARP) + sizeof(ARP_V4BODY),
           0,
           size - sizeof(ETHER) - sizeof(ARP) - sizeof(ARP_V4BODY));
}

void build_arp_reply(uint8_t *buf, int size, uint8_t *src_mac,
                     uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip)
{
    ETHER *mac = NULL;
    ARP *arp = NULL;
    ARP_V4BODY *body = NULL;

    assert(buf);
    assert(src_mac);
    mac  = (ETHER*)buf;
    arp  = (ARP*)(buf + sizeof(ETHER));
    body = (ARP_V4BODY*)(buf + sizeof(ETHER) + sizeof(ARP));
    /* 构造包 */
    memcpy(mac->ether_src, src_mac, 6);
    memcpy(mac->ether_dst, dst_mac, 6);
    mac->ether_type = hton16(ETHTYPE_ARP);
    arp->arp_hrd    = hton16(ARPHRDTYPE_ETHER);
    arp->arp_pro    = hton16(ARPPROTYPE_IP);
    arp->arp_hln    = 0x6;
    arp->arp_pln    = 0x4;
    arp->arp_op     = hton16(ARPOPCODE_REPLY);
    memcpy(body->arp_shwaddr, mac->ether_src, 6);
    memcpy(body->arp_dhwaddr, mac->ether_dst, 6);
    body->arp_dipaddr = dst_ip;
    body->arp_sipaddr = src_ip;
    /* 填充剩余字节 */
    /* TODO: 长于64字节的进行crc校验 */
    memset(buf + sizeof(ETHER) + sizeof(ARP) + sizeof(ARP_V4BODY),
           0,
           size - sizeof(ETHER) - sizeof(ARP) - sizeof(ARP_V4BODY));
}

/********************************************************************
 ** 函数名：analysis_isarp
 ** 创建人：路泽亚
 ** 描述：解析是否为arp包
 ** 参数：buf 传递的原始数据包
 **      是返回1，不是返回0
 ********************************************************************/
int analysis_isarp(uint8_t *buf)
{
    ETHER *ether = (ETHER*)buf;
    return (ether->ether_type == hton16(ETHTYPE_ARP));
}

/********************************************************************
 ** 函数名：analysis_isip
 ** 创建人：路泽亚
 ** 描述：判断是否为ip包
 ** 参数：buf 传递的原始数据包
 **      是返回1, 不是返回0
 ********************************************************************/
int analysis_isip(uint8_t *buf)
{
    ETHER *ether = (ETHER*)buf;
    return (ether->ether_type == hton16(ETHTYPE_IP));
}

/**
 * arp缓存更新时机
 * 1. 主机收到arp请求时，先检查数据包的目的ip与自己的ip是否一致
 *    一致则更新arp缓存（没有则添加，有就判断是否一样，不一样就直接更新）
 *    （当有主机更换网卡时，会向网络内无应答广播，如果arp缓存中有就更新，没有就忽略）
 * 2. 收到应答包时，会将本地arp缓存更新
 */