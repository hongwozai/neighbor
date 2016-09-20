/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：l1.h
 ** 创建人：路泽亚
 ** 描  述：第一层对外提供的接口，包括给上层的和其余程序使用的
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-19
 ********************************************************************/
#ifndef L1_H
#define L1_H

#include "define.h"
#include "utime.h"
#include "capture.h"

/* ========== l1层对l2层接口 ============= */
struct packet {
    uint8_t *buf;
    uint16_t len;
    struct utime timestamp;
};
/* packet结构不填mac层头部，接收发送都不必考虑上层 */
extern int l1_recv(cap_t *cap, struct packet *pkt);
extern int l1_send(cap_t *cap, struct packet *pkt, uint32_t ip);

/* ============= 操作arp缓存 ============= */
typedef int arp_cache_walk_func(void *buf, uint32_t ip, uint8_t *mac,
                                uint8_t ifindex);
extern void     arp_cache_update(uint32_t ip, uint8_t *mac, uint8_t ifindex);
extern uint8_t* arp_cache_find(uint32_t ip);
extern void     arp_cache_del(uint32_t ip);
/* 遍历所需函数 */
extern void     arp_cache_walk(arp_cache_walk_func callback, void *buf);
extern void     arp_cache_cleanup();

/* ============== 构造arp包 ============== */
extern void build_arp_request(uint8_t *buf, int size, uint8_t *src_mac,
                              uint32_t src_ip, uint32_t dst_ip);
extern void build_arp_reply(uint8_t *buf, int size, uint8_t *src_mac,
                            uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip);
extern int analysis_isarp(uint8_t *buf);
extern int analysis_isip(uint8_t *buf);

#endif /* L1_H */
