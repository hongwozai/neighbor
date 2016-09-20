/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：utils.c
 ** 创建人：路泽亚
 ** 描  述：
 ** 注  意：本程序是否有些特殊说明
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-14
 ********************************************************************/
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "define.h"
#include "utils.h"

/* ========================= 关于位的操作 ============================= */
uint16_t reversebit16(uint16_t byte)
{
    uint32_t ret = 0, i = 15;
    while (byte) {
        if (byte & 1) {
            ret |= (1 << i);
        }
        byte >>= 1;
        i -= 1;
    }
    return ret;
}

uint32_t reversebit32(uint32_t byte)
{
    uint32_t ret = 0, i = 31;
    while (byte) {
        if (byte & 1) {
            ret |= (1 << i);
        }
        byte >>= 1;
        i -= 1;
    }
    return ret;
}

uint64_t reversebit64(uint64_t byte)
{
    uint32_t ret = 0, i = 63;
    while (byte) {
        if (byte & 1) {
            ret |= (1 << i);
        }
        byte >>= 1;
        i -= 1;
    }
    return ret;
}

/* ========================= 关于单个字符 ============================= */
void print_uchar(uint8_t ch)
{
    printf("%02x", ch);
}

void print_char(uint8_t ch)
{
    if (!isprint(ch)) {
        ch = '.';
    }
    printf("%c", ch);
}

/* is not mt-safe */
char *char2hex(uint8_t ch)
{
    static char buf[3];
    snprintf(buf, 2, "%02x", ch);
    return buf;
}

/* is mt-safe */
void char2hex_r(uint8_t ch, char *buf)
{
    snprintf(buf, 2, "%02x", ch);
}

char char2print(uint8_t ch)
{
    if (!isprint(ch)) {
        ch = '.';
    }
    return (char)ch;
}

/* 16进制字符转为正常的数字 */
uint8_t hex2char(char *buf)
{
    uint8_t ch;
    sscanf(buf, "%02X", (uint32_t*)&ch);
    return ch;
}

/* ======================== 关于mac的转换 ============================ */
void print_mac(uint8_t *mac)
{
    int i;
    print_uchar(mac[0]);
    for (i = 1; i < 6; i++) {
        printf(":");
        print_uchar(mac[i]);
    }
}

/* is mt-safe */
void mac_addr(char *addr, uint8_t *mac)
{
    int i;
    char buf[3], *p = addr;

    for (i = 0; i < 6; i++) {
        memcpy(buf, p, 2);
        p += 3;
        sscanf(buf, "%02hhX", &mac[i]);
    }
}

/* is not mt-safe 总共18个字符 */
char *mac_ntoa(uint8_t *mac)
{
    static char addr[18];
    sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return addr;
}

/* is mt-safe */
void mac_ntoa_r(uint8_t *mac, char *addr)
{
    sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ======================= 关于ip的转换 ============================ */
/* 在这里按大端序来计算 */
void print_ipv4(uint32_t ip)
{
    printf("%d.%d.%d.%d",
           (ip & 0xff), (ip & 0xff00) >> 8,
           (ip & 0xff0000) >> 16, (ip & 0xff000000) >> 24);
}

/* FIXME: 如果地址不是ip格式，会有严重错误 */
/* 所得到的是大端ip */
uint32_t ipv4_addr(char *addr)
{
    char buf[16], *older, *p;
    uint32_t ret = 0;

    /* strncpy并非始终添加\0 */
    strncpy(buf, addr, 15);
    buf[15] = '\0';

    /* one */
    older = p = buf;
    p = strchr(p, '.');
    if (!p) return 0;
    *p = '\0';
    ret = atoi(older);

    /* two */
    older = p = p + 1;
    p = strchr(p, '.');
    if (!p) return 0;
    *p = '\0';
    ret |= atoi(older) << 8;

    /* three */
    older = p = p + 1;
    p = strchr(p, '.');
    if (!p) return 0;
    *p = '\0';
    ret |= atoi(older) << 16;

    /* four */
    older = p + 1;
    ret |= atoi(older) << 24;
    return ret;
}

/* not is mt-safe */
char *ipv4_ntoa(uint32_t ip)
{
    static char buf[16];
    snprintf(buf, 16, "%d.%d.%d.%d",
             (ip & 0xff), (ip & 0xff00) >> 8,
             (ip & 0xff0000) >> 16, (ip & 0xff000000) >> 24);
    return buf;
}

/* is mt-safe */
void ipv4_ntoa_r(uint32_t ip, char *addr)
{
    snprintf(addr, 16, "%d.%d.%d.%d",
             (ip & 0xff), (ip & 0xff00) >> 8,
             (ip & 0xff0000) >> 16, (ip & 0xff000000) >> 24);
}

/* 得到掩码位数(计算其中1的个数) */
int ipv4_count(uint32_t netmask)
{
    int count = 0;
    uint32_t i = 1;

    for (; i != 0; i <<= 1)
        if (netmask & i)
            count++;
    return count;
}

/* 由掩码位数构造ip */
uint32_t ipv4_netmask(int count)
{
    int i;
    uint32_t net = 0;

    assert(count >= 0 && count <= 32);
    for (i = 1; i <= count; i++) {
        net += (1 << (32 - i));
    }
    net = hton32(net);
    return net;
}

/* 遍历该ip与netmask所在的子网(传递大端序ip与netmask)
 * 计算时需要使用小端序 */
void ipv4_walk_host(uint32_t ip, uint32_t netmask,
                    int (*walk_func)(uint32_t ip))
{
    uint32_t subnet  = ntoh32(ip & netmask);
    uint32_t maxhost = ntoh32((ip & netmask) | (~netmask));

    if (!walk_func)
        return;
    for (; subnet <= maxhost; subnet++) {
        walk_func(hton32(subnet));
    }
}

/* ========================= 大小端转换 ============================ */
uint16_t hton16(uint16_t host16)
{
    uint16_t ret;
    /* 小端转大端 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    ret = ((host16 & 0xff) << 8) | (host16 >> 8);
#else
    ret = host16;
#endif
    return ret;
}

uint16_t ntoh16(uint16_t net16)
{
    uint16_t ret;
    /* 大端转小端 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    ret = ((net16 & 0xff) << 8) | (net16 >> 8);
#else
    ret = net16;
#endif
    return ret;
}

uint32_t hton32(uint32_t host32)
{
    uint32_t ret;
    /* 小端转大端 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    ret = ((host32 & 0xff) << 24) | ((host32 & 0xff000000) >> 24) |
        ((host32 & 0xff00) << 8) | ((host32 & 0xff0000) >> 8);
#else
    ret = host32;
#endif
    return ret;
}

uint32_t ntoh32(uint32_t net32)
{
    uint32_t ret;
    /* 大端转小端 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    ret = ((net32 & 0xff) << 24) | ((net32 & 0xff000000) >> 24) |
        ((net32 & 0xff00) << 8) | ((net32 & 0xff0000) >> 8);
#else
    ret = net32;
#endif
    return ret;
}

/* =========================== 包处理 =============================== */
void print_packet(uint8_t *buf, int len)
{
    int i, j;
    printf("packet len: %d\n", len);
    for (i = 0; i < len; i++) {
        print_uchar(buf[i]);
        printf(" ");
        if (((i + 1) % 8 == 0) & ((i + 1) % 16 != 0)) {
            printf(" ");
        } else if (((i + 1) % 8 == 0) & ((i + 1) % 16 == 0)) {
            for (j = 0; j < 16; j++) {
                print_char(buf[j]);
                if (j == 7)
                    printf(" ");
            }
            printf("\n");
        }
    }
    /* TODO:补齐最后一行 */
    printf("\n");
}

uint16_t chksum(uint8_t *addr, uint16_t count)
{
    register unsigned int sum = 0;
    uint16_t *addr16 = (uint16_t*)addr;

    /**
     * 每16位相加（相加的进位需要加回）
     * 最后求反
     */
    while (count > 1) {
        sum += *addr16++;
        /* 这样做防止需要加的数字太多,使sum超过32位 */
        if (sum >= 0x10000) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *)addr16;
    }
    return ~(uint16_t)sum;
}

/* 协议字段为具体协议的编号(主机字节序)，用于udp与tcp */
uint16_t chksum_pseudo(uint8_t *addr, uint16_t count,
                       uint32_t src_ip, uint32_t dest_ip,
                       uint8_t protocol)
{
    register unsigned int sum = 0;
    uint16_t *addr16 = (uint16_t*)addr;
    uint16_t len = count;

    while (count > 1) {
        sum += *addr16++;
        if (sum >= 0x10000) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *)addr16;
    }
    sum += (src_ip & 0xffff) + (src_ip >> 16);
    sum += (dest_ip & 0xffff) + (dest_ip >> 16);
    sum += hton16(protocol);
    sum += hton16(len);
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}