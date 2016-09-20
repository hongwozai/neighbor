/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：utils.h
 ** 创建人：路泽亚
 ** 描  述：公用函数
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-14
 ********************************************************************/
#ifndef UTILS_H
#define UTILS_H

#include "define.h"

/* bit部分 */
extern uint16_t reversebit16(uint16_t byte);
extern uint32_t reversebit32(uint32_t byte);
extern uint64_t reversebit64(uint64_t byte);

/* char部分 */
extern void     print_uchar(uint8_t ch);
extern void     print_char(uint8_t ch);
extern char*    char2hex(uint8_t ch);
extern void     char2hex_r(uint8_t ch, char *buf);
extern char     char2print(uint8_t ch);
extern uint8_t  hex2char(char *buf);

/* mac部分 */
extern void     print_mac(uint8_t *mac);
extern void     mac_addr(char *addr, uint8_t *mac);
extern char*    mac_ntoa(uint8_t *mac);
extern void     mac_ntoa_r(uint8_t *mac, char *addr);

/* ip部分 */
extern void     print_ipv4(uint32_t ip);
extern uint32_t ipv4_addr(char *addr);
extern char*    ipv4_ntoa(uint32_t ip);
extern void     ipv4_ntoa_r(uint32_t ip, char *addr);
extern int      ipv4_count(uint32_t netmask);
extern uint32_t ipv4_netmask(int count);

extern void     ipv4_walk_host(uint32_t ip, uint32_t netmask,
                               int (*walk_func)(uint32_t ip));
/* 大小端转换部分 */
extern uint16_t hton16(uint16_t host16);
extern uint16_t ntoh16(uint16_t net16);
extern uint32_t hton32(uint32_t host32);
extern uint32_t ntoh32(uint32_t net32);

/* 包处理 */
extern void     print_packet(uint8_t *buf, int len);
extern uint16_t chksum(uint8_t *addr, uint16_t count);
extern uint16_t chksum_pseudo(uint8_t *addr, uint16_t count,
                              uint32_t src_ip, uint32_t dest_ip,
                              uint8_t protocol);

#endif /* UTILS_H */
