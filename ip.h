/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：ip.h
 ** 创建人：路泽亚
 ** 描  述：ip包的结构体
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-22
 ********************************************************************/
#ifndef IP_H
#define IP_H

#include "define.h"

#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */

struct IP {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4;		/* header length */
    uint8_t ip_v:4;		/* version */
#else
    uint8_t ip_v:4;		/* version */
    uint8_t ip_hl:4;		/* header length */
#endif
    uint8_t  ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
    uint8_t  ip_ttl;			/* time to live */
    uint8_t  ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    uint32_t ip_src, ip_dst;	/* source and dest address */
};

typedef struct IP IP;

#endif /* IP_H */
