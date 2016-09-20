/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：utime.c
 ** 创建人：路泽亚
 ** 描  述：时间模块，该模块与抓包模块应该是唯二与操作系统相关的部分
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-20
 ********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include "error.h"
#include "utime.h"

/********************************************************************
 ** 函数名：utime_get
 ** 创建人：路泽亚
 ** 描述：返回时间戳
 ** 参数：timestamp 传出参数
 ********************************************************************/
int utime_get(struct utime *timestamp)
{
    struct timeval tv;
    if (-1 == gettimeofday(&tv, NULL)) {
        ERR("gettimeofday error.");
        return -1;
    }
    timestamp->sec  = tv.tv_sec;
    timestamp->usec = tv.tv_usec;
    return 0;
}

/********************************************************************
 ** 函数名：print_utime
 ** 创建人：路泽亚
 ** 描述：调试时使用，打印时间戳
 ** 参数：timestamp
 ********************************************************************/
void print_utime(struct utime *timestamp)
{
    printf("%s: %lu", ctime(&(timestamp->sec)), timestamp->usec);
}

/********************************************************************
 ** 函数名：utime_str
 ** 创建人：路泽亚
 ** 描述：获得utime结构的字符串格式
 ** 参数：buf 长度必须足够， timestamp 传入参数
 ********************************************************************/
void utime_str(char *buf, struct utime *timestamp)
{
    sprintf(buf, "%s: %lu", ctime(&(timestamp->sec)), timestamp->usec);
}

/********************************************************************
 ** 函数名：utime_sleep
 ** 创建人：路泽亚
 ** 描述：睡眠定时，以微秒为单位
 ** 参数：usec 微秒
 ********************************************************************/
void utime_sleep(uint32_t usec)
{
    usleep(usec);
}