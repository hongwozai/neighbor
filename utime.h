/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：utime.h
 ** 创建人：路泽亚
 ** 描  述：时间模块，时间戳的生成，时间的打印等
 ** 注  意：1.微妙级别
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-20
 ********************************************************************/
#ifndef UTIME_H
#define UTIME_H

#include <time.h>

#include "define.h"

struct utime {
    time_t   sec;
    uint64_t usec;
};

extern int  utime_get(struct utime *timestamp);
extern void print_utime(struct utime *timestamp);
extern void utime_str(char *buf, struct utime *timestamp);
extern void utime_sleep(uint32_t usec);

#endif /* UTIME_H */
