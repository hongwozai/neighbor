/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：error.h
 ** 创建人：路泽亚
 ** 描  述：错误处理模块，调试模块
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-13
 ********************************************************************/
#ifndef ERROR_H
#define ERROR_H

#include <errno.h>
#include <string.h>

#define ERR(msg, args...)                                               \
    printf("[%s,%d] "msg" (%s)\n", __FILE__, __LINE__, ##args, strerror(errno))

#define ERROR(msg, args...)                             \
    printf("[%s,%d] "msg"\n", __FILE__, __LINE__, ##args)

#define DEBUG(msg, args...)                             \
    printf("[%s,%d] "msg, __FILE__, __LINE__, ##args)

#endif /* ERROR_H */
