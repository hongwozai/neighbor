/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：mem.h
 ** 创建人：路泽亚
 ** 描  述：内存管理模块
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-17
 ********************************************************************/
#ifndef MEM_H
#define MEM_H

#include <stdlib.h>

#define NEW(p)                                  \
    ((p) = malloc(sizeof(*p)))

#define NEW0(p)                                 \
    ((p) = calloc(1, sizeof(*p)))

#define MALLOC(p, size)                         \
    ((p) = malloc(size))

#define FREE(p)                                 \
    (free(p))

#endif /* MEM_H */
