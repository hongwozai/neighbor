/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：getarg.c
 ** 创建人：路泽亚
 ** 描  述：getarg 获取命令行参数的实现
 ** 注  意：1. FIXME: 当第二个字符为:时会有错误
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-20
 ********************************************************************/
#include <stdio.h>
#include <string.h>

#include "getarg.h"

/* 环境 */
char *optarg = NULL;
int   optind = 1;

/* ?代表语法错误, :代表有对应值，只有名称时返回-1且什么也不做 */
int getarg(int argc, char *argv[], const char *optstring)
{
    char *p, *key, *value;

    if (argc == 1 || !optstring || optind >= argc)
        return -1;
    key = argv[optind];
    /* 如果参数第一个字符不等于-,就是语法错误（getarg会越过键值，
     * 每次只遍历key） */
    if (key[0] != '-') {
        optind = argc;
        return '?';
    }
    /* 如果参数第二个字符在optstring中找不到，就是语法错误 */
    if (!(p = strchr(optstring, key[1]))) {
        optind = argc;
        return '?';
    }
    /* optstring中对应的字符后没有:，那么就直接返回
     * 如果有:那么取之后的一个参数（其中会对该参数进行验证，判断是否第一个字符为-）
     */
    if (*(p + 1) != ':') {
        optind++;
        return *p;
    }
    /* 判断之后的参数，要先做越界保护 */
    if (optind == argc) {
        return '?';
    }
    value = argv[optind + 1];
    if (value[0] == '-') {
        optind = argc;
        return '?';
    }
    optarg = value;
    optind += 2;
    return *p;
}
