/********************************************************************
 ** Copyright(c) 2016,哈尔滨工程大学信息安全研究中心
 ** All rights reserved
 **
 ** 文件名：getarg.h
 ** 创建人：路泽亚
 ** 描  述：getarg 获取命令行参数
 ** 注  意：1.
 **
 ** 当前版本： v1.0
 ** 作    者：路泽亚
 ** 完成日期： 2016-04-20
 ********************************************************************/
#ifndef GETARG_H
#define GETARG_H

extern char *optarg;
extern int optind;

extern int getarg(int argc, char *argv[], const char *optstring);

#endif /* GETARG_H */
