 //***************************************************************
 // @file:    des.h
 // @author:  dingfang
 // @date    2019-04-28 21:41:53
 //***************************************************************
 
#ifndef __DES_C__
#define __DES_C__

/* 
 * key 长度是8个字节
 * iv 一般是8个字节
 * */

/*
 * 函数说明: des cbc 模式加密
 * 参数: input: 需要加密的字符串
 *       inSize: input长度
 *       output: 加密后的字符串
 *       outSize: output的长度
 *       key: 加密秘钥
 *       iv: 加密向量
 * 返回值: 0 成功
 * */
int DesCBCEncode(char *const input, int inSize, char *output, int *outSize, unsigned char *const key, unsigned char *iv);

/*
 * 函数说明: des cbc 模式解密
 * 参数: input: 需要加密的字符串
 *       inSize: input长度
 *       output: 加密后的字符串
 *       outSize: output的长度
 *       key: 加密秘钥
 *       iv: 加密向量
 * 返回值: 0 成功
 * */
int DesCBCDecode(char *const input, int inSize, char *output, int *outSize, unsigned char *const key, unsigned char *iv);

/* 对外不调用 */
static int DEScrypto(char *const input, int len, char *output, int *outlen, unsigned char *const key, unsigned char *iv, int enc);


#endif /* __DES_C__ */
