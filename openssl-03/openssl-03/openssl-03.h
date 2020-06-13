#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <memory.h>
#include <malloc.h>
#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp_locl.h>

// ---- rsa非对称加解密 ---- //    
#define KEY_LENGTH  2048               // 密钥长度  
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径  
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径  
#define RSA_BITS        2048		//rsa长度
#define RSA_PASS        "123"		//rsa密钥口令
#define X509_REQ_VERSION 1			
#define X509_REQ_COMMON_NAME "openssl"
#define X509_REQ_COUNTRY_NAME "cn"
#define X509_REQ_ORGANIZATION_NAME "cn"
#define X509_REQ_ORGANIZATION_UNIT_NAME "cn"
#define X509_REQ_CSR_PATH "certreq.csr"

#define X509_CERT_VERSION1 0
#define X509_CERT_VERSION2 1
#define X509_CERT_VERSION3 2
#define X509_SERIAL_NUMBER 3
#define X509_CERT_FILEPATH "ca.cer"

#define PKCS12_PASSPHRSE "sa"

int generate_keys();
//生成csr请求
int generate_csr(RSA * rsa);
//用自己的私钥给自己的公钥csr签名
int generate_cert(char *prikey_file, char *csr_file);
//生成pfx文件
int generate_pfx(char *prikey_file, char *cer_file);

int get_pri_key(RSA **rsa, char *prikey_file);

//将私钥从文件中取出来赋值给EVP_PKEY对象
int get_pri_key_evp(EVP_PKEY **rsa_pri_evp, char *prikey_file);
//将csr从文件中读取出来
int get_csr_file(X509_REQ **req, char *csr_file);
//将cert从文件中读取出来
int get_cert_file(X509 **cert, char *cer_file);
//保存cert到文件
int save_cert(X509 *cert, char *filepath);

// 函数方法生成密钥对   
void generateRSAKey(char* strKey[2], RSA * rsa);





