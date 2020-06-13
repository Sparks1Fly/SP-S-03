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

// ---- rsa�ǶԳƼӽ��� ---- //    
#define KEY_LENGTH  2048               // ��Կ����  
#define PUB_KEY_FILE "pubkey.pem"    // ��Կ·��  
#define PRI_KEY_FILE "prikey.pem"    // ˽Կ·��  
#define RSA_BITS        2048		//rsa����
#define RSA_PASS        "123"		//rsa��Կ����
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
//����csr����
int generate_csr(RSA * rsa);
//���Լ���˽Կ���Լ��Ĺ�Կcsrǩ��
int generate_cert(char *prikey_file, char *csr_file);
//����pfx�ļ�
int generate_pfx(char *prikey_file, char *cer_file);

int get_pri_key(RSA **rsa, char *prikey_file);

//��˽Կ���ļ���ȡ������ֵ��EVP_PKEY����
int get_pri_key_evp(EVP_PKEY **rsa_pri_evp, char *prikey_file);
//��csr���ļ��ж�ȡ����
int get_csr_file(X509_REQ **req, char *csr_file);
//��cert���ļ��ж�ȡ����
int get_cert_file(X509 **cert, char *cer_file);
//����cert���ļ�
int save_cert(X509 *cert, char *filepath);

// ��������������Կ��   
void generateRSAKey(char* strKey[2], RSA * rsa);





