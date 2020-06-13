
#include "openssl-03.h"


// 函数方法生成密钥对   
void generateRSAKey(char * strKey[2],RSA * rsa)
{
	// 公私密钥对    
	int pri_len;
	int pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	// 生成密钥对    
	rsa = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, rsa);

	// 获取长度    
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 密钥对读取到字符串
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	// 存储密钥对    
	strKey[0] = pub_key;
	strKey[1] = pri_key;

	// 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）  
	FILE *pubFile;
	errno_t err = fopen_s(&pubFile, PUB_KEY_FILE, "w");
	if (pubFile == NULL)
	{
		return;
	}
	fputs(pub_key, pubFile);
	fclose(pubFile);

	FILE *priFile;
	err = fopen_s(&priFile, PRI_KEY_FILE, "w");
	if (priFile == NULL)
	{
		return;
	}
	fputs(pri_key, priFile);
	fclose(priFile);

	// 内存释放  
	BIO_free_all(pub);
	BIO_free_all(pri);

	free(pri_key);
	free(pub_key);
	printf("generated keys\n");
	return;
}

int main()
{
	char* test[2];
	RSA * rsa=NULL;
	generateRSAKey(test,rsa);
	if (generate_csr(PRI_KEY_FILE) != 0)
	{
		printf("generate csr failed\n");
		return 0;
	}
	else {
		printf("generate csr success \n");
	}
	if (generate_cert(PRI_KEY_FILE, X509_REQ_CSR_PATH) == 0)
	{
		printf("generate cert success\n");
	}
	else {
		printf("generate cert failed\n");
	}

	return 0;
}
