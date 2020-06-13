#include "openssl-03.h"

int generate_keys()
{
	OpenSSL_add_all_algorithms();
	RSA *r = NULL;
	int ret = 0;
	BIGNUM *bne = NULL;
	BIO *b = NULL;
	const EVP_CIPHER *enc = NULL;

	bne = BN_new();
	ret = BN_set_word(bne, RSA_3);
	r = RSA_new();
	ret = RSA_generate_key_ex(r, RSA_BITS, bne, NULL);
	if (ret != 1)
	{
		printf("RSA_generate_key_ex failed\n");
		return -1;
	}
	//pri.key pem
	enc = EVP_des_ede3_ofb();
	b = BIO_new_file(PRI_KEY_FILE, "w");
	//这里的最后一个参数是密码
	ret = PEM_write_bio_RSAPrivateKey(b, r, enc, NULL, 0, RSA_PASS,NULL);
	if (ret != 1)
	{
		printf("PEM_write_bio_RSAPrivateKey failed\n");
		BIO_free(b);
		RSA_free(r);
		return -1;
	}

	//pub.key pem
	BIO_flush(b);
	BIO_free(b);
	b = BIO_new_file(PUB_KEY_FILE, "w");
	ret = PEM_write_bio_RSAPublicKey(b, r);
	if (ret != 1)
	{
		printf("PEM_write_bio_RSAPublicKey failed...\n");
		BIO_free(b);
		RSA_free(r);
		return -1;
	}
}

//生成csr请求文件
int generate_csr(char *prikey_file)
{
	OpenSSL_add_all_algorithms();
	X509_REQ *req = NULL;
	int ret = 0;
	X509_NAME *name = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	X509_NAME_ENTRY *entry = NULL;
	char mdout[20];
	int mdlen;
	const EVP_MD *md = NULL;
	BIO *b = NULL;

	req = X509_REQ_new();
	//set version
	ret = X509_REQ_set_version(req, X509_REQ_VERSION);
	//set name
	name = X509_NAME_new();
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "commonName", V_ASN1_UTF8STRING, X509_REQ_COMMON_NAME, strlen(X509_REQ_COMMON_NAME));
	X509_NAME_add_entry(name, entry, 0, -1);
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "countryName", V_ASN1_UTF8STRING, X509_REQ_COUNTRY_NAME, strlen(X509_REQ_COUNTRY_NAME));
	X509_NAME_add_entry(name, entry, 1, -1);
	//subject name
	ret = X509_REQ_set_subject_name(req, name);
	//pub key
	pkey = EVP_PKEY_new();
	if ((ret = get_pri_key(&rsa, prikey_file)) == -1)
	{
		printf("get_pri_key failed\n");
		return -1;
	}
	EVP_PKEY_assign_RSA(pkey, rsa);
	//set public key
	ret = X509_REQ_set_pubkey(req, pkey);
	//set attribute
	ret = X509_REQ_add1_attr_by_txt(req, "organizationName", V_ASN1_UTF8STRING, X509_REQ_ORGANIZATION_NAME, strlen(X509_REQ_ORGANIZATION_NAME));
	ret = X509_REQ_add1_attr_by_txt(req, "organizationUnitName", V_ASN1_UTF8STRING, X509_REQ_ORGANIZATION_UNIT_NAME, strlen(X509_REQ_ORGANIZATION_UNIT_NAME));
	md = EVP_sha1();
	//将X509_REQ用指定的散列算法type进行散列,结果在md中,len是结果的长度
	ret = X509_REQ_digest(req, md, mdout, &mdlen);
	//对X509_REQ中X509_REQ_INFO结构用pkey于md进行签名,并用算法标识与签名填充X509_REQ中的sig_alg与signature域
	ret = X509_REQ_sign(req, pkey, md);
	if (!ret)
	{
		printf("sign err\n");
		X509_REQ_free(req);
		return -1;
	}
	//写入文件PEM格式
	b = BIO_new_file(X509_REQ_CSR_PATH, "w");
	PEM_write_bio_X509_REQ(b, req);
	BIO_free(b);
	return 0;
}


//用自己的私钥给自己的公钥csr签名
int generate_cert(char *prikey_file, char *csr_file)
{
	OpenSSL_add_all_algorithms();
	X509 *cert = NULL;
	X509_REQ *req = NULL;
	X509_NAME *pName = NULL;
	EVP_PKEY *rsa_pri_evp = NULL;
	const EVP_MD *md = NULL;
	int ret = 0;
	char mdout[20];
	int mdlen;

	if ((cert = X509_new()) == NULL)
	{
		printf("X509_new failed\n");
		return -1;
	}
	//设置版本号
	if ((ret = X509_set_version(cert, X509_CERT_VERSION3)) != 1)
	{
		printf("X509_set_version failed\n");
		return -1;
	}
	//设置序列号
	if ((ret = ASN1_INTEGER_set(X509_get_serialNumber(cert), X509_SERIAL_NUMBER)) != 1)
	{
		printf("ASN1_INTEGER_set failed\n");
		return -1;
	}
	//设置证书开始时间
	if (!X509_gmtime_adj(X509_get_notBefore(cert), 0))
	{
		printf("X509_get_notBefore failed\n");
		return -1;
	}
	//设置证书结束时间
	if (!X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24))
	{
		printf("X509_get_notAfter failed\n");
		return -1;
	}
	//从文件中得到csr文件
	if (get_csr_file(&req, csr_file) == -1)
	{
		printf("get_csr_file failed\n");
		return -1;
	}
	//设置请求csr
	if (!X509_set_subject_name(cert, X509_REQ_get_subject_name(req)))
	{
		printf("X509_set_subject_name failed\n");
		return -1;
	}
	//得到csr中的公钥,并为X509证书文件设置公钥
	EVP_PKEY *tmppubkey = X509_REQ_get_pubkey(req);
	if (!tmppubkey || !X509_set_pubkey(cert, tmppubkey))
	{
		EVP_PKEY_free(tmppubkey);
		printf("X509_set_pubkey\n");
		return -1;
	}
	EVP_PKEY_free(tmppubkey);
	//设置issuer_name
	if ((pName = X509_REQ_get_subject_name(req)) == NULL)
	{
		printf("X509_REQ_get_subject_name failed\n");
		return -1;
	}
	//
	if (!X509_set_issuer_name(cert, pName))
	{
		printf("X509_set_issuer_name\n");
		return -1;
	}
	//得到ca的私钥
	if (get_pri_key_evp(&rsa_pri_evp, prikey_file) == -1)
	{
		printf("get_pri_key_evp failed\n");
		return -1;
	}

	md = EVP_sha1();
	ret = X509_digest(req, md, mdout, &mdlen);
	X509_sign(cert, rsa_pri_evp, md);
	if (save_cert(cert, X509_CERT_FILEPATH) == -1)
	{
		printf("save_cert failed\n");
		return -1;
	}
	return 0;
}



int get_pri_key(RSA **rsa, char *prikey_file)
{
	*rsa = RSA_new();
	BIO *b = BIO_new_file(prikey_file, "rb");
	if ((*rsa = PEM_read_bio_RSAPrivateKey(b, rsa, NULL, RSA_PASS)) == NULL)
	{
		printf("*rsa is null\n");
		return -1;
	}
	return 0;
}

//将私钥从文件中取出来赋值给EVP_PKEY对象
int get_pri_key_evp(EVP_PKEY **rsa_pri_evp, char *prikey_file)
{
	BIO *pbio = NULL;
	if ((pbio = BIO_new_file(prikey_file, "r")) == NULL)
	{
		printf("BIO_new_file failed\n");
		return -1;
	}
	*rsa_pri_evp = PEM_read_bio_PrivateKey(pbio, NULL, 0, NULL);
	if (NULL == *rsa_pri_evp)
	{
		printf("PEM_read_bio_PrivateKey failed\n");
		BIO_free(pbio);
		return -1;
	}
	BIO_free(pbio);
}


//将csr从文件中读取出来
int get_csr_file(X509_REQ **req, char *csr_file)
{
	BIO *b = BIO_new_file(csr_file, "r");
	*req = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);
	if (*req == NULL)
	{
		printf("PEM_read_bio_X509_REQ failed\n");
		return -1;
	}
	return 0;
}


//保存cert到文件
int save_cert(X509 *cert, char *filepath)
{
	BIO *pbio=NULL;
	if (NULL == filepath)
		return -1;
	pbio = BIO_new_file(filepath, "w");
	if (NULL == pbio)
		return -1;
	if (!PEM_write_bio_X509(pbio, cert))
	{
		printf("PEM_write_bio_X509 failed\n");
		return -1;
	}
	BIO_free(pbio);
	return 0;
}