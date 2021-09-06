#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include<stdio.h>
#include <openssl/rand.h>
#include <string>
#include <cstring>

//#include <dlfcn.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

const string odata= "/home/dpnums/A.jpg";
const string endata = "/home/dpnums/en_A.aes";
const string dedata = "/home/dpnums/de_A.jpg";

void encrypt_seccess();
void decrypt_seccess();

int main() {
 encrypt_seccess();
 decrypt_seccess();


}


void handleErrors(void)
{
 ERR_print_errors_fp(stderr);
 abort();
}

/*
用于AES加密的函数
*/
int encryptAES(unsigned char* PlainF, unsigned char* key,
 unsigned char* iv, unsigned char* CipherF, unsigned char* salt, int salt_len) {
 EVP_CIPHER_CTX* ctx;
 unsigned char ciphertext[1184]; //保存密文的缓冲区
 int len=0;
 unsigned char plaintext[1184]; //保存原文的缓冲区

 int plaintext_len; //读取文件件的长度

 long ciphertext_len = 0; //密文长度
 FILE* fpIn;
 FILE* fpOut;
 //打开待加密文件
 fpIn = fopen((const char*)PlainF, "rb");
 if (fpIn == NULL)
 {
  printf("，Error!\n");
  exit(0);
 }
 //打开保存密文的文件
 fpOut = fopen((const char*)CipherF, "wb");
 if (fpOut == NULL)
 {
  printf("，Error!\n");
  fclose(fpIn);
  exit(0);
 }
 /* Create and initialise the context 创建并初始化上下文*/
 if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

 /* Initialise the encryption operation. IMPORTANT - ensure you use a key
 * and IV size appropriate for your cipher
 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
 * IV size for most modes is the same as the block size. For AES this
 * is 128 bits初始化加密操作。重要信息 - 确保使用
 适合您的密码的密钥*和IV大小
 *在此示例中，我们使用256位AES（即256位密钥）。
 *大多数*模式的* IV大小与块大小相同。对于AES，此
 为128位
 */
 if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
  handleErrors();
 /* Provide the message to be encrypted, and obtain the encrypted output.
 * EVP_EncryptUpdate can be called multiple times if necessary
 提供要加密的消息，并获取加密输出。
 *如果需要，可以多次调用EVP_EncryptUpdate
 */
 EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
 /*
 将盐值保存到文件的开头
 */
  const char *flag ="#*#";
  fwrite(salt, 1, salt_len, fpOut);
  fwrite(flag, sizeof(char), 3, fpOut);
 int line = 0;
 for (;;)
 {
  plaintext_len = fread(plaintext, 1, 1024, fpIn);

  if (plaintext_len <= 0)//读取原文结束
   break;
  //加密
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
  {
   fclose(fpIn);
   fclose(fpOut);
   handleErrors();
  }
  ciphertext_len += len;
  line = len;
  fwrite(ciphertext, 1, len, fpOut);//保存密文到文件
 }
 //加密结束
 EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

 fwrite(ciphertext + line, 1, len, fpOut);//保存密文到文件
 ciphertext_len += len;


 fclose(fpIn);
 fclose(fpOut);

 /* Clean up */
 EVP_CIPHER_CTX_free(ctx);
 return 0;
}
/*
//AES解密函数

1*/
int decryptAES(unsigned char* CipherF, unsigned char* key, //AES解密函数
 unsigned char* iv, unsigned char* DecryptedF, int salt_len) {
 EVP_CIPHER_CTX* ctx;
 unsigned char ciphertext[1184]; //保存密文的缓冲区
 int len=0;
 unsigned char plaintext[1184]; //保存原文的缓冲区

 int ciphertext_len; //读取文件件的长度

 long plaintext_len = 0; //明文长度
 FILE* fpIn;
 FILE* fpOut;
 //打开加密文件
 fpIn = fopen((const char*)CipherF, "rb");
 if (fpIn == NULL)
 {
  printf("，Error!\n");
  exit(0);
 }
 //打开保存明文的文件
 fpOut = fopen((const char*)DecryptedF, "wb");
 if (fpOut == NULL)
 {

  fclose(fpIn);
  exit(0);
 }
 /* Create and initialise the context 创建并初始化上下文*/
 if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

 /* Initialise the encryption operation. IMPORTANT - ensure you use a key
 * and IV size appropriate for your cipher
 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
 * IV size for most modes is the same as the block size. For AES this
 * is 128 bits初始化加密操作。重要信息 - 确保使用
 适合您的密码的密钥*和IV大小
 *在此示例中，我们使用256位AES（即256位密钥）。
 *大多数*模式的* IV大小与块大小相同。对于AES，此
 为128位
 */
 if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
  handleErrors();

 EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
 /* Provide the message to be encrypted, and obtain the encrypted output.
 * EVP_EncryptUpdate can be called multiple times if necessary
 提供要加密的消息，并获取加密输出。
 *如果需要，可以多次调用EVP_EncryptUpdate
 */

  unsigned char salt[1028];
  fread(salt, 1,(salt_len+3), fpIn);
 int line = 0;//最后一块的大小
 for (;;)
 {
  ciphertext_len = fread(ciphertext, 1, 1024, fpIn);
  if (ciphertext_len <= 0)//读取原文结束
   break;

  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
  {
   fclose(fpIn);
   fclose(fpOut);
   handleErrors();
  }
  plaintext_len += len;
  fwrite(plaintext, 1, len, fpOut);//保存密文到文件
  line = len;


 }
 //解密结束


 EVP_DecryptFinal_ex(ctx, plaintext + len, &len);


 fwrite(plaintext + line, 1, len, fpOut);//保存密文到文件
 plaintext_len += len;


 fclose(fpIn);
 fclose(fpOut);

 /* Clean up */
 EVP_CIPHER_CTX_free(ctx);
 return 0;
}



void encrypt_seccess() {
 // TODO: 在此添加控件通知处理程序代码
 const int ITERRATIVE_ROUND_FOR_KEY = 3;
 unsigned char key[EVP_MAX_KEY_LENGTH]; //秘钥
 unsigned char iv[EVP_MAX_IV_LENGTH]; //初始向量
 // USES_CONVERSION;
 // ;
 //CString转char*

 //进行转换
 //CString KL = kouling;
 string p = "passwd";

 const char* passwd = p.c_str();//T2A(KL.GetBuffer(0));
 //KL.ReleaseBuffer();

 unsigned char salt[1028] = {0};

 RAND_bytes(salt, sizeof(passwd) + 1024); //生成盐值salt

 const EVP_CIPHER* type;
 OpenSSL_add_all_ciphers();
 OpenSSL_add_all_digests();
 type = EVP_aes_256_cbc(); //AES加密算法
 EVP_BytesToKey(
  type,
  EVP_md5(),
  salt,
  (const unsigned char*)passwd,
  (int)strlen(passwd),
  ITERRATIVE_ROUND_FOR_KEY,
  key,
  iv
 );
 /* Encrypt the plaintext */
 int salt_len = strlen((const char*)salt);
 int ciphertext_len;
 string fp = odata;
 const char* PlainF = fp.c_str();//T2A(PlainP.GetBuffer(0));
 //PlainP.ReleaseBuffer();

 //CString path = PlainP;
 //int local = path.ReverseFind('.');
 //int len = path.GetLength();
 //path.Delete(0, local);
 //CString name("\\Encrypt_F");
 //CString P = CipherP + name + path;
 //进行转换
 string cfp = endata;
 const char* CipherF = cfp.c_str();//T2A(P.GetBuffer(0));
 //P.ReleaseBuffer();
 ciphertext_len = encryptAES((unsigned char*)PlainF, key, iv, (unsigned char*)CipherF, salt, salt_len);
 printf("加密成功！");
}
void Get_salt(char* salt, int* salt_len);
void decrypt_seccess() //AES256 解密
{
 // TODO: 在此添加控件通知处理程序代码
 // TODO: 在此添加控件通知处理程序代码
 const int ITERRATIVE_ROUND_FOR_KEY = 3;
 unsigned char key[EVP_MAX_KEY_LENGTH]; //秘钥
 unsigned char iv[EVP_MAX_IV_LENGTH]; //初始向量
 // USES_CONVERSION;
 // ;
 //CString转char*

 //进行转换
 //CString KL = koulin2;
 string p = "passwd";
 const char* passwd = p.c_str();//T2A(KL.GetBuffer(0));
 //KL.ReleaseBuffer();
 unsigned char salt[1028] = {0};

 int salt_len = 0;

 Get_salt((char *)salt, &salt_len); //从文本中取回盐值
 const EVP_CIPHER* type;
 OpenSSL_add_all_ciphers();
 OpenSSL_add_all_digests();
 type = EVP_aes_256_cbc(); //AES加密算法
 EVP_BytesToKey(
  type,
  EVP_md5(),
  salt,
  (const unsigned char*)passwd,
  (int)strlen(passwd),
  ITERRATIVE_ROUND_FOR_KEY,
  key,
  iv
 );

 string cfp = endata;
 const char* CipherF = cfp.c_str();//T2A(CipherW.GetBuffer(0)); //带解密文件路径
 //CipherW.ReleaseBuffer();

 //CString path = CipherW; //解密好的明文保存路径
 // int local = path.ReverseFind('.');
 // int len = path.GetLength();
 // path.Delete(0, local);
 //CString name("\\Decrypt_F");
 //CString P = DecryptedP + name + path;
 //进行转换
 string dfp = dedata;
 const char* DecryptedF = dfp.c_str();//T2A(P.GetBuffer(0));
 //P.ReleaseBuffer();

 int decryptedtext_len;
 decryptedtext_len = decryptAES((unsigned char*)CipherF, key, iv, (unsigned char*)DecryptedF, salt_len);
 printf("解密成功！");
}

void Get_salt(char* salt, int* salt_len)
{
 //USES_CONVERSION;
 string cfp = endata;
 const char* Cipher = cfp.c_str();//T2A(CipherW.GetBuffer(0));
 //CipherW.ReleaseBuffer();

 FILE* stream;
 char ch;
 if ((stream = fopen(Cipher, "rb")) == NULL)
  exit(0);
 ch = fgetc(stream);
 for (;;)
 {
  if (ch != '#')
  {
   *salt = ch;
   *salt++;
   (*salt_len)++;
   ch = fgetc(stream);
  }
  else
  {
   char s1 = fgetc(stream);
   char s2 = fgetc(stream);
   if (s1 == '*' && s2 == '#')
   {
    break;
   }
   else
   {
    *salt = '#';
    *salt++;
    (*salt_len)++;
    *salt = s1;
    *salt++;
    (*salt_len)++;
    *salt = s2;
    *salt++;
    (*salt_len)++;
    ch = fgetc(stream);
   }

  }
 }
 fclose(stream);

}