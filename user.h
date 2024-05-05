#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h> // 添加头文件以使用布尔类型
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define AES_KEY_LEN 16 // AES-256密钥长度为32字节
#define MAX_HASH_LEN 500

// 函数声明
void change_password(); // 修改密码
bool register_user();
bool login();
bool user_exists(const char *username);                               // 检查用户是否存在
bool authenticate_user(const char *username, const char *password);   // 验证用户
void get_hash_value(const char *password, char *hashed_password_hex); // 获取密码的哈希值
void get_aes_key(const char *username, unsigned char *aes_key);       // 获取AES密钥
