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
void register_user();
void login();
bool user_exists(const char *username);                               // 检查用户是否存在
bool authenticate_user(const char *username, const char *password);   // 验证用户
void get_hash_value(const char *password, char *hashed_password_hex); // 获取密码的哈希值
void get_aes_key(const char *username, unsigned char *aes_key);       // 获取AES密钥

int main()
{
    int choice;

    // 显示菜单
    printf("1. 注册新用户\n");
    printf("2. 登录\n");
    printf("3. 修改密码\n"); // 添加修改密码选项
    printf("请选择: ");
    scanf("%d", &choice);

    // 根据用户选择执行相应操作
    switch (choice)
    {
    case 1:
        register_user();
        break;
    case 2:
        login();
        break;
    case 3:
        change_password();
        break;
    default:
        printf("无效的选择\n");
    }

    return 0;
}

// 检查用户是否存在
bool user_exists(const char *username)
{
    FILE *fp;
    char line[256];
    char *token;
    // 打开文件
    fp = fopen("/etc/aeskey", "r");
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        exit(1);
    }
    // 逐行读取文件
    while (fgets(line, sizeof(line), fp))
    {
        // 分割行为用户名、密码哈希和AES密钥
        token = strtok(line, ":");
        if (strcmp(token, username) == 0)
        {
            // 用户名存在
            fclose(fp);
            return true;
        }
    }
    // 用户名不存在
    fclose(fp);
    return false;
}

// 注册新用户
void register_user()
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char hashed_password_hex[MAX_HASH_LEN];
    unsigned char aes_key[AES_KEY_LEN];
    FILE *fp;

    // 获取用户名和密码
    printf("请输入用户名: ");
    scanf("%s", username);
    printf("请输入密码: ");
    scanf("%s", password);

    // 检查用户是否已存在
    if (user_exists(username))
    {
        printf("用户已存在\n");
        exit(1);
    }
    // 生成AES密钥
    RAND_bytes(aes_key, AES_KEY_LEN);

    // 打开文件
    fp = fopen("/etc/aeskey", "a");
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        exit(1);
    }

    // 写入用户名、密码哈希和AES密钥到文件
    fprintf(fp, "%s:", username);
    get_hash_value(password, hashed_password_hex);
    fprintf(fp, "%s", hashed_password_hex);
    fprintf(fp, ":");
    for (int i = 0; i < AES_KEY_LEN; i++)
    {
        fprintf(fp, "%02x", aes_key[i]);
    }
    fprintf(fp, "\n");
    // 关闭文件
    fclose(fp);
    printf("注册成功\n");
}

// 用户登录
void login()
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    // 获取用户名和密码
    printf("请输入用户名: ");
    scanf("%s", username);
    printf("请输入密码: ");
    scanf("%s", password);

    // 验证用户
    if (authenticate_user(username, password))
    {
        printf("登录成功\n");
    }
    else
    {
        printf("用户名或密码错误\n");
    }
}

// 修改密码
void change_password()
{
    // 与注册用户类似，但需要先检查用户是否存在

    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char new_password[MAX_PASSWORD_LEN];
    char hashed_password_hex[MAX_HASH_LEN];
    unsigned char aes_key[AES_KEY_LEN];
    char *token;
    FILE *fp;
    char line[256];

    // 获取用户名和密码
    printf("请输入用户名: ");
    scanf("%s", username);
    printf("请输入密码: ");
    scanf("%s", password);

    // 检查用户是否存在
    if (!user_exists(username))
    {
        printf("用户不存在\n");
        exit(1);
    }
    // 检查密码是否正确
    if (!authenticate_user(username, password))
    {
        printf("密码错误\n");
        exit(1);
    }
    // 输入新密码
    printf("请输入新密码: ");
    scanf("%s", new_password);

    // 计算新密码的哈希值
    get_hash_value(new_password, hashed_password_hex);

    // 打开文件进行修改
    fp = fopen("/etc/aeskey", "r+");
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        exit(1);
    }

    RAND_bytes(aes_key, AES_KEY_LEN);
    // 逐行读取文件
    while (fgets(line, sizeof(line), fp))
    {
        // 分割行为用户名、密码哈希和AES密钥
        token = strtok(line, ":");
        if (strcmp(token, username) == 0)
        {
            // 用户名匹配，修改密码哈希
            fseek(fp, -strlen(line), SEEK_CUR); // 将文件指针移回当前行开头
            fprintf(fp, "%s:", username);       // 重新写入用户名
            fprintf(fp, "%s", hashed_password_hex);
            fprintf(fp, ":"); // 写入分隔符
            // 将文件指针移到AES密钥位置
            for (int i = 0; i < AES_KEY_LEN; i++)
            {
                fprintf(fp, "%02x", aes_key[i]);
            }
            printf("密码已修改\n");
            fclose(fp);
            return;
        }
    }

    // 用户名不存在（理论上不应该到达这里）
    printf("用户不存在\n");
    fclose(fp);
}

bool authenticate_user(const char *username, const char *password)
{
    char hashed_password_hex[MAX_HASH_LEN];
    unsigned char aes_key[AES_KEY_LEN];
    char *token;
    FILE *fp;
    char line[256];
    // 计算密码的哈希值
    get_hash_value(password, hashed_password_hex);
    // 打开文件
    fp = fopen("/etc/aeskey", "r");
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        exit(1);
    }
    // 逐行读取文件
    while (fgets(line, sizeof(line), fp))
    {
        // 分割行为用户名、密码哈希和AES密钥
        token = strtok(line, ":");
        if (strcmp(token, username) == 0)
        {
            // 用户名匹配，验证密码
            token = strtok(NULL, ":");
            if (strcmp(token, hashed_password_hex) == 0) // 使用十六进制字符串进行比较
            {

                fclose(fp);
                return true;
            }
        }
    }
    // 用户名或密码错误
    fclose(fp);
    return false;
}

void get_hash_value(const char *password, char *hashed_password_hex)
{
    char hashed_password[EVP_MAX_MD_SIZE];
    unsigned int hashed_password_len;

    // 计算密码的哈希值
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx, password, strlen(password));
    EVP_DigestFinal(&mdctx, hashed_password, &hashed_password_len);
    EVP_MD_CTX_cleanup(&mdctx);

    // 将哈希值转换为十六进制字符串
    for (int i = 0; i < hashed_password_len; ++i)
    {
        sprintf(&hashed_password_hex[2 * i], "%02x", hashed_password[i]);
    }
    hashed_password_hex[2 * hashed_password_len] = '\0';
}

void get_aes_key(const char *username, unsigned char *aes_key)
{
    FILE *fp;
    char line[256];
    char *token;

    // 打开文件
    fp = fopen("/etc/aeskey", "r");
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        exit(1);
    }

    // 逐行读取文件
    while (fgets(line, sizeof(line), fp))
    {
        // 分割行为用户名、密码哈希和AES密钥
        token = strtok(line, ":");
        if (strcmp(token, username) == 0)
        {
            // 用户名匹配，提取AES密钥
            token = strtok(NULL, ":");
            token = strtok(NULL, ":");
            aes_key = token;
            fclose(fp);
            return;
        }
    }

    // 用户名不存在
    printf("用户不存在\n");
    fclose(fp);
    exit(1);
}