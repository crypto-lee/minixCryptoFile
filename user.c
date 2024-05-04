#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define AES_KEY_LEN 32 // AES-256密钥长度为32字节

// 函数声明
void register_user();
void login();

int main()
{
    int choice;

    // 显示菜单
    printf("1. 注册新用户\n");
    printf("2. 登录\n");
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
    default:
        printf("无效的选择\n");
    }

    return 0;
}

// 注册新用户
void register_user()
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char hashed_password[EVP_MAX_MD_SIZE];
    unsigned int hashed_password_len;
    unsigned char aes_key[AES_KEY_LEN];
    FILE *fp;

    // 获取用户名和密码
    printf("请输入用户名: ");
    scanf("%s", username);
    printf("请输入密码: ");
    scanf("%s", password);

    // 计算密码的哈希值
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx, password, strlen(password));
    EVP_DigestFinal(&mdctx, hashed_password, &hashed_password_len);
    EVP_MD_CTX_cleanup(&mdctx);

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
    for (int i = 0; i < hashed_password_len; i++)
    {
        fprintf(fp, "%02x", hashed_password[i]);
    }
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
    char hashed_password[EVP_MAX_MD_SIZE];
    unsigned int hashed_password_len;
    unsigned char aes_key[AES_KEY_LEN];
    char *token;
    FILE *fp;
    char line[256];

    // 获取用户名和密码
    printf("请输入用户名: ");
    scanf("%s", username);
    printf("请输入密码: ");
    scanf("%s", password);

    // 计算密码的哈希值
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx, password, strlen(password));
    EVP_DigestFinal(&mdctx, hashed_password, &hashed_password_len);
    EVP_MD_CTX_cleanup(&mdctx);

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
            if (strcmp(token, hashed_password) == 0)
            {
                // 密码哈希匹配，提取AES密钥
                token = strtok(NULL, ":");
                for (int i = 0; i < AES_KEY_LEN; i += 2)
                {
                    sscanf(token + i, "%2hhx", &aes_key[i / 2]);
                }
                // 使用AES密钥进行加密或解密操作...
                printf("登录成功\n");
                fclose(fp);
                return;
            }
        }
    }

    // 用户名或密码错误
    printf("用户名或密码错误\n");
    fclose(fp);
}
