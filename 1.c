#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/aes.h>

// 将密钥调整为 16 字节，不足部分用 0 补齐，超出部分截断
void adjust_key(unsigned char *user_key, unsigned char *adjusted_key)
{
    int len = strlen((char *)user_key);
    if (len < 16)
    {
        memcpy(adjusted_key, user_key, len);
        memset(adjusted_key + len, 0, 16 - len);
    }
    else
    {
        memcpy(adjusted_key, user_key, 16);
    }
}

int main(int argc, char **argv)
{

    if (5 != argc)
    {
        fprintf(stderr, "something worring!\n");
        exit(1);
    }

    FILE *fp_plain = NULL;
    FILE *fp_encrypted = NULL;
    AES_KEY key;
    unsigned char p[16], e[16];
    char user_key[17];
    int res = 0;

    if (!strcmp(argv[4], "-e"))
    {
        fp_plain = fopen(argv[1], "rb");
        if (NULL == fp_plain)
        {
            fprintf(stderr, "open %s fail: %s\n", argv[1], strerror(errno));
            exit(1);
        }
        fp_encrypted = fopen(argv[2], "wb");

        strcpy(user_key, argv[3]);
        unsigned char adjusted_key[17];
        // 调整密钥长度为 16 字节
        adjust_key(user_key, adjusted_key);
        AES_set_encrypt_key(adjusted_key, 128, &key);

        while (res = fread(p, 1, 16, fp_plain))
        {
            AES_encrypt(p, e, &key);
            printf("\np:%s\n", p);
            printf("\ne:%s\n", e);
            fwrite(e, 1, 16, fp_encrypted);
            if (res < 16)
                break;
        }
        if (res == 0)
            res = 16;
        sprintf(p, "%d", res);
        AES_encrypt(p, e, &key);
        printf("\np:%s\n", p);
        printf("\ne:%s\n", e);
        fwrite(e, 1, 16, fp_encrypted);
        printf("\np:%s", p);

        fclose(fp_plain);
        fclose(fp_encrypted);
    }
    else if (!strcmp(argv[4], "-d"))
    {
        int len = 0;
        long end = 0;
        fp_encrypted = fopen(argv[1], "rb");
        if (NULL == fp_encrypted)
        {
            fprintf(stderr, "open %s fail: %s\n", argv[1], strerror(errno));
            exit(1);
        }
        fp_plain = fopen(argv[2], "wb");

        strcpy(user_key, argv[3]);
        unsigned char adjusted_key[17];
        // 调整密钥长度为 16 字节
        adjust_key(user_key, adjusted_key);
        AES_set_decrypt_key(adjusted_key, 128, &key);

        fseek(fp_encrypted, -16, SEEK_END);
        end = ftell(fp_encrypted);
        fread(e, 1, 16, fp_encrypted);
        AES_decrypt(e, p, &key);
        len = atoi(p);
        rewind(fp_encrypted);

        while (1)
        {
            fread(e, 1, 16, fp_encrypted);
            AES_decrypt(e, p, &key);
            if (end == ftell(fp_encrypted))
            {
                fwrite(p, 1, len, fp_plain);
                break;
            }
            fwrite(p, 1, 16, fp_plain);
        }

        fclose(fp_plain);
        fclose(fp_encrypted);
    }

    return 0;
}