#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "/usr/include/openssl/aes.h"

int main(int argc, char **argv)
{
    if (5 != argc)
    {
        fprintf(stderr, "参数输入错误\n");
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
        AES_set_encrypt_key(user_key, 128, &key);

        // Get the size of the plaintext file
        fseek(fp_plain, 0, SEEK_END);
        long plaintext_size = ftell(fp_plain);
        fseek(fp_plain, 0, SEEK_SET);

        // Write the plaintext size to the encrypted file
        fwrite(&plaintext_size, sizeof(plaintext_size), 1, fp_encrypted);

        while (res = fread(p, 1, 16, fp_plain))
        {
            AES_encrypt(p, e, &key);
            fwrite(e, 1, 16, fp_encrypted);
            if (res < 16)
                break;
        }

        fclose(fp_plain);
        fclose(fp_encrypted);
    }
    else if (!strcmp(argv[4], "-d"))
    {
        long plaintext_size = 0;

        fp_encrypted = fopen(argv[1], "rb");
        if (NULL == fp_encrypted)
        {
            fprintf(stderr, "open %s fail: %s\n", argv[1], strerror(errno));
            exit(1);
        }
        fp_plain = fopen(argv[2], "wb");

        strcpy(user_key, argv[3]);
        AES_set_decrypt_key(user_key, 128, &key);

        // Read the plaintext size from the encrypted file
        fread(&plaintext_size, sizeof(plaintext_size), 1, fp_encrypted);

        while (1)
        {
            fread(e, 1, 16, fp_encrypted);
            AES_decrypt(e, p, &key);

            if (plaintext_size > 16)
                fwrite(p, 1, 16, fp_plain);
            else
                fwrite(p, 1, plaintext_size, fp_plain);

            plaintext_size -= 16;
            if (plaintext_size <= 0)
                break;
        }

        fclose(fp_plain);
        fclose(fp_encrypted);
    }

    return 0;
}
