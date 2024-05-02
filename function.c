#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <mthread.h>
#include "/usr/include/openssl/aes.h"

#define BLOCK_SIZE 16
#define NUM_THREADS 4

struct ThreadData
{
    FILE *input_file;
    FILE *output_file;
    AES_KEY *key;
};

void *encrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;
    unsigned char plain_block[BLOCK_SIZE], encrypted_block[BLOCK_SIZE];

    while (fread(plain_block, 1, BLOCK_SIZE, data->input_file) == BLOCK_SIZE)
    {
        AES_encrypt(plain_block, encrypted_block, data->key);
        fwrite(encrypted_block, 1, BLOCK_SIZE, data->output_file);
    }

    return NULL;
}

void *decrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;
    unsigned char encrypted_block[BLOCK_SIZE], decrypted_block[BLOCK_SIZE];

    while (fread(encrypted_block, 1, BLOCK_SIZE, data->input_file) == BLOCK_SIZE)
    {
        AES_decrypt(encrypted_block, decrypted_block, data->key);
        fwrite(decrypted_block, 1, BLOCK_SIZE, data->output_file);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 6)
    {
        fprintf(stderr, "参数输入错误\n");
        exit(1);
    }

    FILE *fp_input = fopen(argv[2], "rb");
    if (NULL == fp_input)
    {
        fprintf(stderr, "open %s fail: %s\n", argv[2], strerror(errno));
        exit(1);
    }

    FILE *fp_output = fopen(argv[3], "wb");
    if (NULL == fp_output)
    {
        fprintf(stderr, "open %s fail: %s\n", argv[3], strerror(errno));
        fclose(fp_input);
        exit(1);
    }

    AES_KEY key;
    char user_key[17];
    strcpy(user_key, argv[4]);
    AES_set_encrypt_key(user_key, 128, &key);

    pthread_t threads[NUM_THREADS];
    struct ThreadData thread_data[NUM_THREADS];

    int i;
    if (!strcmp(argv[1], "-e"))
    {
        for (i = 0; i < NUM_THREADS; ++i)
        {
            thread_data[i].input_file = fp_input;
            thread_data[i].output_file = fp_output;
            thread_data[i].key = &key;
            pthread_create(&threads[i], NULL, encrypt_thread, &thread_data[i]);
        }
    }
    else if (!strcmp(argv[1], "-d"))
    {
        for (i = 0; i < NUM_THREADS; ++i)
        {
            thread_data[i].input_file = fp_input;
            thread_data[i].output_file = fp_output;
            thread_data[i].key = &key;
            pthread_create(&threads[i], NULL, decrypt_thread, &thread_data[i]);
        }
    }
    else
    {
        fprintf(stderr, "Invalid option\n");
        fclose(fp_input);
        fclose(fp_output);
        exit(1);
    }

    for (i = 0; i < NUM_THREADS; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    fclose(fp_input);
    fclose(fp_output);

    return 0;
}
