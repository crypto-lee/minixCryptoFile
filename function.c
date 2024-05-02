#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <minix/mthread.h>
#include <openssl/aes.h>

#define BLOCK_SIZE 16
#define BUFFER_SIZE 1024
#define NUM_THREADS 4

struct ThreadData
{
    FILE *input_file;
    FILE *output_file;
    AES_KEY *key;
};

struct Buffer
{
    unsigned char data[BUFFER_SIZE];
    size_t size;
    mthread_mutex_t mutex;
    pthread_cond_t cond_full;
    pthread_cond_t cond_empty;
};

void *encrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;

    while (1)
    {
        pthread_mutex_lock(&data->input_file->mutex);
        size_t bytes_read = fread(data->input_file->data, 1, BUFFER_SIZE, data->input_file);
        pthread_mutex_unlock(&data->input_file->mutex);

        if (bytes_read == 0)
            break;

        size_t num_blocks = bytes_read / BLOCK_SIZE;
        for (size_t i = 0; i < num_blocks; ++i)
        {
            unsigned char plain_block[BLOCK_SIZE];
            memcpy(plain_block, data->input_file->data + i * BLOCK_SIZE, BLOCK_SIZE);

            unsigned char encrypted_block[BLOCK_SIZE];
            AES_encrypt(plain_block, encrypted_block, data->key);

            pthread_mutex_lock(&data->output_file->mutex);
            fwrite(encrypted_block, 1, BLOCK_SIZE, data->output_file);
            pthread_mutex_unlock(&data->output_file->mutex);
        }
    }

    return NULL;
}

void *decrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;

    while (1)
    {
        pthread_mutex_lock(&data->input_file->mutex);
        size_t bytes_read = fread(data->input_file->data, 1, BUFFER_SIZE, data->input_file);
        pthread_mutex_unlock(&data->input_file->mutex);

        if (bytes_read == 0)
            break;

        size_t num_blocks = bytes_read / BLOCK_SIZE;
        for (size_t i = 0; i < num_blocks; ++i)
        {
            unsigned char encrypted_block[BLOCK_SIZE];
            memcpy(encrypted_block, data->input_file->data + i * BLOCK_SIZE, BLOCK_SIZE);

            unsigned char decrypted_block[BLOCK_SIZE];
            AES_decrypt(encrypted_block, decrypted_block, data->key);

            pthread_mutex_lock(&data->output_file->mutex);
            fwrite(decrypted_block, 1, BLOCK_SIZE, data->output_file);
            pthread_mutex_unlock(&data->output_file->mutex);
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 5)
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

    mthread_thread_t threads[NUM_THREADS];
    struct ThreadData thread_data[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        thread_data[i].input_file = fp_input;
        thread_data[i].output_file = fp_output;
        thread_data[i].key = &key;
        pthread_create(&threads[i], NULL, encrypt_thread, &thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    fclose(fp_input);
    fclose(fp_output);

    return 0;
}
