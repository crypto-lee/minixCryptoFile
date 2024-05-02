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
    struct Buffer *input_buffer;
    struct Buffer *output_buffer;
    AES_KEY *key;
};

struct Buffer
{
    FILE *file;
    unsigned char data[BUFFER_SIZE];
    size_t size;
    mthread_mutex_t mutex;
};

void *encrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;

    while (1)
    {
        mthread_mutex_lock(&data->input_buffer->mutex);
        size_t bytes_read = fread(data->input_buffer->data, 1, BUFFER_SIZE, data->input_buffer->file);
        data->input_buffer->size = bytes_read;
        mthread_mutex_unlock(&data->input_buffer->mutex);

        if (bytes_read == 0)
            break;

        size_t num_blocks = bytes_read / BLOCK_SIZE;
        for (size_t i = 0; i < num_blocks; ++i)
        {
            unsigned char plain_block[BLOCK_SIZE];
            memcpy(plain_block, data->input_buffer->data + i * BLOCK_SIZE, BLOCK_SIZE);

            unsigned char encrypted_block[BLOCK_SIZE];
            AES_encrypt(plain_block, encrypted_block, data->key);

            mthread_mutex_lock(&data->output_buffer->mutex);
            fwrite(encrypted_block, 1, BLOCK_SIZE, data->output_buffer->file);
            mthread_mutex_unlock(&data->output_buffer->mutex);
        }
    }

    return NULL;
}

void *decrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;

    while (1)
    {
        mthread_mutex_lock(&data->input_buffer->mutex);
        size_t bytes_read = fread(data->input_buffer->data, 1, BUFFER_SIZE, data->input_buffer->file);
        data->input_buffer->size = bytes_read;
        mthread_mutex_unlock(&data->input_buffer->mutex);

        if (bytes_read == 0)
            break;

        size_t num_blocks = bytes_read / BLOCK_SIZE;
        for (size_t i = 0; i < num_blocks; ++i)
        {
            unsigned char encrypted_block[BLOCK_SIZE];
            memcpy(encrypted_block, data->input_buffer->data + i * BLOCK_SIZE, BLOCK_SIZE);

            unsigned char decrypted_block[BLOCK_SIZE];
            AES_decrypt(encrypted_block, decrypted_block, data->key);

            mthread_mutex_lock(&data->output_buffer->mutex);
            fwrite(decrypted_block, 1, BLOCK_SIZE, data->output_buffer->file);
            mthread_mutex_unlock(&data->output_buffer->mutex);
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

    struct Buffer input_buffer = {fp_input, {0}, 0, PTHREAD_MUTEX_INITIALIZER};
    struct Buffer output_buffer = {fp_output, {0}, 0, PTHREAD_MUTEX_INITIALIZER};

    AES_KEY key;
    unsigned char user_key[17];        // Changed to unsigned char
    strcpy((char *)user_key, argv[4]); // Cast to char *

    AES_set_encrypt_key(user_key, 128, &key);

    mthread_thread_t threads[NUM_THREADS];
    struct ThreadData thread_data[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        thread_data[i].input_buffer = &input_buffer;
        thread_data[i].output_buffer = &output_buffer;
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
