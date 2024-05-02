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

void *encrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;

    while (1)
    {
        mthread_mutex_lock(&data->input_buffer->mutex);
        size_t bytes_read = fread(data->input_buffer->data, 1, BLOCK_SIZE, data->input_buffer->file);
        mthread_mutex_unlock(&data->input_buffer->mutex);

        if (bytes_read == 0)
            break;

        mthread_mutex_lock(&data->output_buffer->mutex);
        size_t num_blocks = bytes_read / BLOCK_SIZE;
        for (size_t i = 0; i < num_blocks; ++i)
        {
            unsigned char plain_block[BLOCK_SIZE];
            memcpy(plain_block, data->input_buffer->data + i * BLOCK_SIZE, BLOCK_SIZE);

            unsigned char encrypted_block[BLOCK_SIZE];
            AES_encrypt(plain_block, encrypted_block, data->key);

            fwrite(encrypted_block, 1, BLOCK_SIZE, data->output_buffer->file);
        }
        mthread_mutex_unlock(&data->output_buffer->mutex);
    }

    return NULL;
}

void *decrypt_thread(void *arg)
{
    struct ThreadData *data = (struct ThreadData *)arg;

    while (1)
    {
        mthread_mutex_lock(&data->input_buffer->mutex);
        size_t bytes_read = fread(data->input_buffer->data, 1, BLOCK_SIZE, data->input_buffer->file);
        mthread_mutex_unlock(&data->input_buffer->mutex);

        if (bytes_read == 0)
            break;

        mthread_mutex_lock(&data->output_buffer->mutex);
        size_t num_blocks = bytes_read / BLOCK_SIZE;
        for (size_t i = 0; i < num_blocks; ++i)
        {
            unsigned char plain_block[BLOCK_SIZE];
            memcpy(plain_block, data->input_buffer->data + i * BLOCK_SIZE, BLOCK_SIZE);

            unsigned char decrypted_block[BLOCK_SIZE];
            AES_decrypt(plain_block, decrypted_block, data->key);

            fwrite(decrypted_block, 1, BLOCK_SIZE, data->output_buffer->file);
        }
        mthread_mutex_unlock(&data->output_buffer->mutex);
    }

    return NULL;
}

// 加密解密函数
void encrypt_decrypt_string(const unsigned char *key)
{
    const unsigned char plaintext[] = "hello world!";
    unsigned char ciphertext[128];
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(plaintext, ciphertext, &aes_key);

    // 打印加密后的结果（以十六进制字符串形式）
    printf("Encrypted: ");
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    AES_set_decrypt_key(key, 128, &aes_key);
    AES_decrypt(ciphertext, plaintext, &aes_key);
    printf("Decrypted: %s\n", plaintext);
}

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        fprintf(stderr, "参数输入错误\n");
        exit(1);
    }

    // 打印每个命令行参数
    for (int i = 0; i < argc; ++i)
    {
        printf("Argument %d: %s\n", i, argv[i]);
    }

    FILE *fp_input = fopen(argv[2], "rb");
    if (NULL == fp_input)
    {
        fprintf(stderr, "open %s fail: %s\n", argv[3], strerror(errno));
        exit(1);
    }

    FILE *fp_output = fopen(argv[3], "wb");
    if (NULL == fp_output)
    {
        fprintf(stderr, "open %s fail: %s\n", argv[4], strerror(errno));
        fclose(fp_input);
        exit(1);
    }

    struct Buffer input_buffer;
    input_buffer.file = fp_input;
    input_buffer.size = 0;
    mthread_mutex_init(&input_buffer.mutex, NULL);

    struct Buffer output_buffer;
    output_buffer.file = fp_output;
    output_buffer.size = 0;
    mthread_mutex_init(&output_buffer.mutex, NULL);

    AES_KEY key;
    unsigned char user_key[17];
    unsigned char adjusted_key[17];
    strcpy((char *)user_key, argv[4]);

    // 调整密钥长度为 16 字节
    adjust_key(user_key, adjusted_key);
    encrypt_decrypt_string(user_key);

    AES_set_encrypt_key(adjusted_key, 128, &key);
    AES_set_decrypt_key(adjusted_key, 128, &key);

    mthread_thread_t threads[NUM_THREADS * 2];
    struct ThreadData thread_data[NUM_THREADS * 2];

    int num_threads = 0;
    if (strcmp(argv[1], "-e") == 0)
    {
        // Create encryption threads
        printf("\nencrypt!!\n");
        for (int i = 0; i < NUM_THREADS; ++i)
        {
            thread_data[i].input_buffer = &input_buffer;
            thread_data[i].output_buffer = &output_buffer;
            thread_data[i].key = &key;
            mthread_create(&threads[i], NULL, encrypt_thread, &thread_data[i]);
        }
        num_threads = NUM_THREADS;
    }
    else if (strcmp(argv[1], "-d") == 0)
    {
        // 创建解密线程
        printf("\nDecrypting...\n");
        for (int i = 0; i < NUM_THREADS; ++i)
        {
            thread_data[NUM_THREADS + i].input_buffer = &input_buffer;   // Input buffer is now the encrypted output
            thread_data[NUM_THREADS + i].output_buffer = &output_buffer; // Output buffer is now the decrypted input
            thread_data[NUM_THREADS + i].key = &key;
            mthread_create(&threads[NUM_THREADS + i], NULL, decrypt_thread, &thread_data[NUM_THREADS + i]);
        }
        num_threads = NUM_THREADS;
    }
    else
    {
        fprintf(stderr, "无效的参数\n");
        fclose(fp_input);
        fclose(fp_output);
        exit(1);
    }

    // 等待所有线程完成
    for (int i = 0; i < num_threads; ++i)
    {
        mthread_join(threads[i], NULL);
    }

    fclose(fp_input);
    fclose(fp_output);

    return 0;
}
