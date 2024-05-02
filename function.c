#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <minix/mthread.h>
#include <openssl/aes.h>

#define BLOCK_SIZE 16
#define BUFFER_SIZE 1024

struct ThreadData
{
    struct Buffer *input_buffer;
    struct Buffer *output_buffer;
    AES_KEY *key;
    bool last_block;
};

struct Buffer
{
    unsigned char data[BUFFER_SIZE];
    size_t size;
};

// 将密钥调整为 16 字节，不足部分用 0 补齐，超出部分截断
void adjust_key(const unsigned char *user_key, unsigned char *adjusted_key)
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

void *encrypt_thread(void *thread_arg)
{
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    unsigned char p[BLOCK_SIZE], e[BLOCK_SIZE];
    size_t effset = 0; // 每次开始读或写的位置
    size_t bytes_to_read = 0;
    size_t size_copy = data->input_buffer->size;

    while (1)
    {
        // Check if there is data available in input buffer
        if (size_copy == 0)
        {
            // If no data available, exit thread
            break;
        }
        // Read data from input buffer
        bytes_to_read = size_copy < BLOCK_SIZE ? size_copy : BLOCK_SIZE;
        memcpy(p, data->input_buffer->data + effset, bytes_to_read);
        size_copy -= bytes_to_read;
        effset += bytes_to_read;

        // Encrypt data
        AES_encrypt(p, e, data->key);

        // Write encrypted data to output buffer
        memcpy(data->output_buffer->data + effset, e, BLOCK_SIZE);
    }

    if (data->last_block)
    {
        // Encrypt remaining bytes count and append to output buffer
        if (bytes_to_read == 0)
        {
            bytes_to_read = BLOCK_SIZE;
        }
        sprintf(p, "%d", bytes_to_read);
        AES_encrypt(p, e, data->key);

        // Write encrypted bytes count to output buffer
        memcpy(data->output_buffer->data + size_copy, e, BLOCK_SIZE);
        size_copy += BLOCK_SIZE;
    }

    return NULL;
}

void *decrypt_thread(void *thread_arg)
{
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    unsigned char p[BLOCK_SIZE], d[BLOCK_SIZE];
    size_t effset = 0; // 每次开始读或写的位置
    size_t bytes_to_read = 0;
    size_t size_copy = data->input_buffer->size;
    int last_block_size = 0;

    if (data->last_block)
    {
        // Decrypt last block size
        memcpy(p, data->input_buffer->data + size_copy - BLOCK_SIZE, BLOCK_SIZE);
        AES_decrypt(p, d, data->key);
        last_block_size = atoi((char *)d);
        size_copy -= BLOCK_SIZE;
    }

    while (1)
    {
        // Check if there is data available in input buffer
        if (size_copy == 0)
        {
            // If no data available, exit thread
            break;
        }

        // Read data from input buffer
        bytes_to_read = size_copy < BLOCK_SIZE ? size_copy : BLOCK_SIZE;
        effset = size_copy - bytes_to_read; // Update effset for decryption
        memcpy(p, data->input_buffer->data + effset, bytes_to_read);
        size_copy -= bytes_to_read;

        // Decrypt data
        AES_decrypt(p, d, data->key);

        // Write decrypted data to output buffer
        if (data->last_block && size_copy == 0)
        {
            bytes_to_read = last_block_size;
        }
        memcpy(data->output_buffer->data + effset, d, bytes_to_read);
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

    AES_KEY key;
    unsigned char user_key[17];
    unsigned char adjusted_key[17];
    strcpy((char *)user_key, argv[4]);

    // 调整密钥长度为 16 字节
    adjust_key(user_key, adjusted_key);
    encrypt_decrypt_string(adjusted_key);

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
        fclose(fp_output);
        exit(1);
    }

    // 计算线程数量
    fseek(fp_input, 0, SEEK_END);
    size_t file_size = ftell(fp_input);
    int num_threads = (file_size + BUFFER_SIZE - 1) / BUFFER_SIZE;

    mthread_thread_t threads[num_threads];
    struct ThreadData thread_data[num_threads];

    // 初始化线程数据结构
    for (int i = 0; i < num_threads; ++i)
    {
        thread_data[i].input_buffer = (struct Buffer *)malloc(sizeof(struct Buffer));
        thread_data[i].output_buffer = (struct Buffer *)malloc(sizeof(struct Buffer));
        thread_data[i].key = &key;
        thread_data[i].last_block = true; // You may adjust this based on your needs
    }

    // 重置文件指针
    fseek(fp_input, 0, SEEK_SET);

    if (strcmp(argv[1], "-e") == 0)
    {
        // 创建加密线程
        printf("\nEncrypting...\n");
        for (int i = 0; i < num_threads; ++i)
        {
            thread_data[i].input_buffer->size = fread(thread_data[i].input_buffer->data, 1, BUFFER_SIZE, fp_input);
            if (thread_data[i].input_buffer->size == 0)
            {
                break;
            }
            thread_data[i].output_buffer->size = 0;
            mthread_create(&threads[i], NULL, encrypt_thread, &thread_data[i]);
        }
    }
    else if (strcmp(argv[1], "-d") == 0)
    {
        // 创建解密线程
        printf("\nDecrypting...\n");
        for (int i = 0; i < num_threads; ++i)
        {
            thread_data[i].input_buffer->size = fread(thread_data[i].input_buffer->data, 1, BUFFER_SIZE, fp_input);
            if (thread_data[i].input_buffer->size == 0)
            {
                break;
            }
            thread_data[i].output_buffer->size = 0;
            mthread_create(&threads[i], NULL, decrypt_thread, &thread_data[i]);
        }
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

    // 将输出缓冲区的数据写入输出文件
    for (int i = 0; i < num_threads; ++i)
    {
        fwrite(thread_data[i].output_buffer->data, 1, thread_data[i].output_buffer->size, fp_output);
    }

    // 关闭文件
    fclose(fp_input);
    fclose(fp_output);

    // 释放内存
    for (int i = 0; i < num_threads; ++i)
    {
        free(thread_data[i].input_buffer);
        free(thread_data[i].output_buffer);
    }

    return 0;
}
