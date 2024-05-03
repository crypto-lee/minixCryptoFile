#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <minix/mthread.h>
#include <openssl/aes.h>
#include <stdbool.h>

#define BLOCK_SIZE 16
#define BUFFER_SIZE 10240

struct ThreadData
{
    struct Buffer *input_buffer;
    struct Buffer *output_buffer;
    AES_KEY *key;
    bool last_block;
};

struct Buffer
{
    unsigned char data[18];
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
void print_buffer(unsigned char ciphertext[16])
{
    printf("Encrypted: ");
    for (int i = 0; i < 18; ++i)
    {
        printf("%02x", ciphertext[i]);
    }
    // printf("\n");
    // printf("ciphertext:%s\n", ciphertext);
}

void *encrypt_thread(void *thread_arg)
{
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    unsigned char p[BLOCK_SIZE];
    unsigned char e[BLOCK_SIZE];
    memset(p, 0, BLOCK_SIZE);
    memset(e, 0, BLOCK_SIZE);
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
        memcpy(data->output_buffer->data + effset, e, BLOCK_SIZE);
        AES_encrypt(p, e, data->key);
        size_copy -= bytes_to_read;
        effset += bytes_to_read;
        // Encrypt data

        printf("wf\n");
        print_buffer(p);
        print_buffer(e);
        // Write encrypted data to output buffer

        data->output_buffer->size += BLOCK_SIZE;
        memset(p, 0, BLOCK_SIZE);
        memset(e, 0, BLOCK_SIZE);
        print_buffer(data->output_buffer->data);
    }

    if (data->last_block)
    {
        // Encrypt remaining bytes count and append to output buffer
        if (bytes_to_read == 0)
        {
            bytes_to_read = BLOCK_SIZE;
        }
        sprintf(p, "%d", bytes_to_read);
        printf("if\n");
        AES_encrypt(p, e, data->key);
        print_buffer(p);
        print_buffer(e);
        size_copy = data->output_buffer->size;
        // Write encrypted bytes count to output buffer
        memcpy(data->output_buffer->data + size_copy, e, BLOCK_SIZE);
        size_copy += BLOCK_SIZE;
        data->output_buffer->size += BLOCK_SIZE;
        print_buffer(data->output_buffer->data);
    }

    return NULL;
}

void *decrypt_thread(void *thread_arg)
{
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    unsigned char p[BLOCK_SIZE], d[BLOCK_SIZE];
    memset(p, 0, BLOCK_SIZE);
    memset(d, 0, BLOCK_SIZE);
    size_t effset = 0; // 每次开始读或写的位置
    size_t bytes_to_read = 0;
    size_t size_copy = data->input_buffer->size;
    int last_block_size = 0;

    // if (data->last_block)
    // {
    //     // 解密最后一个块的大小
    //     bytes_to_read = BLOCK_SIZE;
    //     memcpy(p, data->input_buffer->data + (size_copy - BLOCK_SIZE), BLOCK_SIZE);
    //     print_buffer(p);
    //     AES_decrypt(p, d, data->key);
    //     last_block_size = atoi(d);
    //     size_copy -= BLOCK_SIZE;
    //     printf("Decrypted data: %s\n", d);
    //     memset(p, 0, BLOCK_SIZE);
    //     memset(d, 0, BLOCK_SIZE);
    // }

    while (size_copy > 0)
    {
        // 从输入缓冲区读取数据
        print_buffer(data->input_buffer->data);
        printf("Size copy: %d\n", size_copy);
        bytes_to_read = (size_copy < BLOCK_SIZE) ? size_copy : BLOCK_SIZE;
        memcpy(p, data->input_buffer->data + effset, bytes_to_read);
        size_copy -= bytes_to_read;
        effset += bytes_to_read;
        // 解密数据
        printf("Decrypting data\n");
        print_buffer(p);
        AES_decrypt(p, d, data->key);
        print_buffer(d);

        // 写入解密后的数据到输出缓冲区
        if (data->last_block && size_copy == 0)
        {
            memcpy(data->output_buffer->data + effset, d, last_block_size);
            data->output_buffer->size += last_block_size;
        }
        else
        {
            memcpy(data->output_buffer->data + effset, d, BLOCK_SIZE);
            data->output_buffer->size += BLOCK_SIZE;
        }
        memset(p, 0, BLOCK_SIZE);
        memset(d, 0, BLOCK_SIZE);
    }

    return NULL;
}

// 加密解密函数
void encrypt_decrypt_string(const unsigned char *key)
{
    const unsigned char plaintext[] = "hello world!";
    unsigned char ciphertext[16];
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
    int num_threads = file_size / BUFFER_SIZE;
    if (file_size % BUFFER_SIZE != 0)
    {
        num_threads++;
    }
    printf("\nNumber of threads: %d\n", num_threads);
    mthread_thread_t threads[num_threads];
    struct ThreadData thread_data[num_threads];

    // 初始化线程数据结构
    for (int i = 0; i < num_threads; ++i)
    {
        thread_data[i] = *(struct ThreadData *)malloc(sizeof(struct ThreadData));
        thread_data[i].input_buffer = (struct Buffer *)malloc(sizeof(struct Buffer));
        thread_data[i].output_buffer = (struct Buffer *)malloc(sizeof(struct Buffer));
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
                printf("\nNo data to read\n");
                break;
            }
            thread_data[i].output_buffer->size = 0;
            thread_data[i].last_block = (i == num_threads - 1); // Set last_block to true for the last thread
            AES_KEY key;
            thread_data[i].key = &key;
            AES_set_encrypt_key(adjusted_key, 128, thread_data[i].key);
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
            AES_KEY key;
            thread_data[i].key = &key;
            AES_set_decrypt_key(adjusted_key, 128, thread_data[i].key);
            thread_data[i].output_buffer->size = 0;
            thread_data[i].last_block = (i == num_threads - 1); // Set last_block to true for the last thread
            printf("last_block:%d\n", thread_data[i].last_block);
            mthread_create(&threads[i], NULL, decrypt_thread, &thread_data[i]);
            printf("\nThread %d created\n", i);
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

    // // 将输出缓冲区的数据写入输出文件
    for (int i = 0; i < num_threads; ++i)
    {
        printf("\nWriting to output file...\n");
        print_buffer(thread_data[i].output_buffer->data);
        fwrite(thread_data[i].output_buffer->data, 1, thread_data[i].output_buffer->size, fp_output);
    }

    // 关闭文件
    fclose(fp_input);
    fclose(fp_output);

    // // 释放内存
    // for (int i = 0; i < num_threads; ++i)
    // {
    //     free(thread_data[i].input_buffer);
    //     free(thread_data[i].output_buffer);
    //     free(&thread_data[i]);
    // }

    return 0;
}
