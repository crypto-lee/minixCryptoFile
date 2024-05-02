#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <minix/mthread.h>
#include <openssl/aes.h>

#define BLOCK_SIZE 16
#define BUFFER_SIZE 1024
#define NUM_THREADS 1

struct ThreadData
{
    struct Buffer *input_buffer;
    struct Buffer *output_buffer;
    AES_KEY *key;
    bool last_block = false;
};

struct Buffer
{
    unsigned char data[BUFFER_SIZE];
    size_t size;
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

void *encrypt_thread(struct ThreadData *data)
{
    unsigned char p[BLOCK_SIZE], e[BLOCK_SIZE];
    size_t effset = 0; // 每次开始读或写的位置
    size_t bytes_to_read = 0;
    size_t size_copy = 0;
    size_copy = data->input_buffer->size;
    while (1)
    {
        // Check if there is data available in input buffer
        if (size_copy == 0)
        {
            // If no data available, exit thread
            break;
        }
        // Read data from input buffer
        bytes_to_read = size_copy < 16 ? size_copy : 16;
        memcpy(p, data->input_buffer->data + effset, bytes_to_read);
        size_copy -= bytes_to_read;
        effset += bytes_to_read;

        // Encrypt data
        AES_encrypt(p, e, data->key);

        // Write encrypted data to output buffer
        memcpy(data->output_buffer->data + size_copy, e, 16);
    }

    if (data->last_block)
    {
        // Encrypt remaining bytes count and append to output buffer
        if (bytes_to_read == 0)
        {
            bytes_to_read = 16;
        }
        sprintf(p, "%d", bytes_to_read);
        AES_encrypt(p, e, data->key);

        // Write encrypted bytes count to output buffer
        memcpy(data->output_buffer->data + size_copy, e, 16);
        size_copy += 16;
    }

    return NULL;
}
void *decrypt_thread(struct ThreadData *data)
{
    unsigned char p[BLOCK_SIZE], d[BLOCK_SIZE];
    size_t effset = 0; // 每次开始读或写的位置
    size_t bytes_to_read = 0;
    size_t size_copy = 0;
    size_copy = data->input_buffer->size;
    int last_block_size;
    if (data->last_block)
    {
        // Decrypt last block size
        memcpy(p, data->input_buffer->data + size_copy - BLOCK_SIZE, BLOCK_SIZE);
        AES_decrypt(p, d, data->key);
        last_block_size = atoi(d);
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
        bytes_to_read = BLOCK_SIZE;
        effset = size_copy - bytes_to_read; // Update effset for decryption
        memcpy(p, data->input_buffer->data + effset, bytes_to_read);
        size_copy -= bytes_to_read;

        // Decrypt data
        AES_decrypt(p, d, data->key);
        if (data->last_block && size_copy == 0)
        {
            bytes_to_read = last_block_size;
        }
        else
        {
            bytes_to_read = BLOCK_SIZE;
        }
        // Write decrypted data to output buffer
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

    AES_KEY key;
    unsigned char user_key[17];
    unsigned char adjusted_key[17];
    strcpy((char *)user_key, argv[4]);

    // 调整密钥长度为 16 字节
    adjust_key(user_key, adjusted_key);
    encrypt_decrypt_string(adjusted_key);

    AES_set_encrypt_key(adjusted_key, 128, &key);
    AES_set_decrypt_key(adjusted_key, 128, &key);

    mthread_thread_t threads[NUM_THREADS];
    struct ThreadData thread_data[NUM_THREADS];

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
