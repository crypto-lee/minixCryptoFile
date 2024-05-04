#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <minix/mthread.h>
#include <openssl/aes.h>
#include <stdbool.h>

#define BLOCK_SIZE 16
#define BUFFER_SIZE 320000

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

void adjust_key(const unsigned char *user_key, unsigned char *adjusted_key);

void write_log(const char *message, const unsigned char *data, size_t size);

void *encrypt_thread(void *thread_arg);

void *decrypt_thread(void *thread_arg);

void encrypt_decrypt_string(const unsigned char *key);

void encrypt_file(const unsigned char *key, const char *input_file, const char *output_file);

void decrypt_file(const unsigned char *key, const char *input_file, const char *output_file);
