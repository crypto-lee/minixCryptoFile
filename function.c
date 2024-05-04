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

// The key is adjusted to 16 bytes, the insufficient part is filled with 0, and the excess part is truncated
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
void write_log(const char *message, const unsigned char *data, size_t size)
{
    FILE *fp;
    fp = fopen("log.txt", "a"); // Open the file in append mode
    if (fp == NULL)
    {
        printf("Error opening file!\n");
        return;
    }

    // get time
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[20];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    fprintf(fp, "[%s] %s: ", timestamp, message);
    for (size_t i = 0; i < size; ++i)
    {
        fprintf(fp, "%02x", data[i]);
    }
    fprintf(fp, "\n");

    fclose(fp);
}

void *encrypt_thread(void *thread_arg)
{
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    unsigned char p[BLOCK_SIZE];
    unsigned char e[BLOCK_SIZE];
    memset(p, 0, BLOCK_SIZE);
    memset(e, 0, BLOCK_SIZE);
    size_t effset = 0; // Where to start reading or writing each time
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
        AES_encrypt(p, e, data->key);
        memcpy(data->output_buffer->data + effset, e, BLOCK_SIZE);
        size_copy -= bytes_to_read;
        effset += bytes_to_read;
        // Encrypt data

        // printf("wf\n");
        // print_buffer(p);
        // write_log("encrypt_thread:p", p, BLOCK_SIZE);
        // write_log("encrypt_thread:e", e, BLOCK_SIZE);
        // print_buffer(e);
        // Write encrypted data to output buffer

        data->output_buffer->size += BLOCK_SIZE;
        memset(p, 0, BLOCK_SIZE);
        memset(e, 0, BLOCK_SIZE);
        // print_buffer(data->output_buffer->data);
        // write_log("encrypt_thread:output_buffer", data->output_buffer->data, data->output_buffer->size);
        // printf("out_buff_size%d\n", data->output_buffer->size);
    }

    if (data->last_block)
    {
        // Encrypt remaining bytes count and append to output buffer
        printf("last_block!!!!!!!!!!!\n");
        if (bytes_to_read == 0)
        {
            bytes_to_read = BLOCK_SIZE;
        }
        sprintf(p, "%d", bytes_to_read);
        AES_encrypt(p, e, data->key);
        write_log("encrypt_thread last block:p", p, BLOCK_SIZE);
        write_log("encrypt_thread last block:e", e, BLOCK_SIZE);
        // print_buffer(p);
        // print_buffer(e);
        size_copy = data->output_buffer->size;
        // Write encrypted bytes count to output buffer
        memcpy(data->output_buffer->data + size_copy, e, BLOCK_SIZE);
        size_copy += BLOCK_SIZE;
        data->output_buffer->size += BLOCK_SIZE;
        // print_buffer(data->output_buffer->data);
        write_log("encrypt_thread last block:output_buffer", data->output_buffer->data, data->output_buffer->size);
        printf("out_buff_size%d\n", data->output_buffer->size);
    }

    return NULL;
}

void *decrypt_thread(void *thread_arg)
{
    struct ThreadData *data = (struct ThreadData *)thread_arg;
    unsigned char p[BLOCK_SIZE], d[BLOCK_SIZE];
    memset(p, 0, BLOCK_SIZE);
    memset(d, 0, BLOCK_SIZE);
    size_t effset = 0; // Where to start reading or writing each time
    size_t bytes_to_read = 0;
    size_t size_copy = data->input_buffer->size;
    int last_block_size = 0;

    if (data->last_block)
    {
        // Decrypt the size of the last block
        bytes_to_read = BLOCK_SIZE;
        memcpy(p, data->input_buffer->data + (size_copy - BLOCK_SIZE), BLOCK_SIZE);
        // print_buffer(p);
        write_log("decrypt_thread:p", p, BLOCK_SIZE);
        AES_decrypt(p, d, data->key);
        // print_buffer(d);
        write_log("decrypt_thread:d", d, BLOCK_SIZE);
        printf("size_copy%d\n", size_copy);
        last_block_size = atoi(d);
        // size_copy -= BLOCK_SIZE;
        printf("Decrypted data: %s\n", d);
        memset(p, 0, BLOCK_SIZE);
        memset(d, 0, BLOCK_SIZE);
        printf("last block!!!!!!!!!!\n");
    }

    while (size_copy > 0)
    {
        // Reads data from the input buffer
        // print_buffer(data->input_buffer->data);
        // printf("Size copy: %d\n", size_copy);
        bytes_to_read = (size_copy < BLOCK_SIZE) ? size_copy : BLOCK_SIZE;
        memcpy(p, data->input_buffer->data + effset, bytes_to_read);

        // Decrypt the data
        // printf("Decrypting data\n");
        // print_buffer(p);
        // write_log("decrypt_thread:p", p, BLOCK_SIZE);
        AES_decrypt(p, d, data->key);
        // print_buffer(d);
        // write_log("decrypt_thread:d", d, BLOCK_SIZE);

        // Write the decrypted data to the output buffer
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
        size_copy -= bytes_to_read;
        effset += bytes_to_read;
        memset(p, 0, BLOCK_SIZE);
        memset(d, 0, BLOCK_SIZE);
    }

    return NULL;
}

void encrypt_decrypt_string(const unsigned char *key)
{
    const unsigned char plaintext[] = "hello world!";
    unsigned char ciphertext[16];
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(plaintext, ciphertext, &aes_key);

    // Print the encrypted result (as a hexadecimal string)
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
        fprintf(stderr, "Parameter input error\n");
        exit(1);
    }

    // Prints each command line argument
    for (int i = 0; i < argc; ++i)
    {
        printf("Argument %d: %s\n", i, argv[i]);
    }

    unsigned char user_key[17];
    unsigned char adjusted_key[17];
    strcpy((char *)user_key, argv[4]);

    // Change the key length to 16 bytes
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

    // Count the thread count
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

    // Initializes the thread data structure
    for (int i = 0; i < num_threads; ++i)
    {
        thread_data[i] = *(struct ThreadData *)malloc(sizeof(struct ThreadData));
        thread_data[i].input_buffer = (struct Buffer *)malloc(sizeof(struct Buffer));
        thread_data[i].output_buffer = (struct Buffer *)malloc(sizeof(struct Buffer));
    }

    // Reset the file pointer
    fseek(fp_input, 0, SEEK_SET);

    if (strcmp(argv[1], "-e") == 0)
    {
        // Create an encrypted thread
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
            // printf("\nThread %d created\n", i);
        }
    }
    else if (strcmp(argv[1], "-d") == 0)
    {
        // Create a decryption thread
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
            // printf("last_block:%d\n", thread_data[i].last_block);
            mthread_create(&threads[i], NULL, decrypt_thread, &thread_data[i]);
            // printf("\nThread %d created\n", i);
        }
    }
    else
    {
        fprintf(stderr, "Parameter input error\n");
        fclose(fp_input);
        fclose(fp_output);
        exit(1);
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; ++i)
    {
        mthread_join(threads[i], NULL);
    }

    // writes the data from the output buffer to the output file
    for (int i = 0; i < num_threads; ++i)
    {
        // printf("\nWriting to output file...\n");
        // write_log("output_file", thread_data[i].output_buffer->data, thread_data[i].output_buffer->size);
        // print_buffer(thread_data[i].output_buffer->data);
        fwrite(thread_data[i].output_buffer->data, 1, thread_data[i].output_buffer->size, fp_output);
    }

    // Close the file
    fclose(fp_input);
    fclose(fp_output);

    // Free memory
    for (int i = 0; i < num_threads; ++i)
    {
        if (thread_data[i].input_buffer != NULL)
        {
            free(thread_data[i].input_buffer);
            thread_data[i].input_buffer = NULL; // Set pointer to NULL to avoid dangling pointer
        }
        if (thread_data[i].output_buffer != NULL)
        {
            free(thread_data[i].output_buffer);
            thread_data[i].output_buffer = NULL; // Set pointer to NULL to avoid dangling pointer
        }
    }

    // // Free the array of thread_data structures
    // if (thread_data != NULL)
    // {
    //     free(thread_data);
    //     thread_data = NULL; // Set pointer to NULL to avoid dangling pointer
    // }

    return 0;
}
