#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define AES_KEY_LEN 16
#define MAX_HASH_LEN 500

// void change_password();
bool register_user();
bool login(char *name, char *passwd);
bool user_exists(const char *username);
bool authenticate_user(const char *username, const char *password);
void get_hash_value(const char *password, char *hashed_password_hex);
// void get_aes_key(const char *username, unsigned char *aes_key);
void get_aes_key(const char *username, unsigned char *aes_key);
void generate_aes_key(const char *username, const char *password, unsigned char *aes_key);
