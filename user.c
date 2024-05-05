#include "user.h"

bool user_exists(const char *username)
{
    FILE *fp;
    char line[256];
    char *token;

    fp = fopen("/etc/aeskey", "r");
    if (fp == NULL)
    {
        printf("can not open file\n");
        exit(1);
    }

    while (fgets(line, sizeof(line), fp))
    {

        token = strtok(line, ":");
        if (strcmp(token, username) == 0)
        {

            fclose(fp);
            return true;
        }
    }

    fclose(fp);
    return false;
}
void generate_aes_key(const char *username, const char *password, unsigned char *aes_key)
{

    char combined_string[256];
    snprintf(combined_string, sizeof(combined_string), "%s:%s", username, password);
    char hashed_password_hex[MAX_HASH_LEN];
    unsigned int hash_len;
    get_hash_value(combined_string, hashed_password_hex);
    memcpy(aes_key, hashed_password_hex, AES_KEY_LEN);
}

bool register_user()
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char hashed_password_hex[MAX_HASH_LEN];
    // unsigned char aes_key[AES_KEY_LEN];
    FILE *fp;

    printf("please input username: ");
    scanf("%s", username);
    printf("please input passwd: ");
    scanf("%s", password);

    if (user_exists(username))
    {
        printf("user is exist!\n");
        exit(1);
    }

    // RAND_bytes(aes_key, AES_KEY_LEN);
    // generate_aes_key(username, password, aes_key);

    fp = fopen("/etc/aeskey", "a");
    if (fp == NULL)
    {
        printf("can not open file\n");
        exit(1);
    }

    fprintf(fp, "%s:", username);
    get_hash_value(password, hashed_password_hex);
    fprintf(fp, "%s", hashed_password_hex);
    // fprintf(fp, ":");
    // for (int i = 0; i < AES_KEY_LEN; i++)
    // {
    //     fprintf(fp, "%02x", aes_key[i]);
    // }
    fprintf(fp, "\n");

    fclose(fp);
    printf("regeist success!\n");
    return true;
}

bool login(char *name, char *passwd)
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];

    printf("please input username: ");
    scanf("%s", username);
    printf("please input passwd: ");
    scanf("%s", password);

    if (authenticate_user(username, password))
    {
        strcpy(name, username);
        strcpy(passwd, password);
        return true;
        printf("login success!\n");
    }
    else
    {

        printf("passwd incorrect!\n");
        exit(1);
    }
    return true;
}

// void change_password()
// {
//     char username[MAX_USERNAME_LEN];
//     char password[MAX_PASSWORD_LEN];
//     char new_password[MAX_PASSWORD_LEN];
//     char hashed_password_hex[MAX_HASH_LEN];
//     // unsigned char aes_key[AES_KEY_LEN];
//     FILE *fp;
//     FILE *temp_fp;
//     char line[256];

//     printf("please input username: ");
//     scanf("%s", username);
//     printf("please input passwd: ");
//     scanf("%s", password);

//     if (!user_exists(username))
//     {
//         printf("user not exist\n");
//         exit(1);
//     }

//     if (!authenticate_user(username, password))
//     {
//         printf("passwd not correct\n");
//         exit(1);
//     }

//     printf("please input passwd: ");
//     scanf("%s", new_password);

//     get_hash_value(new_password, hashed_password_hex);

//     fp = fopen("/etc/aeskey", "a");
//     temp_fp = fopen("/etc/temp_file", "a");
//     if (fp == NULL || temp_fp == NULL)
//     {
//         printf("can not open file\n");
//         exit(1);
//     }
//     rewind(fp);

//     while (fgets(line, sizeof(line), fp))
//     {

//         char *token = strtok(line, ":");
//         if (strcmp(token, username) == 0)
//         {

//             fprintf(temp_fp, "%s:%s:", username, hashed_password_hex);
//             // RAND_bytes(aes_key, AES_KEY_LEN);
//             // for (int i = 0; i < AES_KEY_LEN; i++)
//             // {
//             //     fprintf(temp_fp, "%02x", aes_key[i]);
//             // }
//             // fprintf(temp_fp, "\n");
//             printf("passwd change success!\n");
//         }
//         else
//         {

//             fputs(line, temp_fp);
//         }
//     }

//     fclose(fp);
//     fclose(temp_fp);

//     // remove("/etc/aeskey");
//     // rename("/etc/temp_file", "/etc/aeskey");
// }

bool authenticate_user(const char *username, const char *password)
{
    char hashed_password_hex[MAX_HASH_LEN];
    // unsigned char aes_key[AES_KEY_LEN];
    char *token;
    FILE *fp;
    char line[256];

    get_hash_value(password, hashed_password_hex);

    fp = fopen("/etc/aeskey", "r");
    if (fp == NULL)
    {
        printf("can not open file\n");
        exit(1);
    }

    while (fgets(line, sizeof(line), fp))
    {

        token = strtok(line, ":");
        if (strcmp(token, username) == 0)
        {

            token = strtok(NULL, ":");
            if (strcmp(token, hashed_password_hex) == 0)
            {

                fclose(fp);
                return true;
            }
        }
    }

    fclose(fp);
    return false;
}

void get_hash_value(const char *password, char *hashed_password_hex)
{
    char hashed_password[EVP_MAX_MD_SIZE];
    unsigned int hashed_password_len;

    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(&mdctx, password, strlen(password));
    EVP_DigestFinal(&mdctx, hashed_password, &hashed_password_len);
    EVP_MD_CTX_cleanup(&mdctx);

    for (int i = 0; i < hashed_password_len; ++i)
    {
        sprintf(&hashed_password_hex[2 * i], "%02x", hashed_password[i]);
    }
    hashed_password_hex[2 * hashed_password_len] = '\0';
}

// void get_aes_key(const char *username, unsigned char *aes_key)
// {
//     FILE *fp;
//     char line[256];
//     char *token;

//     fp = fopen("/etc/aeskey", "r");
//     if (fp == NULL)
//     {
//         printf("can not open file\n");
//         exit(1);
//     }

//     while (fgets(line, sizeof(line), fp))
//     {

//         token = strtok(line, ":");
//         if (strcmp(token, username) == 0)
//         {

//             token = strtok(NULL, ":");
//             // token = strtok(NULL, ":");
//             // aes_key = token;
//             strcpy(aes_key, token);
//             fclose(fp);
//             return;
//         }
//     }

//     printf("user not exist\n");
//     fclose(fp);
//     exit(1);
// }