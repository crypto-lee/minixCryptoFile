#include "aes.h"
#include "user.h"

int main()
{
    int choice;
    char username[MAX_USERNAME_LEN];
    unsigned char user_key[17];
    // detail menu
    while (1)
    {
        printf("1. regeist\n");
        printf("2. login\n");
        printf("3. exit\n");
        printf("pleasr choice: ");
        scanf("%d", &choice);
        if (choice == 1)
        {
            if (register_user())
            {
                printf("register success\n");
            }
            else
            {
                printf("register failed\n");
            }
        }
        else if (choice == 2)
        {
            if (login(username))
            {
                printf("login success\n");
                break;
            }
            else
            {
                printf("login failed\n");
            }
        }
        else if (choice == 3)
        {
            return 0;
        }
        else
        {
            printf("Parameter input error\n");
        }
    }
    printf("1. encrypto file\n");
    printf("2. decrypto file\n");
    printf("3. exit\n");
    scanf("%d", &choice);
    if (choice == 1)
    {
        printf("please input input file path\n");
        char input_file[100];
        scanf("%s", input_file);
        printf("please input output file path\n");
        char output_file[100];
        user_key = get_aes_key(username);
        encrypt_file(user_key, input_file, output_file);
    }
    else if (choice == 2)
    {
        printf("please input input file path\n");
        char input_file[100];
        scanf("%s", input_file);
        printf("please input output file path\n");
        char output_file[100];
        user_key = get_aes_key(username);
        decrypt_file(user_key, input_file, output_file);
    }
    else if (choice == 3)
    {
        return 0;
    }
    else
    {
        printf("Parameter input error\n");
    }
}