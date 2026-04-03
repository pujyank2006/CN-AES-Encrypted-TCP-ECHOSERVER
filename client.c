#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/evp.h>

#pragma comment(lib, "ws2_32.lib")

unsigned char *aes_key = (unsigned char *)"01234567890123456789012345678901";
unsigned char *aes_iv = (unsigned char *)"0123456789012345";

int encrypt_msg(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_msg(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main(int argc, char *argv[])
{
    WSADATA wsaData;
    int sd, i;
    struct sockaddr_in serv_addr, cli_addr;
    unsigned char buffer[512] = {0};
    unsigned char ciphertext[512] = {0};
    unsigned char decryptedtext[512] = {0};
    int PORT;

    if (argc != 3)
    {
        printf("USAGE: client <portno> <server_name>\n");
        exit(1);
    }

    PORT = atoi(argv[1]);

    // 1. Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 2. Create Socket & Connect
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("CLIENT: socket error\n");
        exit(1);
    }

    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(0);
    cli_addr.sin_addr.s_addr = htonl(0L);

    if (bind(sd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0)
    {
        perror("CLIENT: bind error\n");
        exit(1);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr(argv[2]);

    if (connect(sd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("CLIENT: connect error\n");
        exit(1);
    }

    printf("Connected to server %s:%d\n", argv[2], PORT);

    while (1)
    {
        // 3. Prepare the message
        printf("\nEnter message: ");
        fgets((char *)buffer, 512, stdin);
        buffer[strcspn((char *)buffer, "\n")] = '\0';


        printf("\n[+] Original Message: %s\n", buffer);

        // 4. Encrypt message
        int encrypted_len = encrypt_msg((unsigned char *)buffer, strlen(buffer), ciphertext);
        printf("[+] Sending Encrypted Data (%d bytes)...\n", encrypted_len);
        printf("[+] The ciphertext is: %s\n", ciphertext);
        
        // 5. Send over TCP
        send(sd, (char *)ciphertext, encrypted_len, 0);

        // 6. Receive Echo
        int bytes_read = recv(sd, (char *)buffer, 512, 0);
        printf("[+] Received Encrypted Echo (%d bytes)\n", bytes_read);

        // 7. Decrypt Echo
        int decrypted_len = decrypt_msg(buffer, bytes_read, decryptedtext);
        decryptedtext[decrypted_len] = '\0';
        printf("[+] Decrypted Echo: %s\n", decryptedtext);
    }
    // Cleanup
    closesocket(sd);
    WSACleanup();
    return 0;
}