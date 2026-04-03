#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <winsock2.h>
#include <openssl/evp.h>

#pragma comment(lib, "ws2_32.lib") // For MSVC compatibility

// Hardcoded Key and IV (In production, exchange these securely!)
unsigned char *aes_key = (unsigned char *)"01234567890123456789012345678901"; // 32 bytes for AES-256
unsigned char *aes_iv = (unsigned char *)"0123456789012345";                  // 16 bytes for AES block size

// Helper function to encrypt
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

// Helper function to decrypt
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
    int sd, nsd;
    struct sockaddr_in serv_add, cli_add;
    int cliaddrlen, childpid;
    unsigned char buffer[512] = {0};
    unsigned char plaintext[512] = {0};
    unsigned char ciphertext[512] = {0};
    int PORT;

    // 1. Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (argc != 2)
    {
        printf("USAGE: server <portno>\n");
        exit(1);
    }

    PORT = atoi(argv[1]);
    
    // 2. Create Socket
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("SERVER: socket error\n");
        exit(1);
    }

    serv_add.sin_family = AF_INET;
    serv_add.sin_port = htons(atoi(argv[1]));
    serv_add.sin_addr.s_addr = htonl(INADDR_ANY);

    // 3. Bind and Listen
    if (bind(sd, (struct sockaddr *)&serv_add, sizeof(serv_add)) < 0)
    {
        perror("SERVER: bind error\n");
        exit(1);
    }

    if (listen(sd, 5) < 0)
    {
        perror("SERVER: listen error\n");
        exit(1);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1)
    {
        // 4. Accept Client
        cliaddrlen = sizeof(cli_add);
        if ((nsd = accept(sd, (struct sockaddr *)&cli_add, &cliaddrlen)) < 0)
        {
            perror("SERVER: accept error\n");
            exit(1);
        }

        printf("[+] Client connected!\n");
        // 5. Receive, Decrypt, Encrypt, and Echo
        while (1)
        {
            int bytes_read = recv(nsd, (char *)buffer, 512, 0);
            if (bytes_read <= 0)
                break; // Client disconnected

            printf("\n[+] Received Encrypted Data (%d bytes)\n", bytes_read);

            // Decrypt the incoming message
            int decrypted_len = decrypt_msg(buffer, bytes_read, plaintext);
            plaintext[decrypted_len] = '\0'; // Null-terminate for printing
            printf("[+] Decrypted Message: %s\n", plaintext);

            // Encrypt it back to echo
            int encrypted_len = encrypt_msg(plaintext, decrypted_len, ciphertext);

            // Send back to client
            send(nsd, (char *)ciphertext, encrypted_len, 0);
            printf("[+] Echoed encrypted data back to client.\n");
        }
    }
    // Cleanup
    closesocket(nsd);
    closesocket(sd);
    WSACleanup();
    return 0;
}