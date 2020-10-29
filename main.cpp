#include <iostream>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "openssl_rsa.h"

using namespace std;


int main() {

    RSA *private_key;
    RSA *public_key;

    char message[KEY_LENGTH / 8] = "Demo message";
    char *encrypt = NULL;
    char *decrypt = NULL;

    char private_key_pem[12] = "private_key";
    char public_key_pem[11]  = "public_key";


    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);
    printf("Generate key has been created.");

    private_key = create_RSA(keypair, PRIVATE_KEY_PEM, private_key_pem);
    printf("Private key pem file has been created.");

    public_key  = create_RSA(keypair, PUBLIC_KEY_PEM, public_key_pem);
    printf("Public key pem file has been created.");;

    encrypt = (char*)malloc(RSA_size(public_key));
    int encrypt_length = public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
    if(encrypt_length == -1) {
        printf("error in public_encrypt");
    }
    printf("Data has been encrypted.");

    create_encrypted_file(encrypt, public_key);
    printf("Encrypted file has been created.");

    decrypt = (char *)malloc(encrypt_length);
    int decrypt_length = private_decrypt(encrypt_length, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
    if(decrypt_length == -1) {
        printf("error in private_decrypt()");
    }
    printf("Data has been decrypted.");

    FILE *decrypted_file = fopen("decrypted_file.txt", "w");
    fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
    fclose(decrypted_file);
    printf("Decrypted file has been created.");

    RSA_free(keypair);
    free(private_key);
    free(public_key);
    free(encrypt);
    free(decrypt);
    printf("OpenSSL_RSA has been finished.");

    return 0;
}
