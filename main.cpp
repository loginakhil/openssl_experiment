#include <iostream>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
using namespace std;

// Smart pointers to wrap openssl C types that need explicit free
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&RSA_free)>;

int main(int argc, char *argv[])
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    OPENSSL_no_config();
    if (argc < 2)
    {
        std::cout << "Missing filename" << std::endl;
        return 1;
    }
    if (argc < 3)
    {
        std::cout << "Missing password" << std::endl;
        return 1;
    }
    std::string inFile(argv[1]);    
    std::cout << inFile << std::endl;
    std::cout << std::endl;

    BIO_ptr input(BIO_new(BIO_s_file()), BIO_free);
    if (BIO_read_filename(input.get(), inFile.c_str()) <= 0)
    {
        std::cout << "Error reading file" << std::endl;
        return 1;
    }
    
    RSA_ptr rsa(PEM_read_bio_RSAPrivateKey(input.get(), NULL, NULL, argv[2]), RSA_free);

    // Create a BIO to write info to stdout from the cert
    BIO_ptr output_bio(BIO_new_fp(stdout, BIO_NOCLOSE), BIO_free);    
    PEM_write_bio_RSA_PUBKEY(output_bio.get(), rsa.get());


    BIO_reset(output_bio.get());

    FIPS_mode_set(0);
    CONF_modules_unload(1);
    CONF_modules_free();
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
