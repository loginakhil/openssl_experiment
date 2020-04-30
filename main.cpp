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
    std::string inFile(argv[1]);
    std::cout << inFile << std::endl;
    std::cout << std::endl;

    BIO_ptr input(BIO_new(BIO_s_file()), BIO_free);
    if (BIO_read_filename(input.get(), inFile.c_str()) <= 0)
    {
        std::cout << "Error reading file" << std::endl;
        return 1;
    }

    // Create an openssl certificate from the BIO
    X509_ptr cert(PEM_read_bio_X509_AUX(input.get(), NULL, NULL, NULL), X509_free);

    // Create a BIO to write info to stdout from the cert
    BIO_ptr output_bio(BIO_new_fp(stdout, BIO_NOCLOSE), BIO_free);

    EVP_PKEY_ptr pub_key(X509_get_pubkey(cert.get()), EVP_PKEY_free);

    EVP_PKEY_print_public(output_bio.get(), pub_key.get(), 0, NULL);

    PEM_write_bio_PUBKEY(output_bio.get(), pub_key.get());

    BIO_reset(output_bio.get());

    FIPS_mode_set(0);
    CONF_modules_unload(1);
    CONF_modules_free();
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
