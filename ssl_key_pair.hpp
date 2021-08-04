/**
* @file     ssl_key_pair.hpp
* @brief    simple OpenSSL implementation to create an RSA key pair and export it to a file
* @author   Clemens Pruggmayer
* (c) 2021 by Clemens Pruggmayer
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#pragma once

#include <iostream>

#include <openssl/pem.h>
#include <openssl/x509.h>

namespace ssl
{
    class key_pair
    {
        enum error_enum : int
        {
            none = 0,
            create_evp_pkey,
            bn_set_word,
            gen_rsa,
            fopen,
            write_private_key,
            write_public_key
        };
        struct error_category : std::error_category
        {
            const char* name() const noexcept override
            {
                return "ssl.key_pair.error";
            }
            std::string message(int ev) const override
            {
                switch (ev)
                {
                case ssl::key_pair::error_enum::create_evp_pkey:
                    return "Failed to generate EVP_PKEY structure";
                case ssl::key_pair::error_enum::gen_rsa:
                    return "Failed to generate RSA key pair";
                case ssl::key_pair::error_enum::fopen:
                    return "Error opening file handle";
                case ssl::key_pair::error_enum::write_private_key:
                    return "Error writing private key to file";
                case ssl::key_pair::error_enum::write_public_key:
                    return "Error writing public key to file";
                default:
                    return "Unknown error";
                }
            }
        };

    public:
        using native_handle_t = EVP_PKEY*;
        using rsa_handle_t = RSA*;
    private:
        inline static ssl::key_pair::error_category error_instance;
        native_handle_t _key{ nullptr };
        rsa_handle_t _rsa{ nullptr };

        key_pair(const key_pair&) = delete; // copy constuctor
        key_pair& operator=(const key_pair&) = delete; // copy assign
        key_pair(key_pair&&) = delete; // move constructor
        key_pair& operator=(key_pair&&) = delete; // move assign
    public:
        key_pair() {}
        virtual ~key_pair()
        {
            //if (_rsa != nullptr) { RSA_free(_rsa); _rsa = nullptr; }
            if (_key != nullptr) { EVP_PKEY_free(_key); _key = nullptr; }
        }
        native_handle_t native_handle() { return _key; }
        std::error_code& write_to_file(const std::string& filename, std::error_code& ec)
        {
            FILE* file = ::fopen(filename.c_str(), "wb"); // open file to export private key
            if (!file)
            {
                ec.assign(ssl::key_pair::error_enum::fopen, ssl::key_pair::error_instance);
                return ec;
            }
            bool success = PEM_write_PrivateKey(file, _key, NULL, NULL, 0, NULL, NULL); // write private key to file
            if (!success)
            {
                ec.assign(ssl::key_pair::error_enum::write_private_key, ssl::key_pair::error_instance);
            }
            success = PEM_write_PUBKEY(file, _key); // write public key to the same file
            if (!success)
            {
                ec.assign(ssl::key_pair::error_enum::write_public_key, ssl::key_pair::error_instance);
            }

            fclose(file);
            return ec;
        }
        std::error_code& generate(int keylength_bits, std::error_code& ec)
        {
            BIGNUM* bne = NULL;
            int ret;

            _key = EVP_PKEY_new(); // allocate EVP_PKEY memory
            if (!_key)
            {
                ec.assign(ssl::key_pair::error_enum::create_evp_pkey, ssl::key_pair::error_instance);
                return ec;
            }

            // deprecated code
            //_rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
            bne = BN_new();
            ret = BN_set_word(bne, 65537); // set RSA key exponent
            if (ret != 1)
            {
                ec.assign(ssl::key_pair::error_enum::bn_set_word, ssl::key_pair::error_instance);
                return ec;
            }
            _rsa = RSA_new();
            ret = RSA_generate_key_ex(_rsa, keylength_bits, bne, NULL);
            if (ret != 1)
            {
                ec.assign(ssl::key_pair::error_enum::gen_rsa, ssl::key_pair::error_instance);
                return ec;
            }
            if (!EVP_PKEY_assign_RSA(_key, _rsa))
            {
                ec.assign(ssl::key_pair::error_enum::gen_rsa, ssl::key_pair::error_instance);
                return ec;
            }
            return ec;
        }
    };
} // namespace ssl
