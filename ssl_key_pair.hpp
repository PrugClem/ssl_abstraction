/**
* @file     ssl_key_pair.hpp
* @brief    simple OpenSSL implementation to create an RSA key pair
* @author   Clemens Pruggmayer
* (c) 2021 by Clemens Pruggmayer
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#pragma once

#include "ssl_defs.hpp"

namespace ssl
{
    class key_pair
    {
    public:
        // native handle is used in order to make the code more readable
        using native_handle_t = EVP_PKEY*;
    private:
        native_handle_t _key{ nullptr };

        // make non-movable
        key_pair(const key_pair&) = delete; // copy constuctor
        key_pair& operator=(const key_pair&) = delete; // copy assign
        key_pair(key_pair&&) = delete; // move constructor
        key_pair& operator=(key_pair&&) = delete; // move assign
    public:
        key_pair() {}
        virtual ~key_pair()
        {
            if (_key != nullptr) { EVP_PKEY_free(_key); _key = nullptr; } // only free the memory if it needs to be free'd
        }
        /**
         * @brief get the native OpenSSL handle for the EVP_PKEY
         */
        native_handle_t native_handle() { return _key; }
        /**
         * @brief read a private key from the filesystem. the key is stored in the calling object
         * 
         * @param filename the location of the key in a pem file
         * @param ec error code to write errors to
         * @return the returned reference refers to the provided std::error_code
         */
        std::error_code& read_from_file(const std::string& filename, std::error_code& ec)
        {
            FILE* file = ::fopen(filename.c_str(), "rb"); // open file to read from
            if (!file)
            {
                ec.assign(ssl::error_enum::fopen, ssl::error_instance);
                return ec;
            }
            bool success = PEM_read_PrivateKey(file, &_key, NULL, NULL); // read the private key from the file
            if (!success)
            {
                ec.assign(ssl::error_enum::read_key_pair, ssl::error_instance);
                fclose(file);
                return ec;
            }

            fclose(file);
            return ec;
        }
        /**
         * @brief write a key pair into a file in the filesystem. the key stored in the calling object is written.
         * 
         * @param filename the filename to write the key pair to
         * @param ec error code to write errors to
         * @return the returned reference refers to the provided std::error_code
         */
        std::error_code& write_to_file(const std::string& filename, std::error_code& ec)
        {
            FILE* file = ::fopen(filename.c_str(), "wb"); // open file to export private key
            if (!file)
            {
                ec.assign(ssl::error_enum::fopen, ssl::error_instance);
                return ec;
            }
            bool success = PEM_write_PrivateKey(file, _key, NULL, NULL, 0, NULL, NULL); // write private key to file
            if (!success)
            {
                ec.assign(ssl::error_enum::write_key_pair, ssl::error_instance);
                fclose(file);
                return ec;
            }

            fclose(file);
            return ec;
        }
        /**
         * @brief generate a key pair for RSA asymetric encryption
         * 
         * @param keylength_bits the length of the RSA key in bits
         * @param ec error code to write errors to
         * @return the returned reference refers to the provided std::error_code
         */
        std::error_code& generate_rsa(int keylength_bits, std::error_code& ec)
        {
            BIGNUM* bne{ nullptr };
            RSA* _rsa{ nullptr };
            int ret;

            if (_key != nullptr) EVP_PKEY_free(_key); // deallocate key if key is already loaded

            _key = EVP_PKEY_new(); // allocate EVP_PKEY memory
            if (!_key)
            {
                ec.assign(ssl::error_enum::create_evp_pkey, ssl::error_instance);
                return ec;
            }

            bne = BN_new();
            ret = BN_set_word(bne, 65537); // set RSA key exponent
            if (ret != 1)
            {
                ec.assign(ssl::error_enum::bn_set_word, ssl::error_instance);
                return ec;
            }
            _rsa = RSA_new();
            ret = RSA_generate_key_ex(_rsa, keylength_bits, bne, NULL);
            if (ret != 1)
            {
                ec.assign(ssl::error_enum::gen_rsa, ssl::error_instance);
                return ec;
            }
            if (!EVP_PKEY_assign_RSA(_key, _rsa))
            {
                ec.assign(ssl::error_enum::gen_rsa, ssl::error_instance);
                return ec;
            }
            return ec;
        }
    }; // class key_pair
} // namespace ssl
