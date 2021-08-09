/**
* @file     ssl_crt_signing_request.hpp
* @brief    simple OpenSSL implementation to create an SSL certificate signing request
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
    class crt_signing_request
    {
    public:
        using native_handle_t = X509_REQ*;
    private:
        native_handle_t _csr{ nullptr };

        // make non-movable
        crt_signing_request(const crt_signing_request&) = delete; // copy constuctor
        crt_signing_request& operator=(const crt_signing_request&) = delete; // copy assign
        crt_signing_request(crt_signing_request&&) = delete; // move constructor
        crt_signing_request& operator=(crt_signing_request&&) = delete; // move assign
    public:
        crt_signing_request() {}
        virtual ~crt_signing_request()
        {
            if (_csr != nullptr) X509_REQ_free(_csr);
        }
        native_handle_t native_handle() { return _csr; }
        std::error_code& read_from_file(const std::string& filename, std::error_code& ec)
        {
            FILE* file = ::fopen(filename.c_str(), "rb"); // open file to read the certificate signing request from
            if (!file)
            {
                ec.assign(ssl::error_enum::fopen, ssl::error_instance);
                return ec;
            }
            bool success = PEM_read_X509_REQ(file, &_csr, NULL, NULL);
            if (!success)
            {
                ec.assign(ssl::error_enum::read_signing_request, ssl::error_instance);
                fclose(file);
                return ec;
            }
            fclose(file);
            return ec;
        }
        std::error_code& write_to_file(const std::string& filename, std::error_code& ec)
        {
            FILE* file = ::fopen(filename.c_str(), "wb"); // open file to write the certificate signing request
            if (!file)
            {
                ec.assign(ssl::error_enum::fopen, ssl::error_instance);
                return ec;
            }
            bool success = PEM_write_X509_REQ(file, _csr);
            if (!success)
            {
                ec.assign(ssl::error_enum::write_signing_request, ssl::error_instance);
                fclose(file);
                return ec;
            }
            fclose(file);
            return ec;
        }
        std::error_code& create(ssl::key_pair& key, std::error_code& ec)
        {
            bool success;

            if (_csr != nullptr) X509_REQ_free(_csr);

            _csr = X509_REQ_new();
            if (!_csr)
            {
                ec.assign(ssl::error_enum::alloc_signing_struct, ssl::error_instance);
                return ec;
            }

            success = X509_REQ_set_pubkey(_csr, key.native_handle());
            if (!success)
            {
                ec.assign(ssl::error_enum::assign_pub_key, ssl::error_instance);
                return ec;
            }

            success = X509_REQ_sign(_csr, key.native_handle(), EVP_sha256());
            if (!success)
            {
                ec.assign(ssl::error_enum::sign_request, ssl::error_instance);
                return ec;
            }

            return ec;
        }
    }; // class crt_signing_request
} // namespace ssl
