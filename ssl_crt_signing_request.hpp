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
        std::error_code& create(ssl::key_pair& key, const ssl::certificate_subject& subject, std::error_code& ec)
        {
            bool success;
            X509_NAME *_subject;

            if (_csr != nullptr) X509_REQ_free(_csr);

            _subject = X509_NAME_new();
            if (!_subject)
            {
                ec.assign(ssl::error_enum::alloc_subject_struct, ssl::error_instance);
                X509_NAME_free(_subject);
                return ec;
            }

            _csr = X509_REQ_new();
            if (!_csr)
            {
                ec.assign(ssl::error_enum::alloc_signing_struct, ssl::error_instance);
                X509_NAME_free(_subject);
                return ec;
            }

            success = X509_REQ_set_pubkey(_csr, key.native_handle());
            if (!success)
            {
                ec.assign(ssl::error_enum::assign_pub_key, ssl::error_instance);
                X509_NAME_free(_subject);
                return ec;
            }

            // Set subject field if the field is not empty in the parameters
            if(!subject.country_name.empty())           X509_NAME_add_entry_by_txt(_subject, "C", MBSTRING_ASC, (const unsigned char*)subject.country_name.c_str(), -1, -1, 0);
            if(!subject.state_name.empty())             X509_NAME_add_entry_by_txt(_subject, "S", MBSTRING_ASC, (const unsigned char*)subject.state_name.c_str(), -1, -1, 0);
            if(!subject.locality_name.empty())          X509_NAME_add_entry_by_txt(_subject, "L", MBSTRING_ASC, (const unsigned char*)subject.locality_name.c_str(), -1, -1, 0);
            if(!subject.organisation_name.empty())      X509_NAME_add_entry_by_txt(_subject, "O", MBSTRING_ASC, (const unsigned char*)subject.organisation_name.c_str(), -1, -1, 0);
            if(!subject.organisation_unit_name.empty()) X509_NAME_add_entry_by_txt(_subject, "OU", MBSTRING_ASC, (const unsigned char*)subject.organisation_unit_name.c_str(), -1, -1, 0);
            if(!subject.common_name.empty())            X509_NAME_add_entry_by_txt(_subject, "CN", MBSTRING_ASC, (const unsigned char*)subject.common_name.c_str(), -1, -1, 0);
            if(!subject.email.empty())                  X509_NAME_add_entry_by_txt(_subject, "E", MBSTRING_ASC, (const unsigned char*)subject.email.c_str(), -1, -1, 0);

            success = X509_REQ_set_subject_name(_csr, _subject);
            if (!success)
            {
                ec.assign(ssl::error_enum::set_subject_name, ssl::error_instance);
                X509_NAME_free(_subject);
                return ec;
            }

            success = X509_REQ_sign(_csr, key.native_handle(), EVP_sha256());
            if (!success)
            {
                ec.assign(ssl::error_enum::sign_request, ssl::error_instance);
                X509_NAME_free(_subject);
                return ec;
            }

            return ec;
        }
    }; // class crt_signing_request
} // namespace ssl
