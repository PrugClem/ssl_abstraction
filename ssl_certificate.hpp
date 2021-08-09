/**
* @file     ssl_certificate.hpp
* @brief    simple OpenSSL implementation to create an SSL certificate
* @author   Clemens Pruggmayer
* (c) 2021 by Clemens Pruggmayer
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#pragma once

#include <chrono>

#include "ssl_defs.hpp"

namespace ssl
{
    class certificate
    {
    public:
        using native_handle_t = X509*;
    private:
        native_handle_t _crt{ nullptr };
        
        // make non-movable
        certificate(const crt_signing_request&) = delete; // copy constuctor
        certificate& operator=(const crt_signing_request&) = delete; // copy assign
        certificate(crt_signing_request&&) = delete; // move constructor
        certificate& operator=(crt_signing_request&&) = delete; // move assign;
    public:
        certificate() {}
        virtual ~certificate()
        {
            if (_crt != nullptr) { X509_free(_crt); }
        }
        native_handle_t native_handle() { return _crt; }
        std::error_code& read_from_file(const std::string& filename, std::error_code& ec)
        {
            FILE* file = ::fopen(filename.c_str(), "rb");
            if (!file)
            {
                ec.assign(ssl::error_enum::fopen, ssl::error_instance);
                return ec;
            }
            bool success = PEM_read_X509(file, &_crt, NULL, NULL);
            if (!success)
            {
                ec.assign(ssl::error_enum::read_certificate, ssl::error_instance);
                fclose(file);
                return ec;
            }
            fclose(file);
            return ec;
        }
        std::error_code& write_to_file(const std::string& filename, std::error_code& ec)
        {
            FILE* file = ::fopen(filename.c_str(), "wb");
            if (!file)
            {
                ec.assign(ssl::error_enum::fopen, ssl::error_instance);
                return ec;
            }
            bool success = PEM_write_X509(file, _crt);
            if (!success)
            {
                ec.assign(ssl::error_enum::write_certificate, ssl::error_instance);
                fclose(file);
                return ec;
            }
            fclose(file);
            return ec;
        }
        std::error_code& create_from_request(ssl::key_pair& ca_private_key, ssl::certificate& ca_cert, ssl::crt_signing_request& sign_request,
            std::chrono::seconds valid_from, std::chrono::seconds valid_to, std::error_code& ec)
        {
            ASN1_INTEGER* p_serial_number{ NULL };
            BIGNUM* p_bignum;
            EVP_PKEY *request_key, *ca_pub_key;
            bool success;

            ca_pub_key = X509_get_pubkey(ca_cert.native_handle());
            if(!ca_pub_key)
            {
                ec.assign(ssl::error_enum::get_ca_cert_key, ssl::error_instance);
                goto CLEANUP; // goto end of function to reduce the amount of code present
            }

            _crt = X509_new();
            if (!_crt)
            {
                ec.assign(ssl::error_enum::alloc_certificate_struct, ssl::error_instance);
                goto CLEANUP; // goto end of function to reduce the amount of code present
            }

            p_serial_number = ASN1_INTEGER_new();
            p_bignum = BN_new();
            BN_pseudo_rand(p_bignum, 64, 0, 0);
            BN_to_ASN1_INTEGER(p_bignum, p_serial_number);
            BN_free(p_bignum);

            X509_set_serialNumber(_crt, p_serial_number);

            X509_set_issuer_name(_crt, X509_REQ_get_subject_name(sign_request.native_handle()));
            X509_set_subject_name(_crt, X509_REQ_get_subject_name(sign_request.native_handle()));

            X509_gmtime_adj(X509_get_notBefore(_crt), valid_from.count() );
            X509_gmtime_adj(X509_get_notAfter(_crt), valid_to.count() );

            request_key = X509_REQ_get_pubkey(sign_request.native_handle());
            if (!request_key)
            {
                ec.assign(ssl::error_enum::get_request_key, ssl::error_instance);
                goto CLEANUP; // goto end of function to reduce the amount of code present
            }

            success = X509_set_pubkey(_crt, request_key);
            if (!success)
            {
                ec.assign(ssl::error_enum::set_public_key, ssl::error_instance);
                goto CLEANUP; // goto end of function to reduce the amount of code present
            }
            /*success = EVP_PKEY_copy_parameters(ca_pub_key, ca_private_key.native_handle());
            if (!success)
            {
                ec.assign(ssl::error_enum::copy_parameters, ssl::error_instance);
                goto CLEANUP; // goto end of function to reduce the amount of code present
            }*/

            X509_set_issuer_name(_crt, X509_get_subject_name(ca_cert.native_handle()));

            if (!X509_sign(_crt, ca_private_key.native_handle(), EVP_sha256()))
            {
                ec.assign(ssl::error_enum::sign_certificate, ssl::error_instance);
                goto CLEANUP; // goto end of function to reduce the amount of code present
            }

        CLEANUP: // All the code to clean up the signing of the certificate
            EVP_PKEY_free(request_key);
            EVP_PKEY_free(ca_pub_key);
            ASN1_INTEGER_free(p_serial_number);
            //BN_free(p_bignum);

            return ec;
        }
    }; // class certificate
} // namespace ssl
