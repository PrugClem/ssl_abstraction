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
        // native handle is used in order to make the code more readable
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
        /**
         * @brief get the native OpenSSL handle of the certificate
         */
        native_handle_t native_handle() { return _crt; }
        /**
         * @brief read a certificate from a file in the filesystem. The read certificate is then stored in the calling object.
         * 
         * @param filename the location of the certificate in a pem file
         * @param ec error code to write errors to
         * @return the returned reference refers to the provided std::error_code
         */
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
        /**
         * @brief write a certificate to a file in the filesystem. The certificate stored in the calling object is written.
         * 
         * @param filename the filename to write the certificate to
         * @param ec error code to write errors to
         * @return the returned reference refers to the provided std::error_code
         */
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
        /**
         * @brief create a certificate from a certificate signing request. The CA key and certificate have to be provided and the result is stored in the calling object
         * 
         * @param ca_private_key The CA's private key; this method will not try to import this key from a file!
         * @param ca_cert The CA's certificate; this method will not try to import this certificate from a file!
         * @param sign_request The certificate signing request; this method will not try to import this request from a file!
         * @param valid_from a time duration for the start of validity, eg. if the certificate should only be valid in 1 hr
         * @param valid_to a time duration for the end of validity, eg. if the certificate should only be valid for 1 day
         * @param ec error code to write errors to
         * @return the returned reference refers to the provided std::error_code
         */
        std::error_code& create_from_request(ssl::key_pair& ca_private_key, ssl::certificate& ca_cert, ssl::crt_signing_request& sign_request,
            std::chrono::seconds valid_from, std::chrono::seconds valid_to, std::error_code& ec)
        {
            /**
             *  This function uses  goto  in order to reduce the amount of code for the cleanup
             *  It was the best way to handle the Cleanup Process without copy-pasting the same code several times
             * 
             *  The CA certificate is required to write the issuer name into the new certificate
             *  The CA private key is required to actually sign the certificate
             *  The Signing request is needed to get the details about the certificate that should be created
             *  The valid_from and valid_to times are required to set the validity for the certificate
             */
            ASN1_INTEGER* p_serial_number{ NULL };
            BIGNUM* p_bignum;
            EVP_PKEY *request_key, *ca_pub_key;
            bool success;

            ca_pub_key = X509_get_pubkey(ca_cert.native_handle()); // get the public key from the CA certificate
            if(!ca_pub_key)
            {
                ec.assign(ssl::error_enum::get_ca_cert_key, ssl::error_instance);
                goto ssl_certificate_create_from_request_cleanup; // goto end of function to reduce the amount of code present
            }

            _crt = X509_new(); // allocate memory for the certificate itself
            if (!_crt)
            {
                ec.assign(ssl::error_enum::alloc_certificate_struct, ssl::error_instance);
                goto ssl_certificate_create_from_request_cleanup; // goto end of function to reduce the amount of code present
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

            request_key = X509_REQ_get_pubkey(sign_request.native_handle()); // get the public key from the Certificate signing request
            if (!request_key)
            {
                ec.assign(ssl::error_enum::get_request_key, ssl::error_instance);
                goto ssl_certificate_create_from_request_cleanup; // goto end of function to reduce the amount of code present
            }

            success = X509_set_pubkey(_crt, request_key); // set the new certificate's public key to the request's public key
            if (!success)
            {
                ec.assign(ssl::error_enum::set_public_key, ssl::error_instance);
                goto ssl_certificate_create_from_request_cleanup; // goto end of function to reduce the amount of code present
            }
            // This code always causes an error and the program seems to run file without it so it stays commented out
            /*success = EVP_PKEY_copy_parameters(ca_pub_key, ca_private_key.native_handle());
            if (!success)
            {
                ec.assign(ssl::error_enum::copy_parameters, ssl::error_instance);
                goto ssl_certificate_create_from_request_cleanup; // goto end of function to reduce the amount of code present
            }*/
            success = X509_set_subject_name(_crt, X509_REQ_get_subject_name(sign_request.native_handle())); // set the certificate's subject name (Country, Organisation, etc)
            if (!success)
            {
                ec.assign(ssl::error_enum::copy_subject_name, ssl::error_instance);
                goto ssl_certificate_create_from_request_cleanup;
            }

            X509_set_issuer_name(_crt, X509_get_subject_name(ca_cert.native_handle())); // set the certificate's issuer name to the CA's common name

            if (!X509_sign(_crt, ca_private_key.native_handle(), EVP_sha256())) // Sign the certificate using the CA's private key
            {
                ec.assign(ssl::error_enum::sign_certificate, ssl::error_instance);
                goto ssl_certificate_create_from_request_cleanup; // goto end of function to reduce the amount of code present
            }

        ssl_certificate_create_from_request_cleanup: // All the code to clean up the signing of the certificate
            EVP_PKEY_free(request_key);
            EVP_PKEY_free(ca_pub_key);
            ASN1_INTEGER_free(p_serial_number);
            //BN_free(p_bignum);

            return ec;
        }
    }; // class certificate
} // namespace ssl
