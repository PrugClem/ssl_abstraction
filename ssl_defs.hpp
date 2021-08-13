/**
* @file     ssl_defs.hpp
* @brief    include file for definitions for the ssl abstraction library
* @author   Clemens Pruggmayer
* (c) 2021 by Clemens Pruggmayer
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#pragma once

#include <system_error>     // error handling
#include <chrono>           // certificate validity time
#include <sstream>          // stringstream to generate command line commands
#include <functional>       // dh generator callback function type

#include <openssl/pem.h>    // file IO operations
#include <openssl/x509.h>   // certificate handling
#include <openssl/dh.h>
#include <openssl/bn.h>

namespace ssl {
    constexpr std::chrono::seconds valid_now = std::chrono::seconds(0);
    constexpr std::chrono::seconds valid_1_day = std::chrono::seconds(60 * 60 * 24);
    constexpr std::chrono::seconds valid_30_days = valid_1_day * 30;
    constexpr std::chrono::seconds valid_1_year = valid_1_day * 365;

    /**
     * @brief stores information about a certificate, eg Counter, Organisation, etc
     * 
     */
    struct certificate_subject
    {
        std::string country_name;           // "C"
        std::string state_name;             // "S"
        std::string locality_name;          // "L"
        std::string organisation_name;      // "O"
        std::string organisation_unit_name; // "OU"
        std::string common_name;            // "CN"
        std::string email;                  // "E"
    };

    /**
     * @brief error codes for the ssl abstraction library
     * 
     */
    enum error_enum : int
    {
        none = 0,
        fopen,

        read_key_pair,
        write_key_pair,
        create_evp_pkey,
        bn_set_word,
        gen_rsa,

        read_signing_request,
        write_signing_request,
        alloc_subject_struct,
        alloc_signing_struct,
        assign_pub_key,
        set_subject_name,
        sign_request,

        read_certificate,
        write_certificate,
        alloc_certificate_struct,
        get_ca_cert_key,
        get_request_key,
        set_public_key,
        copy_parameters,
        copy_subject_name,
        sign_certificate,

        alloc_gencb,
        alloc_dh,
        generate_dhparam,
        write_dhparam
    };
    /**
     * @brief error category has to be inherited in order to allow std::error_code decode the integer from the enum
     * 
     */
    struct error_category : std::error_category
    {
        const char* name() const noexcept
        {
            return "ssl.error";
        }
        std::string message(int ev) const
        {
            switch (ev)
            {
            case ssl::error_enum::fopen:
                return "Error opening file handle";

            case ssl::error_enum::read_key_pair:
                return "Error reading private key";
            case ssl::error_enum::write_key_pair:
                return "Error writing private key to file";
            case ssl::error_enum::create_evp_pkey:
                return "Failed to generate EVP_PKEY structure";
            case ssl::error_enum::bn_set_word:
                return "Failed to set RSA Key exponent";
            case ssl::error_enum::gen_rsa:
                return "Failed to generate RSA key pair";

            case ssl::error_enum::read_signing_request:
                return "Failed to read certificate signing request from file";
            case ssl::error_enum::write_signing_request:
                return "Failed to write certificate signing request to file";
            case ssl::error_enum::alloc_subject_struct:
                return "Failed to allocate memory for the subject name";
            case ssl::error_enum::alloc_signing_struct:
                return "Failed to allocate memory for the signing request";
            case ssl::error_enum::assign_pub_key:
                return "Failed to assign public key";
            case ssl::error_enum::set_subject_name:
                return "Failed to set subject name";
            case ssl::error_enum::sign_request:
                return "Failed to create certificate reqeust";

            case ssl::error_enum::read_certificate:
                return "Failed to read certificate";
            case ssl::error_enum::write_certificate:
                return "Failed to write certificate";
            case ssl::error_enum::alloc_certificate_struct:
                return "Failed to allocate memory for the certificate";
            case ssl::error_enum::get_ca_cert_key:
                return "Failed to retrieve the public key from the CA certificate";
            case ssl::error_enum::get_request_key:
                return "Failed to retrieve the public key from the signing request";
            case ssl::error_enum::set_public_key:
                return "Failed to set the certificate's public key";
            case ssl::error_enum::copy_parameters:
                return "Failed to copy CA key's parameters";
            case ssl::error_enum::copy_subject_name:
                return "Failed to copy certificate's subject name";
            case ssl::error_enum::sign_certificate:
                return "Failed to sign the certificate";

            case ssl::error_enum::alloc_gencb:
                return "Failed to allocate memory for the Generator structure";
            case ssl::error_enum::alloc_dh:
                return "Failed to allocate memory for the dhparam structure";
            case ssl::error_enum::generate_dhparam:
                return "Failed to generate DH Parameters";
            case ssl::error_enum::write_dhparam:
                return "Failed to write DH parameters to file";

            default:
                return "Unknown error";
            }
        }
    }; // struct error_category
    // instance for the std::error_code
    inline static error_category error_instance;

    /**
     * @brief generate diffie-hellmann parameters for a DH-key exchange and write the output to a file
     * 
     * @param filename the filename the output should be written to
     * @param length_bits length of the prime number, it is recommended that this number is some power of 2
     * @param generator_number it is recommended to use 2 or 5 for this number
     * @param callback function to let the program know that the process is running and hasn't died yet
     * @param ec error code to write errors to
     * @return the returned reference refers to the provided std::error_code
     */
    std::error_code& generate_dhparams(const std::string& filename, int length_bits, int generator_number, std::function<void(int, int)> callback, std::error_code& ec)
    {
        DH* dh;
        BN_GENCB* cb;
        bool success;
        FILE *file;

        cb = BN_GENCB_new();
        if(!cb)
        {
            ec.assign(ssl::error_enum::alloc_gencb, ssl::error_instance);
            BN_GENCB_free(cb);
            return ec;
        }
        BN_GENCB_set_old(cb, [](int p, int n, void* std_function)
            {
                // get the function pointer back from the parameter and invoke the function
                std::function<void(int, int)> callback = *(std::function<void(int, int)>*)std_function;
                callback(p, n);
            }, &callback);
        dh = DH_new();
        if(!dh)
        {
            ec.assign(ssl::error_enum::alloc_dh, ssl::error_instance);
            BN_GENCB_free(cb);
            return ec;
        }
        success = DH_generate_parameters_ex(dh, length_bits, generator_number, cb);
        if(!success)
        {
            ec.assign(ssl::error_enum::generate_dhparam, ssl::error_instance);
            BN_GENCB_free(cb);
            return ec;
        }
        file = ::fopen(filename.c_str(), "wb");
        if(!file)
        {
            ec.assign(ssl::error_enum::fopen, ssl::error_instance);
            fclose(file);
            BN_GENCB_free(cb);
            return ec;
        }

        success = PEM_write_DHparams(file, dh);
        if (!success)
        {
            ec.assign(ssl::error_enum::write_dhparam, ssl::error_instance);
            fclose(file);
            BN_GENCB_free(cb);
            return ec;
        }
        fclose(file);
        BN_GENCB_free(cb);
        return ec;
    }
} // namespace ssl
