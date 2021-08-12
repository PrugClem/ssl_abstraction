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
        generate_dhparam
    };
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

            default:
                return "Unknown error";
            }
        }
    }; // struct error_category
    inline static error_category error_instance;

    using dh_generator_callback = void(*)(int, int, void*);

    [[deprecated ("Wait for proper C++ implementation, this is using C-style function pointers") ]]
    std::error_code& generate_dhparams(const std::string& filename, int length_bits, int generator_number, ssl::dh_generator_callback callback, void* arg, std::error_code& ec)
    {
// preprocessor directive to choose generating mode
// if 0: use openssl dhparam command with std::system
// if 1: use c code to generate the dh parameters
#if 1
        DH* dh;
        BN_GENCB* cb;
        bool success;
        FILE *file;

        cb = BN_GENCB_new();
        if(!cb)
        {
            ec.assign(ssl::error_enum::alloc_gencb, ssl::error_instance);
            BN_GENCB_free(cb);
        }
        BN_GENCB_set_old(cb, callback, arg );
        dh = DH_new();
        if(!dh)
        {
            ec.assign(ssl::error_enum::alloc_dh, ssl::error_instance);
            BN_GENCB_free(cb);
        }
        success = DH_generate_parameters_ex(dh, length_bits, generator_number, cb);
        if(!success)
        {
            ec.assign(ssl::error_enum::generate_dhparam, ssl::error_instance);
            BN_GENCB_free(cb);
        }
        file = ::fopen(filename.c_str(), "wb");
        if(!file)
        {
            ec.assign(ssl::error_enum::fopen, ssl::error_instance);
            fclose(file);
            BN_GENCB_free(cb);
        }

        PEM_write_DHparams(file, dh);

        fclose(file);
        BN_GENCB_free(cb);
#else
        std::stringstream commandbuffer;
        commandbuffer << "openssl dhparam -out " << filename << " " << length_bits;
        std::system(commandbuffer.str().c_str());
#endif
        return ec;
    }
} // namespace ssl
