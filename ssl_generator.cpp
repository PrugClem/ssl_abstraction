/**
* @file     ssl_generator.cpp
* @brief    simple program to generate a server and client certificate from a root key
* @author   Clemens Pruggmayer
* (c) 2021 by Clemens Pruggmayer
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#include <iostream>

#include "ssl_abstraction.hpp"

int main()
{
    ssl::error_category test;
    ssl::error_enum test2;
    
    std::error_code ec;
    ssl::key_pair root_key, server_key, client_key;
    ssl::crt_signing_request server_csr, client_csr;
    ssl::certificate root_crt, server_crt, client_crt;

    /*key.generate(2048, ec);
    std::cout << "key.generate(): " << ec.message() << std::endl;

    key.write_to_file("crt/test.key", ec);
    std::cout << "key.write_to_file(): " << ec.message() << std::endl;

    copy.read_from_file("crt/root.key", ec);
    std::cout << "key.read_from_file(): " << ec.message() << std::endl;

    copy.write_to_file("crt/root_copy.key", ec);
    std::cout << "key.write_to_file(): " << ec.message() << std::endl;*/

    // read root key from file
    root_key.read_from_file("crt/root.key", ec);
    std::cout << "root_key.read_from_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    root_crt.read_from_file("crt/root.crt", ec);
    std::cout << "root_crt.read_from_file(): " << ec.message() << std::endl;  if (ec) { return -1; }

    // generate the server's key and certificate
    server_key.generate(2048, ec);
    std::cout << "server_key.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    server_csr.create(server_key, ec);
    std::cout << "server_csr.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    server_crt.create_from_request(root_key, root_crt, server_csr, ssl::valid_now, ssl::valid_1_year, ec);
    std::cout << "server_crt.generate_from_request(): " << ec.message() << std::endl; if (ec) { return -1; }

    // generate the client's key and certificate
    client_key.generate(2048, ec);
    std::cout << "client_key.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    client_csr.create(client_key, ec);
    std::cout << "client_csr.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    client_crt.create_from_request(root_key, root_crt, client_csr, ssl::valid_now, ssl::valid_1_year, ec);
    std::cout << "client.crt.generate_from_request(): " << ec.message() << std::endl; if (ec) { return -1; }

    ssl::generate_dhparams("crt/dh4096.pem", 4096, ec);

    // write keys and certificates to the respective files
    server_key.write_to_file("crt/server.key", ec);
    std::cout << "server_key.write_to_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    server_csr.write_to_file("crt/server.csr", ec);
    std::cout << "server_csr.write_to_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    server_crt.write_to_file("crt/server.crt", ec);
    std::cout << "server_crt.write_to_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    client_key.write_to_file("crt/client.key", ec);
    std::cout << "client_key.write_to_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    client_csr.write_to_file("crt/client.csr", ec);
    std::cout << "client_csr.write_to_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    client_crt.write_to_file("crt/client.crt", ec);
    std::cout << "client_crt.write_to_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    std::cout << "Done running program" << std::endl;
    return 0;
}
