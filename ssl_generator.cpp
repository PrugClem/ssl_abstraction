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
#include <thread>
#include <string.h>

#include "ssl_abstraction.hpp"

void dh_gen_callback(int, int, char*, const size_t);

int main()
{
    constexpr size_t backlog_len = 127;
    char backlog_data[backlog_len + 1];
    memset(backlog_data, 0, sizeof(backlog_data));

    std::error_code ec;
    ssl::key_pair root_key, server_key, client_key;
    ssl::crt_signing_request server_csr, client_csr;
    ssl::certificate root_crt, server_crt, client_crt;

    ssl::certificate_subject server_subject, client_subject;
    server_subject.country_name = client_subject.country_name = "AT";
    server_subject.state_name = client_subject.state_name = "LA";
    server_subject.locality_name = client_subject.locality_name = "VIE";
    server_subject.organisation_name = client_subject.organisation_name = "Private";
    server_subject.common_name = "server certificate";
    client_subject.common_name = "client certificate";

    // read root key from file
    root_key.read_from_file("crt/root.key", ec);
    std::cout << "root_key.read_from_file(): " << ec.message() << std::endl; if (ec) { return -1; }

    root_crt.read_from_file("crt/root.crt", ec);
    std::cout << "root_crt.read_from_file(): " << ec.message() << std::endl;  if (ec) { return -1; }

    // generate the server's key and certificate
    server_key.generate_rsa(2048, ec);
    std::cout << "server_key.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    server_csr.create(server_key, server_subject, ec);
    std::cout << "server_csr.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    server_crt.create_from_request(root_key, root_crt, server_csr, ssl::valid_now, ssl::valid_1_year, ec);
    std::cout << "server_crt.generate_from_request(): " << ec.message() << std::endl; if (ec) { return -1; }

    // generate the client's key and certificate
    client_key.generate_rsa(2048, ec);
    std::cout << "client_key.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    client_csr.create(client_key, client_subject, ec);
    std::cout << "client_csr.generate(): " << ec.message() << std::endl; if (ec) { return -1; }

    client_crt.create_from_request(root_key, root_crt, client_csr, ssl::valid_now, ssl::valid_1_year, ec);
    std::cout << "client.crt.generate_from_request(): " << ec.message() << std::endl; if (ec) { return -1; }

    // generate Diffie Hellman Parameters for key-exchange
    ssl::generate_dhparams("crt/dh4096.pem", 4096, 2, std::bind(dh_gen_callback, std::placeholders::_1, std::placeholders::_2, backlog_data, backlog_len), ec);
    std::cout << "ssl::generate_dhparams(): " << ec.message() << std::endl; if (ec) { return -1; }

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

void buffer_push_back(char* buffer, const size_t bufferlen, char data)
{
    size_t last = std::min(bufferlen-1, strlen(buffer));
    if(last == bufferlen-1)
        for (size_t i = 1; i < last; i++)
        {
            buffer[i - 1] = buffer[i];
        }
    buffer[last] = data;
}

void print_buffer(char* buffer, const size_t bufferlen, std::ostream& output)
{
    for(size_t i=0; i<bufferlen; i++)
    {
        output << buffer[i];
    }
}

void dh_gen_callback(int p, int n, char* backlog_data, const size_t backlog_len)
{
    char c = '\0';
    if(p == 0)
        c = '.';
    else if(p == 1)
        c = '+';
    else if(p == 2)
        c = '*';
    else if(p == 3)
        c = '\n';
    if(c != '\0') buffer_push_back(backlog_data, backlog_len, c);
    std::cout << "n: " << n << " Backlog: " << backlog_data << "\r";
    std::cout.flush();
}
