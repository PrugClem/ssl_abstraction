/**
* @file     ssl_client.cpp
* @brief    simple program to generate a (self signed) SSL certificate
* @author   Clemens Pruggmayer
* (c) 2021 by Clemens Pruggmayer
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#include "ssl_key_pair.hpp"

int main()
{
    std::error_code ec;
    ssl::key_pair key;

    key.generate(2048, ec);
    std::cout << "key.generate(): " << ec.message() << std::endl;

    key.write_to_file("crt/test.key", ec);
    std::cout << "key.write_to_file(): " << ec.message() << std::endl;

    std::cout << "Done running program";
    return 0;
}
