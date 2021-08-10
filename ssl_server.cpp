/**
* @file     ssl_server.cpp
* @brief    simple ssl server with client certificate verification
* @author   Clemens Pruggmayer
* (c) 2021 by Clemens Pruggmayer
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#include <iostream>

#include <asio.hpp>
#include <asio/ssl.hpp>

bool verify_certificate_callback(bool preverified, asio::ssl::verify_context& verify_context)
{
    // this function just prints the subject string of the certificate
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(verify_context.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, sizeof(subject_name));
    std::clog << "Preverified: " << (preverified ? "yes" : "no ") << "  Verifying " << subject_name << std::endl;
    return preverified;
}

int main()
{
    try
    {
        char buf[256];
        std::size_t len;
        std::error_code ec;
        asio::io_context io_context; // asio io context

        asio::ssl::context ssl_context(asio::ssl::context::tlsv13_server); // ssl_context: using TLSv1.3 as a server

        // ========== set SSL context options ==========
        // set verification mode to require a client certificate (fail if client does not send one)
        ssl_context.set_verify_mode(asio::ssl::context_base::verify_peer | asio::ssl::context_base::verify_fail_if_no_peer_cert, ec);
        std::cout << "ssl_context.set_verify_mode(): " << ec.message() << std::endl;
        
        // specify server certificate file for tls authentication
        ssl_context.use_certificate_file("crt/server.crt", asio::ssl::context_base::file_format::pem, ec);
        std::cout << "ssl_context.use_certificate_file(): " << ec.message() << std::endl;
        
        // specify server private key file for encryption
        ssl_context.use_private_key_file("crt/server.key", asio::ssl::context_base::pem, ec);
        std::cout << "ssl_context.use_private_key_file(): " << ec.message() << std::endl;
        
        // set callback function for key password callback. currently, the generated keys are not password protected
        ssl_context.set_password_callback([](std::size_t, asio::ssl::context::password_purpose) {return ""; }, ec);
        std::cout << "ssl_context.set_password_callback(): " << ec.message() << std::endl;
        
        // temporary diffie-hellman parameters for keyexchange
        //ssl_context.use_tmp_dh_file("crt/dh4096.pem", ec);
        //std::cout << "ssl_context.use_tmp_dh_file(): " << ec.message() << std::endl;

        // root certificate to verify client certificate
        ssl_context.load_verify_file("crt/root.crt", ec);
        std::cout << "ssl_context.load_verify_file(): " << ec.message() << std::endl;

        // set the callback for optional additional verification
        ssl_context.set_verify_callback(verify_certificate_callback, ec);
        std::clog << "ssl_context.set_verify_callback(): " << ec.message() << std::endl;

        // ========== set up TCP server and accept TCP connection ==========
        asio::ip::tcp::acceptor acceptor(io_context); // socket to accept tcp connections, will be closed after accepting one connection
        asio::ssl::stream< asio::ip::tcp::socket> connection(io_context, ssl_context); // ssl stream for the connection, tcp socket is contained within and accessible with the lowest_layer() method

        acceptor.open(asio::ip::tcp::v4(), ec); // IPv4 server
        std::clog << "acceptor.open(): " << ec.message() << std::endl;

        acceptor.bind(asio::ip::tcp::endpoint(asio::ip::address::from_string("0.0.0.0"), 10000), ec); // bind to all interfaced port 10000
        std::clog << "acceptor.bind(): " << ec.message() << std::endl;
        if (ec) return -1; // exit if bind was unsuccessful (e.g. address already in use, etc)

        acceptor.listen(1, ec); // listen for 1 connection
        std::cout << "acceptor.listen(): " << ec.message() << std::endl;

        connection.lowest_layer() = acceptor.accept(ec); // accept one connection
        std::cout << "acceptor.accept(): " << ec.message() << std::endl;
        
        acceptor.close(ec); // close the acceptor socket since this program will not accept any more connections
        std::cout << "acceptor.close(): " << ec.message() << std::endl;

        // ========== perform TLS Handshake ==========
        connection.handshake(asio::ssl::stream_base::handshake_type::server, ec);
        std::cout << "connection.handshake(): " << ec.message() << std::endl;
        if (ec) return -2; // exit if tls handshake was unsuccessful


        // ========== use the connection ==========
        len = connection.read_some(asio::buffer(buf, sizeof(buf)), ec); // wait for the client to send data
        std::clog << "connection.read_some(): " << ec.message() << std::endl;

        std::cout << "data reveived (" << len << " bytes): " << buf << std::endl; // print received data

        connection.write_some(asio::buffer(buf, strlen(buf) + 1), ec); // echo received data
        std::clog << "connection.write_some(): " << ec.message() << std::endl;
        // ========== done with using connection ==========
        


        // ========== close TLS & TCP connection ==========
        connection.shutdown(ec); // shut down the tls connection, tcp connection will still be open
        std::cout << "connection.shutdown(): " << ec.message() << std::endl;
        
        connection.lowest_layer().shutdown(asio::socket_base::shutdown_both, ec); // shut down tcp connection (FIN and not RST)
        std::cout << "connection.tcp.shutdown(): " << ec.message() << std::endl;
        
        connection.lowest_layer().close(ec); // close the tcp connection socket
        std::cout << "connection.tcp.close(): " << ec.message() << std::endl;

        // ========== stop IO context ===========
        io_context.stop();
    }
    catch(std::exception &e)
    {
        // if an exception occurs, print the message and terminate
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}
