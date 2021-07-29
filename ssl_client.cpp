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
        char buf[256] = "Hello\n";
        std::size_t len;
        std::error_code ec;
        asio::io_context io_context;

        asio::ssl::context ssl_context(asio::ssl::context::tls_client);

        // ========== set SSL context options ==========
        // set the verification to verify the server certificate and fail if the server does not privide a certificate
        ssl_context.set_verify_mode(asio::ssl::context_base::verify_peer | asio::ssl::context_base::verify_fail_if_no_peer_cert, ec); // TODO: CHANGE VERIFY MODE
        std::clog << "ssl_context.set_verify_mode(): " << ec.message() << std::endl;

        // set the callback for optinal additional verification
        ssl_context.set_verify_callback(verify_certificate_callback, ec);
        std::clog << "ssl_context.set_verify_callback(): " << ec.message() << std::endl;

        // load root certificate to verify the server certificate
        ssl_context.load_verify_file("crt/root.crt", ec);
        std::clog << "ssl_context.load_verify_file(): " << ec.message() << std::endl;

        // load client certificate file for 2 way authentication
        ssl_context.use_certificate_file("crt/client.crt", asio::ssl::context_base::file_format::pem, ec);
        std::clog << "ssl_context.use_certificate_file(): " << ec.message() << std::endl;

        // load client private key for 2 way authentication
        ssl_context.use_private_key_file("crt/client.key", asio::ssl::context_base::file_format::pem, ec);
        std::clog << "ssl_context.use_private_key_file(): " << ec.message() << std::endl;

        // ========== set up TCP connection ==========
        asio::ssl::stream<asio::ip::tcp::socket> connection(io_context, ssl_context);
        connection.lowest_layer().connect(asio::ip::tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 10000), ec);
        std::clog << "connection.tcp.connect(): " << ec.message() << std::endl;
        if (ec) return -1; // return if connect was unsuccessful (e.g. connection refused, etc)

        // ========== perform TLS handshake ==========
        connection.handshake(asio::ssl::stream_base::handshake_type::client, ec);
        std::clog << "connection.handshake(): " << ec.message() << std::endl;


        // ========== use the connection ==========
        // the message to send is stored in the buffer at the initialisation
        connection.write_some(asio::buffer(buf, strlen(buf) + 1), ec);
        std::clog << "connection.write_some(): " << ec.message() << std::endl;

        len = connection.read_some(asio::buffer(buf, sizeof(buf)), ec);
        std::clog << "connection.read_some(): " << ec.message() << std::endl;

        std::cout << "data reveived (" << len << " bytes): " << buf << std::endl;
        // ========== done with using the connection ==========



        // ========== close TLS & TCP connection ==========
        connection.shutdown(ec);
        std::clog << "connection.shutdown(): " << ec.message() << std::endl;

        connection.lowest_layer().shutdown(asio::socket_base::shutdown_both, ec);
        std::clog << "connection.tcp.shutdon(): " << ec.message() << std::endl;

        connection.lowest_layer().close(ec);
        std::clog << "connection.tcp.close(): " << ec.message() << std::endl;

        // ========== stop IO context ==========
        io_context.stop();
    }
    catch(std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}
