/*
 * Copyright (c) 2015 Cryptonomex, Inc., and contributors.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <cassert>
#include <algorithm>
#include <memory>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <mutex>
#include <fc/crypto/hex.hpp>
#include <fc/crypto/aes.hpp>
#include <fc/crypto/city.hpp>
#include <fc/log/logger.hpp>
#include <fc/network/ip.hpp>
#include <fc/exception/exception.hpp>
#include <graphene/net/stcp_socket.hpp>

namespace graphene { namespace net {

// Class representing a secure TCP socket (stcp_socket).
// This class handles establishing connections, data transmission,
// encryption/decryption using AES, and key exchange for secure communication.
class stcp_socket {
public:
    // Constructor initializes the socket.
    stcp_socket();
    // Destructor cleans up resources and closes the socket.
    ~stcp_socket();

    // Connects to a remote endpoint (IP address and port).
    void connect_to(const fc::ip::endpoint& remote_endpoint);
    // Binds the socket to a local endpoint (IP address and port).
    void bind(const fc::ip::endpoint& local_endpoint);
    
    // Reads data from the socket into a provided buffer, ensuring data is decrypted.
    size_t readsome(char* buffer, size_t len);
    // Reads data from a shared buffer with a specific offset.
    size_t readsome(const std::shared_ptr<char>& buf, size_t len, size_t offset);
    // Checks if the socket has reached the end of the data stream.
    bool eof() const;
    // Writes encrypted data to the socket from a provided buffer.
    size_t writesome(const char* buffer, size_t len);
    // Writes encrypted data from a shared buffer with a specific offset.
    size_t writesome(const std::shared_ptr<const char>& buf, size_t len, size_t offset);
    
    // Flushes the socket to ensure all data is sent.
    void flush();
    // Closes the socket, releasing resources.
    void close();
    // Accepts a connection from a remote endpoint and performs key exchange.
    void accept();

private:
    // Performs the key exchange to establish a shared secret for encryption.
    void do_key_exchange();
    // Allocates memory for the read and write buffers.
    void allocate_buffers(size_t size);
    // Logs errors to the console with context.
    void log_error(const std::string& context, const std::exception& e) const;

    // Buffers for reading and writing data.
    std::shared_ptr<char> _read_buffer;
    std::shared_ptr<char> _write_buffer;

    // Private key used for secure communication.
    fc::ecc::private_key _priv_key;
    // Shared secret for encryption/decryption.
    fc::ecc::public_key_data _shared_secret;
    
    // AES encryption and decryption objects.
    AES _send_aes, _recv_aes;

    // Mutex to ensure thread safety during operations.
    mutable std::mutex _mutex;

    // Constant for the size of the buffers.
    static constexpr size_t BUFFER_SIZE = 4096;

    // Deleted copy constructor and assignment operator to prevent copying.
    stcp_socket(const stcp_socket&) = delete;
    stcp_socket& operator=(const stcp_socket&) = delete;
};

// Constructor: Initializes buffers to nullptr.
stcp_socket::stcp_socket()
    : _read_buffer(nullptr), _write_buffer(nullptr) {}

// Destructor: Ensures the socket is closed when the object is destroyed.
stcp_socket::~stcp_socket() {
    close();
}

// Performs the key exchange process to generate a shared secret for encryption.
void stcp_socket::do_key_exchange() {
    try {
        // Generate a new private key and derive the corresponding public key.
        _priv_key = fc::ecc::private_key::generate();
        fc::ecc::public_key pub = _priv_key.get_public_key();
        fc::ecc::public_key_data serialized_pub = pub.serialize();

        // Create a buffer to hold the serialized public key and exchange it.
        std::vector<char> serialized_key_buffer(sizeof(fc::ecc::public_key_data));
        std::memcpy(serialized_key_buffer.data(), &serialized_pub, sizeof(fc::ecc::public_key_data));
        _sock.write(serialized_key_buffer.data(), sizeof(fc::ecc::public_key_data));
        _sock.read(serialized_key_buffer.data(), sizeof(fc::ecc::public_key_data));

        // Deserialize the received public key.
        fc::ecc::public_key_data received_pub;
        std::memcpy(&received_pub, serialized_key_buffer.data(), sizeof(fc::ecc::public_key_data));

        // Derive the shared secret using the private key and received public key.
        _shared_secret = _priv_key.get_shared_secret(received_pub);
        // Generate hash and CRC for AES initialization.
        auto shared_secret_hash = fc::sha256::hash(reinterpret_cast<char*>(&_shared_secret), sizeof(_shared_secret));
        auto shared_secret_crc = fc::city_hash_crc_128(reinterpret_cast<char*>(&_shared_secret), sizeof(_shared_secret));

        // Initialize the AES encryption and decryption objects with the shared secret.
        _send_aes.init(shared_secret_hash, shared_secret_crc);
        _recv_aes.init(shared_secret_hash, shared_secret_crc);
    } catch (const std::exception& e) {
        // Log any exceptions that occur during key exchange.
        log_error("Key exchange failed", e);
        throw;  // Rethrow the exception to signal failure.
    }
}

// Connects to a specified remote endpoint and performs key exchange.
void stcp_socket::connect_to(const fc::ip::endpoint& remote_endpoint) {
    _sock.connect_to(remote_endpoint);
    do_key_exchange();
}

// Binds the socket to a local endpoint.
void stcp_socket::bind(const fc::ip::endpoint& local_endpoint) {
    _sock.bind(local_endpoint);
}

// Allocates memory for read and write buffers if not already allocated.
void stcp_socket::allocate_buffers(size_t size) {
    if (!_read_buffer) {
        _read_buffer = std::make_shared<char[]>(size);
    }
    if (!_write_buffer) {
        _write_buffer = std::make_shared<char[]>(size);
    }
}

// Logs errors to the console with context.
void stcp_socket::log_error(const std::string& context, const std::exception& e) const {
    std::cerr << context << ": " << e.what() << std::endl;
}

// Reads data from the socket into a provided buffer, ensuring data is decrypted.
size_t stcp_socket::readsome(char* buffer, size_t len) {
    if (len == 0 || (len % 16) != 0) {
        throw std::invalid_argument("Length must be greater than 0 and a multiple of 16");
    }

    std::unique_lock<std::mutex> lock(_mutex);  // Lock for thread safety.
    allocate_buffers(BUFFER_SIZE);  // Allocate buffers if needed.

    size_t to_read = std::min(BUFFER_SIZE, len);  // Determine how much to read.
    size_t bytes_read = _sock.readsome(_read_buffer.get(), to_read, 0);  // Read from socket.

    // Ensure that we read a complete block for decryption.
    if (bytes_read % 16 != 0) {
        _sock.read(_read_buffer.get(), 16 - (bytes_read % 16), bytes_read);
        bytes_read += 16 - (bytes_read % 16);
    }

    // Decrypt the read data into the provided buffer.
    _recv_aes.decode(_read_buffer.get(), bytes_read, buffer);
    return bytes_read;  
}

// Reads data from a shared buffer with a specific offset.
size_t stcp_socket::readsome(const std::shared_ptr<char>& buf, size_t len, size_t offset) {
    return readsome(buf.get() + offset, len);
}

// Checks if the socket has reached the end of the data stream.
bool stcp_socket::eof() const {
    return _sock.eof();
}

// Writes encrypted data to the socket from a provided buffer.
size_t stcp_socket::writesome(const char* buffer, size_t len) {
    if (len == 0 || (len % 16) != 0) {
        throw std::invalid_argument("Length must be greater than 0 and a multiple of 16");
    }

    std::unique_lock<std::mutex> lock(_mutex);  // Lock for thread safety.

    allocate_buffers(BUFFER_SIZE);  // Allocate buffers if needed.

    std::memset(_write_buffer.get(), 0, len);  // Clear the write buffer before use.
    
    // Encrypt the provided data and store it in the write buffer.
    uint32_t ciphertext_len = _send_aes.encode(buffer, len, _write_buffer.get());
    assert(ciphertext_len == len);  // Ensure encryption was successful.
    
    _sock.write(_write_buffer.get(), ciphertext_len);  // Write the encrypted data to the socket.
    return ciphertext_len;  // Return the number of bytes written.
}

// Writes encrypted data from a shared buffer with a specific offset.
size_t stcp_socket::writesome(const std::shared_ptr<const char>& buf, size_t len, size_t offset) {
    return writesome(buf.get() + offset, len);
}

// Flushes the socket to ensure all buffered data is sent.
void stcp_socket::flush() {
    _sock.flush();
}

// Closes the socket, ensuring all resources are released properly.
void stcp_socket::close() {
    try {
        _sock.close();  
    } catch (const std::exception& e) {
        log_error("Error closing stcp socket", e);  
    }
}

// Accepts a connection from a remote endpoint and performs key exchange.
void stcp_socket::accept() {
    do_key_exchange();  
}

}} // namespace graphene::net

   

