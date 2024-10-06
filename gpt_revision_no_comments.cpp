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

class stcp_socket {
public:
    stcp_socket();
    ~stcp_socket();

    void connect_to(const fc::ip::endpoint& remote_endpoint);
    void bind(const fc::ip::endpoint& local_endpoint);
    size_t readsome(char* buffer, size_t len);
    size_t readsome(const std::shared_ptr<char>& buf, size_t len, size_t offset);
    bool eof() const;
    size_t writesome(const char* buffer, size_t len);
    size_t writesome(const std::shared_ptr<const char>& buf, size_t len, size_t offset);
    void flush();
    void close();
    void accept();

private:
    void do_key_exchange();
    void allocate_buffers(size_t size);
    void log_error(const std::string& context, const std::exception& e) const;

    std::shared_ptr<char> _read_buffer;
    std::shared_ptr<char> _write_buffer;
    fc::ecc::private_key _priv_key;
    fc::ecc::public_key_data _shared_secret;
    AES _send_aes, _recv_aes;
    mutable std::mutex _mutex;
    static constexpr size_t BUFFER_SIZE = 4096;

    stcp_socket(const stcp_socket&) = delete;
    stcp_socket& operator=(const stcp_socket&) = delete;
};

stcp_socket::stcp_socket()
    : _read_buffer(nullptr), _write_buffer(nullptr) {}

stcp_socket::~stcp_socket() {
    close();
}

void stcp_socket::do_key_exchange() {
    try {
        _priv_key = fc::ecc::private_key::generate();
        fc::ecc::public_key pub = _priv_key.get_public_key();
        fc::ecc::public_key_data serialized_pub = pub.serialize();

        std::vector<char> serialized_key_buffer(sizeof(fc::ecc::public_key_data));
        std::memcpy(serialized_key_buffer.data(), &serialized_pub, sizeof(fc::ecc::public_key_data));
        _sock.write(serialized_key_buffer.data(), sizeof(fc::ecc::public_key_data));
        _sock.read(serialized_key_buffer.data(), sizeof(fc::ecc::public_key_data));

        fc::ecc::public_key_data received_pub;
        std::memcpy(&received_pub, serialized_key_buffer.data(), sizeof(fc::ecc::public_key_data));

        _shared_secret = _priv_key.get_shared_secret(received_pub);
        auto shared_secret_hash = fc::sha256::hash(reinterpret_cast<char*>(&_shared_secret), sizeof(_shared_secret));
        auto shared_secret_crc = fc::city_hash_crc_128(reinterpret_cast<char*>(&_shared_secret), sizeof(_shared_secret));

        _send_aes.init(shared_secret_hash, shared_secret_crc);
        _recv_aes.init(shared_secret_hash, shared_secret_crc);
    } catch (const std::exception& e) {
        log_error("Key exchange failed", e);
        throw;
    }
}

void stcp_socket::connect_to(const fc::ip::endpoint& remote_endpoint) {
    _sock.connect_to(remote_endpoint);
    do_key_exchange();
}

void stcp_socket::bind(const fc::ip::endpoint& local_endpoint) {
    _sock.bind(local_endpoint);
}

void stcp_socket::allocate_buffers(size_t size) {
    if (!_read_buffer) {
        _read_buffer = std::make_shared<char[]>(size);
    }
    if (!_write_buffer) {
        _write_buffer = std::make_shared<char[]>(size);
    }
}

void stcp_socket::log_error(const std::string& context, const std::exception& e) const {
    std::cerr << context << ": " << e.what() << std::endl;
}

size_t stcp_socket::readsome(char* buffer, size_t len) {
    if (len == 0 || (len % 16) != 0) {
        throw std::invalid_argument("Length must be greater than 0 and a multiple of 16");
    }

    std::unique_lock<std::mutex> lock(_mutex);
    allocate_buffers(BUFFER_SIZE);

    size_t to_read = std::min(BUFFER_SIZE, len);
    size_t bytes_read = _sock.readsome(_read_buffer.get(), to_read, 0);

    if (bytes_read % 16 != 0) {
        _sock.read(_read_buffer.get(), 16 - (bytes_read % 16), bytes_read);
        bytes_read += 16 - (bytes_read % 16);
    }

    _recv_aes.decode(_read_buffer.get(), bytes_read, buffer);
    return bytes_read;
}

size_t stcp_socket::readsome(const std::shared_ptr<char>& buf, size_t len, size_t offset) {
    return readsome(buf.get() + offset, len);
}

bool stcp_socket::eof() const {
    return _sock.eof();
}

size_t stcp_socket::writesome(const char* buffer, size_t len) {
    if (len == 0 || (len % 16) != 0) {
        throw std::invalid_argument("Length must be greater than 0 and a multiple of 16");
    }

    std::unique_lock<std::mutex> lock(_mutex);
    allocate_buffers(BUFFER_SIZE);

    std::memset(_write_buffer.get(), 0, len);
    uint32_t ciphertext_len = _send_aes.encode(buffer, len, _write_buffer.get());
    assert(ciphertext_len == len);
    
    _sock.write(_write_buffer.get(), ciphertext_len);
    return ciphertext_len;
}

size_t stcp_socket::writesome(const std::shared_ptr<const char>& buf, size_t len, size_t offset) {
    return writesome(buf.get() + offset, len);
}

void stcp_socket::flush() {
    _sock.flush();
}

void stcp_socket::close() {
    try {
        _sock.close();
    } catch (const std::exception& e) {
        log_error("Error closing stcp socket", e);
    }
}

void stcp_socket::accept() {
    do_key_exchange();
}

}} // namespace graphene::net

