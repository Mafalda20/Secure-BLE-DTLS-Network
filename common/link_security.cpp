#include "link_security.hpp"

#include <linux/if_alg.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace sic {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'S', 'L', 'K', '1'};
constexpr std::size_t kHeaderSize = 16;
constexpr std::size_t kTagSize = 32;
constexpr std::size_t kSha256BlockSize = 64;
constexpr std::size_t kMaximumPlaintext = 1024 * 1024;

class FileDescriptor {
public:
    explicit FileDescriptor(int value = -1) : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) {
            close(value_);
        }
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    [[nodiscard]] int get() const { return value_; }

private:
    int value_;
};

std::array<std::uint8_t, 32> sha256(
    const std::vector<std::uint8_t>& input
) {
    FileDescriptor algorithm(socket(AF_ALG, SOCK_SEQPACKET, 0));
    if (algorithm.get() < 0) {
        throw std::runtime_error("nao foi possivel abrir AF_ALG");
    }

    sockaddr_alg address{};
    address.salg_family = AF_ALG;
    std::strncpy(reinterpret_cast<char*>(address.salg_type), "hash",
                 sizeof(address.salg_type) - 1);
    std::strncpy(reinterpret_cast<char*>(address.salg_name), "sha256",
                 sizeof(address.salg_name) - 1);

    if (bind(algorithm.get(), reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) != 0) {
        throw std::runtime_error("kernel nao disponibiliza SHA-256 por AF_ALG");
    }

    FileDescriptor operation(accept(algorithm.get(), nullptr, nullptr));
    if (operation.get() < 0) {
        throw std::runtime_error("nao foi possivel iniciar SHA-256");
    }

    if (!input.empty()) {
        const auto sent = send(operation.get(), input.data(), input.size(), 0);
        if (sent < 0 || static_cast<std::size_t>(sent) != input.size()) {
            throw std::runtime_error("erro ao enviar dados para SHA-256");
        }
    }

    std::array<std::uint8_t, 32> digest{};
    const auto received = recv(operation.get(), digest.data(), digest.size(), 0);
    if (received != static_cast<ssize_t>(digest.size())) {
        throw std::runtime_error("erro ao receber digest SHA-256");
    }
    return digest;
}

std::array<std::uint8_t, kTagSize> hmac_sha256(
    const SessionKey& key,
    const std::vector<std::uint8_t>& input
) {
    std::array<std::uint8_t, kSha256BlockSize> inner_pad{};
    std::array<std::uint8_t, kSha256BlockSize> outer_pad{};
    inner_pad.fill(0x36);
    outer_pad.fill(0x5c);

    for (std::size_t index = 0; index < key.size(); ++index) {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }

    std::vector<std::uint8_t> inner(inner_pad.begin(), inner_pad.end());
    inner.insert(inner.end(), input.begin(), input.end());
    const auto inner_digest = sha256(inner);

    std::vector<std::uint8_t> outer(outer_pad.begin(), outer_pad.end());
    outer.insert(outer.end(), inner_digest.begin(), inner_digest.end());
    return sha256(outer);
}

void put_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
    }
}

void put_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
    }
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& input, std::size_t at) {
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index) {
        value = (value << 8U) | input.at(at + index);
    }
    return value;
}

std::uint64_t get_u64(const std::vector<std::uint8_t>& input, std::size_t at) {
    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index) {
        value = (value << 8U) | input.at(at + index);
    }
    return value;
}

bool constant_time_equal(
    const std::uint8_t* lhs,
    const std::uint8_t* rhs,
    std::size_t size
) {
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < size; ++index) {
        difference |= lhs[index] ^ rhs[index];
    }
    return difference == 0;
}

}

SessionKey generate_session_key() {
    SessionKey key{};
    std::size_t offset = 0;
    while (offset < key.size()) {
        const auto received = getrandom(
            key.data() + offset, key.size() - offset, 0
        );
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            throw std::runtime_error("nao foi possivel gerar session key");
        }
        offset += static_cast<std::size_t>(received);
    }
    return key;
}

LinkSender::LinkSender(SessionKey key) : key_(key) {}

std::vector<std::uint8_t> LinkSender::protect(
    const std::vector<std::uint8_t>& plaintext
) {
    if (plaintext.size() > kMaximumPlaintext) {
        throw std::length_error("frame de link excede o limite");
    }
    if (next_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("sequence number de link esgotado");
    }

    std::vector<std::uint8_t> frame;
    frame.reserve(kHeaderSize + plaintext.size() + kTagSize);
    frame.insert(frame.end(), kMagic.begin(), kMagic.end());
    put_u64(frame, next_sequence_++);
    put_u32(frame, static_cast<std::uint32_t>(plaintext.size()));
    frame.insert(frame.end(), plaintext.begin(), plaintext.end());
    const auto tag = hmac_sha256(key_, frame);
    frame.insert(frame.end(), tag.begin(), tag.end());
    return frame;
}

std::uint64_t LinkSender::next_sequence() const {
    return next_sequence_;
}

LinkReceiver::LinkReceiver(SessionKey key) : key_(key) {}

std::optional<std::vector<std::uint8_t>> LinkReceiver::verify(
    const std::vector<std::uint8_t>& frame
) {
    if (frame.size() < kHeaderSize + kTagSize ||
        !std::equal(kMagic.begin(), kMagic.end(), frame.begin())) {
        return std::nullopt;
    }

    const auto payload_size = get_u32(frame, 12);
    if (payload_size > kMaximumPlaintext ||
        frame.size() != kHeaderSize + payload_size + kTagSize) {
        return std::nullopt;
    }

    const auto authenticated_end = frame.end() -
        static_cast<std::ptrdiff_t>(kTagSize);
    const std::vector<std::uint8_t> authenticated(frame.begin(),
                                                   authenticated_end);
    const auto expected_tag = hmac_sha256(key_, authenticated);
    if (!constant_time_equal(expected_tag.data(), &*authenticated_end,
                             expected_tag.size())) {
        return std::nullopt;
    }

    const auto sequence = get_u64(frame, 4);
    if (sequence <= last_sequence_) {
        return std::nullopt;
    }

    last_sequence_ = sequence;
    return std::vector<std::uint8_t>(frame.begin() + kHeaderSize,
                                     authenticated_end);
}

std::uint64_t LinkReceiver::last_sequence() const {
    return last_sequence_;
}

}
