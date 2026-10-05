#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace sic {

using SessionKey = std::array<std::uint8_t, 32>;

[[nodiscard]] SessionKey generate_session_key();

class LinkSender {
public:
    explicit LinkSender(SessionKey key);
    [[nodiscard]] std::vector<std::uint8_t> protect(
        const std::vector<std::uint8_t>& plaintext
    );
    [[nodiscard]] std::uint64_t next_sequence() const;

private:
    SessionKey key_;
    std::uint64_t next_sequence_{1};
};

class LinkReceiver {
public:
    explicit LinkReceiver(SessionKey key);
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> verify(
        const std::vector<std::uint8_t>& frame
    );
    [[nodiscard]] std::uint64_t last_sequence() const;

private:
    SessionKey key_;
    std::uint64_t last_sequence_{0};
};

}
