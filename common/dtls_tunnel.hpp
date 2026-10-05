#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sic {

struct DatagramFragment {
    std::uint64_t id;
    std::uint32_t index;
    std::uint32_t count;
    std::string data;
};

inline std::string encode_fragment(const DatagramFragment& fragment) {
    return std::to_string(fragment.id) + ":" + std::to_string(fragment.index) + ":" +
           std::to_string(fragment.count) + ":" + fragment.data;
}

inline std::optional<DatagramFragment> decode_fragment(const std::string& value) {
    auto first = value.find(':');
    auto second = first == std::string::npos ? first : value.find(':', first + 1);
    auto third = second == std::string::npos ? second : value.find(':', second + 1);
    if (first == std::string::npos || second == std::string::npos || third == std::string::npos) {
        return std::nullopt;
    }
    try {
        return DatagramFragment{
            std::stoull(value.substr(0, first)),
            static_cast<std::uint32_t>(std::stoul(value.substr(first + 1, second - first - 1))),
            static_cast<std::uint32_t>(std::stoul(value.substr(second + 1, third - second - 1))),
            value.substr(third + 1)
        };
    } catch (...) {
        return std::nullopt;
    }
}

inline std::vector<DatagramFragment> fragment_datagram(
    std::uint64_t id,
    const std::string& datagram,
    std::size_t chunk_size = 120
) {
    std::uint32_t count = static_cast<std::uint32_t>((datagram.size() + chunk_size - 1) / chunk_size);
    if (count == 0) {
        count = 1;
    }
    std::vector<DatagramFragment> result;
    result.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        auto offset = static_cast<std::size_t>(index) * chunk_size;
        result.push_back({id, index, count, datagram.substr(offset, chunk_size)});
    }
    return result;
}

class DatagramReassembler {
public:
    std::optional<std::string> accept(const std::string& peer, const DatagramFragment& fragment) {
        if (fragment.count == 0 || fragment.count > 128 || fragment.index >= fragment.count) {
            return std::nullopt;
        }
        auto key = peer + ":" + std::to_string(fragment.id);
        auto& pending = pending_[key];
        if (pending.parts.empty()) {
            pending.parts.resize(fragment.count);
            pending.present.resize(fragment.count, false);
        }
        if (pending.parts.size() != fragment.count) {
            pending_.erase(key);
            return std::nullopt;
        }
        pending.parts[fragment.index] = fragment.data;
        pending.present[fragment.index] = true;
        for (bool present : pending.present) {
            if (!present) {
                return std::nullopt;
            }
        }
        std::string datagram;
        for (const auto& part : pending.parts) {
            datagram += part;
        }
        pending_.erase(key);
        return datagram;
    }

private:
    struct Pending {
        std::vector<std::string> parts;
        std::vector<bool> present;
    };
    std::map<std::string, Pending> pending_;
};

}
