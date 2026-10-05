#pragma once

#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace sic {

struct Frame {
    std::string type;
    std::string source;
    std::string destination;
    std::string service;
    std::uint32_t client;
    std::uint64_t sequence;
    std::string payload;
};

inline std::string hex_encode(const std::string& value) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : value) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

inline std::optional<std::string> hex_decode(const std::string& value) {
    if (value.size() % 2 != 0) {
        return std::nullopt;
    }
    std::string output;
    output.reserve(value.size() / 2);
    try {
        for (std::size_t i = 0; i < value.size(); i += 2) {
            output.push_back(static_cast<char>(std::stoul(value.substr(i, 2), nullptr, 16)));
        }
    } catch (...) {
        return std::nullopt;
    }
    return output;
}

inline std::string encode(const Frame& frame) {
    return "SIC1|" + frame.type + "|" + frame.source + "|" + frame.destination + "|" +
           frame.service + "|" + std::to_string(frame.client) + "|" +
           std::to_string(frame.sequence) + "|" + hex_encode(frame.payload);
}

inline std::optional<Frame> decode(const std::string& value) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (;;) {
        auto end = value.find('|', start);
        if (end == std::string::npos) {
            fields.push_back(value.substr(start));
            break;
        }
        fields.push_back(value.substr(start, end - start));
        start = end + 1;
    }
    if (fields.size() != 8 || fields[0] != "SIC1") {
        return std::nullopt;
    }
    auto payload = hex_decode(fields[7]);
    if (!payload) {
        return std::nullopt;
    }
    try {
        return Frame{fields[1], fields[2], fields[3], fields[4],
                     static_cast<std::uint32_t>(std::stoul(fields[5])),
                     std::stoull(fields[6]), *payload};
    } catch (...) {
        return std::nullopt;
    }
}

inline std::vector<std::uint8_t> bytes(const std::string& value) {
    return {value.begin(), value.end()};
}

inline std::string text(const std::vector<std::uint8_t>& value) {
    return {value.begin(), value.end()};
}

}
