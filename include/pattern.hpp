#pragma once

#include <vector>
#include <optional>
#include <ranges>

namespace noviy {
using pattern_t = std::vector<std::optional<std::uint8_t>>;

struct Pattern {
    static auto find_all(const std::vector<std::uint8_t>& data, const pattern_t& pattern) -> std::vector<std::size_t> {
        std::vector<std::size_t> results;

        auto predicate = [](const std::uint8_t& x, const std::optional<std::uint8_t>& y) {
            return !y.has_value() || (y.has_value() && x == y.value());
        };

        auto it = data.begin();
        while (it != data.end()) {
            auto match_result = std::ranges::search(std::ranges::subrange(it, data.end()),
                                                    std::ranges::subrange(pattern.begin(), pattern.end()), predicate);

            if (match_result.begin() == data.end()) {
                break;
            }

            std::size_t offset = std::distance(data.begin(), match_result.begin());
            results.push_back(offset);

            it = match_result.begin() + 1;
            if (it == data.end()) {
                break;
            }
        }

        return results;
    }
};
}  // namespace noviy