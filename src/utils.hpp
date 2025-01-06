#ifndef __UTILS_HPP__
#define __UTILS_HPP__

#include <cstddef>

namespace cryptovfs {

inline bool is_all_zeros(const unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (buffer[i] != 0) {
            return false;
        }
    }
    return true;
}

}

#endif  // __UTILS_HPP__
