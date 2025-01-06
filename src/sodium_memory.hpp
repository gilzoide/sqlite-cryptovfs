#ifndef __SODIUM_MEMORY_HPP__
#define __SODIUM_MEMORY_HPP__

#include <sodium.h>

template<typename T>
class SodiumMemory {
public:
	SodiumMemory() : value((T*) sodium_malloc(sizeof(T))), length(1) {
		new(value) T;
	}

	SodiumMemory(nullptr_t) : value(nullptr), length(0) {}

	SodiumMemory(size_t N) : value((T*) sodium_allocarray(N, sizeof(T))), length(N) {
		for (size_t i = 0; i < N; i++) {
			new(value + i) T;
		}
	}

	SodiumMemory(const T& other) : value((T*) sodium_malloc(sizeof(T))), length(1) {
		new(value) T(other);
	}

	SodiumMemory(const T *values, size_t N) : value((T*) sodium_allocarray(N, sizeof(T))), length(N) {
		for (size_t i = 0; i < N; i++) {
			new(value + i) T(values[i]);
		}
	}

	SodiumMemory(const SodiumMemory& other) = delete;
	SodiumMemory(SodiumMemory&& other) : value(other.value), length(other.length) {
		other.value = nullptr;
		other.length = 0;
	}

	SodiumMemory& operator=(const SodiumMemory& other) = delete;
	SodiumMemory& operator=(SodiumMemory&& other) {
		if (value) {
			sodium_free(value);
		}
		value = other.value;
		length = other.length;
		other.value = nullptr;
		other.length = 0;
		return *this;
	}

	~SodiumMemory() {
		free();
	}

	void free() {
		if (value) {
			sodium_free(value);
		}
		value = nullptr;
		length = 0;
	}

	T* ptr() {
		return value;
	}
	const T* ptr() const {
		return value;
	}

	size_t size() const {
		return length;
	}

	T& operator*() {
		return *value;
	}
	const T& operator*() const {
		return *value;
	}
	T* operator->() {
		return value;
	}
	const T* operator->() const {
		return value;
	}
	operator T*() {
		return value;
	}
	operator const T*() const {
		return value;
	}
	operator bool() const {
		return value;
	}

private:
	T *value;
	size_t length;
};

#endif  // __SODIUM_MEMORY_HPP__
