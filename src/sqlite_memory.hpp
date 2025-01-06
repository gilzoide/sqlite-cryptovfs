#ifndef __SQLITE_MEMORY_HPP__
#define __SQLITE_MEMORY_HPP__

#include <cstddef>

#include <sqlite3.h>

template<typename T>
class SQLiteMemory {
public:
    SQLiteMemory() : value((T*) sqlite3_malloc(sizeof(T))), length(1) {
		new(value) T;
	}

	SQLiteMemory(nullptr_t) : value(nullptr), length(0) {}

	SQLiteMemory(size_t N) : value((T*) sqlite3_malloc64(N * sizeof(T))), length(N) {
		for (size_t i = 0; i < N; i++) {
			new(value + i) T;
		}
	}

	SQLiteMemory(const T& other) : value((T*) sqlite3_malloc(sizeof(T))), length(1) {
		new(value) T(other);
	}

	SQLiteMemory(const T *values, size_t N) : value((T*) sqlite3_malloc64(N * sizeof(T))), length(N) {
		for (size_t i = 0; i < N; i++) {
			new(value + i) T(values[i]);
		}
	}

	SQLiteMemory(const SQLiteMemory& other) = delete;
	SQLiteMemory(SQLiteMemory&& other) : value(other.value), length(other.length) {
		other.value = nullptr;
		other.length = 0;
	}

	SQLiteMemory& operator=(const SQLiteMemory& other) = delete;
	SQLiteMemory& operator=(SQLiteMemory&& other) {
		if (value) {
			sqlite3_free(value);
		}
		value = other.value;
		length = other.length;
		other.value = nullptr;
		other.length = 0;
		return *this;
	}

	~SQLiteMemory() {
		free();
	}

    bool resize(size_t N) {
		if (N == length) {
			return true;
		}
		else if (T *newptr = (T*) sqlite3_realloc64(value, N)) {
			value = newptr;
			length = N;
			return true;
		}
		else {
			return false;
		}
	}

	bool resize_at_least(size_t N) {
		if (length >= N) {
			return true;
		}
		else {
			return resize(N);
		}
	}

	void free() {
		sqlite3_free(value);
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

#endif  // __SQLITE_MEMORY_HPP__
