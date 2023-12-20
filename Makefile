BUILD_DIRS = \
	build/macos

$(BUILD_DIRS):
	mkdir -p $@

build/%/cryptovfs.dylib: CFLAGS += $(shell pkg-config --cflags libsodium)
build/%/cryptovfs.dylib: LINKFLAGS += -shared -lsqlite3 $(shell pkg-config --variable=libdir libsodium)/libsodium.a
build/%/cryptovfs.dylib: src/cryptovfs.c | build/%
	$(CC) -o $@ $< $(CFLAGS) $(LINKFLAGS)

# build/sqlite3crypto: 

# Targets
macos-universal: CFLAGS += -arch arm64
macos-universal: build/macos/cryptovfs.dylib