BUILD_DIRS = \
	build/macos

$(BUILD_DIRS):
	mkdir -p $@

build/%/cryptofile.o: src/cryptofile.c | build/%
	$(CC) -o $@ -c $< $(CFLAGS)
build/%/cryptovfs.o: src/cryptovfs.c | build/%
	$(CC) -o $@ -c $< $(CFLAGS)
.PRECIOUS: build/%/cryptofile.o build/%/cryptovfs.o

build/%/libcryptovfs.dylib: LINKFLAGS += -shared -lsqlite3
build/%/libcryptovfs.dylib: build/%/cryptofile.o build/%/cryptovfs.o
	$(CC) -o $@ $^ $(CFLAGS) $(LINKFLAGS)


# Targets
macos-universal: CFLAGS += -arch x86_64 -arch arm64
macos-universal: build/macos/libcryptovfs.dylib