NDK = /Users/berkegulacar/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin
CXX = $(NDK)/aarch64-linux-android35-clang++
STRIP = $(NDK)/llvm-strip
TARGET = hayabusa
SOURCES = main.cpp memory.cpp tracer.cpp
CXXFLAGS = -O3 -std=c++23 -static-libstdc++
LDFLAGS = -ldl

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) $(LDFLAGS) -o $(TARGET)
	$(STRIP) $(TARGET)

clean:
	rm -f $(TARGET)