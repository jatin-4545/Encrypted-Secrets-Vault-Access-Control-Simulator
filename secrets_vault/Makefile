CXX ?= g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pedantic -Iinclude
LDLIBS := -lssl -lcrypto
TARGET := bin/secrets_vault
SRC := src/main.cpp src/vault.cpp

all: $(TARGET)

$(TARGET): $(SRC) include/vault.hpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(SRC) -o $@ $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	bash tests/smoke_test.sh

clean:
	rm -rf bin data_test

.PHONY: all run test clean
