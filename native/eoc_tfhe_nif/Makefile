# Makefile for eoc_tfhe_nif

# Erlang include path
ERL_INTERFACE_INCLUDE_DIR = $(shell erl -eval 'io:format("~s~n", [code:lib_dir(erl_interface, include)])' -s init stop -noshell)
ERL_INTERFACE_LIB_DIR = $(shell erl -eval 'io:format("~s~n", [code:lib_dir(erl_interface, lib)])' -s init stop -noshell)
ERTS_INCLUDE_DIR = $(shell erl -eval 'io:format("~s~n", [code:root_dir() ++ "/erts-" ++ erlang:system_info(version) ++ "/include"])' -s init stop -noshell)

# TFHE include and lib paths
REBAR_ROOT_DIR ?= $(shell pwd)/../..
TFHE_INCLUDE_DIR = $(REBAR_ROOT_DIR)/_build/tfhe/src/include
TFHE_LIB_DIR = $(REBAR_ROOT_DIR)/_build/tfhe/build/libtfhe

# Compiler and linker flags
CFLAGS = -fPIC -O3 -Wall -std=c++11 -I$(ERL_INTERFACE_INCLUDE_DIR) -I$(ERTS_INCLUDE_DIR) -I$(TFHE_INCLUDE_DIR)
LDFLAGS = -shared -L$(ERL_INTERFACE_LIB_DIR) -L$(TFHE_LIB_DIR) -Wl,--no-as-needed -lei -ltfhe-nayuki-portable -ldl -lpthread -Wl,-rpath,$(TFHE_LIB_DIR)

# Target
TARGET = ../../priv/eoc_tfhe_nif.so

# Source files
SOURCES = eoc_tfhe_nif.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Rules
all: $(TARGET)

$(TARGET): $(OBJECTS)
	g++ $(LDFLAGS) -o $@ $^

%.o: %.cpp
	g++ $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
