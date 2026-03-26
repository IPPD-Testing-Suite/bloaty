# OSS-Fuzz compatible Makefile for Bloaty fuzzing harnesses.
#
# Usage (standalone, without OSS-Fuzz):
#   make BLOATY_ROOT=/path/to/bloaty OUT=/tmp/fuzzers
#
# Usage (within OSS-Fuzz, OUT and LIB_FUZZING_ENGINE are set externally):
#   make

BLOATY_ROOT ?= ../..
OUT         ?= .
CXX         ?= clang++
CXXFLAGS    ?= -std=c++17 -g -O1 \
               -fsanitize=address,undefined \
               -fno-sanitize-recover=all \
               -fsanitize=fuzzer \
               -I$(BLOATY_ROOT)/src \
               -I$(BLOATY_ROOT) \
               -I$(BLOATY_ROOT)/third_party/abseil-cpp \
               -I$(BLOATY_ROOT)/third_party/protobuf/src

LIB_FUZZING_ENGINE ?= -fsanitize=fuzzer

LIBBLOATY   ?= $(BLOATY_ROOT)/build/libbloaty.a
EXTRA_LIBS  ?= $(BLOATY_ROOT)/build/libprotoc.a \
               $(BLOATY_ROOT)/build/libre2.a \
               $(BLOATY_ROOT)/build/libcapstone.a \
               $(BLOATY_ROOT)/build/libzlibstatic.a \
               -labsl_strings -labsl_demangle_internal

HARNESSES = \
  dwarf_leb128_fuzzer \
  elf_symtab_fuzzer \
  dwarf_strtab_fuzzer \
  readfixed_fuzzer \
  elf_section_fuzzer

all: $(addprefix $(OUT)/,$(HARNESSES)) \
     $(addsuffix _seed_corpus.zip,$(addprefix $(OUT)/,$(HARNESSES))) \
     $(addsuffix .options,$(addprefix $(OUT)/,$(HARNESSES)))

$(OUT)/%_fuzzer: %_fuzzer.cpp
	$(CXX) $(CXXFLAGS) $< $(LIBBLOATY) $(EXTRA_LIBS) $(LIB_FUZZING_ENGINE) -o $@

$(OUT)/%_fuzzer_seed_corpus.zip: %_corpus
	zip -j $@ $</*

$(OUT)/%_fuzzer.options:
	printf '[libfuzzer]\nmax_len = 65536\n' > $@

clean:
	rm -f $(addprefix $(OUT)/,$(HARNESSES)) \
	      $(addsuffix _seed_corpus.zip,$(addprefix $(OUT)/,$(HARNESSES))) \
	      $(addsuffix .options,$(addprefix $(OUT)/,$(HARNESSES)))

.PHONY: all clean
