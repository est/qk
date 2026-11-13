# Makefile for the qkfec prototype.
#
# It is a plain POSIX program with no dependencies beyond libc, so it builds
# on Linux and on macOS.
#
#   make          build qkfec
#   make clean

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -g

BIN := qkfec

.PHONY: all clean

all: $(BIN)

$(BIN): qkfec.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN)
