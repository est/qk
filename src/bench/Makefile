# Makefile for the TCP congestion control comparison bench.
#
# WHAT THIS BUILDS
#   tcperf - a small TCP throughput probe that selects a congestion control
#   per socket (setsockopt(TCP_CONGESTION)) and reports one machine readable
#   RESULT line per run.  It has three modes: "client" writes to a peer,
#   "reader" reads from a peer, and "server" accepts a connection.
#
# HOW TO BUILD
#   Linux only (the source uses Linux UAPI headers):
#       make
#       make native
#       make clean
#
#   On a non Linux host use the helper below, which builds inside the
#   container image used by lab.sh:
#       make docker-build
#
# HOW TO RUN
#   See the comment block at the top of tcperf.c, or:
#       ./lab.sh compare --cc reno,cubic,qk --duration 10 --repeat 3
#
# The built binary lands next to this Makefile and is bind mounted into the
# lab containers as /lab/tcperf.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -g
LDFLAGS ?=

BIN     := tcperf
SRC     := tcperf.c

.PHONY: all build clean docker-build native

# On a Linux host the tool builds directly.  Elsewhere it is built inside a
# container, because the source uses Linux UAPI headers.
ifeq ($(shell uname -s),Linux)
all: $(BIN)
else
all: docker-build
endif

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build on this machine, whatever the operating system: the source needs the
# Linux uapi headers, so this only works where they are installed.
native: $(BIN)

clean:
	rm -f $(BIN)

# Build inside a container so that the tool can be produced from a non Linux
# workstation.  lab.sh owns the container/image names.
docker-build:
	./lab.sh build

# The root Makefile looks for a "build" target in every subproject.
build: all
