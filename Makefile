# SPDX-License-Identifier: GPL-2.0
#
# Top level Makefile.
#
# This project has three subprojects, each with its own Makefile:
#
#   src/cc     the BPF congestion controller
#   src/bench  the comparison benchmark
#   src/tools  measurement and inspection tools
#
# Every subproject provides a `clean' target and an entry point that is
# called `build' or `all'; the wrapper below picks whichever is there.
#
# The tools are the only ones that can be built from a macOS host, and even
# then only inside a Linux container (see `make -C src/tools container`).

SUBPROJECTS := cc bench tools

# The subprojects are written independently.  Prefer their `build' target and
# fall back to `all' when a subproject does not provide one.
sub_target = $(shell if grep -qE '^build[[:space:]]*:' src/$(1)/Makefile 2>/dev/null; then echo build; else echo all; fi)

.PHONY: all build cc bench tools container clean help

all: build

# Build every subproject.
build: cc bench tools

cc:
	@if [ ! -f src/cc/Makefile ]; then \
		echo "src/cc: no Makefile yet"; exit 1; \
	fi
	@$(MAKE) --no-print-directory -C src/cc $(call sub_target,cc)

bench:
	@if [ ! -f src/bench/Makefile ]; then \
		echo "src/bench: no Makefile yet"; exit 1; \
	fi
	@$(MAKE) --no-print-directory -C src/bench $(call sub_target,bench)

tools:
	@if [ ! -f src/tools/Makefile ]; then \
		echo "src/tools: no Makefile yet"; exit 1; \
	fi
	@$(MAKE) --no-print-directory -C src/tools $(call sub_target,tools)

# Build the measurement tools inside a throwaway Linux container.  The other
# subprojects need a Linux kernel to build BPF objects and are not covered
# here yet.
container:
	@$(MAKE) --no-print-directory -C src/tools container

# Remove the build output of every subproject.  Subprojects that have no
# Makefile yet are skipped, so `make clean' always works.
clean:
	@for d in $(SUBPROJECTS); do \
		if [ -f "src/$$d/Makefile" ]; then \
			echo "  clean  src/$$d"; \
			$(MAKE) --no-print-directory -C "src/$$d" clean || exit 1; \
		else \
			echo "  skip   src/$$d (no Makefile yet)"; \
		fi; \
	done

help:
	@echo "queqiao-k — kernel native transport"
	@echo ""
	@echo "targets:"
	@echo "  all        build everything (same as 'build')"
	@echo "  build      build all three subprojects: cc, bench and tools"
	@echo "  cc         build the BPF congestion controller   (src/cc)"
	@echo "  bench      build the comparison benchmark        (src/bench)"
	@echo "  tools      build the measurement tools           (src/tools)"
	@echo "  container  build the tools inside a Linux container"
	@echo "  clean      remove the build output of every subproject"
	@echo "  help       print this message"
	@echo ""
	@echo "every subproject has its own Makefile with 'build' and 'clean' (some"
	@echo "call the entry point 'all'); see src/tools/Makefile for the"
	@echo "container build (CONTAINER, IMAGE)."
