# MemScope C port -- builds memscope.exe and ptrscan.exe.
#
# The two executables share every object except their own main_*.c; the
# implementation files live under src/, and COMMON_SRCS is everything there
# except the two main_*.c entry points. CFLAGS asks gcc to emit a .d file
# beside each .o listing the headers it included, and those .d files are
# included below so that editing a header rebuilds every object that
# includes it, not just the .c files that changed.

CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -O2 -Iinclude -MMD -MP
LDLIBS  := -lkernel32

BUILD_DIR := build

ALL_SRCS    := $(wildcard src/*.c)
COMMON_SRCS := $(filter-out src/main_memscope.c src/main_ptrscan.c,$(ALL_SRCS))
COMMON_OBJS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(COMMON_SRCS))

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_OBJS := $(patsubst tests/%.c,$(BUILD_DIR)/tests/%.o,$(TEST_SRCS))
TEST_BINS := $(patsubst tests/%.c,$(BUILD_DIR)/tests/%.exe,$(TEST_SRCS))

TARGET_BIN := $(BUILD_DIR)/tests/target.exe

COMMON_DEPS := $(COMMON_OBJS:.o=.d) $(BUILD_DIR)/main_memscope.d $(BUILD_DIR)/main_ptrscan.d
TEST_DEPS   := $(TEST_OBJS:.o=.d)

.PHONY: all clean test

all: memscope.exe ptrscan.exe $(TARGET_BIN)

memscope.exe: $(BUILD_DIR)/main_memscope.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ptrscan.exe: $(BUILD_DIR)/main_ptrscan.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tests/%.o: tests/%.c | $(BUILD_DIR)/tests
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tests/%.exe: $(BUILD_DIR)/tests/%.o $(COMMON_OBJS) | $(BUILD_DIR)/tests
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR) $(BUILD_DIR)/tests:
	mkdir -p $@

test: $(TEST_BINS)
ifeq ($(TEST_SRCS),)
	@echo "no C tests yet"
else
	@for t in $(TEST_BINS); do \
		echo "== $$t =="; \
		"$$t" || exit 1; \
	done
endif

clean:
	rm -rf $(BUILD_DIR) memscope.exe ptrscan.exe

-include $(COMMON_DEPS)
-include $(TEST_DEPS)
