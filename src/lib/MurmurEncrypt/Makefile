CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c11 -I . -g
SRCS    = ascon.c murmur.c
TESTS   = test_murmur.c
BUILD   = build

.PHONY: test clean

test: $(BUILD)/test_murmur
	@./$(BUILD)/test_murmur

$(BUILD)/test_murmur: $(SRCS) $(TESTS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BUILD)
