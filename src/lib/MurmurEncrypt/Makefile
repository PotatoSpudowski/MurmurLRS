CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c11 -I . -g
SRCS    = ascon.c murmur.c
BUILD   = build

.PHONY: test clean

test: $(BUILD)/test_murmur $(BUILD)/test_acquisition $(BUILD)/test_epoch_overflow
	@./$(BUILD)/test_murmur
	@./$(BUILD)/test_acquisition
	@./$(BUILD)/test_epoch_overflow

$(BUILD)/test_murmur: $(SRCS) test_murmur.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/test_acquisition: $(SRCS) test_acquisition.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/test_epoch_overflow: $(SRCS) test_epoch_overflow.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BUILD)
