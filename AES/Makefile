BUILD_DIR = build
INC_DIR = inc
SRC_DIR = src

CC = gcc
CFLAGS = -maes -Wall -Wextra -O3 -funroll-loops -march=native

.PHONY: clean aes_ni aes

aes: clean
	mkdir $(BUILD_DIR) && $(CC) $(CFLAGS) -I$(INC_DIR) $(SRC_DIR)/*.c -o $(BUILD_DIR)/aes

clean:
	rm -rf $(BUILD_DIR)/