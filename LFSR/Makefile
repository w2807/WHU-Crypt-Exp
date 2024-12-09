BUILD_DIR = build
INC_DIR = inc
SRC_DIR = src

CC = gcc
CFLAGS = -Wall -Wextra -O3 -funroll-loops -march=native -lm

all: clean generate
	mkdir $(BUILD_DIR) && $(CC) $(CFLAGS) -I$(INC_DIR) $(SRC_DIR)/*.c -o $(BUILD_DIR)/lfsr
	./$(BUILD_DIR)/lfsr test.txt encrypt.bin decrypt.txt

generate:
	python3 data.py

clean:
	rm -rf $(BUILD_DIR)/
	rm -f *.txt *.bin