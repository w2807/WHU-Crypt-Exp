BUILD_DIR = build
INC_DIR = inc
SRC_DIR = src

CC = gcc
CFLAGS = -Wall -Wextra -O3 -funroll-loops -march=native -lm

all:
	mkdir $(BUILD_DIR) && $(CC) $(CFLAGS) -I$(INC_DIR) $(SRC_DIR)/*.c -o $(BUILD_DIR)/des

clean:
	rm -rf $(BUILD_DIR)/
