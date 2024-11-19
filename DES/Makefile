BUILD_DIR = build
INC_DIR = inc
SRC_DIR = src

CC = clang
CFLAGS = -Wall -Wextra -O3 -funroll-loops -march=native

all:
	mkdir build && $(CC) $(CFLAGS) -I$(INC_DIR) $(SRC_DIR)/*.c -o $(BUILD_DIR)/des $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)/