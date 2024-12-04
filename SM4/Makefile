BUILD_DIR = build
INC_DIR = inc
SRC_DIR = src

SRC_SM4 = $(SRC_DIR)/sm4.c $(SRC_DIR)/test_sm4.c $(SRC_DIR)/benchmark.c
SRC_CBC = $(SRC_DIR)/sm4_cbc.c $(SRC_DIR)/sm4.c

CC = gcc
CFLAGS = -maes -Wall -Wextra -O3 -funroll-loops -march=native

.PHONY: clean sm4

sm4: clean
	mkdir $(BUILD_DIR) && $(CC) $(CFLAGS) -I$(INC_DIR) $(SRC_SM4) -o $(BUILD_DIR)/sm4
	./$(BUILD_DIR)/sm4

cbc: clean generate_data
	mkdir $(BUILD_DIR) && $(CC) $(CFLAGS) -I$(INC_DIR) $(SRC_CBC) -o $(BUILD_DIR)/cbc
	./$(BUILD_DIR)/cbc test1.bin test2.bin test3.bin

generate_data:
	python3 test_cbc_data.py

clean:
	rm -rf $(BUILD_DIR)/
	rm -f test*.bin