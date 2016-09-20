TARGET = neighbor

.PHONY: all clean

all: neighbor
	./$(TARGET)

neighbor: capture.c getarg.c l1.c neighbor.c utils.c utime.c
	gcc -o $@ $^ -g -Wall -O2 -lpthread

clean:
	rm -rf $(TARGET)