CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g
LDFLAGS = -lcapstone

SRCS = mdb.c
OBJS = $(SRCS:.c=.o)
TARGET = mdb

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean run
