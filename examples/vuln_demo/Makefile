CC     ?= cc
CFLAGS  = -Wall -Wextra -g

TARGET = vuln_demo
SRCS   = main.c
OBJS   = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
