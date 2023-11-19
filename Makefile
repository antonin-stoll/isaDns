
PROJ = dns
EXECUTABLE = $(PROJ)
OBJS = dns.o

VPATH = src include
CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -pedantic -fcommon

ZIP_FILE = $(PROJ).zip

.PHONY: all pack run clean

all: $(EXECUTABLE)

run: $(EXECUTABLE)
	./$(EXECUTABLE) $(ARGS)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

pack: $(ZIP_FILE)

clean:
	rm -f $(EXECUTABLE) *.o $(ZIP_FILE)


#
