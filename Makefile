CC=gcc
CFLAGS=-O2
LIBS=-lpthread
TARGET=bombard

.PHONY: all

all:
	$(CC) main.c $(CFLAGS) $(LIBS) -o $(TARGET) 

install: all
	mkdir -p ~/.local/bin
	cp $(TARGET) ~/.local/bin/$(TARGET)

clean:
	rm $(TARGET)
