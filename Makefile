CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/include/pcap
LIBS = -lpcap

OBJS = main.o interface.o capture.o util.o filter.o storage.o inspector.o ethernet.o network.o transport.o application.o

all: cshark

cshark: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) cshark

.PHONY: all clean
