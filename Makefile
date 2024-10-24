CC = g++
CFLAGS = -std=c++11 -Wall
SRCS = p2nprobe.cpp
EXEC = p2nprobe

all: $(EXEC)

$(EXEC): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -lpcap -o $(EXEC)


run:
	make
	./$(EXEC)  localhost:2055 test1.pcap -a 5 -i 30

clean:
	rm -f $(EXEC)