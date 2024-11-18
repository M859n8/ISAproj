CC = g++
CFLAGS = -std=c++11 -Wall
SRCS = p2nprobe.cpp sendUDP.cpp
EXEC = p2nprobe

all: $(EXEC)

$(EXEC): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -lpcap -o $(EXEC)


clean:
	rm -f $(EXEC)