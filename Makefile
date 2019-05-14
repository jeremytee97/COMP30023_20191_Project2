CC = gcc
CFLAGS = -g -std=c99 -O3 -Wall -Wpedantic 
DEPS = sha256.h crack.h
OBJ    = crack.o sha256.o
EXE    = crack

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ)

clean:
	rm -f *.o crack