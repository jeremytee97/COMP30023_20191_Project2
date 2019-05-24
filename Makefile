CC = gcc
CFLAGS = -lm -g -std=c99 -O3 -Wall -Wpedantic 
LIBS = -lm
DEPS = sha256.h crack.h
OBJ    = crack.o sha256.o
EXE    = crack

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LIBS)

clean:
	rm -f *.o crack