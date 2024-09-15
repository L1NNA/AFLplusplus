
CFLAGS = -Wall -I/usr/include/hiredis -O3 -funroll-loops -fPIC -Wl,-Bsymbolic
LDFLAGS = -lhiredis

all: aflpp-mutator.so

aflpp-mutator.so:	aflpp.c
	$(CC) $(CFLAGS) -I../../include -I. -shared -o aflpp-mutator.so aflpp.c ../../src/afl-performance.c $(LDFLAGS)

clean:
	rm -f *.o *~ *.so core
