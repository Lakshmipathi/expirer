#
# Makefile
#
CFLAGS = -g -O0
LDFLAGS = -lext2fs -ldb

expirer:
	gcc $(CFLAGS) $(LDFLAGS) src/expirer.c -o expirer

expirerd:
	gcc $(CFLAGS) $(LDFLAGS) src/expirerd.c -o expirerd

clean:
	rm -f expirer expirerd
	
all: expirer expirerd

.PHONY: clean

.PHONY: expirer all expirerd
