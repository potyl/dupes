CC=gcc -O0 -g3
LIBS=`pkg-config --libs --cflags openssl sqlite3`


md5: md5.c
	$(CC) $(LIBS) $ -o $@ $<


.PHONY: clean
clean:
	rm -f md5
