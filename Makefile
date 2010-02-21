CC=gcc -O0 -g3
LIBS=`pkg-config --libs --cflags openssl sqlite3`


dupes: dupes.c
	$(CC) $(LIBS) $ -o $@ $<


.PHONY: clean
clean:
	rm -f dupes
