CC=gcc -O0 -g3
LIBS=`pkg-config --libs openssl --cflags`

md5: md5.c
	$(CC) $(LIBS) $ -o $@ $<

