libx509pq.so:
	gcc -O3 -fpic -c x509pq.c -I`pg_config --includedir-server` -I/usr/local/ssl/include -std=gnu99 -pedantic -Wno-long-long
	gcc -shared -O3 -fPIC -o libx509pq.so -Wl,-Bsymbolic -Wl,-Bsymbolic-functions x509pq.o /usr/local/ssl/lib/libcrypto.a

install:
	su -c "cp libx509pq.so `pg_config --pkglibdir`"

clean:
	rm -f *.o *.so *~
