SRC:=$(wildcard *.c)

build:
	gcc -Wall -D_GNU_SOURCE -fPIC -shared -g -o hosts-recvfrom-hijacking.so $(SRC) -ldl

test:
	gcc -DHA_DNS_TEST -g -o dns-test.out dns.c && ./dns-test.out

clean:
	rm -rf *dSYM/ *.out *.so
