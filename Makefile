NAME 		= ufavonet
VERSION 	= 1.0.0
SOVERSION 	= 1
#config
PREFIX = /usr/local
# flags
CFLAGS = -std=c99 -pedantic -Wall -Wextra -O3
SO_LDFLAGS = -Wl,-soname=lib$(NAME).so.$(SOVERSION)
# compiler
CC = gcc


CFILES = src/*.c
HFILES = include/*.h

all: $(NAME)

clean:
	rm -f tests libufavonet.so*

tests: $(NAME) tests.c
	$(CC) tests.c -std=gnu99 -pedantic -Wall -Wextra -O3 -Wno-unused-parameter -o tests -L. -l$(NAME) -Wl,-rpath=. && ./tests

$(NAME): $(CFILES) $(HFILES)
	$(CC) $(CFILES) $(CFLAGS) -shared -fPIC -o lib$(NAME).so.$(VERSION) $(SO_LDFLAGS)
	ln -f -s lib$(NAME).so.$(VERSION) lib$(NAME).so.$(SOVERSION)
	ln -f -s lib$(NAME).so.$(SOVERSION) lib$(NAME).so

install: all
	mkdir -p $(PREFIX)/include/$(NAME)/
	cp -f include/* $(PREFIX)/include/$(NAME)/
	cp -f -P lib$(NAME).so* $(PREFIX)/lib/

uninstall:
	rm -f -r $(PREFIX)/include/$(NAME) $(PREFIX)/lib/lib$(NAME).so*
