NAME 		= ufavonet
VERSION 	= 1.0.0
SOVERSION 	= 1
# config
CC			?= cc
WINCC		?= x86_64-w64-mingw32-gcc
DESTDIR 	?=
PREFIX		?= /usr/local
# flags
CFLAGS 		+= -std=c99 -pedantic -Wall -Wextra -O3
LDFLAGS 	+= -Wl,-soname=lib$(NAME).so.$(SOVERSION)
DLL_LDFLAGS += -lws2_32

CFILES 		= $(wildcard src/*.c)
HFILES 		= $(wildcard include/*.h)

.PHONY: all clean install uninstall tests testsdll dll $(NAME)

all: $(NAME)

clean:
	rm -f tests tests.exe lib$(NAME).so* $(NAME).dll

tests: $(NAME) tests.c
	$(CC) tests.c -std=gnu99 -pedantic -Wall -Wextra -O3 -Wno-unused-parameter -o tests -L. -l$(NAME) -Wl,-rpath=. && ./tests

testsdll: dll tests.c
	$(WINCC) tests.c -std=gnu99 -pedantic -O3 -Wno-unused-parameter -o tests.exe -L. -l$(NAME) $(DLL_LDFLAGS) -Wl,-rpath=. && wine64 tests.exe

$(NAME): $(CFILES) $(HFILES)
	@echo prefix = $(PREFIX)
	$(CC) $(CFILES) $(CFLAGS) -shared -fPIC -o lib$(NAME).so.$(VERSION) $(LDFLAGS)
	ln -f -s lib$(NAME).so.$(VERSION) lib$(NAME).so.$(SOVERSION)
	ln -f -s lib$(NAME).so.$(SOVERSION) lib$(NAME).so

dll: $(CFILES) $(HFILES)
	$(WINCC) $(CFILES) $(CFLAGS) -shared -fPIC -o $(NAME).dll $(DLL_LDFLAGS)

install: $(NAME)
	mkdir -p $(DESTDIR)$(PREFIX)/include/$(NAME)/ $(DESTDIR)$(PREFIX)/lib/
	cp -f include/* $(DESTDIR)$(PREFIX)/include/$(NAME)/
	cp -f -P lib$(NAME).so* $(DESTDIR)$(PREFIX)/lib/

uninstall:
	rm -f -r $(DESTDIR)$(PREFIX)/include/$(NAME) $(DESTDIR)$(PREFIX)/lib/lib$(NAME).so*
