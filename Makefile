NAME 		= ufavonet
VERSION 	= 2.0.0
SOVERSION 	= 2
# config
DESTDIR 	?=
PREFIX		?= /usr/local
# flags
CFLAGS 		+= -std=c99 -pedantic -Wall -Wextra -O3 -flto -fPIC

CFILES 		= $(wildcard src/*.c)
HFILES 		= $(wildcard include/*.h src/*.h)

OBJ = ${CFILES:.c=.o}

LDFLAGS += -flto
SO_LDFLAGS += -flto -shared 

# platform
ifneq (,$(findstring win64,$(PLATFORM)))
	PLATFORM	 = win64

	ifeq ($(CC),)
		CC = x86_64-w64-mingw32-gcc
	endif

	LDFLAGS		+= -lws2_32 -static
	SO_LDFLAGS	+= -lws2_32 -static
	FILE_EXT	 = .exe
	SO_NAME		 = $(NAME).dll
	RUNNER_TOOL	 = wine
else
	PLATFORM	 = linux

	ifeq ($(CC),)
		CC = cc
	endif

	SO_NAME_BASE = lib$(NAME).so
	SO_NAME		 = $(SO_NAME_BASE).$(VERSION)
	SO_LDFLAGS	+= -Wl,-soname=$(SO_NAME)
	SO_LINK		 = so_ln_linux
endif

.PHONY: all clean install uninstall tests options so_ln_linux

all: $(SO_NAME) $(SO_LINK)

.c.o:
	$(CC) -c $(CFLAGS) $(CONFIG) $< -o $@

options:
	@echo "CC:           $(CC)"
	@echo "CFLAGS:       $(CFLAGS)"
	@echo "LDFLAGS:      $(LDFLAGS)"
	@echo "SO_LDFLAGS:   $(SO_LDFLAGS)"
	@echo "PLATFORM:     $(PLATFORM)"

clean:
	rm -f tests tests.exe lib$(NAME).so* $(NAME).dll $(OBJ)

# testing now uses objects instead of the built .so 
# to test internal functionality independently. e.g netmsg
tests: $(OBJ) tests.c
	$(CC) tests.c $(OBJ) -std=gnu99 -pedantic -Wall -Wextra -O3 -Wno-unused-parameter -flto=auto -o tests$(FILE_EXT) $(LDFLAGS) && $(RUNNER_TOOL) ./tests$(FILE_EXT)

# use CC for linking to be able to use -flto
$(SO_NAME): $(OBJ) $(HFILES)
	@echo prefix = $(PREFIX)
	$(CC) $(OBJ) $(SO_LDFLAGS) -o $(SO_NAME)

so_ln_linux: $(SO_NAME)
	ln -f -s $(SO_NAME) $(SO_NAME_BASE).$(SOVERSION)
	ln -f -s $(SO_NAME) $(SO_NAME_BASE)

install: $(SO_NAME)
	mkdir -p $(DESTDIR)$(PREFIX)/include/$(NAME)/ $(DESTDIR)$(PREFIX)/lib/
	cp -f include/* $(DESTDIR)$(PREFIX)/include/$(NAME)/
	cp -f -P $(SO_NAME_BASE)* $(DESTDIR)$(PREFIX)/lib/

uninstall:
	rm -f -r $(DESTDIR)$(PREFIX)/include/$(NAME) $(DESTDIR)$(PREFIX)/lib/$(SO_NAME_BASE)*
