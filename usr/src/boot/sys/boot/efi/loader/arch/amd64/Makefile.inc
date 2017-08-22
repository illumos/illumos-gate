
SRCS +=	amd64_tramp.S \
	start.S \
	framebuffer.c \
	elf64_freebsd.c \
	trap.c \
	exc.S

OBJS += amd64_tramp.o \
	start.o \
	framebuffer.o \
	elf64_freebsd.o \
	trap.o \
	exc.o

SRCS +=	nullconsole.c \
	spinconsole.c \
	comconsole.c

OBJS += nullconsole.o \
	spinconsole.o \
	comconsole.o

CFLAGS +=	-fPIC
LDFLAGS +=	-znocombreloc
