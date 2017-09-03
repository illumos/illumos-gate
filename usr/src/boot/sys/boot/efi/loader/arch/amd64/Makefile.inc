
SRCS +=	multiboot_tramp.S \
	start.S \
	framebuffer.c \
	trap.c \
	exc.S

OBJS += multiboot_tramp.o \
	start.o \
	framebuffer.o \
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
