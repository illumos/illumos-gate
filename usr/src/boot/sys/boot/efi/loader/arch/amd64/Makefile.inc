
SRCS +=	multiboot_tramp.S \
	start.S \
	trap.c \
	exc.S

OBJS += multiboot_tramp.o \
	start.o \
	trap.o \
	exc.o

SRCS +=	nullconsole.c \
	spinconsole.c \
	comconsole.c

OBJS += nullconsole.o \
	spinconsole.o \
	comconsole.o
