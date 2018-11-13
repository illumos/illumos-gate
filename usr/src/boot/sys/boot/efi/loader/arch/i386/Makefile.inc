
SRCS +=	multiboot_tramp.S \
	start.S \
	cpuid.c

OBJS +=	multiboot_tramp.o \
	start.o \
	cpuid.o

SRCS +=	nullconsole.c \
	spinconsole.c \
	comconsole.c

OBJS +=	nullconsole.o \
	spinconsole.o \
	comconsole.o
