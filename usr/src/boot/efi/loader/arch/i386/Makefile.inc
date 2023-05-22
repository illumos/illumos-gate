
SRCS +=	multiboot_tramp.S \
	start.S \
	cpuid.c \
	exec.c

OBJS +=	multiboot_tramp.o \
	start.o \
	cpuid.o \
	exec.o

SRCS +=	nullconsole.c \
	spinconsole.c \
	comconsole.c

OBJS +=	nullconsole.o \
	spinconsole.o \
	comconsole.o
