
SRCS +=	multiboot_tramp.S \
	start.S \
	cpuid.c \
	trap.c \
	exec.c \
	exc.S

OBJS += multiboot_tramp.o \
	start.o \
	cpuid.o \
	trap.o \
	exec.o \
	exc.o

SRCS +=	nullconsole.c \
	spinconsole.c \
	comconsole.c

OBJS += nullconsole.o \
	spinconsole.o \
	comconsole.o
