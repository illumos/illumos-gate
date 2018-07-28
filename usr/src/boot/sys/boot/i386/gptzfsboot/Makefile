#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2015 Toomas Soome <tsoome@me.com>
# Copyright 2016 RackTop Systems.
#

#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.version

AS=	$(GNU_ROOT)/bin/gas
LD=	$(GNU_ROOT)/bin/gld
CC=	$(GNUC_ROOT)/bin/gcc
OBJCOPY=	$(GNU_ROOT)/bin/gobjcopy

PROG=		gptzfsboot
MAN=		gptzfsboot.8
FILEMODE=0444

BOOT_COMCONSOLE_PORT= 0x3f8
BOOT_COMCONSOLE_SPEED= 9600
B2SIOFMT=	0x3

REL1=	0x700
ORG1=	0x7c00
ORG2=	0x0

CPPFLAGS=
CFLAGS=	-nostdinc -DBOOTPROG=\"gptzfsboot\" \
	-O1 \
	-DGPT -DBOOT2 \
	-DLOADER_MBR_SUPPORT -DLOADER_GPT_SUPPORT \
	-DSIOPRT=${BOOT_COMCONSOLE_PORT} \
	-DSIOFMT=${B2SIOFMT} \
	-DSIOSPD=${BOOT_COMCONSOLE_SPEED} \
	-I../../../../include \
	-I../../../../lib/libstand \
	-I../../common \
	-I../common \
	-I../../zfs \
	-I../../../cddl/boot/zfs \
	-I../btx/lib -I. \
	-I../../.. \
	-I../libi386 \
	-Wall -Waggregate-return -Wbad-function-cast -Wcast-align \
	-Wmissing-declarations -Wmissing-prototypes -Wnested-externs \
	-Wpointer-arith -Wshadow -Wwrite-strings \
	-Winline -Wno-unknown-pragmas

CFLAGS +=	--param max-inline-insns-single=100
CFLAGS +=	-fno-reorder-functions

LD_FLAGS=-static -N --gc-sections
CCASFLAGS=-Wa,--divide
LIBSTAND=	../../libstand/i386/libstand.a
LIBZFSBOOT=	../../zfs/i386/libzfsboot.a

include ../Makefile.inc

.PARALLEL:

all: $(PROG)

install: all $(ROOTBOOTPROG)

OBJS =	multiboot.o zfsboot.o sio.o cons.o panic.o devopen.o \
	part.o biosmem.o smbios.o biosdisk.o devicename.o disk.o bcache.o \
	time.o crc32.o

CLEANFILES=	gptzfsboot $(OBJS)

gptzfsboot: gptldr.bin gptzfsboot.bin ${BTXKERN}
	$(BTXLD) -E ${ORG2} -f bin -b ${BTXKERN} -V ${BOOT_VERSION} -l \
		gptldr.bin -o $@ gptzfsboot.bin

CLEANFILES +=	gptldr.bin gptldr.out gptldr.o

gptldr.bin: gptldr.out
	${OBJCOPY} -S -O binary gptldr.out $@

gptldr.out: gptldr.o
	${LD} ${LD_FLAGS} -e start -Ttext ${ORG1} -o $@ gptldr.o

CLEANFILES +=	gptzfsboot.bin gptzfsboot.out

gptzfsboot.bin: gptzfsboot.out
	${OBJCOPY} -S -O binary gptzfsboot.out $@

gptzfsboot.out: ${BTXCRT} ${OBJS} ${LIBZFSBOOT} ${LIBSTAND}
	${LD} ${LD_FLAGS} -Ttext ${ORG2} -o $@ ${BTXCRT} ${OBJS} \
		${LIBZFSBOOT} ${LIBSTAND}

machine:
	$(RM) machine
	$(SYMLINK) ../../../i386/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

$(OBJS): machine x86

%.o:	../common/%.c
	$(COMPILE.c) -o $@ $<

%.o:	../../common/%.c
	$(COMPILE.c) -o $@ $<

biosdisk.o: ../libi386/biosdisk.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Dalloca=__builtin_alloca -c -o $@ ../libi386/$*.c

biosmem.o: ../libi386/biosmem.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ ../libi386/$*.c

smbios.o: ../libi386/smbios.c
	$(CC) $(CFLAGS) $(CPPFLAGS) \
		-DSMBIOS_SERIAL_NUMBERS -DSMBIOS_LITTLE_ENDIAN_UUID \
		-c -o $@ ../libi386/$*.c

devicename.o: ../libi386/devicename.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ ../libi386/$*.c

time.o: ../libi386/time.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ ../libi386/$*.c

multiboot.o: ../../common/multiboot.S
	$(CC) $(CFLAGS) $(CCASFLAGS) -c -o $@ ../../common/$*.S

.S.o:
	$(CC) $(CFLAGS) $(CCASFLAGS) -c -o $@ $<

clobber: clean

clean:
	$(RM) $(CLEANFILES) machine x86
