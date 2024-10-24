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
include $(SRC)/boot/Makefile.inc

PROG=		gptzfsboot
MAN=		gptzfsboot.8
FILEMODE=0444

BOOT_COMCONSOLE_PORT= 0x3f8
BOOT_COMCONSOLE_SPEED= 9600
B2SIOFMT=	0x3

REL1=	0x700
ORG1=	0x7c00
ORG2=	0x0

CPPFLAGS += -DBOOTPROG=\"gptzfsboot\" \
	-DGPT -DBOOT2 \
	-DLOADER_MBR_SUPPORT -DLOADER_GPT_SUPPORT \
	-DSIOPRT=$(BOOT_COMCONSOLE_PORT) \
	-DSIOFMT=$(B2SIOFMT) \
	-DSIOSPD=$(BOOT_COMCONSOLE_SPEED) \
	-I../../include \
	-I../../libsa \
	-I../../common \
	-I../common \
	-I$(ZFSSRC) \
	-I../../sys/cddl/boot/zfs \
	-I../btx/lib -I. \
	-I../../sys \
	-I../libi386
AS_CPPFLAGS += $(CPPFLAGS)

LDSCRIPT=	../boot.ldscript
LD_FLAGS=	-static -N --gc-sections
LIBI386=	-L ../libi386 -li386
LIBSTAND=	-L ../../libsa/$(MACH) -lsa
LIBS=		$(LIBI386) $(LIBSTAND)
DPADD=		../libi386/libi386.a ../../libsa/$(MACH)/libsa.a

include ../Makefile.inc

.PARALLEL:

all: $(PROG)

install: all $(ROOTBOOTPROG)

OBJS =	mb_header.o zfsboot.o sio.o cons.o devopen.o \
	part.o disk.o bcache.o zfs_cmd.o

cons.o := CFLAGS += -_gcc14=--param=min-pagesize=0
zfsboot.o := CFLAGS += -_gcc14=--param=min-pagesize=0
zfsboot.o := CPPFLAGS += -I$(SRC)/uts/common -I$(SRC)/uts/common/fs/zfs
zfs_cmd.o := CPPFLAGS += -I$(SRC)/uts/common
part.o := CPPFLAGS += -I$(ZLIB)
smbios.o := CPPFLAGS += -DSMBIOS_SERIAL_NUMBERS
smbios.o := CPPFLAGS += -DSMBIOS_LITTLE_ENDIAN_UUID
gptldr.out := LD_FLAGS += $(GLDTARGET)

CLEANFILES=	gptzfsboot $(OBJS)

gptzfsboot: gptldr.bin gptzfsboot.bin $(BTXKERN)
	$(BTXLD) -E $(ORG2) -f bin -b $(BTXKERN) -V $(BOOT_VERSION) -l \
		gptldr.bin -o $@ gptzfsboot.bin

CLEANFILES +=	gptldr.bin gptldr.out gptldr.o

gptldr.bin: gptldr.out
	$(OBJCOPY) -S -O binary gptldr.out $@

gptldr.out: gptldr.o
	$(GLD) $(LD_FLAGS) -e start -Ttext $(ORG1) -o $@ gptldr.o

CLEANFILES +=	gptzfsboot.bin gptzfsboot.out

gptzfsboot.bin: gptzfsboot.out
	$(OBJCOPY) -S -O binary gptzfsboot.out $@

gptzfsboot.out: $(BTXCRT) $(OBJS) $(DPADD)
	$(GLD) $(LD_FLAGS) -T $(LDSCRIPT) -o $@ $(BTXCRT) $(OBJS) $(LIBS)

machine:
	$(RM) machine
	$(SYMLINK) ../../sys/i386/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../sys/x86/include x86

$(OBJS): machine x86

%.o:	../common/%.c
	$(COMPILE.c) $<

%.o:	../../common/%.c
	$(COMPILE.c) $<

%.o: ../../common/%.S
	$(COMPILE.S) $<

clobber: clean

clean:
	$(RM) $(CLEANFILES) machine x86
