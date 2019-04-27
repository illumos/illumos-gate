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
#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.version
include $(SRC)/boot/sys/boot/Makefile.inc

PROG= isoboot
FILEMODE=0444

BOOT_COMCONSOLE_PORT= 0x3f8
BOOT_COMCONSOLE_SPEED= 9600
B2SIOFMT= 0x3

ORG1= 0x7c00
ORG2= 0x0

ISOBOOTSIZE= 30720

CPPFLAGS += -DBOOTPROG=\"isoboot\" \
	-DSIOPRT=$(BOOT_COMCONSOLE_PORT) \
	-DSIOFMT=$(B2SIOFMT) \
	-DSIOSPD=$(BOOT_COMCONSOLE_SPEED) \
	-I../../../../include \
	-I../../../../lib/libstand \
	-I. \
	-I../../.. \
	-I../common \
	-I../btx/lib \
	-I../../common \
	-I../gptzfsboot

LDSCRIPT=	../boot.ldscript
LD_FLAGS=	-static -N --gc-sections
LIBSTAND=	../../libstand/$(MACH)/libstand.a

gptldr.out := LD_FLAGS += -m elf_i386_sol2

include ../Makefile.inc

all: $(PROG)

install: all $(ROOTBOOTPROG)

OBJS= multiboot.o isoboot.o sio.o drv.o cons.o gptldr.o

CLEANFILES += isoboot

isoboot: gptldr.bin isoboot.bin $(BTXKERN)
	btxld -v -E $(ORG2) -f bin -b $(BTXKERN) -V $(BOOT_VERSION) -l \
		gptldr.bin -o $@ isoboot.bin
	@set -- `ls -l $@`; x=$$(($(ISOBOOTSIZE)-$$5)); \
	    echo "$$x bytes available"; test $$x -ge 0

CLEANFILES += gptldr.bin gptldr.out gptldr.o

gptldr.bin: gptldr.out
	$(OBJCOPY) -S -O binary gptldr.out $@

gptldr.out:	gptldr.o
	$(LD) $(LD_FLAGS) -e start -Ttext $(ORG1) -o $@ gptldr.o

CLEANFILES += isoboot.bin isoboot.out $(OBJS)

isoboot.bin: isoboot.out
	$(OBJCOPY) -S -O binary isoboot.out $@

isoboot.out: $(BTXCRT) $(OBJS)
	$(LD) $(LD_FLAGS) -T $(LDSCRIPT) -o $@ $(BTXCRT) $(OBJS) $(LIBSTAND)

machine:
	$(RM) machine
	$(SYMLINK) ../../../i386/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

$(OBJS): machine x86

%.o:	../gptzfsboot/%.S
	$(COMPILE.S) $<

%.o:	../../common/%.S
	$(COMPILE.S) $<

%.o:	../common/%.c
	$(COMPILE.c) $<

%.o:	../../common/%.c
	$(COMPILE.c) $<

clobber: clean

clean:
	$(RM) $(CLEANFILES) machine x86
