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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include ../Makefile.tools

.KEEP_STATE:

COMMON_SRC=	$(SRC)/cmd/boot/common
EINFO_SRC=	$(COMMON_SRC)/bblk_einfo.c
UTILS_SRC=	$(COMMON_SRC)/boot_utils.c
EXTRA_SRC=	$(COMMON_SRC)/mboot_extra.c

PROG=		btxld
MAN1ONBLDFILES=	btxld.1onbld
SRCS=		btxld.c elfh.c version.c $(UTILS_SRC) $(EINFO_SRC) $(EXTRA_SRC)
OBJS=		btxld.o elfh.o version.o bblk_einfo.o mboot_extra.o boot_utils.o
LDLIBS +=	-lmd5
C99MODE=	$(C99_ENABLE)
CPPFLAGS +=	-I$(SRC)/uts/common -I$(COMMON_SRC)

$(ROOTONBLDMAN1ONBLDFILES)	:= FILEMODE=	644

all: $(PROG) $(MAN1ONBLDFILES)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDMAN1ONBLDFILES)

clean:
	$(RM) $(OBJS)

%.o:	%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o:	$(COMMON_SRC)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../Makefile.targ
