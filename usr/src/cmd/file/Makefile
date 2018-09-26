#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= file
XPG4PROG= file
MAGIC= magic

ELFCAP=	$(SRC)/common/elfcap
SGSRTCID=	$(SRC)/common/sgsrtcid

LOBJS=	file.o elf_read32.o elf_read64.o magicutils.o
OBJS=	$(LOBJS) elfcap.o
XPG4OBJS= $(OBJS:%.o=xpg4_%.o)
SRCS=	file.c elf_read.c magicutils.c $(ELFCAP)/elfcap.c

include ../Makefile.cmd

CSTD=	$(CSTD_GNU99)
C99LMODE= -Xc99=%all

CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-type-limits

POFILE= file_all.po
POFILES= $(SRCS:%.c=%.po)

# The debug binary can be built using the flag
# -D COPTFLAG=-g CGLOBALSTATIC=
# This will avoid the multiple symbols definition error
# for static global variables in elf_read32.o and elf_read64.o

LDLIBS += -lelf
CPPFLAGS += -I$(ELFCAP) -I$(SGSRTCID)
$(XPG4) := CFLAGS += -DXPG4

ROOTETCMAGIC= $(MAGIC:%=$(ROOTETC)/%)

$(ROOTETCMAGIC) :=	FILEMODE =	$(LIBFILEMODE)

.PARALLEL:	$(OBJS) $(XPG4OBJS) $(POFILES)

.KEEP_STATE:

all: $(PROG) $(XPG4) $(MAGIC)

$(PROG) : $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG4) : $(XPG4OBJS)
	$(LINK.c) $(XPG4OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	%.c
	$(COMPILE.c) -o $@ $<

%32.o:	%.c
	$(COMPILE.c) -o $@ $<

%64.o:	%.c
	$(COMPILE.c) -D_ELF64 -o $@ $<

xpg4_%.o:	%.c
	$(COMPILE.c) -o $@ $<

xpg4_%32.o:	%.c
	$(COMPILE.c) -o $@ $<

xpg4_%64.o:	%.c
	$(COMPILE.c) -D_ELF64 -o $@ $<

elfcap.o:	$(ELFCAP)/elfcap.c
	$(COMPILE.c) -o $@ $(ELFCAP)/elfcap.c

xpg4_elfcap.o:	$(ELFCAP)/elfcap.c
	$(COMPILE.c) -o $@ $(ELFCAP)/elfcap.c

$(POFILE):	$(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTETCMAGIC)

clean:
	$(RM) $(OBJS) $(XPG4OBJS)

lint: lint_SRCS

include ../Makefile.targ
