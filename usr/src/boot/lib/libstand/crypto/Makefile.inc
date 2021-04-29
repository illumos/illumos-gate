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
# Copyright 2021 Toomas Soome <tsoome@me.com>
#

COMDIR = $(SRC)/common/crypto

SRCS +=		$(CRYPTOSRC)/digest.c
SRCS +=		$(COMDIR)/sha1/sha1.c
SRCS +=		$(COMDIR)/edonr/edonr.c
SRCS +=		$(COMDIR)/skein/skein.c
SRCS +=		$(COMDIR)/skein/skein_iv.c
SRCS +=		$(COMDIR)/skein/skein_block.c
OBJS +=		digest.o
OBJS +=		sha1.o
OBJS +=		edonr.o
OBJS +=		skein.o
OBJS +=		skein_iv.o
OBJS +=		skein_block.o

digest.o := CPPFLAGS +=	-I../../common

# Do not unroll skein loops, reduce code size
skein_block.o := CPPFLAGS +=	-DSKEIN_LOOP=111

%.o:	$(COMDIR)/edonr/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(COMDIR)/skein/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(CRYPTOSRC)/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(COMDIR)/sha1/%.c
	$(COMPILE.c) $<

sha1-x86_64.s: $(COMDIR)/sha1/amd64/sha1-x86_64.pl
	$(PERL) $? $@

sha1-x86_64.o: sha1-x86_64.s
	$(COMPILE.s) -o $@ ${@F:.o=.s}
