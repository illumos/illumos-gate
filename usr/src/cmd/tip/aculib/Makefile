#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 1983 Regents of the University of California.
# All rights reserved. The Berkeley software License Agreement
# specifies the terms and conditions for redistribution.
#

# make file for tip device drivers
#
# Current drivers:
#	BIZCOMP
#	DEC DF02-AC, DF03-AC
#	DEC DN-11/Able Quadracall
#	VENTEL 212+ (w/o echo)
#	VADIC 831 RS232 adaptor
#	VADIC 3451
#	HAYES SmartModem
#
# cmd/tip/aculib/Makefile

ACULIB=	aculib.a
OBJS=	biz22.o biz31.o df.o dn11.o hayes.o ventel.o v831.o v3451.o

include ../../Makefile.cmd

LINTFLAGS +=	-u
CPPFLAGS=	-I../ -DUSG $(CPPFLAGS.master)
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-parentheses

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(ACULIB)

$(ACULIB): $(OBJS)
	$(AR) cr $(ACULIB) $(OBJS)

clean:
	$(RM) $(ACULIB) $(OBJS)

lint:
	$(LINT.c) $(OBJS:%.o=%.c) $(LDLIBS)
