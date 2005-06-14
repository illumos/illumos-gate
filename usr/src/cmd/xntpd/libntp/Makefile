#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1996,1999 by Sun Microsystems, Inc.
# All rights reserved.
#

LIBNAME=	libntp

all:	$(LIBNAME).a

include ../../Makefile.cmd
include ../Makefile.cmd

CFLAGS	+=	$(AUTHDEFS) $(LIBDEFS)

SOURCE=	atoint.c atolfp.c atouint.c auth12crypt.c authdecrypt.c authdes.c \
	authencrypt.c authkeys.c authparity.c authreadkeys.c authusekey.c \
	buftvtots.c caljulian.c calleapwhen.c caltontp.c calyearstart.c \
	clocktime.c dofptoa.c dolfptoa.c emalloc.c fptoa.c fptoms.c getopt.c \
	hextoint.c hextolfp.c humandate.c inttoa.c \
	lib_strbuf.c mfptoa.c mfptoms.c modetoa.c mstolfp.c \
	msutotsf.c numtoa.c refnumtoa.c numtohost.c octtoint.c \
	prettydate.c ranny.c tsftomsu.c tstotv.c tvtoa.c tvtots.c \
	uglydate.c uinttoa.c utvtoa.c machines.c clocktypes.c \
	a_md5encrypt.c a_md5decrypt.c \
	a_md512crypt.c decodenetnum.c systime.c msyslog.c syssignal.c \
	findconfig.c netof.c statestr.c

OBJS=	atoint.o atolfp.o atouint.o auth12crypt.o authdecrypt.o authdes.o \
	authencrypt.o authkeys.o authparity.o authreadkeys.o authusekey.o \
	buftvtots.o caljulian.o calleapwhen.o caltontp.o calyearstart.o \
	clocktime.o dofptoa.o dolfptoa.o emalloc.o fptoa.o fptoms.o getopt.o \
	hextoint.o hextolfp.o humandate.o inttoa.o \
	lib_strbuf.o mfptoa.o mfptoms.o modetoa.o mstolfp.o \
	msutotsf.o numtoa.o refnumtoa.o numtohost.o octtoint.o \
	prettydate.o ranny.o tsftomsu.o tstotv.o tvtoa.o tvtots.o \
	uglydate.o uinttoa.o utvtoa.o machines.o clocktypes.o \
	a_md5encrypt.o a_md5decrypt.o \
	a_md512crypt.o decodenetnum.o systime.o msyslog.o syssignal.o \
	findconfig.o netof.o statestr.o

$(LIBNAME).a:	$(OBJS)
	$(AR) r $@ $?

install:	$(LIBNAME).a

lintlib:	llib-l$(LIBNAME).ln

llib-l$(LIBNAME).ln:	$(SOURCE)
	$(LINT.c) -C$(LIBNAME) $(DEFS) $(INCL) $(CLOCKDEFS) $(AUTHDEFS) $(LIBDEFS) $(SOURCE) >lintlib.errs

lint:
	$(LINT.c) -u $(DEFS) $(INCL) $(CLOCKDEFS) $(AUTHDEFS) $(LIBDEFS) $(SOURCE) >lint.errs

clean clobber:
	$(RM) $(OBJS) $(LIBNAME).a lint.errs lintlib.errs llib-l$(LIBNAME).ln

.PARALLEL:
