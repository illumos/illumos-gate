#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for intermachine communications package.
#
# Files are:
#	/etc/remote		remote host description file
#	/etc/phones		phone number file, owned by uucp and
#				  mode 6??
#	/var/adm/aculog		ACU accounting file, owned by uucp and
#				  mode 6?? (if ACULOG defined)
# Presently supports:
#	BIZCOMP
#	DEC DF02-AC, DF03-AC
#	DEC DN-11/Able Quadracall
#	VENTEL 212+
#	VADIC 831 RS232 adaptor
#	VADIC 3451
#	HAYES SmartModem
# (drivers are located in aculib.a)
#
# Configuration defines:
#	DF02, DF03, DN11	ACU's supported
#	  BIZ1031, BIZ1022, VENTEL, V831, V3451, HAYES
#	ACULOG			turn on tip logging of ACU use
#	PRISTINE		no phone #'s put in ACU log file
#	DEFBR			default baud rate to make connection at
#	DEFFS			default frame size for FTP buffering of
#				writes on local side
#	BUFSIZ			buffer sizing from stdio, must be fed
#				explicitly to remcap.c if not 1024
#
# cmd/tip/Makefile

PROG=	tip

OBJS=	acu.o cmds.o cmdtab.o cu.o hunt.o \
	log.o partab.o remote.o tip.o tipout.o value.o vars.o \
	acutab.o remcap.o uucplock.o

# sigh, NSE can't handle wildcards
#DRIVERS=	aculib/*.c

SRCS=	$(OBJS:.o=.c)

SOURCES=$(SRCS) $(DRIVERS)

include	../Makefile.cmd

REMOTE=		etc.remote
ACULOG=		aculog
ROOTETCREMOTE=	$(ROOTETC)/remote
ROOTACULOGD=	$(ROOT)/var/adm
ROOTACULOG=	$(ROOTACULOGD)/aculog

$(ROOTPROG) :=		FILEMODE =	4511
$(ROOTETCREMOTE) :=	FILEMODE =	644
$(ROOTACULOG) :=	FILEMODE =	600

LINTFLAGS +=	-u
CPPFLAGS +=	-DDEFBR=300 -DDEFFS=BUFSIZ -DACULOG -DUSG
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-uninitialized
CONFIG=	-DV831 -DVENTEL -DV3451 -DDF02 -DDF03 -DBIZ1031 -DBIZ1022 -DHAYES
ACULIB=	aculib/aculib.a
LDLIBS=	$(ACULIB) $(LDLIBS.cmd)

CLOBBERFILES += $(ACULOG)

# install rules
$(ROOTACULOGD)/% : %
	$(INS.file)

$(ROOTETC)/% : etc.%
	$(INS.rename)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG) $(REMOTE) $(ACULOG)

$(PROG):	$(OBJS) $(ACULIB)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

# special build rules
remcap.o :=	CPPFLAGS += -DBUFSIZ=1024
acutab.o :=	CPPFLAGS += $(CONFIG)

# acutab is configuration dependent, and so depends on the makefile
acutab.o: Makefile

# remote.o depends on the makefile because of DEFBR and DEFFS
remote.o: Makefile

# log.o depends on the makefile because of ACULOG
log.o:	Makefile

$(ACULIB): FRC
	cd aculib; $(MAKE)

install: all $(ROOTPROG) $(ROOTETCREMOTE) $(ROOTACULOG)

$(ACULOG):
	cp /dev/null $(ACULOG)

clean:	FRC
	cd aculib; $(MAKE) clean
	$(RM) $(OBJS)

lint:
	cd aculib; $(MAKE) lint
	$(LINT.c) $(SRCS) $(LDLIBS.cmd)


include ../Makefile.targ

FRC:
