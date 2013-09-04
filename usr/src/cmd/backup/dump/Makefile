#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/backup/dump/Makefile
#
# Copyright (c) 1980 Regents of the University of California.
# All rights reserved.  The Berkeley software License Agreement
# specifies the terms and conditions for redistribution.
#
#	dump.h			header file
#	dumpfstab.c		reads fstab/vfstab, mtab/mnttab
#	dumpitime.c		reads /etc/dumpdates
#	dumpmain.c		driver
#	dumponline.c		online dump support
#	dumpoptr.c		operator interface
#	dumptape.c		handles the mag tape and opening/closing
#	dumptraverse.c		traverses the file system
#	lftw.c			fixed version of ftw(3)
#	partial.c		partial filesystem dump support
#	unctime.c		undo ctime
#
# CPPFLAGS:
#	DEBUG			use local directory to find ddate and dumpdates
#	PARTIAL			enable partial filesystem dump support
#	TDEBUG			trace out the process forking
#
#	CAUTION: FSTYPE must be defined before including ../Makefile.backup,
#		 otherwise UFSROOTPKGUSRLIBFSTYPE doesn't get expanded
#		 properly and the magic doesn't happen.

FSTYPE=		ufs

include ../Makefile.backup

#CFLAGS +=	-DTDEBUG
UFSDUMP=	ufsdump

PROG=		$(UFSDUMP)
PRODUCT=	$(PROG)
ROLLDIR=	../../fs.d/ufs/roll_log
ROLLOBJS=	$(ROLLDIR)/$(MACH)/roll_log.o
ROLLSRCS=	$(ROLLDIR)/roll_log.c

LOBJECTS=	dumponline.o dumpfstab.o dumpitime.o dumpmain.o \
		dumpoptr.o dumptape.o dumptraverse.o unctime.o \
		partial.o lftw.o
OBJECTS=	$(LOBJECTS) roll_log.o
SRCS=		$(LOBJECTS:.o=.c)

POFILES=	$(OBJECTS:.o=.po) ../lib/libdump.po
POFILE=		ufsdump.po
ROLLPOFILES=	roll_log.po

# XXX This is only needed for the check: target.  It would be nice to
# XXX automatically generate the list when needed.
HEADERS=	../../../head/protocols/dumprestore.h \
	../../fs.d/ufs/roll_log/roll_log.h ../include/byteorder.h \
	../include/memutils.h \
	../include/rmt.h dump.h dumpusg.h

CLOBBERFILES +=	$(PRODUCT) $(DEBUGPRODUCTS) dumpdates

LOCAL=		.
GENERAL=	../include
GLOBAL=		../../../head
CPPFLAGS=	-I$(LOCAL) -I$(GENERAL) -I$(GLOBAL) -DPARTIAL \
		-I$(ROLLDIR) $(CPPFLAGS.master) \
		-D_LARGEFILE64_SOURCE=1
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-extra
LIBDUMP=	../lib/libdump.a
LINTLIBDUMP=	../lib/llib-ldump.ln -lkstat
LDLIBS +=	$(BSTATIC) -L../lib -ldump $(BDYNAMIC) \
		-lsocket -lnsl -ladm -lm -lkstat

UFSROOTDUMPDATES=	$(UFSROOTETC)/dumpdates
UFSROOTLINK=		$(UFSROOTUSRSBIN)/$(PROG)
LINKVALUE=		../lib/fs/$(FSTYPE)/$(PROG)
LIBDIR=			$(UFSROOTUSRLIBFS)/$(FSTYPE)
$(UFSROOTDUMPDATES):=	FILEMODE=	0664
$(LIBDIR):=		DIRMODE=	0755

FILEMODE=	04555

.KEEP_STATE:

all:		$(PRODUCT) 

$(PROG):	$(OBJECTS) $$(LIBDUMP)
	$(LINK.c) -o $@ $(OBJECTS) $(LDLIBS)
	$(POST_PROCESS)

$(LIBDUMP): FRC
	$(DO_LIBDIR)

$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

FRC:

install:	all $(LIBDIR) $(UFSROOTPKGUSRLIBFSTYPE) dumpdates \
		$(UFSROOTDUMPDATES) $(UFSROOTLINK)

dumpdates:
	cp /dev/null dumpdates

#XXX Should actually note return value from close(2), particularly regarding
#XXX tape descriptors.  Some drives don't actually force anything to media
#XXX except when they are writing a file mark....

# grep is looking for non-space/tab
lint:	$(SRCS) $(ROLLSRCS) $$(LINTLIBDUMP)
	$(LINT.c) $(SRCS) $(ROLLSRCS) $(LINTLIBDUMP) 2>&1 \
	| sed -f lint.sed | grep '^[^ 	]'

$(LINTLIBDUMP):	FRC
	cd ../lib; pwd; $(MAKE) lint
	pwd

check:	FRC
	$(CSTYLE) $(CSTYLEFLAGS) $(SRCS) $(ROLLSRCS) $(HEADERS)
	$(HDRCHK) $(HDRCHKFLAGS) $(HEADERS)

clean:
	$(RM) $(OBJECTS) $(ROLLOBJS) $(DEBUGOBJS) *.ln

$(LIBDIR):
	$(INS.dir)

$(UFSROOTLINK):
	-$(RM) $@; $(SYMLINK) $(LINKVALUE) $(UFSROOTLINK)

roll_log.o:
	cd $(ROLLDIR) ; pwd ; $(MAKE)
	cp $(ROLLOBJS) .
	pwd

.debug/roll_log.o:
	cd $(ROLLDIR) ; pwd ; $(MAKE) CFLAGS=-g
	cp $(ROLLOBJS) .debug
	pwd

$(ROLLPOFILES): $(ROLLSRCS)
	cd $(ROLLDIR) ; pwd ; $(MAKE) `echo $(ROLLPOFILES) | sed -e 's@$(ROLLDIR)/@@g'`
	cp $(ROLLDIR)/*.po .
	pwd

../lib/libdump.po:
	cd ../lib ; pwd ; $(MAKE)  libdump.po

include ../Makefile.targ
