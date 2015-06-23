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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Copyright 2014 Alexander Pyhalov
#


LIBPROG=	mailwrapper 

PROG= 	       $(LIBPROG)

include ../Makefile.cmd

MWOBJS=		fgetln.o fparseln.o mailwrapper.o

CLOBBERFILES=	$(PROG)
CLEANFILES=	$(MWOBJS)

SRCS=	 	$(MWOBJS:%.o=%.c)

CPROG=		mailwrapper
CPROGSRC= 	$(CPROG:%=_%.c)

CFS=		mailer.conf

ROOTETCFILES=$(CFS:%=$(ROOTETC)/%)

$(ROOTETCFILES) :=	FILEMODE = 0644

# installed modules
ROOTLIBPROG=	$(LIBPROG:%=$(ROOTLIB)/%)

ROOTSYMLINKS=	$(ROOTBIN)/mailq \
		$(ROOTLIB)/sendmail \
		$(ROOTUSRSBIN)/newaliases \
		$(ROOTUSRSBIN)/sendmail

CPPFLAGS =	-I. $(CPPFLAGS.master)

LINTFLAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2

# conditional assignments
#
all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

# install rules
$(ROOTINC)/% : %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(MWOBJS) $(OBJS)

all:		$(PROG) 

mailwrapper:	$(MWOBJS)
	$(LINK.c) -o $@ $(MWOBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTLIBPROG) $(ROOTSYMLINKS) $(ROOTETCFILES)

# ROOTSYMLINKS
#
$(ROOTBIN)/mailq: 
	$(RM) $@; $(SYMLINK) ../lib/mailwrapper $@

$(ROOTLIB)/sendmail:
	$(RM) $@; $(SYMLINK) mailwrapper $@

$(ROOTUSRSBIN)/newaliases:
	$(RM) $@; $(SYMLINK) ../lib/mailwrapper $@

$(ROOTUSRSBIN)/sendmail:
	$(RM) $@; $(SYMLINK) ../lib/mailwrapper $@

$(ROOTETCMAIL)/%:  %
	$(INS.file)

lint: 
	$(LINT.c) $(SRCS)

clean:
	$(RM) $(OBJS) $(MWOBJS) mailwrapper

clobber: clean
	$(RM) $(ROOTSYMLINKS) $(ROOTLIBPROG) $(ROOTETCFILES)
