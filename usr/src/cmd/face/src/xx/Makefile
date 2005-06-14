#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# /usr/src/cmd/face/src/xx/Makefile
#

include		../../../Makefile.cmd

# include common face definitions and rules
include		../Makefile.com

PROG=		slash facesuspend
SHFILES=	chksys unix

TEXTS=		initial.txt cmdfile.txt

SUBDIRS=	../proc ../../HELP ../../OBJECTS

ROOTFILES=	$(PROG) $(SHFILES)

ROOTCMDS=	$(ROOTFILES:%=$(ROOTVMBIN)/%)
ROOTTEXTS=	$(TEXTS:%.txt=$(ROOTVMBIN)/%)

# local libraries
LOCALLIB = ../proc/libproc.a
facesuspend := LDLIBS += $(LOCALLIB)

CPPFLAGS = 	-I../filecab/inc $(CPPFLAGS.master)

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint


$(ROOTCMDS):=		FILEMODE=	755
$(ROOTTEXTCMDS):=	FILEMODE=	644

.KEEP_STATE:

all: $(SUBDIRS) .WAIT $(PROG) $(SHFILES) $(TEXTS)

facesuspend: suspend.c $(LOCALLIB)
	$(LINK.c) -o $@ suspend.c $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTCMDS) $(ROOTTEXTS) $(SUBDIRS)


$(ROOTVMBIN)/% : %.txt
	$(INS.rename)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

clobber clean: $(SUBDIRS)

lint:
	$(LINT.c) slash.c $(LDLIBS)
	$(LINT.c) suspend.c ../proc/suspend.c $(LDLIBS)

FRC:

include ../../../Makefile.targ
