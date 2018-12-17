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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= sac sacadm pmadm

MANIFEST = sac.xml

include ../Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

SACOBJ= sac.o readtab.o global.o log.o misc.o
SACOBJS= $(SACOBJ) util1.o
SACADMOBJ= sacadm.o admutil.o
SACADMOBJS= $(SACADMOBJ) util2.o
PMADMOBJ= pmadm.o admutil.o
PMADMOBJS= $(PMADMOBJ) util2.o
SACSRC= $(SACOBJ:%.o=%.c)
SACSRCS= $(SACSRC) util.c
SACADMSRC= $(SACADMOBJ:%.o=%.c)
SACADMSRCS= $(SACADMSRC) util.c
PMADMSRC= $(PMADMOBJ:%.o=%.c)
PMADMSRCS= $(PMADMSRC) util.c
OBJS= $(SACOBJS) $(SACADMOBJS) $(PMADMOBJS)

LIBSAFD = $(ROOTLIB)/saf
DIRS= $(LIBSAFD)
SACF= sac
ADMF= sacadm pmadm
ROOTSACF= $(SACF:%=$(LIBSAFD)/%)
ROOTADMF= $(ADMF:%=$(ROOTUSRSBIN)/%)

LDLIBS += -lnsl
LDFLAGS += $(MAPFILE.NGB:%=-M%)
LINTFLAGS += -b -x

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-extra

# too many untyped funcs
SMATCH=off

util1.o := CPPFLAGS += -DSAC
util2.o := CPPFLAGS += -USAC

sac :=	LDLIBS += -lpam

$(ROOTUSRSBIN)/sacadm :=	FILEMODE =	04755

$(LIBSAFD)/% : %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG) 

sac: $(SACOBJS) $(MAPFILE.NGB)
	$(LINK.c) $(SACOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

sacadm: $(SACADMOBJS) $(MAPFILE.NGB)
	$(LINK.c) $(SACADMOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

pmadm: $(PMADMOBJS) $(MAPFILE.NGB)
	$(LINK.c) $(PMADMOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

util1.o: util.c
	$(COMPILE.c) -o $@ util.c

util2.o: util.c
	$(COMPILE.c) -o $@ util.c

install: all .WAIT $(ROOTSACF) $(ROOTADMF) $(ROOTMANIFEST)

# Don't install dirs already installed by Targetdirs
#$(DIRS):
#	$(INS.dir)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) $(SACSRCS)
	$(LINT.c) $(SACADMSRCS)
	$(LINT.c) $(PMADMSRCS)

include ../Makefile.targ
