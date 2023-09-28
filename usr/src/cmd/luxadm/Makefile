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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG = luxadm

COBJS = adm.o fchba.o lux_util.o fabric_conf.o
OBJS_sparc= g_adm.o diag.o fcalupdate.o hotplug.o qlgcupdate.o setboot.o
OBJS_i386 = x86_adm.o errormsgs.o
OBJS = $(OBJS_$(MACH)) $(COBJS)

SRCS = $(OBJS:%.o=%.c)

POFILES = $(OBJS:%.o=%.po)
POFILE = luxadm.po

include ../Makefile.cmd

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-address

# not linted
SMATCH=off

sparc_LDLIBS = -la5k -lg_fc -ldevid -lkstat -ldevinfo
i386_LDLIBS =
LDLIBS += $($(MACH)_LDLIBS)
LDLIBS += -lnvpair
LDLIBS += -ldevice
LDLIBS += -lHBAAPI

INCS += -I$(SRC)/lib/sun_fc/common

CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)

ROOTUSRSBINLINKS = $(PROG:%=$(ROOTUSRSBIN)/%)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

GENCAT_PROG=a5k_g_fc_i18n_cat
GENMSG_LUX=	$(PROG).msg
LUXFIRMWARED=   $(ROOTLIB)/locale/C/LC_MESSAGES
LUXIBFIRMWARE_sparc=  $(LUXFIRMWARED)/ibfirmware
LUXIBFIRMWARE=  $(LUXIBFIRMWARE_$(MACH))
LUXGENCAT_PROG_sparc= $(LUXFIRMWARED)/$(GENCAT_PROG)
LUXGENCAT_PROG= $(LUXGENCAT_PROG_$(MACH))
$(LUXIBFIRMWARE):= FILEMODE= 0644
$(LUXGENCAT_PROG):= FILEMODE= 0644

$(LUXFIRMWARED):
	$(INS.dir)

$(LUXIBFIRMWARE):       $(LUXFIRMWARED) ibfirmware
	$(INS.file) ibfirmware

$(GENMSG_LUX):		$(SRCS)
	/usr/bin/genmsg -d -p '$(COMPILE.cpp)' -o $@ $(SRCS)

$(GENCAT_PROG):		$(GENMSG_LUX)
	/usr/bin/gencat $@ $(GENMSG_LUX)

$(LUXGENCAT_PROG):      $(LUXFIRMWARED) $(GENCAT_PROG)
	$(INS.file) $(GENCAT_PROG)

install: all $(ROOTUSRSBINPROG) $(LUXIBFIRMWARE) $(LUXGENCAT_PROG)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

clean:
	$(RM) $(OBJS) $(PROG) $(GENCAT_PROG) $(GENMSG_LUX)

include ../Makefile.targ
