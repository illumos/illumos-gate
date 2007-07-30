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
# Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

SCRIPT =		wrsmcfg
INIT_D =		$(ROOTETC)/init.d
INIT_PROG =		$(INIT_D)/$(SCRIPT)
RCS_SSCRIPT =		S29wrsmcfg
RCS_KSCRIPT =		K44wrsmcfg
ROOTRCS_D =		$(ROOTETC)/rcS.d
ROOTRCS_SLINK =		$(ROOTRCS_D)/$(RCS_SSCRIPT)
ROOTRCS_KLINK =		$(ROOTRCS_D)/$(RCS_KSCRIPT)
DATA_D =		$(ROOTETC)/wrsm

PROG		= wrsmconf
ROOTFS_PROG	= $(PROG)
PLATFORM	= sun4u
OBJS		= wrsmconf.o mkconfig.o
SRCS		= $(OBJS:%.o=%.c)


include ../Makefile.cmd
include ../../Makefile.psm

ROOTBIN= $(ROOT)/platform/sun4u/sbin
ROOTPROG= $(ROOTBIN)/$(PROG)
POFILE= wrsmconf_cmd.po
POFILES= wrsmconf.po mkconfig.po

INS.root.sys = install -s -m 755 -f
$(CH)INS.root.sys = install -s -m 755 -u root -g sys -f
INSLINKTARGET=	$(INIT_PROG)


CPPFLAGS	+= -I$(USR_PSM_INCL_DIR)
LDFLAGS		+= -L$(ROOT)/platform/sun4u/lib -R/platform/sun4u/lib
LDLIBS		+= -lwrsmconf

.KEEP_STATE:

all: $(ROOTFS_PROG)

install: all $(ROOTPROG) $(INIT_PROG) $(ROOTRCS_SLINK) $(ROOTRCS_KLINK) $(DATA_D)


$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(DATA_D):
	$(INS.dir.root.sys)

$(ROOTBIN):
	$(INS.dir.root.sys)

$(INIT_D):
	$(INS.dir.root.sys)

$(ROOTRCS_D):
	$(INS.dir.root.sys)

$(ROOTRCS_SLINK): $(INIT_PROG) $(ROOTRCS_D)
	$(INS.link)

$(ROOTRCS_KLINK): $(INIT_PROG) $(ROOTRCS_D)
	$(INS.link)

$(INIT_PROG): $(INIT_D) $(SCRIPT)
	$(INS.root.sys) $(INIT_D) $(SCRIPT)

$(ROOTPROG): $(ROOTBIN) $(PROG)
	$(INS.root.sys) $(ROOTBIN) $(PROG)

clean:
	$(RM) $(OBJS)

lint: $(MACH)_lint

i386_lint:

sparc_lint:
	$(LINT.c) -u $(SRCS) $(LDLIBS.cmd)

$(POFILE):      $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@

include ../Makefile.targ
