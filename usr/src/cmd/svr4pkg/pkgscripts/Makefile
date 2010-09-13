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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		cmdexec

OBJS=		cmdexec.o
SRCS=           $(OBJS:.o=.c)

CLASS_ACTION_SCRIPTS =  i.awk		\
			i.build		\
			i.CompCpio	\
			i.preserve	\
			i.sed		\
			r.awk		\
			r.build		\
			r.sed
ADMINFILE =		default

ROOTPKGMNFSTDIR=$(ROOT)/lib/svc/manifest/system
ROOTPKGMNFST=   $(ROOTPKGMNFSTDIR)/pkgserv.xml

$(ROOTPKGMNFST) := FILEMODE = 0444

# cmdexec also installed in usr/sadm/install/scripts
SCRIPTS = $(CLASS_ACTION_SCRIPTS) $(PROG)

include $(SRC)/cmd/svr4pkg/Makefile.svr4pkg
CLOBBERFILES += $(CLASS_ACTION_SCRIPTS)

ROOTLINKS=	$(ROOTCLASS_SCR_DIR)/i.CONFIG.prsv
PRESRV=		$(ROOTCLASS_SCR_DIR)/i.preserve

LDLIBS  +=      -lpkg

.KEEP_STATE:

all:	$(PROG) $(CLASS_ACTION_SCRIPTS)

install: all $(ROOTCLASS_SCR_FILES) $(ROOTADMIN_SRC_FILE) \
	$(ROOTPKGMNFST) $(ROOTLINKS)

$(ROOTLINKS): $(ROOTCLASS_SCR_FILES)
	$(RM) $@
	$(LN) $(PRESRV) $@

include $(SRC)/cmd/svr4pkg/Makefile.svr4pkg.targ
