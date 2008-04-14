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
# ident	"%Z%%M%	%I%	%E% SMI"
#

.DEFAULT:

include ../Makefile.inc
include ../../Makefile.cmd

PROG       = fpsd 
PROGBIN    = $(OBJ_DIR)/fpsd

MANIFEST = $(PROG).xml
ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

DBX     = -O

CUR_DIR:sh = /bin/pwd

CFLAGS  += -I../include -I../../../head -I$(ROOT)/usr/include -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS

DLIBS	= -ldevinfo

SRCS = fpsd_main.c fpsd_sched.c fpsd_util.c fpsd_esutil.c fpsd_log.c

OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)

POFILE = $(PROG)_msg.po
POFILES = $(SRCS:%.c=%.po)

LINTFLAGS += $(INC_SPEC) -I../include -I../../../head -I$(ROOT)/usr/include -D_sparc64 -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -Dunix -asxumn

.KEEP_STATE:

##### beginning of dependency lines #####

./fpsd  : $$(OBJS) $(MESSAGE)
	(unset LD_LIBRARY_PATH LD_RUN_PATH; \
	$(CC) -i $(CFLAGS) -L$(HCK_LIBDIR) -o $@ $(OBJS) -lc -mt -zignore -ldoor -ldevinfo -lkstat -lscf -lgen $(LDFLAGS))
	$(POST_PROCESS)
all: install
install  : $$(PROGBIN)
	install -d $(INSTBINDIR)
	$(RM) $(INSTBINDIR)/$(PROGBIN)
	install -f $(INSTBINDIR) -m 755 $(PROGBIN)
	install -d $(ROOTMANIFESTDIR)
	$(RM) $(ROOTMANIFESTDIR)/$(MANIFEST)
	install -m 755 -f $(ROOTMANIFESTDIR) $(MANIFEST)

$(POFILE):  $(POFILES) FRC
	@$(RM) $@
	$(CAT) $(POFILES) > $@

clean: FRC
	rm -f *.o *.ln .make.state
	rm -f *.po
clobber: clean
	rm -rf $(PROG)
lint : FRC
	$(LINT) $(LINTFLAGS) $(SRCS)

FRC:
