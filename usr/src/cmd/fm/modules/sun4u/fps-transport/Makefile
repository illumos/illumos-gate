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

include ../../../../fps/Makefile.inc
include ../../../../Makefile.cmd

PROG       = fps-transport.so 
INSTBINDIR = $(ROOT)/usr/platform/sun4u/lib/fm/fmd/plugins
DBX     = -O

CFLAGS  += -I ../../../fmd/common -I. -Kpic

SRCS = fps-transport.c

OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)

LINTFLAGS = -I. -I ../../../fmd/common -D_sparc64 -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -Dunix -munx

.KEEP_STATE:

##### beginning of dependency lines #####

LDFLAGS += -M../../../fmd/common/fmd_api.map

fps-transport.so  : $$(OBJS)
	(unset LD_LIBRARY_PATH LD_RUN_PATH; \
	$(CC) -i $(CFLAGS) -o $@ -G $(OBJS) -mt -zignore -ztext -zdefs -lc -ldoor -lnvpair -lsysevent $(LDFLAGS))
	$(POST_PROCESS_SO)

all: install
install  : $(PROG) 
	install -d $(INSTBINDIR)
	$(RM) $(INSTBINDIR)/$(PROG)
	install -f $(INSTBINDIR) -m 555 $(PROG)

install_h: FRC

clean: FRC
	rm -f *.o *.ln .make.state

clobber: clean
	rm -rf $(PROG)

lint : FRC
	$(LINT) $(LINTFLAGS) $(SRCS)

FRC:
