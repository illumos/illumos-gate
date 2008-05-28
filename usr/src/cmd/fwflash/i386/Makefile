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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/fwflash/i386/Makefile
#
#


PROG=		fwflash
OBJS=		fwflash.o
SRCS=		fwflash.c
LINTFILE=	fwflash.ln


all:	$(PROG)
lint:	lint_SRCS

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include ../Makefile.com

$(ROOTUSRSBIN)/$(PROG) :=	FILEMODE = 0555

#
# Message catalog
#
POFILES= $(SRCS:%.c=%.po)
POFILE= fwflash_msg.po

CFLAGS	+= -g -D_POSIX_PTHREAD_SEMANTICS
LDLIBS += -ldevinfo -lumem

#
# Message catalog
#

$(POFILES): ../common/$(SRCS)
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) \
	    `($(GREP) -l gettext ../common/fwflash.c || echo /dev/null)`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@


clean:
	$(RM) $(PROG) $(OBJS)

clobber: clean
	$(RM) $(POFILE) $(POFILES) $(LINTFILE)

install_h:
	@cd ../common ; $(MAKE) install_h

$(PROG): install_h $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(COMMON_OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) $(CFLAGS) -o $@ $<

install: all $(ROOTUSRSBIN) $(ROOTUSRSBIN)/$(PROG)

lint_SRCS: ../common/$(SRCS:%.c=%.ln)

_msg msg:	$(POFILE)
