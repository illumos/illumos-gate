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
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# Copyright (c) 2018, Joyent, Inc.

CFLAGS += v

PROG= ctags
XPG4PROG= ctags
OTHERPROGS= fold cxref
SRCS= $(PROG).c fold.c mkstr.c xstr.c
TXTS= READ_ME del.h.cb mkstr.c xstr.c
#
# For message catalogue file
#
POFILES= $(SRCS:%.c=%.po)

include ../../Makefile.cmd
$(XPG4) := CFLAGS += -DXPG4

CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-variable

# way too old
SMATCH=off

POFILE= misc.po

CLOBBERFILES += $(OTHERPROGS)

.KEEP_STATE:

all: $(PROG) $(XPG4) $(OTHERPROGS)

catalog: $(POFILE)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $(POFILE)


install: all $(ROOTPROG) $(ROOTXPG4PROG)

clean:

lint:	lint_SRCS

include ../../Makefile.targ
