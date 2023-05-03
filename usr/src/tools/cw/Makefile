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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2018 Joyent, Inc.

PROG	= cw

MAN1ONBLDFILES=	cw.1onbld

include ../Makefile.tools

# Bootstrap problem -- we have to build cw before we can use it
i386_CC=	$(GNUC_ROOT)/bin/gcc
sparc_CC=	$(GNUC_ROOT)/bin/gcc

CFLAGS += $(CCVERBOSE)

# Override CFLAGS.  This is needed only for bootstrap of cw.
CFLAGS=	-O -D__sun -Wall -Werror -std=gnu99 -nodefaultlibs
LDLIBS +=	-Wl,-zassert-deflib=libc.so -lc
LDFLAGS=	$(MAPFILE.NES:%=-Wl,-M%)
ZASSERTDEFLIB = -Wl,-zassert-deflib
ZFATALWARNINGS = -Wl,-zfatal-warnings
ZGUIDANCE = -Wl,-zguidance
LDFLAGS += -Wl,$(ZDIRECT)

$(ROOTONBLDMAN1ONBLDFILES) := FILEMODE=      644
CSTD=	$(CSTD_GNU99)

# Assume we don't have the install.bin available yet
INS.file=	$(RM) $@; $(CP) $< $(@D); $(CHMOD) $(FILEMODE) $@

.KEEP_STATE:

all: $(PROG) $(MAN1ONBLDFILES)

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDMAN1ONBLDFILES)

clean:

#
# Not run by default: bootstrap...
check:
	$(ROOTONBLDBINMACH)/mandoc -Tlint -Wwarning $(MAN1ONBLDFILES)

include ../Makefile.targ
