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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/fwflash/plugins/sparc
#

SRCS=		tavor-MELLANOX.c hermon-MELLANOX.c
OBJECTS=	$(SRCS:%.c=%.o)
PLUGINS=	$(SRCS:%.c=%.so)
POFILES=	$(SRCS:%.c=%.po)
LINTFILE=	$(SRCS:%.c=%.ln)

VERIFYPOFILE=	fwflash_verify_msg.po

CLOBBERFILES=	$(PLUGINS) $(OBJECTS) $(LINTFILE) \
		$(POFILES) $(VERIFYPOFILE)
TEXT_DOMAIN= SUNW_OST_OSCMD

all:		$(PLUGINS)


include $(SRC)/Makefile.master
include $(SRC)/cmd/fwflash/Makefile.com


CFLAGS  += -g -D_POSIX_PTHREAD_SEMANTICS -I$(ROOT)/usr/include
MANUFACTURING_MODE=0
CFLAGS += -DMANUFACTURING_MODE=$(MANUFACTURING_MODE)
LDLIBS	+= -ldevinfo -lumem -lc
DYNFLAGS += -Bdynamic
LIBS=   $(DYNLIB)

BUILD.SO=	$(LD) -o $@ $(HERMON_LDFLAGS) -G $(DYNFLAGS)

hermon-MELLANOX.so := HERMON_LDFLAGS += -N/usr/lib/fwflash/identify/hermon.so

%.o: ../vendor/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.so: %.o
	$(BUILD.SO) $<
	$(POST_PROCESS)

%.ln: ../vendor/%.c
	$(LINT.c) $(LINTFLAGS) -c $<

%.po: ../vendor/%.c
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) \
	    `($(GREP) -l gettext $< || echo /dev/null)`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

#
# Message catalog
#

$(VERIFYPOFILE):	$(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: $(ROOTLIBFWFLASHVERIFY) \
	$(ROOTLIBFWFLASHVERIFY)/tavor-MELLANOX.so \
	$(ROOTLIBFWFLASHVERIFY)/hermon-MELLANOX.so

clean:
	$(RM) $(OBJECTS)

clobber: clean
	$(RM) $(CLOBBERFILES)

lint:		lint_SRCS
lint_SRCS:	$(LINTFILE)

_msg msg:	$(VERIFYPOFILE)
