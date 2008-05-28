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
# 
# cmd/fwflash/plugins/transport/i386
#

SRCS=		ses.c

OBJECTS= 	$(SRCS:%.c=%.o)
PLUGINS= 	$(SRCS:%.c=%.so)
POFILES=	ses.po
IDENTPOFILE= 	fwflash_transport_identify_ses.po
LINTFILE=	ses.ln

CLEANFILES=	$(OBJECTS)
CLOBBERFILES=	$(PLUGINS) $(POFILES) $(IDENTPOFILE) $(LINTFILE)



all:		$(PLUGINS)
_msg msg:	$(IDENTPOFILE)


include $(SRC)/Makefile.master
include $(SRC)/cmd/fwflash/Makefile.com

CFLAGS  += -g -D_POSIX_PTHREAD_SEMANTICS
DYNFLAGS += -Bdynamic
LDLIBS	+= -L$(ROOT)/usr/lib/scsi -ldevinfo -lumem -lc -lscsi -lses
LDFLAGS += -R/usr/lib/scsi

BUILD.SO=	$(LD) -o $@ -G $(DYNFLAGS) $(LDFLAGS) $(LDLIBS)

$(PLUGINS) :=	FILEMODE = 0555


install: $(ROOTLIBFWFLASHPLUGINS) \
	$(ROOTLIBFWFLASHPLUGINS)/ses.so

clobber clean:
	$(RM) $(CLEANFILES) $(CLOBBERFILES)

lint:	lint_SRCS

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.so: %.o
	$(BUILD.SO) $<


#
# Message catalog
#
$(POFILES): ../common/$(SRCS)
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) \
	    `($(GREP) -l gettext ../common/ses.c || echo /dev/null)`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(IDENTPOFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

lint_SRCS: ../common/$(SRCS:%.c=%.ln)

msg:	$(IDENTPOFILE)
