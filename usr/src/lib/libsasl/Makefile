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
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
#

include	../Makefile.lib

HDRS=		sasl.h		saslplug.h	saslutil.h	prop.h
HDRDIR=		include
ROOTHDRDIR=	$(ROOT)/usr/include/sasl

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

LIBRARY=        libsasl.a
POFILE=         $(LIBRARY:.a=.po)
MSGFILES=	lib/canonusr.c lib/checkpw.c lib/client.c lib/common.c \
			lib/external.c lib/server.c lib/seterror.c \
			plugin/plugin_common.c \
			$(SRC)/lib/sasl_plugins/cram/cram.c \
			$(SRC)/lib/sasl_plugins/digestmd5/digestmd5.c \
			$(SRC)/lib/sasl_plugins/gssapi/gssapi.c \
			$(SRC)/lib/sasl_plugins/login/login.c \
			$(SRC)/lib/sasl_plugins/plain/plain.c

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

all install: THIRDPARTYLICENSE

install_h:	$(ROOTHDRS)

check:	$(CHECKHDRS)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

include $(SRC)/Makefile.msg.targ

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

THIRDPARTYLICENSE: LICENSE.txt
	$(SED) -n '/Carnegie Mellon/,$$p' LICENSE.txt > $@

CLOBBERFILES += THIRDPARTYLICENSE

include ../Makefile.targ

.PARALLEL: $(SUBDIRS)
