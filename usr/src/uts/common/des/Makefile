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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1989,1999 by Sun Microsystems, Inc.
# All rights reserved.
#
# uts/common/des/Makefile
#
# include global definitions
include ../../../Makefile.master

HDRS=	des.h		desdata.h	softdes.h

ROOTDIRS= $(ROOT)/usr/include/des

ROOTHDRS= $(HDRS:%=$(ROOTDIRS)/%)

CHECKHDRS= $(HDRS:%.h=%.check)

# install rule
$(ROOTDIRS)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIRS) $(ROOTHDRS)

$(ROOTDIRS):
	$(INS.dir)

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) Makefile+ des_crypt.c+ des_soft.c+ desdata.h+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< des_crypt.c > des_crypt.c+
	$(MV) des_crypt.c+ des_crypt.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< des_soft.c > des_soft.c+
	$(MV) des_soft.c+ des_soft.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< desdata.h > desdata.h+
	$(MV) desdata.h+ desdata.h
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(RM) Makefile
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile des_crypt.c des_soft.c desdata.h

# EXPORT DELETE END
check:	$(CHECKHDRS)
