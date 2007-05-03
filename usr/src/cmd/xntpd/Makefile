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
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.cmd

SUBDIRS=libntp libparse xntpd ntpq ntpdate ntptrace xntpdc etc.inet

all :=		TARGET=all
install :=	TARGET=install
clobber :=	TARGET=clobber
clean :=	TARGET=clean
lint :=		TARGET=lint

all clobber clean lint:	$(SUBDIRS)

all:	THIRDPARTYLICENSE

install:	all $(SUBDIRS)

clobber:	FRC
	$(RM) THIRDPARTYLICENSE

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)

install_h check _msg _dc:

FRC:

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) Makefile+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< libntp/authdes.c >libntp/authdes.c+
	$(MV) libntp/authdes.c+ libntp/authdes.c
	sed -e "/^EXPORT_SRC:/,/^$$/d" < Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile libntp/authdes.c

# EXPORT DELETE END

THIRDPARTYLICENSE: COPYRIGHT
	$(SED) -n '/David L. Mills/,/implied warranty/p' COPYRIGHT > $@
