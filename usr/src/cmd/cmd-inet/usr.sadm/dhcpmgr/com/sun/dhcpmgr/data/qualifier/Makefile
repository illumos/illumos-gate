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
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/cmd-inet/usr.sadm/dhcpmgr/com/sun/dhcpmgr/data/Makefile
#

CLASSFILES =	QualifierType.class \
		QualifierTypeImpl.class \
		Qualifier.class \
		QualifierEnum.class \
		QualifierRange.class \
		QualifierImpl.class \
		QualifierBoolean.class \
		QualifierString.class \
		QualifierStringEnum.class \
		QualifierInteger.class \
		QualifierIntegerEnum.class \
		QualifierIntegerRange.class \
		QualifierArray.class \
		QualifierAnd.class \
		QualifierOr.class \
		QualifierFQDN.class \
		QualifierIPv4.class \
		QualifierIPv6.class

all     :=	TARGET= all
install :=	TARGET= install
clean   :=	TARGET= clean
clobber :=	TARGET= clobber
lint    :=	TARGET= lint
_msg    :=	TARGET= _msg

include		$(SRC)/Makefile.master

CLASSPATH=	$(SRC)/cmd/cmd-inet/usr.sadm/dhcpmgr

JAVAFILES =	$(CLASSFILES:.class=.java)

CLEANFILES=	*.class
CLOBBERFILES=

.KEEP_STATE:

all: $(CLASSFILES)

install: all

_msg:

lint:

clean:
	$(RM) $(CLEANFILES)

clobber: clean

