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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

CPPFLAGS.sm=	$(CPPFLAGS.master) -DSOLARIS=2$(RELEASE_MINOR)00 \
		-D_FILE_OFFSET_BITS=64
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-empty-body
CERRWARN +=	-_gcc=-Wno-unused-variable
DBMDEF=		-DNDBM -DNEWDB -DNIS -DUSERDB -DMAP_REGEX -DLDAPMAP

ROOTLIBSMTPSM = $(ROOTLIB)/smtp/sendmail

$(ROOTLIBSMTPSM):
	$(INS.dir)

$(ROOTLIBSMTPSM)/%: $(ROOTLIBSMTPSM) %
	$(INS.file)
