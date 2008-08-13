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
# cmd/fwflash/Makefile.com
#
#

# common rules for $SRC/cmd/fwflash

CLOSED=			$(SRC)/../closed

ROOTLIB=                $(ROOT)/usr/lib
ROOTLIBFWFLASH=         $(ROOTLIB)/fwflash
ROOTLIBFWFLASHPLUGINS=  $(ROOTLIBFWFLASH)/identify
ROOTLIBFWFLASHVERIFY=   $(ROOTLIBFWFLASH)/verify
ROOTUSR=                $(ROOT)/usr
ROOTUSRINCLUDE=         $(ROOTUSR)/include
ROOTUSRINCLUDEFWFLASH=  $(ROOTUSRINCLUDE)/fwflash
ROOTUSRSBIN=		$(ROOT)/usr/sbin



$(ROOTLIB):
	$(INS.dir)

$(ROOTLIBFWFLASH):	$(ROOTLIB)
	$(INS.dir)

$(ROOTLIBFWFLASH)/%:	$(ROOTLIB) %
	$(INS.dir)

$(ROOTLIBFWFLASHPLUGINS): $(ROOTLIBFWFLASH)
	$(INS.dir)

$(ROOTLIBFWFLASHPLUGINS)/%: $(ROOTLIBFWFLASHPLUGINS) %
	$(INS.file)

$(ROOTLIBFWFLASHVERIFY): $(ROOTLIBFWFLASH)
	$(INS.dir)

$(ROOTLIBFWFLASHVERIFY)/%: $(ROOTLIBFWFLASHVERIFY) %
	$(INS.file)

$(ROOTUSR):
	$(INS.dir)

$(ROOTUSRINCLUDE):	$(ROOTUSR)
	$(INS.dir)

$(ROOTUSRINCLUDEFWFLASH):
	$(INS.dir)

$(ROOTUSRINCLUDEFWFLASH)/%: $(ROOTUSRINCLUDEFWFLASH) %
	$(INS.file)

$(ROOTUSRSBIN):		$(ROOTUSR)
	$(INS.dir)

$(ROOTUSRSBIN)/%:	%
	$(INS.file)

BUILD.SO=  $(CC) -o $@ $(GSHARED) $(DYNFLAGS) $(PICS) $(LDLIBS)
POST_PROCESS_O += ; $(CTFCONVERT_POST)
POST_PROCESS_SO += ; $(CTFMERGE_POST)

LINTFLAGS += -D_POSIX_PTHREAD_SEMANTICS -erroff=E_CONSTANT_CONDITION \
	-erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
