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
# cmd/fwflash/Makefile.com
#
#
# common rules for $SRC/cmd/fwflash

CERRWARN +=		-_gcc=-Wno-parentheses
CERRWARN +=		-_gcc=-Wno-uninitialized
CERRWARN +=		-_gcc=-Wno-address

ROOTUSR=                $(ROOT)/usr
ROOTUSRINCLD=		$(ROOTUSR)/include
ROOTUSRINCLDFWFLASH=	$(ROOTUSRINCLD)/fwflash
ROOTUSRLIB=             $(ROOTUSR)/lib
ROOTUSRLIBFWFLASH=	$(ROOTUSRLIB)/fwflash
ROOTUSRLIBFWFLASHIDF=	$(ROOTUSRLIBFWFLASH)/identify
ROOTUSRLIBFWFLASHVRF=   $(ROOTUSRLIBFWFLASH)/verify
ROOTUSRSBIN=		$(ROOTUSR)/sbin

$(ROOTUSR):
	$(INS.dir)

$(ROOTUSRINCLD):	$(ROOTUSR)
	$(INS.dir)

$(ROOTUSRINCLDFWFLASH):
	$(INS.dir)

$(ROOTUSRINCLDFWFLASH)/%: $(ROOTUSRINCLDFWFLASH) %
	$(INS.file)

$(ROOTUSRLIB):
	$(INS.dir)

$(ROOTUSRLIBFWFLASH):	$(ROOTUSRLIB)
	$(INS.dir)

$(ROOTUSRLIBFWFLASH)/%:	$(ROOTUSRLIB) %
	$(INS.dir)

$(ROOTUSRLIBFWFLASHIDF): $(ROOTUSRLIBFWFLASH)
	$(INS.dir)

$(ROOTUSRLIBFWFLASHIDF)/%: $(ROOTUSRLIBFWFLASHIDF) %
	$(INS.file)

$(ROOTUSRLIBFWFLASHVRF): $(ROOTUSRLIBFWFLASH)
	$(INS.dir)

$(ROOTUSRLIBFWFLASHVRF)/%: $(ROOTUSRLIBFWFLASHVRF) %
	$(INS.file)

$(ROOTUSRSBIN):		$(ROOTUSR)
	$(INS.dir)

$(ROOTUSRSBIN)/%:	%
	$(INS.file)



%.ln: $(SRCDIR)/%.c
	$(LINT.c) $(LINTFLAGS) -c $<

%.po: $(SRCDIR)/%.c
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) \
	    `($(GREP) -l gettext $< || echo /dev/null)`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) >$@		

LINTFLAGS += -D_POSIX_PTHREAD_SEMANTICS -erroff=E_CONSTANT_CONDITION \
	-erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
