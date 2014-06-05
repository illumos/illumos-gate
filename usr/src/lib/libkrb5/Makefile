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
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#

include		../Makefile.lib

SUBDIRS =	$(MACH) $(BUILD64) $(MACH64)

INSTALLED_HDRS = \
		com_err.h krb5.h locate_plugin.h
COMERRH =	$(SRC)/lib/gss_mechs/mech_krb5/include/com_err.h
LOCPLUGH =	$(SRC)/lib/gss_mechs/mech_krb5/include/locate_plugin.h
KRB5H =		$(SRC)/uts/common/gssapi/mechs/krb5/include/krb5.h

KRB5INCDIR= 	$(ROOT)/usr/include/kerberosv5

COMERRHINST =	$(KRB5INCDIR)/com_err.h
LOCPLUGHINST =	$(KRB5INCDIR)/locate_plugin.h
KRB5HINST =	$(KRB5INCDIR)/krb5.h

KRB5HDRS =	$(INSTALLED_HDRS:%=$(KRB5INCDIR)/%)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

lint check:

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

install_h:	$(KRB5INCDIR) $(KRB5HDRS)

$(COMERRHINST):	$(COMERRH)
	install -s -m 644 -f $(KRB5INCDIR) $(COMERRH)
$(KRB5HINST):	$(KRB5H)
	install -s -m 644 -f $(KRB5INCDIR) $(KRB5H)
$(LOCPLUGHINST): $(LOCPLUGH)
	install -s -m 644 -f $(KRB5INCDIR) $(LOCPLUGH)

FRC:
