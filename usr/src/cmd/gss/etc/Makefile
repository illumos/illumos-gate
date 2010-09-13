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

include ../../Makefile.cmd

TXTS=
GSSTXTS= mech qop gsscred.conf
KRB5TXTS= warn.conf krb5.conf kdc.conf kpropd.acl kadm5.acl

IETCFILES=			$(TXTS:%=$(ROOTETC)/%)
IETCGSSFILES=			$(GSSTXTS:%=$(ROOTETC)/gss/%)
IETCKRB5FILES=			$(KRB5TXTS:%=$(ROOTETC)/krb5/%)
GSSDIR=				$(ROOTETC)/gss
KRB5DIR=			$(ROOTETC)/krb5

FILEMODE= 0644

.KEEP_STATE:

all: $(TXTS) $(GSSTXTS) dummy_mech_token.conf

dummy_mech_token.conf:	dummy_mech_token.conf.sh
			$(RM) $@
			sh dummy_mech_token.conf.sh

install: all $(GSSDIR) $(KRB5DIR) $(IETCFILES) $(IETCGSSFILES) $(IETCKRB5FILES)

install_h:

$(GSSDIR):
	$(INS.dir)

$(KRB5DIR):
	$(INS.dir)

$(ROOTETC)/%: %
	$(INS.file)

$(ROOTETC)/gss/%: %
	$(INS.file)

$(ROOTETC)/krb5/%: %
	$(INS.file)

FRC:

include ../../Makefile.targ

CLOBBERFILES += dummy_mech_token.conf

clean lint:
