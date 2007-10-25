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

ETCFILES= ioctl.syscon passwd shadow motd
KVMFILES= README
SMBFILES= smbpasswd

include ../../Makefile.cmd

ROOTETCFILES= $(ETCFILES:%=$(ROOTETC)/%)
ROOTUSRKVMFILES= $(KVMFILES:%=$(ROOTUSRKVM)/%)
ROOTVARSMBFILES= $(SMBFILES:%=$(ROOTVARSMB)/%)

FILEMODE= 0644
OWNER= root
GROUP= sys

$(ROOTETC)/shadow :=	FILEMODE =	400
$(ROOTVARSMB)/smbpasswd :=	FILEMODE =	0400

.KEEP_STATE:

all: $(ETCFILES) $(KVMFILES) $(SMBFILES)

install: all $(ROOTETCFILES) $(ROOTUSRKVMFILES) $(ROOTVARSMBFILES)

clean:

lint:

clobber:

motd:	FRC
	@-$(ECHO) "rebuilding motd"
	@$(RELEASE_BUILD)-$(ECHO) "Sun Microsystems Inc.\tSunOS $(RELEASE)\t$(VERSION)\t$(RELEASE_DATE)" > motd
	@$(NOT_RELEASE_BUILD)-$(ECHO) "Sun Microsystems Inc.\tSunOS $(RELEASE)\t$(VERSION)\t`date +'%h. %d, %Y'`" > motd
	@$(NOT_RELEASE_BUILD)-$(ECHO) $(DEV_CM) | sed -e "s/@(#)//" >> motd
	@-$(CAT) release_info >> motd

smbpasswd:
	$(TOUCH) smbpasswd

clean:

lint:

clobber:
	$(RM) motd smbpasswd

FRC:
