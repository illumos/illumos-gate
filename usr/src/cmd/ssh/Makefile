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

include		../Makefile.cmd

SUBDIRS= \
	etc \
	libopenbsd-compat \
	libssh \
	.WAIT \
	ssh \
	sshd \
	scp \
	ssh-add \
	ssh-agent \
	ssh-keygen \
	ssh-keysign \
	ssh-keyscan \
	sftp-server \
	sftp \
	ssh-http-proxy-connect \
	ssh-socks5-proxy-connect

MSGFILE=ssh.po
POFILE=_messages.po

.KEEP_STATE:

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
delete :=       TARGET= delete
install :=      TARGET= install
lint :=         TARGET= lint
catalog :=      TARGET= catalog
package :=      TARGET= package
_msg :=		TARGET= _msg
$(POFILE) :=	TARGET= $(POFILE)

all clean clobber install lint $(POFILE): $(SUBDIRS)

clobber: FRC
	$(RM) THIRDPARTYLICENSE

all install: THIRDPARTYLICENSE

check: $(CHECKHDRS)

# See Makefile.msg.targ for $(MSGFILE) update instructions
_msg_manual:
	$(RM) $(POFILE)
	$(TOUCH) $(POFILE)
	$(MAKE) $(POFILE)
	$(SED) "/^domain/d" $(POFILE) > $(MSGFILE)

_msg:
	$(RM) $(MSGDOMAIN)/$(MSGFILE)
	@# Uncomment when /bin/xgettext gets GNU extensions
	@# See Makefile.msg.targ for $(MSGFILE) update instructions
	@#$(MAKE) _msg_manual
	$(CP) $(MSGFILE) $(MSGDOMAIN)

$(SUBDIRS):     FRC
	cd $@; pwd; $(MAKE) $(TARGET)

# skip the summary; just include the actual license clauses.
THIRDPARTYLICENSE: doc/LICENCE
	$(SED) -n '/1)/,$$p' doc/LICENCE > $@

FRC:
