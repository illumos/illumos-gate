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

include		../Makefile.cmd

# libopenbsd-compat and libssh are used by all SSH binaries, and sftp-server is
# also used as an internal part of sshd.
SUBDIRS= \
	etc \
	libopenbsd-compat \
	libssh \
	sftp-server \
	.WAIT \
	ssh \
	sshd \
	scp \
	ssh-add \
	ssh-agent \
	ssh-keygen \
	ssh-keysign \
	ssh-keyscan \
	sftp \
	ssh-http-proxy-connect \
	ssh-socks5-proxy-connect

MSGFILE=ssh.po
POFILE=_messages.po

CLOBBERFILES += $(MSGFILE) THIRDPARTYLICENSE

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

all clean install lint $(POFILE): $(SUBDIRS)
clobber: $(SUBDIRS) clobber_local
clobber_local:
	$(RM) $(CLOBBERFILES)

all install: THIRDPARTYLICENSE

check: $(CHECKHDRS)

# See Makefile.msg.targ for $(MSGFILE) update instructions
_msg:
	$(RM) $(POFILE)
	$(TOUCH) $(POFILE)
	$(MAKE) $(POFILE) XGETTEXT=/usr/bin/gxgettext
	$(CP) $(POFILE) $(MSGFILE)
	$(CP) $(MSGFILE) $(MSGDOMAIN)

$(SUBDIRS):     FRC
	cd $@; pwd; $(MAKE) $(TARGET)

# skip the summary; just include the actual license clauses.
THIRDPARTYLICENSE: doc/LICENCE
	$(SED) -n '/1)/,$$p' doc/LICENCE > $@

FRC:
