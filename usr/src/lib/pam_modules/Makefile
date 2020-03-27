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
# Copyright 2014 Nexenta Systems, Inc.
#
# lib/pam_modules/Makefile
#

include $(SRC)/Makefile.master

SUBDIRS = \
	allow	\
	authtok_get	\
	authtok_check	\
	authtok_store	\
	deny		\
	dhkeys		\
	dial_auth	\
	krb5		\
	krb5_migrate	\
	ldap		\
	list		\
	passwd_auth	\
	rhosts_auth	\
	roles		\
	sample		\
	smb		\
	smbfs		\
	timestamp	\
	tsol_acct	\
	unix_auth	\
	unix_account	\
	unix_cred	\
	unix_session

all :=		TARGET= all
catalog :=	TARGET= _msg
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
_msg :=		TARGET= _msg

.KEEP_STATE:

all clean clobber install _msg: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
