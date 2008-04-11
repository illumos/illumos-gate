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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.com

DATAFILES += \
	i.cronroot	\
	i.definit	\
	i.defkbd	\
	i.deflogin	\
	i.defpasswd	\
	i.defsu		\
	i.dhcpinittab	\
	i.etcprofile	\
	i.etcremote	\
	i.etcrpc	\
	i.fstypes	\
	i.group		\
	i.hosts		\
	i.inetdconf	\
	i.initd		\
	i.inittab	\
	i.kmfconfbase   \
	i.locallogin	\
	i.localprofile	\
	i.logadmconf	\
	i.logindevperm	\
	i.mailxrc	\
	i.manifest	\
	r.manifest	\
	i.netconfig	\
	i.nscd		\
	i.nsswitch	\
	i.pamconf	\
	i.passwd	\
	i.pkcs11confbase \
	i.policyconf	\
	i.preserve	\
	i.rbac		\
	r.rbac		\
	i.renamenew	\
	i.renameold	\
	i.seedmanifest	\
	i.services	\
	i.shadow	\
	i.syslogconf	\
	i.tiservices	\
	i.ttydefs	\
	i.ttysrch	\
	i.vfstab

LICENSEFILES += \
	../../cmd/cmd-inet/sbin/ifparse/THIRDPARTYLICENSE \
	../../cmd/cmd-inet/usr.sbin/THIRDPARTYLICENSE.route \
	../../cmd/cmd-inet/usr.sbin/ifconfig/THIRDPARTYLICENSE

CHKINSTALLSRC=checkinstall.initd

.KEEP_STATE:

all: $(FILES) preinstall postinstall
install: all pkg

include ../Makefile.targ
