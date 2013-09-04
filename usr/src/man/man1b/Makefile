#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	 1b

MANFILES=	basename.1b	\
		biff.1b		\
		chown.1b	\
		df.1b		\
		du.1b		\
		echo.1b		\
		exportfs.1b	\
		expr.1b		\
		fastboot.1b	\
		file.1b		\
		from.1b		\
		groups.1b	\
		grpck.1b	\
		ln.1b		\
		logger.1b	\
		lpc.1b		\
		lpq.1b		\
		lpr.1b		\
		lprm.1b		\
		lptest.1b	\
		mail.1b		\
		mkstr.1b	\
		printenv.1b	\
		ps.1b		\
		rusage.1b	\
		shutdown.1b	\
		stty.1b		\
		sum.1b		\
		test.1b		\
		touch.1b	\
		tset.1b		\
		users.1b	\
		vipw.1b		\
		whereis.1b	\
		whoami.1b

MANLINKS=	Mail.1b		\
		fasthalt.1b	\
		reset.1b

Mail.1b		:= LINKSRC = mail.1b

fasthalt.1b	:= LINKSRC = fastboot.1b

reset.1b	:= LINKSRC = tset.1b

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
