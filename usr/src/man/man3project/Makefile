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

MANSECT= 	3project

MANFILES= 	getprojent.3project		\
	 	project_walk.3project		\
	 	setproject.3project


MANLINKS=	endprojent.3project		\
		fgetprojent.3project		\
		getdefaultproj.3project		\
		getprojbyid.3project		\
		getprojbyname.3project		\
		getprojidbyname.3project	\
		inproj.3project			\
		setprojent.3project

endprojent.3project		:= LINKSRC = getprojent.3project
fgetprojent.3project		:= LINKSRC = getprojent.3project
getdefaultproj.3project		:= LINKSRC = getprojent.3project
getprojbyid.3project		:= LINKSRC = getprojent.3project
getprojbyname.3project		:= LINKSRC = getprojent.3project
getprojidbyname.3project	:= LINKSRC = getprojent.3project
inproj.3project			:= LINKSRC = getprojent.3project
setprojent.3project		:= LINKSRC = getprojent.3project

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
