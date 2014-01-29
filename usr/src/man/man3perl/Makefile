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
# Copyright (c) 2014 Racktop Systems.
#

include		$(SRC)/Makefile.master

MANSECT=	3perl

MANFILES=	Kstat.3perl			\
	 	Lgrp.3perl			\
	 	Project.3perl			\
	 	Task.3perl

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install: $(ROOTMANFILES) $(ROOTMANLINKS)
