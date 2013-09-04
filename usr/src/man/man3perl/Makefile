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

MANSECT=	3perl

MANFILES=	Exacct.3perl			\
	 	Exacct\:\:Catalog.3perl		\
	 	Exacct\:\:File.3perl		\
	 	Exacct\:\:Object.3perl		\
	 	Exacct\:\:Object\:\:Group.3perl \
	 	Exacct\:\:Object\:\:Item.3perl	\
	 	Kstat.3perl			\
	 	Lgrp.3perl			\
	 	Privilege.3perl			\
	 	Project.3perl			\
	 	Task.3perl			\
	 	Ucred.3perl

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

#
# When KEEP_STATE is in effect and a target has a colon in the name (like the
# Exacct::* pages above, dmake will write them to the state file unescaped,
# creating a file which then cannot be reparsed, breaking any build other than
# the first in this directory:
#
# See CR 6987108 make will write un-escaped :'s to .make.state, break itself
#
# As a workaround, install the files manually in a FRC target.
CMD= $(INS) -s -m $(FILEMODE) -f $(ROOTMAN)/man$(MANSECT)
install: FRC
	@for file in $(MANFILES); do					\
		if [[ $$file -nt $(ROOTMAN)/man$(MANSECT)/$$file ]]; then \
			$(ECHO) $(CMD) $$file;				\
			$(RM) $(ROOTMAN)/man$(MANSECT)/$$file;		\
			$(CMD) $$file;					\
		fi							\
	done;
