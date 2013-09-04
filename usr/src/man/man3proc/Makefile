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

MANSECT= 	3proc

MANFILES=	proc_service.3proc		\
	 	ps_lgetregs.3proc		\
	 	ps_pglobal_lookup.3proc		\
	 	ps_pread.3proc			\
	 	ps_pstop.3proc

MANLINKS=	ps_kill.3proc		\
		ps_lcontinue.3proc	\
		ps_lgetfpregs.3proc	\
		ps_lgetxregs.3proc	\
		ps_lgetxregsize.3proc	\
		ps_lrolltoaddr.3proc	\
		ps_lsetfpregs.3proc	\
		ps_lsetregs.3proc	\
		ps_lsetxregs.3proc	\
		ps_lstop.3proc		\
		ps_pcontinue.3proc	\
		ps_pdread.3proc		\
		ps_pdwrite.3proc	\
		ps_pglobal_sym.3proc	\
		ps_ptread.3proc		\
		ps_ptwrite.3proc	\
		ps_pwrite.3proc

ps_lgetfpregs.3proc	:= LINKSRC = ps_lgetregs.3proc
ps_lgetxregs.3proc	:= LINKSRC = ps_lgetregs.3proc
ps_lgetxregsize.3proc	:= LINKSRC = ps_lgetregs.3proc
ps_lsetfpregs.3proc	:= LINKSRC = ps_lgetregs.3proc
ps_lsetregs.3proc	:= LINKSRC = ps_lgetregs.3proc
ps_lsetxregs.3proc	:= LINKSRC = ps_lgetregs.3proc

ps_pglobal_sym.3proc	:= LINKSRC = ps_pglobal_lookup.3proc

ps_pdread.3proc		:= LINKSRC = ps_pread.3proc
ps_pdwrite.3proc	:= LINKSRC = ps_pread.3proc
ps_ptread.3proc		:= LINKSRC = ps_pread.3proc
ps_ptwrite.3proc	:= LINKSRC = ps_pread.3proc
ps_pwrite.3proc		:= LINKSRC = ps_pread.3proc

ps_kill.3proc		:= LINKSRC = ps_pstop.3proc
ps_lcontinue.3proc	:= LINKSRC = ps_pstop.3proc
ps_lrolltoaddr.3proc	:= LINKSRC = ps_pstop.3proc
ps_lstop.3proc		:= LINKSRC = ps_pstop.3proc
ps_pcontinue.3proc	:= LINKSRC = ps_pstop.3proc

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
