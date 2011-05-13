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

# Copyright 2011, Richard Lowe

include ../../Makefile.master

MANSECT = 	3gen

MANFILES = 	bgets.3gen	\
	 	bufsplit.3gen	\
	 	copylist.3gen	\
	 	gmatch.3gen	\
	 	isencrypt.3gen	\
	 	mkdirp.3gen	\
	 	p2open.3gen	\
	 	pathfind.3gen	\
	 	regexpr.3gen	\
	 	strccpy.3gen	\
	 	strfind.3gen

MANSOFILES =	advance.3gen	\
		compile.3gen	\
		p2close.3gen	\
		rmdirp.3gen	\
		step.3gen	\
		str.3gen	\
		strcadd.3gen	\
		streadd.3gen	\
		strecpy.3gen	\
		strrspn.3gen	\
		strtrns.3gen

MANFILES +=	$(MANSOFILES)

rmdirp.3gen	:= SOSRC = man3gen/mkdirp.3gen

p2close.3gen	:= SOSRC = man3gen/p2open.3gen

advance.3gen	:= SOSRC = man3gen/regexpr.3gen
compile.3gen	:= SOSRC = man3gen/regexpr.3gen
step.3gen	:= SOSRC = man3gen/regexpr.3gen

strcadd.3gen	:= SOSRC = man3gen/strccpy.3gen
streadd.3gen	:= SOSRC = man3gen/strccpy.3gen
strecpy.3gen	:= SOSRC = man3gen/strccpy.3gen

str.3gen	:= SOSRC = man3gen/strfind.3gen
strrspn.3gen	:= SOSRC = man3gen/strfind.3gen
strtrns.3gen	:= SOSRC = man3gen/strfind.3gen


.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)


