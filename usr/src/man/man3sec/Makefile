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

MANSECT = 	3sec

MANFILES = 	acl_check.3sec		\
	 	acl_free.3sec		\
	 	acl_get.3sec		\
	 	acl_strip.3sec		\
	 	acl_totext.3sec		\
	 	acl_trivial.3sec	\
	 	aclcheck.3sec		\
	 	aclsort.3sec		\
	 	acltomode.3sec		\
	 	acltotext.3sec

MANSOFILES =	acl_fromtext.3sec	\
		acl_set.3sec		\
		aclfrommode.3sec	\
		aclfromtext.3sec	\
		facl_get.3sec		\
		facl_set.3sec

MANFILES +=	$(MANSOFILES)

acl_set.3sec		:= SOSRC = man3sec/acl_get.3sec
facl_get.3sec		:= SOSRC = man3sec/acl_get.3sec
facl_set.3sec		:= SOSRC = man3sec/acl_get.3sec

acl_fromtext.3sec	:= SOSRC = man3sec/acl_totext.3sec

aclfrommode.3sec	:= SOSRC = man3sec/acltomode.3sec

aclfromtext.3sec	:= SOSRC = man3sec/acltotext.3sec

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)


