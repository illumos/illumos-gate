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

MANSECT = 	3fstyp

MANFILES = 	fstyp_get_attr.3fstyp	\
		fstyp_ident.3fstyp	\
		fstyp_init.3fstyp	\
		fstyp_mod_init.3fstyp	\
		fstyp_strerror.3fstyp

MANSOFILES =	fstyp_fini.3fstyp		\
	 	fstyp_mod_dump.3fstyp		\
	 	fstyp_mod_fini.3fstyp		\
	 	fstyp_mod_get_attr.3fstyp	\
	 	fstyp_mod_ident.3fstyp

MANFILES +=	$(MANSOFILES)

fstyp_fini.3fstyp		:= SOSRC = man3fstyp/fstyp_init.3fstyp

fstyp_mod_dump.3fstyp		:= SOSRC = man3fstyp/fstyp_mod_init.3fstyp
fstyp_mod_fini.3fstyp		:= SOSRC = man3fstyp/fstyp_mod_init.3fstyp
fstyp_mod_get_attr.3fstyp	:= SOSRC = man3fstyp/fstyp_mod_init.3fstyp
fstyp_mod_ident.3fstyp		:= SOSRC = man3fstyp/fstyp_mod_init.3fstyp

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)


