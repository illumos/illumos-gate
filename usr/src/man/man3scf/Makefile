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
# Copyright 2020 Joyent, Inc.
#

include		$(SRC)/Makefile.master

MANSECT=	3scf

MANFILES=	scf_entry_create.3scf		\
		scf_error.3scf			\
		scf_handle_create.3scf		\
		scf_handle_decode_fmri.3scf	\
		scf_instance_create.3scf	\
		scf_iter_create.3scf		\
		scf_limit.3scf			\
		scf_pg_create.3scf		\
		scf_property_create.3scf	\
		scf_scope_create.3scf		\
		scf_service_create.3scf		\
		scf_simple_prop_get.3scf	\
		scf_simple_walk_instances.3scf	\
		scf_snaplevel_create.3scf	\
		scf_snapshot_create.3scf	\
		scf_tmpl_pg_create.3scf		\
		scf_tmpl_pg_name.3scf		\
		scf_tmpl_prop_create.3scf	\
		scf_tmpl_prop_name.3scf		\
		scf_tmpl_validate_fmri.3scf	\
		scf_transaction_create.3scf	\
		scf_value_create.3scf		\
		smf_enable_instance.3scf

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
