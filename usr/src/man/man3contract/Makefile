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

MANSECT=	3contract

MANFILES=	ct_ctl_adopt.3contract			\
		ct_dev_status_get_dev_state.3contract	\
		ct_dev_tmpl_set_aset.3contract		\
		ct_event_read.3contract			\
		ct_pr_event_get_pid.3contract		\
		ct_pr_status_get_param.3contract	\
		ct_pr_tmpl_set_transfer.3contract	\
		ct_status_read.3contract		\
		ct_tmpl_activate.3contract

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
