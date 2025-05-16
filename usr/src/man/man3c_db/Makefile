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

MANSECT=	3c_db

MANFILES=	td_init.3c_db			\
		td_log.3c_db			\
		td_sync_get_info.3c_db		\
		td_ta_enable_stats.3c_db	\
		td_ta_event_addr.3c_db		\
		td_ta_get_nthreads.3c_db	\
		td_ta_map_addr2sync.3c_db	\
		td_ta_map_id2thr.3c_db		\
		td_ta_new.3c_db			\
		td_ta_setconcurrency.3c_db	\
		td_ta_sync_iter.3c_db		\
		td_thr_dbsuspend.3c_db		\
		td_thr_get_info.3c_db		\
		td_thr_getgregs.3c_db		\
		td_thr_lockowner.3c_db		\
		td_thr_setprio.3c_db		\
		td_thr_setsigpending.3c_db	\
		td_thr_sleepinfo.3c_db		\
		td_thr_tsd.3c_db		\
		td_thr_validate.3c_db

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
