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
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2025 Peter Tribble
#

include		$(SRC)/Makefile.master

MANSECT=	9e

MANFILES=	Intro.9e				\
		_fini.9e				\
		aread.9e				\
		attach.9e				\
		awrite.9e				\
		chpoll.9e				\
		close.9e				\
		csx_event_handler.9e			\
		detach.9e				\
		ddi_ufm.9e				\
		devmap.9e				\
		devmap_access.9e			\
		devmap_contextmgt.9e			\
		devmap_dup.9e				\
		devmap_map.9e				\
		devmap_unmap.9e				\
		dump.9e					\
		getinfo.9e				\
		gld.9e					\
		identify.9e				\
		ioctl.9e				\
		ksensor.9e				\
		ksensor_ops.9e				\
		ks_snapshot.9e				\
		ks_update.9e				\
		mac.9e					\
		mac_capab_transceiver.9e		\
		mac_capab_led.9e			\
		mac_capab_rings.9e			\
		mac_filter.9e				\
		mc_getcapab.9e				\
		mc_getprop.9e				\
		mc_getstat.9e				\
		mc_ioctl.9e				\
		mc_multicst.9e				\
		mc_open.9e				\
		mc_propinfo.9e				\
		mc_setpromisc.9e			\
		mc_setprop.9e				\
		mc_start.9e				\
		mc_tx.9e				\
		mc_unicst.9e				\
		mgi_start.9e				\
		mi_enable.9e				\
		mr_gget.9e				\
		mr_rget.9e				\
		mri_poll.9e				\
		mri_stat.9e				\
		mmap.9e					\
		open.9e					\
		power.9e				\
		print.9e				\
		probe.9e				\
		prop_op.9e				\
		put.9e					\
		quiesce.9e				\
		read.9e					\
		segmap.9e				\
		srv.9e					\
		strategy.9e				\
		tran_abort.9e				\
		tran_bus_reset.9e			\
		tran_dmafree.9e				\
		tran_getcap.9e				\
		tran_init_pkt.9e			\
		tran_quiesce.9e				\
		tran_reset.9e				\
		tran_reset_notify.9e			\
		tran_setup_pkt.9e			\
		tran_start.9e				\
		tran_sync_pkt.9e			\
		tran_tgt_free.9e			\
		tran_tgt_init.9e			\
		tran_tgt_probe.9e			\
		usba_hcdi_cb_ops.9e			\
		usba_hcdi_device_address.9e		\
		usba_hcdi_device_init.9e		\
		usba_hcdi_hub_update.9e			\
		usba_hcdi_pipe_bulk_xfer.9e		\
		usba_hcdi_pipe_ctrl_xfer.9e		\
		usba_hcdi_pipe_intr_xfer.9e		\
		usba_hcdi_pipe_isoc_xfer.9e		\
		usba_hcdi_pipe_open.9e			\
		usba_hcdi_pipe_reset.9e			\
		usba_hcdi_pipe_stop_intr_polling.9e	\
		usba_hcdi.9e				\
		write.9e

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
