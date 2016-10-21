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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#

include		$(SRC)/Makefile.master

MANSECT= 	9s

MANFILES= 	Intro.9s			\
	 	aio_req.9s			\
	 	buf.9s				\
	 	cb_ops.9s			\
	 	copyreq.9s			\
	 	copyresp.9s			\
	 	datab.9s			\
	 	ddi_device_acc_attr.9s		\
	 	ddi_dma_attr.9s			\
	 	ddi_dma_cookie.9s		\
	 	ddi_dmae_req.9s			\
	 	ddi_fm_error.9s			\
	 	ddi_idevice_cookie.9s		\
	 	dev_ops.9s			\
	 	devmap_callback_ctl.9s		\
	 	fmodsw.9s			\
	 	free_rtn.9s			\
	 	gld_mac_info.9s			\
	 	gld_stats.9s			\
	 	hook_nic_event.9s		\
	 	hook_pkt_event.9s		\
	 	hook_t.9s			\
	 	iocblk.9s			\
	 	iovec.9s			\
	 	kstat.9s			\
	 	kstat_intr.9s			\
	 	kstat_io.9s			\
	 	kstat_named.9s			\
	 	linkblk.9s			\
		mac_callbacks.9s		\
		mac_register.9s			\
	 	modldrv.9s			\
	 	modlinkage.9s			\
	 	modlmisc.9s			\
	 	modlstrmod.9s			\
	 	module_info.9s			\
	 	msgb.9s				\
	 	net_inject_t.9s			\
	 	net_instance_t.9s		\
	 	qband.9s			\
	 	qinit.9s			\
	 	queclass.9s			\
	 	queue.9s			\
	 	scsi_address.9s			\
	 	scsi_arq_status.9s		\
	 	scsi_asc_key_strings.9s		\
	 	scsi_device.9s			\
	 	scsi_extended_sense.9s		\
	 	scsi_hba_tran.9s		\
	 	scsi_inquiry.9s			\
	 	scsi_pkt.9s			\
	 	scsi_status.9s			\
	 	streamtab.9s			\
	 	stroptions.9s			\
	 	tuple.9s			\
	 	uio.9s				\
	 	usb_bulk_request.9s		\
	 	usb_callback_flags.9s		\
	 	usb_cfg_descr.9s		\
	 	usb_client_dev_data.9s		\
	 	usb_completion_reason.9s	\
	 	usb_ctrl_request.9s		\
	 	usb_dev_descr.9s		\
	 	usb_dev_qlf_descr.9s		\
	 	usb_ep_descr.9s			\
	 	usb_if_descr.9s			\
	 	usb_intr_request.9s		\
	 	usb_isoc_request.9s		\
	 	usb_other_speed_cfg_descr.9s	\
	 	usb_request_attributes.9s	\
	 	usb_string_descr.9s

MANLINKS=	dblk.9s			\
		intro.9s		\
		mac_callbacks_t.9s	\
		mac_register_t.9s	\
		mblk.9s

intro.9s		:= LINKSRC = Intro.9s

dblk.9s			:= LINKSRC = datab.9s

mac_callbacks_t.9s	:= LINKSRC = mac_callbacks.9s
mac_register_t.9s	:= LINKSRC = mac_register.9s

mblk.9s			:= LINKSRC = msgb.9s

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
