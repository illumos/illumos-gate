#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2014 Garrett D'Amore <garrett@damore>
# Copyright 2016 Joyent, Inc.
#

include		$(SRC)/Makefile.master

MANSECT= 	9f

MANFILES= 	ASSERT.9f				\
	 	Intro.9f				\
	 	OTHERQ.9f				\
	 	RD.9f					\
	 	SAMESTR.9f				\
	 	STRUCT_DECL.9f				\
	 	WR.9f					\
	 	adjmsg.9f				\
	 	allocb.9f				\
	 	atomic_add.9f				\
	 	atomic_and.9f				\
	 	atomic_bits.9f				\
	 	atomic_cas.9f				\
	 	atomic_dec.9f				\
	 	atomic_inc.9f				\
	 	atomic_ops.9f				\
	 	atomic_or.9f				\
	 	atomic_swap.9f				\
		avl.9f					\
	 	backq.9f				\
	 	bcanput.9f				\
	 	bcmp.9f					\
	 	bcopy.9f				\
	 	bioclone.9f				\
	 	biodone.9f				\
	 	bioerror.9f				\
	 	biofini.9f				\
	 	bioinit.9f				\
	 	biomodified.9f				\
	 	bioreset.9f				\
	 	biosize.9f				\
	 	biowait.9f				\
	 	bp_copyin.9f				\
	 	bp_copyout.9f				\
	 	bp_mapin.9f				\
	 	bp_mapout.9f				\
	 	btop.9f					\
	 	btopr.9f				\
	 	bufcall.9f				\
	 	bzero.9f				\
	 	canput.9f				\
	 	canputnext.9f				\
	 	clrbuf.9f				\
	 	cmn_err.9f				\
	 	condvar.9f				\
	 	copyb.9f				\
	 	copyin.9f				\
	 	copymsg.9f				\
	 	copyout.9f				\
	 	csx_AccessConfigurationRegister.9f	\
	 	csx_CS_DDI_Info.9f			\
	 	csx_ConvertSize.9f			\
	 	csx_ConvertSpeed.9f			\
	 	csx_DeregisterClient.9f			\
	 	csx_DupHandle.9f			\
	 	csx_Error2Text.9f			\
	 	csx_Event2Text.9f			\
	 	csx_FreeHandle.9f			\
	 	csx_Get8.9f				\
	 	csx_GetFirstClient.9f			\
	 	csx_GetFirstTuple.9f			\
	 	csx_GetHandleOffset.9f			\
	 	csx_GetMappedAddr.9f			\
	 	csx_GetStatus.9f			\
	 	csx_GetTupleData.9f			\
	 	csx_MakeDeviceNode.9f			\
	 	csx_MapLogSocket.9f			\
	 	csx_MapMemPage.9f			\
	 	csx_ModifyConfiguration.9f		\
	 	csx_ModifyWindow.9f			\
	 	csx_ParseTuple.9f			\
	 	csx_Parse_CISTPL_BATTERY.9f		\
	 	csx_Parse_CISTPL_BYTEORDER.9f		\
	 	csx_Parse_CISTPL_CFTABLE_ENTRY.9f	\
	 	csx_Parse_CISTPL_CONFIG.9f		\
	 	csx_Parse_CISTPL_DATE.9f		\
	 	csx_Parse_CISTPL_DEVICE.9f		\
	 	csx_Parse_CISTPL_DEVICEGEO.9f		\
	 	csx_Parse_CISTPL_DEVICEGEO_A.9f		\
	 	csx_Parse_CISTPL_FORMAT.9f		\
	 	csx_Parse_CISTPL_FUNCE.9f		\
	 	csx_Parse_CISTPL_FUNCID.9f		\
	 	csx_Parse_CISTPL_GEOMETRY.9f		\
	 	csx_Parse_CISTPL_JEDEC_C.9f		\
	 	csx_Parse_CISTPL_LINKTARGET.9f		\
	 	csx_Parse_CISTPL_LONGLINK_A.9f		\
	 	csx_Parse_CISTPL_LONGLINK_MFC.9f	\
	 	csx_Parse_CISTPL_MANFID.9f		\
	 	csx_Parse_CISTPL_ORG.9f			\
	 	csx_Parse_CISTPL_SPCL.9f		\
	 	csx_Parse_CISTPL_SWIL.9f		\
	 	csx_Parse_CISTPL_VERS_1.9f		\
	 	csx_Parse_CISTPL_VERS_2.9f		\
	 	csx_Put8.9f				\
	 	csx_RegisterClient.9f			\
	 	csx_ReleaseConfiguration.9f		\
	 	csx_RepGet8.9f				\
	 	csx_RepPut8.9f				\
	 	csx_RequestConfiguration.9f		\
	 	csx_RequestIO.9f			\
	 	csx_RequestIRQ.9f			\
	 	csx_RequestSocketMask.9f		\
	 	csx_RequestWindow.9f			\
	 	csx_ResetFunction.9f			\
	 	csx_SetEventMask.9f			\
	 	csx_SetHandleOffset.9f			\
	 	csx_ValidateCIS.9f			\
	 	datamsg.9f				\
	 	ddi_add_event_handler.9f		\
	 	ddi_add_intr.9f				\
	 	ddi_add_softintr.9f			\
	 	ddi_binding_name.9f			\
	 	ddi_btop.9f				\
	 	ddi_can_receive_sig.9f			\
	 	ddi_cb_register.9f			\
	 	ddi_check_acc_handle.9f			\
	 	ddi_copyin.9f				\
	 	ddi_copyout.9f				\
	 	ddi_create_minor_node.9f		\
	 	ddi_cred.9f				\
	 	ddi_dev_is_needed.9f			\
	 	ddi_dev_is_sid.9f			\
	 	ddi_dev_nintrs.9f			\
	 	ddi_dev_nregs.9f			\
	 	ddi_dev_regsize.9f			\
	 	ddi_dev_report_fault.9f			\
	 	ddi_device_copy.9f			\
	 	ddi_device_zero.9f			\
	 	ddi_devid_compare.9f			\
	 	ddi_dma_addr_bind_handle.9f		\
	 	ddi_dma_alloc_handle.9f			\
	 	ddi_dma_buf_bind_handle.9f		\
	 	ddi_dma_burstsizes.9f			\
	 	ddi_dma_free_handle.9f			\
	 	ddi_dma_getwin.9f			\
	 	ddi_dma_mem_alloc.9f			\
	 	ddi_dma_mem_free.9f			\
	 	ddi_dma_nextcookie.9f			\
	 	ddi_dma_numwin.9f			\
	 	ddi_dma_set_sbus64.9f			\
	 	ddi_dma_sync.9f				\
	 	ddi_dma_unbind_handle.9f		\
	 	ddi_dmae.9f				\
	 	ddi_driver_major.9f			\
	 	ddi_driver_name.9f			\
	 	ddi_enter_critical.9f			\
	 	ddi_ffs.9f				\
	 	ddi_fm_acc_err_clear.9f			\
	 	ddi_fm_acc_err_get.9f			\
	 	ddi_fm_ereport_post.9f			\
	 	ddi_fm_handler_register.9f		\
	 	ddi_fm_init.9f				\
	 	ddi_fm_service_impact.9f		\
	 	ddi_get8.9f				\
	 	ddi_get_cred.9f				\
	 	ddi_get_devstate.9f			\
	 	ddi_get_driver_private.9f		\
	 	ddi_get_eventcookie.9f			\
	 	ddi_get_instance.9f			\
	 	ddi_get_kt_did.9f			\
	 	ddi_get_lbolt.9f			\
	 	ddi_get_parent.9f			\
	 	ddi_get_pid.9f				\
	 	ddi_get_time.9f				\
	 	ddi_getiminor.9f			\
	 	ddi_in_panic.9f				\
	 	ddi_intr_add_handler.9f			\
	 	ddi_intr_add_softint.9f			\
	 	ddi_intr_alloc.9f			\
	 	ddi_intr_dup_handler.9f			\
	 	ddi_intr_enable.9f			\
	 	ddi_intr_get_cap.9f			\
	 	ddi_intr_get_hilevel_pri.9f		\
	 	ddi_intr_get_nintrs.9f			\
	 	ddi_intr_get_pending.9f			\
	 	ddi_intr_get_pri.9f			\
	 	ddi_intr_get_supported_types.9f		\
	 	ddi_intr_hilevel.9f			\
	 	ddi_intr_set_mask.9f			\
	 	ddi_intr_set_nreq.9f			\
	 	ddi_io_get8.9f				\
	 	ddi_io_put8.9f				\
	 	ddi_io_rep_get8.9f			\
	 	ddi_io_rep_put8.9f			\
	 	ddi_log_sysevent.9f			\
	 	ddi_map_regs.9f				\
	 	ddi_mem_get8.9f				\
	 	ddi_mem_put8.9f				\
	 	ddi_mem_rep_get8.9f			\
	 	ddi_mem_rep_put8.9f			\
	 	ddi_mmap_get_model.9f			\
	 	ddi_model_convert_from.9f		\
	 	ddi_modopen.9f				\
	 	ddi_no_info.9f				\
	 	ddi_node_name.9f			\
	 	ddi_peek.9f				\
	 	ddi_periodic_add.9f			\
	 	ddi_periodic_delete.9f			\
	 	ddi_poke.9f				\
	 	ddi_prop_create.9f			\
	 	ddi_prop_exists.9f			\
	 	ddi_prop_get_int.9f			\
	 	ddi_prop_lookup.9f			\
	 	ddi_prop_op.9f				\
	 	ddi_prop_update.9f			\
	 	ddi_put8.9f				\
	 	ddi_regs_map_free.9f			\
	 	ddi_regs_map_setup.9f			\
	 	ddi_remove_event_handler.9f		\
	 	ddi_remove_minor_node.9f		\
	 	ddi_removing_power.9f			\
	 	ddi_rep_get8.9f				\
	 	ddi_rep_put8.9f				\
	 	ddi_report_dev.9f			\
	 	ddi_root_node.9f			\
	 	ddi_segmap.9f				\
	 	ddi_slaveonly.9f			\
	 	ddi_soft_state.9f			\
	 	ddi_strtol.9f				\
	 	ddi_strtoll.9f				\
	 	ddi_strtoul.9f				\
	 	ddi_umem_alloc.9f			\
	 	ddi_umem_iosetup.9f			\
	 	ddi_umem_lock.9f			\
	 	delay.9f				\
	 	devmap_default_access.9f		\
	 	devmap_devmem_setup.9f			\
	 	devmap_do_ctxmgt.9f			\
	 	devmap_set_ctx_timeout.9f		\
	 	devmap_setup.9f				\
	 	devmap_unload.9f			\
	 	disksort.9f				\
	 	dlbindack.9f				\
	 	drv_getparm.9f				\
	 	drv_hztousec.9f				\
	 	drv_priv.9f				\
	 	drv_usectohz.9f				\
	 	drv_usecwait.9f				\
	 	dupb.9f					\
	 	dupmsg.9f				\
	 	enableok.9f				\
	 	esballoc.9f				\
	 	esbbcall.9f				\
	 	flushband.9f				\
	 	flushq.9f				\
	 	freeb.9f				\
	 	freemsg.9f				\
	 	freerbuf.9f				\
	 	freezestr.9f				\
	 	get_pktiopb.9f				\
	 	geterror.9f				\
	 	gethrtime.9f				\
	 	getmajor.9f				\
	 	getminor.9f				\
	 	getq.9f					\
	 	getrbuf.9f				\
	 	gld.9f					\
	 	hook_alloc.9f				\
	 	hook_free.9f				\
	 	id32_alloc.9f				\
	 	inb.9f					\
	 	insq.9f					\
	 	kiconv.9f				\
	 	kiconv_close.9f				\
	 	kiconv_open.9f				\
	 	kiconvstr.9f				\
	 	kmem_alloc.9f				\
	 	kmem_cache_create.9f			\
	 	kstat_create.9f				\
	 	kstat_delete.9f				\
	 	kstat_install.9f			\
	 	kstat_named_init.9f			\
	 	kstat_queue.9f				\
	 	ldi_add_event_handler.9f		\
	 	ldi_aread.9f				\
	 	ldi_devmap.9f				\
	 	ldi_dump.9f				\
	 	ldi_ev_finalize.9f			\
	 	ldi_ev_get_cookie.9f			\
	 	ldi_ev_get_type.9f			\
	 	ldi_ev_notify.9f			\
	 	ldi_ev_register_callbacks.9f		\
	 	ldi_ev_remove_callbacks.9f		\
	 	ldi_get_dev.9f				\
	 	ldi_get_eventcookie.9f			\
	 	ldi_get_size.9f				\
	 	ldi_ident_from_dev.9f			\
	 	ldi_ioctl.9f				\
	 	ldi_open_by_dev.9f			\
	 	ldi_poll.9f				\
	 	ldi_prop_exists.9f			\
	 	ldi_prop_get_int.9f			\
	 	ldi_prop_lookup_int_array.9f		\
	 	ldi_putmsg.9f				\
	 	ldi_read.9f				\
	 	ldi_remove_event_handler.9f		\
	 	ldi_strategy.9f				\
	 	linkb.9f				\
	 	list_create.9f				\
	 	makecom.9f				\
	 	makedevice.9f				\
	 	max.9f					\
	 	mcopyin.9f				\
	 	mcopymsg.9f				\
	 	mcopyout.9f				\
	 	membar_ops.9f				\
	 	memchr.9f				\
	 	merror.9f				\
	 	mexchange.9f				\
	 	min.9f					\
	 	mioc2ack.9f				\
	 	miocack.9f				\
	 	miocnak.9f				\
	 	miocpullup.9f				\
	 	mkiocb.9f				\
	 	mod_install.9f				\
	 	msgdsize.9f				\
	 	msgpullup.9f				\
	 	msgsize.9f				\
	 	mt-streams.9f				\
	 	mutex.9f				\
	 	net_event_notify_register.9f		\
	 	net_getifname.9f			\
	 	net_getlifaddr.9f			\
	 	net_getmtu.9f				\
	 	net_getnetid.9f				\
	 	net_getpmtuenabled.9f			\
	 	net_hook_register.9f			\
	 	net_hook_unregister.9f			\
	 	net_inject.9f				\
	 	net_inject_alloc.9f			\
	 	net_inject_free.9f			\
	 	net_instance_alloc.9f			\
	 	net_instance_free.9f			\
	 	net_instance_notify_register.9f		\
	 	net_instance_register.9f		\
	 	net_instance_unregister.9f		\
	 	net_ispartialchecksum.9f		\
	 	net_isvalidchecksum.9f			\
	 	net_kstat_create.9f			\
	 	net_kstat_delete.9f			\
	 	net_lifgetnext.9f			\
	 	net_netidtozonid.9f			\
	 	net_phygetnext.9f			\
	 	net_phylookup.9f			\
	 	net_protocol_lookup.9f			\
	 	net_protocol_notify_register.9f		\
	 	net_protocol_release.9f			\
	 	net_protocol_walk.9f			\
	 	net_routeto.9f				\
	 	net_zoneidtonetid.9f			\
	 	netinfo.9f				\
	 	nochpoll.9f				\
	 	nodev.9f				\
	 	noenable.9f				\
	 	nulldev.9f				\
	 	nvlist_add_boolean.9f			\
	 	nvlist_alloc.9f				\
	 	nvlist_lookup_boolean.9f		\
	 	nvlist_lookup_nvpair.9f			\
	 	nvlist_next_nvpair.9f			\
	 	nvlist_remove.9f			\
	 	nvpair_value_byte.9f			\
	 	outb.9f					\
	 	pci_config_get8.9f			\
	 	pci_config_setup.9f			\
	 	pci_ereport_setup.9f			\
	 	pci_report_pmcap.9f			\
	 	pci_save_config_regs.9f			\
	 	physio.9f				\
	 	pm_busy_component.9f			\
	 	pm_power_has_changed.9f			\
	 	pm_raise_power.9f			\
	 	pm_trans_check.9f			\
	 	pollwakeup.9f				\
	 	priv_getbyname.9f			\
	 	priv_policy.9f				\
	 	proc_signal.9f				\
	 	ptob.9f					\
	 	pullupmsg.9f				\
	 	put.9f					\
	 	putbq.9f				\
	 	putctl.9f				\
	 	putctl1.9f				\
	 	putnext.9f				\
	 	putnextctl.9f				\
	 	putnextctl1.9f				\
	 	putq.9f					\
	 	qassociate.9f				\
	 	qbufcall.9f				\
	 	qenable.9f				\
	 	qprocson.9f				\
	 	qreply.9f				\
	 	qsize.9f				\
	 	qtimeout.9f				\
	 	qunbufcall.9f				\
	 	quntimeout.9f				\
	 	qwait.9f				\
	 	qwriter.9f				\
	 	rmalloc.9f				\
	 	rmalloc_wait.9f				\
	 	rmallocmap.9f				\
	 	rmfree.9f				\
	 	rmvb.9f					\
	 	rmvq.9f					\
	 	rwlock.9f				\
	 	scsi_abort.9f				\
	 	scsi_alloc_consistent_buf.9f		\
	 	scsi_cname.9f				\
	 	scsi_destroy_pkt.9f			\
	 	scsi_dmaget.9f				\
	 	scsi_errmsg.9f				\
	 	scsi_ext_sense_fields.9f		\
	 	scsi_find_sense_descr.9f		\
	 	scsi_free_consistent_buf.9f		\
	 	scsi_get_device_type_scsi_options.9f	\
	 	scsi_get_device_type_string.9f		\
	 	scsi_hba_attach_setup.9f		\
	 	scsi_hba_init.9f			\
	 	scsi_hba_lookup_capstr.9f		\
	 	scsi_hba_pkt_alloc.9f			\
	 	scsi_hba_pkt_comp.9f			\
	 	scsi_hba_probe.9f			\
	 	scsi_hba_tran_alloc.9f			\
	 	scsi_ifgetcap.9f			\
	 	scsi_init_pkt.9f			\
	 	scsi_log.9f				\
	 	scsi_pktalloc.9f			\
	 	scsi_poll.9f				\
	 	scsi_probe.9f				\
	 	scsi_reset.9f				\
	 	scsi_reset_notify.9f			\
	 	scsi_sense_key.9f			\
	 	scsi_setup_cdb.9f			\
	 	scsi_slave.9f				\
	 	scsi_sync_pkt.9f			\
	 	scsi_transport.9f			\
	 	scsi_unprobe.9f				\
	 	scsi_validate_sense.9f			\
	 	scsi_vu_errmsg.9f			\
	 	semaphore.9f				\
	 	stoi.9f					\
	 	string.9f				\
	 	strlog.9f				\
	 	strqget.9f				\
	 	strqset.9f				\
	 	swab.9f					\
	 	taskq.9f				\
	 	testb.9f				\
	 	timeout.9f				\
	 	u8_strcmp.9f				\
	 	u8_textprep_str.9f			\
	 	u8_validate.9f				\
	 	uconv_u16tou32.9f			\
	 	uiomove.9f				\
	 	unbufcall.9f				\
	 	unlinkb.9f				\
	 	untimeout.9f				\
	 	ureadc.9f				\
	 	usb_alloc_request.9f			\
	 	usb_client_attach.9f			\
	 	usb_clr_feature.9f			\
	 	usb_create_pm_components.9f		\
	 	usb_get_addr.9f				\
	 	usb_get_alt_if.9f			\
	 	usb_get_cfg.9f				\
	 	usb_get_current_frame_number.9f		\
	 	usb_get_dev_data.9f			\
	 	usb_get_max_pkts_per_isoc_request.9f	\
	 	usb_get_status.9f			\
	 	usb_get_string_descr.9f			\
	 	usb_handle_remote_wakeup.9f		\
	 	usb_lookup_ep_data.9f			\
	 	usb_parse_data.9f			\
	 	usb_pipe_bulk_xfer.9f			\
	 	usb_pipe_close.9f			\
	 	usb_pipe_ctrl_xfer.9f			\
	 	usb_pipe_drain_reqs.9f			\
	 	usb_pipe_get_max_bulk_transfer_size.9f	\
	 	usb_pipe_get_state.9f			\
	 	usb_pipe_intr_xfer.9f			\
	 	usb_pipe_isoc_xfer.9f			\
	 	usb_pipe_open.9f			\
	 	usb_pipe_reset.9f			\
	 	usb_pipe_set_private.9f			\
	 	usb_register_hotplug_cbs.9f		\
	 	usb_reset_device.9f			\
	 	uwritec.9f				\
	 	va_arg.9f				\
	 	vsprintf.9f

MANLINKS=	SIZEOF_PTR.9f				\
	 	SIZEOF_STRUCT.9f			\
	 	STRUCT_BUF.9f				\
	 	STRUCT_FADDR.9f				\
	 	STRUCT_FGET.9f				\
	 	STRUCT_FGETP.9f				\
	 	STRUCT_FSET.9f				\
	 	STRUCT_FSETP.9f				\
	 	STRUCT_HANDLE.9f			\
	 	STRUCT_INIT.9f				\
	 	STRUCT_SET_HANDLE.9f			\
	 	STRUCT_SIZE.9f				\
	 	assert.9f				\
	 	atomic_add_16.9f			\
	 	atomic_add_16_nv.9f			\
	 	atomic_add_32.9f			\
	 	atomic_add_32_nv.9f			\
	 	atomic_add_64.9f			\
	 	atomic_add_64_nv.9f			\
	 	atomic_add_8.9f				\
	 	atomic_add_8_nv.9f			\
	 	atomic_add_char.9f			\
	 	atomic_add_char_nv.9f			\
	 	atomic_add_int.9f			\
	 	atomic_add_int_nv.9f			\
	 	atomic_add_long.9f			\
	 	atomic_add_long_nv.9f			\
	 	atomic_add_ptr.9f			\
	 	atomic_add_ptr_nv.9f			\
	 	atomic_add_short.9f			\
	 	atomic_add_short_nv.9f			\
	 	atomic_and_16.9f			\
	 	atomic_and_16_nv.9f			\
	 	atomic_and_32.9f			\
	 	atomic_and_32_nv.9f			\
	 	atomic_and_64.9f			\
	 	atomic_and_64_nv.9f			\
	 	atomic_and_8.9f				\
	 	atomic_and_8_nv.9f			\
	 	atomic_and_uchar.9f			\
	 	atomic_and_uchar_nv.9f			\
	 	atomic_and_uint.9f			\
	 	atomic_and_uint_nv.9f			\
	 	atomic_and_ulong.9f			\
	 	atomic_and_ulong_nv.9f			\
	 	atomic_and_ushort.9f			\
	 	atomic_and_ushort_nv.9f			\
	 	atomic_cas_16.9f			\
	 	atomic_cas_32.9f			\
	 	atomic_cas_64.9f			\
	 	atomic_cas_8.9f				\
	 	atomic_cas_ptr.9f			\
	 	atomic_cas_uchar.9f			\
	 	atomic_cas_uint.9f			\
	 	atomic_cas_ulong.9f			\
	 	atomic_cas_ushort.9f			\
	 	atomic_clear_long_excl.9f		\
	 	atomic_dec_16.9f			\
	 	atomic_dec_16_nv.9f			\
	 	atomic_dec_32.9f			\
	 	atomic_dec_32_nv.9f			\
	 	atomic_dec_64.9f			\
	 	atomic_dec_64_nv.9f			\
	 	atomic_dec_8.9f				\
	 	atomic_dec_8_nv.9f			\
	 	atomic_dec_ptr.9f			\
	 	atomic_dec_ptr_nv.9f			\
	 	atomic_dec_uchar.9f			\
	 	atomic_dec_uchar_nv.9f			\
	 	atomic_dec_uint.9f			\
	 	atomic_dec_uint_nv.9f			\
	 	atomic_dec_ulong.9f			\
	 	atomic_dec_ulong_nv.9f			\
	 	atomic_dec_ushort.9f			\
	 	atomic_dec_ushort_nv.9f			\
	 	atomic_inc_16.9f			\
	 	atomic_inc_16_nv.9f			\
	 	atomic_inc_32.9f			\
	 	atomic_inc_32_nv.9f			\
	 	atomic_inc_64.9f			\
	 	atomic_inc_64_nv.9f			\
	 	atomic_inc_8.9f				\
	 	atomic_inc_8_nv.9f			\
	 	atomic_inc_ptr.9f			\
	 	atomic_inc_ptr_nv.9f			\
	 	atomic_inc_uchar.9f			\
	 	atomic_inc_uchar_nv.9f			\
	 	atomic_inc_uint.9f			\
	 	atomic_inc_uint_nv.9f			\
	 	atomic_inc_ulong.9f			\
	 	atomic_inc_ulong_nv.9f			\
	 	atomic_inc_ushort.9f			\
	 	atomic_inc_ushort_nv.9f			\
	 	atomic_or_16.9f				\
	 	atomic_or_16_nv.9f			\
	 	atomic_or_32.9f				\
	 	atomic_or_32_nv.9f			\
	 	atomic_or_64.9f				\
	 	atomic_or_64_nv.9f			\
	 	atomic_or_8.9f				\
	 	atomic_or_8_nv.9f			\
	 	atomic_or_uchar.9f			\
	 	atomic_or_uchar_nv.9f			\
	 	atomic_or_uint.9f			\
	 	atomic_or_uint_nv.9f			\
	 	atomic_or_ulong.9f			\
	 	atomic_or_ulong_nv.9f			\
	 	atomic_or_ushort.9f			\
	 	atomic_or_ushort_nv.9f			\
	 	atomic_set_long_excl.9f			\
	 	atomic_swap_16.9f			\
	 	atomic_swap_32.9f			\
	 	atomic_swap_64.9f			\
	 	atomic_swap_8.9f			\
	 	atomic_swap_ptr.9f			\
	 	atomic_swap_uchar.9f			\
	 	atomic_swap_uint.9f			\
	 	atomic_swap_ulong.9f			\
	 	atomic_swap_ushort.9f			\
		avl_add.9f				\
		avl_create.9f				\
		avl_destroy.9f				\
		avl_destroy_nodes.9f			\
		avl_find.9f 				\
		avl_first.9f				\
		avl_insert.9f				\
		avl_insert_here.9f			\
		avl_is_empty.9f				\
		avl_last.9f				\
		avl_nearest.9f				\
		avl_numnodes.9f				\
		avl_remove.9f				\
		avl_swap.9f				\
		AVL_NEXT.9f				\
		AVL_PREV.9f				\
	 	bcanputnext.9f				\
	 	crgetgid.9f				\
	 	crgetgroups.9f				\
	 	crgetngroups.9f				\
	 	crgetrgid.9f				\
	 	crgetruid.9f				\
	 	crgetsgid.9f				\
	 	crgetsuid.9f				\
	 	crgetuid.9f				\
	 	crgetzoneid.9f				\
	 	csx_Get16.9f				\
	 	csx_Get32.9f				\
	 	csx_Get64.9f				\
	 	csx_GetEventMask.9f			\
	 	csx_GetNextClient.9f			\
	 	csx_GetNextTuple.9f			\
	 	csx_Parse_CISTPL_DEVICE_A.9f		\
	 	csx_Parse_CISTPL_DEVICE_OA.9f		\
	 	csx_Parse_CISTPL_DEVICE_OC.9f		\
	 	csx_Parse_CISTPL_JEDEC_A.9f		\
	 	csx_Parse_CISTPL_LONGLINK_C.9f		\
	 	csx_Put16.9f				\
	 	csx_Put32.9f				\
	 	csx_Put64.9f				\
	 	csx_ReleaseIO.9f			\
	 	csx_ReleaseIRQ.9f			\
	 	csx_ReleaseSocketMask.9f		\
	 	csx_ReleaseWindow.9f			\
	 	csx_RemoveDeviceNode.9f			\
	 	csx_RepGet16.9f				\
	 	csx_RepGet32.9f				\
	 	csx_RepGet64.9f				\
	 	csx_RepPut16.9f				\
	 	csx_RepPut32.9f				\
	 	csx_RepPut64.9f				\
	 	cv_broadcast.9f				\
	 	cv_destroy.9f				\
	 	cv_init.9f				\
	 	cv_reltimedwait.9f			\
	 	cv_reltimedwait_sig.9f			\
	 	cv_signal.9f				\
	 	cv_timedwait.9f				\
	 	cv_timedwait_sig.9f			\
	 	cv_wait.9f				\
	 	cv_wait_sig.9f				\
	 	ddi_btopr.9f				\
	 	ddi_cb_unregister.9f			\
	 	ddi_check_dma_handle.9f			\
	 	ddi_devid_free.9f			\
	 	ddi_devid_get.9f			\
	 	ddi_devid_init.9f			\
	 	ddi_devid_register.9f			\
	 	ddi_devid_sizeof.9f			\
	 	ddi_devid_str_decode.9f			\
	 	ddi_devid_str_encode.9f			\
	 	ddi_devid_str_free.9f			\
	 	ddi_devid_unregister.9f			\
	 	ddi_devid_valid.9f			\
	 	ddi_devmap_segmap.9f			\
	 	ddi_dmae_1stparty.9f			\
	 	ddi_dmae_alloc.9f			\
	 	ddi_dmae_disable.9f			\
	 	ddi_dmae_enable.9f			\
	 	ddi_dmae_getattr.9f			\
	 	ddi_dmae_getcnt.9f			\
	 	ddi_dmae_prog.9f			\
	 	ddi_dmae_release.9f			\
	 	ddi_dmae_stop.9f			\
	 	ddi_exit_critical.9f			\
	 	ddi_fls.9f				\
	 	ddi_fm_capable.9f			\
	 	ddi_fm_dma_err_clear.9f			\
	 	ddi_fm_dma_err_get.9f			\
	 	ddi_fm_fini.9f				\
	 	ddi_fm_handler_unregister.9f		\
	 	ddi_get16.9f				\
	 	ddi_get32.9f				\
	 	ddi_get64.9f				\
	 	ddi_get_iblock_cookie.9f		\
	 	ddi_get_lbolt64.9f			\
	 	ddi_get_name.9f				\
	 	ddi_get_soft_iblock_cookie.9f		\
	 	ddi_get_soft_state.9f			\
	 	ddi_getb.9f				\
	 	ddi_getl.9f				\
	 	ddi_getll.9f				\
	 	ddi_getlongprop.9f			\
	 	ddi_getlongprop_buf.9f			\
	 	ddi_getprop.9f				\
	 	ddi_getproplen.9f			\
	 	ddi_getw.9f				\
	 	ddi_intr_block_disable.9f		\
	 	ddi_intr_block_enable.9f		\
	 	ddi_intr_clr_mask.9f			\
	 	ddi_intr_disable.9f			\
	 	ddi_intr_free.9f			\
	 	ddi_intr_get_navail.9f			\
	 	ddi_intr_get_softint_pri.9f		\
	 	ddi_intr_remove_handler.9f		\
	 	ddi_intr_remove_softint.9f		\
	 	ddi_intr_set_cap.9f			\
	 	ddi_intr_set_pri.9f			\
	 	ddi_intr_set_softint_pri.9f		\
	 	ddi_intr_trigger_softint.9f		\
	 	ddi_io_get16.9f				\
	 	ddi_io_get32.9f				\
	 	ddi_io_getb.9f				\
	 	ddi_io_getl.9f				\
	 	ddi_io_getw.9f				\
	 	ddi_io_put16.9f				\
	 	ddi_io_put32.9f				\
	 	ddi_io_putb.9f				\
	 	ddi_io_putl.9f				\
	 	ddi_io_putw.9f				\
	 	ddi_io_rep_get16.9f			\
	 	ddi_io_rep_get32.9f			\
	 	ddi_io_rep_getb.9f			\
	 	ddi_io_rep_getl.9f			\
	 	ddi_io_rep_getw.9f			\
	 	ddi_io_rep_put16.9f			\
	 	ddi_io_rep_put32.9f			\
	 	ddi_io_rep_putb.9f			\
	 	ddi_io_rep_putl.9f			\
	 	ddi_io_rep_putw.9f			\
	 	ddi_mem_get16.9f			\
	 	ddi_mem_get32.9f			\
	 	ddi_mem_get64.9f			\
	 	ddi_mem_getb.9f				\
	 	ddi_mem_getl.9f				\
	 	ddi_mem_getll.9f			\
	 	ddi_mem_getw.9f				\
	 	ddi_mem_put16.9f			\
	 	ddi_mem_put32.9f			\
	 	ddi_mem_put64.9f			\
	 	ddi_mem_putb.9f				\
	 	ddi_mem_putl.9f				\
	 	ddi_mem_putll.9f			\
	 	ddi_mem_putw.9f				\
	 	ddi_mem_rep_get16.9f			\
	 	ddi_mem_rep_get32.9f			\
	 	ddi_mem_rep_get64.9f			\
	 	ddi_mem_rep_getb.9f			\
	 	ddi_mem_rep_getl.9f			\
	 	ddi_mem_rep_getll.9f			\
	 	ddi_mem_rep_getw.9f			\
	 	ddi_mem_rep_put16.9f			\
	 	ddi_mem_rep_put32.9f			\
	 	ddi_mem_rep_put64.9f			\
	 	ddi_mem_rep_putb.9f			\
	 	ddi_mem_rep_putl.9f			\
	 	ddi_mem_rep_putll.9f			\
	 	ddi_mem_rep_putw.9f			\
	 	ddi_modclose.9f				\
	 	ddi_modsym.9f				\
	 	ddi_peek16.9f				\
	 	ddi_peek32.9f				\
	 	ddi_peek64.9f				\
	 	ddi_peek8.9f				\
	 	ddi_peekc.9f				\
	 	ddi_peekd.9f				\
	 	ddi_peekl.9f				\
	 	ddi_peeks.9f				\
	 	ddi_poke16.9f				\
	 	ddi_poke32.9f				\
	 	ddi_poke64.9f				\
	 	ddi_poke8.9f				\
	 	ddi_pokec.9f				\
	 	ddi_poked.9f				\
	 	ddi_pokel.9f				\
	 	ddi_pokes.9f				\
	 	ddi_prop_free.9f			\
	 	ddi_prop_get_int64.9f			\
	 	ddi_prop_lookup_byte_array.9f		\
	 	ddi_prop_lookup_int64_array.9f		\
	 	ddi_prop_lookup_int_array.9f		\
	 	ddi_prop_lookup_string.9f		\
	 	ddi_prop_lookup_string_array.9f		\
	 	ddi_prop_modify.9f			\
	 	ddi_prop_remove.9f			\
	 	ddi_prop_remove_all.9f			\
	 	ddi_prop_undefine.9f			\
	 	ddi_prop_update_byte_array.9f		\
	 	ddi_prop_update_int.9f			\
	 	ddi_prop_update_int64.9f		\
	 	ddi_prop_update_int64_array.9f		\
	 	ddi_prop_update_int_array.9f		\
	 	ddi_prop_update_string.9f		\
	 	ddi_prop_update_string_array.9f		\
	 	ddi_ptob.9f				\
	 	ddi_put16.9f				\
	 	ddi_put32.9f				\
	 	ddi_put64.9f				\
	 	ddi_putb.9f				\
	 	ddi_putl.9f				\
	 	ddi_putll.9f				\
	 	ddi_putw.9f				\
	 	ddi_remove_intr.9f			\
	 	ddi_remove_softintr.9f			\
	 	ddi_rep_get16.9f			\
	 	ddi_rep_get32.9f			\
	 	ddi_rep_get64.9f			\
	 	ddi_rep_getb.9f				\
	 	ddi_rep_getl.9f				\
	 	ddi_rep_getll.9f			\
	 	ddi_rep_getw.9f				\
	 	ddi_rep_put16.9f			\
	 	ddi_rep_put32.9f			\
	 	ddi_rep_put64.9f			\
	 	ddi_rep_putb.9f				\
	 	ddi_rep_putl.9f				\
	 	ddi_rep_putll.9f			\
	 	ddi_rep_putw.9f				\
	 	ddi_segmap_setup.9f			\
	 	ddi_set_driver_private.9f		\
	 	ddi_soft_state_fini.9f			\
	 	ddi_soft_state_free.9f			\
	 	ddi_soft_state_init.9f			\
	 	ddi_soft_state_zalloc.9f		\
	 	ddi_strdup.9f				\
	 	ddi_strtoull.9f				\
	 	ddi_taskq_create.9f			\
	 	ddi_taskq_destroy.9f			\
	 	ddi_taskq_dispatch.9f			\
	 	ddi_taskq_resume.9f			\
	 	ddi_taskq_suspend.9f			\
	 	ddi_taskq_wait.9f			\
	 	ddi_trigger_softintr.9f			\
	 	ddi_umem_free.9f			\
	 	ddi_umem_unlock.9f			\
	 	ddi_unmap_regs.9f			\
	 	desballoc.9f				\
	 	dev_err.9f				\
	 	devmap_load.9f				\
	 	devmap_umem_setup.9f			\
	 	dlerrorack.9f				\
	 	dlokack.9f				\
	 	dlphysaddrack.9f			\
	 	dluderrorind.9f				\
	 	free_pktiopb.9f				\
	 	gld_intr.9f				\
	 	gld_mac_alloc.9f			\
	 	gld_mac_free.9f				\
	 	gld_recv.9f				\
	 	gld_register.9f				\
	 	gld_sched.9f				\
	 	gld_unregister.9f			\
	 	id32_free.9f				\
	 	id32_lookup.9f				\
	 	inl.9f					\
	 	intro.9f				\
	 	inw.9f					\
	 	kmem_cache_alloc.9f			\
	 	kmem_cache_destroy.9f			\
	 	kmem_cache_free.9f			\
	 	kmem_cache_set_move.9f			\
	 	kmem_free.9f				\
	 	kmem_zalloc.9f				\
	 	kstat_named_setstr.9f			\
	 	kstat_runq_back_to_waitq.9f		\
	 	kstat_runq_enter.9f			\
	 	kstat_runq_exit.9f			\
	 	kstat_waitq_enter.9f			\
	 	kstat_waitq_exit.9f			\
	 	kstat_waitq_to_runq.9f			\
	 	ldi_awrite.9f				\
	 	ldi_close.9f				\
	 	ldi_get_devid.9f			\
	 	ldi_get_minor_name.9f			\
	 	ldi_get_otyp.9f				\
	 	ldi_getmsg.9f				\
	 	ldi_ident_from_dip.9f			\
	 	ldi_ident_from_stream.9f		\
	 	ldi_ident_release.9f			\
	 	ldi_open_by_devid.9f			\
	 	ldi_open_by_name.9f			\
	 	ldi_prop_get_int64.9f			\
	 	ldi_prop_lookup_byte_array.9f		\
	 	ldi_prop_lookup_int64_array.9f		\
	 	ldi_prop_lookup_string.9f		\
	 	ldi_prop_lookup_string_array.9f		\
	 	ldi_write.9f				\
	 	list_destroy.9f				\
	 	list_head.9f				\
	 	list_insert_after.9f			\
	 	list_insert_before.9f			\
	 	list_insert_head.9f			\
	 	list_insert_tail.9f			\
	 	list_is_empty.9f			\
	 	list_link_active.9f			\
	 	list_link_init.9f			\
	 	list_link_replace.9f			\
	 	list_move_tail.9f			\
	 	list_next.9f				\
	 	list_prev.9f				\
	 	list_remove.9f				\
	 	list_remove_head.9f			\
	 	list_remove_tail.9f			\
	 	list_tail.9f				\
	 	makecom_g0.9f				\
	 	makecom_g0_s.9f				\
	 	makecom_g1.9f				\
	 	makecom_g5.9f				\
	 	membar_consumer.9f			\
	 	membar_enter.9f				\
	 	membar_exit.9f				\
	 	membar_producer.9f			\
	 	memcmp.9f				\
	 	memcpy.9f				\
	 	memmove.9f				\
	 	memset.9f				\
	 	minphys.9f				\
	 	mod_info.9f				\
	 	mod_modname.9f				\
	 	mod_remove.9f				\
	 	mutex_destroy.9f			\
	 	mutex_enter.9f				\
	 	mutex_exit.9f				\
	 	mutex_init.9f				\
	 	mutex_owned.9f				\
	 	mutex_tryenter.9f			\
	 	net_event_notify_unregister.9f		\
	 	net_instance_notify_unregister.9f	\
	 	net_instance_protocol_unregister.9f	\
	 	numtos.9f				\
	 	nv_alloc_fini.9f			\
	 	nv_alloc_init.9f			\
	 	nvlist_add_boolean_array.9f		\
	 	nvlist_add_boolean_value.9f		\
	 	nvlist_add_byte.9f			\
	 	nvlist_add_byte_array.9f		\
	 	nvlist_add_int16.9f			\
	 	nvlist_add_int16_array.9f		\
	 	nvlist_add_int32.9f			\
	 	nvlist_add_int32_array.9f		\
	 	nvlist_add_int64.9f			\
	 	nvlist_add_int64_array.9f		\
	 	nvlist_add_int8.9f			\
	 	nvlist_add_int8_array.9f		\
	 	nvlist_add_nvlist.9f			\
	 	nvlist_add_nvlist_array.9f		\
	 	nvlist_add_nvpair.9f			\
	 	nvlist_add_string.9f			\
	 	nvlist_add_string_array.9f		\
	 	nvlist_add_uint16.9f			\
	 	nvlist_add_uint16_array.9f		\
	 	nvlist_add_uint32.9f			\
	 	nvlist_add_uint32_array.9f		\
	 	nvlist_add_uint64.9f			\
	 	nvlist_add_uint64_array.9f		\
	 	nvlist_add_uint8.9f			\
	 	nvlist_add_uint8_array.9f		\
	 	nvlist_dup.9f				\
	 	nvlist_exists.9f			\
	 	nvlist_free.9f				\
	 	nvlist_lookup_boolean_array.9f		\
	 	nvlist_lookup_boolean_value.9f		\
	 	nvlist_lookup_byte.9f			\
	 	nvlist_lookup_byte_array.9f		\
	 	nvlist_lookup_int16.9f			\
	 	nvlist_lookup_int16_array.9f		\
	 	nvlist_lookup_int32.9f			\
	 	nvlist_lookup_int32_array.9f		\
	 	nvlist_lookup_int64.9f			\
	 	nvlist_lookup_int64_array.9f		\
	 	nvlist_lookup_int8.9f			\
	 	nvlist_lookup_int8_array.9f		\
	 	nvlist_lookup_nvlist.9f			\
	 	nvlist_lookup_nvlist_array.9f		\
	 	nvlist_lookup_pairs.9f			\
	 	nvlist_lookup_string.9f			\
	 	nvlist_lookup_string_array.9f		\
	 	nvlist_lookup_uint16.9f			\
	 	nvlist_lookup_uint16_array.9f		\
	 	nvlist_lookup_uint32.9f			\
	 	nvlist_lookup_uint32_array.9f		\
	 	nvlist_lookup_uint64.9f			\
	 	nvlist_lookup_uint64_array.9f		\
	 	nvlist_lookup_uint8.9f			\
	 	nvlist_lookup_uint8_array.9f		\
	 	nvlist_merge.9f				\
	 	nvlist_pack.9f				\
	 	nvlist_remove_all.9f			\
	 	nvlist_size.9f				\
	 	nvlist_t.9f				\
	 	nvlist_unpack.9f			\
	 	nvlist_xalloc.9f			\
	 	nvlist_xdup.9f				\
	 	nvlist_xpack.9f				\
	 	nvlist_xunpack.9f			\
	 	nvpair_name.9f				\
	 	nvpair_type.9f				\
	 	nvpair_value_boolean_array.9f		\
	 	nvpair_value_byte_array.9f		\
	 	nvpair_value_int16.9f			\
	 	nvpair_value_int16_array.9f		\
	 	nvpair_value_int32.9f			\
	 	nvpair_value_int32_array.9f		\
	 	nvpair_value_int64.9f			\
	 	nvpair_value_int64_array.9f		\
	 	nvpair_value_int8.9f			\
	 	nvpair_value_int8_array.9f		\
	 	nvpair_value_nvlist.9f			\
	 	nvpair_value_nvlist_array.9f		\
	 	nvpair_value_string.9f			\
	 	nvpair_value_string_array.9f		\
	 	nvpair_value_uint16.9f			\
	 	nvpair_value_uint16_array.9f		\
	 	nvpair_value_uint32.9f			\
	 	nvpair_value_uint32_array.9f		\
	 	nvpair_value_uint64.9f			\
	 	nvpair_value_uint64_array.9f		\
	 	nvpair_value_uint8.9f			\
	 	nvpair_value_uint8_array.9f		\
	 	otherq.9f				\
	 	outl.9f					\
	 	outw.9f					\
	 	pci_config_get16.9f			\
	 	pci_config_get32.9f			\
	 	pci_config_get64.9f			\
	 	pci_config_getb.9f			\
	 	pci_config_getl.9f			\
	 	pci_config_getll.9f			\
	 	pci_config_getw.9f			\
	 	pci_config_put16.9f			\
	 	pci_config_put32.9f			\
	 	pci_config_put64.9f			\
	 	pci_config_put8.9f			\
	 	pci_config_putb.9f			\
	 	pci_config_putl.9f			\
	 	pci_config_putll.9f			\
	 	pci_config_putw.9f			\
	 	pci_config_teardown.9f			\
	 	pci_ereport_post.9f			\
	 	pci_ereport_teardown.9f			\
	 	pci_restore_config_regs.9f		\
	 	pm_idle_component.9f			\
	 	pm_lower_power.9f			\
	 	priv_policy_choice.9f			\
	 	priv_policy_only.9f			\
	 	proc_ref.9f				\
	 	proc_unref.9f				\
	 	qprocsoff.9f				\
	 	qwait_sig.9f				\
	 	rd.9f					\
	 	repinsb.9f				\
	 	repinsd.9f				\
	 	repinsw.9f				\
	 	repoutsb.9f				\
	 	repoutsd.9f				\
	 	repoutsw.9f				\
	 	rmallocmap_wait.9f			\
	 	rmfreemap.9f				\
	 	rw_destroy.9f				\
	 	rw_downgrade.9f				\
	 	rw_enter.9f				\
	 	rw_exit.9f				\
	 	rw_init.9f				\
	 	rw_read_locked.9f			\
	 	rw_tryenter.9f				\
	 	rw_tryupgrade.9f			\
	 	samestr.9f				\
	 	scsi_dmafree.9f				\
	 	scsi_dname.9f				\
	 	scsi_hba_detach.9f			\
	 	scsi_hba_fini.9f			\
	 	scsi_hba_pkt_free.9f			\
	 	scsi_hba_tran_free.9f			\
	 	scsi_ifsetcap.9f			\
	 	scsi_mname.9f				\
	 	scsi_pktfree.9f				\
	 	scsi_resalloc.9f			\
	 	scsi_resfree.9f				\
	 	scsi_rname.9f				\
	 	scsi_sense_asc.9f			\
	 	scsi_sense_ascq.9f			\
	 	scsi_sense_cmdspecific_uint64.9f	\
	 	scsi_sense_info_uint64.9f		\
	 	scsi_sname.9f				\
	 	scsi_unslave.9f				\
	 	sema_destroy.9f				\
	 	sema_init.9f				\
	 	sema_p.9f				\
	 	sema_p_sig.9f				\
	 	sema_tryp.9f				\
	 	sema_v.9f				\
	 	strcasecmp.9f				\
	 	strcat.9f				\
	 	strchr.9f				\
	 	strcmp.9f				\
	 	strcpy.9f				\
	 	strdup.9f				\
	 	strfree.9f				\
	 	strlcat.9f				\
	 	strlcpy.9f				\
	 	strlen.9f				\
	 	strncasecmp.9f				\
	 	strncat.9f				\
	 	strncmp.9f				\
	 	strncpy.9f				\
	 	strnlen.9f				\
	 	strrchr.9f				\
	 	strspn.9f				\
	 	taskq_suspended.9f			\
	 	uconv_u16tou8.9f			\
	 	uconv_u32tou16.9f			\
	 	uconv_u32tou8.9f			\
	 	uconv_u8tou16.9f			\
	 	uconv_u8tou32.9f			\
	 	unfreezestr.9f				\
	 	usb_alloc_bulk_req.9f			\
	 	usb_alloc_ctrl_req.9f			\
	 	usb_alloc_intr_req.9f			\
	 	usb_alloc_isoc_req.9f			\
	 	usb_client_detach.9f			\
	 	usb_free_bulk_req.9f			\
	 	usb_free_ctrl_req.9f			\
	 	usb_free_descr_tree.9f			\
	 	usb_free_dev_data.9f			\
	 	usb_free_intr_req.9f			\
	 	usb_free_isoc_req.9f			\
	 	usb_get_if_number.9f			\
	 	usb_owns_device.9f			\
	 	usb_pipe_ctrl_xfer_wait.9f		\
	 	usb_pipe_get_private.9f			\
	 	usb_pipe_stop_intr_polling.9f		\
	 	usb_pipe_stop_isoc_polling.9f		\
	 	usb_print_descr_tree.9f			\
	 	usb_set_alt_if.9f			\
	 	usb_set_cfg.9f				\
	 	usb_unregister_hotplug_cbs.9f		\
	 	va_copy.9f				\
	 	va_end.9f				\
	 	va_start.9f				\
	 	vcmn_err.9f				\
	 	vzcmn_err.9f				\
	 	wr.9f					\
	 	zcmn_err.9f

assert.9f				:= LINKSRC = ASSERT.9f

intro.9f				:= LINKSRC = Intro.9f

otherq.9f				:= LINKSRC = OTHERQ.9f

rd.9f					:= LINKSRC = RD.9f

samestr.9f				:= LINKSRC = SAMESTR.9f

SIZEOF_PTR.9f				:= LINKSRC = STRUCT_DECL.9f
SIZEOF_STRUCT.9f			:= LINKSRC = STRUCT_DECL.9f
STRUCT_BUF.9f				:= LINKSRC = STRUCT_DECL.9f
STRUCT_FADDR.9f				:= LINKSRC = STRUCT_DECL.9f
STRUCT_FGET.9f				:= LINKSRC = STRUCT_DECL.9f
STRUCT_FGETP.9f				:= LINKSRC = STRUCT_DECL.9f
STRUCT_FSET.9f				:= LINKSRC = STRUCT_DECL.9f
STRUCT_FSETP.9f				:= LINKSRC = STRUCT_DECL.9f
STRUCT_HANDLE.9f			:= LINKSRC = STRUCT_DECL.9f
STRUCT_INIT.9f				:= LINKSRC = STRUCT_DECL.9f
STRUCT_SET_HANDLE.9f			:= LINKSRC = STRUCT_DECL.9f
STRUCT_SIZE.9f				:= LINKSRC = STRUCT_DECL.9f

wr.9f					:= LINKSRC = WR.9f

atomic_add_16.9f			:= LINKSRC = atomic_add.9f
atomic_add_16_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_32.9f			:= LINKSRC = atomic_add.9f
atomic_add_32_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_64.9f			:= LINKSRC = atomic_add.9f
atomic_add_64_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_8.9f				:= LINKSRC = atomic_add.9f
atomic_add_8_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_char.9f			:= LINKSRC = atomic_add.9f
atomic_add_char_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_int.9f			:= LINKSRC = atomic_add.9f
atomic_add_int_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_long.9f			:= LINKSRC = atomic_add.9f
atomic_add_long_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_ptr.9f			:= LINKSRC = atomic_add.9f
atomic_add_ptr_nv.9f			:= LINKSRC = atomic_add.9f
atomic_add_short.9f			:= LINKSRC = atomic_add.9f
atomic_add_short_nv.9f			:= LINKSRC = atomic_add.9f
atomic_and_16.9f			:= LINKSRC = atomic_and.9f
atomic_and_16_nv.9f			:= LINKSRC = atomic_and.9f
atomic_and_32.9f			:= LINKSRC = atomic_and.9f
atomic_and_32_nv.9f			:= LINKSRC = atomic_and.9f
atomic_and_64.9f			:= LINKSRC = atomic_and.9f
atomic_and_64_nv.9f			:= LINKSRC = atomic_and.9f
atomic_and_8.9f				:= LINKSRC = atomic_and.9f
atomic_and_8_nv.9f			:= LINKSRC = atomic_and.9f
atomic_and_uchar.9f			:= LINKSRC = atomic_and.9f
atomic_and_uchar_nv.9f			:= LINKSRC = atomic_and.9f
atomic_and_uint.9f			:= LINKSRC = atomic_and.9f
atomic_and_uint_nv.9f			:= LINKSRC = atomic_and.9f
atomic_and_ulong.9f			:= LINKSRC = atomic_and.9f
atomic_and_ulong_nv.9f			:= LINKSRC = atomic_and.9f
atomic_and_ushort.9f			:= LINKSRC = atomic_and.9f
atomic_and_ushort_nv.9f			:= LINKSRC = atomic_and.9f

atomic_clear_long_excl.9f		:= LINKSRC = atomic_bits.9f
atomic_set_long_excl.9f			:= LINKSRC = atomic_bits.9f

atomic_cas_16.9f			:= LINKSRC = atomic_cas.9f
atomic_cas_32.9f			:= LINKSRC = atomic_cas.9f
atomic_cas_64.9f			:= LINKSRC = atomic_cas.9f
atomic_cas_8.9f				:= LINKSRC = atomic_cas.9f
atomic_cas_ptr.9f			:= LINKSRC = atomic_cas.9f
atomic_cas_uchar.9f			:= LINKSRC = atomic_cas.9f
atomic_cas_uint.9f			:= LINKSRC = atomic_cas.9f
atomic_cas_ulong.9f			:= LINKSRC = atomic_cas.9f
atomic_cas_ushort.9f			:= LINKSRC = atomic_cas.9f

atomic_dec_16.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_16_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_32.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_32_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_64.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_64_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_8.9f				:= LINKSRC = atomic_dec.9f
atomic_dec_8_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_ptr.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_ptr_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_uchar.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_uchar_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_uint.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_uint_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_ulong.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_ulong_nv.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_ushort.9f			:= LINKSRC = atomic_dec.9f
atomic_dec_ushort_nv.9f			:= LINKSRC = atomic_dec.9f

atomic_inc_16.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_16_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_32.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_32_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_64.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_64_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_8.9f				:= LINKSRC = atomic_inc.9f
atomic_inc_8_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_ptr.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_ptr_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_uchar.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_uchar_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_uint.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_uint_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_ulong.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_ulong_nv.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_ushort.9f			:= LINKSRC = atomic_inc.9f
atomic_inc_ushort_nv.9f			:= LINKSRC = atomic_inc.9f

atomic_or_16.9f				:= LINKSRC = atomic_or.9f
atomic_or_16_nv.9f			:= LINKSRC = atomic_or.9f
atomic_or_32.9f				:= LINKSRC = atomic_or.9f
atomic_or_32_nv.9f			:= LINKSRC = atomic_or.9f
atomic_or_64.9f				:= LINKSRC = atomic_or.9f
atomic_or_64_nv.9f			:= LINKSRC = atomic_or.9f
atomic_or_8.9f				:= LINKSRC = atomic_or.9f
atomic_or_8_nv.9f			:= LINKSRC = atomic_or.9f
atomic_or_uchar.9f			:= LINKSRC = atomic_or.9f
atomic_or_uchar_nv.9f			:= LINKSRC = atomic_or.9f
atomic_or_uint.9f			:= LINKSRC = atomic_or.9f
atomic_or_uint_nv.9f			:= LINKSRC = atomic_or.9f
atomic_or_ulong.9f			:= LINKSRC = atomic_or.9f
atomic_or_ulong_nv.9f			:= LINKSRC = atomic_or.9f
atomic_or_ushort.9f			:= LINKSRC = atomic_or.9f
atomic_or_ushort_nv.9f			:= LINKSRC = atomic_or.9f

atomic_swap_16.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_32.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_64.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_8.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_ptr.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_uchar.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_uint.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_ulong.9f			:= LINKSRC = atomic_swap.9f
atomic_swap_ushort.9f			:= LINKSRC = atomic_swap.9f

avl_add.9f				:= LINKSRC = avl.9f
avl_create.9f				:= LINKSRC = avl.9f
avl_destroy.9f				:= LINKSRC = avl.9f
avl_destroy_nodes.9f			:= LINKSRC = avl.9f
avl_find.9f 				:= LINKSRC = avl.9f
avl_first.9f				:= LINKSRC = avl.9f
avl_insert.9f				:= LINKSRC = avl.9f
avl_insert_here.9f			:= LINKSRC = avl.9f
avl_is_empty.9f				:= LINKSRC = avl.9f
avl_last.9f				:= LINKSRC = avl.9f
avl_nearest.9f				:= LINKSRC = avl.9f
avl_numnodes.9f				:= LINKSRC = avl.9f
avl_remove.9f				:= LINKSRC = avl.9f
avl_swap.9f				:= LINKSRC = avl.9f
AVL_NEXT.9f				:= LINKSRC = avl.9f
AVL_PREV.9f				:= LINKSRC = avl.9f

dev_err.9f				:= LINKSRC = cmn_err.9f
vcmn_err.9f				:= LINKSRC = cmn_err.9f
vzcmn_err.9f				:= LINKSRC = cmn_err.9f
zcmn_err.9f				:= LINKSRC = cmn_err.9f

cv_broadcast.9f				:= LINKSRC = condvar.9f
cv_destroy.9f				:= LINKSRC = condvar.9f
cv_init.9f				:= LINKSRC = condvar.9f
cv_reltimedwait.9f			:= LINKSRC = condvar.9f
cv_reltimedwait_sig.9f			:= LINKSRC = condvar.9f
cv_signal.9f				:= LINKSRC = condvar.9f
cv_timedwait.9f				:= LINKSRC = condvar.9f
cv_timedwait_sig.9f			:= LINKSRC = condvar.9f
cv_wait.9f				:= LINKSRC = condvar.9f
cv_wait_sig.9f				:= LINKSRC = condvar.9f

csx_Get16.9f				:= LINKSRC = csx_Get8.9f
csx_Get32.9f				:= LINKSRC = csx_Get8.9f
csx_Get64.9f				:= LINKSRC = csx_Get8.9f

csx_GetNextClient.9f			:= LINKSRC = csx_GetFirstClient.9f

csx_GetNextTuple.9f			:= LINKSRC = csx_GetFirstTuple.9f

csx_RemoveDeviceNode.9f			:= LINKSRC = csx_MakeDeviceNode.9f

csx_Parse_CISTPL_DEVICE_A.9f		:= LINKSRC = csx_Parse_CISTPL_DEVICE.9f
csx_Parse_CISTPL_DEVICE_OA.9f		:= LINKSRC = csx_Parse_CISTPL_DEVICE.9f
csx_Parse_CISTPL_DEVICE_OC.9f		:= LINKSRC = csx_Parse_CISTPL_DEVICE.9f

csx_Parse_CISTPL_JEDEC_A.9f		:= LINKSRC = csx_Parse_CISTPL_JEDEC_C.9f

csx_Parse_CISTPL_LONGLINK_C.9f		:= LINKSRC = csx_Parse_CISTPL_LONGLINK_A.9f

csx_Put16.9f				:= LINKSRC = csx_Put8.9f
csx_Put32.9f				:= LINKSRC = csx_Put8.9f
csx_Put64.9f				:= LINKSRC = csx_Put8.9f

csx_RepGet16.9f				:= LINKSRC = csx_RepGet8.9f
csx_RepGet32.9f				:= LINKSRC = csx_RepGet8.9f
csx_RepGet64.9f				:= LINKSRC = csx_RepGet8.9f

csx_RepPut16.9f				:= LINKSRC = csx_RepPut8.9f
csx_RepPut32.9f				:= LINKSRC = csx_RepPut8.9f
csx_RepPut64.9f				:= LINKSRC = csx_RepPut8.9f

csx_ReleaseIO.9f			:= LINKSRC = csx_RequestIO.9f

csx_ReleaseIRQ.9f			:= LINKSRC = csx_RequestIRQ.9f

csx_ReleaseSocketMask.9f		:= LINKSRC = csx_RequestSocketMask.9f

csx_ReleaseWindow.9f			:= LINKSRC = csx_RequestWindow.9f

csx_GetEventMask.9f			:= LINKSRC = csx_SetEventMask.9f

ddi_get_iblock_cookie.9f		:= LINKSRC = ddi_add_intr.9f
ddi_remove_intr.9f			:= LINKSRC = ddi_add_intr.9f

ddi_get_soft_iblock_cookie.9f		:= LINKSRC = ddi_add_softintr.9f
ddi_remove_softintr.9f			:= LINKSRC = ddi_add_softintr.9f
ddi_trigger_softintr.9f			:= LINKSRC = ddi_add_softintr.9f

ddi_get_name.9f				:= LINKSRC = ddi_binding_name.9f

ddi_btopr.9f				:= LINKSRC = ddi_btop.9f
ddi_ptob.9f				:= LINKSRC = ddi_btop.9f

ddi_cb_unregister.9f			:= LINKSRC = ddi_cb_register.9f

ddi_check_dma_handle.9f			:= LINKSRC = ddi_check_acc_handle.9f

bcanputnext.9f				:= LINKSRC = canputnext.9f

crgetgid.9f				:= LINKSRC = ddi_cred.9f
crgetgroups.9f				:= LINKSRC = ddi_cred.9f
crgetngroups.9f				:= LINKSRC = ddi_cred.9f
crgetrgid.9f				:= LINKSRC = ddi_cred.9f
crgetruid.9f				:= LINKSRC = ddi_cred.9f
crgetsgid.9f				:= LINKSRC = ddi_cred.9f
crgetsuid.9f				:= LINKSRC = ddi_cred.9f
crgetuid.9f				:= LINKSRC = ddi_cred.9f
crgetzoneid.9f				:= LINKSRC = ddi_cred.9f

ddi_devid_free.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_get.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_init.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_register.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_sizeof.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_str_decode.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_str_encode.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_str_free.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_unregister.9f			:= LINKSRC = ddi_devid_compare.9f
ddi_devid_valid.9f			:= LINKSRC = ddi_devid_compare.9f

ddi_dmae_1stparty.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_alloc.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_disable.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_enable.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_getattr.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_getcnt.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_prog.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_release.9f			:= LINKSRC = ddi_dmae.9f
ddi_dmae_stop.9f			:= LINKSRC = ddi_dmae.9f

ddi_exit_critical.9f			:= LINKSRC = ddi_enter_critical.9f

ddi_fls.9f				:= LINKSRC = ddi_ffs.9f

ddi_fm_dma_err_clear.9f			:= LINKSRC = ddi_fm_acc_err_clear.9f

ddi_fm_dma_err_get.9f			:= LINKSRC = ddi_fm_acc_err_get.9f

ddi_fm_handler_unregister.9f		:= LINKSRC = ddi_fm_handler_register.9f

ddi_fm_capable.9f			:= LINKSRC = ddi_fm_init.9f
ddi_fm_fini.9f				:= LINKSRC = ddi_fm_init.9f

ddi_get16.9f				:= LINKSRC = ddi_get8.9f
ddi_get32.9f				:= LINKSRC = ddi_get8.9f
ddi_get64.9f				:= LINKSRC = ddi_get8.9f
ddi_getb.9f				:= LINKSRC = ddi_get8.9f
ddi_getl.9f				:= LINKSRC = ddi_get8.9f
ddi_getll.9f				:= LINKSRC = ddi_get8.9f
ddi_getw.9f				:= LINKSRC = ddi_get8.9f

ddi_set_driver_private.9f		:= LINKSRC = ddi_get_driver_private.9f

ddi_get_lbolt64.9f			:= LINKSRC = ddi_get_lbolt.9f

ddi_intr_remove_handler.9f		:= LINKSRC = ddi_intr_add_handler.9f

ddi_intr_get_softint_pri.9f		:= LINKSRC = ddi_intr_add_softint.9f
ddi_intr_remove_softint.9f		:= LINKSRC = ddi_intr_add_softint.9f
ddi_intr_set_softint_pri.9f		:= LINKSRC = ddi_intr_add_softint.9f
ddi_intr_trigger_softint.9f		:= LINKSRC = ddi_intr_add_softint.9f

ddi_intr_free.9f			:= LINKSRC = ddi_intr_alloc.9f

ddi_intr_block_disable.9f		:= LINKSRC = ddi_intr_enable.9f
ddi_intr_block_enable.9f		:= LINKSRC = ddi_intr_enable.9f
ddi_intr_disable.9f			:= LINKSRC = ddi_intr_enable.9f

ddi_intr_set_cap.9f			:= LINKSRC = ddi_intr_get_cap.9f

ddi_intr_get_navail.9f			:= LINKSRC = ddi_intr_get_nintrs.9f

ddi_intr_set_pri.9f			:= LINKSRC = ddi_intr_get_pri.9f

ddi_intr_clr_mask.9f			:= LINKSRC = ddi_intr_set_mask.9f

ddi_io_get16.9f				:= LINKSRC = ddi_io_get8.9f
ddi_io_get32.9f				:= LINKSRC = ddi_io_get8.9f
ddi_io_getb.9f				:= LINKSRC = ddi_io_get8.9f
ddi_io_getl.9f				:= LINKSRC = ddi_io_get8.9f
ddi_io_getw.9f				:= LINKSRC = ddi_io_get8.9f

ddi_io_put16.9f				:= LINKSRC = ddi_io_put8.9f
ddi_io_put32.9f				:= LINKSRC = ddi_io_put8.9f
ddi_io_putb.9f				:= LINKSRC = ddi_io_put8.9f
ddi_io_putl.9f				:= LINKSRC = ddi_io_put8.9f
ddi_io_putw.9f				:= LINKSRC = ddi_io_put8.9f

ddi_io_rep_get16.9f			:= LINKSRC = ddi_io_rep_get8.9f
ddi_io_rep_get32.9f			:= LINKSRC = ddi_io_rep_get8.9f
ddi_io_rep_getb.9f			:= LINKSRC = ddi_io_rep_get8.9f
ddi_io_rep_getl.9f			:= LINKSRC = ddi_io_rep_get8.9f
ddi_io_rep_getw.9f			:= LINKSRC = ddi_io_rep_get8.9f

ddi_io_rep_put16.9f			:= LINKSRC = ddi_io_rep_put8.9f
ddi_io_rep_put32.9f			:= LINKSRC = ddi_io_rep_put8.9f
ddi_io_rep_putb.9f			:= LINKSRC = ddi_io_rep_put8.9f
ddi_io_rep_putl.9f			:= LINKSRC = ddi_io_rep_put8.9f
ddi_io_rep_putw.9f			:= LINKSRC = ddi_io_rep_put8.9f

ddi_unmap_regs.9f			:= LINKSRC = ddi_map_regs.9f

ddi_mem_get16.9f			:= LINKSRC = ddi_mem_get8.9f
ddi_mem_get32.9f			:= LINKSRC = ddi_mem_get8.9f
ddi_mem_get64.9f			:= LINKSRC = ddi_mem_get8.9f
ddi_mem_getb.9f				:= LINKSRC = ddi_mem_get8.9f
ddi_mem_getl.9f				:= LINKSRC = ddi_mem_get8.9f
ddi_mem_getll.9f			:= LINKSRC = ddi_mem_get8.9f
ddi_mem_getw.9f				:= LINKSRC = ddi_mem_get8.9f

ddi_mem_put16.9f			:= LINKSRC = ddi_mem_put8.9f
ddi_mem_put32.9f			:= LINKSRC = ddi_mem_put8.9f
ddi_mem_put64.9f			:= LINKSRC = ddi_mem_put8.9f
ddi_mem_putb.9f				:= LINKSRC = ddi_mem_put8.9f
ddi_mem_putl.9f				:= LINKSRC = ddi_mem_put8.9f
ddi_mem_putll.9f			:= LINKSRC = ddi_mem_put8.9f
ddi_mem_putw.9f				:= LINKSRC = ddi_mem_put8.9f

ddi_mem_rep_get16.9f			:= LINKSRC = ddi_mem_rep_get8.9f
ddi_mem_rep_get32.9f			:= LINKSRC = ddi_mem_rep_get8.9f
ddi_mem_rep_get64.9f			:= LINKSRC = ddi_mem_rep_get8.9f
ddi_mem_rep_getb.9f			:= LINKSRC = ddi_mem_rep_get8.9f
ddi_mem_rep_getl.9f			:= LINKSRC = ddi_mem_rep_get8.9f
ddi_mem_rep_getll.9f			:= LINKSRC = ddi_mem_rep_get8.9f
ddi_mem_rep_getw.9f			:= LINKSRC = ddi_mem_rep_get8.9f

ddi_mem_rep_put16.9f			:= LINKSRC = ddi_mem_rep_put8.9f
ddi_mem_rep_put32.9f			:= LINKSRC = ddi_mem_rep_put8.9f
ddi_mem_rep_put64.9f			:= LINKSRC = ddi_mem_rep_put8.9f
ddi_mem_rep_putb.9f			:= LINKSRC = ddi_mem_rep_put8.9f
ddi_mem_rep_putl.9f			:= LINKSRC = ddi_mem_rep_put8.9f
ddi_mem_rep_putll.9f			:= LINKSRC = ddi_mem_rep_put8.9f
ddi_mem_rep_putw.9f			:= LINKSRC = ddi_mem_rep_put8.9f

ddi_modclose.9f				:= LINKSRC = ddi_modopen.9f
ddi_modsym.9f				:= LINKSRC = ddi_modopen.9f

ddi_peek16.9f				:= LINKSRC = ddi_peek.9f
ddi_peek32.9f				:= LINKSRC = ddi_peek.9f
ddi_peek64.9f				:= LINKSRC = ddi_peek.9f
ddi_peek8.9f				:= LINKSRC = ddi_peek.9f
ddi_peekc.9f				:= LINKSRC = ddi_peek.9f
ddi_peekd.9f				:= LINKSRC = ddi_peek.9f
ddi_peekl.9f				:= LINKSRC = ddi_peek.9f
ddi_peeks.9f				:= LINKSRC = ddi_peek.9f

ddi_poke16.9f				:= LINKSRC = ddi_poke.9f
ddi_poke32.9f				:= LINKSRC = ddi_poke.9f
ddi_poke64.9f				:= LINKSRC = ddi_poke.9f
ddi_poke8.9f				:= LINKSRC = ddi_poke.9f
ddi_pokec.9f				:= LINKSRC = ddi_poke.9f
ddi_poked.9f				:= LINKSRC = ddi_poke.9f
ddi_pokel.9f				:= LINKSRC = ddi_poke.9f
ddi_pokes.9f				:= LINKSRC = ddi_poke.9f

ddi_prop_modify.9f			:= LINKSRC = ddi_prop_create.9f
ddi_prop_remove.9f			:= LINKSRC = ddi_prop_create.9f
ddi_prop_remove_all.9f			:= LINKSRC = ddi_prop_create.9f
ddi_prop_undefine.9f			:= LINKSRC = ddi_prop_create.9f

ddi_prop_get_int64.9f			:= LINKSRC = ddi_prop_get_int.9f

ddi_prop_free.9f			:= LINKSRC = ddi_prop_lookup.9f
ddi_prop_lookup_byte_array.9f		:= LINKSRC = ddi_prop_lookup.9f
ddi_prop_lookup_int64_array.9f		:= LINKSRC = ddi_prop_lookup.9f
ddi_prop_lookup_int_array.9f		:= LINKSRC = ddi_prop_lookup.9f
ddi_prop_lookup_string.9f		:= LINKSRC = ddi_prop_lookup.9f
ddi_prop_lookup_string_array.9f		:= LINKSRC = ddi_prop_lookup.9f

ddi_getlongprop.9f			:= LINKSRC = ddi_prop_op.9f
ddi_getlongprop_buf.9f			:= LINKSRC = ddi_prop_op.9f
ddi_getprop.9f				:= LINKSRC = ddi_prop_op.9f
ddi_getproplen.9f			:= LINKSRC = ddi_prop_op.9f

ddi_prop_update_byte_array.9f		:= LINKSRC = ddi_prop_update.9f
ddi_prop_update_int.9f			:= LINKSRC = ddi_prop_update.9f
ddi_prop_update_int64.9f		:= LINKSRC = ddi_prop_update.9f
ddi_prop_update_int64_array.9f		:= LINKSRC = ddi_prop_update.9f
ddi_prop_update_int_array.9f		:= LINKSRC = ddi_prop_update.9f
ddi_prop_update_string.9f		:= LINKSRC = ddi_prop_update.9f
ddi_prop_update_string_array.9f		:= LINKSRC = ddi_prop_update.9f

ddi_put16.9f				:= LINKSRC = ddi_put8.9f
ddi_put32.9f				:= LINKSRC = ddi_put8.9f
ddi_put64.9f				:= LINKSRC = ddi_put8.9f
ddi_putb.9f				:= LINKSRC = ddi_put8.9f
ddi_putl.9f				:= LINKSRC = ddi_put8.9f
ddi_putll.9f				:= LINKSRC = ddi_put8.9f
ddi_putw.9f				:= LINKSRC = ddi_put8.9f

ddi_rep_get16.9f			:= LINKSRC = ddi_rep_get8.9f
ddi_rep_get32.9f			:= LINKSRC = ddi_rep_get8.9f
ddi_rep_get64.9f			:= LINKSRC = ddi_rep_get8.9f
ddi_rep_getb.9f				:= LINKSRC = ddi_rep_get8.9f
ddi_rep_getl.9f				:= LINKSRC = ddi_rep_get8.9f
ddi_rep_getll.9f			:= LINKSRC = ddi_rep_get8.9f
ddi_rep_getw.9f				:= LINKSRC = ddi_rep_get8.9f

ddi_rep_put16.9f			:= LINKSRC = ddi_rep_put8.9f
ddi_rep_put32.9f			:= LINKSRC = ddi_rep_put8.9f
ddi_rep_put64.9f			:= LINKSRC = ddi_rep_put8.9f
ddi_rep_putb.9f				:= LINKSRC = ddi_rep_put8.9f
ddi_rep_putl.9f				:= LINKSRC = ddi_rep_put8.9f
ddi_rep_putll.9f			:= LINKSRC = ddi_rep_put8.9f
ddi_rep_putw.9f				:= LINKSRC = ddi_rep_put8.9f

ddi_segmap_setup.9f			:= LINKSRC = ddi_segmap.9f

ddi_get_soft_state.9f			:= LINKSRC = ddi_soft_state.9f
ddi_soft_state_fini.9f			:= LINKSRC = ddi_soft_state.9f
ddi_soft_state_free.9f			:= LINKSRC = ddi_soft_state.9f
ddi_soft_state_init.9f			:= LINKSRC = ddi_soft_state.9f
ddi_soft_state_zalloc.9f		:= LINKSRC = ddi_soft_state.9f

ddi_strtoull.9f				:= LINKSRC = ddi_strtoll.9f

ddi_umem_free.9f			:= LINKSRC = ddi_umem_alloc.9f

ddi_umem_unlock.9f			:= LINKSRC = ddi_umem_lock.9f

devmap_umem_setup.9f			:= LINKSRC = devmap_devmem_setup.9f

ddi_devmap_segmap.9f			:= LINKSRC = devmap_setup.9f

devmap_load.9f				:= LINKSRC = devmap_unload.9f

dlerrorack.9f				:= LINKSRC = dlbindack.9f
dlokack.9f				:= LINKSRC = dlbindack.9f
dlphysaddrack.9f			:= LINKSRC = dlbindack.9f
dluderrorind.9f				:= LINKSRC = dlbindack.9f

desballoc.9f				:= LINKSRC = esballoc.9f

unfreezestr.9f				:= LINKSRC = freezestr.9f

free_pktiopb.9f				:= LINKSRC = get_pktiopb.9f

gld_intr.9f				:= LINKSRC = gld.9f
gld_mac_alloc.9f			:= LINKSRC = gld.9f
gld_mac_free.9f				:= LINKSRC = gld.9f
gld_recv.9f				:= LINKSRC = gld.9f
gld_register.9f				:= LINKSRC = gld.9f
gld_sched.9f				:= LINKSRC = gld.9f
gld_unregister.9f			:= LINKSRC = gld.9f

id32_free.9f				:= LINKSRC = id32_alloc.9f
id32_lookup.9f				:= LINKSRC = id32_alloc.9f

inl.9f					:= LINKSRC = inb.9f
inw.9f					:= LINKSRC = inb.9f
repinsb.9f				:= LINKSRC = inb.9f
repinsd.9f				:= LINKSRC = inb.9f
repinsw.9f				:= LINKSRC = inb.9f

kmem_free.9f				:= LINKSRC = kmem_alloc.9f
kmem_zalloc.9f				:= LINKSRC = kmem_alloc.9f

kmem_cache_alloc.9f			:= LINKSRC = kmem_cache_create.9f
kmem_cache_destroy.9f			:= LINKSRC = kmem_cache_create.9f
kmem_cache_free.9f			:= LINKSRC = kmem_cache_create.9f
kmem_cache_set_move.9f			:= LINKSRC = kmem_cache_create.9f

kstat_named_setstr.9f			:= LINKSRC = kstat_named_init.9f

kstat_runq_back_to_waitq.9f		:= LINKSRC = kstat_queue.9f
kstat_runq_enter.9f			:= LINKSRC = kstat_queue.9f
kstat_runq_exit.9f			:= LINKSRC = kstat_queue.9f
kstat_waitq_enter.9f			:= LINKSRC = kstat_queue.9f
kstat_waitq_exit.9f			:= LINKSRC = kstat_queue.9f
kstat_waitq_to_runq.9f			:= LINKSRC = kstat_queue.9f

ldi_awrite.9f				:= LINKSRC = ldi_aread.9f

ldi_get_devid.9f			:= LINKSRC = ldi_get_dev.9f
ldi_get_minor_name.9f			:= LINKSRC = ldi_get_dev.9f
ldi_get_otyp.9f				:= LINKSRC = ldi_get_dev.9f

ldi_ident_from_dip.9f			:= LINKSRC = ldi_ident_from_dev.9f
ldi_ident_from_stream.9f		:= LINKSRC = ldi_ident_from_dev.9f
ldi_ident_release.9f			:= LINKSRC = ldi_ident_from_dev.9f

ldi_close.9f				:= LINKSRC = ldi_open_by_dev.9f
ldi_open_by_devid.9f			:= LINKSRC = ldi_open_by_dev.9f
ldi_open_by_name.9f			:= LINKSRC = ldi_open_by_dev.9f

ldi_prop_get_int64.9f			:= LINKSRC = ldi_prop_get_int.9f

ldi_prop_lookup_byte_array.9f		:= LINKSRC = ldi_prop_lookup_int_array.9f
ldi_prop_lookup_int64_array.9f		:= LINKSRC = ldi_prop_lookup_int_array.9f
ldi_prop_lookup_string.9f		:= LINKSRC = ldi_prop_lookup_int_array.9f
ldi_prop_lookup_string_array.9f		:= LINKSRC = ldi_prop_lookup_int_array.9f

ldi_getmsg.9f				:= LINKSRC = ldi_putmsg.9f

ldi_write.9f				:= LINKSRC = ldi_read.9f

list_destroy.9f				:= LINKSRC = list_create.9f
list_head.9f				:= LINKSRC = list_create.9f
list_insert_after.9f			:= LINKSRC = list_create.9f
list_insert_before.9f			:= LINKSRC = list_create.9f
list_insert_head.9f			:= LINKSRC = list_create.9f
list_insert_tail.9f			:= LINKSRC = list_create.9f
list_is_empty.9f			:= LINKSRC = list_create.9f
list_link_active.9f			:= LINKSRC = list_create.9f
list_link_init.9f			:= LINKSRC = list_create.9f
list_link_replace.9f			:= LINKSRC = list_create.9f
list_move_tail.9f			:= LINKSRC = list_create.9f
list_next.9f				:= LINKSRC = list_create.9f
list_prev.9f				:= LINKSRC = list_create.9f
list_remove.9f				:= LINKSRC = list_create.9f
list_remove_head.9f			:= LINKSRC = list_create.9f
list_remove_tail.9f			:= LINKSRC = list_create.9f
list_tail.9f				:= LINKSRC = list_create.9f

makecom_g0.9f				:= LINKSRC = makecom.9f
makecom_g0_s.9f				:= LINKSRC = makecom.9f
makecom_g1.9f				:= LINKSRC = makecom.9f
makecom_g5.9f				:= LINKSRC = makecom.9f

membar_consumer.9f			:= LINKSRC = membar_ops.9f
membar_enter.9f				:= LINKSRC = membar_ops.9f
membar_exit.9f				:= LINKSRC = membar_ops.9f
membar_producer.9f			:= LINKSRC = membar_ops.9f

memcmp.9f				:= LINKSRC = memchr.9f
memcpy.9f				:= LINKSRC = memchr.9f
memmove.9f				:= LINKSRC = memchr.9f
memset.9f				:= LINKSRC = memchr.9f

mod_info.9f				:= LINKSRC = mod_install.9f
mod_modname.9f				:= LINKSRC = mod_install.9f
mod_remove.9f				:= LINKSRC = mod_install.9f

mutex_destroy.9f			:= LINKSRC = mutex.9f
mutex_enter.9f				:= LINKSRC = mutex.9f
mutex_exit.9f				:= LINKSRC = mutex.9f
mutex_init.9f				:= LINKSRC = mutex.9f
mutex_owned.9f				:= LINKSRC = mutex.9f
mutex_tryenter.9f			:= LINKSRC = mutex.9f

net_event_notify_unregister.9f		:= LINKSRC = net_event_notify_register.9f

net_instance_notify_unregister.9f	:= LINKSRC = net_instance_notify_register.9f

net_instance_protocol_unregister.9f	:= LINKSRC = net_protocol_notify_register.9f

nvlist_add_boolean_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_boolean_value.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_byte.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_byte_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int16.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int16_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int32.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int32_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int64.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int64_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int8.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_int8_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_nvlist.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_nvlist_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_nvpair.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_string.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_string_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint16.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint16_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint32.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint32_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint64.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint64_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint8.9f			:= LINKSRC = nvlist_add_boolean.9f
nvlist_add_uint8_array.9f		:= LINKSRC = nvlist_add_boolean.9f
nvlist_t.9f				:= LINKSRC = nvlist_add_boolean.9f

nv_alloc_fini.9f			:= LINKSRC = nvlist_alloc.9f
nv_alloc_init.9f			:= LINKSRC = nvlist_alloc.9f
nvlist_dup.9f				:= LINKSRC = nvlist_alloc.9f
nvlist_free.9f				:= LINKSRC = nvlist_alloc.9f
nvlist_merge.9f				:= LINKSRC = nvlist_alloc.9f
nvlist_pack.9f				:= LINKSRC = nvlist_alloc.9f
nvlist_size.9f				:= LINKSRC = nvlist_alloc.9f
nvlist_unpack.9f			:= LINKSRC = nvlist_alloc.9f
nvlist_xalloc.9f			:= LINKSRC = nvlist_alloc.9f
nvlist_xdup.9f				:= LINKSRC = nvlist_alloc.9f
nvlist_xpack.9f				:= LINKSRC = nvlist_alloc.9f
nvlist_xunpack.9f			:= LINKSRC = nvlist_alloc.9f

nvlist_lookup_boolean_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_boolean_value.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_byte.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_byte_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int16.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int16_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int32.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int32_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int64.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int64_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int8.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_int8_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_nvlist.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_nvlist_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_pairs.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_string.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_string_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint16.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint16_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint32.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint32_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint64.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint64_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint8.9f			:= LINKSRC = nvlist_lookup_boolean.9f
nvlist_lookup_uint8_array.9f		:= LINKSRC = nvlist_lookup_boolean.9f

nvlist_exists.9f			:= LINKSRC = nvlist_lookup_nvpair.9f

nvpair_name.9f				:= LINKSRC = nvlist_next_nvpair.9f
nvpair_type.9f				:= LINKSRC = nvlist_next_nvpair.9f

nvlist_remove_all.9f			:= LINKSRC = nvlist_remove.9f

nvpair_value_boolean_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_byte_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int16.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int16_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int32.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int32_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int64.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int64_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int8.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_int8_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_nvlist.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_nvlist_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_string.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_string_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint16.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint16_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint32.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint32_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint64.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint64_array.9f		:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint8.9f			:= LINKSRC = nvpair_value_byte.9f
nvpair_value_uint8_array.9f		:= LINKSRC = nvpair_value_byte.9f

outl.9f					:= LINKSRC = outb.9f
outw.9f					:= LINKSRC = outb.9f
repoutsb.9f				:= LINKSRC = outb.9f
repoutsd.9f				:= LINKSRC = outb.9f
repoutsw.9f				:= LINKSRC = outb.9f

pci_config_get16.9f			:= LINKSRC = pci_config_get8.9f
pci_config_get32.9f			:= LINKSRC = pci_config_get8.9f
pci_config_get64.9f			:= LINKSRC = pci_config_get8.9f
pci_config_getb.9f			:= LINKSRC = pci_config_get8.9f
pci_config_getl.9f			:= LINKSRC = pci_config_get8.9f
pci_config_getll.9f			:= LINKSRC = pci_config_get8.9f
pci_config_getw.9f			:= LINKSRC = pci_config_get8.9f
pci_config_put16.9f			:= LINKSRC = pci_config_get8.9f
pci_config_put32.9f			:= LINKSRC = pci_config_get8.9f
pci_config_put64.9f			:= LINKSRC = pci_config_get8.9f
pci_config_put8.9f			:= LINKSRC = pci_config_get8.9f
pci_config_putb.9f			:= LINKSRC = pci_config_get8.9f
pci_config_putl.9f			:= LINKSRC = pci_config_get8.9f
pci_config_putll.9f			:= LINKSRC = pci_config_get8.9f
pci_config_putw.9f			:= LINKSRC = pci_config_get8.9f

pci_config_teardown.9f			:= LINKSRC = pci_config_setup.9f

pci_ereport_post.9f			:= LINKSRC = pci_ereport_setup.9f
pci_ereport_teardown.9f			:= LINKSRC = pci_ereport_setup.9f

pci_restore_config_regs.9f		:= LINKSRC = pci_save_config_regs.9f

minphys.9f				:= LINKSRC = physio.9f

pm_idle_component.9f			:= LINKSRC = pm_busy_component.9f

pm_lower_power.9f			:= LINKSRC = pm_raise_power.9f

priv_policy_choice.9f			:= LINKSRC = priv_policy.9f
priv_policy_only.9f			:= LINKSRC = priv_policy.9f

proc_ref.9f				:= LINKSRC = proc_signal.9f
proc_unref.9f				:= LINKSRC = proc_signal.9f

qprocsoff.9f				:= LINKSRC = qprocson.9f

qwait_sig.9f				:= LINKSRC = qwait.9f

rmallocmap_wait.9f			:= LINKSRC = rmallocmap.9f
rmfreemap.9f				:= LINKSRC = rmallocmap.9f

rw_destroy.9f				:= LINKSRC = rwlock.9f
rw_downgrade.9f				:= LINKSRC = rwlock.9f
rw_enter.9f				:= LINKSRC = rwlock.9f
rw_exit.9f				:= LINKSRC = rwlock.9f
rw_init.9f				:= LINKSRC = rwlock.9f
rw_read_locked.9f			:= LINKSRC = rwlock.9f
rw_tryenter.9f				:= LINKSRC = rwlock.9f
rw_tryupgrade.9f			:= LINKSRC = rwlock.9f

scsi_dname.9f				:= LINKSRC = scsi_cname.9f
scsi_mname.9f				:= LINKSRC = scsi_cname.9f
scsi_rname.9f				:= LINKSRC = scsi_cname.9f
scsi_sname.9f				:= LINKSRC = scsi_cname.9f

scsi_dmafree.9f				:= LINKSRC = scsi_dmaget.9f

scsi_sense_cmdspecific_uint64.9f	:= LINKSRC = scsi_ext_sense_fields.9f
scsi_sense_info_uint64.9f		:= LINKSRC = scsi_ext_sense_fields.9f

scsi_hba_detach.9f			:= LINKSRC = scsi_hba_attach_setup.9f

scsi_hba_fini.9f			:= LINKSRC = scsi_hba_init.9f

scsi_hba_pkt_free.9f			:= LINKSRC = scsi_hba_pkt_alloc.9f

scsi_hba_tran_free.9f			:= LINKSRC = scsi_hba_tran_alloc.9f

scsi_ifsetcap.9f			:= LINKSRC = scsi_ifgetcap.9f

scsi_pktfree.9f				:= LINKSRC = scsi_pktalloc.9f
scsi_resalloc.9f			:= LINKSRC = scsi_pktalloc.9f
scsi_resfree.9f				:= LINKSRC = scsi_pktalloc.9f

scsi_sense_asc.9f			:= LINKSRC = scsi_sense_key.9f
scsi_sense_ascq.9f			:= LINKSRC = scsi_sense_key.9f

scsi_unslave.9f				:= LINKSRC = scsi_unprobe.9f

sema_destroy.9f				:= LINKSRC = semaphore.9f
sema_init.9f				:= LINKSRC = semaphore.9f
sema_p.9f				:= LINKSRC = semaphore.9f
sema_p_sig.9f				:= LINKSRC = semaphore.9f
sema_tryp.9f				:= LINKSRC = semaphore.9f
sema_v.9f				:= LINKSRC = semaphore.9f

numtos.9f				:= LINKSRC = stoi.9f

ddi_strdup.9f				:= LINKSRC = string.9f
strcasecmp.9f				:= LINKSRC = string.9f
strcat.9f				:= LINKSRC = string.9f
strchr.9f				:= LINKSRC = string.9f
strcmp.9f				:= LINKSRC = string.9f
strcpy.9f				:= LINKSRC = string.9f
strdup.9f				:= LINKSRC = string.9f
strfree.9f				:= LINKSRC = string.9f
strlcat.9f				:= LINKSRC = string.9f
strlcpy.9f				:= LINKSRC = string.9f
strlen.9f				:= LINKSRC = string.9f
strncasecmp.9f				:= LINKSRC = string.9f
strncat.9f				:= LINKSRC = string.9f
strncmp.9f				:= LINKSRC = string.9f
strncpy.9f				:= LINKSRC = string.9f
strnlen.9f				:= LINKSRC = string.9f
strrchr.9f				:= LINKSRC = string.9f
strspn.9f				:= LINKSRC = string.9f

ddi_taskq_create.9f			:= LINKSRC = taskq.9f
ddi_taskq_destroy.9f			:= LINKSRC = taskq.9f
ddi_taskq_dispatch.9f			:= LINKSRC = taskq.9f
ddi_taskq_resume.9f			:= LINKSRC = taskq.9f
ddi_taskq_suspend.9f			:= LINKSRC = taskq.9f
ddi_taskq_wait.9f			:= LINKSRC = taskq.9f
taskq_suspended.9f			:= LINKSRC = taskq.9f

uconv_u16tou8.9f			:= LINKSRC = uconv_u16tou32.9f
uconv_u32tou16.9f			:= LINKSRC = uconv_u16tou32.9f
uconv_u32tou8.9f			:= LINKSRC = uconv_u16tou32.9f
uconv_u8tou16.9f			:= LINKSRC = uconv_u16tou32.9f
uconv_u8tou32.9f			:= LINKSRC = uconv_u16tou32.9f

usb_alloc_bulk_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_alloc_ctrl_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_alloc_intr_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_alloc_isoc_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_free_bulk_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_free_ctrl_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_free_intr_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_free_isoc_req.9f			:= LINKSRC = usb_alloc_request.9f
usb_client_detach.9f			:= LINKSRC = usb_client_attach.9f

usb_get_if_number.9f			:= LINKSRC = usb_get_alt_if.9f
usb_owns_device.9f			:= LINKSRC = usb_get_alt_if.9f
usb_set_alt_if.9f			:= LINKSRC = usb_get_alt_if.9f

usb_set_cfg.9f				:= LINKSRC = usb_get_cfg.9f

usb_free_descr_tree.9f			:= LINKSRC = usb_get_dev_data.9f
usb_free_dev_data.9f			:= LINKSRC = usb_get_dev_data.9f
usb_print_descr_tree.9f			:= LINKSRC = usb_get_dev_data.9f

usb_pipe_ctrl_xfer_wait.9f		:= LINKSRC = usb_pipe_ctrl_xfer.9f
usb_pipe_stop_intr_polling.9f		:= LINKSRC = usb_pipe_intr_xfer.9f
usb_pipe_stop_isoc_polling.9f		:= LINKSRC = usb_pipe_isoc_xfer.9f

usb_pipe_get_private.9f			:= LINKSRC = usb_pipe_set_private.9f

usb_unregister_hotplug_cbs.9f		:= LINKSRC = usb_register_hotplug_cbs.9f

va_copy.9f				:= LINKSRC = va_arg.9f
va_end.9f				:= LINKSRC = va_arg.9f
va_start.9f				:= LINKSRC = va_arg.9f

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
