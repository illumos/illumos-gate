#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/uts/Makefile.uts

GROUP=bin
FILEMODE=644

#
#	Note that the following headers are present in the kernel but
#	neither installed or shipped as part of the product:
#		cpuid_drv.h:		Private interface for cpuid consumers
#		unix_bb_info.h:		Private interface to kcov
#

i386_HDRS=			\
	agp/agpamd64gart_io.h	\
	agp/agpdefs.h		\
	agp/agpgart_impl.h	\
	agp/agpmaster_io.h	\
	agp/agptarget_io.h	\
	agpgart.h		\
	asy.h			\
	audio/audio810.h	\
	audio/audiohd.h	\
	audio/audioixp.h	\
	fd_debug.h		\
	fdc.h			\
	fdmedia.h		\
	mouse.h			\
	mse.h			\
	vuidmice.h		\
	ucode.h

AVHDRS=				\
	av/iec61883.h

sparc_HDRS= 			\
	audio/audiots.h		\
	audio/am_src2.h		\
	mouse.h			\
	scsi/targets/ssddef.h	\
	$(MDESCHDRS)		\
	$(AVHDRS)

# Generated headers
GENHDRS=			\
	priv_const.h		\
	priv_names.h

CHKHDRS=			\
	acpi_drv.h		\
	acct.h			\
	acctctl.h		\
	acl.h			\
	acl_impl.h		\
	aggr.h			\
	aggr_impl.h		\
	aio.h			\
	aio_impl.h		\
	aio_req.h		\
	aiocb.h			\
	ascii.h			\
	asynch.h		\
	atomic.h		\
	attr.h			\
	audio.h			\
	audiodebug.h		\
	audioio.h		\
	audiovar.h		\
	autoconf.h		\
	auxv.h			\
	auxv_386.h		\
	auxv_SPARC.h		\
	avl.h			\
	avl_impl.h		\
	bitmap.h		\
	bitset.h		\
	bl.h			\
	bmc_intf.h		\
	bofi.h			\
	bofi_impl.h		\
	bpp_io.h		\
	bootstat.h		\
	brand.h			\
	buf.h			\
	bufmod.h		\
	bustypes.h		\
	byteorder.h		\
	callb.h			\
	callo.h			\
	cpucaps.h		\
	cpucaps_impl.h		\
	ccompile.h		\
	cdio.h			\
	cladm.h			\
	class.h			\
	clconf.h		\
	cmlb.h			\
	cmn_err.h		\
	compress.h		\
	condvar.h		\
	condvar_impl.h		\
	conf.h			\
	consdev.h		\
	console.h		\
	contract.h		\
	contract_impl.h		\
	copyops.h		\
	core.h			\
	corectl.h		\
	cpc_impl.h		\
	cpc_pcbe.h		\
	cpr.h			\
	cpupart.h		\
	cpuvar.h		\
	crc32.h			\
	cred.h			\
	cred_impl.h		\
	crtctl.h		\
	cryptmod.h		\
	csiioctl.h		\
	ctf.h			\
	ctfs.h			\
	ctfs_impl.h		\
	ctf_api.h		\
	ctype.h			\
	cyclic.h		\
	cyclic_impl.h		\
	dacf.h			\
	dacf_impl.h		\
	dc_ki.h			\
	ddi.h			\
	ddifm.h			\
	ddifm_impl.h		\
	ddi_intr.h		\
	ddi_intr_impl.h		\
	ddi_impldefs.h		\
	ddi_implfuncs.h		\
	ddi_obsolete.h		\
	ddi_timer.h		\
	ddidevmap.h		\
	ddidmareq.h		\
	ddimapreq.h		\
	ddipropdefs.h		\
	dditypes.h		\
	debug.h			\
	des.h			\
	devctl.h		\
	devcache.h		\
	devcache_impl.h		\
	devid_cache.h		\
	devinfo_impl.h		\
	devops.h		\
	devpolicy.h		\
	devpoll.h		\
	dirent.h		\
	disp.h			\
	dkbad.h			\
	dkio.h			\
	dklabel.h		\
	dl.h			\
	dlpi.h			\
	dld.h			\
	dld_impl.h		\
	dls.h			\
	dls_impl.h		\
	dma_i8237A.h            \
	dnlc.h			\
	door.h			\
	door_data.h		\
	door_impl.h		\
	dtrace.h		\
	dtrace_impl.h		\
	dumpadm.h		\
	dumphdr.h		\
	ecppsys.h		\
	ecppio.h                \
	ecppreg.h               \
	ecppvar.h               \
	efi_partition.h		\
	elf.h			\
	elf_386.h		\
	elf_SPARC.h		\
	elf_notes.h		\
	elf_amd64.h		\
	elftypes.h		\
	emul64.h		\
	emul64cmd.h		\
	emul64var.h		\
	epm.h			\
	errno.h			\
	errorq.h		\
	errorq_impl.h		\
	esunddi.h		\
	ethernet.h		\
	euc.h			\
	eucioctl.h		\
	exacct.h		\
	exacct_catalog.h	\
	exacct_impl.h		\
	exec.h			\
	exechdr.h		\
	extdirent.h		\
	fault.h			\
	fasttrap.h		\
	fasttrap_impl.h		\
	fbio.h			\
	fbuf.h			\
	fcntl.h			\
	fdbuffer.h		\
	fdio.h			\
	feature_tests.h		\
	fem.h			\
	file.h			\
	filio.h			\
	flock.h			\
	flock_impl.h		\
	fork.h			\
	fss.h			\
	fsspriocntl.h		\
	fsid.h			\
	fssnap.h                \
	fssnap_if.h             \
	fstyp.h			\
	ftrace.h		\
	fx.h			\
	fxpriocntl.h		\
	gfs.h			\
	gld.h			\
	gldpriv.h		\
	group.h			\
	hdio.h			\
	hook.h			\
	hook_event.h		\
	hook_impl.h		\
	hwconf.h		\
	ia.h			\
	iapriocntl.h		\
	id32.h			\
	idmap.h 		\
	ieeefp.h		\
	id_space.h		\
	instance.h		\
	int_const.h		\
	int_fmtio.h		\
	int_limits.h		\
	int_types.h		\
	inttypes.h		\
	ioccom.h		\
	ioctl.h			\
	ipc.h			\
	ipc_impl.h		\
	ipc_rctl.h		\
	isa_defs.h		\
	iscsi_authclient.h	\
	iscsi_authclientglue.h	\
	iscsi_protocol.h	\
	jioctl.h		\
	kbd.h			\
	kbdreg.h		\
	kbio.h			\
	kcpc.h			\
	kdi.h			\
	kdi_impl.h		\
	kiconv.h		\
	kiconv_big5_utf8.h	\
	kiconv_cck_common.h	\
	kiconv_cp950hkscs_utf8.h	\
	kiconv_emea1.h		\
	kiconv_emea2.h		\
	kiconv_euckr_utf8.h	\
	kiconv_euctw_utf8.h	\
	kiconv_gb18030_utf8.h	\
	kiconv_gb2312_utf8.h	\
	kiconv_hkscs_utf8.h	\
	kiconv_ja.h		\
	kiconv_ja_jis_to_unicode.h	\
	kiconv_ja_unicode_to_jis.h	\
	kiconv_ko.h		\
	kiconv_latin1.h		\
	kiconv_sc.h		\
	kiconv_tc.h		\
	kiconv_uhc_utf8.h	\
	kiconv_utf8_big5.h	\
	kiconv_utf8_cp950hkscs.h	\
	kiconv_utf8_euckr.h	\
	kiconv_utf8_euctw.h	\
	kiconv_utf8_gb18030.h	\
	kiconv_utf8_gb2312.h	\
	kiconv_utf8_hkscs.h	\
	kiconv_utf8_uhc.h	\
	kidmap.h		\
	klpd.h			\
	klwp.h			\
	kmdb.h			\
	kmem.h			\
	kmem_impl.h		\
	kobj.h			\
	kobj_impl.h		\
	kstat.h			\
	kstr.h			\
	ksyms.h			\
	ksynch.h		\
	ldterm.h		\
	lgrp.h			\
	lgrp_user.h		\
	libc_kernel.h		\
	link.h			\
	list.h			\
	list_impl.h		\
	llc1.h			\
	loadavg.h		\
	lock.h			\
	lockfs.h		\
	lockstat.h		\
	lofi.h			\
	log.h			\
	logindmux.h		\
	logindmux_impl.h	\
	lwp.h			\
	lwp_timer_impl.h	\
	lwp_upimutex_impl.h	\
	mac.h			\
	mac_impl.h		\
	machelf.h		\
	map.h			\
	md4.h			\
	md5.h			\
	md5_consts.h		\
	mdi_impldefs.h		\
	mem.h			\
	mem_config.h		\
	memlist.h		\
	mkdev.h			\
	mhd.h			\
	miiregs.h		\
	mixer.h			\
	mman.h			\
	mntent.h		\
	mntio.h			\
	mnttab.h		\
	modctl.h		\
	mode.h			\
	model.h			\
	modhash.h		\
	modhash_impl.h		\
	mount.h			\
	mouse.h			\
	msacct.h		\
	msg.h			\
	msg_impl.h		\
	msio.h			\
	msreg.h			\
	mtio.h			\
	multidata.h		\
	multidata_impl.h	\
	mutex.h			\
	nbmlock.h		\
	ndifm.h		\
	ndi_impldefs.h		\
	net80211.h		\
	net80211_crypto.h	\
	net80211_proto.h	\
	netconfig.h		\
	neti.h			\
	netstack.h		\
	nexusdefs.h		\
	note.h			\
	nvpair.h                \
	nvpair_impl.h           \
	objfs.h			\
	objfs_impl.h		\
	ontrap.h                \
	open.h			\
	openpromio.h		\
	panic.h			\
	param.h			\
	pathconf.h		\
	pathname.h		\
	pattr.h			\
	queue.h			\
	serializer.h		\
	pbio.h			\
	pccard.h		\
	pci.h			\
	pcie.h			\
	pci_impl.h		\
	pcmcia.h		\
	pctypes.h		\
	pem.h			\
	pfmod.h			\
	pg.h			\
	pghw.h			\
	physmem.h		\
	pm.h			\
	policy.h		\
	poll.h			\
	poll_impl.h		\
	pool.h			\
	pool_impl.h		\
	pool_pset.h		\
	port.h			\
	port_impl.h		\
	port_kernel.h		\
	ppmio.h                 \
	priocntl.h		\
	priv.h			\
	priv_impl.h		\
	prnio.h			\
	proc.h			\
	processor.h		\
	procfs.h		\
	procset.h		\
	project.h		\
	protosw.h		\
	prsystm.h		\
	pset.h			\
	pshot.h			\
	ptem.h			\
	ptms.h			\
	ptyvar.h		\
	raidioctl.h		\
	ramdisk.h		\
	random.h		\
	rctl.h			\
	rctl_impl.h		\
	reboot.h		\
	refstr.h		\
	refstr_impl.h		\
	resource.h		\
	rlioctl.h		\
	rt.h			\
	rtpriocntl.h		\
	rwlock.h		\
	rwlock_impl.h		\
	rwstlock.h		\
	sad.h			\
	schedctl.h		\
	sdt.h			\
	select.h		\
	sem.h			\
	sem_impl.h		\
	sema_impl.h		\
	semaphore.h		\
	sendfile.h		\
	ser_sync.h		\
	session.h		\
	sha1.h			\
	sha1_consts.h		\
	sha2.h			\
	sha2_consts.h		\
	share.h			\
	shm.h			\
	shm_impl.h		\
	sid.h			\
	siginfo.h		\
	signal.h		\
	sleepq.h		\
	smbios.h		\
	smbios_impl.h		\
	sobject.h		\
	socket.h		\
	socket_impl.h		\
	socketvar.h		\
	sockio.h		\
	squeue.h		\
	squeue_impl.h		\
	srn.h			\
	sservice.h		\
	stat.h			\
	statfs.h		\
	statvfs.h		\
	stdint.h		\
	stermio.h		\
	stream.h		\
	strft.h			\
	strlog.h		\
	strmdep.h		\
	stropts.h		\
	strredir.h		\
	strstat.h		\
	strsubr.h		\
	strsun.h		\
	strtty.h		\
	sunddi.h		\
	sunldi.h		\
	sunldi_impl.h		\
	sunmdi.h		\
	sunndi.h		\
	sunos_dhcp_class.h	\
	sunpm.h			\
	suntpi.h		\
	suntty.h		\
	swap.h			\
	synch.h			\
	syscall.h		\
	sysconf.h		\
	sysconfig.h		\
	sysevent.h		\
	sysevent_impl.h         \
	sysinfo.h		\
	syslog.h		\
	sysmacros.h		\
	sysmsg_impl.h		\
	systeminfo.h		\
	systm.h			\
	task.h			\
	taskq.h			\
	taskq_impl.h		\
	t_kuser.h		\
	t_lock.h		\
	telioctl.h		\
	termio.h		\
	termios.h		\
	termiox.h		\
	thread.h		\
	ticlts.h		\
	ticots.h		\
	ticotsord.h		\
	tihdr.h			\
	time.h			\
	time_impl.h		\
	time_std_impl.h		\
	timeb.h			\
	timer.h			\
	times.h			\
	timex.h			\
	timod.h			\
	tirdwr.h		\
	tiuser.h		\
	tl.h			\
	tnf.h			\
	tnf_com.h		\
	tnf_probe.h		\
	tnf_writer.h		\
	todio.h			\
	tpicommon.h		\
	ts.h			\
	tspriocntl.h		\
	ttcompat.h		\
	ttold.h			\
	tty.h			\
	ttychars.h		\
	ttydev.h		\
	tuneable.h		\
	turnstile.h		\
	types.h			\
	types32.h		\
	tzfile.h		\
	u8_textprep.h		\
	u8_textprep_data.h	\
	uadmin.h		\
	ucred.h			\
	uio.h			\
	ulimit.h		\
	un.h			\
	unistd.h		\
	user.h			\
	ustat.h			\
	utime.h			\
	utsname.h		\
	utssys.h		\
	uuid.h			\
	va_impl.h		\
	va_list.h		\
	var.h			\
	varargs.h		\
	vfs.h			\
	vfs_opreg.h		\
	vfstab.h		\
	vgareg.h		\
	videodev2.h		\
	visual_io.h		\
	vlan.h			\
	vm.h			\
	vm_usage.h		\
	vmem.h			\
	vmem_impl.h		\
	vmmeter.h		\
	vmsystm.h		\
	vnic.h			\
	vnic_impl.h		\
	vnode.h			\
	vscan.h			\
	vtoc.h			\
	vtrace.h		\
	vuid_event.h		\
	vuid_wheel.h		\
	vuid_queue.h		\
	vuid_state.h		\
	vuid_store.h		\
	wait.h			\
	waitq.h			\
	wanboot_impl.h		\
	watchpoint.h		\
	winlockio.h		\
	zcons.h			\
	zone.h			\
	xti_inet.h		\
	xti_osi.h		\
	xti_xtiopt.h		\
	zmod.h

HDRS=				\
	$(GENHDRS)		\
	$(CHKHDRS)

AUDIOHDRS=			\
	ac97.h			\
	am_src1.h		\
	audio_apm.h		\
	audio_mixer.h		\
	audio_src.h		\
	audio_support.h		\
	audio_trace.h		\
	g711.h

BSCHDRS=			\
	bscbus.h		\
	bscv_impl.h		\
	lom_ebuscodes.h		\
	lom_io.h		\
	lom_priv.h		\
	lombus.h

MDESCHDRS=			\
	mdesc.h			\
	mdesc_impl.h		

CPUDRVHDRS=			\
	cpudrv.h

CRYPTOHDRS=			\
	elfsign.h		\
	ioctl.h			\
	ioctladmin.h		\
	common.h		\
	impl.h			\
	spi.h			\
	api.h			\
	ops_impl.h		\
	sched_impl.h

DCAMHDRS=			\
	dcam1394_io.h

IBHDRS=			\
	ib_types.h	\
	ib_pkt_hdrs.h

IBTLHDRS=		\
	ibtl_types.h	\
	ibtl_status.h	\
	ibti.h		\
	ibti_cm.h	\
	ibci.h		\
	ibti_common.h	\
	ibvti.h		\
	ibtl_ci_types.h

IBTLIMPLHDRS=		\
	ibtl_util.h

IBNEXHDRS=		\
	ibnex_devctl.h

IBMFHDRS=		\
	ibmf.h		\
	ibmf_msg.h	\
	ibmf_saa.h	\
	ibmf_utils.h

IBMGTHDRS=		\
	ib_dm_attr.h	\
	ib_mad.h	\
	sm_attr.h	\
	sa_recs.h

IBDHDRS=		\
	ibd.h

ISOHDRS=			\
	signal_iso.h

DERIVED_LVMHDRS=	\
	md_mdiox.h		\
	md_basic.h		\
	mdmed.h			\
	md_mhdx.h		\
	mdmn_commd.h

LVMHDRS=			\
	md_convert.h		\
	md_crc.h		\
	md_hotspares.h		\
	md_mddb.h		\
	md_mirror.h		\
	md_mirror_shared.h	\
	md_names.h		\
	md_notify.h		\
	md_raid.h		\
	md_rename.h		\
	md_sp.h			\
	md_stripe.h		\
	md_trans.h		\
	mdio.h			\
	mdvar.h			

ALL_LVMHDRS=			\
	$(LVMHDRS)		\
	$(DERIVED_LVMHDRS)

FMHDRS=				\
	protocol.h		\
	util.h

FMFSHDRS=			\
	zfs.h

FMIOHDRS=			\
	ddi.h			\
	disk.h			\
	pci.h			\
	scsi.h			\
	sun4upci.h		\
	opl_mc_fm.h

FSHDRS=				\
	autofs.h		\
	cachefs_dir.h		\
	cachefs_dlog.h		\
	cachefs_filegrp.h	\
	cachefs_fs.h		\
	cachefs_fscache.h	\
	cachefs_ioctl.h		\
	cachefs_log.h		\
	decomp.h		\
	dv_node.h		\
	sdev_impl.h		\
	sdev_node.h		\
	fifonode.h		\
	hsfs_isospec.h		\
	hsfs_node.h		\
	hsfs_rrip.h		\
	hsfs_spec.h		\
	hsfs_susp.h		\
	lofs_info.h		\
	lofs_node.h		\
	mntdata.h		\
	namenode.h		\
	pc_dir.h		\
	pc_fs.h			\
	pc_label.h		\
	pc_node.h		\
	pxfs_ki.h		\
	snode.h			\
	swapnode.h		\
	tmp.h			\
	tmpnode.h		\
	udf_inode.h		\
	udf_volume.h		\
	ufs_acl.h		\
	ufs_bio.h		\
	ufs_filio.h		\
	ufs_fs.h		\
	ufs_fsdir.h		\
	ufs_inode.h		\
	ufs_lockfs.h		\
	ufs_log.h		\
	ufs_mount.h		\
	ufs_panic.h		\
	ufs_prot.h		\
	ufs_quota.h		\
	ufs_snap.h              \
	ufs_trans.h		\
	zfs.h

PCMCIAHDRS=		\
	pcata.h		\
	pcgld.h		\
	pcramio.h	\
	pcramvar.h	\
	pcser_conf.h	\
	pcser_io.h	\
	pcser_reg.h	\
	pcser_manuspec.h \
	pcser_var.h

SCSIHDRS=		\
	scsi.h		\
	scsi_address.h	\
	scsi_ctl.h	\
	scsi_params.h	\
	scsi_pkt.h	\
	scsi_resource.h	\
	scsi_types.h	\
	scsi_watch.h

SCSICONFHDRS=		\
	autoconf.h	\
	device.h

SCSIGENHDRS=		\
	commands.h	\
	dad_mode.h	\
	inquiry.h	\
	message.h	\
	mode.h		\
	persist.h	\
	sense.h		\
	smp_frames.h	\
	status.h

SCSIIMPLHDRS=		\
	commands.h	\
	inquiry.h	\
	mode.h		\
	sas_transport.h	\
	sense.h		\
	services.h	\
	status.h	\
	transport.h	\
	scsi_reset_notify.h \
	spc3_types.h	\
	types.h		\
	uscsi.h		\
	usmp.h

SCSITARGETSHDRS=	\
	ses.h		\
	sesio.h		\
	sgendef.h	\
	stdef.h		\
	sddef.h		\
	smp.h

SCSICADHDRS=

SCSIVHCIHDRS=		\
	scsi_vhci.h	\
	mpapi_impl.h	\
	mpapi_scsi_vhci.h

FCHDRS=			\
	fc_transport.h	\
	linkapp.h	\
	fc.h		\
	fcp.h		\
	fcal_transport.h \
	fcal.h		\
	fcal_linkapp.h	\
	fcio.h

SATAGENHDRS=		\
	sata_hba.h	\
	sata_defs.h	\
	sata_cfgadm.h

SYSEVENTHDRS=		\
	ap_driver.h     \
	dev.h		\
	domain.h        \
	dr.h            \
	env.h           \
	eventdefs.h	\
	ipmp.h		\
	pwrctl.h	\
	svm.h

CONTRACTHDRS=		\
	process.h	\
	process_impl.h	\
	device.h	\
	device_impl.h

USBHDRS=	\
	usba.h	\
	usbai.h

USBAUDHDRS=           \
	usb_audio.h

USBHUBDHDRS=		\
	hub.h		\
	hubd_impl.h

USBHIDHDRS=		\
	hid.h

USBMSHDRS=		\
	usb_bulkonly.h	\
	usb_cbi.h

USBPRNHDRS=           \
	usb_printer.h

USBCDCHDRS=		\
	usb_cdc.h

USBVIDHDRS=           \
	usbvc.h

UGENHDRS=           \
	usb_ugen.h

HOTPLUGHDRS=	\
	hpcsvc.h	\
	hpctrl.h

HOTPLUGPCIHDRS=	\
	pcicfg.h	\
	pcihp.h

RSMHDRS= \
	rsm.h	\
	rsm_common.h	\
	rsmapi_common.h \
	rsmpi.h	\
	rsmpi_driver.h	\
	rsmka_path_int.h

TSOLHDRS=		\
	label.h		\
	label_macro.h	\
	priv.h		\
	tndb.h		\
	tsyscall.h

I1394HDRS=		\
	cmd1394.h	\
	id1394.h	\
	ieee1212.h	\
	ieee1394.h	\
	ixl1394.h	\
	s1394_impl.h	\
	t1394.h

# "cmdk" headers used on sparc
SDKTPHDRS=		\
	dadkio.h	\
	fdisk.h

# "cmdk" headers used on i386
DKTPHDRS=		\
	altsctr.h	\
	bbh.h		\
	cm.h		\
	cmdev.h		\
	cmdk.h		\
	cmpkt.h		\
	controller.h	\
	dadev.h		\
	dadk.h		\
	dadkio.h	\
	fctypes.h	\
	fdisk.h		\
	flowctrl.h	\
	gda.h		\
	quetypes.h	\
	queue.h		\
	tgcom.h		\
	tgdk.h

# "pc" header files used on i386
PCHDRS=			\
	avintr.h	\
	dma_engine.h	\
	i8272A.h	\
	pcic_reg.h	\
	pcic_var.h	\
	pic.h		\
	pit.h		\
	rtc.h

NXGEHDRS=			\
	nxge.h			\
	nxge_common.h		\
	nxge_common_impl.h	\
	nxge_defs.h		\
	nxge_hw.h		\
	nxge_impl.h		\
	nxge_ipp.h		\
	nxge_ipp_hw.h		\
	nxge_mac.h		\
	nxge_mac_hw.h		\
	nxge_fflp.h		\
	nxge_fflp_hw.h		\
	nxge_mii.h		\
	nxge_rxdma.h		\
	nxge_rxdma_hw.h		\
	nxge_txc.h		\
	nxge_txc_hw.h		\
	nxge_txdma.h		\
	nxge_txdma_hw.h		\
	nxge_virtual.h		\
	nxge_espc.h

include Makefile.syshdrs

dcam/%.check:	dcam/%.h
	$(DOT_H_CHECK)

CHECKHDRS=						\
	$($(MACH)_HDRS:%.h=%.check)			\
	$(AUDIOHDRS:%.h=audio/%.check)			\
	$(BSCHDRS:%.h=%.check)				\
	$(CHKHDRS:%.h=%.check)				\
	$(CPUDRVHDRS:%.h=%.check)			\
	$(CRYPTOHDRS:%.h=crypto/%.check)		\
	$(DCAMHDRS:%.h=dcam/%.check)			\
	$(IBHDRS:%.h=ib/%.check)			\
	$(IBDHDRS:%.h=ib/clients/ibd/%.check)		\
	$(IBTLHDRS:%.h=ib/ibtl/%.check)			\
	$(IBTLIMPLHDRS:%.h=ib/ibtl/impl/%.check)	\
	$(IBNEXHDRS:%.h=ib/ibnex/%.check)	\
	$(IBMGTHDRS:%.h=ib/mgt/%.check)			\
	$(IBMFHDRS:%.h=ib/mgt/ibmf/%.check)		\
	$(TAVORHDRS:%.h=ib/adapters/tavor/%.check)	\
	$(ISOHDRS:%.h=iso/%.check)			\
	$(FMHDRS:%.h=fm/%.check)			\
	$(FMFSHDRS:%.h=fm/fs/%.check)			\
	$(FMIOHDRS:%.h=fm/io/%.check)			\
	$(FSHDRS:%.h=fs/%.check)			\
	$(LVMHDRS:%.h=lvm/%.check)			\
	$(PCMCIAHDRS:%.h=pcmcia/%.check)		\
	$(SCSIHDRS:%.h=scsi/%.check)			\
	$(SCSICONHDRS:%.h=scsi/conf/%.check)		\
	$(SCSIIMPLHDRS:%.h=scsi/impl/%.check)		\
	$(SCSITARGETSHDRS:%.h=scsi/targets/%.check)	\
	$(SCSIVHCIHDRS:%.h=scsi/adapters/%.check)	\
	$(FCHDRS:%.h=fc4/%.check)			\
	$(SATAGENHDRS:%.h=sata/%.check)			\
	$(SYSEVENTHDRS:%.h=sysevent/%.check)            \
	$(CONTRACTHDRS:%.h=contract/%.check)            \
	$(USBAUDHDRS:%.h=usb/clients/audio/%.check)   \
	$(USBHUBDHDRS:%.h=usb/hubd/%.check)		\
	$(USBHIDHDRS:%.h=usb/clients/hid/%.check)	\
	$(USBMSHDRS:%.h=usb/clients/mass_storage/%.check)	\
	$(USBPRNHDRS:%.h=usb/clients/printer/%.check)   \
	$(USBCDCHDRS:%.h=usb/clients/usbcdc/%.check)	\
	$(USBVIDHDRS:%.h=usb/clients/video/usbvc/%.check)   \
	$(UGENHDRS:%.h=usb/clients/ugen/%.check)   \
	$(USBHDRS:%.h=usb/%.check)                      \
	$(I1394HDRS:%.h=1394/%.check)			\
	$(RSMHDRS:%.h=rsm/%.check)			\
	$(TSOLHDRS:%.h=tsol/%.check)			\
	$(NXGEHDRS:%.h=nxge/%.check)


.KEEP_STATE:

.PARALLEL:			\
	$(CHECKHDRS)		\
	$(ROOTHDRS)		\
	$(ROOTAUDHDRS)		\
	$(ROOTCRYPTOHDRS)	\
	$(ROOTDCAMHDRS)		\
	$(ROOTISOHDRS)		\
	$(ROOTFMHDRS)		\
	$(ROOTFMIOHDRS)		\
	$(ROOTFMFSHDRS)		\
	$(ROOTFSHDRS)		\
	$(ROOTIBDHDRS)		\
	$(ROOTIBHDRS)		\
	$(ROOTIBTLHDRS)		\
	$(ROOTIBTLIMPLHDRS)	\
	$(ROOTIBNEXHDRS)	\
	$(ROOTIBMGTHDRS)	\
	$(ROOTIBMFHDRS)		\
	$(ROOTTAVORHDRS)	\
	$(ROOTLVMHDRS)		\
	$(ROOTPCMCIAHDRS)	\
	$(ROOTSCSIHDRS)		\
	$(ROOTSCSICONFHDRS)	\
	$(ROOTSCSIGENHDRS)	\
	$(ROOTSCSIIMPLHDRS)	\
	$(ROOTSCSIVHCIHDRS)	\
	$(ROOTFCHDRS)		\
	$(ROOTSYSEVENTHDRS)     \
	$(ROOTCONTRACTHDRS)     \
	$(ROOTUSBHDRS)		\
	$(ROOTUSBAUDHDRS)	\
	$(ROOTUSBHUBDHDRS)	\
	$(ROOTUSBHIDHDRS)	\
	$(ROOTUSBMSHDRS)	\
	$(ROOTUSBPRNHDRS)       \
	$(ROOTUSBCDCHDRS)       \
	$(ROOTUSBVIDHDRS)       \
	$(ROOTUGENHDRS)		\
	$(ROOT1394HDRS)         \
	$(ROOTHOTPLUGHDRS)	\
	$(ROOTHOTPLUGPCIHDRS)	\
	$(ROOTRSMHDRS)		\
	$(ROOTTSOLHDRS)		\
	$($(MACH)_ROOTHDRS)


install_h:			\
	$(ROOTDIRS)		\
	LVMDERIVED_H		\
	.WAIT			\
	$(ROOTHDRS)		\
	$(ROOTAUDHDRS)		\
	$(ROOTCRYPTOHDRS)	\
	$(ROOTDCAMHDRS)		\
	$(ROOTISOHDRS)		\
	$(ROOTFMHDRS)		\
	$(ROOTFMFSHDRS)		\
	$(ROOTFMIOHDRS)		\
	$(ROOTFSHDRS)		\
	$(ROOTIBDHDRS)		\
	$(ROOTIBHDRS)		\
	$(ROOTIBTLHDRS)		\
	$(ROOTIBTLIMPLHDRS)	\
	$(ROOTIBNEXHDRS)	\
	$(ROOTIBMGTHDRS)	\
	$(ROOTIBMFHDRS)		\
	$(ROOTTAVORHDRS)	\
	$(ROOTLVMHDRS)		\
	$(ROOTPCMCIAHDRS)	\
	$(ROOTSCSIHDRS)		\
	$(ROOTSCSICONFHDRS)	\
	$(ROOTSCSIGENHDRS)	\
	$(ROOTSCSIIMPLHDRS)	\
	$(ROOTSCSIVHCIHDRS)	\
	$(ROOTFCHDRS)		\
	$(ROOTSYSEVENTHDRS)     \
	$(ROOTCONTRACTHDRS)     \
	$(ROOTUSBHDRS)		\
	$(ROOTUSBAUDHDRS)	\
	$(ROOTUSBHUBDHDRS)	\
	$(ROOTUSBHIDHDRS)	\
	$(ROOTUSBMSHDRS)	\
	$(ROOTUSBPRNHDRS)       \
	$(ROOTUSBCDCHDRS)       \
	$(ROOTUSBVIDHDRS)       \
	$(ROOTUGENHDRS)		\
	$(ROOT1394HDRS)         \
	$(ROOTHOTPLUGHDRS)	\
	$(ROOTHOTPLUGPCIHDRS)	\
	$(ROOTRSMHDRS)		\
	$(ROOTTSOLHDRS)		\
	$($(MACH)_ROOTHDRS)

all_h: $(GENHDRS)

priv_const.h: $(PRIVS_AWK) $(PRIVS_DEF)
	$(NAWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) -v privhfile=$@

priv_names.h: $(PRIVS_AWK) $(PRIVS_DEF)
	$(NAWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) -v pubhfile=$@

LVMDERIVED_H:
	cd $(SRC)/uts/common/sys/lvm; pwd; $(MAKE)

check:	$(CHECKHDRS)

FRC:

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) wanboot_impl.h+ Makefile+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< wanboot_impl.h > wanboot_impl.h+
	$(MV) wanboot_impl.h+ wanboot_impl.h
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(RM) Makefile
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile wanboot_impl.h
# EXPORT DELETE END
