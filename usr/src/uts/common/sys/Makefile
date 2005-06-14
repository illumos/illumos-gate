#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
	audio/audiovia823x.h	\
	fd_debug.h		\
	fdc.h			\
	fdmedia.h		\
	mse.h			\
	vuidmice.h

AVHDRS=				\
	av/iec61883.h

sparc_HDRS= 			\
	audio/audiots.h		\
	audio/am_src2.h		\
	scsi/targets/ssddef.h	\
	$(MDESCHDRS)		\
	$(AVHDRS)

# Generated headers
GENHDRS=			\
	priv_const.h		\
	priv_names.h

CHKHDRS=			\
	acct.h			\
	acctctl.h		\
	acl.h			\
	aggr.h			\
	aggr_impl.h		\
	aio.h			\
	aio_impl.h		\
	aio_req.h		\
	aiocb.h			\
	ascii.h			\
	atomic.h		\
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
	battery.h		\
	bitmap.h		\
	bl.h			\
	bofi.h			\
	bofi_impl.h		\
	bpp_io.h		\
	bootstat.h		\
	buf.h			\
	bufmod.h		\
	bustypes.h		\
	byteorder.h		\
	callb.h			\
	callo.h			\
	ccompile.h		\
	cdio.h			\
	chip.h			\
	cladm.h			\
	class.h			\
	clconf.h		\
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
	ddidevmap.h		\
	ddidmareq.h		\
	ddimapreq.h		\
	ddipropdefs.h		\
	dditypes.h		\
	debug.h			\
	des.h			\
	devctl.h		\
	devctl_impl.h		\
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
	elf_M32.h		\
	elf_SPARC.h		\
	elf_ia64.h		\
	elf_notes.h		\
	elf_amd64.h		\
	elftypes.h		\
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
	ght.h			\
	gld.h			\
	gldpriv.h		\
	hdio.h			\
	hwconf.h		\
	ia.h			\
	iapriocntl.h		\
	id32.h			\
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
	ioreq.h			\
	ipc.h			\
	ipc_impl.h		\
	isa_defs.h		\
	jioctl.h		\
	kbd.h			\
	kbdreg.h		\
	kbio.h			\
	kcpc.h			\
	kdi.h			\
	kdi_impl.h		\
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
	link.h			\
	list.h			\
	list_impl.h		\
	llc1.h			\
	llc2.h			\
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
	map.h			\
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
	netconfig.h		\
	nexusdefs.h		\
	nexusintr.h		\
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
	serializer.h		\
	pbio.h			\
	pccard.h		\
	pci.h			\
	pci_impl.h		\
	pcmcia.h		\
	pctypes.h		\
	pem.h			\
	pfmod.h			\
	phx.h			\
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
	siginfo.h		\
	signal.h		\
	sleepq.h		\
	sobject.h		\
	socket.h		\
	socket_impl.h		\
	socketvar.h		\
	sockio.h		\
	squeue.h		\
	squeue_impl.h		\
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
	sysevent.h	\
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
	vfstab.h		\
	vgareg.h		\
	visual_io.h		\
	vm.h			\
	vmem.h			\
	vmem_impl.h		\
	vmmeter.h		\
	vmsystm.h		\
	vnode.h			\
	vol.h			\
	vtoc.h			\
	vtrace.h		\
	vuid_event.h		\
	vuid_wheel.h		\
	vuid_queue.h		\
	vuid_state.h		\
	vuid_store.h		\
	wait.h			\
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
	audioens.h		\
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

TAVORHDRS=		\
	tavor_ioctl.h

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

sparc_FMCPUHDRS=		\
	UltraSPARC-II.h		\
	UltraSPARC-III.h
FMCPUHDRS=$($(MACH)_FMCPUHDRS)

FMIOHDRS=			\
	ddi.h			\
	pci.h			\
	sun4upci.h

FSHDRS=				\
	autofs.h		\
	cachefs_dir.h		\
	cachefs_dlog.h		\
	cachefs_filegrp.h	\
	cachefs_fs.h		\
	cachefs_fscache.h	\
	cachefs_ioctl.h		\
	cachefs_log.h		\
	dv_node.h		\
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
	ufs_trans.h

PCMCIAHDRS=		\
	pcata.h		\
	pcelx.h		\
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
	sense.h		\
	status.h

SCSIIMPLHDRS=		\
	commands.h	\
	inquiry.h	\
	mode.h		\
	pkt_wrapper.h	\
	sense.h		\
	services.h	\
	status.h	\
	transport.h	\
	scsi_reset_notify.h \
	types.h		\
	uscsi.h

SCSITARGETSHDRS=	\
	ses.h		\
	sesio.h		\
	stdef.h		\
	sddef.h		\
	sgendef.h

SCSICADHDRS=		\
	glmreg.h	\
	glmvar.h	\
	mptreg.h	\
	mptvar.h

SCSIVHCIHDRS=		\
	scsi_vhci.h

FCHDRS=			\
	fc_transport.h	\
	linkapp.h	\
	fc.h		\
	fcp.h		\
	fcal_transport.h \
	fcal.h		\
	fcal_linkapp.h	\
	fcio.h

SYSEVENTHDRS=		\
	ap_driver.h     \
	dev.h		\
	domain.h        \
	dr.h            \
	env.h           \
	eventdefs.h	\
	ipmp.h		\
	svm.h

CONTRACTHDRS=		\
	process.h	\
	process_impl.h

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
	dklb.h		\
	fctypes.h	\
	fdisk.h		\
	flowctrl.h	\
	gda.h		\
	hba.h		\
	objmgr.h	\
	quetypes.h	\
	queue.h		\
	snlb.h		\
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

# I2O header files (currently used only on i386)
I2OHDRS=		\
	i2oadptr.h	\
	i2obscsi.h	\
	i2oexec.h	\
	i2omsg.h	\
	i2omstr.h	\
	i2outil.h

# SVVS headers and other excluded headers
XHDRS=		\
	lo.h	\
	tidg.h	\
	tivc.h	\
	tmux.h

# check files really don't exist

audio/%.check:	audio/%.h
	$(DOT_H_CHECK)

av/%.check:	av/%.h
	$(DOT_H_CHECK)

fm/%.check:     fm/%.h
	$(DOT_H_CHECK)

fm/cpu/%.check:     fm/cpu/%.h
	$(DOT_H_CHECK)

fm/io/%.check:     fm/io/%.h
	$(DOT_H_CHECK)

fs/%.check:	fs/%.h
	$(DOT_H_CHECK)

ib/%.check:		ib/%.h
	$(DOT_H_CHECK)

ib/clients/ibd/%.check:	ib/clients/ibd/%.h
	$(DOT_H_CHECK)

ib/ibtl/%.check:	ib/ibtl/%.h
	$(DOT_H_CHECK)

ib/ibtl/impl/%.check:	ib/ibtl/impl/%.h
	$(DOT_H_CHECK)

ib/ibnex/%.check:	ib/ibnex/%.h
	$(DOT_H_CHECK)

ib/mgt/%.check:	ib/mgt/%.h
	$(DOT_H_CHECK)

ib/mgt/ibmf/%.check:	ib/mgt/ibmf/%.h
	$(DOT_H_CHECK)

ib/adapters/tavor/%.check:	ib/adapters/tavor/%.h
	$(DOT_H_CHECK)

lvm/%.check:	lvm/%.h
	$(DOT_H_CHECK)

pcmcia/%.check:	pcmcia/%.h
	$(DOT_H_CHECK)

scsi/%.check:		scsi/%.h
	$(DOT_H_CHECK)

scsi/conf/%.check:	scsi/conf/%.h
	$(DOT_H_CHECK)

scsi/generic/%.check:	scsi/generic/%.h
	$(DOT_H_CHECK)

scsi/impl/%.check:	scsi/impl/%.h
	$(DOT_H_CHECK)

scsi/targets/%.check:	scsi/targets/%.h
	$(DOT_H_CHECK)

scsi/adapters/%.check:	scsi/adapters/%.h
	$(DOT_H_CHECK)

sysevent/%.check:     sysevent/%.h
	$(DOT_H_CHECK)

contract/%.check:     contract/%.h
	$(DOT_H_CHECK)

usb/%.check:		usb/%.h
	$(DOT_H_CHECK)

usb/clients/audio/%.check:  usb/clients/audio/%.h
	$(DOT_H_CHECK)

usb/hubd/%.check:	usb/hubd/%.h
	$(DOT_H_CHECK)

usb/clients/hid/%.check:	usb/clients/hid/%.h
	$(DOT_H_CHECK)

usb/clients/mass_storage/%.check:	usb/clients/mass_storage/%.h
	$(DOT_H_CHECK)

usb/clients/hid/%.check:	usb/clients/hid/%.h
	$(DOT_H_CHECK)

usb/clients/printer/%.check:  usb/clients/printer/%.h
	$(DOT_H_CHECK)

1394/%.check:         1394/%.h
	$(DOT_H_CHECK)

rsm/%.check:	rsm/%.h
	$(DOT_H_CHECK)

CHECKHDRS=						\
	$($(MACH)_HDRS:%.h=%.check)			\
	$(AUDIOHDRS:%.h=audio/%.check)			\
	$(BSCHDRS:%.h=%.check)				\
	$(CHKHDRS:%.h=%.check)				\
	$(CRYPTOHDRS:%.h=crypto/%.check)		\
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
	$(FMCPUHDRS:%.h=fm/cpu/%.check)			\
	$(FMIOHDRS:%.h=fm/io/%.check)			\
	$(FSHDRS:%.h=fs/%.check)			\
	$(LVMHDRS:%.h=lvm/%.check)			\
	$(XHDRS:%.h=%.check)				\
	$(PCMCIAHDRS:%.h=pcmcia/%.check)		\
	$(SCSIHDRS:%.h=scsi/%.check)			\
	$(SCSICONHDRS:%.h=scsi/conf/%.check)		\
	$(SCSIIMPLHDRS:%.h=scsi/impl/%.check)		\
	$(SCSITARGETSHDRS:%.h=scsi/targets/%.check)	\
	$(SCSIVHCIHDRS:%.h=scsi/adapters/%.check)	\
	$(FCHDRS:%.h=fc4/%.check)			\
	$(SYSEVENTHDRS:%.h=sysevent/%.check)            \
	$(CONTRACTHDRS:%.h=contract/%.check)            \
	$(USBAUDHDRS:%.h=usb/clients/audio/%.check)   \
	$(USBHUBDHDRS:%.h=usb/hubd/%.check)		\
	$(USBHIDHDRS:%.h=usb/clients/hid/%.check)	\
	$(USBMSHDRS:%.h=usb/clients/mass_storage/%.check)	\
	$(USBPRNHDRS:%.h=usb/clients/printer/%.check)   \
	$(UGENHDRS:%.h=usb/clients/ugen/%.check)   \
	$(USBHDRS:%.h=usb/%.check)                      \
	$(I1394HDRS:%.h=1394/%.check)			\
	$(RSMHDRS:%.h=rsm/%.check)


ROOTDIR=	$(ROOT)/usr/include/sys

ROOTDKTPDIR=	$(ROOTDIR)/dktp

sparc_ROOTDIRS=	$(ROOTDKTPDIR) $(ROOTDIR)/scsi/adapters \
		$(ROOTDIR)/scsi/targets \
		$(ROOTDIR)/av

i386_ROOTDIRS=	$(ROOTDKTPDIR) $(ROOTDIR)/scsi/adapters $(ROOTDIR)/scsi/targets \
		$(ROOTDIR)/i2o $(ROOTDIR)/agp

ROOTDIRS=			\
	$(ROOTDIR)		\
	$(ROOTDIR)/audio	\
	$(ROOTDIR)/hotplug	\
	$(ROOTDIR)/hotplug/pci	\
	$(ROOTDIR)/crypto	\
	$(ROOTDIR)/iso		\
	$(ROOTDIR)/fm		\
	$(ROOTDIR)/fm/cpu	\
	$(ROOTDIR)/fm/io	\
	$(ROOTDIR)/fs		\
	$(ROOTDIR)/ib		\
	$(ROOTDIR)/ib/adapters/tavor	\
	$(ROOTDIR)/ib/ibtl	\
	$(ROOTDIR)/ib/ibtl/impl	\
	$(ROOTDIR)/ib/mgt	\
	$(ROOTDIR)/ib/mgt/ibmf	\
	$(ROOTDIR)/ib/ibnex	\
	$(ROOTDIR)/ib/clients/ibd \
	$(ROOTDIR)/lvm		\
	$(ROOTDIR)/pcmcia	\
	$(ROOTDIR)/scsi		\
	$(ROOTDIR)/scsi/conf	\
	$(ROOTDIR)/scsi/generic	\
	$(ROOTDIR)/scsi/impl	\
	$(ROOTDIR)/fc4		\
	$(ROOTDIR)/sysevent     \
	$(ROOTDIR)/contract     \
	$(ROOTDIR)/usb		\
	$(ROOTDIR)/usb/hubd	\
	$(ROOTDIR)/usb/clients	\
	$(ROOTDIR)/usb/clients/audio  \
	$(ROOTDIR)/usb/clients/hid \
	$(ROOTDIR)/usb/clients/mass_storage	\
	$(ROOTDIR)/usb/clients/printer  \
	$(ROOTDIR)/usb/clients/ugen  \
	$(ROOTDIR)/1394         \
	$(ROOTDIR)/rsm		\
	$($(MACH)_ROOTDIRS)


ROOTHDRS=				\
	$($(MACH)_HDRS:%=$(ROOTDIR)/%)	\
	$(HDRS:%=$(ROOTDIR)/%)

ROOTAUDHDRS= $(AUDIOHDRS:%=$(ROOTDIR)/audio/%)

ROOTAVHDRS= $(AVHDRS:%=$(ROOTDIR)/av/%)

ROOTCRYPTOHDRS= $(CRYPTOHDRS:%=$(ROOTDIR)/crypto/%)

ROOTIBHDRS= $(IBHDRS:%=$(ROOTDIR)/ib/%)
ROOTIBDHDRS= $(IBDHDRS:%=$(ROOTDIR)/ib/clients/ibd/%)
ROOTIBTLHDRS= $(IBTLHDRS:%=$(ROOTDIR)/ib/ibtl/%)
ROOTIBTLIMPLHDRS= $(IBTLIMPLHDRS:%=$(ROOTDIR)/ib/ibtl/impl/%)
ROOTIBNEXHDRS= $(IBNEXHDRS:%=$(ROOTDIR)/ib/ibnex/%)
ROOTIBMGTHDRS= $(IBMGTHDRS:%=$(ROOTDIR)/ib/mgt/%)
ROOTIBMFHDRS= $(IBMFHDRS:%=$(ROOTDIR)/ib/mgt/ibmf/%)
ROOTTAVORHDRS= $(TAVORHDRS:%=$(ROOTDIR)/ib/adapters/tavor/%)

ROOTISOHDRS= $(ISOHDRS:%=$(ROOTDIR)/iso/%)

ROOTFMHDRS= $(FMHDRS:%=$(ROOTDIR)/fm/%)
ROOTFMCPUHDRS= $(FMCPUHDRS:%=$(ROOTDIR)/fm/cpu/%)
ROOTFMIOHDRS= $(FMIOHDRS:%=$(ROOTDIR)/fm/io/%)

ROOTFSHDRS= $(FSHDRS:%=$(ROOTDIR)/fs/%)

ROOTLVMHDRS= $(ALL_LVMHDRS:%=$(ROOTDIR)/lvm/%)

ROOTPCMCIAHDRS= $(PCMCIAHDRS:%=$(ROOTDIR)/pcmcia/%)

ROOTSCSIHDRS= $(SCSIHDRS:%=$(ROOTDIR)/scsi/%)
ROOTSCSICONFHDRS= $(SCSICONFHDRS:%=$(ROOTDIR)/scsi/conf/%)
ROOTSCSIGENHDRS= $(SCSIGENHDRS:%=$(ROOTDIR)/scsi/generic/%)
ROOTSCSIIMPLHDRS= $(SCSIIMPLHDRS:%=$(ROOTDIR)/scsi/impl/%)
ROOTSCSITARGETSHDRS= $(SCSITARGETSHDRS:%=$(ROOTDIR)/scsi/targets/%)
ROOTSCSICADHDRS= $(SCSICADHDRS:%=$(ROOTDIR)/scsi/adapters/%)
ROOTSCSIVHCIHDRS= $(SCSIVHCIHDRS:%=$(ROOTDIR)/scsi/adapters/%)

ROOTFCHDRS= $(FCHDRS:%=$(ROOTDIR)/fc4/%)

ROOTSYSEVENTHDRS= $(SYSEVENTHDRS:%=$(ROOTDIR)/sysevent/%)
ROOTCONTRACTHDRS= $(CONTRACTHDRS:%=$(ROOTDIR)/contract/%)

ROOTXHDRS= $(XHDRS:%=$(ROOTDIR)/%)

ROOTUSBHDRS= $(USBHDRS:%=$(ROOTDIR)/usb/%)
ROOTUSBAUDHDRS= $(USBAUDHDRS:%=$(ROOTDIR)/usb/clients/audio/%)
ROOTUSBHUBDHDRS= $(USBHUBDHDRS:%=$(ROOTDIR)/usb/hubd/%)
ROOTUSBHIDHDRS = $(USBHIDHDRS:%=$(ROOTDIR)/usb/clients/hid/%)
ROOTUSBMSHDRS= $(USBMSHDRS:%=$(ROOTDIR)/usb/clients/mass_storage/%)
ROOTUSBPRNHDRS= $(USBPRNHDRS:%=$(ROOTDIR)/usb/clients/printer/%)
ROOTUGENHDRS= $(UGENHDRS:%=$(ROOTDIR)/usb/clients/ugen/%)

ROOT1394HDRS= $(I1394HDRS:%=$(ROOTDIR)/1394/%)

ROOTRSMHDRS= $(RSMHDRS:%=$(ROOTDIR)/rsm/%)

ROOTSDKTPHDRS= $(SDKTPHDRS:%=$(ROOTDIR)/dktp/%)
ROOTDKTPHDRS= $(DKTPHDRS:%=$(ROOTDIR)/dktp/%)
ROOTPCHDRS= $(PCHDRS:%=$(ROOTDIR)/%)
ROOTI2OHDRS= $(I2OHDRS:%=$(ROOTDIR)/i2o/%)
ROOTHOTPLUGHDRS= $(HOTPLUGHDRS:%=$(ROOTDIR)/hotplug/%)
ROOTHOTPLUGPCIHDRS= $(HOTPLUGPCIHDRS:%=$(ROOTDIR)/hotplug/pci/%)


sparc_ROOTHDRS=	$(ROOTSDKTPHDRS) $(ROOTSCSICADHDRS) $(ROOTSCSITARGETSHDRS) \
		$(ROOTFCHDRS) $(ROOTUSBHDRS) $(ROOTUSBHUBDHDRS) $(ROOTPCMCIAHDRS) \
		$(ROOTUSBAUDHDRS) \
		$(ROOTUSBHIDHDRS) $(ROOTUSBMSHDRS) $(ROOTUSBPRNHDRS) \
		$(ROOTUGENHDRS)

i386_ROOTHDRS=	$(ROOTDKTPHDRS) $(ROOTPCHDRS) $(ROOTSCSITARGETSHDRS)	\
		$(ROOTSCSIVHCIHDRS) $(ROOTFCHDRS)	\
		$(ROOTI2OHDRS) $(ROOTPCMCIAHDRS) $(ROOTHOTPLUGHDRS) \
		$(ROOTHOTPLUGPCIHDRS)

# install rules
$(ROOTDIR)/%: %
	$(INS.file)

$(ROOTDIR)/crypto/%: crypto/%
	$(INS.file)

$(ROOTDIR)/fm/%:                fm/%
	$(INS.file)

$(ROOTDIR)/fm/cpu/%:                fm/cpu/%
	$(INS.file)

$(ROOTDIR)/fm/io/%:                fm/io/%
	$(INS.file)

$(ROOTDIR)/fs/%: fs/%
	$(INS.file)

$(ROOTDIR)/ib/%:		ib/%
	$(INS.file)

$(ROOTDIR)/ib/clients/ibd/%:	ib/clients/ibd/%
	$(INS.file)

$(ROOTDIR)/ib/ibtl/%:		ib/ibtl/%
	$(INS.file)

$(ROOTDIR)/ib/ibtl/impl/%:	ib/ibtl/impl/%
	$(INS.file)

$(ROOTDIR)/ib/ibnex/%:		ib/ibnex/%
	$(INS.file)

$(ROOTDIR)/ib/mgt/%:		ib/mgt/%
	$(INS.file)

$(ROOTDIR)/ib/mgt/ibmf/%:	ib/mgt/ibmf/%
	$(INS.file)

$(ROOTDIR)/ib/adapters/tavor/%:	ib/adapters/tavor/%
	$(INS.file)

$(ROOTDIR)/lvm/%: lvm/%
	$(INS.file)

$(ROOTDIR)/pcmcia/%:		pcmcia/%
	$(INS.file)

$(ROOTDIR)/scsi/%:		scsi/%
	$(INS.file)

$(ROOTDIR)/scsi/conf/%:		scsi/conf/%
	$(INS.file)

$(ROOTDIR)/scsi/generic/%:	scsi/generic/%
	$(INS.file)

$(ROOTDIR)/scsi/impl/%:		scsi/impl/%
	$(INS.file)

$(ROOTDIR)/scsi/targets/%:	scsi/targets/%
	$(INS.file)

$(ROOTDIR)/fc4/%:		fc4/%
	$(INS.file)

$(ROOTDIR)/sysevent/%:		sysevent/%
	$(INS.file)

$(ROOTDIR)/contract/%:		contract/%
	$(INS.file)

$(ROOTDIR)/usb/%:		usb/%
	$(INS.file)

$(ROOTDIR)/usb/hubd/%:		usb/hubd/%
	$(INS.file)

$(ROOTDIR)/usb/clients/hid/%:	usb/clients/hid/%
	$(INS.file)

$(ROOTDIR)/usb/clients/mass_storage/%:	usb/clients/mass_storage/%
	$(INS.file)

$(ROOTDIR)/dktp/%: dktp/%
	$(INS.file)

$(ROOTDIR)/1394/%:                    1394/%
	$(INS.file)

$(ROOTDIR)/rsm/%:	rsm/%
	$(INS.file)

.KEEP_STATE:

.PARALLEL:			\
	$(CHECKHDRS)		\
	$(ROOTHDRS)		\
	$(ROOTAUDHDRS)		\
	$(ROOTCRYPTOHDRS)	\
	$(ROOTISOHDRS)		\
	$(ROOTFMHDRS)		\
	$(ROOTFMCPUHDRS)	\
	$(ROOTFMIOHDRS)	\
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
	$(ROOTUGENHDRS)		\
	$(ROOT1394HDRS)         \
	$(ROOTHOTPLUGHDRS)	\
	$(ROOTHOTPLUGPCIHDRS)	\
	$(ROOTRSMHDRS)		\
	$($(MACH)_ROOTHDRS)


install_h:			\
	$(ROOTDIRS)		\
	LVMDERIVED_H		\
	.WAIT			\
	$(ROOTHDRS)		\
	$(ROOTAUDHDRS)		\
	$(ROOTCRYPTOHDRS)	\
	$(ROOTISOHDRS)		\
	$(ROOTFMHDRS)		\
	$(ROOTFMCPUHDRS)	\
	$(ROOTFMIOHDRS)	\
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
	$(ROOTUGENHDRS)		\
	$(ROOT1394HDRS)         \
	$(ROOTHOTPLUGHDRS)	\
	$(ROOTHOTPLUGPCIHDRS)	\
	$(ROOTRSMHDRS)		\
	$($(MACH)_ROOTHDRS)	\
	svvs_h

svvs_h: FRC
	@if [ -f lo.h  ]; then \
		$(MAKE) install_X_h; \
	else \
		true; \
	fi

all_h: $(GENHDRS)

priv_const.h: $(PRIVS_AWK) $(PRIVS_DEF)
	$(NAWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) -v privhfile=$@

priv_names.h: $(PRIVS_AWK) $(PRIVS_DEF)
	$(NAWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) -v pubhfile=$@

install_X_h: $(ROOTXHDRS)

$(ROOTDIRS):
	$(INS.dir)

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
