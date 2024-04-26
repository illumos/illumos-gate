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
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2013, 2016 by Delphix. All rights reserved.
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright (c) 2017, Chris Fraire <cfraire@me.com>.
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2020 Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2022 Garrett D'Amore
# Copyright 2023 Peter Tribble
# Copyright 2023 MNX Cloud, Inc.
# Copyright 2024 Oxide Computer Company
#

include		$(SRC)/Makefile.master

MANSECT=	8

_MANFILES=	6to4relay.8		\
		Intro.8			\
		Uutry.8			\
		accept.8		\
		acct.8			\
		acctadm.8		\
		acctcms.8		\
		acctcon.8		\
		acctmerg.8		\
		acctprc.8		\
		acctsh.8		\
		adbgen.8		\
		add_allocatable.8	\
		add_drv.8		\
		addbadsec.8		\
		altexec.8		\
		arcstat.8		\
		arp.8			\
		atohexlabel.8		\
		audit.8			\
		audit_warn.8		\
		auditconfig.8		\
		auditd.8		\
		auditrecord.8		\
		auditreduce.8		\
		auditstat.8		\
		automount.8		\
		automountd.8		\
		autopush.8		\
		bart.8			\
		beadm.8			\
		boot.8			\
		bootadm.8		\
		busstat.8		\
		captoinfo.8		\
		catman.8		\
		ccidadm.8		\
		cfgadm.8		\
		cfgadm_cardbus.8	\
		cfgadm_fp.8		\
		cfgadm_ib.8		\
		cfgadm_pci.8		\
		cfgadm_sata.8		\
		cfgadm_sbd.8		\
		cfgadm_scsi.8		\
		cfgadm_usb.8		\
		chat.8			\
		check-hostname.8	\
		check-permissions.8	\
		chroot.8		\
		clear_locks.8		\
		clinfo.8		\
		clri.8			\
		connstat.8		\
		consadm.8		\
		conv_lp.8		\
		conv_lpd.8		\
		coreadm.8		\
		cpustat.8		\
		cron.8			\
		cryptoadm.8		\
		datadm.8		\
		dd.8			\
		devattr.8		\
		devfree.8		\
		devfsadm.8		\
		devinfo.8		\
		devlinks.8		\
		devnm.8			\
		devprop.8		\
		devreserv.8		\
		df.8			\
		df_ufs.8		\
		dfmounts.8		\
		dfmounts_nfs.8		\
		dfshares.8		\
		dfshares_nfs.8		\
		dhcpagent.8		\
		diskinfo.8		\
		disks.8			\
		diskscan.8		\
		dispadmin.8		\
		dladm.8			\
		dlmgmtd.8		\
		dmesg.8			\
		dminfo.8		\
		dns-sd.8		\
		domainname.8		\
		drvconfig.8		\
		dtrace.8		\
		dumpadm.8		\
		editmap.8		\
		edquota.8		\
		eeprom.8		\
		embedded_su.8		\
		etrn.8			\
		fcinfo.8		\
		fdetach.8		\
		fdisk.8			\
		ff.8			\
		ff_ufs.8		\
		fiocompress.8		\
		flowadm.8		\
		fmadm.8			\
		fmd.8			\
		fmdump.8		\
		fmstat.8		\
		fmthard.8		\
		format.8		\
		fsck.8			\
		fsck_pcfs.8		\
		fsck_udfs.8		\
		fsck_ufs.8		\
		fsdb.8			\
		fsdb_udfs.8		\
		fsdb_ufs.8		\
		fsirand.8		\
		fssnap.8		\
		fssnap_ufs.8		\
		fsstat.8		\
		fstyp.8			\
		fuser.8			\
		fwflash.8		\
		fwtmp.8			\
		getdev.8		\
		getdevpolicy.8		\
		getdgrp.8		\
		getent.8		\
		getty.8			\
		getvol.8		\
		groupadd.8		\
		groupdel.8		\
		groupmod.8		\
		growfs.8		\
		gsscred.8		\
		gssd.8			\
		hal-device.8		\
		hal-fdi-validate.8	\
		hal-find.8		\
		hal-get-property.8	\
		hald.8			\
		halt.8			\
		hextoalabel.8		\
		hostconfig.8		\
		hotplug.8		\
		id.8			\
		idmap.8			\
		idmapd.8		\
		idsconfig.8		\
		if_mpadm.8		\
		ifconfig.8		\
		ifparse.8		\
		ikeadm.8		\
		ikecert.8		\
		in.chargend.8		\
		in.comsat.8		\
		in.daytimed.8		\
		in.discardd.8		\
		in.echod.8		\
		in.fingerd.8		\
		in.iked.8		\
		in.lpd.8		\
		in.mpathd.8		\
		in.ndpd.8		\
		in.rarpd.8		\
		in.rdisc.8		\
		in.rexecd.8		\
		in.ripngd.8		\
		in.rlogind.8		\
		in.routed.8		\
		in.rshd.8		\
		in.rwhod.8		\
		in.talkd.8		\
		in.telnetd.8		\
		in.tftpd.8		\
		in.timed.8		\
		in.uucpd.8		\
		inetadm.8		\
		inetconv.8		\
		inetd.8			\
		infocmp.8		\
		init.8			\
		inityp2l.8		\
		install.8		\
		installboot.8		\
		installf.8		\
		installgrub.8		\
		intrd.8			\
		intrstat.8		\
		iostat.8		\
		ipaddrsel.8		\
		ipadm.8			\
		ipdadm.8		\
		ipf.8			\
		ipfs.8			\
		ipfstat.8		\
		ipmon.8			\
		ipmpstat.8		\
		ipnat.8			\
		ippool.8		\
		ipqosconf.8		\
		ipsecalgs.8		\
		ipsecconf.8		\
		ipseckey.8		\
		iscsiadm.8		\
		isns.8			\
		isnsadm.8		\
		itadm.8			\
		k5srvutil.8		\
		kadb.8			\
		kadmin.8		\
		kadmind.8		\
		kclient.8		\
		kdb5_ldap_util.8	\
		kdb5_util.8		\
		kdcmgr.8		\
		kernel.8		\
		keyserv.8		\
		killall.8		\
		kprop.8			\
		kpropd.8		\
		kproplog.8		\
		krb5kdc.8		\
		kstat.8			\
		ktkt_warnd.8		\
		labelit.8		\
		labelit_hsfs.8		\
		labelit_udfs.8		\
		labelit_ufs.8		\
		latencytop.8		\
		ldap_cachemgr.8		\
		ldapaddent.8		\
		ldapclient.8		\
		link.8			\
		listdgrp.8		\
		listen.8		\
		locator.8		\
		lockfs.8		\
		lockstat.8		\
		lofiadm.8		\
		logadm.8		\
		logins.8		\
		lpadmin.8		\
		lpfilter.8		\
		lpforms.8		\
		lpget.8			\
		lpmove.8		\
		lpsched.8		\
		lpset.8			\
		lpshut.8		\
		lpsystem.8		\
		lpusers.8		\
		luxadm.8		\
		mail.local.8		\
		mailwrapper.8		\
		makedbm.8		\
		makemap.8		\
		mdnsd.8			\
		mkdevalloc.8		\
		mkdevmaps.8		\
		mkfifo.8		\
		mkfile.8		\
		mkfs.8			\
		mkfs_pcfs.8		\
		mkfs_udfs.8		\
		mkfs_ufs.8		\
		mknod.8			\
		mkpwdict.8		\
		modinfo.8		\
		modload.8		\
		modunload.8		\
		mount.8			\
		mount_hsfs.8		\
		mount_nfs.8		\
		mount_pcfs.8		\
		mount_smbfs.8		\
		mount_tmpfs.8		\
		mount_udfs.8		\
		mount_ufs.8		\
		mountall.8		\
		mountd.8		\
		mpathadm.8		\
		mpstat.8		\
		msgid.8			\
		mvdir.8			\
		ncheck.8		\
		ncheck_ufs.8		\
		ndd.8			\
		ndp.8			\
		ndmpadm.8		\
		ndmpd.8			\
		ndmpstat.8		\
		netstat.8		\
		netstrategy.8		\
		newaliases.8		\
		newfs.8			\
		newkey.8		\
		nfs4cbd.8		\
		nfsd.8			\
		nfslogd.8		\
		nfsmapid.8		\
		nfsstat.8		\
		nlsadmin.8		\
		nscd.8			\
		nwamd.8			\
		passmgmt.8		\
		pbind.8			\
		pcitool.8		\
		picld.8			\
		ping.8			\
		pkgadd.8		\
		pkgadm.8		\
		pkgask.8		\
		pkgchk.8		\
		pkgrm.8			\
		plockstat.8		\
		pmadm.8			\
		pmconfig.8		\
		polkit-is-privileged.8	\
		pooladm.8		\
		poolbind.8		\
		poolcfg.8		\
		poold.8			\
		poolstat.8		\
		ports.8			\
		powerd.8		\
		powertop.8		\
		ppdmgr.8		\
		pppd.8			\
		pppdump.8		\
		pppoec.8		\
		pppoed.8		\
		pppstats.8		\
		praudit.8		\
		print-service.8		\
		projadd.8		\
		projdel.8		\
		projmod.8		\
		prstat.8		\
		prtconf.8		\
		prtdiag.8		\
		prtpicl.8		\
		prtvtoc.8		\
		psradm.8		\
		psrinfo.8		\
		psrset.8		\
		putdev.8		\
		putdgrp.8		\
		pwck.8			\
		pwconv.8		\
		quot.8			\
		quota.8			\
		quotacheck.8		\
		quotaon.8		\
		raidctl.8		\
		ramdiskadm.8		\
		rcapadm.8		\
		rcapd.8			\
		rctladm.8		\
		rdate.8			\
		reboot.8		\
		rem_drv.8		\
		remove_allocatable.8	\
		removef.8		\
		repquota.8		\
		rmmount.8		\
		rmt.8			\
		rmvolmgr.8		\
		roleadd.8		\
		roledel.8		\
		rolemod.8		\
		root_archive.8		\
		route.8			\
		routeadm.8		\
		rpc.bootparamd.8	\
		rpc.rstatd.8		\
		rpc.rusersd.8		\
		rpc.rwalld.8		\
		rpc.smserverd.8		\
		rpc.sprayd.8		\
		rpc.yppasswdd.8		\
		rpc.ypupdated.8		\
		rpcbind.8		\
		rpcinfo.8		\
		rquotad.8		\
		rsh.8			\
		rtc.8			\
		rtquery.8		\
		runacct.8		\
		rwall.8			\
		sac.8			\
		sacadm.8		\
		saf.8			\
		sar.8			\
		sasinfo.8		\
		savecore.8		\
		sbdadm.8		\
		sdpadm.8		\
		sendmail.8		\
		share.8			\
		share_nfs.8		\
		shareall.8		\
		sharectl.8		\
		sharemgr.8		\
		showmount.8		\
		shutdown.8		\
		slpd.8			\
		smbadm.8		\
		smbd.8			\
		smbiod.8		\
		smbios.8		\
		smbstat.8		\
		smrsh.8			\
		snoop.8			\
		soconfig.8		\
		sppptun.8		\
		spray.8			\
		statd.8			\
		stmfadm.8		\
		stmsboot.8		\
		strace.8		\
		strclean.8		\
		strerr.8		\
		sttydefs.8		\
		su.8			\
		sulogin.8		\
		svc.configd.8		\
		svc.ipfd.8		\
		svc.startd.8		\
		svcadm.8		\
		svccfg.8		\
		swap.8			\
		sync.8			\
		syncinit.8		\
		syncloop.8		\
		syncstat.8		\
		sysdef.8		\
		syseventadm.8		\
		syseventconfd.8		\
		syseventd.8		\
		syslogd.8		\
		tapes.8			\
		tcpd.8			\
		tcpdchk.8		\
		tcpdmatch.8		\
		tcpkey.8		\
		th_define.8		\
		th_manage.8		\
		tic.8			\
		tnchkdb.8		\
		tnctl.8			\
		tnd.8			\
		tninfo.8		\
		tpmadm.8		\
		traceroute.8		\
		trapstat.8		\
		ttyadm.8		\
		ttymon.8		\
		tunefs.8		\
		txzonemgr.8		\
		tzreload.8		\
		tzselect.8		\
		uadmin.8		\
		ucodeadm.8		\
		ufsdump.8		\
		ufsrestore.8		\
		unshare.8		\
		unshare_nfs.8		\
		update_drv.8		\
		updatehome.8		\
		useradd.8		\
		userdel.8		\
		usermod.8		\
		utmpd.8			\
		uucheck.8		\
		uucico.8		\
		uucleanup.8		\
		uusched.8		\
		uuxqt.8			\
		vfsstat.8		\
		vmstat.8		\
		vndadm.8		\
		vndstat.8		\
		volcopy.8		\
		volcopy_ufs.8		\
		vscanadm.8		\
		vscand.8		\
		wall.8			\
		whodo.8			\
		wificonfig.8		\
		wpad.8			\
		wracct.8		\
		ypbind.8		\
		ypinit.8		\
		ypmake.8		\
		ypmap2src.8		\
		yppoll.8		\
		yppush.8		\
		ypserv.8		\
		ypset.8			\
		ypstart.8		\
		ypxfr.8			\
		zdb.8			\
		zdump.8			\
		zfs.8			\
		zfs-program.8		\
		zic.8			\
		zoneadm.8		\
		zoneadmd.8		\
		zonecfg.8		\
		zonestatd.8		\
		zpool.8			\
		zstreamdump.8		\
		ztest.8

i386_MANFILES=			\
		acpidump.8	\
		acpixtract.8	\
		bhyve.8		\
		bhyvectl.8	\
		nvmeadm.8	\
		pptadm.8	\
		rdmsr.8

MANLINKS=	acctcon1.8			\
		acctcon2.8			\
		acctdisk.8			\
		acctdusg.8			\
		accton.8			\
		acctprc1.8			\
		acctprc2.8			\
		acctwtmp.8			\
		audlinks.8			\
		bootparamd.8			\
		chargefee.8			\
		ckpacct.8			\
		closewtmp.8			\
		comsat.8			\
		dcopy.8				\
		devfsadmd.8			\
		dodisk.8			\
		fcadm.8				\
		fingerd.8			\
		grpck.8				\
		hal-find-by-capability.8	\
		hal-find-by-property.8		\
		hal-set-property.8		\
		intro.8				\
		kadmin.local.8			\
		lastlogin.8			\
		monacct.8			\
		nulladm.8			\
		poweroff.8			\
		prctmp.8			\
		prdaily.8			\
		prtacct.8			\
		quotaoff.8			\
		rarpd.8				\
		rdisc.8				\
		reject.8			\
		restricted_shell.8		\
		rexecd.8			\
		rlogind.8			\
		routed.8			\
		rshd.8				\
		rstatd.8			\
		rusersd.8			\
		rwalld.8			\
		rwhod.8				\
		sa1.8				\
		sa2.8				\
		sadc.8				\
		shutacct.8			\
		sprayd.8			\
		startup.8			\
		talkd.8				\
		telinit.8			\
		telnetd.8			\
		tftpd.8				\
		turnacct.8			\
		umount.8			\
		umount_smbfs.8			\
		umountall.8			\
		unlink.8			\
		unshareall.8			\
		utmp2wtmp.8			\
		uucpd.8				\
		uutry.8				\
		wtmpfix.8			\
		yppasswdd.8			\
		ypstop.8			\
		ypupdated.8			\
		ypxfr_1perday.8			\
		ypxfr_1perhour.8		\
		ypxfr_2perday.8			\
		ypxfrd.8

MANFILES=	$(_MANFILES) $($(MACH)_MANFILES)

intro.8			:= LINKSRC = Intro.8

uutry.8			:= LINKSRC = Uutry.8

reject.8		:= LINKSRC = accept.8

acctdisk.8		:= LINKSRC = acct.8
acctdusg.8		:= LINKSRC = acct.8
accton.8		:= LINKSRC = acct.8
acctwtmp.8		:= LINKSRC = acct.8
closewtmp.8		:= LINKSRC = acct.8
utmp2wtmp.8		:= LINKSRC = acct.8

acctcon1.8		:= LINKSRC = acctcon.8
acctcon2.8		:= LINKSRC = acctcon.8

acctprc1.8		:= LINKSRC = acctprc.8
acctprc2.8		:= LINKSRC = acctprc.8

chargefee.8		:= LINKSRC = acctsh.8
ckpacct.8		:= LINKSRC = acctsh.8
dodisk.8		:= LINKSRC = acctsh.8
lastlogin.8		:= LINKSRC = acctsh.8
monacct.8		:= LINKSRC = acctsh.8
nulladm.8		:= LINKSRC = acctsh.8
prctmp.8		:= LINKSRC = acctsh.8
prdaily.8		:= LINKSRC = acctsh.8
prtacct.8		:= LINKSRC = acctsh.8
shutacct.8		:= LINKSRC = acctsh.8
startup.8		:= LINKSRC = acctsh.8
turnacct.8		:= LINKSRC = acctsh.8

dcopy.8			:= LINKSRC = clri.8

audlinks.8		:= LINKSRC = devfsadm.8
devfsadmd.8		:= LINKSRC = devfsadm.8

fcadm.8			:= LINKSRC = fcinfo.8

wtmpfix.8		:= LINKSRC = fwtmp.8

hal-find-by-capability.8	:= LINKSRC = hal-find.8
hal-find-by-property.8		:= LINKSRC = hal-find.8

hal-set-property.8	:= LINKSRC = hal-get-property.8

poweroff.8		:= LINKSRC = halt.8


comsat.8		:= LINKSRC = in.comsat.8
fingerd.8		:= LINKSRC = in.fingerd.8
rarpd.8			:= LINKSRC = in.rarpd.8
rdisc.8			:= LINKSRC = in.rdisc.8
rexecd.8		:= LINKSRC = in.rexecd.8
rlogind.8		:= LINKSRC = in.rlogind.8
routed.8		:= LINKSRC = in.routed.8
rshd.8			:= LINKSRC = in.rshd.8
rwhod.8			:= LINKSRC = in.rwhod.8
talkd.8			:= LINKSRC = in.talkd.8
telnetd.8		:= LINKSRC = in.telnetd.8
tftpd.8			:= LINKSRC = in.tftpd.8
uucpd.8			:= LINKSRC = in.uucpd.8

telinit.8		:= LINKSRC = init.8

kadmin.local.8		:= LINKSRC = kadmin.8

unlink.8		:= LINKSRC = link.8

umount.8		:= LINKSRC = mount.8

umount_smbfs.8		:= LINKSRC = mount_smbfs.8

umountall.8		:= LINKSRC = mountall.8

grpck.8			:= LINKSRC = pwck.8

quotaoff.8		:= LINKSRC = quotaon.8

bootparamd.8		:= LINKSRC = rpc.bootparamd.8
rstatd.8		:= LINKSRC = rpc.rstatd.8
rusersd.8		:= LINKSRC = rpc.rusersd.8
rwalld.8		:= LINKSRC = rpc.rwalld.8
sprayd.8		:= LINKSRC = rpc.sprayd.8
yppasswdd.8		:= LINKSRC = rpc.yppasswdd.8
ypupdated.8		:= LINKSRC = rpc.ypupdated.8

restricted_shell.8	:= LINKSRC = rsh.8

sa1.8			:= LINKSRC = sar.8
sa2.8			:= LINKSRC = sar.8
sadc.8			:= LINKSRC = sar.8

unshareall.8		:= LINKSRC = shareall.8

ypxfrd.8		:= LINKSRC = ypserv.8

ypstop.8		:= LINKSRC = ypstart.8

ypxfr_1perday.8		:= LINKSRC = ypxfr.8
ypxfr_1perhour.8	:= LINKSRC = ypxfr.8
ypxfr_2perday.8		:= LINKSRC = ypxfr.8


.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
