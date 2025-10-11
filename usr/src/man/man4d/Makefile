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
# Copyright 2016 Garrett D'Amore <garrett@damore.org>
# Copyright 2019 Joyent, Inc.
# Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2023 Peter Tribble
# Copyright 2025 Oxide Computer Company
# Copyright 2023 RackTop Systems, Inc.
#

include		$(SRC)/Makefile.master

MANSECT=	4d

_MANFILES=	aac.4d		\
		afe.4d		\
		audio.4d	\
		audio1575.4d	\
		audioens.4d	\
		audiols.4d	\
		audiop16x.4d	\
		audiopci.4d	\
		audiots.4d	\
		av1394.4d	\
		bge.4d		\
		blkdev.4d	\
		bnxe.4d		\
		ccid.4d		\
		chxge.4d	\
		console.4d	\
		cpuid.4d	\
		dca.4d		\
		dcam1394.4d	\
		devinfo.4d	\
		dmfe.4d		\
		dtrace.4d	\
		e1000g.4d	\
		ehci.4d		\
		ena.4d		\
		fasttrap.4d	\
		fbt.4d		\
		fcip.4d		\
		fcoe.4d		\
		fcoei.4d	\
		fcoet.4d	\
		fcp.4d		\
		fctl.4d		\
		fd.4d		\
		fp.4d		\
		full.4d		\
		gld.4d		\
		hci1394.4d	\
		hermon.4d	\
		hid.4d		\
		hme.4d		\
		hubd.4d		\
		hxge.4d		\
		ib.4d		\
		ibcm.4d		\
		ibd.4d		\
		ibdm.4d		\
		ibdma.4d	\
		ibtl.4d		\
		ieee1394.4d	\
		igb.4d		\
		igc.4d		\
		ipnet.4d	\
		iscsi.4d	\
		iser.4d		\
		ismt.4d		\
		ixgbe.4d	\
		kgpio.4d	\
		kmdb.4d		\
		kstat.4d	\
		ksensor.4d	\
		ksyms.4d	\
		llc1.4d		\
		lmrc.4d		\
		lockstat.4d	\
		lofi.4d		\
		log.4d		\
		lm7x.4d		\
		mem.4d		\
		mpt_sas.4d	\
		mr_sas.4d	\
		msglog.4d	\
		mt.4d		\
		mxfe.4d		\
		myri10ge.4d	\
		null.4d		\
		nulldriver.4d	\
		nxge.4d		\
		ohci.4d		\
		openprom.4d	\
		pcic.4d		\
		pchsmbus.4d	\
		pcmcia.4d	\
		physmem.4d	\
		pm.4d		\
		poll.4d		\
		profile.4d	\
		ptm.4d		\
		pty.4d		\
		qlc.4d		\
		ramdisk.4d	\
		random.4d	\
		rge.4d		\
		rtls.4d		\
		sad.4d		\
		sata.4d		\
		scsa1394.4d	\
		scsa2usb.4d	\
		sd.4d		\
		sdp.4d		\
		sdt.4d		\
		ses.4d		\
		sfe.4d		\
		sgen.4d		\
		smartpqi.4d	\
		srpt.4d		\
		st.4d		\
		sysmsg.4d	\
		systrace.4d	\
		ticlts.4d	\
		tmp43x.4d	\
		ts511x.4d	\
		tty.4d		\
		tzmon.4d	\
		ufm.4d		\
		ugen.4d		\
		uhci.4d		\
		usb_ac.4d	\
		usb_as.4d	\
		usb_ia.4d	\
		usb_mid.4d	\
		usba.4d		\
		usbftdi.4d	\
		usbprn.4d	\
		usbsacm.4d	\
		usbsksp.4d	\
		usbsprl.4d	\
		usbvc.4d	\
		virtualkm.4d	\
		vni.4d		\
		vr.4d		\
		wscons.4d	\
		xge.4d		\
		yge.4d		\
		zcons.4d	\
		zero.4d

i386_MANFILES=	ahci.4d		\
		amd8111s.4d	\
		amdnbtemp.4d	\
		amdzen.4d	\
		amr.4d		\
		arcmsr.4d	\
		arn.4d		\
		asy.4d		\
		ata.4d		\
		atge.4d		\
		ath.4d		\
		atu.4d		\
		audio810.4d	\
		audiocmi.4d	\
		audiocmihd.4d	\
		audioemu10k.4d	\
		audiohd.4d	\
		audioixp.4d	\
		audiosolo.4d	\
		audiovia823x.4d \
		bcm_sata.4d	\
		bfe.4d		\
		cmdk.4d		\
		coretemp.4d	\
		cpqary3.4d	\
		dnet.4d		\
		ecpp.4d		\
		elxl.4d		\
		i40e.4d		\
		imc.4d		\
		imcstub.4d	\
		ipmi.4d		\
		iprb.4d		\
		ipw.4d		\
		iwh.4d		\
		iwi.4d		\
		iwn.4d		\
		mega_sas.4d	\
		mlxcx.4d	\
		npe.4d		\
		ntxn.4d		\
		nv_sata.4d	\
		nvme.4d		\
		pchtemp.4d	\
		pcn.4d		\
		pvscsi.4d	\
		qede.4d		\
		ral.4d		\
		rtw.4d		\
		rum.4d		\
		rwd.4d		\
		rwn.4d		\
		sda.4d		\
		sdhost.4d	\
		sfxge.4d	\
		si3124.4d	\
		skd.4d		\
		smbios.4d	\
		smntemp.4d	\
		uath.4d		\
		ural.4d		\
		urtw.4d		\
		usmn.4d		\
		vio9p.4d	\
		vioblk.4d	\
		vioif.4d	\
		vioscsi.4d	\
		virtio.4d	\
		vmxnet3s.4d	\
		wpi.4d		\
		xhci.4d		\
		zen_udf.4d	\
		zyd.4d

MANFILES=	$(_MANFILES) $($(MACH)_MANFILES)

i386_MANLINK_SRC=	Manlink.i386

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
