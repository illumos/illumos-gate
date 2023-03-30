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
# Copyright 2015, Joyent, Inc.
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2018 Gary Mills
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2022 Garrett D'Amore <garrett@dmaore.org>
#

include		$(SRC)/Makefile.master

MANSECT=	5

_MANFILES=	Intro.5				\
		NISLDAPmapping.5		\
		a.out.5				\
		admin.5				\
		alias.5				\
		aliases.5			\
		au.5				\
		audit.log.5			\
		audit_class.5			\
		audit_event.5			\
		auth_attr.5			\
		autofs.5			\
		bart_manifest.5			\
		bart_rules.5			\
		bootparams.5			\
		cardbus.5			\
		compver.5			\
		contents.5			\
		contract.5			\
		copyright.5			\
		core.5				\
		crypt.conf.5			\
		crypto_certs.5			\
		ctf.5				\
		d_passwd.5			\
		dacf.conf.5			\
		dat.conf.5			\
		default_fs.5			\
		defaultdomain.5			\
		defaultrouter.5			\
		depend.5			\
		device_allocate.5		\
		device_contract.5		\
		device_maps.5			\
		devices.5			\
		dfstab.5			\
		dhcp_inittab.5			\
		dialups.5			\
		dir_ufs.5			\
		driver.conf.5			\
		ethers.5			\
		exec_attr.5			\
		fdi.5				\
		format.dat.5			\
		fspec.5				\
		fstypes.5			\
		ftp.5				\
		ftpusers.5			\
		fx_dptbl.5			\
		gateways.5			\
		group.5				\
		gsscred.conf.5			\
		hba.conf.5			\
		holidays.5			\
		hosts.5				\
		hosts.equiv.5			\
		hosts_access.5			\
		hosts_options.5			\
		ib.5				\
		ike.config.5			\
		ike.preshared.5			\
		ipf.5				\
		ipmon.5				\
		ipnat.5				\
		ippool.5			\
		inet_type.5			\
		inetd.conf.5			\
		init.5				\
		init.d.5			\
		inittab.5			\
		ipaddrsel.conf.5		\
		ipnodes.5			\
		issue.5				\
		kadm5.acl.5			\
		kdc.conf.5			\
		keytables.5			\
		krb5.conf.5			\
		ldapfilter.conf.5		\
		ldapsearchprefs.conf.5		\
		ldaptemplates.conf.5		\
		logadm.conf.5			\
		logindevperm.5			\
		loginlog.5			\
		magic.5				\
		mailer.conf.5			\
		mech.5				\
		menu.lst.5				\
		mnttab.5			\
		mpapi.conf.5			\
		ndmp.5				\
		ndpd.conf.5			\
		netconfig.5			\
		netgroup.5			\
		netid.5				\
		netmasks.5			\
		netrc.5				\
		networks.5			\
		nfs.5				\
		nfslog.conf.5			\
		nfssec.conf.5			\
		nodename.5			\
		nologin.5			\
		note.5				\
		notrouter.5			\
		nscd.conf.5			\
		nsmbrc.5			\
		nss.5				\
		nsswitch.conf.5			\
		overlay_files.5			\
		packingrules.5			\
		pam.conf.5			\
		passwd.5			\
		path_to_inst.5			\
		pci.5				\
		phones.5			\
		pkginfo.5			\
		pkgmap.5			\
		policy.conf.5			\
		power.conf.5			\
		printers.5			\
		printers.conf.5			\
		priv_names.5			\
		proc.5				\
		process.5			\
		prof_attr.5			\
		profile.5			\
		project.5			\
		protocols.5			\
		prototype.5			\
		pseudo.5			\
		publickey.5			\
		queuedefs.5			\
		rcmscript.5			\
		remote.5			\
		resolv.conf.5			\
		rmtab.5				\
		rpc.5				\
		rt_dptbl.5			\
		sasl_appname.conf.5		\
		scsi.5				\
		securenets.5			\
		sendmail.5			\
		service_bundle.5		\
		service_provider.conf.5		\
		services.5			\
		shadow.5			\
		sharetab.5			\
		shells.5			\
		slp.conf.5			\
		slpd.reg.5			\
		smb.5				\
		smbautohome.5			\
		smhba.conf.5			\
		sock2path.d.5			\
		space.5				\
		sulog.5				\
		syslog.conf.5			\
		system.5			\
		term.5				\
		terminfo.5			\
		timezone.5			\
		ts_dptbl.5			\
		ttydefs.5			\
		ttysrch.5			\
		ufsdump.5			\
		updaters.5			\
		user_attr.5			\
		utmp.5				\
		utmpx.5				\
		vfstab.5			\
		warn.conf.5			\
		ypfiles.5			\
		yppasswdd.5			\
		ypserv.5			\
		zoneinfo.5

i386_MANFILES=	bhyve_config.5			\
		loader.conf.5			\
		sysbus.5

_MANLINKS=	addresses.5			\
		devid_cache.5			\
		devname_cache.5			\
		dir.5				\
		dumpdates.5			\
		fbtab.5				\
		forward.5			\
		fs.5				\
		hosts.allow.5			\
		hosts.deny.5			\
		intro.5				\
		ipf.conf.5			\
		ipf6.conf.5			\
		ipmon.conf.5			\
		ipnat.conf.5			\
		ippool.conf.5			\
		mdi_ib_cache.5			\
		mdi_scsi_vhci_cache.5		\
		pci_unitaddr_persistent.5	\
		pcie.5				\
		qop.5				\
		rhosts.5			\
		TIMEZONE.5			\
		sendmail.cf.5			\
		snapshot_cache.5		\
		submit.cf.5			\
		wtmp.5				\
		wtmpx.5

i386_MANLINKS=	isa.5

MANFILES=	$(_MANFILES) $($(MACH)_MANFILES)
MANLINKS=	$(_MANLINKS) $($(MACH)_MANLINKS)

intro.5				:= LINKSRC = Intro.5

addresses.5			:= LINKSRC = aliases.5
forward.5			:= LINKSRC = aliases.5

fs.5				:= LINKSRC = default_fs.5

devid_cache.5			:= LINKSRC = devices.5
devname_cache.5			:= LINKSRC = devices.5
mdi_ib_cache.5			:= LINKSRC = devices.5
mdi_scsi_vhci_cache.5		:= LINKSRC = devices.5
pci_unitaddr_persistent.5	:= LINKSRC = devices.5
snapshot_cache.5		:= LINKSRC = devices.5

dir.5				:= LINKSRC = dir_ufs.5

rhosts.5			:= LINKSRC = hosts.equiv.5

TIMEZONE.5			:= LINKSRC = init.5

hosts.allow.5			:= LINKSRC = hosts_access.5
hosts.deny.5			:= LINKSRC = hosts_access.5

ipf.conf.5			:= LINKSRC = ipf.5
ipf6.conf.5			:= LINKSRC = ipf.5

ipmon.conf.5			:= LINKSRC = ipmon.5

ipnat.conf.5			:= LINKSRC = ipnat.5

ippool.conf.5			:= LINKSRC = ippool.5

fbtab.5				:= LINKSRC = logindevperm.5

qop.5				:= LINKSRC = mech.5

pcie.5				:= LINKSRC = pci.5

sendmail.cf.5			:= LINKSRC = sendmail.5
submit.cf.5			:= LINKSRC = sendmail.5

isa.5				:= LINKSRC = sysbus.5

dumpdates.5			:= LINKSRC = ufsdump.5

wtmp.5				:= LINKSRC = utmp.5

wtmpx.5				:= LINKSRC = utmpx.5

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
