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
# Copyright 2020 Joyent, Inc.
# Copyright 2023 Peter Tribble
#

include		$(SRC)/Makefile.master

MANSECT=	3lib

MANFILES=	libMPAPI.3lib		\
		libSMHBAAPI.3lib	\
		libadm.3lib		\
		libaio.3lib		\
		libavl.3lib		\
		libbsdmalloc.3lib	\
		libbsm.3lib		\
		libc.3lib		\
		libc_db.3lib		\
		libcfgadm.3lib		\
		libcommputil.3lib	\
		libcontract.3lib	\
		libcpc.3lib		\
		libcrypt.3lib		\
		libcurses.3lib		\
		libdat.3lib		\
		libdevid.3lib		\
		libdevinfo.3lib		\
		libdl.3lib		\
		libdlpi.3lib		\
		libdns_sd.3lib		\
		libdoor.3lib		\
		libdtrace.3lib		\
		libefi.3lib		\
		libelf.3lib		\
		libexacct.3lib		\
		libfcoe.3lib		\
		libform.3lib		\
		libfstyp.3lib		\
		libgen.3lib		\
		libgss.3lib		\
		libintl.3lib		\
		libiscsit.3lib		\
		libjedec.3lib		\
		libkmf.3lib		\
		libkrb5.3lib		\
		libkstat.3lib		\
		libkvm.3lib		\
		libl.3lib		\
		liblgrp.3lib		\
		libm.3lib		\
		libmail.3lib		\
		libmalloc.3lib		\
		libmapmalloc.3lib	\
		libmd.3lib		\
		libmd5.3lib		\
		libmenu.3lib		\
		libmp.3lib		\
		libmtmalloc.3lib	\
		libmvec.3lib		\
		libnls.3lib		\
		libnsl.3lib		\
		libnvpair.3lib		\
		libpam.3lib		\
		libpanel.3lib		\
		libpapi.3lib		\
		libpctx.3lib		\
		libpicl.3lib		\
		libpicltree.3lib	\
		libpkcs11.3lib		\
		libpool.3lib		\
		libproc.3lib		\
		libproject.3lib		\
		libpthread.3lib		\
		libresolv.3lib		\
		librpcsvc.3lib		\
		librsm.3lib		\
		librt.3lib		\
		librtld_db.3lib		\
		libsasl.3lib		\
		libscf.3lib		\
		libsctp.3lib		\
		libsec.3lib		\
		libsecdb.3lib		\
		libsendfile.3lib	\
		libsip.3lib		\
		libslp.3lib		\
		libsocket.3lib		\
		libstmf.3lib		\
		libsysevent.3lib	\
		libtecla.3lib		\
		libthread.3lib		\
		libtsnet.3lib		\
		libtsol.3lib		\
		libumem.3lib		\
		libuuid.3lib		\
		libvolmgt.3lib		\
		libw.3lib		\
		libxnet.3lib		\
		liby.3lib

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
