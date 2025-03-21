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
# Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	3nsl

MANFILES=	dial.3nsl			\
		doconfig.3nsl			\
		gethostbyname.3nsl		\
		getipsecalgbyname.3nsl		\
		getipsecprotobyname.3nsl	\
		getnetconfig.3nsl		\
		getnetpath.3nsl			\
		getpublickey.3nsl		\
		getrpcbyname.3nsl		\
		netdir.3nsl			\
		nlsgetcall.3nsl			\
		nlsprovider.3nsl		\
		nlsrequest.3nsl			\
		rpc.3nsl			\
		rpc_clnt_auth.3nsl		\
		rpc_clnt_calls.3nsl		\
		rpc_clnt_create.3nsl		\
		rpc_control.3nsl		\
		rpc_gss_get_error.3nsl		\
		rpc_gss_get_mechanisms.3nsl	\
		rpc_gss_get_principal_name.3nsl \
		rpc_gss_getcred.3nsl		\
		rpc_gss_max_data_length.3nsl	\
		rpc_gss_mech_to_oid.3nsl	\
		rpc_gss_seccreate.3nsl		\
		rpc_gss_set_callback.3nsl	\
		rpc_gss_set_defaults.3nsl	\
		rpc_gss_set_svc_name.3nsl	\
		rpc_soc.3nsl			\
		rpc_svc_calls.3nsl		\
		rpc_svc_create.3nsl		\
		rpc_svc_err.3nsl		\
		rpc_svc_input.3nsl		\
		rpc_svc_reg.3nsl		\
		rpc_xdr.3nsl			\
		rpcbind.3nsl			\
		rpcsec_gss.3nsl			\
		secure_rpc.3nsl			\
		t_accept.3nsl			\
		t_alloc.3nsl			\
		t_bind.3nsl			\
		t_close.3nsl			\
		t_connect.3nsl			\
		t_errno.3nsl			\
		t_error.3nsl			\
		t_free.3nsl			\
		t_getinfo.3nsl			\
		t_getprotaddr.3nsl		\
		t_getstate.3nsl			\
		t_listen.3nsl			\
		t_look.3nsl			\
		t_open.3nsl			\
		t_optmgmt.3nsl			\
		t_rcv.3nsl			\
		t_rcvconnect.3nsl		\
		t_rcvdis.3nsl			\
		t_rcvrel.3nsl			\
		t_rcvreldata.3nsl		\
		t_rcvudata.3nsl			\
		t_rcvuderr.3nsl			\
		t_rcvv.3nsl			\
		t_rcvvudata.3nsl		\
		t_snd.3nsl			\
		t_snddis.3nsl			\
		t_sndrel.3nsl			\
		t_sndreldata.3nsl		\
		t_sndudata.3nsl			\
		t_sndv.3nsl			\
		t_sndvudata.3nsl		\
		t_strerror.3nsl			\
		t_sync.3nsl			\
		t_sysconf.3nsl			\
		t_unbind.3nsl			\
		xdr.3nsl			\
		xdr_admin.3nsl			\
		xdr_complex.3nsl		\
		xdr_create.3nsl			\
		xdr_simple.3nsl			\
		yp_update.3nsl			\
		ypclnt.3nsl

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
