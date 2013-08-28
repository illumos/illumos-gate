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
#

include		$(SRC)/Makefile.master

MANSECT= 	3nsl

MANFILES= 	dial.3nsl			\
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

MANLINKS=	auth_destroy.3nsl			\
		authdes_create.3nsl			\
		authdes_getucred.3nsl			\
		authdes_seccreate.3nsl			\
		authnone_create.3nsl			\
		authsys_create.3nsl			\
		authsys_create_default.3nsl		\
		authunix_create.3nsl			\
		authunix_create_default.3nsl		\
		callrpc.3nsl				\
		clnt_broadcast.3nsl			\
		clnt_call.3nsl				\
		clnt_control.3nsl			\
		clnt_create.3nsl			\
		clnt_create_timed.3nsl			\
		clnt_create_vers.3nsl			\
		clnt_create_vers_timed.3nsl		\
		clnt_destroy.3nsl			\
		clnt_dg_create.3nsl			\
		clnt_door_create.3nsl			\
		clnt_freeres.3nsl			\
		clnt_geterr.3nsl			\
		clnt_pcreateerror.3nsl			\
		clnt_perrno.3nsl			\
		clnt_perror.3nsl			\
		clnt_raw_create.3nsl			\
		clnt_send.3nsl				\
		clnt_spcreateerror.3nsl			\
		clnt_sperrno.3nsl			\
		clnt_sperror.3nsl			\
		clnt_tli_create.3nsl			\
		clnt_tp_create.3nsl			\
		clnt_tp_create_timed.3nsl		\
		clnt_vc_create.3nsl			\
		clntraw_create.3nsl			\
		clnttcp_create.3nsl			\
		clntudp_bufcreate.3nsl			\
		clntudp_create.3nsl			\
		endhostent.3nsl				\
		endnetconfig.3nsl			\
		endnetpath.3nsl				\
		endrpcent.3nsl				\
		freeipsecalgent.3nsl			\
		freenetconfigent.3nsl			\
		get_myaddress.3nsl			\
		gethostbyaddr.3nsl			\
		gethostbyaddr_r.3nsl			\
		gethostbyname_r.3nsl			\
		gethostent.3nsl				\
		gethostent_r.3nsl			\
		getipsecalgbynum.3nsl			\
		getipsecprotobynum.3nsl			\
		getnetconfigent.3nsl			\
		getnetname.3nsl				\
		getrpcbyname_r.3nsl			\
		getrpcbynumber.3nsl			\
		getrpcbynumber_r.3nsl			\
		getrpcent.3nsl				\
		getrpcent_r.3nsl			\
		getrpcport.3nsl				\
		getsecretkey.3nsl			\
		host2netname.3nsl			\
		key_decryptsession.3nsl			\
		key_encryptsession.3nsl			\
		key_gendes.3nsl				\
		key_secretkey_is_set.3nsl		\
		key_setsecret.3nsl			\
		nc_perror.3nsl				\
		nc_sperror.3nsl				\
		netdir_free.3nsl			\
		netdir_getbyaddr.3nsl			\
		netdir_getbyname.3nsl			\
		netdir_mergeaddr.3nsl			\
		netdir_options.3nsl			\
		netdir_perror.3nsl			\
		netdir_sperror.3nsl			\
		netname2host.3nsl			\
		netname2user.3nsl			\
		pmap_getmaps.3nsl			\
		pmap_getport.3nsl			\
		pmap_rmtcall.3nsl			\
		pmap_set.3nsl				\
		pmap_unset.3nsl				\
		publickey.3nsl				\
		registerrpc.3nsl			\
		rpc_broadcast.3nsl			\
		rpc_broadcast_exp.3nsl			\
		rpc_call.3nsl				\
		rpc_createerr.3nsl			\
		rpc_gss_get_mech_info.3nsl		\
		rpc_gss_get_versions.3nsl		\
		rpc_gss_is_installed.3nsl		\
		rpc_gss_qop_to_num.3nsl			\
		rpc_gss_svc_max_data_length.3nsl	\
		rpc_reg.3nsl				\
		rpcb_getaddr.3nsl			\
		rpcb_getmaps.3nsl			\
		rpcb_gettime.3nsl			\
		rpcb_rmtcall.3nsl			\
		rpcb_set.3nsl				\
		rpcb_unset.3nsl				\
		sethostent.3nsl				\
		setnetconfig.3nsl			\
		setnetpath.3nsl				\
		setrpcent.3nsl				\
		svc_add_input.3nsl			\
		svc_auth_reg.3nsl			\
		svc_control.3nsl			\
		svc_create.3nsl				\
		svc_destroy.3nsl			\
		svc_dg_create.3nsl			\
		svc_dg_enablecache.3nsl			\
		svc_done.3nsl				\
		svc_door_create.3nsl			\
		svc_exit.3nsl				\
		svc_fd_create.3nsl			\
		svc_fd_negotiate_ucred.3nsl		\
		svc_fds.3nsl				\
		svc_fdset.3nsl				\
		svc_freeargs.3nsl			\
		svc_getargs.3nsl			\
		svc_getcaller.3nsl			\
		svc_getcallerucred.3nsl			\
		svc_getreq.3nsl				\
		svc_getreq_common.3nsl			\
		svc_getreq_poll.3nsl			\
		svc_getreqset.3nsl			\
		svc_getrpccaller.3nsl			\
		svc_max_pollfd.3nsl			\
		svc_pollfd.3nsl				\
		svc_raw_create.3nsl			\
		svc_reg.3nsl				\
		svc_register.3nsl			\
		svc_remove_input.3nsl			\
		svc_run.3nsl				\
		svc_sendreply.3nsl			\
		svc_tli_create.3nsl			\
		svc_tp_create.3nsl			\
		svc_unreg.3nsl				\
		svc_unregister.3nsl			\
		svc_vc_create.3nsl			\
		svcerr_auth.3nsl			\
		svcerr_decode.3nsl			\
		svcerr_noproc.3nsl			\
		svcerr_noprog.3nsl			\
		svcerr_progvers.3nsl			\
		svcerr_systemerr.3nsl			\
		svcerr_weakauth.3nsl			\
		svcfd_create.3nsl			\
		svcraw_create.3nsl			\
		svctcp_create.3nsl			\
		svcudp_bufcreate.3nsl			\
		svcudp_create.3nsl			\
		taddr2uaddr.3nsl			\
		uaddr2taddr.3nsl			\
		undial.3nsl				\
		user2netname.3nsl			\
		xdr_accepted_reply.3nsl			\
		xdr_array.3nsl				\
		xdr_authsys_parms.3nsl			\
		xdr_authunix_parms.3nsl			\
		xdr_bool.3nsl				\
		xdr_bytes.3nsl				\
		xdr_callhdr.3nsl			\
		xdr_callmsg.3nsl			\
		xdr_char.3nsl				\
		xdr_control.3nsl			\
		xdr_destroy.3nsl			\
		xdr_double.3nsl				\
		xdr_enum.3nsl				\
		xdr_float.3nsl				\
		xdr_free.3nsl				\
		xdr_getpos.3nsl				\
		xdr_hyper.3nsl				\
		xdr_inline.3nsl				\
		xdr_int.3nsl				\
		xdr_long.3nsl				\
		xdr_longlong_t.3nsl			\
		xdr_opaque.3nsl				\
		xdr_opaque_auth.3nsl			\
		xdr_pointer.3nsl			\
		xdr_quadruple.3nsl			\
		xdr_reference.3nsl			\
		xdr_rejected_reply.3nsl			\
		xdr_replymsg.3nsl			\
		xdr_setpos.3nsl				\
		xdr_short.3nsl				\
		xdr_sizeof.3nsl				\
		xdr_string.3nsl				\
		xdr_u_char.3nsl				\
		xdr_u_hyper.3nsl			\
		xdr_u_int.3nsl				\
		xdr_u_long.3nsl				\
		xdr_u_longlong_t.3nsl			\
		xdr_u_short.3nsl			\
		xdr_union.3nsl				\
		xdr_vector.3nsl				\
		xdr_void.3nsl				\
		xdr_wrapstring.3nsl			\
		xdrmem_create.3nsl			\
		xdrrec_create.3nsl			\
		xdrrec_endofrecord.3nsl			\
		xdrrec_eof.3nsl				\
		xdrrec_readbytes.3nsl			\
		xdrrec_skiprecord.3nsl			\
		xdrstdio_create.3nsl			\
		xprt_register.3nsl			\
		xprt_unregister.3nsl			\
		yp_all.3nsl				\
		yp_bind.3nsl				\
		yp_first.3nsl				\
		yp_get_default_domain.3nsl		\
		yp_master.3nsl				\
		yp_match.3nsl				\
		yp_next.3nsl				\
		yp_order.3nsl				\
		yp_unbind.3nsl				\
		yperr_string.3nsl			\
		ypprot_err.3nsl

undial.3nsl				:= LINKSRC = dial.3nsl

endhostent.3nsl				:= LINKSRC = gethostbyname.3nsl
gethostbyaddr.3nsl			:= LINKSRC = gethostbyname.3nsl
gethostbyaddr_r.3nsl			:= LINKSRC = gethostbyname.3nsl
gethostbyname_r.3nsl			:= LINKSRC = gethostbyname.3nsl
gethostent.3nsl				:= LINKSRC = gethostbyname.3nsl
gethostent_r.3nsl			:= LINKSRC = gethostbyname.3nsl
sethostent.3nsl				:= LINKSRC = gethostbyname.3nsl

freeipsecalgent.3nsl			:= LINKSRC = getipsecalgbyname.3nsl
getipsecalgbynum.3nsl			:= LINKSRC = getipsecalgbyname.3nsl

getipsecprotobynum.3nsl			:= LINKSRC = getipsecprotobyname.3nsl

endnetconfig.3nsl			:= LINKSRC = getnetconfig.3nsl
freenetconfigent.3nsl			:= LINKSRC = getnetconfig.3nsl
getnetconfigent.3nsl			:= LINKSRC = getnetconfig.3nsl
nc_perror.3nsl				:= LINKSRC = getnetconfig.3nsl
nc_sperror.3nsl				:= LINKSRC = getnetconfig.3nsl
setnetconfig.3nsl			:= LINKSRC = getnetconfig.3nsl

endnetpath.3nsl				:= LINKSRC = getnetpath.3nsl
setnetpath.3nsl				:= LINKSRC = getnetpath.3nsl

getsecretkey.3nsl			:= LINKSRC = getpublickey.3nsl
publickey.3nsl				:= LINKSRC = getpublickey.3nsl

endrpcent.3nsl				:= LINKSRC = getrpcbyname.3nsl
getrpcbyname_r.3nsl			:= LINKSRC = getrpcbyname.3nsl
getrpcbynumber.3nsl			:= LINKSRC = getrpcbyname.3nsl
getrpcbynumber_r.3nsl			:= LINKSRC = getrpcbyname.3nsl
getrpcent.3nsl				:= LINKSRC = getrpcbyname.3nsl
getrpcent_r.3nsl			:= LINKSRC = getrpcbyname.3nsl
setrpcent.3nsl				:= LINKSRC = getrpcbyname.3nsl

netdir_free.3nsl			:= LINKSRC = netdir.3nsl
netdir_getbyaddr.3nsl			:= LINKSRC = netdir.3nsl
netdir_getbyname.3nsl			:= LINKSRC = netdir.3nsl
netdir_mergeaddr.3nsl			:= LINKSRC = netdir.3nsl
netdir_options.3nsl			:= LINKSRC = netdir.3nsl
netdir_perror.3nsl			:= LINKSRC = netdir.3nsl
netdir_sperror.3nsl			:= LINKSRC = netdir.3nsl
taddr2uaddr.3nsl			:= LINKSRC = netdir.3nsl
uaddr2taddr.3nsl			:= LINKSRC = netdir.3nsl

auth_destroy.3nsl			:= LINKSRC = rpc_clnt_auth.3nsl
authnone_create.3nsl			:= LINKSRC = rpc_clnt_auth.3nsl
authsys_create.3nsl			:= LINKSRC = rpc_clnt_auth.3nsl
authsys_create_default.3nsl		:= LINKSRC = rpc_clnt_auth.3nsl

clnt_call.3nsl				:= LINKSRC = rpc_clnt_calls.3nsl
clnt_freeres.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
clnt_geterr.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
clnt_perrno.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
clnt_perror.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
clnt_send.3nsl				:= LINKSRC = rpc_clnt_calls.3nsl
clnt_sperrno.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
clnt_sperror.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
rpc_broadcast.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
rpc_broadcast_exp.3nsl			:= LINKSRC = rpc_clnt_calls.3nsl
rpc_call.3nsl				:= LINKSRC = rpc_clnt_calls.3nsl

clnt_control.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_create.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_create_timed.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_create_vers.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_create_vers_timed.3nsl		:= LINKSRC = rpc_clnt_create.3nsl
clnt_destroy.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_dg_create.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_door_create.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_pcreateerror.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_raw_create.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_spcreateerror.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_tli_create.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_tp_create.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
clnt_tp_create_timed.3nsl		:= LINKSRC = rpc_clnt_create.3nsl
clnt_vc_create.3nsl			:= LINKSRC = rpc_clnt_create.3nsl
rpc_createerr.3nsl			:= LINKSRC = rpc_clnt_create.3nsl

rpc_gss_get_mech_info.3nsl		:= LINKSRC = rpc_gss_get_mechanisms.3nsl
rpc_gss_get_versions.3nsl		:= LINKSRC = rpc_gss_get_mechanisms.3nsl
rpc_gss_is_installed.3nsl		:= LINKSRC = rpc_gss_get_mechanisms.3nsl

rpc_gss_svc_max_data_length.3nsl	:= LINKSRC = rpc_gss_max_data_length.3nsl

rpc_gss_qop_to_num.3nsl			:= LINKSRC = rpc_gss_mech_to_oid.3nsl

authdes_create.3nsl			:= LINKSRC = rpc_soc.3nsl
authunix_create.3nsl			:= LINKSRC = rpc_soc.3nsl
authunix_create_default.3nsl		:= LINKSRC = rpc_soc.3nsl
callrpc.3nsl				:= LINKSRC = rpc_soc.3nsl
clnt_broadcast.3nsl			:= LINKSRC = rpc_soc.3nsl
clntraw_create.3nsl			:= LINKSRC = rpc_soc.3nsl
clnttcp_create.3nsl			:= LINKSRC = rpc_soc.3nsl
clntudp_bufcreate.3nsl			:= LINKSRC = rpc_soc.3nsl
clntudp_create.3nsl			:= LINKSRC = rpc_soc.3nsl
get_myaddress.3nsl			:= LINKSRC = rpc_soc.3nsl
getrpcport.3nsl				:= LINKSRC = rpc_soc.3nsl
pmap_getmaps.3nsl			:= LINKSRC = rpc_soc.3nsl
pmap_getport.3nsl			:= LINKSRC = rpc_soc.3nsl
pmap_rmtcall.3nsl			:= LINKSRC = rpc_soc.3nsl
pmap_set.3nsl				:= LINKSRC = rpc_soc.3nsl
pmap_unset.3nsl				:= LINKSRC = rpc_soc.3nsl
registerrpc.3nsl			:= LINKSRC = rpc_soc.3nsl
svc_fds.3nsl				:= LINKSRC = rpc_soc.3nsl
svc_getcaller.3nsl			:= LINKSRC = rpc_soc.3nsl
svc_getreq.3nsl				:= LINKSRC = rpc_soc.3nsl
svc_register.3nsl			:= LINKSRC = rpc_soc.3nsl
svc_unregister.3nsl			:= LINKSRC = rpc_soc.3nsl
svcfd_create.3nsl			:= LINKSRC = rpc_soc.3nsl
svcraw_create.3nsl			:= LINKSRC = rpc_soc.3nsl
svctcp_create.3nsl			:= LINKSRC = rpc_soc.3nsl
svcudp_bufcreate.3nsl			:= LINKSRC = rpc_soc.3nsl
svcudp_create.3nsl			:= LINKSRC = rpc_soc.3nsl
xdr_authunix_parms.3nsl			:= LINKSRC = rpc_soc.3nsl

svc_dg_enablecache.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_done.3nsl				:= LINKSRC = rpc_svc_calls.3nsl
svc_exit.3nsl				:= LINKSRC = rpc_svc_calls.3nsl
svc_fd_negotiate_ucred.3nsl		:= LINKSRC = rpc_svc_calls.3nsl
svc_fdset.3nsl				:= LINKSRC = rpc_svc_calls.3nsl
svc_freeargs.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_getargs.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_getcallerucred.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_getreq_common.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_getreq_poll.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_getreqset.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_getrpccaller.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_max_pollfd.3nsl			:= LINKSRC = rpc_svc_calls.3nsl
svc_pollfd.3nsl				:= LINKSRC = rpc_svc_calls.3nsl
svc_run.3nsl				:= LINKSRC = rpc_svc_calls.3nsl
svc_sendreply.3nsl			:= LINKSRC = rpc_svc_calls.3nsl

svc_control.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_create.3nsl				:= LINKSRC = rpc_svc_create.3nsl
svc_destroy.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_dg_create.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_door_create.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_fd_create.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_raw_create.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_tli_create.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_tp_create.3nsl			:= LINKSRC = rpc_svc_create.3nsl
svc_vc_create.3nsl			:= LINKSRC = rpc_svc_create.3nsl

svcerr_auth.3nsl			:= LINKSRC = rpc_svc_err.3nsl
svcerr_decode.3nsl			:= LINKSRC = rpc_svc_err.3nsl
svcerr_noproc.3nsl			:= LINKSRC = rpc_svc_err.3nsl
svcerr_noprog.3nsl			:= LINKSRC = rpc_svc_err.3nsl
svcerr_progvers.3nsl			:= LINKSRC = rpc_svc_err.3nsl
svcerr_systemerr.3nsl			:= LINKSRC = rpc_svc_err.3nsl
svcerr_weakauth.3nsl			:= LINKSRC = rpc_svc_err.3nsl

svc_add_input.3nsl			:= LINKSRC = rpc_svc_input.3nsl
svc_remove_input.3nsl			:= LINKSRC = rpc_svc_input.3nsl

rpc_reg.3nsl				:= LINKSRC = rpc_svc_reg.3nsl
svc_auth_reg.3nsl			:= LINKSRC = rpc_svc_reg.3nsl
svc_reg.3nsl				:= LINKSRC = rpc_svc_reg.3nsl
svc_unreg.3nsl				:= LINKSRC = rpc_svc_reg.3nsl
xprt_register.3nsl			:= LINKSRC = rpc_svc_reg.3nsl
xprt_unregister.3nsl			:= LINKSRC = rpc_svc_reg.3nsl

xdr_accepted_reply.3nsl			:= LINKSRC = rpc_xdr.3nsl
xdr_authsys_parms.3nsl			:= LINKSRC = rpc_xdr.3nsl
xdr_callhdr.3nsl			:= LINKSRC = rpc_xdr.3nsl
xdr_callmsg.3nsl			:= LINKSRC = rpc_xdr.3nsl
xdr_opaque_auth.3nsl			:= LINKSRC = rpc_xdr.3nsl
xdr_rejected_reply.3nsl			:= LINKSRC = rpc_xdr.3nsl
xdr_replymsg.3nsl			:= LINKSRC = rpc_xdr.3nsl

rpcb_getaddr.3nsl			:= LINKSRC = rpcbind.3nsl
rpcb_getmaps.3nsl			:= LINKSRC = rpcbind.3nsl
rpcb_gettime.3nsl			:= LINKSRC = rpcbind.3nsl
rpcb_rmtcall.3nsl			:= LINKSRC = rpcbind.3nsl
rpcb_set.3nsl				:= LINKSRC = rpcbind.3nsl
rpcb_unset.3nsl				:= LINKSRC = rpcbind.3nsl

authdes_getucred.3nsl			:= LINKSRC = secure_rpc.3nsl
authdes_seccreate.3nsl			:= LINKSRC = secure_rpc.3nsl
getnetname.3nsl				:= LINKSRC = secure_rpc.3nsl
host2netname.3nsl			:= LINKSRC = secure_rpc.3nsl
key_decryptsession.3nsl			:= LINKSRC = secure_rpc.3nsl
key_encryptsession.3nsl			:= LINKSRC = secure_rpc.3nsl
key_gendes.3nsl				:= LINKSRC = secure_rpc.3nsl
key_secretkey_is_set.3nsl		:= LINKSRC = secure_rpc.3nsl
key_setsecret.3nsl			:= LINKSRC = secure_rpc.3nsl
netname2host.3nsl			:= LINKSRC = secure_rpc.3nsl
netname2user.3nsl			:= LINKSRC = secure_rpc.3nsl
user2netname.3nsl			:= LINKSRC = secure_rpc.3nsl

xdr_control.3nsl			:= LINKSRC = xdr_admin.3nsl
xdr_getpos.3nsl				:= LINKSRC = xdr_admin.3nsl
xdr_inline.3nsl				:= LINKSRC = xdr_admin.3nsl
xdr_setpos.3nsl				:= LINKSRC = xdr_admin.3nsl
xdr_sizeof.3nsl				:= LINKSRC = xdr_admin.3nsl
xdrrec_endofrecord.3nsl			:= LINKSRC = xdr_admin.3nsl
xdrrec_eof.3nsl				:= LINKSRC = xdr_admin.3nsl
xdrrec_readbytes.3nsl			:= LINKSRC = xdr_admin.3nsl
xdrrec_skiprecord.3nsl			:= LINKSRC = xdr_admin.3nsl

xdr_array.3nsl				:= LINKSRC = xdr_complex.3nsl
xdr_bytes.3nsl				:= LINKSRC = xdr_complex.3nsl
xdr_opaque.3nsl				:= LINKSRC = xdr_complex.3nsl
xdr_pointer.3nsl			:= LINKSRC = xdr_complex.3nsl
xdr_reference.3nsl			:= LINKSRC = xdr_complex.3nsl
xdr_string.3nsl				:= LINKSRC = xdr_complex.3nsl
xdr_union.3nsl				:= LINKSRC = xdr_complex.3nsl
xdr_vector.3nsl				:= LINKSRC = xdr_complex.3nsl
xdr_wrapstring.3nsl			:= LINKSRC = xdr_complex.3nsl

xdr_destroy.3nsl			:= LINKSRC = xdr_create.3nsl
xdrmem_create.3nsl			:= LINKSRC = xdr_create.3nsl
xdrrec_create.3nsl			:= LINKSRC = xdr_create.3nsl
xdrstdio_create.3nsl			:= LINKSRC = xdr_create.3nsl

xdr_bool.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_char.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_double.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_enum.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_float.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_free.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_hyper.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_int.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_long.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_longlong_t.3nsl			:= LINKSRC = xdr_simple.3nsl
xdr_quadruple.3nsl			:= LINKSRC = xdr_simple.3nsl
xdr_short.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_u_char.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_u_hyper.3nsl			:= LINKSRC = xdr_simple.3nsl
xdr_u_int.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_u_long.3nsl				:= LINKSRC = xdr_simple.3nsl
xdr_u_longlong_t.3nsl			:= LINKSRC = xdr_simple.3nsl
xdr_u_short.3nsl			:= LINKSRC = xdr_simple.3nsl
xdr_void.3nsl				:= LINKSRC = xdr_simple.3nsl

yp_all.3nsl				:= LINKSRC = ypclnt.3nsl
yp_bind.3nsl				:= LINKSRC = ypclnt.3nsl
yp_first.3nsl				:= LINKSRC = ypclnt.3nsl
yp_get_default_domain.3nsl		:= LINKSRC = ypclnt.3nsl
yp_master.3nsl				:= LINKSRC = ypclnt.3nsl
yp_match.3nsl				:= LINKSRC = ypclnt.3nsl
yp_next.3nsl				:= LINKSRC = ypclnt.3nsl
yp_order.3nsl				:= LINKSRC = ypclnt.3nsl
yp_unbind.3nsl				:= LINKSRC = ypclnt.3nsl
yperr_string.3nsl			:= LINKSRC = ypclnt.3nsl
ypprot_err.3nsl				:= LINKSRC = ypclnt.3nsl

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
