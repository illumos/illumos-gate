/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1991 by Sun Microsystems, Inc.
 */

/* EDIT_START */

/*
 * nis_clnt.h
 *
 * This file contains definitions that are only of interest to the actual
 * service daemon and client stubs. Normal users of NIS will not include
 * this file.
 *
 * NOTE : This include file is automatically created by a combination
 * of rpcgen and sed. DO NOT EDIT IT, change the nis.x file instead
 * and then remake this file.
 */

#ifndef _NIS_CLNT_H
#define	_NIS_CLNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	NIS_PROG ((u_long)100300)
#define	NIS_VERSION ((u_long)3)

#ifdef __STDC__
#define	NIS_LOOKUP ((u_long)1)
extern  nis_result * nis_lookup_clnt(ns_request *, CLIENT *);
extern  nis_result * nis_lookup_svc(ns_request *, struct svc_req *);
#define	NIS_ADD ((u_long)2)
extern  nis_result * nis_add_clnt(ns_request *, CLIENT *);
extern  nis_result * nis_add_svc(ns_request *, struct svc_req *);
#define	NIS_MODIFY ((u_long)3)
extern  nis_result * nis_modify_clnt(ns_request *, CLIENT *);
extern  nis_result * nis_modify_svc(ns_request *, struct svc_req *);
#define	NIS_REMOVE ((u_long)4)
extern  nis_result * nis_remove_clnt(ns_request *, CLIENT *);
extern  nis_result * nis_remove_svc(ns_request *, struct svc_req *);
#define	NIS_IBLIST ((u_long)5)
extern  nis_result * nis_iblist_clnt(ib_request *, CLIENT *);
extern  nis_result * nis_iblist_svc(ib_request *, struct svc_req *);
#define	NIS_IBADD ((u_long)6)
extern  nis_result * nis_ibadd_clnt(ib_request *, CLIENT *);
extern  nis_result * nis_ibadd_svc(ib_request *, struct svc_req *);
#define	NIS_IBMODIFY ((u_long)7)
extern  nis_result * nis_ibmodify_clnt(ib_request *, CLIENT *);
extern  nis_result * nis_ibmodify_svc(ib_request *, struct svc_req *);
#define	NIS_IBREMOVE ((u_long)8)
extern  nis_result * nis_ibremove_clnt(ib_request *, CLIENT *);
extern  nis_result * nis_ibremove_svc(ib_request *, struct svc_req *);
#define	NIS_IBFIRST ((u_long)9)
extern  nis_result * nis_ibfirst_clnt(ib_request *, CLIENT *);
extern  nis_result * nis_ibfirst_svc(ib_request *, struct svc_req *);
#define	NIS_IBNEXT ((u_long)10)
extern  nis_result * nis_ibnext_clnt(ib_request *, CLIENT *);
extern  nis_result * nis_ibnext_svc(ib_request *, struct svc_req *);
#define	NIS_FINDDIRECTORY ((u_long)12)
extern  fd_result * nis_finddirectory_clnt(fd_args *, CLIENT *);
extern  fd_result * nis_finddirectory_svc(fd_args *, struct svc_req *);
#define	NIS_STATUS ((u_long)14)
extern  nis_taglist * nis_status_clnt(nis_taglist *, CLIENT *);
extern  nis_taglist * nis_status_svc(nis_taglist *, struct svc_req *);
#define	NIS_DUMPLOG ((u_long)15)
extern  log_result * nis_dumplog_clnt(dump_args *, CLIENT *);
extern  log_result * nis_dumplog_svc(dump_args *, struct svc_req *);
#define	NIS_DUMP ((u_long)16)
extern  log_result * nis_dump_clnt(dump_args *, CLIENT *);
extern  log_result * nis_dump_svc(dump_args *, struct svc_req *);
#define	NIS_CALLBACK ((u_long)17)
extern  bool_t * nis_callback_clnt(netobj *, CLIENT *);
extern  bool_t * nis_callback_svc(netobj *, struct svc_req *);
#define	NIS_CPTIME ((u_long)18)
extern  u_long * nis_cptime_clnt(nis_name *, CLIENT *);
extern  u_long * nis_cptime_svc(nis_name *, struct svc_req *);
#define	NIS_CHECKPOINT ((u_long)19)
extern  cp_result * nis_checkpoint_clnt(nis_name *, CLIENT *);
extern  cp_result * nis_checkpoint_svc(nis_name *, struct svc_req *);
#define	NIS_PING ((u_long)20)
extern  void * nis_ping_clnt(ping_args *, CLIENT *);
extern  void * nis_ping_svc(ping_args *, struct svc_req *);
#define	NIS_SERVSTATE ((u_long)21)
extern  nis_taglist * nis_servstate_clnt(nis_taglist *, CLIENT *);
extern  nis_taglist * nis_servstate_svc(nis_taglist *, struct svc_req *);
#define	NIS_MKDIR ((u_long)22)
extern  nis_error * nis_mkdir_clnt(nis_name *, CLIENT *);
extern  nis_error * nis_mkdir_svc(nis_name *, struct svc_req *);
#define	NIS_RMDIR ((u_long)23)
extern  nis_error * nis_rmdir_clnt(nis_name *, CLIENT *);
extern  nis_error * nis_rmdir_svc(nis_name *, struct svc_req *);

#else /* K&R C */

#define	NIS_LOOKUP ((u_long)1)
extern  nis_result * nis_lookup_clnt();
extern  nis_result * nis_lookup_svc();
#define	NIS_ADD ((u_long)2)
extern  nis_result * nis_add_clnt();
extern  nis_result * nis_add_svc();
#define	NIS_MODIFY ((u_long)3)
extern  nis_result * nis_modify_clnt();
extern  nis_result * nis_modify_svc();
#define	NIS_REMOVE ((u_long)4)
extern  nis_result * nis_remove_clnt();
extern  nis_result * nis_remove_svc();
#define	NIS_IBLIST ((u_long)5)
extern  nis_result * nis_iblist_clnt();
extern  nis_result * nis_iblist_svc();
#define	NIS_IBADD ((u_long)6)
extern  nis_result * nis_ibadd_clnt();
extern  nis_result * nis_ibadd_svc();
#define	NIS_IBMODIFY ((u_long)7)
extern  nis_result * nis_ibmodify_clnt();
extern  nis_result * nis_ibmodify_svc();
#define	NIS_IBREMOVE ((u_long)8)
extern  nis_result * nis_ibremove_clnt();
extern  nis_result * nis_ibremove_svc();
#define	NIS_IBFIRST ((u_long)9)
extern  nis_result * nis_ibfirst_clnt();
extern  nis_result * nis_ibfirst_svc();
#define	NIS_IBNEXT ((u_long)10)
extern  nis_result * nis_ibnext_clnt();
extern  nis_result * nis_ibnext_svc();
#define	NIS_FINDDIRECTORY ((u_long)12)
extern  fd_result * nis_finddirectory_clnt();
extern  fd_result * nis_finddirectory_svc();
#define	NIS_STATUS ((u_long)14)
extern  nis_taglist * nis_status_clnt();
extern  nis_taglist * nis_status_svc();
#define	NIS_DUMPLOG ((u_long)15)
extern  log_result * nis_dumplog_clnt();
extern  log_result * nis_dumplog_svc();
#define	NIS_DUMP ((u_long)16)
extern  log_result * nis_dump_clnt();
extern  log_result * nis_dump_svc();
#define	NIS_CALLBACK ((u_long)17)
extern  bool_t * nis_callback_clnt();
extern  bool_t * nis_callback_svc();
#define	NIS_CPTIME ((u_long)18)
extern  u_long * nis_cptime_clnt();
extern  u_long * nis_cptime_svc();
#define	NIS_CHECKPOINT ((u_long)19)
extern  cp_result * nis_checkpoint_clnt();
extern  cp_result * nis_checkpoint_svc();
#define	NIS_PING ((u_long)20)
extern  void * nis_ping_clnt();
extern  void * nis_ping_svc();
#define	NIS_SERVSTATE ((u_long)21)
extern  nis_taglist * nis_servstate_clnt();
extern  nis_taglist * nis_servstate_svc();
#define	NIS_MKDIR ((u_long)22)
extern  nis_error * nis_mkdir_clnt();
extern  nis_error * nis_mkdir_svc();
#define	NIS_RMDIR ((u_long)23)
extern  nis_error * nis_rmdir_clnt();
extern  nis_error * nis_rmdir_svc();

#endif /* K&R C */

/* Now print out the definitions of all the xdr functions */

#ifdef __STDC__
extern  bool_t xdr_nis_attr(XDR *, nis_attr *);
extern  bool_t xdr_nis_name(XDR *, nis_name *);
extern  bool_t xdr_zotypes(XDR *, zotypes *);
extern  bool_t xdr_nstype(XDR *, nstype *);
extern  bool_t xdr_oar_mask(XDR *, oar_mask *);
extern  bool_t xdr_endpoint(XDR *, endpoint *);
extern  bool_t xdr_nis_server(XDR *, nis_server *);
extern  bool_t xdr_directory_obj(XDR *, directory_obj *);
extern  bool_t xdr_entry_col(XDR *, entry_col *);
extern  bool_t xdr_entry_obj(XDR *, entry_obj *);
extern  bool_t xdr_group_obj(XDR *, group_obj *);
extern  bool_t xdr_link_obj(XDR *, link_obj *);
extern  bool_t xdr_table_col(XDR *, table_col *);
extern  bool_t xdr_table_obj(XDR *, table_obj *);
extern  bool_t xdr_objdata(XDR *, objdata *);
extern  bool_t xdr_nis_oid(XDR *, nis_oid *);
extern  bool_t xdr_nis_object(XDR *, nis_object *);
extern  bool_t xdr_nis_error(XDR *, nis_error *);
extern  bool_t xdr_nis_result(XDR *, nis_result *);
extern  bool_t xdr_ns_request(XDR *, ns_request *);
extern  bool_t xdr_ib_request(XDR *, ib_request *);
extern  bool_t xdr_ping_args(XDR *, ping_args *);
extern  bool_t xdr_log_entry_t(XDR *, log_entry_t *);
extern  bool_t xdr_log_entry(XDR *, log_entry *);
extern  bool_t xdr_log_result(XDR *, log_result *);
extern  bool_t xdr_cp_result(XDR *, cp_result *);
extern  bool_t xdr_nis_tag(XDR *, nis_tag *);
extern  bool_t xdr_nis_taglist(XDR *, nis_taglist *);
extern  bool_t xdr_dump_args(XDR *, dump_args *);
extern  bool_t xdr_fd_args(XDR *, fd_args *);
extern  bool_t xdr_fd_result(XDR *, fd_result *);

#else /* K&R C */

bool_t xdr_nis_attr();
bool_t xdr_nis_name();
bool_t xdr_zotypes();
bool_t xdr_nstype();
bool_t xdr_oar_mask();
bool_t xdr_endpoint();
bool_t xdr_nis_server();
bool_t xdr_directory_obj();
bool_t xdr_entry_col();
bool_t xdr_entry_obj();
bool_t xdr_group_obj();
bool_t xdr_link_obj();
bool_t xdr_table_col();
bool_t xdr_table_obj();
bool_t xdr_objdata();
bool_t xdr_nis_oid();
bool_t xdr_nis_object();
bool_t xdr_nis_error();
bool_t xdr_nis_result();
bool_t xdr_ns_request();
bool_t xdr_ib_request();
bool_t xdr_ping_args();
bool_t xdr_log_entry_t();
bool_t xdr_log_entry();
bool_t xdr_log_result();
bool_t xdr_cp_result();
bool_t xdr_nis_tag();
bool_t xdr_nis_taglist();
bool_t xdr_dump_args();
bool_t xdr_fd_args();
bool_t xdr_fd_result();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* _NIS_CLNT_H */
