/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NFS_RESOLVE_H
#define	_NFS_RESOLVE_H

/* number of transports to try */
#define	MNT_PREF_LISTLEN	2
#define	FIRST_TRY		1
#define	SECOND_TRY		2

extern struct knetconfig *get_knconf(struct netconfig *);
extern void free_knconf(struct knetconfig *);
extern bool_t xdr_nfs_fsl_info(XDR *, struct nfs_fsl_info *);
extern struct netconfig *get_netconfig(NCONF_HANDLE *, ushort_t, char *);
extern int setup_nb_parms(struct netconfig *, struct t_bind *, struct t_info *,
    char *, int, bool_t, ushort_t, rpcprog_t, rpcvers_t, int);
extern void cleanup_tli_parms(struct t_bind *, int);
extern struct nfs_fsl_info *get_nfs4ref_info(char *, int, int);
extern void free_nfs4ref_info(struct nfs_fsl_info *);
extern struct netbuf *get_server_addr(char *, rpcprog_t, rpcvers_t,
    struct netconfig *, ushort_t, struct t_info *, caddr_t *,
    bool_t, char *, enum clnt_stat *);
extern struct netbuf *resolve_netconf(char *, rpcprog_t, rpcvers_t,
    struct netconfig **, ushort_t, struct t_info *,
    caddr_t *, bool_t, char *, enum clnt_stat *);

#endif /* _NFS_RESOLVE_H */
