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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * nfs_sec.h, NFS specific security service information.
 */

#ifndef	_NFS_SEC_H
#define	_NFS_SEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <rpc/rpcsec_gss.h>

#ifndef _KERNEL
#define	NFSSEC_CONF	"/etc/nfssec.conf"
#define	SC_FAILURE	-1
/*
 * An error string produced by nfs_syslog_scerr can be no longer than
 * MAXMSGLEN
 */
#define	MAXMSGLEN	80

/*
 *  Errors for the nfssec_*
 */
#define	SC_NOERROR	0
#define	SC_NOMEM	1
#define	SC_OPENFAIL	2
#define	SC_NOTFOUND	3
#define	SC_BADENTRIES	4	/* Bad entries in nfssec.conf file */
#endif /* _KERNEL */

typedef struct seconfig {
	char		sc_name[MAX_NAME_LEN];
	int		sc_nfsnum;
	int		sc_rpcnum;
	char		sc_gss_mech[MAX_NAME_LEN];
	struct rpc_gss_OID_s	*sc_gss_mech_type;
	uint_t		sc_qop;
	rpc_gss_service_t	sc_service;
	uid_t		sc_uid;
} seconfig_t;

#ifdef _SYSCALL32
typedef struct seconfig32 {
	char		sc_name[MAX_NAME_LEN];
	int32_t		sc_nfsnum;
	int32_t		sc_rpcnum;
	char		sc_gss_mech[MAX_NAME_LEN];
	caddr32_t	sc_gss_mech_type;
	uint32_t	sc_qop;
	int32_t		sc_service;
	uid_t		sc_uid;
} seconfig32_t;
#endif /* _SYSCALL32 */

#ifndef _KERNEL
extern int nfs_getseconfig_default(seconfig_t *);
extern int nfs_getseconfig_byname(char *, seconfig_t *);
extern int nfs_getseconfig_bynumber(int, seconfig_t *);
extern int nfs_getseconfig_bydesc(char *, char *, rpc_gss_service_t,
    seconfig_t *);
extern sec_data_t *nfs_clnt_secdata(seconfig_t *, char *, struct knetconfig *,
    struct netbuf *, int);
extern void nfs_free_secdata(sec_data_t *);
extern int nfs_syslog_scerr(int, char[]);
extern bool_t nfs_get_root_principal(seconfig_t *, char *, caddr_t *);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* !_NFS_SEC_H */
