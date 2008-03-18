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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * basic API declarations for share management
 */

#ifndef _LIBSHARE_NFS_H
#define	_LIBSHARE_NFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* property names used by NFS */
#define	SHOPT_RO	"ro"
#define	SHOPT_RW	"rw"

#define	SHOPT_SEC	"sec"
#define	SHOPT_SECURE	"secure"
#define	SHOPT_ROOT	"root"
#define	SHOPT_ANON	"anon"
#define	SHOPT_WINDOW	"window"
#define	SHOPT_NOSUB	"nosub"
#define	SHOPT_NOSUID	"nosuid"
#define	SHOPT_ACLOK	"aclok"
#define	SHOPT_PUBLIC	"public"
#define	SHOPT_INDEX	"index"
#define	SHOPT_LOG	"log"
#define	SHOPT_CKSUM	"cksum"

/*
 * defined options types. These should be in a file rather than
 * compiled in. Until there is a plugin mechanism to add new types,
 * this is sufficient.
 */
#define	OPT_TYPE_ANY		0
#define	OPT_TYPE_STRING		1
#define	OPT_TYPE_BOOLEAN	2
#define	OPT_TYPE_NUMBER		3
#define	OPT_TYPE_RANGE		4
#define	OPT_TYPE_USER		5
#define	OPT_TYPE_ACCLIST	6
#define	OPT_TYPE_DEPRECATED	7
#define	OPT_TYPE_SECURITY	8
#define	OPT_TYPE_PATH		9
#define	OPT_TYPE_FILE		10
#define	OPT_TYPE_LOGTAG		11
#define	OPT_TYPE_STRINGSET	12
#define	OPT_TYPE_DOMAIN		13
#define	OPT_TYPE_ONOFF		14
#define	OPT_TYPE_PROTOCOL	15

#define	OPT_SHARE_ONLY		1

struct option_defs {
	char *tag;
	int index;
	int type;
	int share;	/* share only option */
	int (*check)(sa_handle_t, char *);
};

/*
 * service bit mask values
 */
#define	SVC_LOCKD	0x0001
#define	SVC_STATD	0x0002
#define	SVC_NFSD	0x0004
#define	SVC_MOUNTD	0x0008
#define	SVC_NFS4CBD	0x0010
#define	SVC_NFSMAPID	0x0020
#define	SVC_RQUOTAD	0x0040
#define	SVC_NFSLOGD	0x0080

/*
 * place holder for future service -- will move to daemon_utils.h when
 * fully implemented.
 */
#define	NFSLOGD	"svc:/network/nfs/log:default"

/* The NFS export structure flags for read/write modes */
#define	NFS_RWMODES	(M_RO|M_ROL|M_RW|M_RWL)

/* other values */
/* max size of 64-bit integer in digits plus a bit extra */
#define	MAXDIGITS	32

/* external variable */
extern boolean_t nfsl_errs_to_syslog;

/* imported functions */
extern int exportfs(char *, struct exportdata *);
extern void _check_services(char **);
extern int nfs_getseconfig_default(seconfig_t *);
extern int nfs_getseconfig_byname(char *, seconfig_t *);
extern bool_t nfs_get_root_principal(seconfig_t *, char *, caddr_t *);
extern int nfsl_getconfig_list(nfsl_config_t **);
extern void nfsl_freeconfig_list(nfsl_config_t **);
extern nfsl_config_t *nfsl_findconfig(nfsl_config_t *, char *, int *);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBSHARE_NFS_H */
