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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_NFS_CMD_H
#define	_NFS_CMD_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kiconv.h>

#define	KICONV_MAX_CODENAME_LEN	63 /* copied from sys/kiconv.h */

#define	NFSCMD_VERS_1	1
#define	NFSCMD_VERSION	NFSCMD_VERS_1

typedef enum { NFSCMD_CHARMAP_LOOKUP, NFSCMD_ERROR } nfscmd_t;
typedef enum { NFSCMD_ERR_SUCCESS, NFSCMD_ERR_BADCMD, NFSCMD_ERR_NOTFOUND,
    NFSCMD_ERR_FAIL, NFSCMD_ERR_DROP, NFSCMD_ERR_NOMEM } nfscmd_err_t;
#define	NFSCMD_ERR_RET	0x100000

typedef struct nfscmd_arg {
	uint32_t	version;
	nfscmd_t	cmd;
	union {
		struct {
			char path[MAXPATHLEN];
			struct sockaddr addr;
		} charmap;
	} arg;
} nfscmd_arg_t;

typedef struct nfscmd_res {
	uint32_t	version;
	uint32_t	cmd;
	nfscmd_err_t	error;
	union {
		struct {
		    char	codeset[KICONV_MAX_CODENAME_LEN + 1];
		    uint32_t	apply;
		} charmap;
	} result;
} nfscmd_res_t;

#ifdef _KERNEL

#define	NFSCMD_CONV_INBOUND	1
#define	NFSCMD_CONV_OUTBOUND	0

extern int nfscmd_send(nfscmd_arg_t *, nfscmd_res_t *);
extern struct charset_cache *nfscmd_findmap(struct exportinfo *,
    struct sockaddr *);
extern char *nfscmd_convname(struct sockaddr *, struct exportinfo *,
    char *, int, size_t);
extern char *nfscmd_convdirent(struct sockaddr *, struct exportinfo *, char *,
    size_t, enum nfsstat3 *);
extern size_t nfscmd_convdirplus(struct sockaddr *, struct exportinfo *, char *,
    size_t, size_t, char **);
extern size_t nfscmd_countents(char *, size_t);
extern size_t nfscmd_dropped_entrysize(struct dirent64 *, size_t, size_t);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_CMD_H */
