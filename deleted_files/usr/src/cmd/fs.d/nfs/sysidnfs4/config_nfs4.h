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

#ifndef _CONFIG_NFS4_H
#define	_CONFIG_NFS4_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	UID_ROOT
#define	UID_ROOT	0
#endif

#ifndef	GID_SYS
#define	GID_SYS		3
#endif

#define	NFS4CFG_FILE		"/etc/default/nfs"
#define	NFS4STE_FILE		"/etc/.NFS4inst_state.domain"

typedef enum {
	NFS4CMD_CHECK		= 0,	/* check pattern setting in nfs4 cfg */
	NFS4CMD_CONFIG		= 1,	/* set pattern=value in nfs4 cfg */
	NFS4CMD_UNCONFIG	= 2,	/* ENOTSUP */
	NFS4CMD_COMMENT		= 3,	/* comment 'pattern' in nfs4 cfg */
	NFS4CMD_UNCOMMENT	= 4	/* ENOTSUP */
} nfs4cmd_t;

typedef enum {
	NFS4CFG_OK		=  0,	/* success			   */
	NFS4CFG_ERR_CFG_STAT	= -1,	/* error stating /etc/default/nfs  */
	NFS4CFG_ERR_CFG_OPEN_RO	= -2,	/* error opening nfs4 cfg file RO  */
	NFS4CFG_ERR_CFG_OPEN_RW	= -3,	/* error opening nfs4 cfg file RW  */
	NFS4CFG_ERR_CFG_CREAT	= -4,	/* error creating nfs4 cfg file    */
	NFS4CFG_ERR_CFG_FDOPEN	= -5,	/* error assoc. stream to nfs4 fd  */
	NFS4CFG_ERR_CFG_WCHMOD	= -6,	/* error on chmod of nfs4 cfg file */
	NFS4CFG_ERR_CFG_WCHOWN	= -7,	/* error on chown of nfs4 cfg file */
	NFS4CFG_ERR_WRK_OPEN	= -8,	/* error opening work file	   */
	NFS4CFG_ERR_WRK_FDOPEN	= -9,	/* error assoc. stream to work fd  */
	NFS4CFG_ERR_WRK_WCHMOD	= -10,	/* error on chmod of work file	   */
	NFS4CFG_ERR_WRK_WCHOWN	= -11,	/* error on chown of work file	   */
	NFS4CFG_ERR_WRK_FNAME	= -12,	/* error generating work file name */
	NFS4CFG_ERR_WRK_RENAME	= -13	/* error renaming work -> nfs4 cfg */
} nfs4cfg_err_t;

extern int	 config_nfs4(int, const char *, char *);
extern char	 cur_domain[];

#ifdef	__cplusplus
}
#endif

#endif	/* _CONFIG_NFS4_H */
