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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef _IOMP_DRV_H
#define	_IOMP_DRV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/types32.h>
#include <sys/fiomp.h>

#define	SCF_IOMP_NAME		"mscf0"
#define	SCF_REAL_NAME		"/pseudo/scfd@200:mscf0"
#define	SCF_LOGCAL_PATH		"/dev/FJSVhwr/scfc"
#define	SCF_USER_PATH		"/dev/FJSVhwr/pwrctl"

#define	SCF_MAX_STR		256
#define	FIOMP_STAT_ONLINE	10
#define	FIOMP_STAT_OFFLINE	11
#define	FIOMP_STAT_UNCONFIGURED	12

#define	FIOMP_STAT_RECOVER	20

#define	FIOMP_STAT_BUSY		-1

struct fiompdev_32 {
	int		api_level;	/* API level = 0 */
	int		inst_no;	/* instance number */
	minor32_t	inst_minor;	/* instance management node */
	minor32_t	user_minor;	/* user access node */
	int		num;		/* number of devices */
	caddr32_t	devs;		/* device names */
	int		mpmode;		/* multi pathing */
	int		autopath;	/* automatic path change */
	int		block;		/* able to block physical device */
	int		needsync;	/* need synchronize path status */
	caddr32_t	ext;		/* for extension = NULL */
};

struct fiomp_devinfo_32 {
	int		inst_no;	/* instance number */
	char		real_name[FIOMP_MAX_STR]; /* instance management node */
	char		user_path[FIOMP_MAX_STR]; /* user access path */
	int		path_num;	/* number of paths */
	int		mpmode;		/* multi pathing */
	int		autopath;	/* automatic path change */
	int		block;		/* able to block physical device */
	int		needsync;	/* need synchronize path status */
	caddr32_t	ext;		/* for extension = NULL */
};

struct fiomp_all_devinfo_32 {
	int		num;		/* number of instances */
	caddr32_t	devinfo;	/* device informations */
};

struct fiompprop_32 {
	caddr32_t	iomp_name;	/* instance name */
	caddr32_t	iomp_real_name;
				/* instance management node (/devices) */
	caddr32_t	iomp_user_path;
				/* instance management node (/dev) */
	caddr32_t	iomp_status;	/* status of the instance */
	int		num;		/* number of paths */
	caddr32_t	iomp_path;	/* target device nodes (/devices) */
	caddr32_t	iomp_logical_path; /* target device nodes (/dev) */
	caddr32_t	iomp_path_status; /* status of target devices */
	caddr32_t	iomp_path_block; /* access block */
};

struct fiompstatus_32 {
	int		pathnum;	/* path number */
	int		status;		/* FIOMP_STAT_xxxx */
	caddr32_t	message;	/* some messages */
	int		block_status;	/* access block status */
	caddr32_t	ext;		/* reservesd (= NULL) */
};

struct fiomppath_32 {
	int		num;		/* number of paths */
	caddr32_t	devs;		/* device names */
};

struct fiomp_all_stat_32 {
	int		num;		/* number of paths */
	caddr32_t	status;		/* path status */
};

struct fiompchg_32 {
	int		num;		/* number of all paths */
	caddr32_t	set_status;	/* setting values */
	caddr32_t	pre_status;	/* previous values */
	caddr32_t	status;		/* current values */
};

struct fiompevent_32 {
	int		event;	/* event type = FIOMP_EVT_xx */
	int		num;	/* instance number(meta management) or */
				/* number of all path(instance management) */
	caddr32_t	pre_status;	/* previous status */
	caddr32_t	status;		/* current status */
};

#ifdef	__cplusplus
}
#endif

#endif /* _IOMP_DRV_H */
