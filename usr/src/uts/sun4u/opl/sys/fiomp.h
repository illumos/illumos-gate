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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FIOMP_H
#define	_FIOMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	FIOMP_TRUE  1
#define	FIOMP_FALSE 0

#define	FIOMP_MAX_STR	1024	/* same as FILENAME_MAX */

#define	FIOMP_PATH_ALL	(-1)

/* ioctl base */
#define	FIOMPC		('f' << 8)

/*
 * ioctl for the meta management node
 */

/* create a new multi-path */
#define	FIOMPNEW	(FIOMPC|0x0)
/* encapsulate using devices */
#define	FIOMPENCAP	(FIOMPC|0x1)
struct fiompdev {
	int	api_level;		/* API level = 0 */
	int	inst_no;		/* instance number */
	minor_t	inst_minor;		/* instance management node */
	minor_t	user_minor;		/* user access node */
	int	num;			/* number of devices */
	char	**devs;			/* device names */
	int	mpmode;			/* multi pathing */
	int	autopath;		/* automatic path change */
	int	block;			/* able to block physical device */
	int	needsync;		/* need synchronize path status */
	void	*ext;			/* for extension = NULL */
};

/* get an instance device's information */
#define	FIOMPDEVINFO	(FIOMPC|0x2)
struct fiomp_devinfo {
	int	inst_no;		/* instance number */
	char	real_name[FIOMP_MAX_STR]; /* instance management node */
	char	user_path[FIOMP_MAX_STR]; /* user access path */
	int	path_num;		/* number of paths */
	int	mpmode;			/* multi pathing */
	int	autopath;		/* automatic path change */
	int	block;			/* able to block physical device */
	int	needsync;		/* need synchronize path status */
	void	*ext;			/* for extension = NULL */
};

/* get number of all instances */
#define	FIOMPALLINSTNUM	(FIOMPC|0x3)

/* get all device's informations */
#define	FIOMPALLDEVINFO	(FIOMPC|0x4)
struct fiomp_all_devinfo {
	int	num;			/* number of instances */
	struct	fiomp_devinfo *devinfo;	/* device informations */
};

/* keep 0x5 - 0xf for reserve */

/*
 * ioctl for instance management nodes
 */
/* get max number of paths */
#define	FIOMPMAXPATHNUM	(FIOMPC|0x10)

/* set the device's property */
#define	FIOMPSETPROP	(FIOMPC|0x11)

/* get the device's property */
#define	FIOMPGETPROP	(FIOMPC|0x12)
struct fiompprop {
	char	*iomp_name;		/* instance name */
	char	*iomp_real_name;
				/* instance management node (/devices) */
	char	*iomp_user_path;	/* instance management node (/dev) */
	char	*iomp_status;		/* status of the instance */
	int	num;			/* number of paths */
	char	**iomp_path;		/* target device nodes (/devices) */
	char	**iomp_logical_path;	/* target device nodes (/dev) */
	char	**iomp_path_status;	/* status of target devices */
	char	**iomp_path_block;	/* access block */
};

/* destroy the instance */
#define	FIOMPDESTROY	(FIOMPC|0x13)

/* stop the path */
#define	FIOMPSTOP	(FIOMPC|0x14)

/* start the path */
#define	FIOMPSTART	(FIOMPC|0x15)

/* list all paths */
#define	FIOMPLIST	(FIOMPC|0x16)

/* get the path status */
#define	FIOMPSTATUS	(FIOMPC|0x17)
struct fiompstatus {
	int	pathnum;		/* path number */
	int	status;			/* FIOMP_STAT_xxxx */
	char	*message;		/* some messages */
	int	block_status;		/* access block status */
	void	*ext;			/* reservesd (= NULL) */
};

/* status */
#define	FIOMP_STAT_ACTIVE	PATH_STAT_ACTIVE
#define	FIOMP_STAT_STANDBY	PATH_STAT_STANDBY
#define	FIOMP_STAT_STOP		PATH_STAT_STOP
#define	FIOMP_STAT_FAIL		PATH_STAT_FAIL
#define	FIOMP_STAT_DISCON	PATH_STAT_DISCON
#define	FIOMP_STAT_ENCAP	PATH_STAT_ENCAP
#define	FIOMP_STAT_EMPTY	PATH_STAT_EMPTY

/* access block status */
#define	FIOMP_BSTAT_BLOCK	1
#define	FIOMP_BSTAT_UNBLOCK	0

/* add, delete */
#define	FIOMPADD	(FIOMPC|0x18)
#define	FIOMPDEL	(FIOMPC|0x19)
struct fiomppath {
	int	num;			/* number of paths */
	char	**devs;			/* device names */
};

/* active, stabdby */
#define	FIOMPACTIVE	(FIOMPC|0x1a)
#define	FIOMPSTANDBY	(FIOMPC|0x1b)

/* block, unblock */
#define	FIOMPBLOCK	(FIOMPC|0x1c)
#define	FIOMPUNBLOCK	(FIOMPC|0x1d)

/* diagnostic mode ON,OFF */
#define	FIOMPDIAGON	(FIOMPC|0x1e)
#define	FIOMPDIAGOFF	(FIOMPC|0x1f)
struct fiomp_diag_mode {
	int	 pathnum;		/* path for diagnostic */
	int	level;			/* = 0 */
};

/* get all status */
#define	FIOMPGETALLSTAT	(FIOMPC|0x20)
struct fiomp_all_stat {
	int	num;			/* number of paths */
	struct	fiompstatus *status;	/* path status */
};

/* change the status of paths */
#define	FIOMPCHG	(FIOMPC|0x21)
struct fiompchg {
	int num;			/* number of all paths */
	struct	fiompstatus *set_status; /* setting values */
	struct	fiompstatus *pre_status; /* previous values */
	struct	fiompstatus *status;	/* current values */
};

/* recover the failed path */
#define	FIOMPRECOVER	(FIOMPC|0x22)

/* disconnect/reconnect the path */
#define	FIOMPDISCONNECT	(FIOMPC|0x23)
#define	FIOMPCONNECT	(FIOMPC|0x24)

/* keep 0x25 - 0x2f for reserve */

/*
 * Common ioctl
 */
/* get event */
#define	FIOMPGETEVENT	(FIOMPC|0x30)
struct fiompevent {
	int	event;		/* event type = FIOMP_EVT_xx */
	int	num;		/* instance number(meta management) or */
				/* number of all path(instance management) */
	struct	fiompstatus *pre_status; /* previous status */
	struct	fiompstatus *status;	/* current status */
};

/* event type */
#define	FIOMP_EVT_NONE		0x0
#define	FIOMP_EVT_NEW		0x1
#define	FIOMP_EVT_DESTROY	0x2
#define	FIOMP_EVT_STAT		0x101
#define	FIOMP_EVT_PATHS		0x102

/*
 * Device property
 */
#define	FIOMP_PROP_NAME		"iomp-name"
#define	FIOMP_PROP_REAL_NAME	"iomp-real-name"
#define	FIOMP_PROP_PATH_N	"iomp-path-"
#define	FIOMP_PROP_USER_PATH	"iomp-user-path"
#define	FIOMP_PROP_LOGIC_PATH_N	"iomp-logical-path-"
#define	FIOMP_PROP_STATUS	"iomp-status"
#define	FIOMP_PROP_PATH_NUM	"iomp-path-num"
#define	FIOMP_PROP_STATUS_N	"iomp-path-status-"

#define	FIOMP_PROP_BLOCK_N	"iomp-path-block-"
#define	FIOMP_PROP_BLOCK_DEFAULT "iomp-path-block-default"

#ifdef	__cplusplus
}
#endif

#endif /* _FIOMP_H */
