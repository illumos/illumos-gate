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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __DEV_H
#define	__DEV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/types.h>
#include	<rpc/types.h>
#include	<synch.h>
#include	<sys/vol.h>
#include	<sys/vtoc.h>
#include	"medium.h"

/*
 * Header file for device maniplulation.
 */

struct devsw {
				/* begin using a device */
	bool_t	(*d_use)(char *, char *);
				/* deal with an error on a device */
	bool_t	(*d_error)(struct ve_error *);
	int	(*d_getfd)(dev_t);	/* return an fd to the dev_t */
	void	(*d_poll)(dev_t);	/* launch the poll again */
				/* build devmap */
	void	(*d_devmap)(struct vol *, int, int);
	void	(*d_close)(char *, dev_t);	/* stop using device */
				/* special eject support */
	void	(*d_eject)(struct devs *);
				/* find a missing volume */
	dev_t	(*d_find)(dev_t, struct vol  *);
				/* check to see if new media has arrived */
	int	(*d_check)(struct devs *);
	char	*d_mtype;	/* type of media this device handles */
	char	*d_dtype;	/* type of device */
	ulong_t	d_flags;	/* flags for volumes here */
	uid_t	d_uid;		/* uid for new inserts */
	gid_t	d_gid;		/* gid for new inserts */
	mode_t	d_mode;		/* mode for new inserts */
	bool_t	(*d_test)(char *); /* see if a path is okay for this device */
		/*
		 * Find the new default file descriptor for a medium
		 * after it has been repartitioned
		 */
	bool_t	(*d_remount)(struct vol *);
	long	d_pad[8];	/* room to grow */
	struct q d_pathl;	/* for reconfig stuff */
};

typedef struct dp_vol_lock {
	mutex_t		dp_vol_vg_mutex;	/* for access to cv */
	cond_t		dp_vol_vg_cv;		/* for signalling "vol gone" */
} dp_vol_lock_t;

/*
 * d_flags
 */
#define	D_POLL		0x01	/* device uses d_poll entry point */
#define	D_RDONLY	0x02	/* read-only drive (like cdrom) */
#define	D_RMONEJECT	0x04	/* default, remove volume when ejected */
#define	D_MEJECTABLE	0x08	/* easily manually ejectable */

#define	PID_LEN		17	/* product name length + 1 */
#define	VID_LEN		9	/* vendor name length + 1 */

typedef struct vendor_info {
	char	v_name[VID_LEN];
	char	p_name[PID_LEN];
} vendor_info_t;

struct devs {
	struct q	q;		/* hash queue */
	struct devsw	*dp_dsw;	/* devsw that is for this dev */
	dev_t		dp_dev;		/* device this represents */
	int		dp_ndev;	/* number of managed devices */
	dev_t		dp_all_dev[2 * V_NUMPAR];
					/* all devid which has been managed */
	char		*dp_path;	/* path to this device */
	void		*dp_priv;	/* driver private info */
	struct vvnode	*dp_rvn;	/* pointer to the char vn */
	struct vvnode	*dp_bvn;	/* pointer to the block vn */
	struct vol	*dp_vol;	/* vol_t that's in this device */
	bool_t		dp_writeprot;	/* dev is write protected */
	char		*dp_symname;	/* symbolic name for this dev */
	struct vvnode	*dp_symvn;	/* pointer to alias vn */
	int		dp_ndgrp;	/* number of devices in group */
	struct devs	**dp_dgrp;	/* pointers to dp's in group */
	bool_t		dp_checkresp;	/* respond to checker */
	dp_vol_lock_t	*dp_lock;	/* for signalling between threads */
	medium_handle_t dp_mediump;	/* ptr to medium object in device */
	uint_t		dp_flags;	/* flags */
	uint_t		dp_asynctask;	/* number of async tasks */
};

#define	DP_MEJECTABLE	0x01	/* this device is manually ejectable */
#define	DP_SCANNING	0x02	/* the device is being scanned. */

/*
 * Mapping of volume dev_t to device dev_t.
 */
typedef struct devmap {
	dev_t	dm_voldev;	/* from (vol device name) */
	char	*dm_path;	/* to (path of device media is in */
	dev_t	dm_realdev;	/* cache of the dev_t */
	int	dm_flag;
} devmap_t;

#define	DM_MAPPED	0x01	/* device has been mapped */
#define	DM_REMOVE	0x02	/* device mapping is being removed */
#define	DM_MINOR_VALID	0x04	/* minor number is allocated and valid */
#define	DM_MISSING	0x08	/* missing volume node */
#define	DM_CANCELED	0x10	/* node has been canceled */

/* dev prototypes */

extern void		dev_close(dev_t);
extern void		dev_closeout(struct vol *, bool_t);
extern void		dev_eject(struct vol *, bool_t);
extern void		dev_insert(dev_t);
extern void		dev_error(struct ve_error *);
extern bool_t		dev_use(char *, char *, char *, char *,
				char *, char *, char *, bool_t, bool_t);
extern void		dev_devmap(struct vol *);
extern bool_t		dev_devmapfree(struct vol *);
extern bool_t		dev_map(struct vol *, bool_t);
extern bool_t		dev_map_dropin(struct vol *);
extern bool_t		dev_map_missing(struct vol *, minor_t, bool_t);
extern void		dev_handle_missing(struct vol *, struct vol *);
extern void		dev_reset_devmap(struct vol *, struct vol *);
extern struct vvnode	*dev_newvol(char *, struct label *, time_t);
extern int		dev_type(char *);
extern char 		*dev_ident(int);
extern struct devs 	*dev_getdp(dev_t);
extern struct devs	*dev_search_dp(dev_t);
extern struct devs	*dev_makedp(struct devsw *, char *);
extern int		dev_nastask(void);
extern void		dev_freedp(struct devs *);
extern struct vvnode	*dev_dirpath(char *);
extern char		*dev_makepath(dev_t);
extern void		dev_unhangvol(struct devs *);
extern bool_t		dev_rdonly(dev_t);
extern struct vol 	*dev_unlabeled(struct devs *, enum laread_res,
				struct label *);
extern char		*dev_symname(dev_t);
extern bool_t		dev_remount(struct vol *);
extern int		dev_reset_symname(struct devs *dp, int fd);
extern void		dev_hard_eject(struct devs *dp);
extern void		dev_new(struct devsw *dsw);

#define	DEV_SYM		"dev_init"

#ifdef	__cplusplus
}
#endif

#endif /* __DEV_H */
