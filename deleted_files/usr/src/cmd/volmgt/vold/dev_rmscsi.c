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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mkdev.h>
#include	<sys/dkio.h>
#include	<sys/vtoc.h>
#if defined(_FIRMWARE_NEEDS_FDISK)
#include	<sys/dktp/fdisk.h>
#endif
#include	<errno.h>
#include	<signal.h>
#include	<string.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<thread.h>
#include	<synch.h>
#include	"vold.h"


#ifdef	P0_WA
#undef	P0_WA		/* disable P0_WA (P0 workaround) for Intel */
#endif


static bool_t	rmscsi_use(char *, char *);
static bool_t	rmscsi_error(struct ve_error *);
static int	rmscsi_getfd(dev_t);
static void	rmscsi_devmap(vol_t *, int, int);
static void	rmscsi_close(char *path, dev_t);
static void	rmscsi_thread_wait(struct devs *dp);
static bool_t	rmscsi_testpath(char *);



#define	RMSCSI_MTYPE	"rmscsi"		/* should be in vold.h */


static struct devsw rmscsidevsw = {
	rmscsi_use,		/* d_use */
	rmscsi_error,		/* d_error */
	rmscsi_getfd,		/* d_getfd */
	NULL,			/* d_poll */
	rmscsi_devmap,		/* d_devmap */
	rmscsi_close,		/* d_close */
	NULL, 			/* d_eject */
	NULL, 			/* d_find */
	NULL,			/* d_check */
	RMSCSI_MTYPE,		/* d_mtype */
	DRIVE_CLASS,		/* d_dtype */
	D_POLL|D_MEJECTABLE,	/* d_flags */
	(uid_t)0,		/* d_uid */
	(gid_t)0,		/* d_gid */
	(mode_t)0,		/* d_mode */
	rmscsi_testpath		/* d_test */
};



bool_t
dev_init()
{
	dev_new(&rmscsidevsw);
	return (TRUE);
}


static struct rmscsi_priv {
	char	*rs_rawpath[V_NUMPAR];
	mutex_t	rs_killmutex;			/* mutex for killing thread */
	int	rs_tid;				/* thread id */
	int	rs_fd[V_NUMPAR];
	int	rs_defpart;
#ifdef	P0_WA
	char	*rs_blk_p0_path;		/* the p0 blk name */
	int	rs_p0_part;		/* slice to substitute p0 for */
#endif
#if defined(_FIRMWARE_NEEDS_FDISK)
	int	rs_raw_pfd[FD_NUMPART+1];	/* char fdisk-partition fds */
#endif
};

#define	RMSCSI_NAMEPROTO_DEFD	"%sd0s%d"
#define	RMSCSI_BASEPART		DEFAULT_PARTITION

#define	RMSCSI_NAMEPROTO	"%ss%d"

#if defined(_FIRMWARE_NEEDS_FDISK)
#define	RMSCSI_NAMEPROTO_P	"%sp%d"
#ifdef	P0_WA
#define	RMSCSI_NAMEPROTO_P_ALL	0
#endif
static void	rmscsi_open_exclusive(struct rmscsi_priv *, char *, char *);
#endif


/* thread stack size */
#define	RMSCSI_STKSIZE		(32 * 1024)	/* 32k! */


/*
 * rmscsi_use -- this routine expects either a raw or block path that
 *	to a removable scsi disk (removability being detected
 *	using a SCSI inquiry command)
 *
 *	it further expects that the supplied
 *	path starts with "/dev/dsk/" for block devices or
 *	"/dev/rdsk" for character devices
 *
 *	it finds the complimentary device by switching this
 *	segment, e.g. if you supply "/dev/dsk/c0t6" for a
 *	group of block devices, then this routine will
 *	expect the raw devices to be at "/dev/rdsk/c0t6"
 *
 *	a thread is created which will handle this new group of
 *	interfaces to a device
 *
 *	a devs struct is filled in and passed on to the thread
 *
 *	return TRUE implies that the device is one which isn't
 *	currently managed, and needs to be
 */
static bool_t
rmscsi_use(char *path, char *symname)
{
	struct stat		statbuf;
	char			namebuf1[MAXPATHLEN];
	char			full_path[MAXPATHLEN+1];
	char			*path_trunc = path;
	char			namebuf[MAXNAMELEN];
	struct devs		*dp;
	struct rmscsi_priv	*rsp;
	char			*s;
	char			*p;
	vvnode_t		*bvn;
	vvnode_t		*rvn;
	int			i;



	info(gettext("rmscsi_use: %s, %s\n"), path, symname);

	/*
	 * we don't do an open for the device because it'll probably just
	 * return ENODEV if there isn't a device there
	 *
	 * instead, we just stat the device and make sure the device
	 *  node is there and is a reasonable type
	 */

	/* just take a path if they hand it to us. */
	if (stat(path, &statbuf) < 0) {
		/*
		 * we can accept a path of the form:
		 *
		 * 	/dev/{dsk,rdsk}/cNtN
		 *
		 * we fill in the rest by appending "d0sN"
		 */
		(void) sprintf(full_path, RMSCSI_NAMEPROTO_DEFD, path,
		    RMSCSI_BASEPART);
		if (stat(full_path, &statbuf) < 0) {
			/* can't even find it with "d0sN" appended! */
			debug(1, "rmscsi_use: stat of \"%s\"; %m\n",
			    full_path);
			return (FALSE);
		}
	} else {
		/*
		 * the supplied path is complete -- truncate at the "slice"
		 * part of the name
		 *
		 * XXX: assume all rmscsi pathnames end in "sN"
		 */
		(void) strcpy(full_path, path);
		if ((s = strrchr(path, 's')) != 0) {
			/* XXX: should make sure a slice number follows */
			*s = '\0';		/* truncate at the "sN" */
		} else {
			/* the full path didn't have an "s" in it! */
			warning(gettext("rmscsi: %s is an invalid path\n"),
			    full_path);
			return (FALSE);
		}
	}

	/*
	 * check to see if this guy is already configured
	 */
	if ((dp = dev_getdp(statbuf.st_rdev)) != NULL) {
		if (dp->dp_dsw == &rmscsidevsw) {
			debug(1, "rmscsi_use: %s already in use\n", full_path);
			return (TRUE);
		} else {
			debug(1, "rmscsi_use: %s already managed by %s\n",
				full_path, dp->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	/*
	 * check the modes to make sure that the path is either
	 * a block or a character device
	 */
	if (!S_ISCHR(statbuf.st_mode) && !S_ISBLK(statbuf.st_mode)) {
		warning(gettext(
		    "rmscsi: %s not block or char device (mode 0x%x)\n"),
		    namebuf, statbuf.st_mode);
		return (FALSE);
	}

	/* create en "empty" 'rmscsi-private' data struct */
	rsp = (struct rmscsi_priv *)calloc(1, sizeof (struct rmscsi_priv));
	for (i = 0; i < V_NUMPAR; i++) {
		rsp->rs_fd[i] = -1;
	}
	rsp->rs_defpart = -1;
#ifdef	P0_WA
	rsp->rs_p0_part = -1;
#endif

	/* stick some good stuff in the device hierarchy */
	if ((s = strstr(path_trunc, "rdsk")) != 0) {

		/* he gave us a raw path (i.e. "rdsk" in it) */

		/* save a pointer to the raw vv-node */
		rvn = dev_dirpath(path_trunc);

		/* create the names for rawpath */
		for (i = 0; i < V_NUMPAR; i++) {
			(void) sprintf(namebuf1, RMSCSI_NAMEPROTO,
			    path_trunc, i);
			rsp->rs_rawpath[i] = strdup(namebuf1);
		}

		/* get the block path now from the raw one */

		/* skip past "rdsk/" */
		if ((p = strchr(s, '/')) != 0) {
			p++;
			(void) sprintf(namebuf, "/dev/dsk/%s", p);
		} else {
			/* no slash after rdsk? */
			debug(1, "rmscsi_use: malformed pathname '%s'\n",
			    path_trunc);
			/* what else can we do? */
			(void) strcpy(namebuf, path_trunc);
		}

		/* get the block vv-node */
		bvn = dev_dirpath(namebuf);

#ifdef	P0_WA
		/* set up the p0 block pathname */
		(void) sprintf(namebuf1, RMSCSI_NAMEPROTO_P, namebuf,
		    RMSCSI_NAMEPROTO_P_ALL);
		rsp->rs_blk_p0_path = strdup(namebuf1);
#endif

	} else if (s = strstr(path_trunc, "dsk")) {

		/* he gave us the block path */

		/* save pointer to block vv-node */
		bvn = dev_dirpath(path_trunc);

#ifdef	P0_WA
		(void) sprintf(namebuf1, RMSCSI_NAMEPROTO_P, path_trunc,
		    RMSCSI_NAMEPROTO_P_ALL);
		rsp->rs_blk_p0_path = strdup(namebuf1);
#endif

		/* skip past "dsk/" */
		if ((p = strchr(s, '/')) != 0) {
			p++;
			(void) sprintf(namebuf, "/dev/rdsk/%s", p);
		} else {
			/* no slash after "dsk"? */
			debug(1, "rmscsi_use: malformed path name '%s'\n",
			    path);
			/* what else can we do? */
			(void) strcpy(namebuf, path_trunc);
		}

		/* save a pointer to the raw vv-node */
		rvn = dev_dirpath(namebuf);

		/* create the names for rawpath */
		for (i = 0; i < V_NUMPAR; i++) {
			(void) sprintf(namebuf1, RMSCSI_NAMEPROTO, namebuf, i);
			rsp->rs_rawpath[i] = strdup(namebuf1);
		}

	} else {
		debug(1, "rmscsi_use: malformed path name '%s'\n", path_trunc);
		return (FALSE);
	}

#if	defined(P0_WA) && defined(DEBUG)
	debug(6, "rmscsi_use: p0 block path is \"%s\"\n", rsp->rs_blk_p0_path);
#endif

	if ((dp = dev_makedp(&rmscsidevsw,
	    rsp->rs_rawpath[RMSCSI_BASEPART])) == NULL) {
		debug(1, "rmscsi_use: dev_makedp failed for %s\n",
		    rsp->rs_rawpath[RMSCSI_BASEPART]);
		return (FALSE);
	}

#if defined(_FIRMWARE_NEEDS_FDISK)
	/*
	 * serious hackery --  open the p? interfaces (so others can't
	 *	get around us)
	 */
	rmscsi_open_exclusive(rsp, namebuf, path);
#endif

	dp->dp_priv = (void *)rsp;		/* ptr to our private data */
	dp->dp_symname = strdup(symname);	/* symbolic name */
	dp->dp_bvn = bvn;			/* ptr to block vv-node */
	dp->dp_rvn = rvn;			/* ptr to raw vv-node */

	(void) mutex_init(&rsp->rs_killmutex, USYNC_THREAD, NULL);
	if (thr_create(0, RMSCSI_STKSIZE,
	    (void *(*)(void *))rmscsi_thread_wait, (void *)dp, THR_BOUND,
	    (thread_t *)&(rsp->rs_tid)) < 0) {
		warning(gettext("rmscsi thread create failed; %m\n"));
		return (FALSE);
	}
#ifdef	DEBUG
	debug(6, "rmscsi_use: rmscsi_thread_wait id %d created\n", rsp->rs_tid);
#endif
	return (TRUE);
}


/*ARGSUSED*/
static void
rmscsi_devmap(vol_t *v, int part, int off)
{
	struct devs		*dp;
	struct rmscsi_priv	*rsp;


	dp = dev_getdp(v->v_basedev);
	rsp = (struct rmscsi_priv *)dp->dp_priv;

#ifdef	P0_WA
	/* return P0 path for bigest slice that starts at 0 */
	if (part == rsp->rs_p0_part) {
		/* hack! -- use p0 instead of the requested slice */
		v->v_devmap[off].dm_path = strdup(rsp->rs_blk_p0_path);
		debug(6, "rmscsi_devmap: hacking path for p0 workaround\n");
	} else {
		/* return the actual slice requested */
		v->v_devmap[off].dm_path = strdup(rsp->rs_rawpath[part]);
	}
#else
	v->v_devmap[off].dm_path = strdup(rsp->rs_rawpath[part]);
#endif

#ifdef	DEBUG
	debug(9, "rmscsi_devmap: returning (slice %d, off %d): \"%s\"\n",
	    part, off, v->v_devmap[off].dm_path);
#endif
}


static int
rmscsi_getfd(dev_t dev)
{
	struct devs		*dp;
	struct rmscsi_priv	*rsp;
	int			fd;


	dp = dev_getdp(dev);
	ASSERT(dp != NULL);
	rsp = (struct rmscsi_priv *)dp->dp_priv;
	ASSERT(rsp->rs_defpart != -1);
	ASSERT(rsp->rs_fd[rsp->rs_defpart] >= 0);
	fd = rsp->rs_fd[rsp->rs_defpart];
	return (fd);
}


/*ARGSUSED*/
static bool_t
rmscsi_error(struct ve_error *vie)
{
	debug(1, "rmscsi_error\n");
	return (TRUE);
}


/*
 * State that must be cleaned up:
 *	name in the name space
 *	the "dp"
 *	any pointers to the media
 *	eject any existing media
 *	the priv structure
 */

/*
 * XXX: a bug still exists here.  we have a thread polling on this
 * XXX: device in the kernel, we need to get rid of this also.
 * XXX: since we're going to move the waiter thread up to the
 * XXX: user level, it'll be easier to kill off as part of the
 * XXX: cleanup of the device private data.
 */
static void
rmscsi_close(char *path, dev_t rdev)
{
	char			namebuf[MAXNAMELEN];
	struct	stat		sb;
	struct devs		*dp;
	struct rmscsi_priv	*rsp;
	int			i;

	debug(1, "rmscsi_close %s\n", path);

	(void) sprintf(namebuf, RMSCSI_NAMEPROTO, path, RMSCSI_BASEPART);
	if (stat(namebuf, &sb) < 0) {
		if (rdev == NODEV) {
			warning(gettext("rmscsi_close: %s; %m\n"), namebuf);
			return;
		}
	} else {
		rdev = sb.st_rdev;
	}

	if ((dp = dev_getdp(rdev)) == NULL) {
		debug(1, "rmscsi_close: %s not in use\n", path);
		return;
	}

	/* get our private data */
	rsp = (struct rmscsi_priv *)dp->dp_priv;

	/*
	 * take care of the listner thread
	 */
	(void) mutex_lock(&rsp->rs_killmutex);
	(void) thr_kill(rsp->rs_tid, SIGUSR1);
	(void) mutex_unlock(&rsp->rs_killmutex);
	(void) thr_join(rsp->rs_tid, 0, 0);
	debug(1, "rmscsi_close: thread id %d reaped (killed/joined)\n",
	    rsp->rs_tid);

	/*
	 * if there is a volume inserted in this device ...
	 */
	if (dp->dp_vol) {
		/*
		 * clean up the name space and the device maps
		 * to remove references to any volume that might
		 * be in the device right now
		 *
		 * this crap with the flags is to keep the
		 * "poll" from being relaunched by this function
		 *
		 * yes, its a hack and there should be a better way
		 */
		if (dp->dp_dsw->d_flags & D_POLL) {
			dp->dp_dsw->d_flags &= ~D_POLL;
			dev_eject(dp->dp_vol, TRUE);
			dp->dp_dsw->d_flags |= D_POLL;
		} else {
			dev_eject(dp->dp_vol, TRUE);
		}
		if (dp->dp_vol != NULL) {
			return;
		}
		/* do the eject work */
		(void) ioctl(rsp->rs_fd[RMSCSI_BASEPART], DKIOCEJECT, 0);
	}

	/*
	 * clean up the names in the name space
	 */
	node_unlink(dp->dp_bvn);
	node_unlink(dp->dp_rvn);

	/*
	 * free the private data we've allocated
	 */
	for (i = 0; i < V_NUMPAR; i++) {
		if (rsp->rs_rawpath[i]) {
			free(rsp->rs_rawpath[i]);
		}
		if (rsp->rs_fd[i] != -1) {
			(void) close(rsp->rs_fd[i]);
		}
	}
#if defined(_FIRMWARE_NEEDS_FDISK)
	for (i = 0; i < (FD_NUMPART+1); i++) {
		if (rsp->rs_raw_pfd[i] >= 0) {
			(void) close(rsp->rs_raw_pfd[i]);
		}
	}
#endif
	free(rsp);

	/*
	 * free the dp, so no one points at us anymore
	 */
	dev_freedp(dp);
}

#ifdef	P0_WA
/*
 * return the numnber of the slice that starts at zero and maps the largest
 *	portion of the device.  if none found return a -1
 */
static int
part_to_hack(struct vtoc *v)
{
	int	i;
	int	part_no = -1;
	int	part_start = -1;
	int	part_size = 0;
	int	sz;
	int	st;


	/* scan for lowest starting part that has biggest chunk */
	for (i = 0; i < V_NUMPAR; i++) {

		/* get size and start, ignoring this slice if no size */
		if ((sz = v->v_part[i].p_size) <= 0) {
			continue;
		}
		st = v->v_part[i].p_start;

		/*
		 * 3 possible cases of choosing this partition over
		 *	our previous best:
		 *	-> we don't have a previous best
		 *	-> this part starts earlier than previous best
		 *	-> this part starts at same place but is larger
		 */
		if ((part_start < 0) ||
		    (st < part_start) ||
		    ((st == part_start) && (sz > part_size))) {
			part_start = st;
			part_size = sz;
			part_no = i;
			continue;
		}
	}

	/* return slice found (or -1 if none) */
	return (part_no);
}
#endif	/* P0_WA */


static void
rmscsi_thread_wait(struct devs *dp)
{
	extern void		vol_event(struct vioc_event *, struct devs *);
#ifdef	DEBUG
	static char		*dkiostate_to_str(enum dkio_state);
#endif
	static int		reopen_rmscsi(struct rmscsi_priv *);
	extern int		vold_running;
	extern cond_t 		running_cv;
	extern mutex_t		running_mutex;
	int			fd;
	struct rmscsi_priv	*rsp = (struct rmscsi_priv *)dp->dp_priv;
	struct vioc_event	vie;
	struct vtoc		vtoc;
	enum dkio_state 	rmscsi_state;
	int			i;
	struct dk_cinfo		dkc;

	/* ensure vold main stuff is running before continuing */
	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	/* open each slice of the media to cover all of the bases */
	for (i = 0; i < V_NUMPAR; i++) {
		debug(1, "rmscsi_thread_wait: opening \"%s\" RDONLY ...\n",
		    rsp->rs_rawpath[i]);
		/*
		 * just always open rdonly here, since the DKIOC_INSERTED
		 * state will cause a close/reopen
		 */
		if ((fd = open(rsp->rs_rawpath[i],
		    O_RDONLY|O_NONBLOCK|O_EXCL)) < 0) {
			noise("rmscsi: open of \"%s\"; %m\n",
			    rsp->rs_rawpath[i]);
			goto errout;
		}
		/* XXX: should we do this? it seems to make sens (and work!) */
		dp->dp_writeprot = 1;

		(void) fcntl(fd, F_SETFD, 1);	/* close-on-exec */
		rsp->rs_fd[i] = fd;
	}

	/*
	 * check to make sure device is a SCSI disk
	 *
	 * XXX: isn't this redundant with rmscsi_testpath() ?
	 */
	if (ioctl(rsp->rs_fd[RMSCSI_BASEPART], DKIOCINFO, &dkc) < 0) {
		noise("rmscsi: %s DKIOCINFO failed; %m\n",
		    rsp->rs_rawpath[RMSCSI_BASEPART]);
		goto errout;
	}
	if (dkc.dki_ctype != DKC_SCSI_CCS) {
		noise(
"rmscsi: %s is not a SCSI disk drive (disk type %d expected, %d found)\n",
		    rsp->rs_rawpath[RMSCSI_BASEPART], DKC_SCSI_CCS,
		    dkc.dki_ctype);
		goto errout;
	}

	rmscsi_state = DKIO_NONE;
	rsp->rs_defpart = DEFAULT_PARTITION;

	/*CONSTCOND*/
	while (1) {

		fd = rsp->rs_fd[rsp->rs_defpart];

		/*
		 * this ioctl blocks until state changes.
		 */
#ifdef	DEBUG
		debug(3,
		"rmscsi_thread_wait: ioctl(DKIOCSTATE, \"%s\") on \"%s\"\n",
		    dkiostate_to_str(rmscsi_state),
		    rsp->rs_rawpath[rsp->rs_defpart]);
#else
		debug(3, "rmscsi_thread_wait: ioctl(DKIOCSTATE) on \"%s\"\n",
		    rsp->rs_rawpath[rsp->rs_defpart]);
#endif
		if (ioctl(fd, DKIOCSTATE, &rmscsi_state) < 0) {
			debug(1,
			    "rmscsi_thread_wait: DKIOCSTATE of \"%s\"; %m\n",
			    rsp->rs_rawpath[rsp->rs_defpart]);
			if (errno == ENOTTY) {
				goto errout;
			}
			(void) sleep(1);
			continue;
		}
#ifdef	DEBUG
		debug(5, "rmscsi_thread_wait: new state = \"%s\"\n",
		    dkiostate_to_str(rmscsi_state));
#endif
		if (rmscsi_state == DKIO_NONE) {
			continue;		/* steady state -- ignore */
		}

		(void) memset(&vie, 0, sizeof (struct vioc_event));

		(void) mutex_lock(&rsp->rs_killmutex);
		/*
		 * we have media in the drive
		 */
		if (rmscsi_state == DKIO_INSERTED) {

			/*
			 * if we already know about the media in the
			 * device, just ignore the information
			 */
			if (dp->dp_vol != NULL) {
				(void) mutex_unlock(&rsp->rs_killmutex);
				continue;
			}

			/*
			 * find out the lowest partition that maps the
			 * beginning of the drive
			 */
			if (ioctl(fd, DKIOCGVTOC, &vtoc) == 0) {
				rsp->rs_defpart = partition_low(&vtoc);
				if (rsp->rs_defpart == -1) {
					rsp->rs_defpart = RMSCSI_BASEPART;
				}
				debug(1,
				    "rmscsi_thread_wait: rs_defpart now %d\n",
				    rsp->rs_defpart);
#ifdef	P0_WA
				rsp->rs_p0_part = part_to_hack(&vtoc);
				debug(1,
				    "rmscsi_thread_wait: slice to hack = %d\n",
				    rsp->rs_p0_part);
#endif
			}

			/* generate an "insert" event */
			vie.vie_type = VIE_INSERT;
			vie.vie_insert.viei_dev = dp->dp_dev;
			dp->dp_writeprot = reopen_rmscsi(rsp);
			vol_event(&vie, dp);
		}

		/*
		 * we have NO media in the drive (it's just been ejected)
		 */
		if (rmscsi_state == DKIO_EJECTED) {
			vol_t	*v;

			(void) mutex_lock(&vold_main_mutex);
			/*
			 * if we already know about the ejection,
			 * just continue in our happy loop
			 */
			if ((v = dp->dp_vol) == NULL) {
				(void) mutex_unlock(&vold_main_mutex);
				(void) mutex_unlock(&rsp->rs_killmutex);
				continue;
			}

			/*
			 * generate an eject event (if we have a unit)
			 *
			 * XXX: this doesn't work because the DKIOCSTATE ioctl
			 * never seems to return DKIO_EJECTED for some
			 * devices, such as the ZIP 100
			 */
			for (i = 0; i < (int)v->v_ndev; i++) {
				if (v->v_devmap[i].dm_voldev == dp->dp_dev) {
					vie.vie_type = VIE_EJECT;
					vie.vie_eject.viej_force = TRUE;
					vie.vie_eject.viej_unit =
					    minor(v->v_devmap[i].dm_voldev);
					vol_event(&vie, dp);
					break;
				}
			}
			(void) mutex_unlock(&vold_main_mutex);
		}
		(void) mutex_unlock(&rsp->rs_killmutex);
	}

	/*NOTREACHED*/

errout:
	/*
	 * we get here if we have an error: close all the open fd's and
	 * return
	 */
	for (i = 0; i < V_NUMPAR; i++) {
		if (rsp->rs_fd[i] >= 0) {
			(void) close(rsp->rs_fd[i]);
		}
		rsp->rs_fd[i] = -1;
	}
}


/*
 * close then open the default partition for the media
 */
static int
reopen_rmscsi(struct rmscsi_priv *rsp)
{
	int	rdonly = 0;

	/*
	 * XXX: boy, is this a hack
	 *
	 * this works around a bug in scsi drivers were
	 * you can't seem to read from a file descriptor you've opened
	 * O_NDELAY where there wasn't any media in the drive
	 *
	 * this open can take forever, by the way ...
	 */

#ifdef	DEBUG
	debug(11, "reopen_rmscsi: closing slice %d fd (%d)\n",
	    rsp->rs_defpart, rsp->rs_fd[rsp->rs_defpart]);
#endif
	(void) close(rsp->rs_fd[rsp->rs_defpart]);
	if ((rsp->rs_fd[rsp->rs_defpart] =
	    open(rsp->rs_rawpath[rsp->rs_defpart], O_RDWR|O_EXCL)) < 0) {
		debug(7, "reopen_rmscsi: first open of \"%s\"; %m\n",
		    rsp->rs_rawpath[rsp->rs_defpart]);
		if (errno == EROFS) {
			rsp->rs_fd[rsp->rs_defpart] = open(
			    rsp->rs_rawpath[rsp->rs_defpart],
			    O_RDONLY|O_NDELAY|O_EXCL);
			rdonly = 1;
		} else {
			rsp->rs_fd[rsp->rs_defpart] = open(
			    rsp->rs_rawpath[rsp->rs_defpart],
			    O_RDWR|O_NDELAY|O_EXCL);
		}
	}

	if (rsp->rs_fd[rsp->rs_defpart] < 0) {
		warning(gettext("rmscsi: open error on %s; %m\n"),
		    rsp->rs_rawpath[rsp->rs_defpart]);
	}

	/* set close-on-exec */
	(void) fcntl(rsp->rs_fd[rsp->rs_defpart], F_SETFD, 1);

	debug(1,
	    "reopen_rmscsi: fd = %d (slice %d), rdonly = %d (path \"%s\")\n",
	    rsp->rs_fd[rsp->rs_defpart], rsp->rs_defpart, rdonly,
	    rsp->rs_rawpath[rsp->rs_defpart]);

	return (rdonly);
}


#ifdef	DEBUG

static char *
dkiostate_to_str(enum dkio_state st)
{
	static char		state_buf[30];


	switch (st) {
	case DKIO_NONE:
		(void) sprintf(state_buf, "DKIO_NONE");
		break;
	case DKIO_INSERTED:
		(void) sprintf(state_buf, "DKIO_INSERTED");
		break;
	case DKIO_EJECTED:
		(void) sprintf(state_buf, "DKIO_EJECTED");
		break;
	default:
		(void) sprintf(state_buf, "?unknown? (%d)", (int)st);
		break;
	}

	return (state_buf);
}
#endif	/* DEBUG */


static bool_t
rmscsi_testpath(char *path)
{
	int			fd = -1;
	struct dk_cinfo		dkc;
	struct stat		sb;
	char			*rp = NULL;
	int			removable;
	bool_t			res = FALSE;	/* return result */
	struct devs		*dp;

	/* check to see if we're already using it */
	if (stat(path, &sb) != 0) {
		/* something's seriously wrong */
		debug(5, "rmscsi(probing): stat of \"%s\"; %m\n", path);
		goto dun;
	}

	if ((dp = dev_getdp(sb.st_rdev)) != NULL) {
		if (dp->dp_dsw == &rmscsidevsw) {
			debug(5, "rmscsi(probing): %s already in use\n", path);
			return (TRUE);
		} else {
			debug(5, "rmscsi(probing): %s already managed by %s\n",
				path, dp->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	/* make sure our path is a raw device */
	if ((rp = rawpath(path)) == NULL) {
		debug(5, "rmscsi(probing): can't get rawpath of \"%s\"\n",
		    path);
		goto dun;
	}

	/*
	 * if we can't open it, assume that it's because it's busy or
	 * something else is wrong
	 *
	 * in any event, dev_use couldn't open it either, so it's
	 * not worth trying to use the device
	 */
	if ((fd = open(rp, O_RDONLY|O_NONBLOCK|O_EXCL)) < 0) {
		debug(5, "rmscsi(probing): open of \"%s\"; %m\n", rp);
		goto dun;
	}

	/* check to make sure device is a SCSI device */
	if (ioctl(fd, DKIOCINFO, &dkc) < 0) {
		debug(5, "rmscsi(probing): DKIOCINFO on \"%s\" failed; %m\n",
		    rp);
		goto dun;
	}
	if (dkc.dki_ctype != DKC_SCSI_CCS) {
		debug(5, "rmscsi(probing): \"%s\" is not a SCSI disk drive\n",
		    rp);
		debug(5,
		    "rmscsi(probing): (disk type %d expected, %d found)\n",
		    DKC_SCSI_CCS, dkc.dki_ctype);
		goto dun;
	}

	/*
	 * if we stop here, we'll end up trying to manage hard disks that
	 * are found, since they also return DKC_SCSI_CCS,
	 * so do a DKIOCREMOVABLE ioctl (more general than trying
	 * to do a SCSI inquiry here, since this latter method won't
	 * work on non-SCSI devices, such as IDE disks)
	 */

	/* do the inquiry */
	if (ioctl(fd, DKIOCREMOVABLE, &removable) != 0) {
		debug(5,
		"rmscsi(probing): \"%s\" DKIOCREMOVABLE ioctl failed; %m\n",
		    rp);
		goto dun;
	}

	if (removable == 0) {
		debug(5, "rmscsi(probing): device \"%s\" not removable\n",
		    rp);
		goto dun;
	}

	res = TRUE;
#ifdef	DEBUG
	debug(3, "rmscsi(probing): found removable (scsi?) drive at \"%s\"\n",
	    rp);
#endif

dun:
	/* all done */
	if (fd >= 0) {
		(void) close(fd);
	}
	if (rp != NULL) {
		free(rp);
	}
	return (res);
}


#if defined(_FIRMWARE_NEEDS_FDISK)

/*
 * serious hackery -- attempt to open the p? interfaces of the specified
 *		device -- just to keep users from getting around volmgt
 *		(e.g. "eject /dev/dsk/c0t6d0p0" -- oops)
 *
 *		If this fails, just ignore it.
 *
 *		The supplied params path1 and path2 will be the block
 *		and char prototype paths (but not necessarily in that
 *		order).
 */
static void
rmscsi_open_exclusive(struct rmscsi_priv *rsp, char *path1, char *path2)
{
	char	namebuf[MAXNAMELEN];
	int	i;
	char	*raw_proto;			/* for the "rdsk" path */


	/* initialized all of the fds */
	for (i = 0; i < (FD_NUMPART+1); i++) {
		rsp->rs_raw_pfd[i] = -1;
	}

	/* find out which one is the raw path prototype */
	if (strstr(path1, "rdsk")) {
		raw_proto = path1;
	} else if (strstr(path1, "dsk")) {
		raw_proto = path2;
	} else {
		return;
	}

	/* (attempt to) open each p device */
	for (i = 0; i < (FD_NUMPART+1); i++) {
		/* do the raw device */
		(void) sprintf(namebuf, RMSCSI_NAMEPROTO_P, raw_proto, i);
		rsp->rs_raw_pfd[i] = open(namebuf, O_RDONLY|O_EXCL|O_NDELAY);
#ifdef	DEBUG
		debug(6, "rmscsi_open_exclusive: open(\"%s\") -> %d\n",
		    namebuf, rsp->rs_raw_pfd[i]);
#endif
	}

}

#endif	/* _FIRMWARE_NEEDS_FDISK */
