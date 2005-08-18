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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<signal.h>
#include	<unistd.h>
#include	<string.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/fdio.h>
#include	<errno.h>
#include	<thread.h>
#include	<synch.h>
#include	"vold.h"
#include	"dev.h"


/* external routines */
extern void	vol_event(struct vioc_event *, struct devs *);

/* local routines */
static bool_t	floppy_use(char *, char *);
static bool_t	floppy_error(struct ve_error *);
static int	floppy_getfd(dev_t);
static void	floppy_devmap(vol_t *, int, int);
static void	floppy_close(char *, dev_t);
static void	floppy_eject(struct devs *);
static int	floppy_check(struct devs *);
static bool_t	floppy_testpath(char *);
static bool_t	floppy_remount(vol_t *);

#define	FLOPPY_MAX	10


static struct devsw floppydevsw = {
	floppy_use,		/* d_use */
	floppy_error,		/* d_error */
	floppy_getfd,		/* d_getfd */
	NULL,			/* d_poll */
	floppy_devmap,		/* d_devmap */
	floppy_close,		/* d_close */
	floppy_eject,		/* d_eject */
	NULL,			/* d_find */
	floppy_check,		/* d_check */
	FLOPPY_MTYPE,		/* d_mtype */
	DRIVE_CLASS,		/* d_dtype */
	(ulong_t)0,		/* d_flags */
	(uid_t)0,		/* d_uid */
	(gid_t)0,		/* d_gid */
	(mode_t)0,		/* d_mode */
	floppy_testpath,	/* d_test */
	floppy_remount		/* d_remount */
};

struct fl_priv {
	char		*fl_blockpath;	/* block device for floppy */
	char		*fl_rawpath;	/* character device for floppy */
	char		*fl_protopath;	/* core path */
	int		fl_tid;		/* thread id of watcher thread */
	int		fl_fd;		/* real file descriptor */
	int		fl_fd_a;	/* "hold" exclusive, part a */
	int		fl_fd_b;	/* "hold" exclusive, part b */
	mutex_t		fl_mutex;
	cond_t		fl_cv;
	char		fl_inserted;	/* floppy is in the drive */
	time_t		fl_lastcheck;	/* last time we looked at floppy */
	char		fl_pollable;	/* true if floppy is pollable */
};


#define	FLOPPY_NAMEPROTO	"%sc"

/*
 * thread stack size
 */
#define	FLOPPY_STKSIZE		(32 * 1024)	/* 32k! */



bool_t
dev_init(void)
{
	dev_new(&floppydevsw);
	return (TRUE);
}


static bool_t
floppy_use(char *path, char *symname)
{
	static void	floppy_thread(struct devs *);
	static void	open_exclusive(struct fl_priv *, int);
	struct stat	statbuf;
	char		namebuf[MAXPATHLEN];
	struct devs	*dp;
	struct fl_priv 	*flp;
	char		*s;
	uint_t		unit;
	vvnode_t	*bvn;
	vvnode_t	*rvn;
	int		n;

	info(gettext("floppy_use: %s\n"), path);

	/*
	 * we don't do an open for the floppy because it returns ENODEV
	 * if there isn't a device there.  Instead, we just stat the
	 * device and make sure it's there and is a reasonable type.
	 */

	/*
	 * We check to see if the user gave us a "working" path.
	 * If so, just use it.  Else,
	 * We expect a path of the form:
	 * 	/dev/{r}fd#
	 * We fill in the rest.
	 */
	if (stat(path, &statbuf) >= 0) {
		/* oh, they gave us a "good" path name */
		(void) strlcpy(namebuf, path, sizeof (namebuf));
	} else {
		/*
		 * perhaps they gave us "/dev/[r]fdN", and we want
		 *	"/dev/[r]fdNc" (where N <= 0)
		 */
		(void) snprintf(namebuf, sizeof (namebuf),
		    FLOPPY_NAMEPROTO, path);
		if (stat(namebuf, &statbuf) < 0) {
			debug(1, "floppy: stat of %s; %m\n", namebuf);
			return (FALSE);
		}
	}

	/*
	 * Check to see if vold is already managing the device.
	 */
	if ((dp = dev_getdp(statbuf.st_rdev)) != NULL) {
		if (dp->dp_dsw == &floppydevsw) {
			debug(1, "floppy %s already in use\n", path);
			return (TRUE);
		} else {
			debug(1, "floppy %s already managed by %s\n",
				path, dp->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	if (!S_ISCHR(statbuf.st_mode) && !S_ISBLK(statbuf.st_mode)) {
		warning(gettext(
			"floppy: %s not block or char device (mode 0x%x)\n"),
			namebuf, statbuf.st_mode);
		return (FALSE);
	}

	flp = (struct fl_priv *)calloc(1, sizeof (struct fl_priv));
	flp->fl_protopath = strdup(path);
	flp->fl_fd = -1;
	flp->fl_inserted = FALSE;
	flp->fl_lastcheck = (time_t)0;

	/* stick some good stuff in the device hierarchy */
	if (s = strstr(path, "diskette")) {
		/* he gave us a /dev/[r]diskette# name */
		n = sscanf(s, "diskette%d", &unit);
		if (n != 1) {			/* /dev/diskette */
			unit = 0;
		}
		(void) snprintf(namebuf, sizeof (namebuf),
		    "/dev/rdiskette%d", unit);
		rvn = dev_dirpath(namebuf);
		if (stat(namebuf, &statbuf) < 0) {
			/* assume he's got the old boring name */
			flp->fl_rawpath = "/dev/rdiskette";
		} else {
			flp->fl_rawpath = strdup(namebuf);
		}
		(void) snprintf(namebuf, sizeof (namebuf),
		    "/dev/diskette%d", unit);
		bvn = dev_dirpath(namebuf);
		if (stat(namebuf, &statbuf) < 0) {
			flp->fl_blockpath = "/dev/diskette";
		} else {
			flp->fl_blockpath = strdup(namebuf);
		}
	} else if (s = strstr(path, "fd")) {
		/* he gave us a /dev/[r]fd# name */
		n = sscanf(s, "fd%d", &unit);
		if (n != 1) {
			goto errout;
		}

		(void) snprintf(namebuf, sizeof (namebuf),
		    "/dev/rfd%d", unit);
		rvn = dev_dirpath(path);

		/* make the block name */
		(void) snprintf(namebuf, sizeof (namebuf),
		    "/dev/fd%d", unit);
		bvn = dev_dirpath(namebuf);

		/* make the full raw path name */
		(void) snprintf(namebuf, sizeof (namebuf),
		    "/dev/rfd%dc", unit);
		flp->fl_rawpath = strdup(namebuf);
		/* make the full raw path name */
		(void) snprintf(namebuf, sizeof (namebuf),
		    "/dev/fd%dc", unit);
		flp->fl_blockpath = strdup(namebuf);

	} else {
		goto errout;
	}
	/*
	 * Serious hackery... If there is a /dev/rfd#[ab], we
	 * open them up exclusivly so people can't go around us.
	 */
	open_exclusive(flp, unit);

	dp = dev_makedp(&floppydevsw, flp->fl_rawpath);
	dp->dp_priv = (void *)flp;
	dp->dp_symname = strdup(symname);
	dp->dp_rvn = rvn;
	dp->dp_bvn = bvn;

	if (thr_create(0, FLOPPY_STKSIZE,
		(void *(*)(void *))floppy_thread, (void *)dp, THR_BOUND,
	    (thread_t *)&flp->fl_tid) < 0) {
		warning(gettext("floppy thread create failed; %m\n"));
		return (FALSE);
	}
#ifdef	DEBUG
	debug(6, "floppy_use: floppy_thread id %d created\n", flp->fl_tid);
#endif
	return (TRUE);

errout:
	warning(gettext("floppy: malformed path name '%s'\n"), path);
	return (FALSE);
}


/*ARGSUSED*/
static void
floppy_devmap(vol_t *v, int part, int off)
{
	struct devs	*dp;
	struct fl_priv	*flp;


	dp = dev_getdp(v->v_basedev);
	flp = (struct fl_priv *)dp->dp_priv;
	v->v_devmap[off].dm_path = strdup(flp->fl_rawpath);
}


static int
floppy_getfd(dev_t dev)
{
	struct devs	*dp;
	struct fl_priv	*flp;

	dp = dev_getdp(dev);
	ASSERT(dp != NULL);
	flp = (struct fl_priv *)dp->dp_priv;
	ASSERT(flp->fl_fd != -1);
	return (flp->fl_fd);
}


/*ARGSUSED*/
static bool_t
floppy_error(struct ve_error *vie)
{
	debug(1, "floppy_error\n");
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
floppy_close(char *path, dev_t rdev)
{
	char		namebuf[MAXPATHLEN];
	struct	stat	sb;
	struct devs	*dp;
	struct fl_priv	*flp;

	debug(1, "floppy_close %s\n", path);

	if (stat(path, &sb) < 0) {
		(void) snprintf(namebuf, sizeof (namebuf),
		    FLOPPY_NAMEPROTO, path);
		if (stat(namebuf, &sb) < 0) {
			if (rdev == NODEV) {
				warning(gettext("floppy_close: "
					"stat of %s; %m\n"), namebuf);
				return;
			}
		} else {
			rdev = sb.st_rdev;
		}
	} else {
		rdev = sb.st_rdev;
	}

	dp = dev_getdp(rdev);
	if (dp == NULL) {
		debug(1, "floppy_close: %s not in use\n", path);
		return;
	}

	/* get our private data */
	flp = (struct fl_priv *)dp->dp_priv;

	/*
	 * Take care of the listner thread.
	 */
	(void) mutex_lock(&flp->fl_mutex);
	(void) thr_kill(flp->fl_tid, SIGUSR1);
	/* apparently we have to kick it out of the cv_wait */
	(void) cond_broadcast(&flp->fl_cv);
	(void) mutex_unlock(&flp->fl_mutex);
	(void) thr_join(flp->fl_tid, 0, 0);
	debug(1, "floppy thread reaped\n");

	/*
	 * If there is a volume inserted in this device...
	 */
	if (dp->dp_vol) {
		/*
		 * Clean up the name space and the device maps
		 * to remove references to any volume that might
		 * be in the device right now.
		 * This crap with the flags is to keep the
		 * "poll" from being relaunched by this function.
		 * yes, its a hack and there should be a better way.
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
		(void) ioctl(flp->fl_fd, DKIOCEJECT, 0);
	}

	/*
	 * Clean up the names in the name space.
	 */
	node_unlink(dp->dp_bvn);
	node_unlink(dp->dp_rvn);

	/*
	 * close the file descriptors we're holding open.
	 */
	(void) close(flp->fl_fd);
	if (flp->fl_fd_a >= 0) {
		(void) close(flp->fl_fd_a);
	}
	if (flp->fl_fd_b >= 0) {
		(void) close(flp->fl_fd_b);
	}

	/*
	 * free the private data we've allocated.
	 */
	free(flp->fl_blockpath);
	free(flp->fl_rawpath);
	free(flp);

	/*
	 * Free the dp, so no one points at us anymore.
	 */
	dev_freedp(dp);
}


static void
floppy_thread(struct devs *dp)
{
	static void	active_wait(struct fl_priv *, struct devs *);
	struct fl_priv	*flp = (struct fl_priv *)dp->dp_priv;
	struct fd_drive	fdchar;
	extern int	vold_running;
	extern cond_t 	running_cv;
	extern mutex_t	running_mutex;

	/* ensure that the main loop is ready */
	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	/* ensure the floppy is open */
	(void) mutex_lock(&flp->fl_mutex);
	if (flp->fl_fd == -1) {
		if ((flp->fl_fd =
		    open(flp->fl_rawpath, O_RDWR|O_NDELAY|O_EXCL)) < 0) {
			warning(gettext("floppy: open of %s; %m\n"),
			    flp->fl_rawpath);
			(void) mutex_unlock(&flp->fl_mutex);
			return;
		}
		(void) fcntl(flp->fl_fd, F_SETFD, 1);	/* close-on-exec */
	}
	(void) mutex_unlock(&flp->fl_mutex);

	/* get the drive characteristics */
	if (ioctl(flp->fl_fd, FDGETDRIVECHAR, &fdchar) < 0) {
		debug(1, "FDGETDRIVECHAR; %m\n");
	} else {
		/* if floppy pollable then set flag */
		if (fdchar.fdd_flags & FDD_POLLABLE) {
			flp->fl_pollable = 1;
			debug(1, "floppy at %s is pollable\n",
			    flp->fl_rawpath);
		}
		/* if floppy is ejectable then set flag */
		if (fdchar.fdd_ejectable == 0) {
			debug(1, "floppy at %s is manually ejectable\n",
			    flp->fl_rawpath);
			dp->dp_flags |= DP_MEJECTABLE;
		}
	}
	/* if floppy is pollable then go in to a polling loop */
	if (flp->fl_pollable) {
		active_wait(flp, dp);
	}
}

static void
active_wait(struct fl_priv *flp, struct devs *dp)
{
	extern bool_t		dev_present(struct devs *);
	static int		reopen_floppy(struct fl_priv *);
	int			rval = 0;
	struct vioc_event	vie;


	/*CONSTCOND*/
	while (1) {
		(void) sleep(2);

		(void) mutex_lock(&flp->fl_mutex);

		if (ioctl(flp->fl_fd, FDGETCHANGE, &rval) < 0) {
			debug(1, "FDGETCHANGE; %m\n");
			(void) mutex_unlock(&flp->fl_mutex);
			continue;
		}

		/*
		 * A floppy is IN the drive
		 * and we don't think there's anything there...
		 */
		if (!(rval & FDGC_CURRENT) &&
		    !dev_present(dp) &&
		    !flp->fl_inserted) {
			flp->fl_inserted = TRUE;
			(void) memset(&vie, 0, sizeof (struct vioc_event));
			vie.vie_type = VIE_INSERT;
			vie.vie_insert.viei_dev = dp->dp_dev;
			dp->dp_writeprot = reopen_floppy(flp);
			vol_event(&vie, dp);
		}

#ifdef	FDGETCHANGE_NOW_WORKING
		/*
		 * A floppy is NOT in the drive
		 * and we think there's something there...
		 */
		if (rval & FDGC_CURRENT) {
#ifdef	DEBUG
			debug(10, "active_wait: clearing inserted flag\n");
#endif
			flp->fl_inserted = FALSE;
			if (dev_present(dp)) {
				(void) memset(&vie, 0,
				    sizeof (struct vioc_event));
				vie.vie_type = VIE_EJECT;
				vie.vie_eject.viej_force = TRUE;
				vie.vie_eject.viej_unit = dp->dp_dev;
				vol_event(&vie, dp);
			}
		}
#endif	/* FDGETCHANGE_NOW_WORKING */
		(void) mutex_unlock(&flp->fl_mutex);
	}
	/*NOTREACHED*/
}


/*
 * clean up after an eject event
 */
static void
floppy_eject(struct devs *dp)
{
	struct fl_priv	*flp = (struct fl_priv *)dp->dp_priv;


	debug(10, "floppy_eject: clearing inserted flag\n");

	/* ensure we're alone */
	(void) mutex_lock(&flp->fl_mutex);

	/* clear "inserted" flag */
	flp->fl_inserted = FALSE;

	/* release lock */
	(void) mutex_unlock(&flp->fl_mutex);
}


static int
floppy_check(struct devs *dp)
{
	static int	reopen_floppy(struct fl_priv *);
	struct fl_priv	*flp = (struct fl_priv *)dp->dp_priv;
	int		rval = 0;
	struct vioc_event vie;
	time_t		tnow;
	extern int	vold_running;
	extern cond_t 	running_cv;
	extern mutex_t	running_mutex;
	int		generated_event = 0;
	int		ret_val = 0;


	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	(void) mutex_lock(&flp->fl_mutex);
	/*
	 * If we know the floppy is there, there's no need to check
	 * again.
	 */
	if (flp->fl_inserted || flp->fl_pollable) {
		debug(9, "floppy_check: already inserted (or pollable)\n");
		goto out;
	}

	/*
	 * We only want to do this ioctl every 2 seconds, so we
	 * do our rate limiting right here.
	 */
	(void) time(&tnow);
	if ((tnow - flp->fl_lastcheck) < 2) {
		/*
		 * check for that corner case where time has been set
		 * backwards (;-(
		 */
		if (tnow < flp->fl_lastcheck) {
			noise(gettext(
			"floppy: system time set backwards -- adjusting\n"));
		} else {
			debug(5,
			    "floppy_check: skipping volcheck -- too soon\n");
			goto out;
		}
	}

	flp->fl_lastcheck = tnow;	/* update when we last checked */

	debug(9, "floppy_check\n");

	/* ensure floppy is open */
	if (flp->fl_fd == -1) {
		if ((flp->fl_fd =
		    open(flp->fl_rawpath, O_RDWR|O_NDELAY|O_EXCL)) < 0) {
			warning(gettext("floppy: open of %s; %m\n"),
			    flp->fl_rawpath);
			goto out;
		}
		(void) fcntl(flp->fl_fd, F_SETFD, 1);	/* close-on-exec */
	}

	/* find out if floppy's currently in the drive */
	if (ioctl(flp->fl_fd, FDGETCHANGE, &rval) < 0) {
		debug(1, "FDGETCHANGE; %m\n");
		goto out;
	}

	/*
	 * A floppy is IN the drive
	 * and we don't think there's anything there...
	 */
	if (!(rval & FDGC_CURRENT) && !flp->fl_inserted) {
		flp->fl_inserted = TRUE;
		generated_event = 1;
		(void) cond_broadcast(&flp->fl_cv);
		(void) memset(&vie, 0, sizeof (struct vioc_event));
		vie.vie_type = VIE_INSERT;
		vie.vie_insert.viei_dev = dp->dp_dev;
		dp->dp_writeprot = reopen_floppy(flp);
		vol_event(&vie, dp);
	}

out:
	(void) mutex_unlock(&flp->fl_mutex);

	if (generated_event) {
		ret_val = 2;
	} else 	if (flp->fl_inserted) {
		ret_val = 1;
	}
	return (ret_val);
}



/*
 * Just hang on to these devices.  If they aren't there or the
 * open fails, don't sweat it.
 */
static void
open_exclusive(struct fl_priv *flp, int unit)
{
	char	namebuf[MAXPATHLEN];

	(void) snprintf(namebuf, sizeof (namebuf), "/dev/rfd%da", unit);
	flp->fl_fd_a = open(namebuf, O_RDWR|O_EXCL|O_NDELAY);
	(void) snprintf(namebuf, sizeof (namebuf), "/dev/rfd%db", unit);
	flp->fl_fd_b = open(namebuf, O_RDWR|O_EXCL|O_NDELAY);
}

static int
reopen_floppy(struct fl_priv *flp)
{
	int	rdonly = 0;

	/*
	 * XXX: boy, is this a hack.  This works around a
	 * bug in the floppy driver were you can't seem to read
	 * from a file descriptor you've opened
	 * O_NDELAY where there
	 * wasn't any media in the drive.
	 * This open takes forever, by the way...
	 */

	(void) close(flp->fl_fd);
	if ((flp->fl_fd = open(flp->fl_rawpath, O_RDWR|O_EXCL)) < 0) {
		if (errno == EROFS) {
			flp->fl_fd = open(flp->fl_rawpath,
			    O_RDONLY|O_NDELAY|O_EXCL);
			rdonly = 1;
		} else {
			flp->fl_fd = open(flp->fl_rawpath,
			    O_RDWR|O_NDELAY|O_EXCL);
		}
	}

	if (flp->fl_fd < 0) {
		warning(gettext("floppy: open error on %s; %m\n"),
		    flp->fl_rawpath);
	}

	(void) fcntl(flp->fl_fd, F_SETFD, 1);	/* close-on-exec */
	debug(1, "floppy: fd = %d, rdonly = %d\n", flp->fl_fd, rdonly);

	return (rdonly);
}


/*
 * Return true if the path points at a floppy device, as it's understood
 * by this code.
 */
static bool_t
floppy_testpath(char *p)
{
	struct stat	sb;
	int		fd;
	char		*rp;
	int		rval;
	struct devs	*dp;

	if (stat(p, &sb) < 0) {
		debug(5, "floppy(probing): stat of %s; %m\n", p);
		return (FALSE);
	}

	/* see if device already being used */
	if ((dp = dev_getdp(sb.st_rdev)) != NULL) {
		if (dp->dp_dsw == &floppydevsw) {
			debug(5, "floppy(probing): %s already in use\n", p);
			return (TRUE);
		} else {
			debug(5, "floppy(probing): %s already managed by %s\n",
				p, dp->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	/* make sure our path is a raw device */
	if ((rp = rawpath(p)) == NULL) {
		debug(5, "floppy(probing): can't rawpath %s\n", p);
		return (FALSE);
	}

	if ((fd = open(p, O_RDONLY|O_NDELAY)) < 0) {
		debug(5, "floppy(probing): open of %s; %m\n", rp);
		free(rp);
		return (FALSE);
	}

	if (ioctl(fd, FDGETCHANGE, &rval) < 0) {
		debug(5, "floppy(probing): FDGETCHANGE on %s; %m\n", rp);
		(void) close(fd);
		free(rp);
		return (FALSE);
	}
	(void) close(fd);
	free(rp);
	return (TRUE);
}

static bool_t
floppy_remount(vol_t *volumep)
{
	/*
	 * There's no need to find the new default file
	 * descriptor for a floppy after it has been
	 * formatted and repartitioned.  The default
	 * file descriptor for a floppy never changes.
	 */

	/*
	 * We need to confound lint while creating a dummy
	 * function that does nothing with its argument.
	 */
	if (volumep != NULL) {
		return (TRUE);
	} else {
		return (FALSE);
	}
}
