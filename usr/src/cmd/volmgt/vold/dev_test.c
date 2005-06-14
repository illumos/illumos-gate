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
#include	<string.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<thread.h>
#include	<synch.h>
#include	<errno.h>
#include	"vold.h"
#include	"../test/voltestdrv.h"


static bool_t	test_use(char *, char *);
static bool_t	test_error(struct ve_error *);
static int	test_getfd(dev_t);
static void	test_close(char *, dev_t);
static void	test_devmap(vol_t *, int, int);
static void	test_thread(char *);


static struct devsw testdevsw = {
	test_use,		/* d_use */
	test_error,		/* d_error */
	test_getfd,		/* d_getfd */
	NULL,			/* d_poll */
	test_devmap,		/* d_devmap */
	test_close,		/* d_close */
	NULL, 			/* d_eject */
	NULL, 			/* d_find */
	NULL,			/* d_check */
	TEST_MTYPE,		/* d_mtype */
	TEST_CLASS,		/* d_dtype */
	(ulong_t)0 		/* d_flags */
};


/*
 * thread stack size
 */
#define	TEST_STKSIZE	(32 * 1024)		/* 32k! */

/*
 * this local global keeps track of whether or not the vol test driver
 * is "old" or "new" (as defined by which flavor of IOCTLs it likes)
 *
 * (start out assuming we're up to date)
 */
static bool_t	driver_is_new = TRUE;



bool_t
dev_init(void)
{
	extern void	dev_new(struct devsw *);

	dev_new(&testdevsw);
	return (TRUE);
}

struct t_priv {
	int	t_fd;
};


/*
 * this routine is called when volmgt sees a "use test ..." line
 * in its config file
 *
 * the pathname generally passed in is /dev/voltestdrv, which is expected
 * to be a directory containing a voltestdrv node and nodes for each "unit"
 */
/*ARGSUSED*/
static bool_t
test_use(char *path, char *symname)
{
	char		namebuf[MAXPATHLEN];
	struct stat	statbuf;
	int		fd;
	int		nunits;
	int		i;
	struct devs	*dp;
	static bool_t	in_use = FALSE;
	struct t_priv	*tp;
	int		ttid;			/* test thread id */



	info("test_use: %s\n", path);

	if (in_use) {
		debug(1, "test driver already in use\n");
		return (TRUE);
	}
	in_use = TRUE;

	(void) snprintf(namebuf, sizeof (namebuf), "%s/%s", path, VTCTLNAME);
	if ((fd = open(namebuf, O_RDWR)) < 0) {
		warning("test: open of \"%s\"; %m\n", namebuf);
		return (FALSE);
	}

	(void) fcntl(fd, F_SETFD, 1);
	(void) fstat(fd, &statbuf);

	/* get the nubmer of test units to manage */
	if (ioctl(fd, VTIOCUNITS, &nunits) < 0) {
		if (errno == ENOTTY) {
#ifdef	DEBUG
			debug(6, "test_use: found OLD test driver ioctls\n");
#endif
			/* XXX: ignore results from this? */
			(void) ioctl(fd, VTIOCUNITS_OLD, &nunits);
			driver_is_new = FALSE;
		} else {
			warning(
			    "test: VTIOCUNITS ioctl failed for \"%s\"; %m\n");
			return (FALSE);
		}
	}
#ifdef	DEBUG
	else {
		debug(6, "test_use: found NEW test driver ioctls\n");
	}
#endif

	/* XXX: should we perform a sanity check on nunits? */
	for (i = 1; i < nunits; i++) {
		(void) snprintf(namebuf, sizeof (namebuf), "%s/%d", path, i);
		if ((dp = dev_makedp(&testdevsw, namebuf)) == NULL) {
			/* only happens if path spec'ed in namebuf is bogus */
			warning("test: bailing (on \"%s\")\n", namebuf);
			return (FALSE);
		}
		tp = (struct t_priv *)calloc(1, sizeof (struct t_priv));
		dp->dp_priv = (void *)tp;
		tp->t_fd = -1;
		/*
		 * (void) snprintf(namebuf, "/dev/test/%d", i);
		 */
		(void) snprintf(namebuf, sizeof (namebuf),
		    "/dev/voltestdrv/%d", i);
		/* we only have character devices */
		dp->dp_rvn = dev_dirpath(namebuf);
		(void) snprintf(namebuf, sizeof (namebuf), "test%d", i);
		dp->dp_symname = strdup(namebuf);
	}
	if (close(fd) < 0) {
		warning("test_use: close of \"%s\" failed; %m\n", namebuf);
	}
	(void) snprintf(namebuf, sizeof (namebuf), "%s/%s", path, VTCTLNAME);
	if (thr_create(0, TEST_STKSIZE, (void *(*)(void *))test_thread,
	    (void *)strdup(namebuf), THR_BOUND, (thread_t *)&ttid) < 0) {
		warning(gettext("test_use: thread create failed; %m\n"));
		return (FALSE);
	}
#ifdef	DEBUG
	debug(6, "test_use: test_thread id %d created\n", ttid);
#endif
	return (TRUE);
}


static int
test_getfd(dev_t dev)
{
	struct devs 	*dp = dev_getdp(dev);
	struct t_priv 	*tp = (struct t_priv *)dp->dp_priv;


	ASSERT(tp->t_fd >= 0);
	return (tp->t_fd);
}


/*ARGSUSED*/
static bool_t
test_error(struct ve_error *vie)
{
	debug(1, "test_error\n");
	return (TRUE);
}


/*ARGSUSED*/
static void
test_close(char *path, dev_t rdev)
{
	/* do nothing */
	debug(1, "test_close: called for \"%s\" -- ignoring\n", path);
}


/*ARGSUSED*/
static void
test_devmap(vol_t *v, int part, int off)
{
	struct devs *dp = dev_getdp(v->v_basedev);

	v->v_devmap[off].dm_path = strdup(dp->dp_path);
}


static void
test_thread(char *path)
{
	extern void		vol_event(struct vioc_event *, struct devs *);
	extern int		vold_running;
	extern cond_t 		running_cv;
	extern mutex_t		running_mutex;
	int			fd;
	struct stat		sb;
	struct vioc_event	vie;
	struct vt_event		vte;
	struct devs		*dp;
	dev_t			dev;
	struct t_priv		*tp;
	int			event_ioctl;


#ifdef	DEBUG
	debug(9, "test_thread: entering for \"%s\"\n", path);
#endif

	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	if ((fd = open(path, O_RDWR)) < 0) {
		warning("test driver: %s; %m\n", path);
		return;
	}
	(void) fcntl(fd, F_SETFD, 1);	/* close-on-exec */
	(void) fstat(fd, &sb);

	event_ioctl =  driver_is_new ? VTIOCEVENT : VTIOCEVENT_OLD;

	/*CONSTCOND*/
	while (1) {

#ifdef	DEBUG
		debug(9, "test_thread: waiting for a VT event ...\n");
#endif

		/* this ioctl blocks until an event happens */
		if (ioctl(fd, event_ioctl, &vte) < 0) {
			debug(1, "test driver: VTIOCEVENT; %m\n");
			continue;
		}
		if ((vte.vte_dev == (minor_t)-1) || (vte.vte_dev == 0)) {
			/* no device -> no event */
			continue;
		}

		debug(1, "test_thread: insert on unit %d\n", vte.vte_dev);

		dev = makedev(major(sb.st_rdev), vte.vte_dev);
		dp = dev_getdp(dev);
		ASSERT(dp != NULL);

		tp = (struct t_priv *)dp->dp_priv;

		if (tp->t_fd < 0) {
#ifdef	DEBUG
			debug(9, "test_thread: opening \"%s\" RO\n",
			    dp->dp_path);
#endif
			if ((tp->t_fd = open(dp->dp_path, O_RDONLY)) < 0) {
				warning(
			"test_thread: read-only open of \"%s\" failed; %m\n",
				    dp->dp_path);
			} else {
				/* set close-on-exec */
				(void) fcntl(tp->t_fd, F_SETFD, 1);
			}
		}

		/* generate an insert event for this device */
#ifdef	DEBUG
		debug(9, "test_thread: creating insert event for (%d.%d)\n",
		    major(dev), minor(dev));
#endif
		(void) memset(&vie, 0, sizeof (struct vioc_event));
		vie.vie_type = VIE_INSERT;
		vie.vie_insert.viei_dev = dev;
		vol_event(&vie, dp);
	}
}
