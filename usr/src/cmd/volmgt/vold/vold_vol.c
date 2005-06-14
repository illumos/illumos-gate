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

/*
 * Volume Daemon primary interface to the vol driver
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<signal.h>
#include	<string.h>
#include	<locale.h>
#include	<sys/types.h>
#include	<sys/mkdev.h>
#include	<sys/ddi.h>
#include	<errno.h>
#include	<sys/param.h>
#include	<sys/stat.h>
#include	<sys/time.h>
#include	<sys/wait.h>
#include	<sys/mnttab.h>
#include	<sys/dkio.h>
#include	<sys/tiuser.h>
#include	<sys/vol.h>
#include	<rpc/types.h>
#include	<rpc/auth.h>
#include	<rpc/auth_unix.h>
#include	<rpc/xdr.h>
#include	<rpc/clnt.h>
#include	<rpcsvc/nfs_prot.h>
#include	<thread.h>
#include	<synch.h>
#include	"vold.h"
#include	"label.h"
#include	"dev.h"
#include	"medium.h"

int	vol_fd = -1;
major_t	vol_major = 0;				/* used in minor_alloc() */

struct volins {
	dev_t		vi_dev;		/* device action occured on */
	void		*vi_stk;	/* stack for the thread */
	vol_t		*vi_v;		/* volume that action occured on */
	enum read_type	vi_act;		/* type of action */
};

/*
 * will be obsolete
 */
struct q alabq;
mutex_t	alab_mutex;	/* protect the queue */
bool_t	alab_work;	/* flag to say there's work to do */

static struct q async_taskq;
static bool_t async_taskq_run;
static mutex_t async_taskq_mutex = RECURSIVEMUTEX;

static void vol_event_unlocked(struct vioc_event *);
static vol_t *vol_foundlabel(dev_t, label *, enum read_type, enum laread_res);
static void mount_volume(dev_t, vol_t *, uint_t);
static void insert_medium(dev_t *);
static void remount_medium(dev_t *);
static void vol_forceout(vol_t *);
static void vol_insert(struct volins *);
static void vol_missing(struct ve_missing *);
static struct alab *vol_readlabel(struct volins *);
static int vol_reaper(struct reap *);
static int async_taskq_dupev_check(struct devs *, enum vie_event);

/*
 * thread stack size
 */
#define	VOL_STKSIZE	(64 * 1024)

bool_t
vol_init(void)
{
	char		namebuf[MAXPATHLEN+1];
	struct stat	sb;

	(void) snprintf(namebuf, sizeof (namebuf), "/dev/%s", VOLCTLNAME);
	if ((vol_fd = open(namebuf, O_RDWR)) < 0) {
		warning(gettext("vol_init: open failed on  %s; %m\n"),
		    namebuf);
		return (FALSE);
	}
	(void) fcntl(vol_fd, F_SETFD, 1);	/* close-on-exec */
	(void) fstat(vol_fd, &sb);
	vol_major = major(sb.st_rdev);

	/* set up the driver */
	if (ioctl(vol_fd, VOLIOCDAEMON, getpid()) != 0) {
		fatal(gettext("vol_init: already a daemon running\n"));
		/*NOTREACHED*/
	}

	/* set up our mutex */
	(void) mutex_init(&alab_mutex, USYNC_THREAD, 0);
	return (TRUE);
}

void
vol_event(struct vioc_event *vie, struct devs *dp)
{
	struct async_task	*as;
	struct vioc_event	*viep;

	/*
	 * there may be a chance that the main thread goes into
	 * this route such as via floppy_check(). In such case,
	 * lock has been held, thus async_task_mutex is a recursive
	 * mutex.
	 *
	 * Any events which may create async tasks should be
	 * queued up, so that it's safely dispatched by the
	 * asyncq dispatcher.
	 */
	switch (vie->vie_type) {
	case VIE_INSERT:
	case VIE_REMOUNT:
	case VIE_EJECT:
		break;
	default:
		vol_event_unlocked(vie);
		return;
	}
	if (async_taskq_dupev_check(dp, vie->vie_type)) {
		/*
		 * we aready have same event queued up. just ignore
		 * this event.
		 */
		return;
	}
	as = vold_malloc(sizeof (struct async_task));
	viep = vold_malloc(sizeof (struct vioc_event));
	(void) memcpy(viep, vie, sizeof (struct vioc_event));
	as->act = ASACT_NEWEVENT;
	as->data[0] = (uintptr_t)viep;
	as->data[1] = (uintptr_t)dp;
	async_taskq_insert(as);
}

static struct devs *
find_dp(struct vioc_event *vie)
{
	struct devs	*dp = NULL;
	vol_t		*v;

	switch (vie->vie_type) {
	case VIE_INSERT:
		dp = dev_getdp(vie->vie_insert.viei_dev);
		break;
	case VIE_REMOUNT:
		v = minor_getvol(vie->vie_rm.virm_unit);
		if (v != NULL)
			dp = dev_getdp(v->v_basedev);
		break;
	case VIE_EJECT:
		v = minor_getvol(vie->vie_eject.viej_unit);
		if (v != NULL)
			dp = dev_getdp(v->v_basedev);
		break;
	}
	return (dp);
}

void
vol_readevents(void)
{
	int			err;
	struct vioc_event	vie;

	debug(10, "vol_readevents: scanning for all events\n");

	for (;;) {
		err = ioctl(vol_fd, VOLIOCEVENT, &vie);
		if (err != 0 && errno != EWOULDBLOCK) {
			debug(10, "vol_readevents: ioctl(VOLIOCEVENT); %m\n",
			    err);
		}
		if (err != 0) {
			if (errno == EWOULDBLOCK) {
				debug(10, "vol_readevents: no more events\n");
				return;
			}
			perror("vol_readevents");
			return;
		}
		vol_event(&vie, find_dp(&vie));
	}
}

static char *event_names[] = {
	"VIE_MISSING",
	"VIE_EJECT",
	"VIE_DEVERR",
	"VIE_CLOSE",
	"VIE_CANCEL",
	"VIE_NEWLABEL",
	"VIE_INSERT",
	"VIE_GETATTR",
	"VIE_SETATTR",
	"VIE_INUSE",
	"VIE_CHECK",
	"VIE_REMOVED",
	"VIE_SYMNAME",
	"VIE_SYMDEV",
	"VIE_REMOUNT",
};

static void
vol_event_unlocked(struct vioc_event *vie)
{
	int			err = 0;
	struct volins		*vid;
	dev_t			*in_devicep;
	vol_t			*v;
	thread_t		id;
	dev_t			dev;
	minor_t			mnr;
	char			event_str[50];
	bool_t			result;
	struct devs		*dp;

	if ((vie->vie_type < 0) || (vie->vie_type > VIE_REMOUNT)) {
		(void) sprintf(event_str, "VIE_??? (%d)", vie->vie_type);
	} else {
		(void) strcpy(event_str, event_names[vie->vie_type]);
	}
	debug(1, "vol_event: %d (%s)\n", vie->vie_type, event_str);
	switch (vie->vie_type) {
	case VIE_CHECK: {
		extern int	dev_check(dev_t);
		int		rval;

		rval = dev_check(vie->vie_check.viec_dev);
		/*
		 * dev_check returns:
		 * 0 if it didn't find anything
		 * 1 if it foudn something and we already knew about it
		 * 2 if it found something and we generated an insert event
		 */
		if (rval == 0) {
			(void) ioctl(vol_fd, VOLIOCDCHECK, ENXIO);
		} else if (rval == 1) {
			(void) ioctl(vol_fd, VOLIOCDCHECK, 0);
		}

		/*
		 * If there was something there, a flag was set
		 * in the dp structure saying that a response needs to
		 * be made "as late as possible".  In other words,
		 * if there are no actions to be done, do the response
		 * after the name space has been built.  If there are
		 * actions to be done, respond after they have completed.
		 */
		break;
	}

	case VIE_SYMNAME: {
		struct vol_str	vs;

		dev = vie->vie_symname.vies_dev;
		if ((vs.data = dev_symname(dev)) == NULL) {
			vs.data_len = 0;
		} else {
			vs.data_len = strlen(vs.data);
		}

		debug(11,
		    "vol_event: VIE_SYMNAME: (%d,%d) -> \"%s\" (len %d)\n",
		    major(dev), minor(dev),
		    vs.data ? vs.data : "<null ptr>", vs.data_len);

		(void) ioctl(vol_fd, VOLIOCDSYMNAME, &vs);
		break;
	}

	case VIE_SYMDEV: {
		extern char	*symname_to_dev(char *);
		char		*symname;
		struct vol_str	vs;

		symname = vie->vie_symdev.vied_symname;

		/*
		 * be sure symname is not NULL and symname_to_dev does not
		 * return NULL
		 */
		if (symname != NULL) {
			if ((vs.data = symname_to_dev(symname)) == NULL) {
				vs.data_len = 0;
			} else {
				vs.data_len = strlen(vs.data);
			}
		} else {
			vs.data_len = 0;
			vs.data = NULL;
		}

		debug(11, "vol_event: VIE_SYMDEV: \"%s\" -> \"%s\"\n",
		    symname ? symname : "<null ptr>",
		    vs.data ? vs.data : "<null ptr>");

		(void) ioctl(vol_fd, VOLIOCDSYMDEV, &vs);
		break;
	}

	case VIE_INUSE: {
		extern int	dev_inuse(dev_t);
		extern bool_t	mount_complete;
		bool_t		rval;

		if (!mount_complete) {
			debug(5,
			    "vol_event: VIE_INUSE: poll NOT being done yet\n");
			err = ENXIO;
		} else {

			dev = vie->vie_inuse.vieu_dev;
			debug(5,
			    "vol_event: VIE_INUSE: check for (%d,%d) use\n",
			    major(dev), minor(dev));
			if ((dev == makedev(vol_major, 0)) == 0) {
				rval = (bool_t)dev_inuse(
				    vie->vie_inuse.vieu_dev);
				/*
				 * dev_inuse returns TRUE if the device
				 * is managed, and FALSE if it isn't
				 */
				if (rval == FALSE) {
					err = ENXIO;
				}
			}
		}
		debug(5, "vol_event: returning err=%d\n", err);
		(void) ioctl(vol_fd, VOLIOCDINUSE, err);
		break;
	}

	case VIE_INSERT: {
		in_devicep = vold_calloc(1, sizeof (int));
		dev = vie->vie_insert.viei_dev;
		*in_devicep = vie->vie_insert.viei_dev;
		debug(2, "vol_event: insert into (%d,%d)\n",
			major(dev), minor(dev));
		if ((dp = dev_getdp(dev)) != NULL) {
			dp->dp_asynctask++;
			dp->dp_flags |= DP_SCANNING;
		}
		if (thr_create(0, VOL_STKSIZE,
		    (void *(*)(void *))insert_medium,
		    (void *)in_devicep, THR_BOUND, &id) < 0) {
			warning(gettext("can't create thread; %m\n"));
			if (dp != NULL) {
				dp->dp_asynctask--;
				dp->dp_flags &= ~DP_SCANNING;
			}
		} else {
			debug(6, "vol_event: created insert_medium()"
			    " tid %d (%d,%d) (for INSERT)\n",
			    (int)id, major(dev), minor(dev));
		}
		break;
	}

	case VIE_MISSING:
		vol_missing(&vie->vie_missing);
		break;

	case VIE_EJECT:
		if (vie->vie_eject.viej_force) {
			debug(1, "vol_event: got a forced ejection\n");
			/*
			 * Is it already gone?
			 */
			v = minor_getvol((minor_t)vie->vie_eject.viej_unit);
			if ((v == NULL) || (v->v_confirmed == FALSE)) {
				debug(5, "vol_event: unit %d already gone!\n",
				    vie->vie_eject.viej_unit);
				break;
			}
			v->v_ej_force = TRUE;
		} else {
			v = minor_getvol((minor_t)vie->vie_eject.viej_unit);
			if (v == NULL) {
				debug(1, "eject on strange unit %d\n",
				    vie->vie_eject.viej_unit);
				break;
			}
			v->v_ej_force = FALSE;
		}
		if (v->v_ej_inprog) {
			/* ejection in progress... ignore */
			debug(6, "vol_event: ignoring dup eject on %s\n",
			    v->v_obj.o_name);
			break;
		}
		v->v_ej_inprog = TRUE;
		v->v_clue.c_volume = vie->vie_eject.viej_unit;
		v->v_clue.c_uid = vie->vie_eject.viej_user;
		v->v_clue.c_tty = vie->vie_eject.viej_tty;
		v->v_ejfail = FALSE;

		dp = dev_getdp(v->v_basedev);

		/*
		 * If we're ejecting a piece of media that a new label
		 * has been written to -- read the new label off before
		 * proceeding with the ejection.
		 */
		if ((v->v_flags & V_NEWLABEL) && (v->v_basedev != NODEV)) {
			debug(1, "vol_event: need to read new label on %s\n",
			    v->v_obj.o_name);
			vid = (struct volins *)
			    malloc(sizeof (struct volins));
			vid->vi_stk = 0;
			vid->vi_dev = v->v_basedev;
			vid->vi_v = v;
			vid->vi_act = NEWLABEL;
			if (dp != NULL)
				dp->dp_asynctask++;
			if (thr_create(0, VOL_STKSIZE,
			    (void *(*)(void *))vol_insert, (void *)vid,
			    THR_BOUND, &id) < 0) {
				warning(gettext("can't create thread; %m\n"));
				if (dp != NULL)
					dp->dp_asynctask--;
			} else {
				debug(6,
	"vol_event: created vol_insert() tid %d (%d,%d) (for EJ w/new lab)\n",
				    (int)id, major(vid->vi_dev),
				    minor(vid->vi_dev));
			}
			v->v_flags &= ~V_NEWLABEL;
		} else {
			if (action(ACT_EJECT, v) == 0) {
				dev_eject(v, TRUE);
			}
		}

		break;

	case VIE_DEVERR:
		dev_error(&vie->vie_error);
		debug(1, "device error %d on (%d,%d)\n",
		    vie->vie_error.viee_errno,
		    major(vie->vie_error.viee_dev),
		    minor(vie->vie_error.viee_dev));
		break;

	case VIE_CLOSE: {
		mnr = vie->vie_close.viecl_unit;
		debug(5, "close on unit %d\n", mnr);
		v = minor_getvol(mnr);
		if ((v != NULL) && (v->v_flags & V_NEWLABEL)) {
			debug(1, "need to read new label on %s\n",
			    v->v_obj.o_name);
			if (v->v_basedev == NODEV) {
				debug(1, "error: no device for %s\n",
				    v->v_obj.o_name);
				break;
			}
			dp = dev_getdp(v->v_basedev);
			vid = vold_malloc(sizeof (struct volins));
			vid->vi_stk = 0;
			vid->vi_dev = v->v_basedev;
			vid->vi_v = v;
			vid->vi_act = NEWLABEL;
			if (dp != NULL)
				dp->dp_asynctask++;
			if (thr_create(0, VOL_STKSIZE,
			    (void *(*)(void *))vol_insert, (void *)vid,
			    THR_BOUND, &id) < 0) {
				warning(gettext("can't create thread; %m\n"));
				if (dp != NULL)
					dp->dp_asynctask--;
			} else {
				debug(6,
	"vol_event: created vol_insert() tid %d (%d,%d) (for CLOSE)\n",
				    (int)id, major(mnr), minor(mnr));
			}
			v->v_flags &= ~V_NEWLABEL;
		}
		break;
	}

	case VIE_CANCEL:
		mnr = vie->vie_cancel.viec_unit;
		if ((v = minor_getvol(mnr)) == NULL) {
			debug(5, "cancel on unit %d: unit already gone\n",
			    mnr);
			break;
		}

		debug(5, "cancel on unit %d (vol %s)\n", mnr, v->v_obj.o_name);

		/* if we have a device then clean up after it */
		if (v->v_confirmed == FALSE) {
			vol_forceout(v);
		}

#ifdef	IT_ALL_WORKED
		/*
		 * it'd be nice to "unmount" (i.e. run rmmount, the
		 *	std eject-action handler), but when vol_reaper()
		 *	calls dev_eject(), which calls dev_getdp(), the
		 *	assertion that dev != NODEV in dev_getdp() pukes!
		 *	so, for now, if the user cancels i/o (via volcancel),
		 *	they leave the vol mounted!  -- wld
		 */
		/* now try to run the eject action */
		if (v->v_ej_inprog) {
			/* ejection in progress... ignore */
			debug(6, "ignoring dup eject on %s\n",
			    v->v_obj.o_name);
			break;
		}
		v->v_ej_inprog = TRUE;
		v->v_clue.c_volume = mnr;
		v->v_clue.c_uid = DEFAULT_TOP_UID;
		v->v_clue.c_tty = 0;
		v->v_ejfail = FALSE;

		(void) action(ACT_EJECT, v);
#endif	/* IT_ALL_WORKED */
		break;

	case VIE_NEWLABEL:
		/*
		 * The old code seemed to interact with VIE_CLOSE
		 * and VIE_REMOUNT in a way that unmapped the device
		 * and caused VIE_REMOUNT to fail.  Trying to elminate
		 * that failure by not setting the V_NEWLABEL flag
		 * in the volume object.  I don't know whether that
		 * will work, as the old code for relabeling media
		 * is convoluted, but I'll give it a try.
		 * Henry Knapp 991015
		 */
		break;

	case VIE_GETATTR: {
		char			*value;
		char			*props;
		struct vioc_dattr	vda;

		mnr = vie->vie_attr.viea_unit;
		if ((v = minor_getvol(mnr)) == NULL) {
			debug(5, "getattr on unit %d: unit already gone\n",
			    mnr);
			break;
		}
		props = props_get(v);
		value = prop_attr_get(props, vie->vie_attr.viea_attr);
		if (value != NULL) {
			(void) strncpy(vda.vda_value, value, MAX_ATTR_LEN);
			free(value);
			vda.vda_errno = 0;
		} else {
			vda.vda_errno = ENOENT;
		}
		if (props != NULL) {
			free(props);
		}
		vda.vda_unit = mnr;
		(void) ioctl(vol_fd, VOLIOCDGATTR, &vda);
		break;
	}

	case VIE_SETATTR: {
		extern bool_t		props_check(vol_t *, struct ve_attr *);
		char			*props;
		char			*nprops;
		struct vioc_dattr	vda;

		mnr = vie->vie_attr.viea_unit;
		if ((v = minor_getvol(mnr)) == NULL) {
			debug(5, "setattr on unit %d: unit already gone\n",
			    mnr);
			break;
		}
		if (props_check(v, &vie->vie_attr)) {
			props = props_get(v);
			/* this will free "props" */
			nprops = prop_attr_put(props, vie->vie_attr.viea_attr,
			    vie->vie_attr.viea_value);
			props_set(v, nprops);
			if (nprops != NULL) {
				free(nprops);
			}
			vda.vda_errno = 0;
			change_flags((obj_t *)v);
			(void) db_update((obj_t *)v);
		} else {
			vda.vda_errno = EPERM;
		}
		vda.vda_unit = mnr;
		(void) ioctl(vol_fd, VOLIOCDSATTR, &vda);
		break;
	}

	case VIE_REMOVED:
		if ((v = minor_getvol(vie->vie_rm.virm_unit)) != NULL) {
			debug(1, "volume %s was removed from the drive\n",
			    v->v_obj.o_name);
			vol_forceout(v);	/* get rid of that baby */
		}
		break;

	case VIE_REMOUNT:
		mnr =  vie->vie_remount.vier_unit;
		debug(5, "remount on unit %d\n", mnr);
		v = minor_getvol(mnr);
		if (v != NULL) {
			result = dev_remount(v);
		} else {
			debug(5, "remount failed: volumep was NULL\n");
			result = FALSE;
		}
		if (result != TRUE) {
			debug(5, "dev_remount() failed\n");
			break;
		}
		dp = dev_getdp(v->v_basedev);
		in_devicep = vold_calloc(1, sizeof (int));
		*in_devicep = v->v_device;
		debug(2, "vol_event: remount medium on (%d,%d)\n",
				major(dev), minor(dev));
		if (dp != NULL) {
			dp->dp_asynctask++;
			dp->dp_flags |= DP_SCANNING;
		}
		if (thr_create(0, VOL_STKSIZE,
		    (void *(*)(void *))remount_medium,
		    (void *)in_devicep, THR_BOUND, &id) >= 0) {
			debug(6, "vol_event: created remount_medium()"
			    " tid %d (%d,%d) (VIE_REMOUNT)\n",
			    (int)id, major(dev), minor(dev));
		} else {
			warning(gettext(
			    "VIE_REMOUNT:can't create thread; %m\n"));
			if (dp != NULL) {
				dp->dp_asynctask--;
				dp->dp_flags &= ~DP_SCANNING;
			}
		}
		break;

	default:
		warning(gettext("unknown message type %d from driver\n"),
		    vie->vie_type);
		break;
	}
}


/*
 * Media has been removed from the drive.  Do all the required
 * cleanup.
 */
static void
vol_forceout(vol_t *v)
{
	debug(4, "vol_forceout: forced eject on %s\n", v->v_obj.o_name);
	if (v->v_confirmed == FALSE) {
		debug(5, "vol_forceout: already gone!\n");
		return;
	}

	if (v->v_ej_inprog != FALSE) {
		debug(1, "vol_forceout: v->v_ej_inprog == TRUE\n");
	}
	v->v_ej_force = TRUE;
	v->v_ej_inprog = TRUE;
	dev_eject(v, TRUE);
}

static void
vol_missing(struct ve_missing *miss)
{
	vol_t		*v;

	debug(11, "vol_missing: called (unit %d)\n", miss->viem_unit);

	v = minor_getvol(miss->viem_unit);
	if (v == NULL) {
		debug(1, "missing on strange unit %d\n", miss->viem_unit);
		return;
	}

	debug(2, "missing volume %s\n", v->v_obj.o_name);

	if (dev_map_missing(v, miss->viem_unit, miss->viem_ndelay) != FALSE) {
		/* it's no longer missing */
		return;
	}

	/* okay, it's really missing -- create a notify event */

	info(gettext("can't find the %s volume, please go find it for me!\n"),
	    v->v_obj.o_name);
	v->v_clue.c_uid = miss->viem_user;
	v->v_clue.c_tty = miss->viem_tty;
	(void) action(ACT_NOTIFY, v);
}

static void
insert_medium_common(dev_t *in_devicep, bool_t remount)
{
	dev_t			in_device;
	struct devs		*dp;
	medium_handle_t		mediump;
	medium_result_t		medium_result;
	struct async_task	*as;

	in_device = *in_devicep;
	free(in_devicep);

	debug(2, "insert_medium: device(%d, %d) remount=%d\n",
		major(in_device), minor(in_device), remount);

	medium_result = create_medium(in_device, &mediump);
	if (medium_result == MEDIUM_SUCCESS) {
		if (remount)
			medium_result = medium_remount_partitions(mediump);
		else
			medium_result = medium_mount_partitions(mediump);
	}

	if ((dp = dev_getdp(in_device)) != NULL)
		dp->dp_flags &= ~DP_SCANNING;

	as = vold_malloc(sizeof (struct async_task));
	as->act = ASACT_REAPTHR;
	as->data[0] = (uintptr_t)in_device;
	as->data[1] = (uintptr_t)thr_self();
	async_taskq_insert(as);

	thr_exit(NULL);
}

static void
insert_medium(dev_t *in_devicep)
{
	insert_medium_common(in_devicep, FALSE);
}

static void
remount_medium(dev_t *in_devicep)
{
	insert_medium_common(in_devicep, TRUE);
}

/*
 * Something wonderful has just happened to vid->vi_dev.  Either
 * a new piece of media was inserted into the drive (act == INSERT),
 * someone just wrote a new label over the old one (act == NEWLABEL),
 * or we are being asked to read the label to confirm what was
 * believed to be in the drive (act == CONFIRM).
 */
static void
vol_insert(struct volins *vid)
{
	struct devs	*dp;
	struct alab	*al = NULL;
#ifdef	TWO_SIDED_DEVICE
	struct alab	*al1 = NULL;
#endif

	debug(2, "vol_insert: thread for handling (%d,%d)\n",
	    major(vid->vi_dev), minor(vid->vi_dev));

	dp = dev_getdp(vid->vi_dev);
	if (dp == NULL) {
		debug(1, "no mapping for (%d,%d)!\n", major(vid->vi_dev),
		    minor(vid->vi_dev));
	}

	al = vol_readlabel(vid);

#ifdef TWO_SIDED_DEVICE
	/* if it's a two sided device, we only have one poller per slot */
	if ((vid->vi_act == INSERT) &&
	    ((dp != NULL) && (dp->dp_dsw->d_flags & D_2SIDED))) {
		debug(2, "2sided: other side of (%d,%d) is (%d,%d)\n",
		    major(vid->vi_dev), minor(vid->vi_dev),
		    major(dp->dp_otherside), minor(dp->dp_otherside));
		vid->vi_dev = dp->dp_otherside;
		vid->vi_stk = 0;
		al1 = vol_readlabel(vid);
	}
#endif

	if (al != NULL) {
		al->al_v = vid->vi_v;	/* only on NEWLABEL && CONFIRM */
		al->al_act = vid->vi_act;
	}

	(void) mutex_lock(&alab_mutex);
	if (al != NULL) {
		INSQUE(alabq, al);
		alab_work = TRUE;
		debug(7, "vol_insert: alab_work set to TRUE\n");
	}
#ifdef	TWO_SIDED_DEVICE
	if (al1 != NULL) {
		INSQUE(alabq, al1);
		alab_work = TRUE;
	}
#endif
	(void) mutex_unlock(&alab_mutex);

	(void) mutex_lock(&vold_main_mutex);
	/* we only want to send the signal while he's in a poll */
	if (alab_work) {
		debug(7, "vol_insert: sending SIGUSR2 to tid 1\n");
		(void) thr_kill(1, SIGUSR2);
	}
	(void) mutex_unlock(&vold_main_mutex);

	free(vid);

	debug(7, "vol_insert: thread exiting\n");

	/* this thread is all done */
	thr_exit(NULL);
}


static struct alab *
vol_readlabel(struct volins *vid)
{
	extern int		dev_getfd(dev_t);
	extern enum laread_res	label_scan(int, char *, label *,
				    struct devs *);
	struct devs		*dp;
	label			la;
	dev_t			dev = vid->vi_dev;
	enum laread_res		res;
	struct alab		*al;
	int			fd;


	/*
	 * have the driver specific code tell us how to get to the
	 * raw device.
	 */
	if ((fd = dev_getfd(dev)) == -1) {
		return (NULL);
	}

	la.l_label = 0;

	if ((dp = dev_getdp(dev)) == NULL) {
		return (NULL);
	}

	/*
	 * walk through the label types, trying to read the labels.
	 */
	if ((res = label_scan(fd, dp->dp_dsw->d_mtype, &la, dp)) == L_ERROR) {
		/*
		 * If the label routines couldn't read the device,
		 * get it outta here!
		 */
		dev_hard_eject(dp);
		return (NULL);
	}

	al = (struct alab *)calloc(1, sizeof (struct alab));
	al->al_dev = dev;
	al->al_stk = vid->vi_stk;
	al->al_readres = res;
	al->al_label.l_type = la.l_type;
	al->al_label.l_label = la.l_label;
	al->al_tid = thr_self();
	return (al);
}


static vol_t *
vol_foundlabel(dev_t dev, label *la, enum read_type act, enum laread_res rres)
{
	extern void		dev_hangvol(struct devs *, vol_t *);
	const char		*laread_res_to_str(enum laread_res);
	static const char	*read_type_to_str(enum read_type);
	vvnode_t		*vn;
	struct devs		*dp = dev_getdp(dev);
	vol_t			*v;
	int			nacts = 0;



	debug(3, "vol_foundlabel: entering for (%d.%d) (rres=%s, act=%s)\n",
	    major(dev), minor(dev), laread_res_to_str(rres),
	    read_type_to_str(act));

	/*
	 * go look for it in the namespace, etc.  If it isn't there,
	 * build us a new one.
	 */
	switch (rres) {
	default:
		/*
		 * just drop thru here -- dev_unlabeled will take
		 * care of it for us.
		 */
	case L_UNFORMATTED:
	case L_NOTUNIQUE:
	case L_UNRECOG:
		v = dev_unlabeled(dp, rres, la);
		break;
	case L_ERROR:
	case L_FOUND:
		if ((vn = node_findlabel(dp, la)) == NULL) {
			debug(3,
		"vol_foundlabel: node_findlabel() failed: ejecting\n");
			dev_hard_eject(dp);
			return (NULL);
		}

		v = vn->vn_vol;
		break;
	}

	dev_hangvol(dp, v);

	change_atime((obj_t *)v, &current_time);

	change_location((obj_t *)v, dp->dp_path);
	v->v_confirmed = TRUE;
	debug(1, "found volume \"%s\" in %s (%d,%d)\n",
	    v->v_obj.o_name, dp->dp_path, major(dev), minor(dev));
	if (!(v->v_flags & V_UNLAB)) {
		/*
		 * if it's not an unlabeled thing, write changes
		 * back to the database.
		 */
		(void) db_update((obj_t *)v);
	}
	if (act == INSERT) {
		nacts = action(ACT_INSERT, v);
		if ((dp->dp_checkresp != FALSE) && (nacts != 0)) {
			v->v_checkresp = TRUE;
			dp->dp_checkresp = FALSE;
		}
	}

	/* see if the s-enxio property needs to be cleared for this volume */
	if ((v->v_flags & V_ENXIO) && (act == INSERT) && (rres == L_FOUND)) {
		uint_t		i;

		/* clear s-enxio for each device on this volume */
		for (i = 0; i < v->v_ndev; i++) {
			struct vioc_flags	vfl;

			/*
			 * use the VOLIOCFLAGS ioctl to tell the driver to
			 * quit handling enxio
			 */
			vfl.vfl_unit = minor(v->v_devmap[i].dm_voldev);
			vfl.vfl_flags = 0;
			debug(1,
			"vol_foundlabel: calling VOLIOCFLAGS(0), unit %d\n",
			    vfl.vfl_unit);
			if (ioctl(vol_fd, VOLIOCFLAGS, &vfl) < 0) {
				debug(1, "vol_foundlabel: VOLIOCFLAGS; %m\n");
			}
		}
		/* clear the volume's s-enxio flag */
		v->v_flags &= ~V_ENXIO;
	}

	/* if someone is waiting on the check ioctl, wake them up. */
	if ((dp->dp_checkresp != FALSE) && (nacts == 0)) {
		(void) ioctl(vol_fd, VOLIOCDCHECK, 0);
		dp->dp_checkresp = FALSE;
	}

	return (v);
}

static void
mount_volume(dev_t dev, vol_t *v, uint_t act)
{
	struct devs		*dp = dev_getdp(dev);
	int			nacts = 0;
	struct reap		*r;

	for (r = HEAD(struct reap, reapq); r != NULL;
	    r = NEXT(struct reap, r)) {
		if (r->r_v == v && r->r_act != ACT_NOTIFY) {
			/*
			 * device is being closed or ejected, or might be
			 * being mounted, but we got another mount request
			 * because volume was missing and missing voluem has
			 * been inserted.
			 * We just ignore this request so that we don't
			 * bother the ongoing tasks.
			 */
			if (dp->dp_checkresp &&
			    (r->r_act == ACT_EJECT || r->r_act == ACT_CLOSE)) {
				/*
				 * respond to the check request which
				 * was made after the volume was missing.
				 * If the running action was either eject
				 * or close, we don't need to wait those
				 * to be complete, but respond immediately.
				 */
				(void) ioctl(vol_fd, VOLIOCDCHECK, 0);
				dp->dp_checkresp = FALSE;
			}
			return;
		}
	}

	nacts = action(act, v);
	if ((dp->dp_checkresp != FALSE) && (nacts != 0)) {
		v->v_checkresp = TRUE;
		dp->dp_checkresp = FALSE;
	}

	/*
	 * see if the s-enxio property needs to be cleared for
	 * this volume
	 *
	 * QUESTION: What is the s-enxio property?
	 */

	if (v->v_flags & V_ENXIO) {
		uint_t		i;

		/* clear s-enxio for each device on this volume */
		for (i = 0; i < v->v_ndev; i++) {
			struct vioc_flags	vfl;

			/*
			 * use the VOLIOCFLAGS ioctl to tell the driver to
			 * quit handling enxio
			 */
			vfl.vfl_unit = minor(v->v_devmap[i].dm_voldev);
			vfl.vfl_flags = 0;
			debug(1,
			"mount_volume: calling VOLIOCFLAGS(0), unit %d\n",
			    vfl.vfl_unit);
			if (ioctl(vol_fd, VOLIOCFLAGS, &vfl) < 0) {
				debug(1, "mount_volume: VOLIOCFLAGS; %m\n");
			}
		}

		/* clear the volume's s-enxio flag */

		v->v_flags &= ~V_ENXIO;
	}

	/*
	 * If a device thread is waiting for an ioctl(), send one.
	 */

	if ((dp->dp_checkresp != FALSE) && (nacts == 0)) {
		(void) ioctl(vol_fd, VOLIOCDCHECK, 0);
		dp->dp_checkresp = FALSE;
	}
}

const char *
laread_res_to_str(enum laread_res rres)
{
	const char	*res = NULL;
	static char	res_buf[10];


	switch (rres) {
	case L_UNRECOG:
		res = "L_UNRECOG";
		break;
	case L_UNFORMATTED:
		res = "L_UNFORMATTED";
		break;
	case L_NOTUNIQUE:
		res = "L_NOTUNIQUE";
		break;
	case L_ERROR:
		res = "L_ERROR";
		break;
	case L_FOUND:
		res = "L_FOUND";
		break;
	default:
		(void) sprintf(res_buf, "unknown (%d)", (int)rres);
		res = (const char *)res_buf;
		break;
	}

	return (res);
}


static const char
*read_type_to_str(enum read_type act)
{
	const char	*res = NULL;
	static char	res_buf[10];

enum read_type { INSERT, NEWLABEL, CONFIRM };

	switch (act) {
	case INSERT:
		res = "INSERT";
		break;
	case NEWLABEL:
		res = "NEWLABEL";
		break;
	case CONFIRM:
		res = "CONFIRM";
		break;
	default:
		(void) sprintf(res_buf, "unknown (%d)", (int)act);
		res = (const char *)res_buf;
		break;
	}

	return (res);
}


static void
vol_newlabel(vol_t *v, dev_t dev, label *la)
{
	extern void	dev_hangvol(struct devs *, vol_t *);
	vol_t		*nv = 0;
	struct devs 	*dp;
	uint_t		err;
	bool_t		doej;
	minor_t		c_vol;
	uid_t		c_uid;
	dev_t		c_tty;
	devmap_t	*dm;

	debug(11, "vol_newlabel: entered for \"%s\"\n", v->v_obj.o_name);

	/*
	 * unlabeled -> labeled
	 */
	if ((la->l_label != NULL) && (v->v_flags & V_UNLAB)) {

		debug(5, "vol_newlabel: unlabeled -> labeled\n");

		if (v->v_ej_inprog) {
			c_vol = v->v_clue.c_volume;
			c_uid = v->v_clue.c_uid;
			c_tty = v->v_clue.c_tty;
			debug(5,
			"vol_newlabel: clearing devmap using devmapfree\n");
			(void) dev_devmapfree(v);
			doej = TRUE;
		} else {
			doej = FALSE;
		}

		/* unhang the old unlabeled stuff */
		dev_unhangvol(dev_getdp(dev));
		/* v is gone now */

		/* recognize it in the cannonical way */
		nv = vol_foundlabel(dev, la, NEWLABEL, L_FOUND);

		/* must clear "cancel" flag on vol before unmapping */
		(void) dev_map(nv, FALSE);

		if (doej && (nv != NULL)) {
			nv->v_clue.c_volume = c_vol;
			nv->v_clue.c_uid = c_uid;
			nv->v_clue.c_tty = c_tty;
			nv->v_ejfail = FALSE;
			nv->v_ej_force = FALSE;
			nv->v_ej_inprog = TRUE;
			debug(5, "vol_newlabel: creating devmap\n");
			dev_devmap(nv);
			if (action(ACT_EJECT, nv) == 0) {
				dev_eject(nv, TRUE);
			}
		}
		return;
	}

	/*
	 * labeled -> labeled
	 */
	if ((la->l_label != NULL) && !(v->v_flags & V_UNLAB)) {

		debug(5, "vol_newlabel: labeled -> labeled\n");

		/* just rewrote the label on a normal name */
		change_label((obj_t *)v, la);
		(void) db_update((obj_t *)v);
		if (v->v_ej_inprog && (action(ACT_EJECT, v) == 0)) {
			dev_eject(v, TRUE);
		}
		return;
	}

	/*
	 * labeled -> unlabeled
	 */
	if ((la->l_label == NULL) && !(v->v_flags & V_UNLAB)) {
		debug(5, "vol_newlabel: labeled -> unlabeled\n");
		/* out with the old */
		dp = dev_getdp(dev);
		(void) dev_devmapfree(v);
		if (v->v_ej_inprog) {
			c_vol = v->v_clue.c_volume;
			c_uid = v->v_clue.c_uid;
			c_tty = v->v_clue.c_tty;
			dm = v->v_devmap;
			v->v_devmap = 0;
			doej = TRUE;
		} else {
			doej = FALSE;
		}
		dev_unhangvol(dp);
		node_remove((obj_t *)v, TRUE, &err);
		/* v is gone now */

		/* in with the new */
		nv = dev_unlabeled(dp, L_UNRECOG, la);
		dev_hangvol(dp, nv);
		change_atime((obj_t *)nv, &current_time);
		change_location((obj_t *)nv, dp->dp_path);
		nv->v_confirmed = TRUE;
		if (doej) {
			/*
			 * If we need to eject him, copy the
			 * eject information.
			 */
			nv->v_devmap = dm;
			nv->v_clue.c_volume = c_vol;
			nv->v_clue.c_uid = c_uid;
			nv->v_clue.c_tty = c_tty;
			nv->v_ejfail = FALSE;
			nv->v_ej_force = FALSE;
			nv->v_ej_inprog = TRUE;
			if (action(ACT_EJECT, nv) == 0) {
				dev_eject(nv, TRUE);
			}
		}
		/*
		 * must map device in case someboy is in a hurry to
		 * access it
		 */
		dev_devmap(nv);
		return;
	}

	/*
	 * unlabeled -> unlabeled
	 */
	if ((la->l_label == 0) && (v->v_flags & V_UNLAB)) {
		debug(5, "vol_newlabel: unlabeled -> unlabeled\n");
		if (v->v_ej_inprog && (action(ACT_EJECT, v) == 0)) {
			dev_eject(v, TRUE);
		}
		return;
	}

	/* shouldn't reach here */
	ASSERT(0);
}

static void
dispatch_alab(void)
{
	struct alab	*al, *al_next;

	/*
	 * Results from async label reads.
	 */
	(void) mutex_lock(&alab_mutex);
	for (al = HEAD(struct alab, alabq); al != NULL; al = al_next) {
		al_next = NEXT(struct alab, al);

		switch (al->al_act) {
		case INSERT:
			mount_volume(al->al_dev, al->al_v, ACT_INSERT);
			break;
		case NEWLABEL:
			vol_newlabel(al->al_v, al->al_dev,
			    &al->al_label);
			break;
		case REMOUNT:
			mount_volume(al->al_dev, al->al_v, ACT_REMOUNT);
			break;
		default:
			debug(1, "vol_async: funny work %d\n",
				al->al_act);
		}

		REMQUE(alabq, al);

		/* wait for the thread */
		if (al->al_tid != 0) {
			(void) thr_join(al->al_tid, 0, 0);
		}
		if (al->al_stk != NULL) {
			free(al->al_stk); /* free the thread stack */
		}
		free(al);		/* free the alab */
	}
	alab_work = FALSE;
	(void) mutex_unlock(&alab_mutex);
}

static int
event_check_safe(struct vioc_event *vie, struct devs *dp)
{
	if (dp == NULL)
		return (1);

	switch (vie->vie_type) {
	case VIE_INSERT:
		/*
		 * The intent of the logic below is that we don't want to
		 * block the insert when volume is missing. Otherwise,
		 * new volume won't be created, and the volume is missing
		 * forever.
		 */
		if (dp->dp_asynctask != 0) {
			struct reap	*r;

			if (dp->dp_flags & DP_SCANNING) {
				/*
				 * this device is being read and the volume
				 * is being created. not safe.
				 */
				return (0);
			}
			/*
			 * not scanning the medium, but volume has gone.
			 * That means, either device is missing, or brand
			 * new medium was inserted.
			 */
			if (dp->dp_vol == NULL)
				return (1);
			/*
			 * check the async tasks see if any references
			 * to the volume.
			 */
			for (r = HEAD(struct reap, reapq); r != NULL;
			    r = NEXT(struct reap, r)) {
				if (r->r_v == dp->dp_vol &&
				    (r->r_v->v_flags & V_MISSING) != 0) {
					/*
					 * missing volume. It can go through.
					 */
					return (1);
				}
			}
			return (0);
		}
		break;

	case VIE_REMOUNT:
	case VIE_EJECT:
		/*
		 * if nothing is working, then it's safe.
		 */
		if (dp->dp_asynctask != 0)
			return (0);
		break;
	}
	return (1);
}

static void
dispatch_async_task(void)
{
	struct async_task *as, *as_next;
	struct devs	*dp;
	dev_t		dev;
	int		start_over;

	(void) mutex_lock(&async_taskq_mutex);
restart:
	for (as = TAIL(struct async_task, async_taskq);
	    as != NULL; as = as_next) {
		as_next = PREV(struct async_task, as);

		start_over = 0;
		switch (as->act) {
		case ASACT_REAPTHR: {
			thread_t	tid;

			dev = (dev_t)as->data[0];
			tid = (thread_t)as->data[1];
			dp = dev_getdp(dev);
			if (thr_join(tid, 0, 0) == 0) {
				if (dp != NULL) {
					if (--dp->dp_asynctask == 0)
						start_over = 1;
				}
			}
			break;
		}
		case ASACT_NEWEVENT: {
			struct vioc_event *vie;

			vie = (struct vioc_event *)as->data[0];
			dp = (struct devs *)as->data[1];

			if (!event_check_safe(vie, dp)) {
				/*
				 * leave the async task int the queue and
				 * and go to the next event.
				 */
				continue;
			}
			vol_event_unlocked(vie);
			free(vie);
			break;
		}
		case ASACT_MOUNT:
		case ASACT_REMOUNT: {
			vol_t		*v;
			int		act;

			dev = (dev_t)as->data[0];
			v = (vol_t *)as->data[1];

			act = (as->act == ASACT_MOUNT ? ACT_INSERT :
				ACT_REMOUNT);
			mount_volume(dev, v, act);
			break;
		}
		case ASACT_DEV_CLOSE: {
			dev = (dev_t)as->data[0];
			(void) dev_close(dev);
			break;
		}
		default:
			debug(1, "funny async task %d\n", as->act);
			break;
		}
		REMQUE(async_taskq, as);
		free(as);
		if (start_over)
			goto restart;
	}
	if (HEAD(struct async_task, async_taskq) == NULL)
		async_taskq_run = FALSE;
	(void) mutex_unlock(&async_taskq_mutex);
}

void
async_taskq_insert(struct async_task *as)
{
	(void) mutex_lock(&async_taskq_mutex);
	INSQUE(async_taskq, as);
	async_taskq_run = TRUE;
	vold_run_run();
	(void) mutex_unlock(&async_taskq_mutex);
}

/*
 * remove the NEWEVENT by given devicep from async taskq.
 */
void
async_taskq_clean(struct devs *devicep)
{
	struct async_task *as, *as_next;
	struct vioc_event *vie;
	struct devs *dp;

	if (devicep == NULL)
		return;

	(void) mutex_lock(&async_taskq_mutex);
	for (as = HEAD(struct async_task, async_taskq);
	    as != NULL; as = as_next) {
		as_next = NEXT(struct async_task, as);
		if (as->act != ASACT_NEWEVENT)
			continue;
		dp = (struct devs *)as->data[1];
		if (dp != devicep)
			continue;
		vie = (struct vioc_event *)as->data[0];
		free(vie);
		REMQUE(async_taskq, as);
		free(as);
	}
	(void) mutex_unlock(&async_taskq_mutex);
}

/*
 * check to see if we already have REMOUNT event queued in the
 * async taskq. If so, don't queue.
 */
static int
async_taskq_dupev_check(struct devs *devicep, enum vie_event etype)
{
	struct async_task *as, *as_next;
	struct vioc_event *vie;
	struct devs *dp;

	if (devicep == NULL)
		return (0);

	(void) mutex_lock(&async_taskq_mutex);
	for (as = HEAD(struct async_task, async_taskq);
	    as != NULL; as = as_next) {
		as_next = NEXT(struct async_task, as);
		if (as->act != ASACT_NEWEVENT)
			continue;
		dp = (struct devs *)as->data[1];
		if (dp != devicep)
			continue;
		vie = (struct vioc_event *)as->data[0];
		if (vie->vie_type == etype)
			break;
	}
	(void) mutex_unlock(&async_taskq_mutex);
	return (as != NULL);
}

static void
reap_child(void)
{
	struct reap	*r, *r_next;
	struct devs	*dp;

	for (r = HEAD(struct reap, reapq); r != NULL; r = r_next) {
		r_next = NEXT(struct reap, r);

		if (vol_reaper(r) != 1)
			continue;

		if (r->r_act != ACT_NOTIFY) {
			/*
			 * we need r_dev here, because r_v may be
			 * replaced by an insertion event when volume
			 * was missing. Therefore, v_basedev could point
			 * different drive.
			 */
			if ((dp = dev_getdp(r->r_dev)) != NULL) {
				if (--dp->dp_asynctask == 0)
					vold_run_run();
			}
		}
		/*
		 * child has been dead. respond to the check,
		 * if it's pending. We don't do it for eject, close
		 * or notify, because volume may have been released or
		 * replaced(notify) at this point. And actually volcheck
		 * waits only for the response of insert/remount event.
		 */
		if (r->r_act == ACT_INSERT || r->r_act == ACT_REMOUNT) {
			if (r->r_v != NULL && r->r_v->v_checkresp != FALSE) {
				(void) ioctl(vol_fd, VOLIOCDCHECK, 0);
				r->r_v->v_checkresp = FALSE;
			}
		}
		/* free this thing */
		REMQUE(reapq, r);
		free(r->r_hint);
		free(r);
	}
}

/*
 * called from main vold loop to handle asynchronous events:
 *	- async label reads
 *	- reap process status (e.g. from rmmount)
 * return TRUE if action is in progress.
 */
int
vol_async(void)
{
	int	ret;

	/*
	 * Results from async label reads.
	 */
	if (alab_work) {
		debug(12, "alab_work\n");
		dispatch_alab();
	}

	if (async_taskq_run) {
		debug(12, "asyncq run\n");
		dispatch_async_task();
	}

	/*
	 * Results from action processes (eject specifically)
	 */
	if (HEAD(struct reap, reapq) != NULL) {
		debug(12, "reaping children\n");
		reap_child();
	}
	ret = (HEAD(struct reap, reapq) != NULL || dev_nastask() > 0);
	debug(12, "vol_async: no more async work, return %d\n", ret);
	return (ret);
}

static void
eject_or_close(struct reap *r, bool_t ans)
{
	switch (r->r_act) {
	case ACT_EJECT:
		dev_eject(r->r_v, ans);
		break;
	case ACT_CLOSE:
		dev_closeout(r->r_v, ans);
		break;
	}
}

static int
vol_reaper(struct reap *r)
{
	pid_t		err;
	int		stat;

	debug(12, "vol_reaper: entering: pid=%d, act=%d (%s)\n",
	    r->r_pid, r->r_act, actnames[r->r_act]);
	if (r->r_pid == 0 &&
	    (r->r_act == ACT_EJECT || r->r_act == ACT_CLOSE)) {
		/* had an internal error -- ejecting */
		eject_or_close(r, TRUE);
		return (1);
	}

	if (r->r_pid == -1 &&
	    (r->r_act == ACT_EJECT || r->r_act == ACT_CLOSE)) {
		/* unsafe -- not ejecting */
		if (r->r_v != NULL) {
			warning(gettext(
			    "volume %s has file system mounted, "
			    "cannot eject\n"),
			    r->r_v->v_obj.o_name);
			r->r_v->v_eject = 0;
			r->r_v->v_ejfail = TRUE;
			eject_or_close(r, FALSE);
		}
		return (1);
	}

	debug(12, "vol_reaper: waiting (NOHANG) for pid %d\n", r->r_pid);
	if ((err = waitpid(r->r_pid, &stat, WNOHANG)) == 0) {
		/* process is still working */
		return (0);
	}

	if (err == -1) {
		debug(1, "waitpid for %s action pid %d; %m\n",
		    actnames[r->r_act], r->r_pid);
		return (0);
	}

	debug(12, "vol_reaper: pid %d returned stat 0%o\n", r->r_pid, stat);

	if (WIFEXITED(stat)) {
		debug(4, "status for pid %d: exited with %d\n",
			r->r_pid, WEXITSTATUS(stat));
	} else if (WIFSIGNALED(stat)) {
		if (WCOREDUMP(stat)) {
			debug(4,
	"status for pid %d: signaled with '%s' and dumped core\n",
			    r->r_pid, strsignal(WTERMSIG(stat)));
		} else {
			debug(4,
			    "status for pid %d: signaled with '%s'\n",
			    r->r_pid, strsignal(WTERMSIG(stat)));
		}
	} else {
		debug(4, "status for pid %d: %#x\n", r->r_pid, stat);
	}

	/*
	 * If the process was an eject action and it exited normally,
	 * we take this path.
	 */
	if (r->r_act == ACT_EJECT || r->r_act == ACT_CLOSE) {
		debug(12, "vol_reaper: cleaning up after eject\n");

		/*
		 * volume may have been released while ejecting
		 * the medium.
		 */
		if (r->r_v == NULL)
			return (1);

		if (r->r_v->v_eject > 0) {
			r->r_v->v_eject--;
		}

		if (WIFEXITED(stat)) {
			if (WEXITSTATUS(stat) == 0) {
				/*
				 * don't eject until all the actions are done.
				 */
				if ((r->r_v->v_eject == 0) &&
				    (r->r_v->v_ejfail == FALSE)) {
					eject_or_close(r, TRUE);
				}
				return (1);
			}
			if (WEXITSTATUS(stat) == 1) {
				/*
				 * If we get a no, say that we are done and
				 * fail the eject.
				 */
				r->r_v->v_eject = 0;
				r->r_v->v_ejfail = TRUE;
				eject_or_close(r, FALSE);
				return (1);
			}

			debug(1,
		gettext("eject action %s retns exit code %d, not ejecting\n"),
			    r->r_hint, WEXITSTATUS(stat));
			r->r_v->v_eject = 0;
			r->r_v->v_ejfail = TRUE;
			eject_or_close(r, FALSE);
			return (1);
		}
		if (WIFSIGNALED(stat)) {
			/*
			 * If the process got its brains blown out,
			 * don't treat that as a denial, just continue
			 * along.
			 */
			if ((r->r_v->v_eject == 0) &&
			    (r->r_v->v_ejfail == FALSE)) {
				eject_or_close(r, TRUE);
			}
			return (1);
		}
	}

	if (WIFEXITED(stat) || WIFSIGNALED(stat)) {
		return (1);
	}
	warning(gettext("%s action process %d hanging around...\n"),
	    actnames[r->r_act], r->r_pid);
	return (0);
}

vol_t *
vol_mkvol(struct devs *dp, label *la)
{
	vol_t	*v;

	v = (vol_t *)calloc(1, sizeof (vol_t));
	v->v_obj.o_type = VV_CHR;
	v->v_mtype = strdup(dp->dp_dsw->d_mtype);
	v->v_basedev = NODEV;
	label_setup(la, v, dp);
	change_atime((obj_t *)v, &current_time);
	return (v);
}

void
destroy_volume(vol_t *volumep)
{
	if (volumep == NULL)
		return;
	if (volumep->v_obj.o_name != NULL)
		free(volumep->v_obj.o_name);

	if (volumep->v_obj.o_dir != NULL)
		free(volumep->v_obj.o_dir);

	if (volumep->v_obj.o_props != NULL)
		free(volumep->v_obj.o_props);

	if (volumep->v_mtype != NULL)
		free(volumep->v_mtype);

	destroy_label((partition_label_t **)&volumep->v_label.l_label);

	if (volumep->v_devmap != NULL)
		(void) dev_devmapfree(volumep);

	if (volumep->v_location != NULL)
		free(volumep->v_location);

	free(volumep);
}
