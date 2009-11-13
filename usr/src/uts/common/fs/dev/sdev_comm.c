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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * routines to invoke user level name lookup services
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/mode.h>
#include <sys/policy.h>
#include <sys/disp.h>
#include <sys/door.h>
#include <fs/fs_subr.h>
#include <sys/mount.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>
#include <sys/sunndi.h>
#include <sys/sunddi.h>
#include <sys/sunmdi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ddi.h>

/* default timeout to wait for devfsadm response in seconds */
#define	DEV_DEVFSADM_STARTUP	(1 * 60)
#define	DEV_NODE_WAIT_TIMEOUT	(5 * 60)

/* atomic bitset for devfsadm status */
volatile uint_t devfsadm_state;

static kmutex_t devfsadm_lock;
static kcondvar_t devfsadm_cv;

static int dev_node_wait_timeout = DEV_NODE_WAIT_TIMEOUT;
static int dev_devfsadm_startup =  DEV_DEVFSADM_STARTUP;

/*
 * Door used to communicate with devfsadmd
 */
static door_handle_t	sdev_upcall_door = NULL;	/* Door for upcalls */
static char		*sdev_door_upcall_filename = NULL;
static int		sdev_upcall_door_revoked = 0;
static int		sdev_door_upcall_filename_size;

static int sdev_devfsadm_revoked(void);
static int sdev_ki_call_devfsadmd(sdev_door_arg_t *, sdev_door_res_t *);

void
sdev_devfsadm_lockinit(void)
{
	mutex_init(&devfsadm_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&devfsadm_cv, NULL, CV_DEFAULT, NULL);
}

void
sdev_devfsadm_lockdestroy(void)
{
	mutex_destroy(&devfsadm_lock);
	cv_destroy(&devfsadm_cv);
}

/*
 * Wait for node to be created
 */
int
sdev_wait4lookup(struct sdev_node *dv, int cmd)
{
	clock_t	expire;
	clock_t rv;
	clock_t wakeup = drv_usectohz(2 * 1000000);
	int rval = ENOENT;
	int is_lookup = (cmd == SDEV_LOOKUP);

	ASSERT(cmd == SDEV_LOOKUP || cmd == SDEV_READDIR);
	ASSERT(MUTEX_HELD(&dv->sdev_lookup_lock));

	/* tick value at which wait expires */
	expire = ddi_get_lbolt() +
	    drv_usectohz(dev_node_wait_timeout * 1000000);

	sdcmn_err6(("wait4lookup %s %s, %ld %d\n",
	    is_lookup ? "lookup" : "readdir",
	    dv->sdev_name, expire - ddi_get_lbolt(), dv->sdev_state));

	if (SDEV_IS_LGWAITING(dv)) {
		/* devfsadm nodes */
		while (DEVNAME_DEVFSADM_IS_RUNNING(devfsadm_state) &&
		    !sdev_devfsadm_revoked()) {
			/* wait 2 sec and check devfsadm completion */
			rv = cv_reltimedwait_sig(&dv->sdev_lookup_cv,
			    &dv->sdev_lookup_lock, wakeup, TR_CLOCK_TICK);

			if (is_lookup && (rv > 0)) {
				/* was this node constructed ? */
				if (dv->sdev_state == SDEV_READY) {
					rval = 0;
				}
				sdcmn_err6(("%s: wait done, %screated %d\n",
				    dv->sdev_name, rval ? "not " : "",
				    dv->sdev_state));
				break;
			} else if (rv == 0) {
				/* interrupted */
				sdcmn_err6(("%s: wait interrupted\n",
				    dv->sdev_name));
				break;
			} else if ((rv == -1) &&
			    (ddi_get_lbolt() >= expire)) {
				sdcmn_err6(("%s: wait time is up\n",
				    dv->sdev_name));
				break;
			}
			sdcmn_err6(("%s: wait "
			    "rv %ld state 0x%x expire %ld\n",
			    dv->sdev_name, rv, devfsadm_state,
			    expire - ddi_get_lbolt()));
		}
	} else {
		/*
		 * for the nodes created by
		 * devname_lookup_func callback
		 * or plug-in modules
		 */
		while (SDEV_IS_LOOKUP(dv) || SDEV_IS_READDIR(dv)) {
			cv_wait(&dv->sdev_lookup_cv, &dv->sdev_lookup_lock);
		}
		rval = 0;
	}

	sdcmn_err6(("wait4lookup unblocking %s state 0x%x %d\n",
	    dv->sdev_name, devfsadm_state, dv->sdev_state));

	if (is_lookup) {
		SDEV_UNBLOCK_OTHERS(dv, SDEV_LOOKUP);
	} else {
		SDEV_UNBLOCK_OTHERS(dv, SDEV_READDIR);
	}

	return (rval);
}

void
sdev_unblock_others(struct sdev_node *dv, uint_t cmd)
{
	ASSERT(MUTEX_HELD(&dv->sdev_lookup_lock));

	SDEV_CLEAR_LOOKUP_FLAGS(dv, cmd);
	if (SDEV_IS_LGWAITING(dv)) {
		SDEV_CLEAR_LOOKUP_FLAGS(dv, SDEV_LGWAITING);
	}
	cv_broadcast(&dv->sdev_lookup_cv);
}

/*
 * In the case devfsadmd is down, it is re-started by syseventd
 * upon receiving an event subscribed to by devfsadmd.
 */
static int
sdev_start_devfsadmd()
{
	int		se_err = 0;
	sysevent_t	*ev;
	sysevent_id_t	eid;

	ev = sysevent_alloc(EC_DEVFS, ESC_DEVFS_START, EP_DDI, SE_SLEEP);
	ASSERT(ev);
	if ((se_err = log_sysevent(ev, SE_SLEEP, &eid)) != 0) {
		switch (se_err) {
		case SE_NO_TRANSPORT:
			cmn_err(CE_WARN, "unable to start devfsadm - "
			    "syseventd may not be responding\n");
			break;
		default:
			cmn_err(CE_WARN, "unable to start devfsadm - "
			    "sysevent error %d\n", se_err);
			break;
		}
	}

	sysevent_free(ev);
	return (se_err);
}

static int
sdev_open_upcall_door()
{
	int error;
	clock_t rv;
	clock_t expire;

	ASSERT(sdev_upcall_door == NULL);

	/* timeout expires this many ticks in the future */
	expire = ddi_get_lbolt() + drv_usectohz(dev_devfsadm_startup * 1000000);

	if (sdev_door_upcall_filename == NULL) {
		if ((error = sdev_start_devfsadmd()) != 0) {
			return (error);
		}

		/* wait for devfsadmd start */
		mutex_enter(&devfsadm_lock);
		while (sdev_door_upcall_filename == NULL) {
			sdcmn_err6(("waiting for dev_door creation, %ld\n",
			    expire - ddi_get_lbolt()));
			rv = cv_timedwait_sig(&devfsadm_cv, &devfsadm_lock,
			    expire);
			sdcmn_err6(("dev_door wait rv %ld\n", rv));
			if (rv <= 0) {
				sdcmn_err6(("devfsadmd startup error\n"));
				mutex_exit(&devfsadm_lock);
				return (EBADF);
			}
		}
		sdcmn_err6(("devfsadmd is ready\n"));
		mutex_exit(&devfsadm_lock);
	}

	if ((error = door_ki_open(sdev_door_upcall_filename,
	    &sdev_upcall_door)) != 0) {
		sdcmn_err6(("upcall_lookup: door open error %d\n",
		    error));
		return (error);
	}

	return (0);
}

static void
sdev_release_door()
{
	if (sdev_upcall_door) {
		door_ki_rele(sdev_upcall_door);
		sdev_upcall_door = NULL;
	}
	if (sdev_door_upcall_filename) {
		kmem_free(sdev_door_upcall_filename,
		    sdev_door_upcall_filename_size);
		sdev_door_upcall_filename = NULL;
	}
}

static int
sdev_ki_call_devfsadmd(sdev_door_arg_t *argp, sdev_door_res_t *resultp)
{
	door_arg_t	darg, save_arg;
	int		error;
	int		retry;

	if (((sdev_upcall_door == NULL) &&
	    ((error = sdev_open_upcall_door()) != 0)) ||
	    sdev_devfsadm_revoked()) {
		sdcmn_err6(("call_devfsadm: upcall lookup error\n"));
		return (error);
	}

	ASSERT(argp);
	darg.data_ptr = (char *)argp;
	darg.data_size = sizeof (struct sdev_door_arg);
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = (char *)(resultp);
	darg.rsize = sizeof (struct sdev_door_res);

	ASSERT(sdev_upcall_door);
	save_arg = darg;
	for (retry = 0; ; retry++) {
		sdcmn_err6(("call devfsadm: upcall lookup, retry %d\n", retry));
		if ((error = door_ki_upcall_limited(sdev_upcall_door, &darg,
		    NULL, SIZE_MAX, 0)) == 0) {
			sdcmn_err6(("call devfsadm: upcall lookup ok\n"));
			break;
		}

		/*
		 * handle door call errors
		 */
		if (sdev_devfsadm_revoked()) {
			sdcmn_err6(("upcall lookup door revoked, "
			    "error %d\n", error));
			return (error);
		}

		switch (error) {
		case EINTR:
			/* return error here? */
			sdcmn_err6(("sdev_ki_call_devfsadm: EINTR\n"));
			delay(hz);
			break;
		case EAGAIN:
			sdcmn_err6(("sdev_ki_call_devfsadm: EAGAIN\n"));
			delay(2 * hz);
			break;
		case EBADF:
			if (retry > 4) {
				sdcmn_err6(("sdev_ki_call_devfsadm: EBADF\n"));
				return (EBADF);
			}
			sdcmn_err6((
			    "sdev_ki_call_devfsadm: EBADF, re-binding\n"));
			sdev_release_door();
			delay(retry * hz);
			error = sdev_open_upcall_door();
			if (error != 0) {
				sdcmn_err6(("sdev_ki_call_devfsadm: "
				    "EBADF lookup error %d\n", error));
				if (!sdev_devfsadm_revoked())
					cmn_err(CE_NOTE,
					    "?unable to invoke devfsadm - "
					    "please run manually\n");
				return (EBADF);
			}
			break;
		case EINVAL:
		default:
			cmn_err(CE_CONT,
			    "?sdev: door_ki_upcall unexpected result %d\n",
			    error);
			return (error);
		}

		darg = save_arg;
	}

	if (!error) {
		ASSERT((struct sdev_door_res *)(intptr_t)darg.rbuf == resultp);
		if (resultp->devfsadm_error != 0) {
			sdcmn_err6(("sdev_ki_call_devfsadmd: result %d\n",
			    resultp->devfsadm_error));
			error = resultp->devfsadm_error;
		}
	} else {
		sdcmn_err6(("sdev_ki_call_devfsadmd with error %d\n", error));
	}

	return (error);
}

static int
sdev_devfsadm_revoked(void)
{
	struct door_info info;
	int rv;
	extern int sys_shutdown;

	if (sys_shutdown) {
		sdcmn_err6(("dev: shutdown observed\n"));
		return (1);
	}

	if (sdev_upcall_door && !sdev_upcall_door_revoked) {
		rv = door_ki_info(sdev_upcall_door, &info);
		if ((rv == 0) && info.di_attributes & DOOR_REVOKED) {
			sdcmn_err6(("lookup door: revoked\n"));
			sdev_upcall_door_revoked = 1;
		}
	}

	return (sdev_upcall_door_revoked);
}

/*ARGSUSED*/
static void
sdev_config_all_thread(struct sdev_node *dv)
{
	int32_t error = 0;
	sdev_door_arg_t	*argp;
	sdev_door_res_t result;

	argp = kmem_zalloc(sizeof (sdev_door_arg_t), KM_SLEEP);
	argp->devfsadm_cmd = DEVFSADMD_RUN_ALL;

	error = sdev_ki_call_devfsadmd(argp, &result);
	if (!error) {
		sdcmn_err6(("devfsadm result error: %d\n",
		    result.devfsadm_error));
		if (!result.devfsadm_error) {
			DEVNAME_DEVFSADM_SET_RUN(devfsadm_state);
		} else {
			DEVNAME_DEVFSADM_SET_STOP(devfsadm_state);
		}
	} else {
		DEVNAME_DEVFSADM_SET_STOP(devfsadm_state);
	}

	kmem_free(argp, sizeof (sdev_door_arg_t));
done:
	sdcmn_err6(("sdev_config_all_thread: stopping, devfsadm state 0x%x\n",
	    devfsadm_state));
	thread_exit();
}

/*
 * launch an asynchronous thread to do the devfsadm dev_config_all
 */
/*ARGSUSED*/
void
sdev_devfsadmd_thread(struct sdev_node *ddv, struct sdev_node *dv,
    struct cred *cred)
{
	ASSERT(i_ddi_io_initialized());
	DEVNAME_DEVFSADM_SET_RUNNING(devfsadm_state);
	(void) thread_create(NULL, 0, sdev_config_all_thread, dv, 0,
	    &p0, TS_RUN, MINCLSYSPRI);
}

int
devname_filename_register(char *name)
{
	int error = 0;
	char *strbuf;
	char *namep;
	int n;

	strbuf = kmem_zalloc(MOD_MAXPATH, KM_SLEEP);

	if (copyinstr(name, strbuf, MOD_MAXPATH, 0)) {
		sdcmn_err6(("error copyin \n"));
		error = EFAULT;
	} else {
		sdcmn_err6(("file %s is registering\n", strbuf));
		/* handling the daemon re-start situations */
		n = strlen(strbuf) + 1;
		namep = i_ddi_strdup(strbuf, KM_SLEEP);
		mutex_enter(&devfsadm_lock);
		sdev_release_door();
		sdev_door_upcall_filename_size = n;
		sdev_door_upcall_filename = namep;
		sdcmn_err6(("size %d file name %s\n",
		    sdev_door_upcall_filename_size,
		    sdev_door_upcall_filename));
		cv_broadcast(&devfsadm_cv);
		mutex_exit(&devfsadm_lock);
	}

	kmem_free(strbuf, MOD_MAXPATH);
	return (error);
}
