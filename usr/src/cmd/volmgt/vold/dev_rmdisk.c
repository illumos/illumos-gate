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

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mkdev.h>
#include	<sys/dkio.h>
#include	<sys/vtoc.h>
#include	<sys/dktp/fdisk.h>
#include	<errno.h>
#include	<signal.h>
#include	<string.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<thread.h>
#include	<synch.h>
#include	<sys/types.h>

#include	"vold.h"
#include	"vtoc.h"

#if defined(_FIRMWARE_NEEDS_FDISK)
	static int fdisk_supported = 1;
#else
	static int fdisk_supported = 0;
#endif

#define	NUM_FS_TYPES		2
#define	RMDISK_READ_SIZE	512
#define	RMDMAX_FDISK_PARTITIONS	5

static const int	P_TYPE = 1;
static const int	P_DEFAULT_PARTITION =  0;
static const char	*P_PATH_FORMAT = "%sp%d";
static const int	S_TYPE = 0;
static const int	S_DEFAULT_PARTITION = 2;
static const char	*S_PATH_FORMAT = "%ss%d";
static const int	THREAD_STACK_SIZE = (64 * 1024);

static struct rmdisk_priv {
	mutex_t	rmd_killmutex;
	int	rmd_tid;
	char	*rmd_rawpath[NUM_FS_TYPES][V_NUMPAR];
	int	rmd_fd[NUM_FS_TYPES][V_NUMPAR];
	int	rmd_defpart[NUM_FS_TYPES];
	int	rmd_fs_type;
};

/*
 * Declarations of methods that are externally
 * visible throught the devsw structure
 */

static bool_t	rmdisk_use(char *, char *);
static bool_t	rmdisk_error(struct ve_error *);
static int	rmdisk_getfd(dev_t);
static void	rmdisk_devmap(vol_t *, int, int);
static void	rmdisk_close(char *path, dev_t);
static int	rmdisk_check(struct devs *dp);
static bool_t	rmdisk_testpath(char *);
static bool_t	rmdisk_remount(vol_t *);

static struct devsw rmdiskdevsw = {
	rmdisk_use,		/* d_use */
	rmdisk_error,		/* d_error */
	rmdisk_getfd,		/* d_getfd */
	NULL,			/* d_poll */
	rmdisk_devmap,		/* d_devmap */
	rmdisk_close,		/* d_close */
	NULL, 			/* d_eject */
	NULL, 			/* d_find */
	rmdisk_check,		/* d_check */
	RMDISK_MTYPE,		/* d_mtype */ /* device type */
	"drive",		/* d_dtype */
	D_POLL|D_MEJECTABLE,	/* d_flags */
	(uid_t)0,		/* d_uid */
	(gid_t)0,		/* d_gid */
	(mode_t)0,		/* d_mode */
	rmdisk_testpath,	/* d_test */
	rmdisk_remount		/* d_remount */
};

/*
 * Declarations of private methods
 */

static void	close_fds(struct rmdisk_priv *private_datap);
static char	*dkiostate_to_str(enum dkio_state	st);
static int	reopen_rmdisk(struct rmdisk_priv *rmdp);

#define	CANT_REOPEN	-1
#define	CANT_CLOSE	-1
#define	REOPEN_RO	1
#define	REOPEN_RW	0

static void	rmdisk_thread_wait(struct devs *dp);

/*
 * Definitions of externally visible methods
 */

bool_t
dev_init()
{
	dev_new(&rmdiskdevsw);
	return (TRUE);
}

/*
 * rmdisk_use -- this routine expects either a raw or block path
 *	to a removable disk and detects that the disk is removable
 *	by issuing a DKIOCREMOVABLE ioctl().
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
rmdisk_use(char *pathname, char *symname)
{
	char			block_slice_pathname[MAXNAMELEN + 1];
	char			block_device_pathname[MAXNAMELEN + 1];
	int			default_partition;
	char			*device_namep;
	struct devs		*devicep;
	char			*dsk_startp;
	int			fs_type;
	int			partition_number;
	char			pathname_buffer[MAXNAMELEN + 1];
	int			pathname_length;
	struct rmdisk_priv	*private_datap;
	char			raw_slice_pathname[MAXNAMELEN + 1];
	char			raw_device_pathname[MAXNAMELEN + 1];
	char			*rdsk_startp;
	struct stat		statbuf;

	info(gettext("rmdisk_use: %s, %s\n"), pathname, symname);

	if (stat(pathname, &statbuf) < 0) {
		debug(1, "rmdisk_use: stat of \"%s\"; %m\n", pathname);
		return (FALSE);
	}
	if ((devicep = dev_search_dp(statbuf.st_rdev)) != NULL) {
		if (devicep->dp_dsw == &rmdiskdevsw) {
			debug(1, "rmdisk_use: %s already in use\n", pathname);
			return (TRUE);
		} else {
			debug(1, "rmdisk_use: %s already managed by %s\n",
				pathname, devicep->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	if (S_ISCHR(statbuf.st_mode)) {
		(void) strcpy(raw_slice_pathname, pathname);
		rdsk_startp = strstr(pathname, "/rdsk/");
		device_namep = rdsk_startp + 6;
		(void) strncpy(block_slice_pathname,
			pathname, (rdsk_startp - pathname));
		block_slice_pathname[rdsk_startp - pathname] = '\0';
		(void) strcat(block_slice_pathname, "/dsk/");
		(void) strcat(block_slice_pathname, device_namep);
	} else if (S_ISBLK(statbuf.st_mode)) {
		(void) strcpy(block_slice_pathname, pathname);
		dsk_startp = strstr(pathname, "/dsk/");
		device_namep = dsk_startp + 5;
		(void) strncpy(raw_slice_pathname,
				pathname, (dsk_startp - pathname));
		raw_slice_pathname[dsk_startp - pathname] = '\0';
		(void) strcat(raw_slice_pathname, "/rdsk/");
		(void) strcat(raw_slice_pathname, device_namep);
	} else {
		warning(
			gettext(
			"rmdisk: %s not block or char device (mode 0x%x)\n"),
			pathname, statbuf.st_mode);
		return (FALSE);
	}
	pathname_length = strlen(block_slice_pathname);
	(void) strncpy(block_device_pathname,
			block_slice_pathname, (pathname_length - 2));
	block_device_pathname[pathname_length - 2] = '\0';
	pathname_length = strlen(raw_slice_pathname);
	(void) strncpy(raw_device_pathname,
			raw_slice_pathname, (pathname_length - 2));
	raw_device_pathname[pathname_length - 2] = '\0';

	private_datap = calloc(1, sizeof (struct rmdisk_priv));

	partition_number = 0;
	while (partition_number < V_NUMPAR) {
		(void) sprintf(pathname_buffer, S_PATH_FORMAT,
				raw_device_pathname, partition_number);
		private_datap->rmd_rawpath[S_TYPE][partition_number] =
			strdup(pathname_buffer);
		private_datap->rmd_fd[S_TYPE][partition_number] = -1;
		partition_number++;
	}
	private_datap->rmd_defpart[S_TYPE] = S_DEFAULT_PARTITION;

	if (fdisk_supported) {
		private_datap->rmd_fs_type = P_TYPE;
		private_datap->rmd_defpart[P_TYPE] = P_DEFAULT_PARTITION;
		(void) sprintf(pathname_buffer, P_PATH_FORMAT,
				block_device_pathname,
				P_DEFAULT_PARTITION);
		partition_number = 0;
		while (partition_number < V_NUMPAR) {
			(void) sprintf(pathname_buffer, P_PATH_FORMAT,
					raw_device_pathname, partition_number);
			private_datap->rmd_rawpath[P_TYPE][partition_number] =
				strdup(pathname_buffer);
			private_datap->rmd_fd[P_TYPE][partition_number] = -1;
			partition_number++;
		}
	} else {
		partition_number = 0;
		while (partition_number < V_NUMPAR) {
			private_datap->rmd_rawpath[P_TYPE][partition_number] =
				NULL;
			private_datap->rmd_fd[P_TYPE][partition_number] = -1;
			partition_number++;
		}

		private_datap->rmd_fs_type = S_TYPE;
	}

	fs_type = private_datap->rmd_fs_type;
	default_partition = private_datap->rmd_defpart[fs_type];
	devicep = dev_makedp(&rmdiskdevsw,
	    private_datap->rmd_rawpath[fs_type][default_partition]);
	if (devicep == NULL) {
		debug(1, "rmdisk_use: dev_makedp failed for %s\n",
		    private_datap->rmd_rawpath[fs_type][default_partition]);
		return (FALSE);
	}

	devicep->dp_priv = (void *)private_datap;
	devicep->dp_writeprot = FALSE;
	devicep->dp_symname = strdup(symname);
	devicep->dp_bvn = dev_dirpath(block_device_pathname);
	devicep->dp_rvn = dev_dirpath(raw_device_pathname);

	(void) mutex_init(&private_datap->rmd_killmutex, USYNC_THREAD, NULL);

	if (thr_create(0, THREAD_STACK_SIZE,
	    (void *(*)(void *))rmdisk_thread_wait, (void *)devicep, THR_BOUND,
	    (thread_t *)&(private_datap->rmd_tid)) < 0) {
		warning(gettext("rmdisk thread create failed; %m\n"));
		return (FALSE);
	}
	debug(6, "rmdisk_use: rmdisk_thread_wait id %d created\n",
			private_datap->rmd_tid);
	return (TRUE);
}


/*ARGSUSED*/
static void
rmdisk_devmap(vol_t *v, int part, int off)
{
	struct devs		*dp;
	struct rmdisk_priv	*rmdp;


	dp = dev_getdp(v->v_basedev);
	rmdp = (struct rmdisk_priv *)dp->dp_priv;

	debug(9, "rmdisk_devmap: part = '%d', offset = '%d'\n", part, off);

	if ((rmdp->rmd_fs_type == P_TYPE) && (v->v_fstype == V_SOLARIS)) {

		/*
		 * This handles the case in which there's a Solaris VTOC
		 * described by an fdisk table on an Intel system.
		 */

		v->v_devmap[off].dm_path =
			strdup(rmdp->rmd_rawpath[S_TYPE][part]);
	} else {

		/*
		 * return the path of the partition corresponding
		 * to the default file system type of the system
		 * (P_TYPE for Intel systems, S_TYPE for SPARC systems.)
		 */

		v->v_devmap[off].dm_path =
			strdup(rmdp->rmd_rawpath[rmdp->rmd_fs_type][part]);
	}

	debug(9, "rmdisk_devmap: returning (slice %d, off %d): \"%s\"\n",
	    part, off, v->v_devmap[off].dm_path);
}


static int
rmdisk_getfd(dev_t dev)
{
	struct devs		*dp;
	struct rmdisk_priv	*rmdp;
	int			fd;


	dp = dev_getdp(dev);
	ASSERT(dp != NULL);
	rmdp = (struct rmdisk_priv *)dp->dp_priv;
	if (fdisk_supported) {
		ASSERT(rmdp->rmd_fd[P_TYPE][rmdp->rmd_defpart[P_TYPE]] >= 0);
		fd = rmdp->rmd_fd[P_TYPE][rmdp->rmd_defpart[P_TYPE]];
	} else {
		ASSERT(rmdp->rmd_fd[S_TYPE][rmdp->rmd_defpart[S_TYPE]] >= 0);
		fd = rmdp->rmd_fd[S_TYPE][rmdp->rmd_defpart[S_TYPE]];

	}
	return (fd);
}


/*ARGSUSED*/
static bool_t
rmdisk_error(struct ve_error *vie)
{
	debug(1, "rmdisk_error\n");
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
rmdisk_close(char *path, dev_t rdev)
{
	int			default_partition;
	struct devs		*dp;
	int			fd;
	int			fs_type;
	int			partition;
	struct rmdisk_priv	*rmdp;
	struct	stat		sb;

	debug(1, "rmdisk_close %s\n", path);

	if (stat(path, &sb) < 0) {
		if (rdev == NODEV) {
			warning(gettext("rmdisk_close: %s; %m\n"), path);
			return;
		}
	} else {
		rdev = sb.st_rdev;
	}

	if ((dp = dev_search_dp(rdev)) == NULL) {
		debug(1, "rmdisk_close: %s not in use\n", path);
		return;
	}

	/*
	 * get our private data
	 */
	rmdp = (struct rmdisk_priv *)dp->dp_priv;

	/*
	 * take care of the listner thread
	 */
	(void) mutex_lock(&rmdp->rmd_killmutex);
	(void) thr_kill(rmdp->rmd_tid, SIGUSR1);
	(void) mutex_unlock(&rmdp->rmd_killmutex);
	(void) thr_join(rmdp->rmd_tid, 0, 0);
	debug(1, "rmdisk_close: thread id %d reaped (killed/joined)\n",
	    rmdp->rmd_tid);

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
		fs_type = rmdp->rmd_fs_type;
		default_partition = rmdp->rmd_defpart[rmdp->rmd_fs_type];
		fd = rmdp->rmd_fd[fs_type][default_partition];
		(void) ioctl(fd, DKIOCEJECT, 0);
	}

	/*
	 * clean up the names in the name space
	 */
	node_unlink(dp->dp_bvn);
	node_unlink(dp->dp_rvn);

	/*
	 * free the private data we've allocated
	 */
	for (fs_type = 0; fs_type < NUM_FS_TYPES; fs_type++) {
		for (partition = 0; partition < V_NUMPAR; partition++) {
			if (rmdp->rmd_fd[fs_type][partition] != -1) {
				(void) close(rmdp->rmd_fd[fs_type][partition]);
			}
			if (rmdp->rmd_rawpath[fs_type][partition]) {
				free(rmdp->rmd_rawpath[fs_type][partition]);
			}
		}
	}
	free(rmdp);

	/*
	 * free the dp, so no one points at us anymore
	 */
	free(dp->dp_symname);
	dev_freedp(dp);
}

static int
rmdisk_check(struct devs *dp)
/*
 * Wake up the device thread for a removable media disk drive.
 * See the floppy_check() method in dev_floppy.c to find the
 * general interface rules for <device>_check() methods and
 * an example of a <device>_check() method that checks for
 * previously undetected insertions of media into devices.
 * The rmdisk_check() method doesn't have to check for previously
 * undetected insertions of media because the rmdisk_thread_wait()
 * method continuously checks for insertions of media, and the
 * rmdisk_check() method wakes up the rmdisk_thread_wait() method.
 */
{
	int			fd;
	int			fs_type;
	struct rmdisk_priv	*rmdp;
	uchar_t			read_buffer[RMDISK_READ_SIZE];
	int			result;

	rmdp = (struct rmdisk_priv *)dp->dp_priv;
	fs_type = rmdp->rmd_fs_type;
	fd = rmdp->rmd_fd[fs_type][rmdp->rmd_defpart[fs_type]];

	if (read(fd, &read_buffer, RMDISK_READ_SIZE) == RMDISK_READ_SIZE) {
		result = 1;
	} else {
		result = 0;
	}
	return (result);
}

static bool_t
rmdisk_testpath(char *path)
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
		debug(5, "rmdisk(probing): stat of \"%s\"; %m\n", path);
		goto dun;
	}

	if ((dp = dev_search_dp(sb.st_rdev)) != NULL) {
		if (dp->dp_dsw == &rmdiskdevsw) {
			debug(5, "rmdisk(probing): %s already in use\n", path);
			return (TRUE);
		} else {
			debug(5, "rmdisk(probing): %s already managed by %s\n",
				path, dp->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	if ((rp = rawpath(path)) == NULL) {
		debug(5, "rmdisk(probing): can't get rawpath of \"%s\"\n",
		    path);
		goto dun;
	}
	debug(9, "Rawpath = %s\n", rp);

	/*
	 * if we can't open it, assume that it's because it's busy or
	 * something else is wrong
	 *
	 * in any event, dev_use couldn't open it either, so it's
	 * not worth trying to use the device
	 */
	if ((fd = open(rp, O_RDONLY|O_NONBLOCK|O_EXCL)) < 0) {
		debug(5, "rmdisk(probing): open of \"%s\"; %m\n", rp);
		goto dun;
	}

	/*
	 * check to make sure device is a SCSI or PCMCIA-ATA device
	 */

	if (ioctl(fd, DKIOCINFO, &dkc) < 0) {
		debug(5, "rmdisk(probing): DKIOCINFO on \"%s\" failed; %m\n",
		    rp);
		goto dun;
	}
	if ((dkc.dki_ctype != DKC_SCSI_CCS) &&
		(dkc.dki_ctype != DKC_PCMCIA_ATA)) {
		debug(5,
		"rmdisk(probing): \"%s\" not a SCSI or PCMCIA-ATA drive\n",
		rp);
		debug(5,
		"rmdisk(probing): (disk type %d or %d expected, %d found)\n",
		    DKC_SCSI_CCS, DKC_PCMCIA_ATA, dkc.dki_ctype);
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
	debug(9, "checking on %s, is it removable?\n", rp);
	if (ioctl(fd, DKIOCREMOVABLE, &removable) != 0) {
		debug(5,
		"rmdisk(probing): \"%s\" DKIOCREMOVABLE ioctl failed; %m\n",
		    rp);
		goto dun;
	}

	/*
	 * for now setting removable for know t# and c#
	 */

	if (removable == 0) {
		debug(5, "rmdisk(probing): device \"%s\" not removable\n",
		    rp);
		goto dun;
	}

	res = TRUE;
	debug(3, "rmdisk(probing): found removable (scsi?) drive at \"%s\"\n",
	    rp);

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

static bool_t
rmdisk_remount(vol_t *volumep)
{
	/*
	 * Find the new default file descriptor for
	 * a device after the medium inserted in it
	 * has been repartitioned.
	 */
	int			device_fd;
	struct rmdisk_priv	*device_privatep;
	struct devs		*devicep;
	int			reopen_result, basepart;
	bool_t			result;
	struct vtoc		vtoc;

	devicep = dev_getdp(volumep->v_device);
	device_privatep = (struct rmdisk_priv *)devicep->dp_priv;
	result = TRUE;

	/*
	 * The default file descriptor for fdisk-based file systems
	 * is always the P0 file descriptor, so there's no need to
	 * change it when the medium has been repartitioned.
	 */

	if (device_privatep->rmd_fs_type == S_TYPE) {
		device_fd = device_privatep->
			rmd_fd[S_TYPE][device_privatep->rmd_defpart[S_TYPE]];
		if (ioctl(device_fd, DKIOCGVTOC, &vtoc) == 0) {
			if ((basepart = vtoc_base_partition(&vtoc)) < 0)
				basepart = S_DEFAULT_PARTITION;
			device_privatep->rmd_defpart[S_TYPE] = basepart;

			debug(1, "rmdisk_remount: rmd_defpart now %d\n",
				    device_privatep->rmd_defpart[S_TYPE]);
		} else {
			debug(1, "rmdisk_remount: DKIOCGVTOC ioctl() failed\n");
			result = FALSE;
		}
	}
	/*
	 * Close and reopen the new default partition, and reset the
	 * medium's access permissions to the correct values.
	 */
	reopen_result = reopen_rmdisk(device_privatep);
	if (reopen_result == REOPEN_RO) {
		devicep->dp_writeprot = TRUE;
	} else if (reopen_result == REOPEN_RW) {
		devicep->dp_writeprot = FALSE;
	} else {
		result = FALSE;
	}
	return (result);
}

/*
 * Definitions of private methods
 */

static void
close_fds(struct rmdisk_priv *private_datap)
{
	/*
	 * close all the open fd's
	 */

	int partition_type;
	int partition_number;

	partition_type = 0;
	while (partition_type < NUM_FS_TYPES) {
		partition_number = 0;
		while (partition_number < V_NUMPAR) {
			if (private_datap->
				rmd_fd[partition_type][partition_number] >= 0) {

				(void) close(private_datap->
				rmd_fd[partition_type][partition_number]);

				private_datap->
				rmd_fd[partition_type][partition_number] = -1;
			}
			partition_number++;
		}
		partition_type++;
	}
}

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
	case DKIO_DEV_GONE:
		(void) sprintf(state_buf, "DKIO_DEV_GONE");
		break;
	default:
		(void) sprintf(state_buf, "?unknown? (%d)", (int)st);
		break;
	}

	return (state_buf);
}

static int
reopen_rmdisk(struct rmdisk_priv *rmdp)
{
	/*
	 * Close and reopen the default partition on a removable
	 * medium.
	 */

	int	count;
	int	defpart;
	int	fd;
	int	fs_type;
	char	*raw_path;
	int	result;

	fs_type = rmdp->rmd_fs_type;
	defpart = rmdp->rmd_defpart[fs_type];
	fd = rmdp->rmd_fd[fs_type][defpart];
	raw_path = rmdp->rmd_rawpath[fs_type][defpart];

	debug(2, "reopen_rmdisk: closing %s\n", raw_path);
	if ((result = close(fd)) == CANT_CLOSE) {
		debug(1, "reopen_rmdisk(): unable to close %s: %m\n", raw_path);
		result = CANT_REOPEN;
	} else {
		fd = open(raw_path, O_RDWR|O_EXCL);
		if (fd >= 0) {
			result = REOPEN_RW;
		} else if (errno == EROFS) {
			fd = open(raw_path, O_RDONLY|O_NDELAY|O_EXCL);
			if (fd >= 0) {
				result = REOPEN_RO;
			}
		} else {
			debug(1, "reopen_rmdisk: can't reopen %s; %m\n",
				raw_path);
		}

		/*
		 * The following sequence is a temporary workaround
		 * for a race condition in which a copy of rmmount
		 * has the default partition open while reopen_rmdisk()
		 * is trying to open it O_EXCL.  Remove the workaround
		 * when the root cause of the race condition is found
		 * and removed.
		 */
		count = 0;
		while ((fd < 0) && (count < 5)) {
			if (errno == EROFS) {
				fd = open(raw_path, O_RDONLY|O_NDELAY|O_EXCL);
				if (fd >= 0) {
					result = REOPEN_RO;
					break;
				}
			} else {
				fd = open(raw_path, O_RDWR|O_EXCL);
				if (fd >= 0) {
					result = REOPEN_RW;
					break;
				}
			}
			sleep(1);
			count++;
		}
		/*
		 * we could not open the device without O_NONBLOCK set.
		 * That may be caused because the medium is half corrupted,
		 * or completely unformatted. Try open with NONBLOCK as
		 * a final option.
		 */
		if (fd < 0) {
			fd = open(raw_path, O_RDWR|O_NDELAY|O_EXCL);
			if (fd >= 0)
				result = REOPEN_RW;
		}
		/*
		 * End of the temporary workaround for the race condition.
		 */

		if (fd < 0) {

		warning(gettext("reopen_rmdisk: can't reopen %s; %m\n"),
			raw_path);
			result = CANT_REOPEN;
		} else {
			debug(1, "reopen_rmdisk: reopened %s\n", raw_path);
			/*
			 * set close-on-exec
			 */
			(void) fcntl(fd, F_SETFD, 1);
		}
	}
	rmdp->rmd_fd[fs_type][defpart] = fd;
	return (result);
}

static void
rmdisk_thread_wait(struct devs *dp)
{
	extern cond_t		running_cv;
	extern mutex_t		running_mutex;
	extern void		vol_event(struct vioc_event *, struct devs *);
	extern int		vold_running;

	int			defpart;
	int			fd;
	bool_t			found;
	int			fs_type;
	int			partition_number;
	int			reopen_result;
	struct rmdisk_priv	*rmdp;
	enum dkio_state		rmdisk_state;
	struct vioc_event	vie;
	struct vtoc		vtoc;
	struct stat		st;
	struct async_task	*as;

	/*
	 * Ensure vold_main() is running before continuing.
	 */

	rmdp = (struct rmdisk_priv *)dp->dp_priv;
	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	dp->dp_writeprot = TRUE;

	if (fdisk_supported) {
		/*
		 * Check for P partitions first.
		 */
		partition_number = 0;
		while (partition_number < RMDMAX_FDISK_PARTITIONS) {
			/*
			 * Always open rdonly here, since the
			 * DKIOC_INSERTED state will cause a
			 * close/reopen.
			 */
			debug(1, "rmdisk_thread_wait: opening \"%s\" RDONLY\n",
				rmdp->rmd_rawpath[P_TYPE][partition_number]);
			fd = open(rmdp->rmd_rawpath[P_TYPE][partition_number],
				O_RDONLY|O_NONBLOCK|O_EXCL);
			if (fd < 0) {
				noise("rmdisk: open of \"%s\"; %m\n",
				    rmdp->
					rmd_rawpath[P_TYPE][partition_number]);
				close_fds(rmdp);
				return;
			}
			(void) fcntl(fd, F_SETFD, 1);	/* close-on-exec */
			rmdp->rmd_fd[P_TYPE][partition_number] = fd;
			(void) fstat(fd, &st);
			dp->dp_all_dev[dp->dp_ndev++] = st.st_rdev;
			partition_number++;
		}
	}
	partition_number = 0;
	while (partition_number < V_NUMPAR) {
		/*
		 * Always open rdonly here, since the DKIOC_INSERTED
		 * state will cause a close/reopen.
		 */
		debug(1, "rmdisk_thread_wait: opening \"%s\" RDONLY ...\n",
		    rmdp->rmd_rawpath[S_TYPE][partition_number]);
		if ((fd = open(rmdp->
			rmd_rawpath[S_TYPE][partition_number],
			O_RDONLY|O_NONBLOCK|O_EXCL)) < 0) {

			noise("rmdisk: open of \"%s\"; %m\n",
			    rmdp->rmd_rawpath[S_TYPE][partition_number]);
			close_fds(rmdp);
			return;
		}
		(void) fcntl(fd, F_SETFD, 1);	/* close-on-exec */
		rmdp->rmd_fd[S_TYPE][partition_number] = fd;
		(void) fstat(fd, &st);
		dp->dp_all_dev[dp->dp_ndev++] = st.st_rdev;
		partition_number++;
	}
	/*
	 * Get the vendor's device name (e.g. jaz, zip),
	 * and reset the device symbolic name to reflect it.
	 */

	fs_type = rmdp->rmd_fs_type;
	fd = rmdp->rmd_fd[fs_type][rmdp->rmd_defpart[fs_type]];

	if (dev_reset_symname(dp, fd) != 0) {
		debug(1, "rmdisk_thread_wait(): dev_reset_symname() failed\n");
		return;
	}

	/*
	 * DP_MEJECTABLE should be set for each drvices.
	 */
	if (dp->dp_dsw->d_flags & D_MEJECTABLE)
		dp->dp_flags |= DP_MEJECTABLE;

	debug(9, "rmdisk_thread_wait: pathname = '%s', symname = '%s'\n",
		rmdp->rmd_rawpath[fs_type][rmdp->rmd_defpart[fs_type]],
		dp->dp_symname);

	rmdisk_state = DKIO_NONE;

	for (;;) { /* loop until the thread is killed */

		defpart = rmdp->rmd_defpart[fs_type];
		fd = rmdp->rmd_fd[fs_type][defpart];
		if (fd < 0) {
			warning(gettext(
			"rmdisk_thread_wait: bad file descriptor for %s\n"),
				rmdp->rmd_rawpath[fs_type][defpart]);
			return;
		}
		debug(9, "rmdisk_thread_wait: fd = %d for %s\n",
			fd, rmdp->rmd_rawpath[fs_type][defpart]);
		debug(3,
		"rmdisk_thread_wait: ioctl(DKIOCSTATE) on \"%s\"\n",
		    rmdp->rmd_rawpath[fs_type][rmdp->rmd_defpart[fs_type]]);
		/*
		 * The following ioctl blocks until the device state changes.
		 */
		if (ioctl(fd, DKIOCSTATE, &rmdisk_state) < 0) {

			debug(1,
		"rmdisk_thread_wait: DKIOCSTATE of \"%s\"; %m\n",
		rmdp->rmd_rawpath[fs_type][rmdp->rmd_defpart[fs_type]]);
			if (errno == ENOTTY) {
				close_fds(rmdp);
				return;
			}
			(void) sleep(1);
			continue;
		}

		debug(5, "rmdisk_thread_wait: new state = \"%s\"\n",
		    dkiostate_to_str(rmdisk_state));

		if (rmdisk_state == DKIO_NONE) {
			/*
			 * No event has occurred.  Do nothing.
			 */
			continue;
		}
		if (rmdisk_state == DKIO_DEV_GONE) {
			/* device is gone */
			as = vold_malloc(sizeof (struct async_task));
			as->act = ASACT_DEV_CLOSE;
			as->data[0] = (uintptr_t)dp->dp_dev;
			async_taskq_insert(as);
			/*
			 * we don't bail out from the loop, because we
			 * will need to keep watching the device if device
			 * was busy, and we couldn't close the device.
			 */
			continue;
		}

		(void) memset(&vie, 0, sizeof (struct vioc_event));
		(void) mutex_lock(&rmdp->rmd_killmutex);

		if (rmdisk_state == DKIO_INSERTED) {

			/*
			 * If vold already knows there's a medium
			 * in the device, do nothing.
			 */
			if (dp->dp_vol != NULL) {
				(void) mutex_unlock(&rmdp->rmd_killmutex);
				continue;
			}
			/*
			 * Find the partition that starts at byte 0 on the
			 * medium and that maps the largest portion of the
			 * medium.
			 */
			if ((ioctl(fd, DKIOCGVTOC, &vtoc) == 0) &&
			    (fs_type == S_TYPE)) {
				int basepart = vtoc_base_partition(&vtoc);

				if (basepart < 0)
					basepart = S_DEFAULT_PARTITION;
				rmdp->rmd_defpart[S_TYPE] = basepart;
				debug(1,
				    "rmdisk_thread_wait: rmd_defpart now %d\n",

				    rmdp->rmd_defpart[S_TYPE]);
			}
			/*
			 * Reopen the base file descriptor just found
			 * and generate an insert event.  Note:
			 * the reopen is required to set the access
			 * permissions on the new file descriptor
			 * to those on the medium just inserted into
			 * the device.
			 */
			reopen_result = reopen_rmdisk(rmdp);
			if (reopen_result >= 0) {
				switch (reopen_result) {
				case 0:
					dp->dp_writeprot = FALSE;
					break;
				case 1:
					dp->dp_writeprot = TRUE;
					break;
				}
				vie.vie_type = VIE_INSERT;
				vie.vie_insert.viei_dev = dp->dp_dev;
				vol_event(&vie, dp);
			}
		}

		if (rmdisk_state == DKIO_EJECTED) {
			(void) mutex_lock(&vold_main_mutex);
			if (dp->dp_vol == NULL) {
				(void) mutex_unlock(&vold_main_mutex);
				(void) mutex_unlock(&rmdp->rmd_killmutex);
				continue;
			}
			found = FALSE;
			partition_number = 0;
			while ((partition_number < (int)(dp->dp_vol->v_ndev)) &&
				(found == FALSE)) {

				if (dp->dp_vol->
					v_devmap[partition_number].dm_realdev ==
						dp->dp_dev) {

					vie.vie_type = VIE_EJECT;
					vie.vie_eject.viej_force = TRUE;
					vie.vie_eject.viej_unit =
						minor(dp->dp_vol->v_devmap
						[partition_number].dm_voldev);
					vol_event(&vie, dp);
					found = TRUE;
				}
				partition_number++;
			}
			(void) mutex_unlock(&vold_main_mutex);
		}
		(void) mutex_unlock(&rmdp->rmd_killmutex);
	}

	/*
	 * got error. let vold_run close the device and reap this thread
	 */
	as = vold_malloc(sizeof (struct async_task));
	as->act = ASACT_DEV_CLOSE;
	as->data[0] = (uintptr_t)dp->dp_dev;
	async_taskq_insert(as);
}
