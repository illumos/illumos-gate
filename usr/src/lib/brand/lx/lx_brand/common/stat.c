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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * when a stat() is done for a non-device file, the devt returned
 * via the stat is the devt of the device backing the filesystem which
 * contains the file the stat was performed on.  these devts are currently
 * untranslated.  if this turns out to cause problems in the future then
 * we might want to add more devt translators to convert sd and cmdk
 * devts into linux devts that normally represent disks.
 *
 * XXX this may not be the best place to have the devt translation code.
 * devt translation will also be needed for /proc fs support, which will
 * probably be done in the kernel.  we may need to move this code into
 * the kernel and add a brand syscall to do the translation for us.  this
 * will need to be worked out before putback.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <libintl.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/lx_types.h>
#include <sys/lx_stat.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_ptm.h>
#include <sys/lx_audio.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_syscall.h>
#include <sys/lx_debug.h>
#include <sys/modctl.h>

/* define _KERNEL to get the devt manipulation macros */
#define	_KERNEL
#include <sys/sysmacros.h>
#undef	_KERNEL


#define	LX_PTS_MAJOR_MIN	136
#define	LX_PTS_MAJOR_MAX	143
#define	LX_PTS_MAX		\
	((LX_PTS_MAJOR_MAX - LX_PTS_MAJOR_MIN + 1) * LX_MINORMASK)

#define	LX_PTM_MAJOR		5
#define	LX_PTM_MINOR		2

/* values for dt_type */
#define	DTT_INVALID	0
#define	DTT_LIST	1
#define	DTT_CUSTOM	2

/* convience macros for access the dt_minor union */
#define	dt_list		dt_minor.dtm_list
#define	dt_custom	dt_minor.dtm_custom

/*
 * structure used to define devt translators
 */
typedef struct minor_translator {
	char	*mt_path;	/* solaris minor node path */
	minor_t	mt_minor;	/* solaris minor node number */
	int	mt_lx_major;	/* linux major node number */
	int	mt_lx_minor;	/* linux minor node number */
} minor_translator_t;

typedef struct devt_translator {
	char				*dt_driver; /* solaris driver name */
	major_t				dt_major; /* solaris driver number */

	/* dt_type dictates how we intrepret dt_minor */
	int				dt_type;
	union {
		uintptr_t		dtm_foo; /* required to compile */
		minor_translator_t	*dtm_list;
		int			(*dtm_custom)(dev_t, lx_dev_t *, int);
	} dt_minor;
} devt_translator_t;


/*
 * forward declerations
 */
static devt_translator_t devt_translators[];

/*
 * called to initialize the devt translation subsystem
 */
int
lx_stat_init()
{
	minor_translator_t	*mt;
	struct stat		st;
	major_t			major;
	char			*driver;
	int			i, j, ret;

	for (i = 0; devt_translators[i].dt_driver != NULL; i++) {

		assert(devt_translators[i].dt_type != DTT_INVALID);

		/* figure out the major numbers for our devt translators */
		driver = devt_translators[i].dt_driver;
		ret = modctl(MODGETMAJBIND,
		    driver, strlen(driver) + 1, &major);
		if (ret != 0) {
			lx_err("lx_stat_init(): modctl(MODGETMAJBIND, %s) "
			    "failed: %s\n", driver, strerror(errno));
			lx_err("lx_stat_init(): devt translator disabled "
			    "for: %s\n", driver);
			devt_translators[i].dt_major = (major_t)-1;
			continue;
		}

		/* save the major node value */
		devt_translators[i].dt_major = major;

		/* if this translator doesn't use a list mapping we're done. */
		if (devt_translators[i].dt_type != DTT_LIST)
			continue;

		/* for each device listed, lookup the minor node number */
		mt = devt_translators[i].dt_list;
		for (j = 0; mt[j].mt_path != NULL; j++) {

			/* stat the device */
			ret = stat(mt[j].mt_path, &st);
			if (ret != 0) {
				lx_err("lx_stat_init(): stat(%s) failed: %s\n",
				    mt[j].mt_path, strerror(errno));
				lx_err("lx_stat_init(): devt translator "
				    "disabled for: %s\n", mt[j].mt_path);
				st.st_rdev = NODEV;
			} else {
				/* make sure the major node matches */
				assert(getmajor(st.st_rdev) == major);
				assert(mt[j].mt_minor < LX_MINORMASK);
			}

			/* save the minor node value */
			mt[j].mt_minor = getminor(st.st_rdev);
		}
	}
	return (0);
}

static int
/*ARGSUSED*/
pts_devt_translator(dev_t dev, lx_dev_t *jdev, int fd)
{
	minor_t	min = getminor(dev);
	int	lx_maj;
	int	lx_min;

	/*
	 * linux has a really small minor number name space (8 bits).
	 * so if pts devices are limited to one major number you could
	 * only have 256 of them.  linux addresses this issue by using
	 * multiple major numbers for pts devices.
	 */
	if (min >= LX_PTS_MAX)
		return (EOVERFLOW);

	lx_maj = LX_PTS_MAJOR_MIN + (min / LX_MINORMASK);
	lx_min = min % LX_MINORMASK;

	*jdev = LX_MAKEDEVICE(lx_maj, lx_min);
	return (0);
}


static int
/*ARGSUSED*/
ptm_devt_translator(dev_t dev, lx_dev_t *jdev, int fd)
{
	*jdev = LX_MAKEDEVICE(LX_PTM_MAJOR, LX_PTM_MINOR);
	return (0);
}

static int
audio_devt_translator(dev_t dev, lx_dev_t *jdev, int fd)
{
	int s_minor, l_minor;

	if (fd == -1) {
		s_minor = getminor(dev);
	} else {
		/*
		 * this is a cloning device so we have to ask the driver
		 * what kind of minor node this is
		 */
		if (ioctl(fd, LXA_IOC_GETMINORNUM, &s_minor) < 0)
			return (-EINVAL);
	}

	switch (s_minor) {
	case LXA_MINORNUM_DSP:
		l_minor = 3;
		break;
	case LXA_MINORNUM_MIXER:
		l_minor = 0;
		break;
	default:
		return (-EINVAL);
	}

	*jdev = LX_MAKEDEVICE(14, l_minor);
	return (0);
}

static void
s2l_dev_report(dev_t dev, lx_dev_t jdev)
{
	major_t			maj;
	minor_t			min;
	int			lx_maj, lx_min;

	if (!LX_DEBUG_ISENABLED)
		return;

	maj = getmajor(dev);
	min = getminor(dev);

	lx_maj = LX_GETMAJOR(jdev);
	lx_min = LX_GETMINOR(jdev);

	lx_debug("\ttranslated devt [%d, %d] -> [%d, %d]",
	    maj, min, lx_maj, lx_min);
}

static int
s2l_devt(dev_t dev, lx_dev_t *jdev, int fd)
{
	minor_translator_t	*mt;
	int			i, j, err;
	major_t			maj = getmajor(dev);
	minor_t			min = getminor(dev);

	/* look for a devt translator for this major number */
	for (i = 0; devt_translators[i].dt_driver != NULL; i++) {
		if (devt_translators[i].dt_major == maj)
			break;
	}
	if (devt_translators[i].dt_driver != NULL) {

		/* try to translate the solaris devt to a linux devt */
		switch (devt_translators[i].dt_type) {
		case DTT_LIST:
			mt = devt_translators[i].dt_list;
			for (j = 0; mt[j].mt_path != NULL; j++) {
				if (mt[j].mt_minor == min) {
					assert(mt[j].mt_minor < LX_MINORMASK);

					/* found a translation */
					*jdev = LX_MAKEDEVICE(
					    mt[j].mt_lx_major,
					    mt[j].mt_lx_minor);
					s2l_dev_report(dev, *jdev);
					return (0);
				}
			}
			break;

		case DTT_CUSTOM:
			err = devt_translators[i].dt_custom(dev, jdev, fd);
			if (err == 0)
				s2l_dev_report(dev, *jdev);
			return (err);
			break;
		}
	}

	/* we don't have a translator for this device */
	*jdev = LX_MAKEDEVICE(maj, min);
	return (0);
}

static int
stat_convert(uintptr_t lx_statp, struct stat *s, int fd)
{
	struct lx_stat	buf;
	lx_dev_t	st_dev, st_rdev;
	int		err;

	if ((err = s2l_devt(s->st_dev, &st_dev, fd)) != 0)
		return (err);
	if ((err = s2l_devt(s->st_rdev, &st_rdev, fd)) != 0)
		return (err);

	if ((st_dev > USHRT_MAX) || (st_rdev > USHRT_MAX) ||
	    (s->st_nlink  > USHRT_MAX) || (s->st_size > LONG_MAX))
		return (-EOVERFLOW);

	/* Linux seems to report a 0 st_size for all block devices */
	if ((s->st_mode & S_IFMT) == S_IFBLK)
		s->st_size = 0;

	bzero(&buf, sizeof (buf));
	buf.st_dev = st_dev;
	buf.st_rdev = st_rdev;
	buf.st_ino = (lx_ino_t)s->st_ino;
	buf.st_mode = s->st_mode;
	buf.st_nlink = s->st_nlink;
	buf.st_uid = LX_UID32_TO_UID16(s->st_uid);
	buf.st_gid = LX_GID32_TO_GID16(s->st_gid);
	buf.st_size = (lx_off_t)s->st_size;
	buf.st_blksize = (lx_blksize_t)s->st_blksize;
	buf.st_blocks = s->st_blocks;
	buf.st_atime.ts_sec = s->st_atim.tv_sec;
	buf.st_atime.ts_nsec = s->st_atim.tv_nsec;
	buf.st_ctime.ts_sec = s->st_ctim.tv_sec;
	buf.st_ctime.ts_nsec = s->st_ctim.tv_nsec;
	buf.st_mtime.ts_sec = s->st_mtim.tv_sec;
	buf.st_mtime.ts_nsec = s->st_mtim.tv_nsec;

	if (uucopy(&buf, (void *)lx_statp, sizeof (buf)) != 0)
		return (-errno);

	return (0);
}

static int
stat64_convert(uintptr_t lx_statp, struct stat64 *s, int fd)
{
	struct lx_stat64	buf;
	lx_dev_t		st_dev, st_rdev;
	int			err;

	if ((err = s2l_devt(s->st_dev, &st_dev, fd)) != 0)
		return (err);
	if ((err = s2l_devt(s->st_rdev, &st_rdev, fd)) != 0)
		return (err);

	/* Linux seems to report a 0 st_size for all block devices */
	if ((s->st_mode & S_IFMT) == S_IFBLK)
		s->st_size = 0;

	bzero(&buf, sizeof (buf));
	buf.st_dev = st_dev;
	buf.st_rdev = st_rdev;
#if defined(_ILP32)
	buf.st_small_ino = (lx_ino_t)(s->st_ino & UINT_MAX);
#endif
	buf.st_ino = (lx_ino64_t)s->st_ino;
	buf.st_mode = s->st_mode;
	buf.st_nlink = s->st_nlink;
	buf.st_uid = s->st_uid;
	buf.st_gid = s->st_gid;
	buf.st_size = s->st_size;
	buf.st_blksize = s->st_blksize;
	buf.st_blocks = s->st_blocks;
	buf.st_atime.ts_sec = s->st_atim.tv_sec;
	buf.st_atime.ts_nsec = s->st_atim.tv_nsec;
	buf.st_ctime.ts_sec = s->st_ctim.tv_sec;
	buf.st_ctime.ts_nsec = s->st_ctim.tv_nsec;
	buf.st_mtime.ts_sec = s->st_mtim.tv_sec;
	buf.st_mtime.ts_nsec = s->st_mtim.tv_nsec;

	if (uucopy(&buf, (void *)lx_statp, sizeof (buf)) != 0)
		return (-errno);

	return (0);
}

long
lx_stat(uintptr_t p1, uintptr_t p2)
{
	char		*path = (char *)p1;
	struct stat	sbuf;

	lx_debug("\tstat(%s, ...)", path);
	if (stat(path, &sbuf))
		return (-errno);

	return (stat_convert(p2, &sbuf, -1));
}


long
lx_fstat(uintptr_t p1, uintptr_t p2)
{
	int		fd = (int)p1;
	struct stat	sbuf;
	char		*path, path_buf[MAXPATHLEN];

	if (LX_DEBUG_ISENABLED) {
		path = lx_fd_to_path(fd, path_buf, sizeof (path_buf));
		if (path == NULL)
			path = "?";

		lx_debug("\tfstat(%d - %s, ...)", fd, path);
	}
	if (fstat(fd, &sbuf))
		return (-errno);

	return (stat_convert(p2, &sbuf, fd));
}


long
lx_lstat(uintptr_t p1, uintptr_t p2)
{
	char		*path = (char *)p1;
	struct stat	sbuf;

	lx_debug("\tlstat(%s, ...)", path);
	if (lstat(path, &sbuf))
		return (-errno);

	return (stat_convert(p2, &sbuf, -1));
}

long
lx_stat64(uintptr_t p1, uintptr_t p2)
{
	char			*path = (char *)p1;
	struct stat64		sbuf;

	lx_debug("\tstat64(%s, ...)", path);
	if (stat64(path, &sbuf))
		return (-errno);

	return (stat64_convert(p2, &sbuf, -1));
}


long
lx_fstat64(uintptr_t p1, uintptr_t p2)
{
	int			fd = (int)p1;
	struct stat64		sbuf;
	char			*path, path_buf[MAXPATHLEN];

	if (lx_debug_enabled != 0) {
		path = lx_fd_to_path(fd, path_buf, sizeof (path_buf));
		if (path == NULL)
			path = "?";

		lx_debug("\tfstat64(%d - %s, ...)", fd, path);
	}
	if (fstat64(fd, &sbuf))
		return (-errno);

	return (stat64_convert(p2, &sbuf, fd));
}

long
lx_fstatat64(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int atfd = (int)p1;
	const char *path = (const char *)p2;
	int flag;
	struct stat64 sbuf;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	flag = ltos_at_flag(p4, AT_SYMLINK_NOFOLLOW, B_TRUE);
	if (flag < 0)
		return (-EINVAL);

	if (fstatat64(atfd, path, &sbuf, flag))
		return (-errno);

	return (stat64_convert(p3, &sbuf, -1));
}


long
lx_lstat64(uintptr_t p1, uintptr_t p2)
{
	char			*path = (char *)p1;
	struct stat64		sbuf;

	lx_debug("\tlstat64(%s, ...)", path);
	if (lstat64(path, &sbuf))
		return (-errno);

	return (stat64_convert(p2, &sbuf, -1));
}

/*
 * devt translator definitions
 */
#define	MINOR_TRANSLATOR(path, lx_major, lx_minor)	\
	{ path, 0, lx_major, lx_minor }

#define	MINOR_TRANSLATOR_END				\
	{ NULL, 0, 0, 0 }

#define	DEVT_TRANSLATOR(drv, flags, i)		\
	{ drv, 0, flags, (uintptr_t)i }

/*
 * translators for devts
 */
static minor_translator_t mtranslator_mm[] = {
	MINOR_TRANSLATOR("/dev/null", 1, 3),
	MINOR_TRANSLATOR("/dev/zero", 1, 5),
	MINOR_TRANSLATOR_END
};
static minor_translator_t mtranslator_random[] = {
	MINOR_TRANSLATOR("/dev/random", 1, 8),
	MINOR_TRANSLATOR("/dev/urandom", 1, 9),
	MINOR_TRANSLATOR_END
};
static minor_translator_t mtranslator_sy[] = {
	MINOR_TRANSLATOR("/dev/tty", 5, 0),
	MINOR_TRANSLATOR_END
};
static minor_translator_t mtranslator_zcons[] = {
	MINOR_TRANSLATOR("/dev/console", 5, 1),
	MINOR_TRANSLATOR_END
};
static devt_translator_t devt_translators[] = {
	DEVT_TRANSLATOR("mm",		DTT_LIST,	&mtranslator_mm),
	DEVT_TRANSLATOR("random",	DTT_LIST,	&mtranslator_random),
	DEVT_TRANSLATOR("sy",		DTT_LIST,	&mtranslator_sy),
	DEVT_TRANSLATOR("zcons",	DTT_LIST,	&mtranslator_zcons),
	DEVT_TRANSLATOR(LX_AUDIO_DRV,	DTT_CUSTOM,	audio_devt_translator),
	DEVT_TRANSLATOR(LX_PTM_DRV,	DTT_CUSTOM,	ptm_devt_translator),
	DEVT_TRANSLATOR("pts",		DTT_CUSTOM,	pts_devt_translator),
	DEVT_TRANSLATOR(NULL,		0,		0)
};
