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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>

#define	LX_NAMEMAX	256

struct lx_old_dirent {
	long		d_ino;  /* not l_ino_t */
	long		d_off;
	ushort_t	d_reclen;
	char 		d_name[LX_NAMEMAX];
};

struct lx_dirent {
	long		d_ino;
	long		d_off;
	ushort_t	d_reclen;
	char 		d_name[LX_NAMEMAX];
	uchar_t		d_type;
};

/* base definition of linux_dirent from readdir.c - sizeof is 12 */
typedef struct {
	ulong_t		d_ino;
	ulong_t		d_off;
	ushort_t	d_reclen;
	char		d_name[1];
} lx_linux_dirent_t;

#define	LX_RECLEN(namelen)	\
	((offsetof(struct lx_dirent, d_name) + 1 + (namelen) + 7) & ~7)

struct lx_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	ushort_t	d_reclen;
	uchar_t		d_type;
	char		d_name[LX_NAMEMAX];
};

#define	LX_RECLEN64(namelen)	\
	((offsetof(struct lx_dirent64, d_name) + 1 + (namelen) + 7) & ~7)

/*
 * Read in one dirent structure from fd into dirp.
 * p3 (count) is ignored.
 */
/*ARGSUSED*/
long
lx_readdir(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int fd = (int)p1;
	struct lx_old_dirent *dirp = (struct lx_old_dirent *)p2;
	uint_t count = sizeof (struct lx_old_dirent);
	int rc = 0;
	struct lx_old_dirent _ld;
	struct dirent *sd = (struct dirent *)&_ld;

	/*
	 * The return value from getdents is not applicable, as
	 * it might have squeezed more than one dirent in the buffer
	 * we provided.
	 *
	 * getdents() will deal with the case of dirp == NULL
	 */
	if ((rc = getdents(fd, sd, count)) < 0)
		return (-errno);

	/*
	 * Set rc 1 (pass), or 0 (end of directory).
	 */
	rc = (sd->d_reclen == 0) ? 0 : 1;

	if (uucopy(sd, dirp, count) != 0)
		return (-errno);

	return (rc);
}

/*
 * Read in dirent structures from p1 (fd) into p2 (buffer).
 * p3 (count) is the size of the memory area.
 */
long
lx_getdents(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int fd = (int)p1;
	void *buf = (void *)p2;
	void *sbuf, *lbuf;
	int lbufsz = (uint_t)p3;
	int sbufsz;
	int namelen;
	struct dirent *sd;
	struct lx_dirent *ld;
	int bytes, rc;

	/*
	 * readdir will pass in the full size, but some test code calls getdents
	 * directly and uses the bare struct. For these, just pretend we got
	 * a single full-size entry so we can obtain the proper errno.
	 */
	if (lbufsz == sizeof (lx_linux_dirent_t))
		lbufsz = sizeof (struct lx_dirent);

	if (lbufsz < sizeof (struct lx_dirent))
		return (-EINVAL);

	/*
	 * The Linux dirent is bigger than the Solaris dirent.  To
	 * avoid inadvertently consuming more of the directory than we can
	 * pass back to the Linux app, we hand the kernel a smaller buffer
	 * than the app handed us.
	 */
	sbufsz = (lbufsz / 32) * 24;

	sbuf = SAFE_ALLOCA(sbufsz);
	lbuf = SAFE_ALLOCA(lbufsz);
	if (sbuf == NULL || lbuf == NULL)
		return (-ENOMEM);

	if ((bytes = getdents(fd, sbuf, sbufsz)) < 0)
		return (-errno);

	/* munge the Solaris buffer to a linux buffer. */
	sd = (struct dirent *)sbuf;
	ld = (struct lx_dirent *)lbuf;
	rc = 0;
	while (bytes > 0) {
		namelen = strlen(sd->d_name);
		if (namelen >= LX_NAMEMAX)
			namelen = LX_NAMEMAX - 1;
		ld->d_ino = (uint64_t)sd->d_ino;
		ld->d_off = (int64_t)sd->d_off;
		ld->d_type = 0;

		(void) strncpy(ld->d_name, sd->d_name, namelen);
		ld->d_name[namelen] = 0;
		ld->d_reclen = (ushort_t)LX_RECLEN(namelen);

		bytes -= (int)sd->d_reclen;
		rc += (int)ld->d_reclen;

		sd = (struct dirent *)(void *)((caddr_t)sd + sd->d_reclen);
		ld = (struct lx_dirent *)(void *)((caddr_t)ld + ld->d_reclen);
	}

	/* now copy the lbuf to the userland buffer */
	assert(rc <= lbufsz);
	if (uucopy(lbuf, buf, rc) != 0)
		return (-EFAULT);

	return (rc);
}

/*
 * Read in dirent64 structures from p1 (fd) into p2 (buffer).
 * p3 (count) is the size of the memory area.
 */
long
lx_getdents64(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int fd = (uint_t)p1;
	void *buf = (void *)p2;
	void *sbuf, *lbuf;
	int lbufsz = (uint_t)p3;
	int sbufsz;
	int namelen;
	struct dirent *sd;
	struct lx_dirent64 *ld;
	int bytes, rc;

	if (lbufsz < sizeof (struct lx_dirent64))
		return (-EINVAL);

	/*
	 * The Linux dirent64 is bigger than the Solaris dirent64.  To
	 * avoid inadvertently consuming more of the directory than we can
	 * pass back to the Linux app, we hand the kernel a smaller buffer
	 * than the app handed us.
	 */
	sbufsz = (lbufsz / 32) * 24;

	sbuf = SAFE_ALLOCA(sbufsz);
	lbuf = SAFE_ALLOCA(lbufsz);
	if (sbuf == NULL || lbuf == NULL)
		return (-ENOMEM);

	if ((bytes = getdents(fd, sbuf, sbufsz)) < 0)
		return (-errno);

	/* munge the Solaris buffer to a linux buffer. */
	sd = (struct dirent *)sbuf;
	ld = (struct lx_dirent64 *)lbuf;
	rc = 0;
	while (bytes > 0) {
		namelen = strlen(sd->d_name);
		if (namelen >= LX_NAMEMAX)
			namelen = LX_NAMEMAX - 1;
		ld->d_ino = (uint64_t)sd->d_ino;
		ld->d_off = (int64_t)sd->d_off;
		ld->d_type = 0;

		(void) strncpy(ld->d_name, sd->d_name, namelen);
		ld->d_name[namelen] = 0;
		ld->d_reclen = (ushort_t)LX_RECLEN64(namelen);

		bytes -= (int)sd->d_reclen;
		rc += (int)ld->d_reclen;

		sd = (struct dirent *)(void *)((caddr_t)sd + sd->d_reclen);
		ld = (struct lx_dirent64 *)(void *)((caddr_t)ld + ld->d_reclen);
	}

	/* now copy the lbuf to the userland buffer */
	assert(rc <= lbufsz);
	if (uucopy(lbuf, buf, rc) != 0)
		return (-EFAULT);

	return (rc);
}
