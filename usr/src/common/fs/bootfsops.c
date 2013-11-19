/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

#include <sys/bootconf.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/sysmacros.h>
#include <sys/bootvfs.h>
#include <sys/bootinfo.h>
#include <sys/filep.h>

#ifdef	_BOOT
#include "../common/util.h"
#else
#include <sys/sunddi.h>
#endif

#define	MAX_FILES	MAX_BOOT_MODULES
#define	MAX_FDS		256

extern void *bkmem_alloc(size_t);
extern void bkmem_free(void *, size_t);

/*
 * TODO: Replace these declarations with inclusion of the ordinary userland
 * bootfs headers once they're available.
 */
typedef struct bfile {
	char bf_name[MAXPATHLEN];
	caddr_t bf_addr;
	size_t bf_size;
	struct bfile *bf_next;
	uint64_t bf_ino;
} bfile_t;

typedef struct bf_fd {
	bfile_t *fd_file;
	off_t fd_pos;
} bf_fd_t;

static bfile_t *head;
static uint_t init_done;
static bf_fd_t fds[MAX_FDS];

static char cpath[MAXPATHLEN];	/* For canonicalising filenames */

static void bbootfs_closeall(int);

static void
canonicalise(const char *fn, char *out)
{
	const char *p;
	char *q, *s;
	char *last;
	char *oc;
	int is_slash = 0;
	static char scratch[MAXPATHLEN];

	if (fn == NULL) {
		*out = '\0';
		return;
	}

	/*
	 * Remove leading slashes and condense all multiple slashes into one.
	 */
	p = fn;
	while (*p == '/')
		++p;

	for (q = scratch; *p != '\0'; p++) {
		if (*p == '/' && !is_slash) {
			*q++ = '/';
			is_slash = 1;
		} else if (*p != '/') {
			*q++ = *p;
			is_slash = 0;
		}
	}
	*q = '\0';

	if (strncmp(scratch, "system/boot/", 12) == 0 ||
	    strcmp(scratch, "system/boot") == 0) {
		s = scratch + 12;
	} else {
		s = scratch;
	}

	for (last = strsep(&s, "/"), q = oc = out; last != NULL;
	    last = strsep(&s, "/")) {
		if (strcmp(last, ".") == 0)
			continue;
		if (strcmp(last, "..") == 0) {
			for (oc = q; oc > out && *oc != '/'; oc--)
				;
			q = oc;
			continue;
		}
		if (q > out)
			*q++ = '/';
		q += snprintf(q, MAXPATHLEN - (q - out), "%s", last);
	}

	*q = '\0';
}

/* ARGSUSED */
static int
bbootfs_mountroot(char *str)
{
	return (-1);
}

static int
bbootfs_unmountroot(void)
{
	return (-1);
}

static int
bbootfs_init(void)
{
	bfile_t *fp;
	char propname[32];
	uint64_t propval;
	uint_t i;

	for (i = 0; i < MAX_FILES; i++) {
		(void) snprintf(propname, sizeof (propname),
		    "module-name-%u", i);
		if (do_bsys_getproplen(NULL, propname) < 0)
			break;

		if ((fp = bkmem_alloc(sizeof (bfile_t))) == NULL) {
			bbootfs_closeall(1);
			return (-1);
		}

		(void) do_bsys_getprop(NULL, propname, cpath);
		canonicalise(cpath, fp->bf_name);

		(void) snprintf(propname, sizeof (propname),
		    "module-addr-%u", i);
		if (do_bsys_getproplen(NULL, propname) != sizeof (uint64_t)) {
			bkmem_free(fp, sizeof (bfile_t));
			continue;
		}
		(void) do_bsys_getprop(NULL, propname, &propval);
		fp->bf_addr = (void *)(uintptr_t)propval;

		(void) snprintf(propname, sizeof (propname),
		    "module-size-%u", i);
		if (do_bsys_getproplen(NULL, propname) != sizeof (uint64_t)) {
			bkmem_free(fp, sizeof (bfile_t));
			continue;
		}
		(void) do_bsys_getprop(NULL, propname, &propval);
		fp->bf_size = (size_t)propval;
		fp->bf_ino = i;

		fp->bf_next = head;
		head = fp;
	}

	return (0);
}

/*ARGSUSED*/
static int
bbootfs_open(char *fn, int flags)
{
	uint_t i;
	bfile_t *fp;

	if (!init_done) {
		if (bbootfs_init() != 0)
			return (-1);

		init_done = 1;
	}

	canonicalise(fn, cpath);

	for (fp = head; fp != NULL; fp = fp->bf_next) {
		if (strcmp(fp->bf_name, cpath) == 0)
			break;
	}

	if (fp == NULL)
		return (-1);

	for (i = 0; i < MAX_FDS; i++) {
		if (fds[i].fd_file == NULL) {
			fds[i].fd_file = fp;
			fds[i].fd_pos = 0;
			return (i);
		}
	}

	return (-1);
}

static int
bbootfs_close(int fd)
{
	if (fds[fd].fd_file == NULL)
		return (-1);

	fds[fd].fd_file = NULL;
	fds[fd].fd_pos = 0;

	return (0);
}

static ssize_t
bbootfs_read(int fd, caddr_t buf, size_t size)
{
	ssize_t len;
	bf_fd_t *fdp = &fds[fd];

	if (fdp->fd_file == NULL)
		return (-1);

	if (fdp->fd_pos >= fdp->fd_file->bf_size)
		return (-1);

	if (fdp->fd_pos + size > fdp->fd_file->bf_size)
		len = fdp->fd_file->bf_size - fdp->fd_pos;
	else
		len = size;

	bcopy(fdp->fd_file->bf_addr + fdp->fd_pos, buf, len);

	fdp->fd_pos += len;

	return (len);
}

static off_t
bbootfs_lseek(int fd, off_t addr, int whence)
{
	bf_fd_t *fdp = &fds[fd];

	if (fdp->fd_file == NULL)
		return (-1);

	switch (whence) {
	case SEEK_CUR:
		fdp->fd_pos += addr;
		break;
	case SEEK_SET:
		fdp->fd_pos = addr;
		break;
	case SEEK_END:
		fdp->fd_pos = fdp->fd_file->bf_size;
		break;
	default:
		return (-1);
	}

	return (0);
}

static int
bbootfs_fstat(int fd, struct bootstat *bsp)
{
	bf_fd_t *fdp = &fds[fd];

	if (fdp->fd_file == NULL)
		return (-1);

	bsp->st_dev = 1;
	bsp->st_ino = fdp->fd_file->bf_ino;
	bsp->st_mode = 0444;
	bsp->st_nlink = 1;
	bsp->st_uid = bsp->st_gid = 0;
	bsp->st_rdev = 0;
	bsp->st_size = fdp->fd_file->bf_size;
	bsp->st_blksize = 1;
	bsp->st_blocks = fdp->fd_file->bf_size;
	(void) strcpy(bsp->st_fstype, "bootfs");

	return (0);
}

/* ARGSUSED */
static void
bbootfs_closeall(int flag)
{
	bfile_t *fp;

	while (head != NULL) {
		fp = head;
		head = head->bf_next;

		bkmem_free(fp, sizeof (bfile_t));
	}

	init_done = 0;
}

struct boot_fs_ops bbootfs_ops = {
	"bootfs",
	bbootfs_mountroot,
	bbootfs_unmountroot,
	bbootfs_open,
	bbootfs_close,
	bbootfs_read,
	bbootfs_lseek,
	bbootfs_fstat,
	bbootfs_closeall,
	NULL
};
