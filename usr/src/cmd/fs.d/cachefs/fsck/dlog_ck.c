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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>

/* forward references */
static int create_mapfile(char *fname, int size);

int
dlog_ck(char *dir_path, ino64_t *maxlocalfilenop)
{
	int err;
	int n;
	char dlog_path[MAXPATHLEN];
	char dmap_path[MAXPATHLEN];
	struct stat64 statinfo;
	int fd;
	int dlog_version;
	off_t offset;
	struct cfs_dlog_entry buf;
	int max_seq_num;
	int ent_count = 0;
	ino64_t fileno, maxlocalfileno;

	if (maxlocalfilenop)
		*maxlocalfilenop = 0LL;

	n = strlen(dir_path) + strlen(CACHEFS_DLOG_FILE) + 2;
	if (n > MAXPATHLEN) {
		pr_err(gettext("%s/%s: path too long"),
		    dir_path, CACHEFS_DLOG_FILE);
		return (-1);
	}
	sprintf(dlog_path, "%s/%s", dir_path, CACHEFS_DLOG_FILE);

	n = strlen(dir_path) + strlen(CACHEFS_DMAP_FILE) + 2;
	if (n > MAXPATHLEN) {
		pr_err(gettext("%s/%s: path too long"),
		    dir_path, CACHEFS_DMAP_FILE);
		return (-1);
	}
	sprintf(dmap_path, "%s/%s", dir_path, CACHEFS_DMAP_FILE);

	err = lstat64(dlog_path, &statinfo);
	if (err < 0) {
		if (errno == ENOENT)
			(void) unlink(dmap_path);
		/*
		 * No disconnect log(dlog) file exists to check
		 */
		return (0);
	}

	/* this file will be <2GB */
	fd = open(dlog_path, O_RDWR);
	if (fd < 0) {
		pr_err(gettext("can't open %s"), dlog_path);
		return (-2);
	}
	err = read(fd, &dlog_version, sizeof (dlog_version));
	if (err != sizeof (dlog_version)) {
		pr_err(gettext("can't read %s"), dlog_path);
		(void) close(fd);
		return (-3);
	}
	if (dlog_version != CFS_DLOG_VERSION) {
		pr_err(gettext(
		    "unknown version number in %s"), dlog_path);
		(void) close(fd);
		return (-4);
	}

	offset = sizeof (dlog_version);
	max_seq_num = 0;
	maxlocalfileno = 0LL;
	while (offset < (off_t)statinfo.st_size) {
		err = (int) lseek(fd, offset, SEEK_SET);
		if (err == -1) {
			pr_err(gettext("can't lseek %s"), dlog_path);
			(void) close(fd);
			return (-5);
		}

		err = read(fd, &buf, sizeof (buf));
		if (err < 0) {
			pr_err(gettext("can't read %s"), dlog_path);
			(void) close(fd);
			return (-6);
		}
		++ent_count;
		if (buf.dl_op ==  CFS_DLOG_TRAILER) {
			goto out;
		}
		if ((buf.dl_len & 3) == 0) {
			/*
			 * Record length must be on a word boundary and
			 * fit into the correct size range.
			 */
			if ((buf.dl_len < sizeof (int)) ||
			    (buf.dl_len > CFS_DLOG_ENTRY_MAXSIZE)) {
				goto out;
			}
			/*
			 * Make sure length does not point beyond end of
			 * file
			 */
			if ((offset + (off_t)buf.dl_len) >
			    (off_t)statinfo.st_size) {
				goto out;
			}
		} else {
			goto out;
		}

		/* make sure the valid field is reasonable */
		switch (buf.dl_valid) {
		case CFS_DLOG_VAL_CRASH:
		case CFS_DLOG_VAL_COMMITTED:
		case CFS_DLOG_VAL_ERROR:
		case CFS_DLOG_VAL_PROCESSED:
			break;
		default:
			goto out;
		}

		/* make sure the operation field is reasonable */
		fileno = 0LL;
		switch (buf.dl_op) {
		case CFS_DLOG_CREATE:
			fileno = buf.dl_u.dl_create.dl_new_cid.cid_fileno;
			break;
		case CFS_DLOG_REMOVE:
			break;
		case CFS_DLOG_LINK:
			break;
		case CFS_DLOG_RENAME:
			break;
		case CFS_DLOG_MKDIR:
			fileno = buf.dl_u.dl_mkdir.dl_child_cid.cid_fileno;
			break;
		case CFS_DLOG_RMDIR:
			break;
		case CFS_DLOG_SYMLINK:
			fileno = buf.dl_u.dl_symlink.dl_child_cid.cid_fileno;
			break;
		case CFS_DLOG_SETATTR:
			break;
		case CFS_DLOG_SETSECATTR:
			break;
		case CFS_DLOG_MODIFIED:
			break;
		case CFS_DLOG_MAPFID:
			break;
		default:
			goto out;
		}

		/* track the largest local fileno used */
		if (maxlocalfileno < fileno)
			maxlocalfileno = fileno;

		/* track the largest sequence number used */
		if (max_seq_num < buf.dl_seq) {
			max_seq_num = buf.dl_seq;
		}

		offset += buf.dl_len;
	}

out:
	if ((buf.dl_op != CFS_DLOG_TRAILER) ||
	    (buf.dl_len != sizeof (struct cfs_dlog_trailer)) ||
	    (buf.dl_valid != CFS_DLOG_VAL_COMMITTED) ||
	    ((offset + (off_t)buf.dl_len) != (off_t)statinfo.st_size)) {
		ftruncate(fd, offset);
		buf.dl_len = sizeof (struct cfs_dlog_trailer);
		buf.dl_op = CFS_DLOG_TRAILER;
		buf.dl_valid = CFS_DLOG_VAL_COMMITTED;
		buf.dl_seq = max_seq_num + 1;
		if (wrdlog(fd, &buf,  buf.dl_len, offset) != 0) {
			(void) close(fd);
			return (-7);
		}
	}

	if (fsync(fd) == -1) {
		pr_err(gettext("Cannot sync %s"), dlog_path);
		(void) close(fd);
		return (-8);
	}
	(void) close(fd); /* ignore return since fsync() successful */

	/* check to see that mapfile exists; if not, create it. */
	if (access(dmap_path, F_OK) != 0) {
		/* XXX ent_count is a very high upper bound */
		if (create_mapfile(dmap_path,
		    ent_count * sizeof (struct cfs_dlog_mapping_space)) != 0) {
			return (-9);
		}
	}

	if (maxlocalfilenop)
		*maxlocalfilenop = maxlocalfileno;
	return (0);
}

int
wrdlog(int fd, char * buf, int len, off_t offset)
{
	int err;

	err = lseek(fd, offset, SEEK_SET);
	if (err < 0) {
		return (-1);
	}

	err = write(fd, buf, len);
	if (err != len) {
		return (-2);
	}

	return (0);
}

static int
create_mapfile(char *fname, int size)
{
	char buffy[BUFSIZ];
	int fd, rc, wsize;

	/* this file will be <2GB */
	fd = open(fname, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return (errno);

	memset(buffy, '\0', sizeof (buffy));
	while (size > 0) {
		wsize = (size > sizeof (buffy)) ? sizeof (buffy) : size;
		if (write(fd, buffy, wsize) != wsize) {
			rc = errno;
			(void) close(fd);
			(void) unlink(fname);
			return (rc);
		}
		size -= wsize;
	}

	if (fsync(fd) != 0) {
		rc = errno;
		(void) close(fd);
		(void) unlink(fname);
		return (rc);
	}
	(void) close(fd);

	return (0);
}
