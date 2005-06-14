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
 * Copyright 1994-1996, 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/bootsyms.h>
#include <sys/promif.h>
#include <sys/salib.h>

static struct boot_fs_ops *dfl_fsw = (struct boot_fs_ops *)NULL;
static char *fsmsg = "Fstype has not been selected yet!\n";
static char *msg_noops = "not fs_ops supplied\n";

/*
 * return fs_ops pointer for a given file system name
 */
struct boot_fs_ops *
get_fs_ops_pointer(char *fsw_name)
{
	int	fsw_idx;

	for (fsw_idx = 0; fsw_idx < boot_nfsw; fsw_idx++)
		if (strcmp(boot_fsw[fsw_idx]->fsw_name, fsw_name) == 0) {
			return (boot_fsw[fsw_idx]);
		}
	return ((struct boot_fs_ops *)NULL);
}

/*
 * set default file system type
 */
void
set_default_fs(char *fsw_name)
{
	int	fsw_idx;

	for (fsw_idx = 0; fsw_idx < boot_nfsw; fsw_idx++)
		if (strcmp(boot_fsw[fsw_idx]->fsw_name, fsw_name) == 0) {
			dfl_fsw = boot_fsw[fsw_idx];
			return;
		}
	printf("Fstype <%s> is not recognized\n", fsw_name);
	prom_panic("");
}

/*
 * clear default file system type
 */
void
clr_default_fs(void)
{
	dfl_fsw = NULL;
}

struct boot_fs_ops *
get_default_fs(void)
{
	return (dfl_fsw);
}

void
boot_no_ops_void()
{
	prom_panic(msg_noops);
	/*NOTREACHED*/
}

int
boot_no_ops()
{
	prom_panic(msg_noops);
	/*NOTREACHED*/
	return (0);
}

int
close(int fd)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_close)(fd));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

int
mountroot(char *str)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_mountroot)(str));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

int
unmountroot(void)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_unmountroot)());
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

/*ARGSUSED*/
int
open(const char *filename, int flags)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_open)((char *)filename, flags));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

ssize_t
read(int fd, void *buf, size_t size)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_read)(fd, buf, size));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

void
closeall(int flag)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL) {
		(*dfl_fsw->fsw_closeall)(flag);
		return;
	}
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

int
fstat(int fd, struct stat *sb)
{
	struct bootstat buf;
	int ret;

	if (dfl_fsw == NULL)
		prom_panic(fsmsg);

	ret = (*dfl_fsw->fsw_fstat)(fd, &buf);
	if (ret == -1)
		return (-1);

	sb->st_dev		= buf.st_dev;
	sb->st_ino		= buf.st_ino;
	sb->st_mode		= buf.st_mode;
	sb->st_nlink		= buf.st_nlink;
	sb->st_uid 		= buf.st_uid;
	sb->st_gid		= buf.st_gid;
	sb->st_rdev		= buf.st_rdev;
	sb->st_size		= (off_t)buf.st_size;
	sb->st_blksize		= buf.st_blksize;
	sb->st_blocks		= buf.st_blocks;
	sb->st_atim.tv_sec	= buf.st_atim.tv_sec;
	sb->st_atim.tv_nsec	= buf.st_atim.tv_nsec;
	sb->st_mtim.tv_sec 	= buf.st_mtim.tv_sec;
	sb->st_mtim.tv_nsec	= buf.st_mtim.tv_nsec;
	sb->st_ctim.tv_sec	= buf.st_ctim.tv_sec;
	sb->st_ctim.tv_nsec	= buf.st_ctim.tv_nsec;

	(void) memcpy(sb->st_fstype, buf.st_fstype, sizeof (sb->st_fstype));
	return (0);
}

int
stat(const char *filename, struct stat *sb)
{
	int fd, ret = -1;

	if ((fd = open(filename, O_RDONLY)) != -1) {
		ret = fstat(fd, sb);
		(void) close(fd);
	}

	return (ret);
}

off_t
lseek(int filefd, off_t addr, int whence)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_lseek)(filefd, addr, whence));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

/*
 * Kernel Interface
 */
int
kern_open(char *str, int flags)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_open)(str, flags));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

/*
 *  hi and lo refer to the MS end of the off_t word
 *  and the LS end of the off_t word for when we want
 *  to support 64-bit offsets.  For now, lseek() just
 *  supports 32 bits.
 */

/*ARGSUSED*/
off_t
kern_lseek(int filefd, off_t hi, off_t lo)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_lseek)(filefd, lo, 0));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

ssize_t
kern_read(int fd, caddr_t buf, size_t size)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_read)(fd, buf, size));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

int
kern_close(int fd)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_close)(fd));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

int
kern_fstat(int fd, struct bootstat *buf)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_fstat)(fd, buf));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

int
kern_getdents(int fd, struct dirent *buf, size_t size)
{
	if (dfl_fsw != (struct boot_fs_ops *)NULL)
		return ((*dfl_fsw->fsw_getdents)(fd, buf, size));
	prom_panic(fsmsg);
	/*NOTREACHED*/
}

int
kern_mountroot(char *path)
{
	return (mountroot(path));
}

int
kern_unmountroot(void)
{
	return (unmountroot());
}
