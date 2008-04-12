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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

/*
 *  Function prototypes
 */
static int	promfs_mountroot(char *str);
static int	promfs_unmountroot(void);
static int	promfs_open(char *filename, int flags);
static int	promfs_close(int fd);
static ssize_t	promfs_read(int fd, caddr_t buf, size_t size);
static off_t	promfs_lseek(int fd, off_t offset, int whence);
static int	promfs_fstat(int fd, struct bootstat *stp);
static void	promfs_closeall(int flag);

struct boot_fs_ops promfs_ops = {
	"promfs",
	promfs_mountroot,
	promfs_unmountroot,
	promfs_open,
	promfs_close,
	promfs_read,
	promfs_lseek,
	promfs_fstat,
	promfs_closeall,
	NULL
};

static ihandle_t fsih;

static int
promfs_mountroot(char *str)
{

	(void) prom_getprop(prom_chosennode(), str, (caddr_t)&fsih);
	return (fsih == -1);
}

static int
promfs_unmountroot(void)
{
	(void) prom_close(fsih);
	return (0);
}

/*ARGSUSED*/
static int
promfs_open(char *filename, int flags)
{
	return (prom_fopen(fsih, filename));
}

static int
promfs_close(int fd)
{
	prom_fclose(fsih, fd);
	return (0);
}

static ssize_t
promfs_read(int fd, caddr_t buf, size_t size)
{
	return (prom_fread(fsih, fd, buf, size));
}

/*ARGSUSED*/
static off_t
promfs_lseek(int fd, off_t offset, int whence)
{
	return (prom_fseek(fsih, fd, offset));
}

static int
promfs_fstat(int fd, struct bootstat *stp)
{
	return (prom_fsize(fsih, fd, (size_t *)&stp->st_size));
}

/*ARGSUSED*/
static void
promfs_closeall(int flag)
{
}
