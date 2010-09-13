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

#ifndef	_SYS_BOOTVFS_H
#define	_SYS_BOOTVFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/filep.h>
#include <sys/dirent.h>
#include <sys/bootstat.h>

/* same as those in /usr/include/unistd.h */
#define	SEEK_SET	0	/* Offset */
#define	SEEK_CUR	1	/* Current + Offset */
#define	SEEK_END	2	/* EOF + Offset */

/* mountroot/unmountroot return values */
#define	VFS_SUCCESS	0
#define	VFS_FAILURE	-1

/*
 * unified (vfs-like) file system operations for booters
 */

struct boot_fs_ops {
    char	*fsw_name;
    int		(*fsw_mountroot)(char *str);
    int		(*fsw_unmountroot)(void);
    int		(*fsw_open)(char *filename, int flags);
    int		(*fsw_close)(int fd);
    ssize_t	(*fsw_read)(int fd, caddr_t buf, size_t size);
    off_t	(*fsw_lseek)(int filefd, off_t addr, int whence);
    int		(*fsw_fstat)(int filefd, struct bootstat *buf);
    void	(*fsw_closeall)(int flag);
    int		(*fsw_getdents)(int fd, struct dirent *buf, unsigned size);
};

/*
 *  Function prototypes
 *
 *	fstat() (if exists) supports size and mode right now.
 */

extern	int	mountroot(char *str);
extern	int	unmountroot(void);
extern	int	open(const char *filename, int flags);
extern	int	close(int fd);
extern	ssize_t	read(int fd, void *buf, size_t size);
extern	off_t	lseek(int filefd, off_t addr, int whence);
extern	int	fstat(int fd, struct stat *buf);
extern	int	stat(const char *filename, struct stat *buf);

/*
 * The compfs filesystem provides additional fsswitch-like entry points,
 * though these are not yet hooked properly into the fsswitch.
 */

extern	void	closeall(int flag);

extern	ssize_t	kern_read(int fd, caddr_t buf, size_t size);
extern	int	kern_open(char *filename, int flags);
extern	off_t	kern_seek(int fd, off_t hi, off_t lo);
extern	off_t	kern_lseek(int fd, off_t hi, off_t lo);
extern	int	kern_close(int fd);
extern	int	kern_fstat(int fd, struct bootstat *buf);
extern	int	kern_getdents(int fd, struct dirent *buf, size_t size);
extern	int	kern_mountroot(char *path);
extern	int	kern_unmountroot(void);

/*
 * these are for common fs switch interface routines
 */
extern	int	boot_no_ops(void);	/* no ops entry */
extern	void	boot_no_ops_void(void);	/* no ops entry */

extern	struct boot_fs_ops *get_default_fs(void);
extern	struct boot_fs_ops *get_fs_ops_pointer(char *fsw_name);
extern	void	set_default_fs(char *fsw_name);
extern	void	clr_default_fs(void);
extern	char 	*set_fstype(char *v2path, char *bpath);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOTVFS_H */
