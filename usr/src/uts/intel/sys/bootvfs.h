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
 */

#ifndef	_SYS_BOOTVFS_H
#define	_SYS_BOOTVFS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/bootstat.h>
#include <sys/dirent.h>

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

extern struct boot_fs_ops *bfs_ops;

#ifdef _KERNEL

extern int BRD_MOUNTROOT(struct boot_fs_ops *, char *);
extern int BRD_UNMOUNTROOT(struct boot_fs_ops *);
extern int BRD_OPEN(struct boot_fs_ops *, char *, int);
extern int BRD_CLOSE(struct boot_fs_ops *, int);
extern ssize_t BRD_READ(struct boot_fs_ops *, int, caddr_t, size_t);
extern off_t BRD_SEEK(struct boot_fs_ops *, int, off_t, int);
extern int BRD_FSTAT(struct boot_fs_ops *, int, struct bootstat *);

#else

#define	BRD_MOUNTROOT(ops, str)		((ops)->fsw_mountroot)(str)
#define	BRD_UNMOUNTROOT(ops)		((ops)->fsw_unmountroot)()
#define	BRD_OPEN(ops, file, flag)	((ops)->fsw_open)(file, flag)
#define	BRD_CLOSE(ops, fd)		((ops)->fsw_close)(fd)
#define	BRD_READ(ops, fd, buf, s)	((ops)->fsw_read)(fd, buf, s)
#define	BRD_SEEK(ops, fd, addr, w)	((ops)->fsw_lseek)(fd, addr, w)
#define	BRD_FSTAT(ops, fd, stp)		((ops)->fsw_fstat)(fd, stp)

#endif

#define	SYSTEM_BOOT_PATH	"/system/boot"
#define	BFD_F_SYSTEM_BOOT	0x40000000

#ifdef _BOOT

extern	int	mountroot(char *str);
extern	int	unmountroot(void);
extern	int	open(const char *filename, int flags);
extern	int	close(int fd);
extern	ssize_t	read(int fd, void *buf, size_t size);
extern	off_t	lseek(int filefd, off_t addr, int whence);
extern	void	closeall(int flag);

#endif /* _BOOT */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOTVFS_H */
