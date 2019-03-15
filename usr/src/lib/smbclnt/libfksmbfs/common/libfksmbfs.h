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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _LIBFKSMBFS_H_
#define	_LIBFKSMBFS_H_

/*
 * Declarations for exports in fake_vfs.c
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/vfs.h>

#ifndef	MAXOFF32_T
#define	MAXOFF32_T	0x7fffffff
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Need these visible outside _FAKE_KERNEL for the test CLI.
 * In the kmod/lib build these duplicate declarations in vfs.h or
 * vnode.h but that's OK as long as the declarations are identical.
 */
struct mounta;
struct stat64;
int	fake_installfs(vfsdef_t *);
int	fake_removefs(vfsdef_t *);
int	fake_domount(char *, struct mounta *, struct vfs **);
int	fake_dounmount(struct vfs *, int);
int	fake_lookup(vnode_t *, char *, vnode_t **);
int	fake_lookup_dir(char *, vnode_t **, char **);
int	fake_stat(vnode_t *, struct stat64 *, int);
int	fake_getdents(vnode_t *, offset_t *, void *, size_t);
ssize_t	fake_pread(vnode_t *, void *, size_t, off_t);
ssize_t	fake_pwrite(vnode_t *, void *, size_t, off_t);
int	fake_unlink(char *, int);
int	fake_rename(char *, char *);

int	vn_close_rele(vnode_t *vp, int flag);
int	vn_open(char *pnamep, enum uio_seg seg, int filemode, int createmode,
		struct vnode **vpp, enum create crwhy, mode_t umask);
int	vn_create(char *pnamep, enum uio_seg seg, struct vattr *vap,
		enum vcexcl excl, int mode, struct vnode **vpp,
		enum create why, int flag, mode_t umask);

void	vn_rele(struct vnode *vp);

/* In the real smbfs, these are _init(), _fini() */
int fksmbfs_init(void);
int fksmbfs_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* _LIBFKSMBFS_H_ */
