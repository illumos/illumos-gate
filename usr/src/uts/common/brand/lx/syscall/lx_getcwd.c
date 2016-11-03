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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/pathname.h>

/*
 * getcwd() - Linux syscall semantics are slightly different; we need to return
 * the length of the pathname copied (+ 1 for the terminating NULL byte.)
 */
long
lx_getcwd(char *buf, int size)
{
	int len;
	int error;
	vnode_t *vp;
	char path[MAXPATHLEN + 1];

	mutex_enter(&curproc->p_lock);
	vp = PTOU(curproc)->u_cdir;
	VN_HOLD(vp);
	mutex_exit(&curproc->p_lock);
	if ((error = vnodetopath(NULL, vp, path, sizeof (path), CRED())) != 0) {
		VN_RELE(vp);
		return (set_errno(error));
	}
	VN_RELE(vp);

	len = strlen(path) + 1;
	if (len > size)
		return (set_errno(ERANGE));

	if (copyout(path, buf, len) != 0)
		return (set_errno(EFAULT));

	return (len);
}
