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


#include <sys/types.h>
#include <sys/sunddi.h>		/* declares:    bcopy(), etc.. */
#include <sys/file.h>		/* defines:	FKIOCTL */
#include <sys/socket.h>		/*		AF_INET & company */
#include <sys/cred.h>		/*		kcred */
#include <netinet/in.h>		/* declares:    sa_family_t for socketvar.h */
#include <netinet/tcp.h>	/* TCP */
#include <sys/stropts.h>	/*		strbuf for socketvar.h */
#include <sys/ddi.h>		/*		getmajor */

#include "iscsi.h"
#include <iscsi_if.h>

/*
 * Very specific set of file type function calls which are ONLY used by the
 * iSCSI driver.
 */
#define	ISCSID_GETF	16

int	iscsid_notify_threshold = ISCSI_TCP_CNOTIFY_THRESHOLD_DEFAULT;
int	iscsid_abort_threshold = ISCSI_TCP_CABORT_THRESHOLD_DEFAULT;

static kmutex_t		iscsid_getf_lock;
static file_t		*iscsid_fd[ISCSID_GETF];

/*
 * util_locks_init -- initialize what ever locks local file will use
 */
/* ARGSUSED */
boolean_t
iscsi_util_locks_init(boolean_t restart)
{
	mutex_init(&iscsid_getf_lock, NULL, MUTEX_DRIVER, NULL);
	return (B_TRUE);
}

/*
 * iscsid_getf -- given a file descriptor returns a file pointer
 */
static file_t *
iscsid_getf(int fdes)
{
	file_t	*fp = NULL;

	mutex_enter(&iscsid_getf_lock);
	if ((fdes >= 0) && (fdes < ISCSID_GETF)) {
		fp = iscsid_fd[fdes];
		if (fp != NULL)
			mutex_enter(&fp->f_tlock);
	}
	mutex_exit(&iscsid_getf_lock);

	return (fp);
}

/*
 * iscsid_releasef -- release lock on file pointer
 */
static void
iscsid_releasef(int fdes)
{
	file_t  *fp;

	mutex_enter(&iscsid_getf_lock);
	if ((fdes >= 0) && (fdes < ISCSID_GETF)) {
		fp = iscsid_fd[fdes];
		mutex_exit(&fp->f_tlock);
	}
	mutex_exit(&iscsid_getf_lock);
}

/*
 * iscsid_setf -- stores the file pointer in an empty slot returning index
 */
static int
iscsid_setf(file_t *fp)
{
	int	i = -1;

	mutex_enter(&iscsid_getf_lock);
	for (i = 0; i < ISCSID_GETF; i++) {
		if (iscsid_fd[i] == 0) {
			iscsid_fd[i] = fp;
			break;
		}
	}
	mutex_exit(&iscsid_getf_lock);
	return (i);
}

int iscsid_errno;

/*
 * iscsid_freef -- gets the file pointer based on index and releases memory.
 */
static void
iscsid_freef(int fdes)
{
	file_t *fp;

	mutex_enter(&iscsid_getf_lock);
	if ((fdes >= 0) && (fdes < ISCSID_GETF)) {
		fp = iscsid_fd[fdes];
		unfalloc(fp);
		iscsid_fd[fdes] = NULL;
	}
	mutex_exit(&iscsid_getf_lock);
}

/*
 * iscsid_open -- acts like syscall open, but works for kernel
 *
 * Note: This works for regular files only. No umask is provided to
 * vn_open which means whatever mode is passed in will be used to
 * create a file.
 */
int
iscsid_open(char *path, int flags, int mode)
{
	file_t		*fp	= NULL;
	vnode_t		*vp	= NULL;
	int		fdes	= -1,
	    fflags;

	/*
	 * Need to convert from user mode flags to file system flags.
	 * It's unfortunate that the kernel doesn't define a mask for
	 * the read/write bits which would make this conversion easier.
	 * Only O_RDONLY/O_WRONLY/O_RDWR are different than their FXXXXX
	 * counterparts. If one was provided something like
	 *	fflags = ((flags & mask) + 1) | (flags & ~mask)
	 * would work. But, that would only be true if the relationship
	 * be O_XXX and FXXX was defined and it's not. So we have the
	 * following.
	 */
	if (flags & O_WRONLY)
		fflags = FWRITE;
	else if (flags & O_RDWR)
		fflags = FWRITE | FREAD;
	else
		fflags = FREAD;

	/*
	 * Now that fflags has been initialized with the read/write bits
	 * look at the other flags and OR them in.
	 */
	if (flags & O_CREAT)
		fflags |= FCREAT;
	if (flags & O_TRUNC)
		fflags |= FTRUNC;

	if (iscsid_errno = vn_open(path, UIO_SYSSPACE, fflags,
	    mode & MODEMASK, &vp, CRCREAT, 0)) {
		return (-1);
	}

	if (falloc(vp, fflags, &fp, NULL) != 0) {
		VN_RELE(vp);
		return (-1);
	}
	/* ---- falloc returns with f_tlock held on success ---- */
	mutex_exit(&fp->f_tlock);

	if ((fdes = iscsid_setf(fp)) == -1) {
		VN_RELE(vp);
	}
	return (fdes);
}

/*
 * iscsid_close -- closes down the file by releasing locks and memory.
 */
int
iscsid_close(int fdes)
{
	file_t  *fp;
	vnode_t *vp;

	if ((fp = iscsid_getf(fdes)) == NULL)
		return (-1);
	vp = fp->f_vnode;

	(void) VOP_CLOSE(vp, fp->f_flag, 1, 0, kcred, NULL);
	VN_RELE(vp);
	/*
	 * unfalloc which is called from here will do a mutex_exit
	 * on t_lock in the fp. So don't call iscsid_releasef() here.
	 */
	iscsid_freef(fdes);

	return (0);
}

/*
 * iscsid_remove -- remove file from filesystem
 */
int
iscsid_remove(char *filename)
{
	return (vn_remove(filename, UIO_SYSSPACE, RMFILE));
}

/*
 * iscsid_rename -- rename file from one name to another
 */
int
iscsid_rename(char *oldname, char *newname)
{
	return (vn_rename(oldname, newname, UIO_SYSSPACE));
}

/*
 * iscsid_rw -- common read/write code. Very simplistic.
 */
static ssize_t
iscsid_rw(int fdes, void *cbuf, ssize_t count, enum uio_rw rw)
{
	file_t	*fp;
	vnode_t	*vp;
	ssize_t	resid   = 0;

	if ((fp  = iscsid_getf(fdes)) == NULL)
		return (-1);
	vp = fp->f_vnode;

	if (iscsid_errno = vn_rdwr(rw, vp, (caddr_t)cbuf, count, fp->f_offset,
	    UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid)) {
		iscsid_releasef(fdes);
		return (-1);
	}

	if ((count - resid) > 0)
		fp->f_offset += count;

	iscsid_releasef(fdes);
	return (count - resid);
}

/*
 * iscsid_write -- kernel write function
 */
ssize_t
iscsid_write(int fdes, void *cbuf, ssize_t count)
{
	return (iscsid_rw(fdes, cbuf, count, UIO_WRITE));
}

/*
 * iscsid_read -- kernel read function
 */
ssize_t
iscsid_read(int fdes, void *cbuf, ssize_t count)
{
	return (iscsid_rw(fdes, cbuf, count, UIO_READ));
}

/*
 * iscsid_sendto -- kernel callable sendto function
 */
ssize_t
iscsid_sendto(struct sonode *so, void *buffer, size_t len,
    struct sockaddr *name, socklen_t namelen)
{
	struct nmsghdr	lmsg;
	struct uio	auio;
	struct iovec	aiov[1];
	int		error;

	if ((ssize_t)len < 0) {
		iscsid_errno = EINVAL;
		return (-1);
	}

	bzero(&lmsg, sizeof (lmsg));
	bzero(&auio, sizeof (auio));

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_limit = 0;

	lmsg.msg_name = name;
	lmsg.msg_namelen = namelen;

	error = sosendmsg(so, &lmsg, &auio);

	if (error != 0)
		return (-1);
	return (len - auio.uio_resid);
}

/*
 * iscsid_recvfrom -- kernel callable recvfrom routine
 */
ssize_t
iscsid_recvfrom(struct sonode *so, void *buffer, size_t len)
{
	struct nmsghdr	lmsg;
	struct uio	auio;
	struct iovec	aiov[1];
	int		error;

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_limit = 0;

	lmsg.msg_name = NULL;
	lmsg.msg_namelen = 0;
	lmsg.msg_control = NULL;
	lmsg.msg_controllen = 0;
	lmsg.msg_flags = 0;

	error = sorecvmsg(so, &lmsg, &auio);
	if (error) {
		iscsid_errno = error;
		return (-1);
	}

	return (len - auio.uio_resid);
}

/*
 * iscsi_discovery_event -- send event associated with discovery operations
 *
 * Each discovery event has a start and end event. Which is sent is based
 * on the boolean argument start with the obvious results.
 */
void
iscsi_discovery_event(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t m,
    boolean_t start)
{
	char    *subclass = NULL;

	mutex_enter(&ihp->hba_discovery_events_mutex);
	switch (m) {
	case iSCSIDiscoveryMethodStatic:
		if (start == B_TRUE)
			subclass = ESC_ISCSI_STATIC_START;
		else {
			ihp->hba_discovery_events |= iSCSIDiscoveryMethodStatic;
			subclass = ESC_ISCSI_STATIC_END;
		}
		break;

	case iSCSIDiscoveryMethodSendTargets:
		if (start == B_TRUE)
			subclass = ESC_ISCSI_SEND_TARGETS_START;
		else {
			ihp->hba_discovery_events |=
			    iSCSIDiscoveryMethodSendTargets;
			subclass = ESC_ISCSI_SEND_TARGETS_END;
		}

		break;

	case iSCSIDiscoveryMethodSLP:
		if (start == B_TRUE)
			subclass = ESC_ISCSI_SLP_START;
		else {
			ihp->hba_discovery_events |= iSCSIDiscoveryMethodSLP;
			subclass = ESC_ISCSI_SLP_END;
		}
		break;

	case iSCSIDiscoveryMethodISNS:
		if (start == B_TRUE)
			subclass = ESC_ISCSI_ISNS_START;
		else {
			ihp->hba_discovery_events |= iSCSIDiscoveryMethodISNS;
			subclass = ESC_ISCSI_ISNS_END;
		}
		break;

	}
	mutex_exit(&ihp->hba_discovery_events_mutex);
	iscsi_send_sysevent(ihp, subclass, NULL);
}

/*
 * iscsi_send_sysevent -- send sysevent using iscsi class
 */
void
iscsi_send_sysevent(iscsi_hba_t *ihp, char *subclass, nvlist_t *np)
{
	(void) ddi_log_sysevent(ihp->hba_dip, DDI_VENDOR_SUNW, EC_ISCSI,
	    subclass, np, NULL, DDI_SLEEP);
}
