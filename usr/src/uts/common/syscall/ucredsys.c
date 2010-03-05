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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <c2/audit.h>

/*
 * Getpeerucred system call implementation.
 */
static int
getpeerucred(int fd, void *buf)
{
	file_t *fp;
	struct ucred_s *uc;
	vnode_t *vp;
	k_peercred_t kpc;
	int err;
	int32_t rval;

	kpc.pc_cr = NULL;
	kpc.pc_cpid = -1;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));

	vp = fp->f_vnode;

	switch (vp->v_type) {
	case VFIFO:
	case VSOCK:
		err = VOP_IOCTL(vp, _I_GETPEERCRED, (intptr_t)&kpc,
		    FKIOCTL, CRED(), &rval, NULL);
		break;
	case VCHR: {
		struct strioctl strioc;

		if (vp->v_stream == NULL) {
			err = ENOTSUP;
			break;
		}
		strioc.ic_cmd = _I_GETPEERCRED;
		strioc.ic_timout = INFTIM;
		strioc.ic_len = (int)sizeof (k_peercred_t);
		strioc.ic_dp = (char *)&kpc;

		err = strdoioctl(vp->v_stream, &strioc, FNATIVE|FKIOCTL,
		    STR_NOSIG|K_TO_K, CRED(), &rval);

		/*
		 * Map all unexpected error codes to ENOTSUP.
		 */
		switch (err) {
		case 0:
		case ENOTSUP:
		case ENOTCONN:
		case ENOMEM:
			break;
		default:
			err = ENOTSUP;
			break;
		}
		break;
	}
	default:
		err = ENOTSUP;
		break;
	}
	releasef(fd);

	/*
	 * If someone gave us a credential, err will be 0.
	 */
	if (kpc.pc_cr != NULL) {
		ASSERT(err == 0);

		uc = cred2ucred(kpc.pc_cr, kpc.pc_cpid, NULL, CRED());

		crfree(kpc.pc_cr);

		err = copyout(uc, buf, uc->uc_size);

		kmem_free(uc, uc->uc_size);

		if (err != 0)
			return (set_errno(EFAULT));

		return (0);
	}
	return (set_errno(err));
}

static int
ucred_get(pid_t pid, void *ubuf)
{
	proc_t *p;
	cred_t *pcr;
	int err;
	struct ucred_s *uc;
	uint32_t auditing = AU_AUDITING();

	if (pid == P_MYID || pid == curproc->p_pid) {
		pcr = CRED();
		crhold(pcr);
		pid = curproc->p_pid;
	} else {
		cred_t	*updcred = NULL;

		if (pid < 0)
			return (set_errno(EINVAL));

		if (auditing)
			updcred = cralloc();

		mutex_enter(&pidlock);
		p = prfind(pid);

		if (p == NULL) {
			mutex_exit(&pidlock);
			if (updcred != NULL)
				crfree(updcred);
			return (set_errno(ESRCH));
		}

		/*
		 * Assure that audit data in cred is up-to-date.
		 * updcred will be used or freed.
		 */
		if (auditing)
			audit_update_context(p, updcred);

		err = priv_proc_cred_perm(CRED(), p, &pcr, VREAD);
		mutex_exit(&pidlock);

		if (err != 0)
			return (set_errno(err));
	}

	uc = cred2ucred(pcr, pid, NULL, CRED());

	crfree(pcr);

	err = copyout(uc, ubuf, uc->uc_size);

	kmem_free(uc, uc->uc_size);

	if (err)
		return (set_errno(EFAULT));

	return (0);
}

int
ucredsys(int code, int obj, void *buf)
{
	switch (code) {
	case UCREDSYS_UCREDGET:
		return (ucred_get((pid_t)obj, buf));
	case UCREDSYS_GETPEERUCRED:
		return (getpeerucred(obj, buf));
	default:
		return (set_errno(EINVAL));
	}
}

#ifdef _SYSCALL32_IMPL
int
ucredsys32(int arg1, int arg2, caddr32_t arg3)
{
	return (ucredsys(arg1, arg2, (void *)(uintptr_t)arg3));
}
#endif
