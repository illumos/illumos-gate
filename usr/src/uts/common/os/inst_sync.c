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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Syscall to write out the instance number data structures to
 * stable storage.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/t_lock.h>
#include <sys/modctl.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/cladm.h>
#include <sys/sunddi.h>
#include <sys/dditypes.h>
#include <sys/instance.h>
#include <sys/debug.h>
#include <sys/policy.h>

/*
 * Userland sees:
 *
 *	int inst_sync(pathname, flags);
 *
 * Returns zero if instance number information was successfully
 * written to 'pathname', -1 plus error code in errno otherwise.
 *
 * POC notes:
 *
 * -	This could be done as a case of the modctl(2) system call
 *	though the ability to have it load and unload would disappear.
 *
 * -	'flags' have either of two meanings:
 *	INST_SYNC_IF_REQUIRED	'pathname' will be written if there
 *				has been a change in the kernel's
 *				internal view of instance number
 *				information
 *	INST_SYNC_ALWAYS	'pathname' will be written even if
 *				the kernel's view hasn't changed.
 *
 * -	Maybe we should pass through two filenames - one to create,
 *	and the other as the 'final' target i.e. do the rename of
 *	/etc/instance.new -> /etc/instance in the kernel.
 */

static int in_sync_sys(char *pathname, uint_t flags);

static struct sysent in_sync_sysent = {
	2,			/* number of arguments */
	SE_ARGC | SE_32RVAL1,	/* c-style calling, 32-bit return value */
	in_sync_sys,		/* the handler */
	(krwlock_t *)0		/* rw lock allocated/used by framework */
};

static struct modlsys modlsys = {
	&mod_syscallops, "instance binding syscall", &in_sync_sysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32, "32-bit instance binding syscall", &in_sync_sysent
};
#endif

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

static int in_write_instance(struct vnode *vp);

static int inst_sync_disable = 0;

static int
in_sync_sys(char *pathname, uint_t flags)
{
	struct vnode *vp;
	int error;

	/* For debugging/testing */
	if (inst_sync_disable)
		return (0);

	/*
	 * We must have sufficient privilege to do this, since we lock critical
	 * data structures whilst we're doing it ..
	 */
	if ((error = secpolicy_sys_devices(CRED())) != 0)
		return (set_errno(error));

	if (flags != INST_SYNC_ALWAYS && flags != INST_SYNC_IF_REQUIRED)
		return (set_errno(EINVAL));

	/*
	 * Only one process is allowed to get the state of the instance
	 * number assignments on the system at any given time.
	 */
	e_ddi_enter_instance();

	/*
	 * Recreate the instance file only if the device tree has changed
	 * or if the caller explicitly requests so.
	 */
	if (e_ddi_instance_is_clean() && flags != INST_SYNC_ALWAYS) {
		error = EALREADY;
		goto end;
	}

	/*
	 * Create an instance file for writing, giving it a mode that
	 * will only permit reading.  Note that we refuse to overwrite
	 * an existing file.
	 */
	if ((error = vn_open(pathname, UIO_USERSPACE,
	    FCREAT, 0444, &vp, CRCREAT, 0)) != 0) {
		if (error == EISDIR)
			error = EACCES;	/* SVID compliance? */
		goto end;
	}

	/*
	 * So far so good.  We're singly threaded, the vnode is beckoning
	 * so let's get on with it.  Any error, and we just give up and
	 * hand the first error we get back to userland.
	 */
	error = in_write_instance(vp);

	/*
	 * If there was any sort of error, we deliberately go and
	 * remove the file we just created so that any attempts to
	 * use it will quickly fail.
	 */
	if (error)
		(void) vn_remove(pathname, UIO_USERSPACE, RMFILE);
	else
		e_ddi_instance_set_clean();
end:
	e_ddi_exit_instance();
	return (error ? set_errno(error) : 0);
}

/*
 * At the risk of reinventing stdio ..
 */
#define	FBUFSIZE	512

typedef struct _File {
	char	*ptr;
	int	count;
	char	buf[FBUFSIZE];
	vnode_t	*vp;
	offset_t voffset;
} File;

static int
in_write(struct vnode *vp, offset_t *vo, caddr_t buf, int count)
{
	int error;
	ssize_t resid;
	rlim64_t rlimit = *vo + count + 1;

	error = vn_rdwr(UIO_WRITE, vp, buf, count, *vo,
	    UIO_SYSSPACE, 0, rlimit, CRED(), &resid);

	*vo += (offset_t)(count - resid);

	return (error);
}

static File *
in_fvpopen(struct vnode *vp)
{
	File *fp;

	fp = kmem_zalloc(sizeof (File), KM_SLEEP);
	fp->vp = vp;
	fp->ptr = fp->buf;

	return (fp);
}

static int
in_fclose(File *fp)
{
	int error;

	error = VOP_CLOSE(fp->vp, FCREAT, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(fp->vp);
	kmem_free(fp, sizeof (File));
	return (error);
}

static int
in_fflush(File *fp)
{
	int error = 0;

	if (fp->count)
		error = in_write(fp->vp, &fp->voffset, fp->buf, fp->count);
	if (error == 0)
		error = VOP_FSYNC(fp->vp, FSYNC, CRED(), NULL);
	return (error);
}

static int
in_fputs(File *fp, char *buf)
{
	int error = 0;

	while (*buf) {
		*fp->ptr++ = *buf++;
		if (++fp->count == FBUFSIZE) {
			error = in_write(fp->vp, &fp->voffset, fp->buf,
			    fp->count);
			if (error)
				break;
			fp->count = 0;
			fp->ptr = fp->buf;
		}
	}

	return (error);
}

/*
 * External linkage
 */
static File *in_fp;

/*
 * XXX what is the maximum length of the name of a driver?  Must be maximum
 * XXX file name length (find the correct constant and substitute for this one
 */
#define	DRVNAMELEN (1 + 256)
static char linebuffer[MAXPATHLEN + 1 + 1 + 1 + 1 + 10 + 1 + DRVNAMELEN];

/*
 * XXX	Maybe we should just write 'in_fprintf' instead ..
 */
static int
in_walktree(in_node_t *np, char *this)
{
	char *next;
	int error = 0;
	in_drv_t *dp;

	for (error = 0; np; np = np->in_sibling) {

		if (np->in_drivers == NULL)
			continue;

		if (np->in_unit_addr[0] == '\0')
			(void) sprintf(this, "/%s", np->in_node_name);
		else
			(void) sprintf(this, "/%s@%s", np->in_node_name,
			    np->in_unit_addr);
		next = this + strlen(this);

		ASSERT(np->in_drivers);

		for (dp = np->in_drivers; dp; dp = dp->ind_next_drv) {
			uint_t inst_val = dp->ind_instance;

			/*
			 * Flushing IN_PROVISIONAL could result in duplicate
			 * instances
			 * Flushing IN_UNKNOWN results in instance -1
			 */
			if (dp->ind_state != IN_PERMANENT)
				continue;

			(void) sprintf(next, "\" %d \"%s\"\n", inst_val,
			    dp->ind_driver_name);
			if (error = in_fputs(in_fp, linebuffer))
				return (error);
		}

		if (np->in_child)
			if (error = in_walktree(np->in_child, next))
				break;
	}
	return (error);
}


/*
 * Walk the instance tree, writing out what we find.
 *
 * There's some fairly nasty sharing of buffers in this
 * bit of code, so be careful out there when you're
 * rewriting it ..
 */
static int
in_write_instance(struct vnode *vp)
{
	int error;
	char *cp;

	in_fp = in_fvpopen(vp);

	/*
	 * Place a bossy comment at the beginning of the file.
	 */
	error = in_fputs(in_fp,
	    "#\n#\tCaution! This file contains critical kernel state\n#\n");

	if (error == 0) {
		in_node_t *root = e_ddi_instance_root();
		cp = linebuffer;
		*cp++ = '\"';
		error = in_walktree(root->in_child, cp);
	}

	if (error == 0) {
		if ((error = in_fflush(in_fp)) == 0)
			error = in_fclose(in_fp);
	} else
		(void) in_fclose(in_fp);

	return (error);
}
