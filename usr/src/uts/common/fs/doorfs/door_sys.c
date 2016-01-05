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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * System call I/F to doors (outside of vnodes I/F) and misc support
 * routines
 */
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/door.h>
#include <sys/door_data.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/prsystm.h>
#include <sys/procfs.h>
#include <sys/class.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/stack.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/sobject.h>
#include <sys/schedctl.h>
#include <sys/callb.h>
#include <sys/ucred.h>

#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/vmsystm.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <vm/seg_vn.h>
#include <vm/seg_kpm.h>

#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/pathname.h>
#include <sys/rctl.h>

/*
 * The maximum amount of data (in bytes) that will be transferred using
 * an intermediate kernel buffer.  For sizes greater than this we map
 * in the destination pages and perform a 1-copy transfer.
 */
size_t	door_max_arg = 16 * 1024;

/*
 * Maximum amount of data that will be transferred in a reply to a
 * door_upcall.  Need to guard against a process returning huge amounts
 * of data and getting the kernel stuck in kmem_alloc.
 */
size_t	door_max_upcall_reply = 1024 * 1024;

/*
 * Maximum number of descriptors allowed to be passed in a single
 * door_call or door_return.  We need to allocate kernel memory
 * for all of them at once, so we can't let it scale without limit.
 */
uint_t door_max_desc = 1024;

/*
 * Definition of a door handle, used by other kernel subsystems when
 * calling door functions.  This is really a file structure but we
 * want to hide that fact.
 */
struct __door_handle {
	file_t dh_file;
};

#define	DHTOF(dh) ((file_t *)(dh))
#define	FTODH(fp) ((door_handle_t)(fp))

static int doorfs(long, long, long, long, long, long);

static struct sysent door_sysent = {
	6,
	SE_ARGC | SE_NOUNLOAD,
	(int (*)())doorfs,
};

static struct modlsys modlsys = {
	&mod_syscallops, "doors", &door_sysent
};

#ifdef _SYSCALL32_IMPL

static int
doorfs32(int32_t arg1, int32_t arg2, int32_t arg3, int32_t arg4,
    int32_t arg5, int32_t subcode);

static struct sysent door_sysent32 = {
	6,
	SE_ARGC | SE_NOUNLOAD,
	(int (*)())doorfs32,
};

static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"32-bit door syscalls",
	&door_sysent32
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

dev_t	doordev;

extern	struct vfs door_vfs;
extern	struct vnodeops *door_vnodeops;

int
_init(void)
{
	static const fs_operation_def_t door_vfsops_template[] = {
		NULL, NULL
	};
	extern const fs_operation_def_t door_vnodeops_template[];
	vfsops_t *door_vfsops;
	major_t major;
	int error;

	mutex_init(&door_knob, NULL, MUTEX_DEFAULT, NULL);
	if ((major = getudev()) == (major_t)-1)
		return (ENXIO);
	doordev = makedevice(major, 0);

	/* Create a dummy vfs */
	error = vfs_makefsops(door_vfsops_template, &door_vfsops);
	if (error != 0) {
		cmn_err(CE_WARN, "door init: bad vfs ops");
		return (error);
	}
	VFS_INIT(&door_vfs, door_vfsops, NULL);
	door_vfs.vfs_flag = VFS_RDONLY;
	door_vfs.vfs_dev = doordev;
	vfs_make_fsid(&(door_vfs.vfs_fsid), doordev, 0);

	error = vn_make_ops("doorfs", door_vnodeops_template, &door_vnodeops);
	if (error != 0) {
		vfs_freevfsops(door_vfsops);
		cmn_err(CE_WARN, "door init: bad vnode ops");
		return (error);
	}
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* system call functions */
static int door_call(int, void *);
static int door_return(caddr_t, size_t, door_desc_t *, uint_t, caddr_t, size_t);
static int door_create(void (*pc_cookie)(void *, char *, size_t, door_desc_t *,
    uint_t), void *data_cookie, uint_t);
static int door_revoke(int);
static int door_info(int, struct door_info *);
static int door_ucred(struct ucred_s *);
static int door_bind(int);
static int door_unbind(void);
static int door_unref(void);
static int door_getparam(int, int, size_t *);
static int door_setparam(int, int, size_t);

#define	DOOR_RETURN_OLD	4		/* historic value, for s10 */

/*
 * System call wrapper for all door related system calls
 */
static int
doorfs(long arg1, long arg2, long arg3, long arg4, long arg5, long subcode)
{
	switch (subcode) {
	case DOOR_CALL:
		return (door_call(arg1, (void *)arg2));
	case DOOR_RETURN: {
		door_return_desc_t *drdp = (door_return_desc_t *)arg3;

		if (drdp != NULL) {
			door_return_desc_t drd;
			if (copyin(drdp, &drd, sizeof (drd)))
				return (EFAULT);
			return (door_return((caddr_t)arg1, arg2, drd.desc_ptr,
			    drd.desc_num, (caddr_t)arg4, arg5));
		}
		return (door_return((caddr_t)arg1, arg2, NULL,
		    0, (caddr_t)arg4, arg5));
	}
	case DOOR_RETURN_OLD:
		/*
		 * In order to support the S10 runtime environment, we
		 * still respond to the old syscall subcode for door_return.
		 * We treat it as having no stack limits.  This code should
		 * be removed when such support is no longer needed.
		 */
		return (door_return((caddr_t)arg1, arg2, (door_desc_t *)arg3,
		    arg4, (caddr_t)arg5, 0));
	case DOOR_CREATE:
		return (door_create((void (*)())arg1, (void *)arg2, arg3));
	case DOOR_REVOKE:
		return (door_revoke(arg1));
	case DOOR_INFO:
		return (door_info(arg1, (struct door_info *)arg2));
	case DOOR_BIND:
		return (door_bind(arg1));
	case DOOR_UNBIND:
		return (door_unbind());
	case DOOR_UNREFSYS:
		return (door_unref());
	case DOOR_UCRED:
		return (door_ucred((struct ucred_s *)arg1));
	case DOOR_GETPARAM:
		return (door_getparam(arg1, arg2, (size_t *)arg3));
	case DOOR_SETPARAM:
		return (door_setparam(arg1, arg2, arg3));
	default:
		return (set_errno(EINVAL));
	}
}

#ifdef _SYSCALL32_IMPL
/*
 * System call wrapper for all door related system calls from 32-bit programs.
 * Needed at the moment because of the casts - they undo some damage
 * that truss causes (sign-extending the stack pointer) when truss'ing
 * a 32-bit program using doors.
 */
static int
doorfs32(int32_t arg1, int32_t arg2, int32_t arg3,
    int32_t arg4, int32_t arg5, int32_t subcode)
{
	switch (subcode) {
	case DOOR_CALL:
		return (door_call(arg1, (void *)(uintptr_t)(caddr32_t)arg2));
	case DOOR_RETURN: {
		door_return_desc32_t *drdp =
		    (door_return_desc32_t *)(uintptr_t)(caddr32_t)arg3;
		if (drdp != NULL) {
			door_return_desc32_t drd;
			if (copyin(drdp, &drd, sizeof (drd)))
				return (EFAULT);
			return (door_return(
			    (caddr_t)(uintptr_t)(caddr32_t)arg1, arg2,
			    (door_desc_t *)(uintptr_t)drd.desc_ptr,
			    drd.desc_num, (caddr_t)(uintptr_t)(caddr32_t)arg4,
			    (size_t)(uintptr_t)(size32_t)arg5));
		}
		return (door_return((caddr_t)(uintptr_t)(caddr32_t)arg1,
		    arg2, NULL, 0, (caddr_t)(uintptr_t)(caddr32_t)arg4,
		    (size_t)(uintptr_t)(size32_t)arg5));
	}
	case DOOR_RETURN_OLD:
		/*
		 * In order to support the S10 runtime environment, we
		 * still respond to the old syscall subcode for door_return.
		 * We treat it as having no stack limits.  This code should
		 * be removed when such support is no longer needed.
		 */
		return (door_return((caddr_t)(uintptr_t)(caddr32_t)arg1, arg2,
		    (door_desc_t *)(uintptr_t)(caddr32_t)arg3, arg4,
		    (caddr_t)(uintptr_t)(caddr32_t)arg5, 0));
	case DOOR_CREATE:
		return (door_create((void (*)())(uintptr_t)(caddr32_t)arg1,
		    (void *)(uintptr_t)(caddr32_t)arg2, arg3));
	case DOOR_REVOKE:
		return (door_revoke(arg1));
	case DOOR_INFO:
		return (door_info(arg1,
		    (struct door_info *)(uintptr_t)(caddr32_t)arg2));
	case DOOR_BIND:
		return (door_bind(arg1));
	case DOOR_UNBIND:
		return (door_unbind());
	case DOOR_UNREFSYS:
		return (door_unref());
	case DOOR_UCRED:
		return (door_ucred(
		    (struct ucred_s *)(uintptr_t)(caddr32_t)arg1));
	case DOOR_GETPARAM:
		return (door_getparam(arg1, arg2,
		    (size_t *)(uintptr_t)(caddr32_t)arg3));
	case DOOR_SETPARAM:
		return (door_setparam(arg1, arg2, (size_t)(size32_t)arg3));

	default:
		return (set_errno(EINVAL));
	}
}
#endif

void shuttle_resume(kthread_t *, kmutex_t *);
void shuttle_swtch(kmutex_t *);
void shuttle_sleep(kthread_t *);

/*
 * Support routines
 */
static int door_create_common(void (*)(), void *, uint_t, int, int *,
    file_t **);
static int door_overflow(kthread_t *, caddr_t, size_t, door_desc_t *, uint_t);
static int door_args(kthread_t *, int);
static int door_results(kthread_t *, caddr_t, size_t, door_desc_t *, uint_t);
static int door_copy(struct as *, caddr_t, caddr_t, uint_t);
static void	door_server_exit(proc_t *, kthread_t *);
static void	door_release_server(door_node_t *, kthread_t *);
static kthread_t	*door_get_server(door_node_t *);
static door_node_t	*door_lookup(int, file_t **);
static int	door_translate_in(void);
static int	door_translate_out(void);
static void	door_fd_rele(door_desc_t *, uint_t, int);
static void	door_list_insert(door_node_t *);
static void	door_info_common(door_node_t *, door_info_t *, file_t *);
static int	door_release_fds(door_desc_t *, uint_t);
static void	door_fd_close(door_desc_t *, uint_t);
static void	door_fp_close(struct file **, uint_t);

static door_data_t *
door_my_data(int create_if_missing)
{
	door_data_t *ddp;

	ddp = curthread->t_door;
	if (create_if_missing && ddp == NULL)
		ddp = curthread->t_door = kmem_zalloc(sizeof (*ddp), KM_SLEEP);

	return (ddp);
}

static door_server_t *
door_my_server(int create_if_missing)
{
	door_data_t *ddp = door_my_data(create_if_missing);

	return ((ddp != NULL)? DOOR_SERVER(ddp) : NULL);
}

static door_client_t *
door_my_client(int create_if_missing)
{
	door_data_t *ddp = door_my_data(create_if_missing);

	return ((ddp != NULL)? DOOR_CLIENT(ddp) : NULL);
}

/*
 * System call to create a door
 */
int
door_create(void (*pc_cookie)(), void *data_cookie, uint_t attributes)
{
	int fd;
	int err;

	if ((attributes & ~DOOR_CREATE_MASK) ||
	    ((attributes & (DOOR_UNREF | DOOR_UNREF_MULTI)) ==
	    (DOOR_UNREF | DOOR_UNREF_MULTI)))
		return (set_errno(EINVAL));

	if ((err = door_create_common(pc_cookie, data_cookie, attributes, 0,
	    &fd, NULL)) != 0)
		return (set_errno(err));

	f_setfd(fd, FD_CLOEXEC);
	return (fd);
}

/*
 * Common code for creating user and kernel doors.  If a door was
 * created, stores a file structure pointer in the location pointed
 * to by fpp (if fpp is non-NULL) and returns 0.  Also, if a non-NULL
 * pointer to a file descriptor is passed in as fdp, allocates a file
 * descriptor representing the door.  If a door could not be created,
 * returns an error.
 */
static int
door_create_common(void (*pc_cookie)(), void *data_cookie, uint_t attributes,
    int from_kernel, int *fdp, file_t **fpp)
{
	door_node_t	*dp;
	vnode_t		*vp;
	struct file	*fp;
	static door_id_t index = 0;
	proc_t		*p = (from_kernel)? &p0 : curproc;

	dp = kmem_zalloc(sizeof (door_node_t), KM_SLEEP);

	dp->door_vnode = vn_alloc(KM_SLEEP);
	dp->door_target = p;
	dp->door_data = data_cookie;
	dp->door_pc = pc_cookie;
	dp->door_flags = attributes;
#ifdef _SYSCALL32_IMPL
	if (!from_kernel && get_udatamodel() != DATAMODEL_NATIVE)
		dp->door_data_max = UINT32_MAX;
	else
#endif
		dp->door_data_max = SIZE_MAX;
	dp->door_data_min = 0UL;
	dp->door_desc_max = (attributes & DOOR_REFUSE_DESC)? 0 : INT_MAX;

	vp = DTOV(dp);
	vn_setops(vp, door_vnodeops);
	vp->v_type = VDOOR;
	vp->v_vfsp = &door_vfs;
	vp->v_data = (caddr_t)dp;
	mutex_enter(&door_knob);
	dp->door_index = index++;
	/* add to per-process door list */
	door_list_insert(dp);
	mutex_exit(&door_knob);

	if (falloc(vp, FREAD | FWRITE, &fp, fdp)) {
		/*
		 * If the file table is full, remove the door from the
		 * per-process list, free the door, and return NULL.
		 */
		mutex_enter(&door_knob);
		door_list_delete(dp);
		mutex_exit(&door_knob);
		vn_free(vp);
		kmem_free(dp, sizeof (door_node_t));
		return (EMFILE);
	}
	vn_exists(vp);
	if (fdp != NULL)
		setf(*fdp, fp);
	mutex_exit(&fp->f_tlock);

	if (fpp != NULL)
		*fpp = fp;
	return (0);
}

static int
door_check_limits(door_node_t *dp, door_arg_t *da, int upcall)
{
	ASSERT(MUTEX_HELD(&door_knob));

	/* we allow unref upcalls through, despite any minimum */
	if (da->data_size < dp->door_data_min &&
	    !(upcall && da->data_ptr == DOOR_UNREF_DATA))
		return (ENOBUFS);

	if (da->data_size > dp->door_data_max)
		return (ENOBUFS);

	if (da->desc_num > 0 && (dp->door_flags & DOOR_REFUSE_DESC))
		return (ENOTSUP);

	if (da->desc_num > dp->door_desc_max)
		return (ENFILE);

	return (0);
}

/*
 * Door invocation.
 */
int
door_call(int did, void *args)
{
	/* Locals */
	door_node_t	*dp;
	kthread_t	*server_thread;
	int		error = 0;
	klwp_t		*lwp;
	door_client_t	*ct;		/* curthread door_data */
	door_server_t	*st;		/* server thread door_data */
	door_desc_t	*start = NULL;
	uint_t		ncopied = 0;
	size_t		dsize;
	/* destructor for data returned by a kernel server */
	void		(*destfn)() = NULL;
	void		*destarg;
	model_t		datamodel;
	int		gotresults = 0;
	int		needcleanup = 0;
	int		cancel_pending;

	lwp = ttolwp(curthread);
	datamodel = lwp_getdatamodel(lwp);

	ct = door_my_client(1);

	/*
	 * Get the arguments
	 */
	if (args) {
		if (datamodel == DATAMODEL_NATIVE) {
			if (copyin(args, &ct->d_args, sizeof (door_arg_t)) != 0)
				return (set_errno(EFAULT));
		} else {
			door_arg32_t    da32;

			if (copyin(args, &da32, sizeof (door_arg32_t)) != 0)
				return (set_errno(EFAULT));
			ct->d_args.data_ptr =
			    (char *)(uintptr_t)da32.data_ptr;
			ct->d_args.data_size = da32.data_size;
			ct->d_args.desc_ptr =
			    (door_desc_t *)(uintptr_t)da32.desc_ptr;
			ct->d_args.desc_num = da32.desc_num;
			ct->d_args.rbuf =
			    (char *)(uintptr_t)da32.rbuf;
			ct->d_args.rsize = da32.rsize;
		}
	} else {
		/* No arguments, and no results allowed */
		ct->d_noresults = 1;
		ct->d_args.data_size = 0;
		ct->d_args.desc_num = 0;
		ct->d_args.rsize = 0;
	}

	if ((dp = door_lookup(did, NULL)) == NULL)
		return (set_errno(EBADF));

	/*
	 * We don't want to hold the door FD over the entire operation;
	 * instead, we put a hold on the door vnode and release the FD
	 * immediately
	 */
	VN_HOLD(DTOV(dp));
	releasef(did);

	/*
	 * This should be done in shuttle_resume(), just before going to
	 * sleep, but we want to avoid overhead while holding door_knob.
	 * prstop() is just a no-op if we don't really go to sleep.
	 * We test not-kernel-address-space for the sake of clustering code.
	 */
	if (lwp && lwp->lwp_nostop == 0 && curproc->p_as != &kas)
		prstop(PR_REQUESTED, 0);

	mutex_enter(&door_knob);
	if (DOOR_INVALID(dp)) {
		mutex_exit(&door_knob);
		error = EBADF;
		goto out;
	}

	/*
	 * before we do anything, check that we are not overflowing the
	 * required limits.
	 */
	error = door_check_limits(dp, &ct->d_args, 0);
	if (error != 0) {
		mutex_exit(&door_knob);
		goto out;
	}

	/*
	 * Check for in-kernel door server.
	 */
	if (dp->door_target == &p0) {
		caddr_t rbuf = ct->d_args.rbuf;
		size_t rsize = ct->d_args.rsize;

		dp->door_active++;
		ct->d_kernel = 1;
		ct->d_error = DOOR_WAIT;
		mutex_exit(&door_knob);
		/* translate file descriptors to vnodes */
		if (ct->d_args.desc_num) {
			error = door_translate_in();
			if (error)
				goto out;
		}
		/*
		 * Call kernel door server.  Arguments are passed and
		 * returned as a door_arg pointer.  When called, data_ptr
		 * points to user data and desc_ptr points to a kernel list
		 * of door descriptors that have been converted to file
		 * structure pointers.  It's the server function's
		 * responsibility to copyin the data pointed to by data_ptr
		 * (this avoids extra copying in some cases).  On return,
		 * data_ptr points to a user buffer of data, and desc_ptr
		 * points to a kernel list of door descriptors representing
		 * files.  When a reference is passed to a kernel server,
		 * it is the server's responsibility to release the reference
		 * (by calling closef).  When the server includes a
		 * reference in its reply, it is released as part of the
		 * the call (the server must duplicate the reference if
		 * it wants to retain a copy).  The destfn, if set to
		 * non-NULL, is a destructor to be called when the returned
		 * kernel data (if any) is no longer needed (has all been
		 * translated and copied to user level).
		 */
		(*(dp->door_pc))(dp->door_data, &ct->d_args,
		    &destfn, &destarg, &error);
		mutex_enter(&door_knob);
		/* not implemented yet */
		if (--dp->door_active == 0 && (dp->door_flags & DOOR_DELAY))
			door_deliver_unref(dp);
		mutex_exit(&door_knob);
		if (error)
			goto out;

		/* translate vnodes to files */
		if (ct->d_args.desc_num) {
			error = door_translate_out();
			if (error)
				goto out;
		}
		ct->d_buf = ct->d_args.rbuf;
		ct->d_bufsize = ct->d_args.rsize;
		if (rsize < (ct->d_args.data_size +
		    (ct->d_args.desc_num * sizeof (door_desc_t)))) {
			/* handle overflow */
			error = door_overflow(curthread, ct->d_args.data_ptr,
			    ct->d_args.data_size, ct->d_args.desc_ptr,
			    ct->d_args.desc_num);
			if (error)
				goto out;
			/* door_overflow sets d_args rbuf and rsize */
		} else {
			ct->d_args.rbuf = rbuf;
			ct->d_args.rsize = rsize;
		}
		goto results;
	}

	/*
	 * Get a server thread from the target domain
	 */
	if ((server_thread = door_get_server(dp)) == NULL) {
		if (DOOR_INVALID(dp))
			error = EBADF;
		else
			error = EAGAIN;
		mutex_exit(&door_knob);
		goto out;
	}

	st = DOOR_SERVER(server_thread->t_door);
	if (ct->d_args.desc_num || ct->d_args.data_size) {
		int is_private = (dp->door_flags & DOOR_PRIVATE);
		/*
		 * Move data from client to server
		 */
		DOOR_T_HOLD(st);
		mutex_exit(&door_knob);
		error = door_args(server_thread, is_private);
		mutex_enter(&door_knob);
		DOOR_T_RELEASE(st);
		if (error) {
			/*
			 * We're not going to resume this thread after all
			 */
			door_release_server(dp, server_thread);
			shuttle_sleep(server_thread);
			mutex_exit(&door_knob);
			goto out;
		}
	}

	dp->door_active++;
	ct->d_error = DOOR_WAIT;
	ct->d_args_done = 0;
	st->d_caller = curthread;
	st->d_active = dp;

	shuttle_resume(server_thread, &door_knob);

	mutex_enter(&door_knob);
shuttle_return:
	if ((error = ct->d_error) < 0) {	/* DOOR_WAIT or DOOR_EXIT */
		/*
		 * Premature wakeup. Find out why (stop, forkall, sig, exit ...)
		 */
		mutex_exit(&door_knob);		/* May block in ISSIG */
		cancel_pending = 0;
		if (ISSIG(curthread, FORREAL) || lwp->lwp_sysabort ||
		    MUSTRETURN(curproc, curthread) ||
		    (cancel_pending = schedctl_cancel_pending()) != 0) {
			/* Signal, forkall, ... */
			lwp->lwp_sysabort = 0;
			if (cancel_pending)
				schedctl_cancel_eintr();
			mutex_enter(&door_knob);
			error = EINTR;
			/*
			 * If the server has finished processing our call,
			 * or exited (calling door_slam()), then d_error
			 * will have changed.  If the server hasn't finished
			 * yet, d_error will still be DOOR_WAIT, and we
			 * let it know we are not interested in any
			 * results by sending a SIGCANCEL, unless the door
			 * is marked with DOOR_NO_CANCEL.
			 */
			if (ct->d_error == DOOR_WAIT &&
			    st->d_caller == curthread) {
				proc_t	*p = ttoproc(server_thread);

				st->d_active = NULL;
				st->d_caller = NULL;

				if (!(dp->door_flags & DOOR_NO_CANCEL)) {
					DOOR_T_HOLD(st);
					mutex_exit(&door_knob);

					mutex_enter(&p->p_lock);
					sigtoproc(p, server_thread, SIGCANCEL);
					mutex_exit(&p->p_lock);

					mutex_enter(&door_knob);
					DOOR_T_RELEASE(st);
				}
			}
		} else {
			/*
			 * Return from stop(), server exit...
			 *
			 * Note that the server could have done a
			 * door_return while the client was in stop state
			 * (ISSIG), in which case the error condition
			 * is updated by the server.
			 */
			mutex_enter(&door_knob);
			if (ct->d_error == DOOR_WAIT) {
				/* Still waiting for a reply */
				shuttle_swtch(&door_knob);
				mutex_enter(&door_knob);
				lwp->lwp_asleep = 0;
				goto	shuttle_return;
			} else if (ct->d_error == DOOR_EXIT) {
				/* Server exit */
				error = EINTR;
			} else {
				/* Server did a door_return during ISSIG */
				error = ct->d_error;
			}
		}
		/*
		 * Can't exit if the server is currently copying
		 * results for me.
		 */
		while (DOOR_T_HELD(ct))
			cv_wait(&ct->d_cv, &door_knob);

		/*
		 * If the server has not processed our message, free the
		 * descriptors.
		 */
		if (!ct->d_args_done) {
			needcleanup = 1;
			ct->d_args_done = 1;
		}

		/*
		 * Find out if results were successfully copied.
		 */
		if (ct->d_error == 0)
			gotresults = 1;
	}
	ASSERT(ct->d_args_done);
	lwp->lwp_asleep = 0;		/* /proc */
	lwp->lwp_sysabort = 0;		/* /proc */
	if (--dp->door_active == 0 && (dp->door_flags & DOOR_DELAY))
		door_deliver_unref(dp);
	mutex_exit(&door_knob);

	if (needcleanup)
		door_fp_close(ct->d_fpp, ct->d_args.desc_num);

results:
	/*
	 * Move the results to userland (if any)
	 */

	if (ct->d_noresults)
		goto out;

	if (error) {
		/*
		 * If server returned results successfully, then we've
		 * been interrupted and may need to clean up.
		 */
		if (gotresults) {
			ASSERT(error == EINTR);
			door_fp_close(ct->d_fpp, ct->d_args.desc_num);
		}
		goto out;
	}

	/*
	 * Copy back data if we haven't caused an overflow (already
	 * handled) and we are using a 2 copy transfer, or we are
	 * returning data from a kernel server.
	 */
	if (ct->d_args.data_size) {
		ct->d_args.data_ptr = ct->d_args.rbuf;
		if (ct->d_kernel || (!ct->d_overflow &&
		    ct->d_args.data_size <= door_max_arg)) {
			if (copyout_nowatch(ct->d_buf, ct->d_args.rbuf,
			    ct->d_args.data_size)) {
				door_fp_close(ct->d_fpp, ct->d_args.desc_num);
				error = EFAULT;
				goto out;
			}
		}
	}

	/*
	 * stuff returned doors into our proc, copyout the descriptors
	 */
	if (ct->d_args.desc_num) {
		struct file	**fpp;
		door_desc_t	*didpp;
		uint_t		n = ct->d_args.desc_num;

		dsize = n * sizeof (door_desc_t);
		start = didpp = kmem_alloc(dsize, KM_SLEEP);
		fpp = ct->d_fpp;

		while (n--) {
			if (door_insert(*fpp, didpp) == -1) {
				/* Close remaining files */
				door_fp_close(fpp, n + 1);
				error = EMFILE;
				goto out;
			}
			fpp++; didpp++; ncopied++;
		}

		ct->d_args.desc_ptr = (door_desc_t *)(ct->d_args.rbuf +
		    roundup(ct->d_args.data_size, sizeof (door_desc_t)));

		if (copyout_nowatch(start, ct->d_args.desc_ptr, dsize)) {
			error = EFAULT;
			goto out;
		}
	}

	/*
	 * Return the results
	 */
	if (datamodel == DATAMODEL_NATIVE) {
		if (copyout_nowatch(&ct->d_args, args,
		    sizeof (door_arg_t)) != 0)
			error = EFAULT;
	} else {
		door_arg32_t    da32;

		da32.data_ptr = (caddr32_t)(uintptr_t)ct->d_args.data_ptr;
		da32.data_size = ct->d_args.data_size;
		da32.desc_ptr = (caddr32_t)(uintptr_t)ct->d_args.desc_ptr;
		da32.desc_num = ct->d_args.desc_num;
		da32.rbuf = (caddr32_t)(uintptr_t)ct->d_args.rbuf;
		da32.rsize = ct->d_args.rsize;
		if (copyout_nowatch(&da32, args, sizeof (door_arg32_t)) != 0) {
			error = EFAULT;
		}
	}

out:
	ct->d_noresults = 0;

	/* clean up the overflow buffer if an error occurred */
	if (error != 0 && ct->d_overflow) {
		(void) as_unmap(curproc->p_as, ct->d_args.rbuf,
		    ct->d_args.rsize);
	}
	ct->d_overflow = 0;

	/* call destructor */
	if (destfn) {
		ASSERT(ct->d_kernel);
		(*destfn)(dp->door_data, destarg);
		ct->d_buf = NULL;
		ct->d_bufsize = 0;
	}

	if (dp)
		VN_RELE(DTOV(dp));

	if (ct->d_buf) {
		ASSERT(!ct->d_kernel);
		kmem_free(ct->d_buf, ct->d_bufsize);
		ct->d_buf = NULL;
		ct->d_bufsize = 0;
	}
	ct->d_kernel = 0;

	/* clean up the descriptor copyout buffer */
	if (start != NULL) {
		if (error != 0)
			door_fd_close(start, ncopied);
		kmem_free(start, dsize);
	}

	if (ct->d_fpp) {
		kmem_free(ct->d_fpp, ct->d_fpp_size);
		ct->d_fpp = NULL;
		ct->d_fpp_size = 0;
	}

	if (error)
		return (set_errno(error));

	return (0);
}

static int
door_setparam_common(door_node_t *dp, int from_kernel, int type, size_t val)
{
	int error = 0;

	mutex_enter(&door_knob);

	if (DOOR_INVALID(dp)) {
		mutex_exit(&door_knob);
		return (EBADF);
	}

	/*
	 * door_ki_setparam() can only affect kernel doors.
	 * door_setparam() can only affect doors attached to the current
	 * process.
	 */
	if ((from_kernel && dp->door_target != &p0) ||
	    (!from_kernel && dp->door_target != curproc)) {
		mutex_exit(&door_knob);
		return (EPERM);
	}

	switch (type) {
	case DOOR_PARAM_DESC_MAX:
		if (val > INT_MAX)
			error = ERANGE;
		else if ((dp->door_flags & DOOR_REFUSE_DESC) && val != 0)
			error = ENOTSUP;
		else
			dp->door_desc_max = (uint_t)val;
		break;

	case DOOR_PARAM_DATA_MIN:
		if (val > dp->door_data_max)
			error = EINVAL;
		else
			dp->door_data_min = val;
		break;

	case DOOR_PARAM_DATA_MAX:
		if (val < dp->door_data_min)
			error = EINVAL;
		else
			dp->door_data_max = val;
		break;

	default:
		error = EINVAL;
		break;
	}

	mutex_exit(&door_knob);
	return (error);
}

static int
door_getparam_common(door_node_t *dp, int type, size_t *out)
{
	int error = 0;

	mutex_enter(&door_knob);
	switch (type) {
	case DOOR_PARAM_DESC_MAX:
		*out = (size_t)dp->door_desc_max;
		break;
	case DOOR_PARAM_DATA_MIN:
		*out = dp->door_data_min;
		break;
	case DOOR_PARAM_DATA_MAX:
		*out = dp->door_data_max;
		break;
	default:
		error = EINVAL;
		break;
	}
	mutex_exit(&door_knob);
	return (error);
}

int
door_setparam(int did, int type, size_t val)
{
	door_node_t *dp;
	int error = 0;

	if ((dp = door_lookup(did, NULL)) == NULL)
		return (set_errno(EBADF));

	error = door_setparam_common(dp, 0, type, val);

	releasef(did);

	if (error)
		return (set_errno(error));

	return (0);
}

int
door_getparam(int did, int type, size_t *out)
{
	door_node_t *dp;
	size_t val = 0;
	int error = 0;

	if ((dp = door_lookup(did, NULL)) == NULL)
		return (set_errno(EBADF));

	error = door_getparam_common(dp, type, &val);

	releasef(did);

	if (error)
		return (set_errno(error));

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&val, out, sizeof (val)))
			return (set_errno(EFAULT));
#ifdef _SYSCALL32_IMPL
	} else {
		size32_t val32 = (size32_t)val;

		if (val != val32)
			return (set_errno(EOVERFLOW));

		if (copyout(&val32, out, sizeof (val32)))
			return (set_errno(EFAULT));
#endif /* _SYSCALL32_IMPL */
	}

	return (0);
}

/*
 * A copyout() which proceeds from high addresses to low addresses.  This way,
 * stack guard pages are effective.
 *
 * Note that we use copyout_nowatch();  this is called while the client is
 * held.
 */
static int
door_stack_copyout(const void *kaddr, void *uaddr, size_t count)
{
	const char *kbase = (const char *)kaddr;
	uintptr_t ubase = (uintptr_t)uaddr;
	size_t pgsize = PAGESIZE;

	if (count <= pgsize)
		return (copyout_nowatch(kaddr, uaddr, count));

	while (count > 0) {
		uintptr_t start, end, offset, amount;

		end = ubase + count;
		start = P2ALIGN(end - 1, pgsize);
		if (P2ALIGN(ubase, pgsize) == start)
			start = ubase;

		offset = start - ubase;
		amount = end - start;

		ASSERT(amount > 0 && amount <= count && amount <= pgsize);

		if (copyout_nowatch(kbase + offset, (void *)start, amount))
			return (1);
		count -= amount;
	}
	return (0);
}

/*
 * Writes the stack layout for door_return() into the door_server_t of the
 * server thread.
 */
static int
door_layout(kthread_t *tp, size_t data_size, uint_t ndesc, int info_needed)
{
	door_server_t *st = DOOR_SERVER(tp->t_door);
	door_layout_t *out = &st->d_layout;
	uintptr_t base_sp = (uintptr_t)st->d_sp;
	size_t ssize = st->d_ssize;
	size_t descsz;
	uintptr_t descp, datap, infop, resultsp, finalsp;
	size_t align = STACK_ALIGN;
	size_t results_sz = sizeof (struct door_results);
	model_t datamodel = lwp_getdatamodel(ttolwp(tp));

	ASSERT(!st->d_layout_done);

#ifndef _STACK_GROWS_DOWNWARD
#error stack does not grow downward, door_layout() must change
#endif

#ifdef _SYSCALL32_IMPL
	if (datamodel != DATAMODEL_NATIVE) {
		align = STACK_ALIGN32;
		results_sz = sizeof (struct door_results32);
	}
#endif

	descsz = ndesc * sizeof (door_desc_t);

	/*
	 * To speed up the overflow checking, we do an initial check
	 * that the passed in data size won't cause us to wrap past
	 * base_sp.  Since door_max_desc limits descsz, we can
	 * safely use it here.  65535 is an arbitrary 'bigger than
	 * we need, small enough to not cause trouble' constant;
	 * the only constraint is that it must be > than:
	 *
	 *	5 * STACK_ALIGN +
	 *	    sizeof (door_info_t) +
	 *	    sizeof (door_results_t) +
	 *	    (max adjustment from door_final_sp())
	 *
	 * After we compute the layout, we can safely do a "did we wrap
	 * around" check, followed by a check against the recorded
	 * stack size.
	 */
	if (data_size >= SIZE_MAX - (size_t)65535UL - descsz)
		return (E2BIG);		/* overflow */

	descp = P2ALIGN(base_sp - descsz, align);
	datap = P2ALIGN(descp - data_size, align);

	if (info_needed)
		infop = P2ALIGN(datap - sizeof (door_info_t), align);
	else
		infop = datap;

	resultsp = P2ALIGN(infop - results_sz, align);
	finalsp = door_final_sp(resultsp, align, datamodel);

	if (finalsp > base_sp)
		return (E2BIG);		/* overflow */

	if (ssize != 0 && (base_sp - finalsp) > ssize)
		return (E2BIG);		/* doesn't fit in stack */

	out->dl_descp = (ndesc != 0)? (caddr_t)descp : 0;
	out->dl_datap = (data_size != 0)? (caddr_t)datap : 0;
	out->dl_infop = info_needed? (caddr_t)infop : 0;
	out->dl_resultsp = (caddr_t)resultsp;
	out->dl_sp = (caddr_t)finalsp;

	st->d_layout_done = 1;
	return (0);
}

static int
door_server_dispatch(door_client_t *ct, door_node_t *dp)
{
	door_server_t *st = DOOR_SERVER(curthread->t_door);
	door_layout_t *layout = &st->d_layout;
	int error = 0;

	int is_private = (dp->door_flags & DOOR_PRIVATE);

	door_pool_t *pool = (is_private)? &dp->door_servers :
	    &curproc->p_server_threads;

	int empty_pool = (pool->dp_threads == NULL);

	caddr_t infop = NULL;
	char *datap = NULL;
	size_t datasize = 0;
	size_t descsize;

	file_t **fpp = ct->d_fpp;
	door_desc_t *start = NULL;
	uint_t ndesc = 0;
	uint_t ncopied = 0;

	if (ct != NULL) {
		datap = ct->d_args.data_ptr;
		datasize = ct->d_args.data_size;
		ndesc = ct->d_args.desc_num;
	}

	descsize = ndesc * sizeof (door_desc_t);

	/*
	 * Reset datap to NULL if we aren't passing any data.  Be careful
	 * to let unref notifications through, though.
	 */
	if (datap == DOOR_UNREF_DATA) {
		if (ct->d_upcall != NULL)
			datasize = 0;
		else
			datap = NULL;
	} else if (datasize == 0) {
		datap = NULL;
	}

	/*
	 * Get the stack layout, if it hasn't already been done.
	 */
	if (!st->d_layout_done) {
		error = door_layout(curthread, datasize, ndesc,
		    (is_private && empty_pool));
		if (error != 0)
			goto fail;
	}

	/*
	 * fill out the stack, starting from the top.  Layout was already
	 * filled in by door_args() or door_translate_out().
	 */
	if (layout->dl_descp != NULL) {
		ASSERT(ndesc != 0);
		start = kmem_alloc(descsize, KM_SLEEP);

		while (ndesc > 0) {
			if (door_insert(*fpp, &start[ncopied]) == -1) {
				error = EMFILE;
				goto fail;
			}
			ndesc--;
			ncopied++;
			fpp++;
		}
		if (door_stack_copyout(start, layout->dl_descp, descsize)) {
			error = E2BIG;
			goto fail;
		}
	}
	fpp = NULL;			/* finished processing */

	if (layout->dl_datap != NULL) {
		ASSERT(datasize != 0);
		datap = layout->dl_datap;
		if (ct->d_upcall != NULL || datasize <= door_max_arg) {
			if (door_stack_copyout(ct->d_buf, datap, datasize)) {
				error = E2BIG;
				goto fail;
			}
		}
	}

	if (is_private && empty_pool) {
		door_info_t di;

		infop = layout->dl_infop;
		ASSERT(infop != NULL);

		di.di_target = curproc->p_pid;
		di.di_proc = (door_ptr_t)(uintptr_t)dp->door_pc;
		di.di_data = (door_ptr_t)(uintptr_t)dp->door_data;
		di.di_uniquifier = dp->door_index;
		di.di_attributes = (dp->door_flags & DOOR_ATTR_MASK) |
		    DOOR_LOCAL;

		if (door_stack_copyout(&di, infop, sizeof (di))) {
			error = E2BIG;
			goto fail;
		}
	}

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		struct door_results dr;

		dr.cookie = dp->door_data;
		dr.data_ptr = datap;
		dr.data_size = datasize;
		dr.desc_ptr = (door_desc_t *)layout->dl_descp;
		dr.desc_num = ncopied;
		dr.pc = dp->door_pc;
		dr.nservers = !empty_pool;
		dr.door_info = (door_info_t *)infop;

		if (door_stack_copyout(&dr, layout->dl_resultsp, sizeof (dr))) {
			error = E2BIG;
			goto fail;
		}
#ifdef _SYSCALL32_IMPL
	} else {
		struct door_results32 dr32;

		dr32.cookie = (caddr32_t)(uintptr_t)dp->door_data;
		dr32.data_ptr = (caddr32_t)(uintptr_t)datap;
		dr32.data_size = (size32_t)datasize;
		dr32.desc_ptr = (caddr32_t)(uintptr_t)layout->dl_descp;
		dr32.desc_num = ncopied;
		dr32.pc = (caddr32_t)(uintptr_t)dp->door_pc;
		dr32.nservers = !empty_pool;
		dr32.door_info = (caddr32_t)(uintptr_t)infop;

		if (door_stack_copyout(&dr32, layout->dl_resultsp,
		    sizeof (dr32))) {
			error = E2BIG;
			goto fail;
		}
#endif
	}

	error = door_finish_dispatch(layout->dl_sp);
fail:
	if (start != NULL) {
		if (error != 0)
			door_fd_close(start, ncopied);
		kmem_free(start, descsize);
	}
	if (fpp != NULL)
		door_fp_close(fpp, ndesc);

	return (error);
}

/*
 * Return the results (if any) to the caller (if any) and wait for the
 * next invocation on a door.
 */
int
door_return(caddr_t data_ptr, size_t data_size,
    door_desc_t *desc_ptr, uint_t desc_num, caddr_t sp, size_t ssize)
{
	kthread_t	*caller;
	klwp_t		*lwp;
	int		error = 0;
	door_node_t	*dp;
	door_server_t	*st;		/* curthread door_data */
	door_client_t	*ct;		/* caller door_data */
	int		cancel_pending;

	st = door_my_server(1);

	/*
	 * If thread was bound to a door that no longer exists, return
	 * an error.  This can happen if a thread is bound to a door
	 * before the process calls forkall(); in the child, the door
	 * doesn't exist and door_fork() sets the d_invbound flag.
	 */
	if (st->d_invbound)
		return (set_errno(EINVAL));

	st->d_sp = sp;			/* Save base of stack. */
	st->d_ssize = ssize;		/* and its size */

	/*
	 * This should be done in shuttle_resume(), just before going to
	 * sleep, but we want to avoid overhead while holding door_knob.
	 * prstop() is just a no-op if we don't really go to sleep.
	 * We test not-kernel-address-space for the sake of clustering code.
	 */
	lwp = ttolwp(curthread);
	if (lwp && lwp->lwp_nostop == 0 && curproc->p_as != &kas)
		prstop(PR_REQUESTED, 0);

	/* Make sure the caller hasn't gone away */
	mutex_enter(&door_knob);
	if ((caller = st->d_caller) == NULL || caller->t_door == NULL) {
		if (desc_num != 0) {
			/* close any DOOR_RELEASE descriptors */
			mutex_exit(&door_knob);
			error = door_release_fds(desc_ptr, desc_num);
			if (error)
				return (set_errno(error));
			mutex_enter(&door_knob);
		}
		goto out;
	}
	ct = DOOR_CLIENT(caller->t_door);

	ct->d_args.data_size = data_size;
	ct->d_args.desc_num = desc_num;
	/*
	 * Transfer results, if any, to the client
	 */
	if (data_size != 0 || desc_num != 0) {
		/*
		 * Prevent the client from exiting until we have finished
		 * moving results.
		 */
		DOOR_T_HOLD(ct);
		mutex_exit(&door_knob);
		error = door_results(caller, data_ptr, data_size,
		    desc_ptr, desc_num);
		mutex_enter(&door_knob);
		DOOR_T_RELEASE(ct);
		/*
		 * Pass EOVERFLOW errors back to the client
		 */
		if (error && error != EOVERFLOW) {
			mutex_exit(&door_knob);
			return (set_errno(error));
		}
	}
out:
	/* Put ourselves on the available server thread list */
	door_release_server(st->d_pool, curthread);

	/*
	 * Make sure the caller is still waiting to be resumed
	 */
	if (caller) {
		disp_lock_t *tlp;

		thread_lock(caller);
		ct->d_error = error;		/* Return any errors */
		if (caller->t_state == TS_SLEEP &&
		    SOBJ_TYPE(caller->t_sobj_ops) == SOBJ_SHUTTLE) {
			cpu_t *cp = CPU;

			tlp = caller->t_lockp;
			/*
			 * Setting t_disp_queue prevents erroneous preemptions
			 * if this thread is still in execution on another
			 * processor
			 */
			caller->t_disp_queue = cp->cpu_disp;
			CL_ACTIVE(caller);
			/*
			 * We are calling thread_onproc() instead of
			 * THREAD_ONPROC() because compiler can reorder
			 * the two stores of t_state and t_lockp in
			 * THREAD_ONPROC().
			 */
			thread_onproc(caller, cp);
			disp_lock_exit_high(tlp);
			shuttle_resume(caller, &door_knob);
		} else {
			/* May have been setrun or in stop state */
			thread_unlock(caller);
			shuttle_swtch(&door_knob);
		}
	} else {
		shuttle_swtch(&door_knob);
	}

	/*
	 * We've sprung to life. Determine if we are part of a door
	 * invocation, or just interrupted
	 */
	mutex_enter(&door_knob);
	if ((dp = st->d_active) != NULL) {
		/*
		 * Normal door invocation. Return any error condition
		 * encountered while trying to pass args to the server
		 * thread.
		 */
		lwp->lwp_asleep = 0;
		/*
		 * Prevent the caller from leaving us while we
		 * are copying out the arguments from it's buffer.
		 */
		ASSERT(st->d_caller != NULL);
		ct = DOOR_CLIENT(st->d_caller->t_door);

		DOOR_T_HOLD(ct);
		mutex_exit(&door_knob);
		error = door_server_dispatch(ct, dp);
		mutex_enter(&door_knob);
		DOOR_T_RELEASE(ct);

		/* let the client know we have processed his message */
		ct->d_args_done = 1;

		if (error) {
			caller = st->d_caller;
			if (caller)
				ct = DOOR_CLIENT(caller->t_door);
			else
				ct = NULL;
			goto out;
		}
		mutex_exit(&door_knob);
		return (0);
	} else {
		/*
		 * We are not involved in a door_invocation.
		 * Check for /proc related activity...
		 */
		st->d_caller = NULL;
		door_server_exit(curproc, curthread);
		mutex_exit(&door_knob);
		cancel_pending = 0;
		if (ISSIG(curthread, FORREAL) || lwp->lwp_sysabort ||
		    MUSTRETURN(curproc, curthread) ||
		    (cancel_pending = schedctl_cancel_pending()) != 0) {
			if (cancel_pending)
				schedctl_cancel_eintr();
			lwp->lwp_asleep = 0;
			lwp->lwp_sysabort = 0;
			return (set_errno(EINTR));
		}
		/* Go back and wait for another request */
		lwp->lwp_asleep = 0;
		mutex_enter(&door_knob);
		caller = NULL;
		goto out;
	}
}

/*
 * Revoke any future invocations on this door
 */
int
door_revoke(int did)
{
	door_node_t	*d;
	int		error;

	if ((d = door_lookup(did, NULL)) == NULL)
		return (set_errno(EBADF));

	mutex_enter(&door_knob);
	if (d->door_target != curproc) {
		mutex_exit(&door_knob);
		releasef(did);
		return (set_errno(EPERM));
	}
	d->door_flags |= DOOR_REVOKED;
	if (d->door_flags & DOOR_PRIVATE)
		cv_broadcast(&d->door_servers.dp_cv);
	else
		cv_broadcast(&curproc->p_server_threads.dp_cv);
	mutex_exit(&door_knob);
	releasef(did);
	/* Invalidate the descriptor */
	if ((error = closeandsetf(did, NULL)) != 0)
		return (set_errno(error));
	return (0);
}

int
door_info(int did, struct door_info *d_info)
{
	door_node_t	*dp;
	door_info_t	di;
	door_server_t	*st;
	file_t		*fp = NULL;

	if (did == DOOR_QUERY) {
		/* Get information on door current thread is bound to */
		if ((st = door_my_server(0)) == NULL ||
		    (dp = st->d_pool) == NULL)
			/* Thread isn't bound to a door */
			return (set_errno(EBADF));
	} else if ((dp = door_lookup(did, &fp)) == NULL) {
		/* Not a door */
		return (set_errno(EBADF));
	}

	door_info_common(dp, &di, fp);

	if (did != DOOR_QUERY)
		releasef(did);

	if (copyout(&di, d_info, sizeof (struct door_info)))
		return (set_errno(EFAULT));
	return (0);
}

/*
 * Common code for getting information about a door either via the
 * door_info system call or the door_ki_info kernel call.
 */
void
door_info_common(door_node_t *dp, struct door_info *dip, file_t *fp)
{
	int unref_count;

	bzero(dip, sizeof (door_info_t));

	mutex_enter(&door_knob);
	if (dp->door_target == NULL)
		dip->di_target = -1;
	else
		dip->di_target = dp->door_target->p_pid;

	dip->di_attributes = dp->door_flags & DOOR_ATTR_MASK;
	if (dp->door_target == curproc)
		dip->di_attributes |= DOOR_LOCAL;
	dip->di_proc = (door_ptr_t)(uintptr_t)dp->door_pc;
	dip->di_data = (door_ptr_t)(uintptr_t)dp->door_data;
	dip->di_uniquifier = dp->door_index;
	/*
	 * If this door is in the middle of having an unreferenced
	 * notification delivered, don't count the VN_HOLD by
	 * door_deliver_unref in determining if it is unreferenced.
	 * This handles the case where door_info is called from the
	 * thread delivering the unref notification.
	 */
	if (dp->door_flags & DOOR_UNREF_ACTIVE)
		unref_count = 2;
	else
		unref_count = 1;
	mutex_exit(&door_knob);

	if (fp == NULL) {
		/*
		 * If this thread is bound to the door, then we can just
		 * check the vnode; a ref count of 1 (or 2 if this is
		 * handling an unref notification) means that the hold
		 * from the door_bind is the only reference to the door
		 * (no file descriptor refers to it).
		 */
		if (DTOV(dp)->v_count == unref_count)
			dip->di_attributes |= DOOR_IS_UNREF;
	} else {
		/*
		 * If we're working from a file descriptor or door handle
		 * we need to look at the file structure count.  We don't
		 * need to hold the vnode lock since this is just a snapshot.
		 */
		mutex_enter(&fp->f_tlock);
		if (fp->f_count == 1 && DTOV(dp)->v_count == unref_count)
			dip->di_attributes |= DOOR_IS_UNREF;
		mutex_exit(&fp->f_tlock);
	}
}

/*
 * Return credentials of the door caller (if any) for this invocation
 */
int
door_ucred(struct ucred_s *uch)
{
	kthread_t	*caller;
	door_server_t	*st;
	door_client_t	*ct;
	door_upcall_t	*dup;
	struct proc	*p;
	struct ucred_s	*res;
	int		err;

	mutex_enter(&door_knob);
	if ((st = door_my_server(0)) == NULL ||
	    (caller = st->d_caller) == NULL) {
		mutex_exit(&door_knob);
		return (set_errno(EINVAL));
	}

	ASSERT(caller->t_door != NULL);
	ct = DOOR_CLIENT(caller->t_door);

	/* Prevent caller from exiting while we examine the cred */
	DOOR_T_HOLD(ct);
	mutex_exit(&door_knob);

	p = ttoproc(caller);

	/*
	 * If the credentials are not specified by the client, get the one
	 * associated with the calling process.
	 */
	if ((dup = ct->d_upcall) != NULL)
		res = cred2ucred(dup->du_cred, p0.p_pid, NULL, CRED());
	else
		res = cred2ucred(caller->t_cred, p->p_pid, NULL, CRED());

	mutex_enter(&door_knob);
	DOOR_T_RELEASE(ct);
	mutex_exit(&door_knob);

	err = copyout(res, uch, res->uc_size);

	kmem_free(res, res->uc_size);

	if (err != 0)
		return (set_errno(EFAULT));

	return (0);
}

/*
 * Bind the current lwp to the server thread pool associated with 'did'
 */
int
door_bind(int did)
{
	door_node_t	*dp;
	door_server_t	*st;

	if ((dp = door_lookup(did, NULL)) == NULL) {
		/* Not a door */
		return (set_errno(EBADF));
	}

	/*
	 * Can't bind to a non-private door, and can't bind to a door
	 * served by another process.
	 */
	if ((dp->door_flags & DOOR_PRIVATE) == 0 ||
	    dp->door_target != curproc) {
		releasef(did);
		return (set_errno(EINVAL));
	}

	st = door_my_server(1);
	if (st->d_pool)
		door_unbind_thread(st->d_pool);
	st->d_pool = dp;
	st->d_invbound = 0;
	door_bind_thread(dp);
	releasef(did);

	return (0);
}

/*
 * Unbind the current lwp from it's server thread pool
 */
int
door_unbind(void)
{
	door_server_t *st;

	if ((st = door_my_server(0)) == NULL)
		return (set_errno(EBADF));

	if (st->d_invbound) {
		ASSERT(st->d_pool == NULL);
		st->d_invbound = 0;
		return (0);
	}
	if (st->d_pool == NULL)
		return (set_errno(EBADF));
	door_unbind_thread(st->d_pool);
	st->d_pool = NULL;
	return (0);
}

/*
 * Create a descriptor for the associated file and fill in the
 * attributes associated with it.
 *
 * Return 0 for success, -1 otherwise;
 */
int
door_insert(struct file *fp, door_desc_t *dp)
{
	struct vnode *vp;
	int	fd;
	door_attr_t attributes = DOOR_DESCRIPTOR;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	if ((fd = ufalloc(0)) == -1)
		return (-1);
	setf(fd, fp);
	dp->d_data.d_desc.d_descriptor = fd;

	/* Fill in the attributes */
	if (VOP_REALVP(fp->f_vnode, &vp, NULL))
		vp = fp->f_vnode;
	if (vp && vp->v_type == VDOOR) {
		if (VTOD(vp)->door_target == curproc)
			attributes |= DOOR_LOCAL;
		attributes |= VTOD(vp)->door_flags & DOOR_ATTR_MASK;
		dp->d_data.d_desc.d_id = VTOD(vp)->door_index;
	}
	dp->d_attributes = attributes;
	return (0);
}

/*
 * Return an available thread for this server.  A NULL return value indicates
 * that either:
 *	The door has been revoked, or
 *	a signal was received.
 * The two conditions can be differentiated using DOOR_INVALID(dp).
 */
static kthread_t *
door_get_server(door_node_t *dp)
{
	kthread_t **ktp;
	kthread_t *server_t;
	door_pool_t *pool;
	door_server_t *st;
	int signalled;

	disp_lock_t *tlp;
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&door_knob));

	if (dp->door_flags & DOOR_PRIVATE)
		pool = &dp->door_servers;
	else
		pool = &dp->door_target->p_server_threads;

	for (;;) {
		/*
		 * We search the thread pool, looking for a server thread
		 * ready to take an invocation (i.e. one which is still
		 * sleeping on a shuttle object).  If none are available,
		 * we sleep on the pool's CV, and will be signaled when a
		 * thread is added to the pool.
		 *
		 * This relies on the fact that once a thread in the thread
		 * pool wakes up, it *must* remove and add itself to the pool
		 * before it can receive door calls.
		 */
		if (DOOR_INVALID(dp))
			return (NULL);	/* Target has become invalid */

		for (ktp = &pool->dp_threads;
		    (server_t = *ktp) != NULL;
		    ktp = &st->d_servers) {
			st = DOOR_SERVER(server_t->t_door);

			thread_lock(server_t);
			if (server_t->t_state == TS_SLEEP &&
			    SOBJ_TYPE(server_t->t_sobj_ops) == SOBJ_SHUTTLE)
				break;
			thread_unlock(server_t);
		}
		if (server_t != NULL)
			break;		/* we've got a live one! */

		if (!cv_wait_sig_swap_core(&pool->dp_cv, &door_knob,
		    &signalled)) {
			/*
			 * If we were signaled and the door is still
			 * valid, pass the signal on to another waiter.
			 */
			if (signalled && !DOOR_INVALID(dp))
				cv_signal(&pool->dp_cv);
			return (NULL);	/* Got a signal */
		}
	}

	/*
	 * We've got a thread_lock()ed thread which is still on the
	 * shuttle.  Take it off the list of available server threads
	 * and mark it as ONPROC.  We are committed to resuming this
	 * thread now.
	 */
	tlp = server_t->t_lockp;
	cp = CPU;

	*ktp = st->d_servers;
	st->d_servers = NULL;
	/*
	 * Setting t_disp_queue prevents erroneous preemptions
	 * if this thread is still in execution on another processor
	 */
	server_t->t_disp_queue = cp->cpu_disp;
	CL_ACTIVE(server_t);
	/*
	 * We are calling thread_onproc() instead of
	 * THREAD_ONPROC() because compiler can reorder
	 * the two stores of t_state and t_lockp in
	 * THREAD_ONPROC().
	 */
	thread_onproc(server_t, cp);
	disp_lock_exit(tlp);
	return (server_t);
}

/*
 * Put a server thread back in the pool.
 */
static void
door_release_server(door_node_t *dp, kthread_t *t)
{
	door_server_t *st = DOOR_SERVER(t->t_door);
	door_pool_t *pool;

	ASSERT(MUTEX_HELD(&door_knob));
	st->d_active = NULL;
	st->d_caller = NULL;
	st->d_layout_done = 0;
	if (dp && (dp->door_flags & DOOR_PRIVATE)) {
		ASSERT(dp->door_target == NULL ||
		    dp->door_target == ttoproc(t));
		pool = &dp->door_servers;
	} else {
		pool = &ttoproc(t)->p_server_threads;
	}

	st->d_servers = pool->dp_threads;
	pool->dp_threads = t;

	/* If someone is waiting for a server thread, wake him up */
	cv_signal(&pool->dp_cv);
}

/*
 * Remove a server thread from the pool if present.
 */
static void
door_server_exit(proc_t *p, kthread_t *t)
{
	door_pool_t *pool;
	kthread_t **next;
	door_server_t *st = DOOR_SERVER(t->t_door);

	ASSERT(MUTEX_HELD(&door_knob));
	if (st->d_pool != NULL) {
		ASSERT(st->d_pool->door_flags & DOOR_PRIVATE);
		pool = &st->d_pool->door_servers;
	} else {
		pool = &p->p_server_threads;
	}

	next = &pool->dp_threads;
	while (*next != NULL) {
		if (*next == t) {
			*next = DOOR_SERVER(t->t_door)->d_servers;
			return;
		}
		next = &(DOOR_SERVER((*next)->t_door)->d_servers);
	}
}

/*
 * Lookup the door descriptor. Caller must call releasef when finished
 * with associated door.
 */
static door_node_t *
door_lookup(int did, file_t **fpp)
{
	vnode_t	*vp;
	file_t *fp;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	if ((fp = getf(did)) == NULL)
		return (NULL);
	/*
	 * Use the underlying vnode (we may be namefs mounted)
	 */
	if (VOP_REALVP(fp->f_vnode, &vp, NULL))
		vp = fp->f_vnode;

	if (vp == NULL || vp->v_type != VDOOR) {
		releasef(did);
		return (NULL);
	}

	if (fpp)
		*fpp = fp;

	return (VTOD(vp));
}

/*
 * The current thread is exiting, so clean up any pending
 * invocation details
 */
void
door_slam(void)
{
	door_node_t *dp;
	door_data_t *dt;
	door_client_t *ct;
	door_server_t *st;

	/*
	 * If we are an active door server, notify our
	 * client that we are exiting and revoke our door.
	 */
	if ((dt = door_my_data(0)) == NULL)
		return;
	ct = DOOR_CLIENT(dt);
	st = DOOR_SERVER(dt);

	mutex_enter(&door_knob);
	for (;;) {
		if (DOOR_T_HELD(ct))
			cv_wait(&ct->d_cv, &door_knob);
		else if (DOOR_T_HELD(st))
			cv_wait(&st->d_cv, &door_knob);
		else
			break;			/* neither flag is set */
	}
	curthread->t_door = NULL;
	if ((dp = st->d_active) != NULL) {
		kthread_t *t = st->d_caller;
		proc_t *p = curproc;

		/* Revoke our door if the process is exiting */
		if (dp->door_target == p && (p->p_flag & SEXITING)) {
			door_list_delete(dp);
			dp->door_target = NULL;
			dp->door_flags |= DOOR_REVOKED;
			if (dp->door_flags & DOOR_PRIVATE)
				cv_broadcast(&dp->door_servers.dp_cv);
			else
				cv_broadcast(&p->p_server_threads.dp_cv);
		}

		if (t != NULL) {
			/*
			 * Let the caller know we are gone
			 */
			DOOR_CLIENT(t->t_door)->d_error = DOOR_EXIT;
			thread_lock(t);
			if (t->t_state == TS_SLEEP &&
			    SOBJ_TYPE(t->t_sobj_ops) == SOBJ_SHUTTLE)
				setrun_locked(t);
			thread_unlock(t);
		}
	}
	mutex_exit(&door_knob);
	if (st->d_pool)
		door_unbind_thread(st->d_pool);	/* Implicit door_unbind */
	kmem_free(dt, sizeof (door_data_t));
}

/*
 * Set DOOR_REVOKED for all doors of the current process. This is called
 * on exit before all lwp's are being terminated so that door calls will
 * return with an error.
 */
void
door_revoke_all()
{
	door_node_t *dp;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&door_knob);
	for (dp = p->p_door_list; dp != NULL; dp = dp->door_list) {
		ASSERT(dp->door_target == p);
		dp->door_flags |= DOOR_REVOKED;
		if (dp->door_flags & DOOR_PRIVATE)
			cv_broadcast(&dp->door_servers.dp_cv);
	}
	cv_broadcast(&p->p_server_threads.dp_cv);
	mutex_exit(&door_knob);
}

/*
 * The process is exiting, and all doors it created need to be revoked.
 */
void
door_exit(void)
{
	door_node_t *dp;
	proc_t *p = ttoproc(curthread);

	ASSERT(p->p_lwpcnt == 1);
	/*
	 * Walk the list of active doors created by this process and
	 * revoke them all.
	 */
	mutex_enter(&door_knob);
	for (dp = p->p_door_list; dp != NULL; dp = dp->door_list) {
		dp->door_target = NULL;
		dp->door_flags |= DOOR_REVOKED;
		if (dp->door_flags & DOOR_PRIVATE)
			cv_broadcast(&dp->door_servers.dp_cv);
	}
	cv_broadcast(&p->p_server_threads.dp_cv);
	/* Clear the list */
	p->p_door_list = NULL;

	/* Clean up the unref list */
	while ((dp = p->p_unref_list) != NULL) {
		p->p_unref_list = dp->door_ulist;
		dp->door_ulist = NULL;
		mutex_exit(&door_knob);
		VN_RELE(DTOV(dp));
		mutex_enter(&door_knob);
	}
	mutex_exit(&door_knob);
}


/*
 * The process is executing forkall(), and we need to flag threads that
 * are bound to a door in the child.  This will make the child threads
 * return an error to door_return unless they call door_unbind first.
 */
void
door_fork(kthread_t *parent, kthread_t *child)
{
	door_data_t *pt = parent->t_door;
	door_server_t *st = DOOR_SERVER(pt);
	door_data_t *dt;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	if (pt != NULL && (st->d_pool != NULL || st->d_invbound)) {
		/* parent thread is bound to a door */
		dt = child->t_door =
		    kmem_zalloc(sizeof (door_data_t), KM_SLEEP);
		DOOR_SERVER(dt)->d_invbound = 1;
	}
}

/*
 * Deliver queued unrefs to appropriate door server.
 */
static int
door_unref(void)
{
	door_node_t	*dp;
	static door_arg_t unref_args = { DOOR_UNREF_DATA, 0, 0, 0, 0, 0 };
	proc_t *p = ttoproc(curthread);

	/* make sure there's only one unref thread per process */
	mutex_enter(&door_knob);
	if (p->p_unref_thread) {
		mutex_exit(&door_knob);
		return (set_errno(EALREADY));
	}
	p->p_unref_thread = 1;
	mutex_exit(&door_knob);

	(void) door_my_data(1);			/* create info, if necessary */

	for (;;) {
		mutex_enter(&door_knob);

		/* Grab a queued request */
		while ((dp = p->p_unref_list) == NULL) {
			if (!cv_wait_sig(&p->p_unref_cv, &door_knob)) {
				/*
				 * Interrupted.
				 * Return so we can finish forkall() or exit().
				 */
				p->p_unref_thread = 0;
				mutex_exit(&door_knob);
				return (set_errno(EINTR));
			}
		}
		p->p_unref_list = dp->door_ulist;
		dp->door_ulist = NULL;
		dp->door_flags |= DOOR_UNREF_ACTIVE;
		mutex_exit(&door_knob);

		(void) door_upcall(DTOV(dp), &unref_args, NULL, SIZE_MAX, 0);

		if (unref_args.rbuf != 0) {
			kmem_free(unref_args.rbuf, unref_args.rsize);
			unref_args.rbuf = NULL;
			unref_args.rsize = 0;
		}

		mutex_enter(&door_knob);
		ASSERT(dp->door_flags & DOOR_UNREF_ACTIVE);
		dp->door_flags &= ~DOOR_UNREF_ACTIVE;
		mutex_exit(&door_knob);
		VN_RELE(DTOV(dp));
	}
}


/*
 * Deliver queued unrefs to kernel door server.
 */
/* ARGSUSED */
static void
door_unref_kernel(caddr_t arg)
{
	door_node_t	*dp;
	static door_arg_t unref_args = { DOOR_UNREF_DATA, 0, 0, 0, 0, 0 };
	proc_t *p = ttoproc(curthread);
	callb_cpr_t cprinfo;

	/* should only be one of these */
	mutex_enter(&door_knob);
	if (p->p_unref_thread) {
		mutex_exit(&door_knob);
		return;
	}
	p->p_unref_thread = 1;
	mutex_exit(&door_knob);

	(void) door_my_data(1);		/* make sure we have a door_data_t */

	CALLB_CPR_INIT(&cprinfo, &door_knob, callb_generic_cpr, "door_unref");
	for (;;) {
		mutex_enter(&door_knob);
		/* Grab a queued request */
		while ((dp = p->p_unref_list) == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&p->p_unref_cv, &door_knob);
			CALLB_CPR_SAFE_END(&cprinfo, &door_knob);
		}
		p->p_unref_list = dp->door_ulist;
		dp->door_ulist = NULL;
		dp->door_flags |= DOOR_UNREF_ACTIVE;
		mutex_exit(&door_knob);

		(*(dp->door_pc))(dp->door_data, &unref_args, NULL, NULL, NULL);

		mutex_enter(&door_knob);
		ASSERT(dp->door_flags & DOOR_UNREF_ACTIVE);
		dp->door_flags &= ~DOOR_UNREF_ACTIVE;
		mutex_exit(&door_knob);
		VN_RELE(DTOV(dp));
	}
}


/*
 * Queue an unref invocation for processing for the current process
 * The door may or may not be revoked at this point.
 */
void
door_deliver_unref(door_node_t *d)
{
	struct proc *server = d->door_target;

	ASSERT(MUTEX_HELD(&door_knob));
	ASSERT(d->door_active == 0);

	if (server == NULL)
		return;
	/*
	 * Create a lwp to deliver unref calls if one isn't already running.
	 *
	 * A separate thread is used to deliver unrefs since the current
	 * thread may be holding resources (e.g. locks) in user land that
	 * may be needed by the unref processing. This would cause a
	 * deadlock.
	 */
	if (d->door_flags & DOOR_UNREF_MULTI) {
		/* multiple unrefs */
		d->door_flags &= ~DOOR_DELAY;
	} else {
		/* Only 1 unref per door */
		d->door_flags &= ~(DOOR_UNREF|DOOR_DELAY);
	}
	mutex_exit(&door_knob);

	/*
	 * Need to bump the vnode count before putting the door on the
	 * list so it doesn't get prematurely released by door_unref.
	 */
	VN_HOLD(DTOV(d));

	mutex_enter(&door_knob);
	/* is this door already on the unref list? */
	if (d->door_flags & DOOR_UNREF_MULTI) {
		door_node_t *dp;
		for (dp = server->p_unref_list; dp != NULL;
		    dp = dp->door_ulist) {
			if (d == dp) {
				/* already there, don't need to add another */
				mutex_exit(&door_knob);
				VN_RELE(DTOV(d));
				mutex_enter(&door_knob);
				return;
			}
		}
	}
	ASSERT(d->door_ulist == NULL);
	d->door_ulist = server->p_unref_list;
	server->p_unref_list = d;
	cv_broadcast(&server->p_unref_cv);
}

/*
 * The callers buffer isn't big enough for all of the data/fd's. Allocate
 * space in the callers address space for the results and copy the data
 * there.
 *
 * For EOVERFLOW, we must clean up the server's door descriptors.
 */
static int
door_overflow(
	kthread_t	*caller,
	caddr_t		data_ptr,	/* data location */
	size_t		data_size,	/* data size */
	door_desc_t	*desc_ptr,	/* descriptor location */
	uint_t		desc_num)	/* descriptor size */
{
	proc_t *callerp = ttoproc(caller);
	struct as *as = callerp->p_as;
	door_client_t *ct = DOOR_CLIENT(caller->t_door);
	caddr_t	addr;			/* Resulting address in target */
	size_t	rlen;			/* Rounded len */
	size_t	len;
	uint_t	i;
	size_t	ds = desc_num * sizeof (door_desc_t);

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	ASSERT(DOOR_T_HELD(ct) || ct->d_kernel);

	/* Do initial overflow check */
	if (!ufcanalloc(callerp, desc_num))
		return (EMFILE);

	/*
	 * Allocate space for this stuff in the callers address space
	 */
	rlen = roundup(data_size + ds, PAGESIZE);
	as_rangelock(as);
	map_addr_proc(&addr, rlen, 0, 1, as->a_userlimit, ttoproc(caller), 0);
	if (addr == NULL ||
	    as_map(as, addr, rlen, segvn_create, zfod_argsp) != 0) {
		/* No virtual memory available, or anon mapping failed */
		as_rangeunlock(as);
		if (!ct->d_kernel && desc_num > 0) {
			int error = door_release_fds(desc_ptr, desc_num);
			if (error)
				return (error);
		}
		return (EOVERFLOW);
	}
	as_rangeunlock(as);

	if (ct->d_kernel)
		goto out;

	if (data_size != 0) {
		caddr_t	src = data_ptr;
		caddr_t saddr = addr;

		/* Copy any data */
		len = data_size;
		while (len != 0) {
			int	amount;
			int	error;

			amount = len > PAGESIZE ? PAGESIZE : len;
			if ((error = door_copy(as, src, saddr, amount)) != 0) {
				(void) as_unmap(as, addr, rlen);
				return (error);
			}
			saddr += amount;
			src += amount;
			len -= amount;
		}
	}
	/* Copy any fd's */
	if (desc_num != 0) {
		door_desc_t	*didpp, *start;
		struct file	**fpp;
		int		fpp_size;

		start = didpp = kmem_alloc(ds, KM_SLEEP);
		if (copyin_nowatch(desc_ptr, didpp, ds)) {
			kmem_free(start, ds);
			(void) as_unmap(as, addr, rlen);
			return (EFAULT);
		}

		fpp_size = desc_num * sizeof (struct file *);
		if (fpp_size > ct->d_fpp_size) {
			/* make more space */
			if (ct->d_fpp_size)
				kmem_free(ct->d_fpp, ct->d_fpp_size);
			ct->d_fpp_size = fpp_size;
			ct->d_fpp = kmem_alloc(ct->d_fpp_size, KM_SLEEP);
		}
		fpp = ct->d_fpp;

		for (i = 0; i < desc_num; i++) {
			struct file *fp;
			int fd = didpp->d_data.d_desc.d_descriptor;

			if (!(didpp->d_attributes & DOOR_DESCRIPTOR) ||
			    (fp = getf(fd)) == NULL) {
				/* close translated references */
				door_fp_close(ct->d_fpp, fpp - ct->d_fpp);
				/* close untranslated references */
				door_fd_rele(didpp, desc_num - i, 0);
				kmem_free(start, ds);
				(void) as_unmap(as, addr, rlen);
				return (EINVAL);
			}
			mutex_enter(&fp->f_tlock);
			fp->f_count++;
			mutex_exit(&fp->f_tlock);

			*fpp = fp;
			releasef(fd);

			if (didpp->d_attributes & DOOR_RELEASE) {
				/* release passed reference */
				(void) closeandsetf(fd, NULL);
			}

			fpp++; didpp++;
		}
		kmem_free(start, ds);
	}

out:
	ct->d_overflow = 1;
	ct->d_args.rbuf = addr;
	ct->d_args.rsize = rlen;
	return (0);
}

/*
 * Transfer arguments from the client to the server.
 */
static int
door_args(kthread_t *server, int is_private)
{
	door_server_t *st = DOOR_SERVER(server->t_door);
	door_client_t *ct = DOOR_CLIENT(curthread->t_door);
	uint_t	ndid;
	size_t	dsize;
	int	error;

	ASSERT(DOOR_T_HELD(st));
	ASSERT(MUTEX_NOT_HELD(&door_knob));

	ndid = ct->d_args.desc_num;
	if (ndid > door_max_desc)
		return (E2BIG);

	/*
	 * Get the stack layout, and fail now if it won't fit.
	 */
	error = door_layout(server, ct->d_args.data_size, ndid, is_private);
	if (error != 0)
		return (error);

	dsize = ndid * sizeof (door_desc_t);
	if (ct->d_args.data_size != 0) {
		if (ct->d_args.data_size <= door_max_arg) {
			/*
			 * Use a 2 copy method for small amounts of data
			 *
			 * Allocate a little more than we need for the
			 * args, in the hope that the results will fit
			 * without having to reallocate a buffer
			 */
			ASSERT(ct->d_buf == NULL);
			ct->d_bufsize = roundup(ct->d_args.data_size,
			    DOOR_ROUND);
			ct->d_buf = kmem_alloc(ct->d_bufsize, KM_SLEEP);
			if (copyin_nowatch(ct->d_args.data_ptr,
			    ct->d_buf, ct->d_args.data_size) != 0) {
				kmem_free(ct->d_buf, ct->d_bufsize);
				ct->d_buf = NULL;
				ct->d_bufsize = 0;
				return (EFAULT);
			}
		} else {
			struct as	*as;
			caddr_t		src;
			caddr_t		dest;
			size_t		len = ct->d_args.data_size;
			uintptr_t	base;

			/*
			 * Use a 1 copy method
			 */
			as = ttoproc(server)->p_as;
			src = ct->d_args.data_ptr;

			dest = st->d_layout.dl_datap;
			base = (uintptr_t)dest;

			/*
			 * Copy data directly into server.  We proceed
			 * downward from the top of the stack, to mimic
			 * normal stack usage. This allows the guard page
			 * to stop us before we corrupt anything.
			 */
			while (len != 0) {
				uintptr_t start;
				uintptr_t end;
				uintptr_t offset;
				size_t	amount;

				/*
				 * Locate the next part to copy.
				 */
				end = base + len;
				start = P2ALIGN(end - 1, PAGESIZE);

				/*
				 * if we are on the final (first) page, fix
				 * up the start position.
				 */
				if (P2ALIGN(base, PAGESIZE) == start)
					start = base;

				offset = start - base;	/* the copy offset */
				amount = end - start;	/* # bytes to copy */

				ASSERT(amount > 0 && amount <= len &&
				    amount <= PAGESIZE);

				error = door_copy(as, src + offset,
				    dest + offset, amount);
				if (error != 0)
					return (error);
				len -= amount;
			}
		}
	}
	/*
	 * Copyin the door args and translate them into files
	 */
	if (ndid != 0) {
		door_desc_t	*didpp;
		door_desc_t	*start;
		struct file	**fpp;

		start = didpp = kmem_alloc(dsize, KM_SLEEP);

		if (copyin_nowatch(ct->d_args.desc_ptr, didpp, dsize)) {
			kmem_free(start, dsize);
			return (EFAULT);
		}
		ct->d_fpp_size = ndid * sizeof (struct file *);
		ct->d_fpp = kmem_alloc(ct->d_fpp_size, KM_SLEEP);
		fpp = ct->d_fpp;
		while (ndid--) {
			struct file *fp;
			int fd = didpp->d_data.d_desc.d_descriptor;

			/* We only understand file descriptors as passed objs */
			if (!(didpp->d_attributes & DOOR_DESCRIPTOR) ||
			    (fp = getf(fd)) == NULL) {
				/* close translated references */
				door_fp_close(ct->d_fpp, fpp - ct->d_fpp);
				/* close untranslated references */
				door_fd_rele(didpp, ndid + 1, 0);
				kmem_free(start, dsize);
				kmem_free(ct->d_fpp, ct->d_fpp_size);
				ct->d_fpp = NULL;
				ct->d_fpp_size = 0;
				return (EINVAL);
			}
			/* Hold the fp */
			mutex_enter(&fp->f_tlock);
			fp->f_count++;
			mutex_exit(&fp->f_tlock);

			*fpp = fp;
			releasef(fd);

			if (didpp->d_attributes & DOOR_RELEASE) {
				/* release passed reference */
				(void) closeandsetf(fd, NULL);
			}

			fpp++; didpp++;
		}
		kmem_free(start, dsize);
	}
	return (0);
}

/*
 * Transfer arguments from a user client to a kernel server.  This copies in
 * descriptors and translates them into door handles.  It doesn't touch the
 * other data, letting the kernel server deal with that (to avoid needing
 * to copy the data twice).
 */
static int
door_translate_in(void)
{
	door_client_t *ct = DOOR_CLIENT(curthread->t_door);
	uint_t	ndid;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	ndid = ct->d_args.desc_num;
	if (ndid > door_max_desc)
		return (E2BIG);
	/*
	 * Copyin the door args and translate them into door handles.
	 */
	if (ndid != 0) {
		door_desc_t	*didpp;
		door_desc_t	*start;
		size_t		dsize = ndid * sizeof (door_desc_t);
		struct file	*fp;

		start = didpp = kmem_alloc(dsize, KM_SLEEP);

		if (copyin_nowatch(ct->d_args.desc_ptr, didpp, dsize)) {
			kmem_free(start, dsize);
			return (EFAULT);
		}
		while (ndid--) {
			vnode_t	*vp;
			int fd = didpp->d_data.d_desc.d_descriptor;

			/*
			 * We only understand file descriptors as passed objs
			 */
			if ((didpp->d_attributes & DOOR_DESCRIPTOR) &&
			    (fp = getf(fd)) != NULL) {
				didpp->d_data.d_handle = FTODH(fp);
				/* Hold the door */
				door_ki_hold(didpp->d_data.d_handle);

				releasef(fd);

				if (didpp->d_attributes & DOOR_RELEASE) {
					/* release passed reference */
					(void) closeandsetf(fd, NULL);
				}

				if (VOP_REALVP(fp->f_vnode, &vp, NULL))
					vp = fp->f_vnode;

				/* Set attributes */
				didpp->d_attributes = DOOR_HANDLE |
				    (VTOD(vp)->door_flags & DOOR_ATTR_MASK);
			} else {
				/* close translated references */
				door_fd_close(start, didpp - start);
				/* close untranslated references */
				door_fd_rele(didpp, ndid + 1, 0);
				kmem_free(start, dsize);
				return (EINVAL);
			}
			didpp++;
		}
		ct->d_args.desc_ptr = start;
	}
	return (0);
}

/*
 * Translate door arguments from kernel to user.  This copies the passed
 * door handles.  It doesn't touch other data.  It is used by door_upcall,
 * and for data returned by a door_call to a kernel server.
 */
static int
door_translate_out(void)
{
	door_client_t *ct = DOOR_CLIENT(curthread->t_door);
	uint_t	ndid;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	ndid = ct->d_args.desc_num;
	if (ndid > door_max_desc) {
		door_fd_rele(ct->d_args.desc_ptr, ndid, 1);
		return (E2BIG);
	}
	/*
	 * Translate the door args into files
	 */
	if (ndid != 0) {
		door_desc_t	*didpp = ct->d_args.desc_ptr;
		struct file	**fpp;

		ct->d_fpp_size = ndid * sizeof (struct file *);
		fpp = ct->d_fpp = kmem_alloc(ct->d_fpp_size, KM_SLEEP);
		while (ndid--) {
			struct file *fp = NULL;
			int fd = -1;

			/*
			 * We understand file descriptors and door
			 * handles as passed objs.
			 */
			if (didpp->d_attributes & DOOR_DESCRIPTOR) {
				fd = didpp->d_data.d_desc.d_descriptor;
				fp = getf(fd);
			} else if (didpp->d_attributes & DOOR_HANDLE)
				fp = DHTOF(didpp->d_data.d_handle);
			if (fp != NULL) {
				/* Hold the fp */
				mutex_enter(&fp->f_tlock);
				fp->f_count++;
				mutex_exit(&fp->f_tlock);

				*fpp = fp;
				if (didpp->d_attributes & DOOR_DESCRIPTOR)
					releasef(fd);
				if (didpp->d_attributes & DOOR_RELEASE) {
					/* release passed reference */
					if (fd >= 0)
						(void) closeandsetf(fd, NULL);
					else
						(void) closef(fp);
				}
			} else {
				/* close translated references */
				door_fp_close(ct->d_fpp, fpp - ct->d_fpp);
				/* close untranslated references */
				door_fd_rele(didpp, ndid + 1, 1);
				kmem_free(ct->d_fpp, ct->d_fpp_size);
				ct->d_fpp = NULL;
				ct->d_fpp_size = 0;
				return (EINVAL);
			}
			fpp++; didpp++;
		}
	}
	return (0);
}

/*
 * Move the results from the server to the client
 */
static int
door_results(kthread_t *caller, caddr_t data_ptr, size_t data_size,
		door_desc_t *desc_ptr, uint_t desc_num)
{
	door_client_t	*ct = DOOR_CLIENT(caller->t_door);
	door_upcall_t	*dup = ct->d_upcall;
	size_t		dsize;
	size_t		rlen;
	size_t		result_size;

	ASSERT(DOOR_T_HELD(ct));
	ASSERT(MUTEX_NOT_HELD(&door_knob));

	if (ct->d_noresults)
		return (E2BIG);		/* No results expected */

	if (desc_num > door_max_desc)
		return (E2BIG);		/* Too many descriptors */

	dsize = desc_num * sizeof (door_desc_t);
	/*
	 * Check if the results are bigger than the clients buffer
	 */
	if (dsize)
		rlen = roundup(data_size, sizeof (door_desc_t));
	else
		rlen = data_size;
	if ((result_size = rlen + dsize) == 0)
		return (0);

	if (dup != NULL) {
		if (desc_num > dup->du_max_descs)
			return (EMFILE);

		if (data_size > dup->du_max_data)
			return (E2BIG);

		/*
		 * Handle upcalls
		 */
		if (ct->d_args.rbuf == NULL || ct->d_args.rsize < result_size) {
			/*
			 * If there's no return buffer or the buffer is too
			 * small, allocate a new one.  The old buffer (if it
			 * exists) will be freed by the upcall client.
			 */
			if (result_size > door_max_upcall_reply)
				return (E2BIG);
			ct->d_args.rsize = result_size;
			ct->d_args.rbuf = kmem_alloc(result_size, KM_SLEEP);
		}
		ct->d_args.data_ptr = ct->d_args.rbuf;
		if (data_size != 0 &&
		    copyin_nowatch(data_ptr, ct->d_args.data_ptr,
		    data_size) != 0)
			return (EFAULT);
	} else if (result_size > ct->d_args.rsize) {
		return (door_overflow(caller, data_ptr, data_size,
		    desc_ptr, desc_num));
	} else if (data_size != 0) {
		if (data_size <= door_max_arg) {
			/*
			 * Use a 2 copy method for small amounts of data
			 */
			if (ct->d_buf == NULL) {
				ct->d_bufsize = data_size;
				ct->d_buf = kmem_alloc(ct->d_bufsize, KM_SLEEP);
			} else if (ct->d_bufsize < data_size) {
				kmem_free(ct->d_buf, ct->d_bufsize);
				ct->d_bufsize = data_size;
				ct->d_buf = kmem_alloc(ct->d_bufsize, KM_SLEEP);
			}
			if (copyin_nowatch(data_ptr, ct->d_buf, data_size) != 0)
				return (EFAULT);
		} else {
			struct as *as = ttoproc(caller)->p_as;
			caddr_t	dest = ct->d_args.rbuf;
			caddr_t	src = data_ptr;
			size_t	len = data_size;

			/* Copy data directly into client */
			while (len != 0) {
				uint_t	amount;
				uint_t	max;
				uint_t	off;
				int	error;

				off = (uintptr_t)dest & PAGEOFFSET;
				if (off)
					max = PAGESIZE - off;
				else
					max = PAGESIZE;
				amount = len > max ? max : len;
				error = door_copy(as, src, dest, amount);
				if (error != 0)
					return (error);
				dest += amount;
				src += amount;
				len -= amount;
			}
		}
	}

	/*
	 * Copyin the returned door ids and translate them into door_node_t
	 */
	if (desc_num != 0) {
		door_desc_t *start;
		door_desc_t *didpp;
		struct file **fpp;
		size_t	fpp_size;
		uint_t	i;

		/* First, check if we would overflow client */
		if (!ufcanalloc(ttoproc(caller), desc_num))
			return (EMFILE);

		start = didpp = kmem_alloc(dsize, KM_SLEEP);
		if (copyin_nowatch(desc_ptr, didpp, dsize)) {
			kmem_free(start, dsize);
			return (EFAULT);
		}
		fpp_size = desc_num * sizeof (struct file *);
		if (fpp_size > ct->d_fpp_size) {
			/* make more space */
			if (ct->d_fpp_size)
				kmem_free(ct->d_fpp, ct->d_fpp_size);
			ct->d_fpp_size = fpp_size;
			ct->d_fpp = kmem_alloc(fpp_size, KM_SLEEP);
		}
		fpp = ct->d_fpp;

		for (i = 0; i < desc_num; i++) {
			struct file *fp;
			int fd = didpp->d_data.d_desc.d_descriptor;

			/* Only understand file descriptor results */
			if (!(didpp->d_attributes & DOOR_DESCRIPTOR) ||
			    (fp = getf(fd)) == NULL) {
				/* close translated references */
				door_fp_close(ct->d_fpp, fpp - ct->d_fpp);
				/* close untranslated references */
				door_fd_rele(didpp, desc_num - i, 0);
				kmem_free(start, dsize);
				return (EINVAL);
			}

			mutex_enter(&fp->f_tlock);
			fp->f_count++;
			mutex_exit(&fp->f_tlock);

			*fpp = fp;
			releasef(fd);

			if (didpp->d_attributes & DOOR_RELEASE) {
				/* release passed reference */
				(void) closeandsetf(fd, NULL);
			}

			fpp++; didpp++;
		}
		kmem_free(start, dsize);
	}
	return (0);
}

/*
 * Close all the descriptors.
 */
static void
door_fd_close(door_desc_t *d, uint_t n)
{
	uint_t	i;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	for (i = 0; i < n; i++) {
		if (d->d_attributes & DOOR_DESCRIPTOR) {
			(void) closeandsetf(
			    d->d_data.d_desc.d_descriptor, NULL);
		} else if (d->d_attributes & DOOR_HANDLE) {
			door_ki_rele(d->d_data.d_handle);
		}
		d++;
	}
}

/*
 * Close descriptors that have the DOOR_RELEASE attribute set.
 */
void
door_fd_rele(door_desc_t *d, uint_t n, int from_kernel)
{
	uint_t	i;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	for (i = 0; i < n; i++) {
		if (d->d_attributes & DOOR_RELEASE) {
			if (d->d_attributes & DOOR_DESCRIPTOR) {
				(void) closeandsetf(
				    d->d_data.d_desc.d_descriptor, NULL);
			} else if (from_kernel &&
			    (d->d_attributes & DOOR_HANDLE)) {
				door_ki_rele(d->d_data.d_handle);
			}
		}
		d++;
	}
}

/*
 * Copy descriptors into the kernel so we can release any marked
 * DOOR_RELEASE.
 */
int
door_release_fds(door_desc_t *desc_ptr, uint_t ndesc)
{
	size_t dsize;
	door_desc_t *didpp;
	uint_t desc_num;

	ASSERT(MUTEX_NOT_HELD(&door_knob));
	ASSERT(ndesc != 0);

	desc_num = MIN(ndesc, door_max_desc);

	dsize = desc_num * sizeof (door_desc_t);
	didpp = kmem_alloc(dsize, KM_SLEEP);

	while (ndesc > 0) {
		uint_t count = MIN(ndesc, desc_num);

		if (copyin_nowatch(desc_ptr, didpp,
		    count * sizeof (door_desc_t))) {
			kmem_free(didpp, dsize);
			return (EFAULT);
		}
		door_fd_rele(didpp, count, 0);

		ndesc -= count;
		desc_ptr += count;
	}
	kmem_free(didpp, dsize);
	return (0);
}

/*
 * Decrement ref count on all the files passed
 */
static void
door_fp_close(struct file **fp, uint_t n)
{
	uint_t	i;

	ASSERT(MUTEX_NOT_HELD(&door_knob));

	for (i = 0; i < n; i++)
		(void) closef(fp[i]);
}

/*
 * Copy data from 'src' in current address space to 'dest' in 'as' for 'len'
 * bytes.
 *
 * Performs this using 1 mapin and 1 copy operation.
 *
 * We really should do more than 1 page at a time to improve
 * performance, but for now this is treated as an anomalous condition.
 */
static int
door_copy(struct as *as, caddr_t src, caddr_t dest, uint_t len)
{
	caddr_t	kaddr;
	caddr_t	rdest;
	uint_t	off;
	page_t	**pplist;
	page_t	*pp = NULL;
	int	error = 0;

	ASSERT(len <= PAGESIZE);
	off = (uintptr_t)dest & PAGEOFFSET;	/* offset within the page */
	rdest = (caddr_t)((uintptr_t)dest &
	    (uintptr_t)PAGEMASK);	/* Page boundary */
	ASSERT(off + len <= PAGESIZE);

	/*
	 * Lock down destination page.
	 */
	if (as_pagelock(as, &pplist, rdest, PAGESIZE, S_WRITE))
		return (E2BIG);
	/*
	 * Check if we have a shadow page list from as_pagelock. If not,
	 * we took the slow path and have to find our page struct the hard
	 * way.
	 */
	if (pplist == NULL) {
		pfn_t	pfnum;

		/* MMU mapping is already locked down */
		AS_LOCK_ENTER(as, RW_READER);
		pfnum = hat_getpfnum(as->a_hat, rdest);
		AS_LOCK_EXIT(as);

		/*
		 * TODO: The pfn step should not be necessary - need
		 * a hat_getpp() function.
		 */
		if (pf_is_memory(pfnum)) {
			pp = page_numtopp_nolock(pfnum);
			ASSERT(pp == NULL || PAGE_LOCKED(pp));
		} else
			pp = NULL;
		if (pp == NULL) {
			as_pageunlock(as, pplist, rdest, PAGESIZE, S_WRITE);
			return (E2BIG);
		}
	} else {
		pp = *pplist;
	}
	/*
	 * Map destination page into kernel address
	 */
	if (kpm_enable)
		kaddr = (caddr_t)hat_kpm_mapin(pp, (struct kpme *)NULL);
	else
		kaddr = (caddr_t)ppmapin(pp, PROT_READ | PROT_WRITE,
		    (caddr_t)-1);

	/*
	 * Copy from src to dest
	 */
	if (copyin_nowatch(src, kaddr + off, len) != 0)
		error = EFAULT;
	/*
	 * Unmap destination page from kernel
	 */
	if (kpm_enable)
		hat_kpm_mapout(pp, (struct kpme *)NULL, kaddr);
	else
		ppmapout(kaddr);
	/*
	 * Unlock destination page
	 */
	as_pageunlock(as, pplist, rdest, PAGESIZE, S_WRITE);
	return (error);
}

/*
 * General kernel upcall using doors
 *	Returns 0 on success, errno for failures.
 *	Caller must have a hold on the door based vnode, and on any
 *	references passed in desc_ptr.  The references are released
 *	in the event of an error, and passed without duplication
 *	otherwise.  Note that param->rbuf must be 64-bit aligned in
 *	a 64-bit kernel, since it may be used to store door descriptors
 *	if they are returned by the server.  The caller is responsible
 *	for holding a reference to the cred passed in.
 */
int
door_upcall(vnode_t *vp, door_arg_t *param, struct cred *cred,
    size_t max_data, uint_t max_descs)
{
	/* Locals */
	door_upcall_t	*dup;
	door_node_t	*dp;
	kthread_t	*server_thread;
	int		error = 0;
	klwp_t		*lwp;
	door_client_t	*ct;		/* curthread door_data */
	door_server_t	*st;		/* server thread door_data */
	int		gotresults = 0;
	int		cancel_pending;

	if (vp->v_type != VDOOR) {
		if (param->desc_num)
			door_fd_rele(param->desc_ptr, param->desc_num, 1);
		return (EINVAL);
	}

	lwp = ttolwp(curthread);
	ct = door_my_client(1);
	dp = VTOD(vp);	/* Convert to a door_node_t */

	dup = kmem_zalloc(sizeof (*dup), KM_SLEEP);
	dup->du_cred = (cred != NULL) ? cred : curthread->t_cred;
	dup->du_max_data = max_data;
	dup->du_max_descs = max_descs;

	/*
	 * This should be done in shuttle_resume(), just before going to
	 * sleep, but we want to avoid overhead while holding door_knob.
	 * prstop() is just a no-op if we don't really go to sleep.
	 * We test not-kernel-address-space for the sake of clustering code.
	 */
	if (lwp && lwp->lwp_nostop == 0 && curproc->p_as != &kas)
		prstop(PR_REQUESTED, 0);

	mutex_enter(&door_knob);
	if (DOOR_INVALID(dp)) {
		mutex_exit(&door_knob);
		if (param->desc_num)
			door_fd_rele(param->desc_ptr, param->desc_num, 1);
		error = EBADF;
		goto out;
	}

	if (dp->door_target == &p0) {
		/* Can't do an upcall to a kernel server */
		mutex_exit(&door_knob);
		if (param->desc_num)
			door_fd_rele(param->desc_ptr, param->desc_num, 1);
		error = EINVAL;
		goto out;
	}

	error = door_check_limits(dp, param, 1);
	if (error != 0) {
		mutex_exit(&door_knob);
		if (param->desc_num)
			door_fd_rele(param->desc_ptr, param->desc_num, 1);
		goto out;
	}

	/*
	 * Get a server thread from the target domain
	 */
	if ((server_thread = door_get_server(dp)) == NULL) {
		if (DOOR_INVALID(dp))
			error = EBADF;
		else
			error = EAGAIN;
		mutex_exit(&door_knob);
		if (param->desc_num)
			door_fd_rele(param->desc_ptr, param->desc_num, 1);
		goto out;
	}

	st = DOOR_SERVER(server_thread->t_door);
	ct->d_buf = param->data_ptr;
	ct->d_bufsize = param->data_size;
	ct->d_args = *param;	/* structure assignment */

	if (ct->d_args.desc_num) {
		/*
		 * Move data from client to server
		 */
		DOOR_T_HOLD(st);
		mutex_exit(&door_knob);
		error = door_translate_out();
		mutex_enter(&door_knob);
		DOOR_T_RELEASE(st);
		if (error) {
			/*
			 * We're not going to resume this thread after all
			 */
			door_release_server(dp, server_thread);
			shuttle_sleep(server_thread);
			mutex_exit(&door_knob);
			goto out;
		}
	}

	ct->d_upcall = dup;
	if (param->rsize == 0)
		ct->d_noresults = 1;
	else
		ct->d_noresults = 0;

	dp->door_active++;

	ct->d_error = DOOR_WAIT;
	st->d_caller = curthread;
	st->d_active = dp;

	shuttle_resume(server_thread, &door_knob);

	mutex_enter(&door_knob);
shuttle_return:
	if ((error = ct->d_error) < 0) {	/* DOOR_WAIT or DOOR_EXIT */
		/*
		 * Premature wakeup. Find out why (stop, forkall, sig, exit ...)
		 */
		mutex_exit(&door_knob);		/* May block in ISSIG */
		cancel_pending = 0;
		if (lwp && (ISSIG(curthread, FORREAL) || lwp->lwp_sysabort ||
		    MUSTRETURN(curproc, curthread) ||
		    (cancel_pending = schedctl_cancel_pending()) != 0)) {
			/* Signal, forkall, ... */
			if (cancel_pending)
				schedctl_cancel_eintr();
			lwp->lwp_sysabort = 0;
			mutex_enter(&door_knob);
			error = EINTR;
			/*
			 * If the server has finished processing our call,
			 * or exited (calling door_slam()), then d_error
			 * will have changed.  If the server hasn't finished
			 * yet, d_error will still be DOOR_WAIT, and we
			 * let it know we are not interested in any
			 * results by sending a SIGCANCEL, unless the door
			 * is marked with DOOR_NO_CANCEL.
			 */
			if (ct->d_error == DOOR_WAIT &&
			    st->d_caller == curthread) {
				proc_t	*p = ttoproc(server_thread);

				st->d_active = NULL;
				st->d_caller = NULL;
				if (!(dp->door_flags & DOOR_NO_CANCEL)) {
					DOOR_T_HOLD(st);
					mutex_exit(&door_knob);

					mutex_enter(&p->p_lock);
					sigtoproc(p, server_thread, SIGCANCEL);
					mutex_exit(&p->p_lock);

					mutex_enter(&door_knob);
					DOOR_T_RELEASE(st);
				}
			}
		} else {
			/*
			 * Return from stop(), server exit...
			 *
			 * Note that the server could have done a
			 * door_return while the client was in stop state
			 * (ISSIG), in which case the error condition
			 * is updated by the server.
			 */
			mutex_enter(&door_knob);
			if (ct->d_error == DOOR_WAIT) {
				/* Still waiting for a reply */
				shuttle_swtch(&door_knob);
				mutex_enter(&door_knob);
				if (lwp)
					lwp->lwp_asleep = 0;
				goto	shuttle_return;
			} else if (ct->d_error == DOOR_EXIT) {
				/* Server exit */
				error = EINTR;
			} else {
				/* Server did a door_return during ISSIG */
				error = ct->d_error;
			}
		}
		/*
		 * Can't exit if the server is currently copying
		 * results for me
		 */
		while (DOOR_T_HELD(ct))
			cv_wait(&ct->d_cv, &door_knob);

		/*
		 * Find out if results were successfully copied.
		 */
		if (ct->d_error == 0)
			gotresults = 1;
	}
	if (lwp) {
		lwp->lwp_asleep = 0;		/* /proc */
		lwp->lwp_sysabort = 0;		/* /proc */
	}
	if (--dp->door_active == 0 && (dp->door_flags & DOOR_DELAY))
		door_deliver_unref(dp);
	mutex_exit(&door_knob);

	/*
	 * Translate returned doors (if any)
	 */

	if (ct->d_noresults)
		goto out;

	if (error) {
		/*
		 * If server returned results successfully, then we've
		 * been interrupted and may need to clean up.
		 */
		if (gotresults) {
			ASSERT(error == EINTR);
			door_fp_close(ct->d_fpp, ct->d_args.desc_num);
		}
		goto out;
	}

	if (ct->d_args.desc_num) {
		struct file	**fpp;
		door_desc_t	*didpp;
		vnode_t		*vp;
		uint_t		n = ct->d_args.desc_num;

		didpp = ct->d_args.desc_ptr = (door_desc_t *)(ct->d_args.rbuf +
		    roundup(ct->d_args.data_size, sizeof (door_desc_t)));
		fpp = ct->d_fpp;

		while (n--) {
			struct file *fp;

			fp = *fpp;
			if (VOP_REALVP(fp->f_vnode, &vp, NULL))
				vp = fp->f_vnode;

			didpp->d_attributes = DOOR_HANDLE |
			    (VTOD(vp)->door_flags & DOOR_ATTR_MASK);
			didpp->d_data.d_handle = FTODH(fp);

			fpp++; didpp++;
		}
	}

	/* on return data is in rbuf */
	*param = ct->d_args;		/* structure assignment */

out:
	kmem_free(dup, sizeof (*dup));

	if (ct->d_fpp) {
		kmem_free(ct->d_fpp, ct->d_fpp_size);
		ct->d_fpp = NULL;
		ct->d_fpp_size = 0;
	}

	ct->d_upcall = NULL;
	ct->d_noresults = 0;
	ct->d_buf = NULL;
	ct->d_bufsize = 0;
	return (error);
}

/*
 * Add a door to the per-process list of active doors for which the
 * process is a server.
 */
static void
door_list_insert(door_node_t *dp)
{
	proc_t *p = dp->door_target;

	ASSERT(MUTEX_HELD(&door_knob));
	dp->door_list = p->p_door_list;
	p->p_door_list = dp;
}

/*
 * Remove a door from the per-process list of active doors.
 */
void
door_list_delete(door_node_t *dp)
{
	door_node_t **pp;

	ASSERT(MUTEX_HELD(&door_knob));
	/*
	 * Find the door in the list.  If the door belongs to another process,
	 * it's OK to use p_door_list since that process can't exit until all
	 * doors have been taken off the list (see door_exit).
	 */
	pp = &(dp->door_target->p_door_list);
	while (*pp != dp)
		pp = &((*pp)->door_list);

	/* found it, take it off the list */
	*pp = dp->door_list;
}


/*
 * External kernel interfaces for doors.  These functions are available
 * outside the doorfs module for use in creating and using doors from
 * within the kernel.
 */

/*
 * door_ki_upcall invokes a user-level door server from the kernel, with
 * the credentials associated with curthread.
 */
int
door_ki_upcall(door_handle_t dh, door_arg_t *param)
{
	return (door_ki_upcall_limited(dh, param, NULL, SIZE_MAX, UINT_MAX));
}

/*
 * door_ki_upcall_limited invokes a user-level door server from the
 * kernel with the given credentials and reply limits.  If the "cred"
 * argument is NULL, uses the credentials associated with current
 * thread.  max_data limits the maximum length of the returned data (the
 * client will get E2BIG if they go over), and max_desc limits the
 * number of returned descriptors (the client will get EMFILE if they
 * go over).
 */
int
door_ki_upcall_limited(door_handle_t dh, door_arg_t *param, struct cred *cred,
    size_t max_data, uint_t max_desc)
{
	file_t *fp = DHTOF(dh);
	vnode_t *realvp;

	if (VOP_REALVP(fp->f_vnode, &realvp, NULL))
		realvp = fp->f_vnode;
	return (door_upcall(realvp, param, cred, max_data, max_desc));
}

/*
 * Function call to create a "kernel" door server.  A kernel door
 * server provides a way for a user-level process to invoke a function
 * in the kernel through a door_call.  From the caller's point of
 * view, a kernel door server looks the same as a user-level one
 * (except the server pid is 0).  Unlike normal door calls, the
 * kernel door function is invoked via a normal function call in the
 * same thread and context as the caller.
 */
int
door_ki_create(void (*pc_cookie)(), void *data_cookie, uint_t attributes,
    door_handle_t *dhp)
{
	int err;
	file_t *fp;

	/* no DOOR_PRIVATE */
	if ((attributes & ~DOOR_KI_CREATE_MASK) ||
	    (attributes & (DOOR_UNREF | DOOR_UNREF_MULTI)) ==
	    (DOOR_UNREF | DOOR_UNREF_MULTI))
		return (EINVAL);

	err = door_create_common(pc_cookie, data_cookie, attributes,
	    1, NULL, &fp);
	if (err == 0 && (attributes & (DOOR_UNREF | DOOR_UNREF_MULTI)) &&
	    p0.p_unref_thread == 0) {
		/* need to create unref thread for process 0 */
		(void) thread_create(NULL, 0, door_unref_kernel, NULL, 0, &p0,
		    TS_RUN, minclsyspri);
	}
	if (err == 0) {
		*dhp = FTODH(fp);
	}
	return (err);
}

void
door_ki_hold(door_handle_t dh)
{
	file_t *fp = DHTOF(dh);

	mutex_enter(&fp->f_tlock);
	fp->f_count++;
	mutex_exit(&fp->f_tlock);
}

void
door_ki_rele(door_handle_t dh)
{
	file_t *fp = DHTOF(dh);

	(void) closef(fp);
}

int
door_ki_open(char *pathname, door_handle_t *dhp)
{
	file_t *fp;
	vnode_t *vp;
	int err;

	if ((err = lookupname(pathname, UIO_SYSSPACE, FOLLOW, NULL, &vp)) != 0)
		return (err);
	if (err = VOP_OPEN(&vp, FREAD, kcred, NULL)) {
		VN_RELE(vp);
		return (err);
	}
	if (vp->v_type != VDOOR) {
		VN_RELE(vp);
		return (EINVAL);
	}
	if ((err = falloc(vp, FREAD | FWRITE, &fp, NULL)) != 0) {
		VN_RELE(vp);
		return (err);
	}
	/* falloc returns with f_tlock held on success */
	mutex_exit(&fp->f_tlock);
	*dhp = FTODH(fp);
	return (0);
}

int
door_ki_info(door_handle_t dh, struct door_info *dip)
{
	file_t *fp = DHTOF(dh);
	vnode_t *vp;

	if (VOP_REALVP(fp->f_vnode, &vp, NULL))
		vp = fp->f_vnode;
	if (vp->v_type != VDOOR)
		return (EINVAL);
	door_info_common(VTOD(vp), dip, fp);
	return (0);
}

door_handle_t
door_ki_lookup(int did)
{
	file_t *fp;
	door_handle_t dh;

	/* is the descriptor really a door? */
	if (door_lookup(did, &fp) == NULL)
		return (NULL);
	/* got the door, put a hold on it and release the fd */
	dh = FTODH(fp);
	door_ki_hold(dh);
	releasef(did);
	return (dh);
}

int
door_ki_setparam(door_handle_t dh, int type, size_t val)
{
	file_t *fp = DHTOF(dh);
	vnode_t *vp;

	if (VOP_REALVP(fp->f_vnode, &vp, NULL))
		vp = fp->f_vnode;
	if (vp->v_type != VDOOR)
		return (EINVAL);
	return (door_setparam_common(VTOD(vp), 1, type, val));
}

int
door_ki_getparam(door_handle_t dh, int type, size_t *out)
{
	file_t *fp = DHTOF(dh);
	vnode_t *vp;

	if (VOP_REALVP(fp->f_vnode, &vp, NULL))
		vp = fp->f_vnode;
	if (vp->v_type != VDOOR)
		return (EINVAL);
	return (door_getparam_common(VTOD(vp), type, out));
}
