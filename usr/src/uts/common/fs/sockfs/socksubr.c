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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/user.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/mkdev.h>
#include <sys/pathname.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/zone.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/ucred.h>

#include <sys/tiuser.h>
#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>

#include <c2/audit.h>

#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/sockfilter_impl.h>
#include <fs/sockfs/socktpi.h>
#include <fs/sockfs/socktpi_impl.h>
#include <fs/sockfs/sodirect.h>

/*
 * Macros that operate on struct cmsghdr.
 * The CMSG_VALID macro does not assume that the last option buffer is padded.
 */
#define	CMSG_CONTENT(cmsg)	(&((cmsg)[1]))
#define	CMSG_CONTENTLEN(cmsg)	((cmsg)->cmsg_len - sizeof (struct cmsghdr))
#define	CMSG_VALID(cmsg, start, end)					\
	(ISALIGNED_cmsghdr(cmsg) &&					\
	((uintptr_t)(cmsg) >= (uintptr_t)(start)) &&			\
	((uintptr_t)(cmsg) < (uintptr_t)(end)) &&			\
	((ssize_t)(cmsg)->cmsg_len >= sizeof (struct cmsghdr)) &&	\
	((uintptr_t)(cmsg) + (cmsg)->cmsg_len <= (uintptr_t)(end)))
#define	SO_LOCK_WAKEUP_TIME	3000	/* Wakeup time in milliseconds */

dev_t sockdev;	/* For fsid in getattr */
int sockfs_defer_nl7c_init = 0;

struct socklist socklist;

struct kmem_cache *socket_cache;

/*
 * sockconf_lock protects the socket configuration (socket types and
 * socket filters) which is changed via the sockconfig system call.
 */
krwlock_t sockconf_lock;

static int sockfs_update(kstat_t *, int);
static int sockfs_snapshot(kstat_t *, void *, int);
extern smod_info_t *sotpi_smod_create(void);

extern void sendfile_init();

extern void nl7c_init(void);

extern int modrootloaded;

#define	ADRSTRLEN (2 * sizeof (void *) + 1)
/*
 * kernel structure for passing the sockinfo data back up to the user.
 * the strings array allows us to convert AF_UNIX addresses into strings
 * with a common method regardless of which n-bit kernel we're running.
 */
struct k_sockinfo {
	struct sockinfo	ks_si;
	char		ks_straddr[3][ADRSTRLEN];
};

/*
 * Translate from a device pathname (e.g. "/dev/tcp") to a vnode.
 * Returns with the vnode held.
 */
int
sogetvp(char *devpath, vnode_t **vpp, int uioflag)
{
	struct snode *csp;
	vnode_t *vp, *dvp;
	major_t maj;
	int error;

	ASSERT(uioflag == UIO_SYSSPACE || uioflag == UIO_USERSPACE);

	/*
	 * Lookup the underlying filesystem vnode.
	 */
	error = lookupname(devpath, uioflag, FOLLOW, NULLVPP, &vp);
	if (error)
		return (error);

	/* Check that it is the correct vnode */
	if (vp->v_type != VCHR) {
		VN_RELE(vp);
		return (ENOTSOCK);
	}

	/*
	 * If devpath went through devfs, the device should already
	 * be configured. If devpath is a mknod file, however, we
	 * need to make sure the device is properly configured.
	 * To do this, we do something similar to spec_open()
	 * except that we resolve to the minor/leaf level since
	 * we need to return a vnode.
	 */
	csp = VTOS(VTOS(vp)->s_commonvp);
	if (!(csp->s_flag & SDIPSET)) {
		char *pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		error = ddi_dev_pathname(vp->v_rdev, S_IFCHR, pathname);
		if (error == 0)
			error = devfs_lookupname(pathname, NULLVPP, &dvp);
		VN_RELE(vp);
		kmem_free(pathname, MAXPATHLEN);
		if (error != 0)
			return (ENXIO);
		vp = dvp;	/* use the devfs vp */
	}

	/* device is configured at this point */
	maj = getmajor(vp->v_rdev);
	if (!STREAMSTAB(maj)) {
		VN_RELE(vp);
		return (ENOSTR);
	}

	*vpp = vp;
	return (0);
}

/*
 * Update the accessed, updated, or changed times in an sonode
 * with the current time.
 *
 * Note that both SunOS 4.X and 4.4BSD sockets do not present reasonable
 * attributes in a fstat call. (They return the current time and 0 for
 * all timestamps, respectively.) We maintain the current timestamps
 * here primarily so that should sockmod be popped the resulting
 * file descriptor will behave like a stream w.r.t. the timestamps.
 */
void
so_update_attrs(struct sonode *so, int flag)
{
	time_t now = gethrestime_sec();

	if (SOCK_IS_NONSTR(so))
		return;

	mutex_enter(&so->so_lock);
	so->so_flag |= flag;
	if (flag & SOACC)
		SOTOTPI(so)->sti_atime = now;
	if (flag & SOMOD)
		SOTOTPI(so)->sti_mtime = now;
	mutex_exit(&so->so_lock);
}

extern so_create_func_t sock_comm_create_function;
extern so_destroy_func_t sock_comm_destroy_function;
/*
 * Init function called when sockfs is loaded.
 */
int
sockinit(int fstype, char *name)
{
	static const fs_operation_def_t sock_vfsops_template[] = {
		NULL, NULL
	};
	int error;
	major_t dev;
	char *err_str;

	error = vfs_setfsops(fstype, sock_vfsops_template, NULL);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "sockinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, socket_vnodeops_template,
	    &socket_vnodeops);
	if (error != 0) {
		err_str = "sockinit: bad socket vnode ops template";
		/* vn_make_ops() does not reset socktpi_vnodeops on failure. */
		socket_vnodeops = NULL;
		goto failure;
	}

	socket_cache = kmem_cache_create("socket_cache",
	    sizeof (struct sonode), 0, sonode_constructor,
	    sonode_destructor, NULL, NULL, NULL, 0);

	rw_init(&sockconf_lock, NULL, RW_DEFAULT, NULL);

	error = socktpi_init();
	if (error != 0) {
		err_str = NULL;
		goto failure;
	}

	error = sod_init();
	if (error != 0) {
		err_str = NULL;
		goto failure;
	}

	/*
	 * Set up the default create and destroy functions
	 */
	sock_comm_create_function = socket_sonode_create;
	sock_comm_destroy_function = socket_sonode_destroy;

	/*
	 * Build initial list mapping socket parameters to vnode.
	 */
	smod_init();
	smod_add(sotpi_smod_create());

	sockparams_init();

	/*
	 * If sockets are needed before init runs /sbin/soconfig
	 * it is possible to preload the sockparams list here using
	 * calls like:
	 *	sockconfig(1,2,3, "/dev/tcp", 0);
	 */

	/*
	 * Create a unique dev_t for use in so_fsid.
	 */

	if ((dev = getudev()) == (major_t)-1)
		dev = 0;
	sockdev = makedevice(dev, 0);

	mutex_init(&socklist.sl_lock, NULL, MUTEX_DEFAULT, NULL);
	sendfile_init();
	if (!modrootloaded) {
		sockfs_defer_nl7c_init = 1;
	} else {
		nl7c_init();
	}

	/* Initialize socket filters */
	sof_init();

	return (0);

failure:
	(void) vfs_freevfsops_by_type(fstype);
	if (socket_vnodeops != NULL)
		vn_freevnodeops(socket_vnodeops);
	if (err_str != NULL)
		zcmn_err(GLOBAL_ZONEID, CE_WARN, err_str);
	return (error);
}

/*
 * Caller must hold the mutex. Used to set SOLOCKED.
 */
void
so_lock_single(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	while (so->so_flag & (SOLOCKED | SOASYNC_UNBIND)) {
		cv_wait_stop(&so->so_single_cv, &so->so_lock,
		    SO_LOCK_WAKEUP_TIME);
	}
	so->so_flag |= SOLOCKED;
}

/*
 * Caller must hold the mutex and pass in SOLOCKED or SOASYNC_UNBIND.
 * Used to clear SOLOCKED or SOASYNC_UNBIND.
 */
void
so_unlock_single(struct sonode *so, int flag)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(flag & (SOLOCKED|SOASYNC_UNBIND));
	ASSERT((flag & ~(SOLOCKED|SOASYNC_UNBIND)) == 0);
	ASSERT(so->so_flag & flag);
	/*
	 * Process the T_DISCON_IND on sti_discon_ind_mp.
	 *
	 * Call to so_drain_discon_ind will result in so_lock
	 * being dropped and re-acquired later.
	 */
	if (!SOCK_IS_NONSTR(so)) {
		sotpi_info_t *sti = SOTOTPI(so);

		if (sti->sti_discon_ind_mp != NULL)
			so_drain_discon_ind(so);
	}

	cv_signal(&so->so_single_cv);
	so->so_flag &= ~flag;
}

/*
 * Caller must hold the mutex. Used to set SOREADLOCKED.
 * If the caller wants nonblocking behavior it should set fmode.
 */
int
so_lock_read(struct sonode *so, int fmode)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	while (so->so_flag & SOREADLOCKED) {
		if (fmode & (FNDELAY|FNONBLOCK))
			return (EWOULDBLOCK);
		cv_wait_stop(&so->so_read_cv, &so->so_lock,
		    SO_LOCK_WAKEUP_TIME);
	}
	so->so_flag |= SOREADLOCKED;
	return (0);
}

/*
 * Like so_lock_read above but allows signals.
 */
int
so_lock_read_intr(struct sonode *so, int fmode)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	while (so->so_flag & SOREADLOCKED) {
		if (fmode & (FNDELAY|FNONBLOCK))
			return (EWOULDBLOCK);
		if (!cv_wait_sig(&so->so_read_cv, &so->so_lock))
			return (EINTR);
	}
	so->so_flag |= SOREADLOCKED;
	return (0);
}

/*
 * Caller must hold the mutex. Used to clear SOREADLOCKED,
 * set in so_lock_read() or so_lock_read_intr().
 */
void
so_unlock_read(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(so->so_flag & SOREADLOCKED);

	cv_signal(&so->so_read_cv);
	so->so_flag &= ~SOREADLOCKED;
}

/*
 * Verify that the specified offset falls within the mblk and
 * that the resulting pointer is aligned.
 * Returns NULL if not.
 */
void *
sogetoff(mblk_t *mp, t_uscalar_t offset,
    t_uscalar_t length, uint_t align_size)
{
	uintptr_t ptr1, ptr2;

	ASSERT(mp && mp->b_wptr >= mp->b_rptr);
	ptr1 = (uintptr_t)mp->b_rptr + offset;
	ptr2 = (uintptr_t)ptr1 + length;
	if (ptr1 < (uintptr_t)mp->b_rptr || ptr2 > (uintptr_t)mp->b_wptr) {
		eprintline(0);
		return (NULL);
	}
	if ((ptr1 & (align_size - 1)) != 0) {
		eprintline(0);
		return (NULL);
	}
	return ((void *)ptr1);
}

/*
 * Return the AF_UNIX underlying filesystem vnode matching a given name.
 * Makes sure the sending and the destination sonodes are compatible.
 * The vnode is returned held.
 *
 * The underlying filesystem VSOCK vnode has a v_stream pointer that
 * references the actual stream head (hence indirectly the actual sonode).
 */
static int
so_ux_lookup(struct sonode *so, struct sockaddr_un *soun, int checkaccess,
    vnode_t **vpp)
{
	vnode_t		*vp;	/* Underlying filesystem vnode */
	vnode_t		*rvp;	/* real vnode */
	vnode_t		*svp;	/* sockfs vnode */
	struct sonode	*so2;
	int		error;

	dprintso(so, 1, ("so_ux_lookup(%p) name <%s>\n", (void *)so,
	    soun->sun_path));

	error = lookupname(soun->sun_path, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	if (error) {
		eprintsoline(so, error);
		return (error);
	}

	/*
	 * Traverse lofs mounts get the real vnode
	 */
	if (VOP_REALVP(vp, &rvp, NULL) == 0) {
		VN_HOLD(rvp);		/* hold the real vnode */
		VN_RELE(vp);		/* release hold from lookup */
		vp = rvp;
	}

	if (vp->v_type != VSOCK) {
		error = ENOTSOCK;
		eprintsoline(so, error);
		goto done2;
	}

	if (checkaccess) {
		/*
		 * Check that we have permissions to access the destination
		 * vnode. This check is not done in BSD but it is required
		 * by X/Open.
		 */
		if (error = VOP_ACCESS(vp, VREAD|VWRITE, 0, CRED(), NULL)) {
			eprintsoline(so, error);
			goto done2;
		}
	}

	/*
	 * Check if the remote socket has been closed.
	 *
	 * Synchronize with vn_rele_stream by holding v_lock while traversing
	 * v_stream->sd_vnode.
	 */
	mutex_enter(&vp->v_lock);
	if (vp->v_stream == NULL) {
		mutex_exit(&vp->v_lock);
		if (so->so_type == SOCK_DGRAM)
			error = EDESTADDRREQ;
		else
			error = ECONNREFUSED;

		eprintsoline(so, error);
		goto done2;
	}
	ASSERT(vp->v_stream->sd_vnode);
	svp = vp->v_stream->sd_vnode;
	/*
	 * holding v_lock on underlying filesystem vnode and acquiring
	 * it on sockfs vnode. Assumes that no code ever attempts to
	 * acquire these locks in the reverse order.
	 */
	VN_HOLD(svp);
	mutex_exit(&vp->v_lock);

	if (svp->v_type != VSOCK) {
		error = ENOTSOCK;
		eprintsoline(so, error);
		goto done;
	}

	so2 = VTOSO(svp);

	if (so->so_type != so2->so_type) {
		error = EPROTOTYPE;
		eprintsoline(so, error);
		goto done;
	}

	VN_RELE(svp);
	*vpp = vp;
	return (0);

done:
	VN_RELE(svp);
done2:
	VN_RELE(vp);
	return (error);
}

/*
 * Verify peer address for connect and sendto/sendmsg.
 * Since sendto/sendmsg would not get synchronous errors from the transport
 * provider we have to do these ugly checks in the socket layer to
 * preserve compatibility with SunOS 4.X.
 */
int
so_addr_verify(struct sonode *so, const struct sockaddr *name,
    socklen_t namelen)
{
	int		family;

	dprintso(so, 1, ("so_addr_verify(%p, %p, %d)\n",
	    (void *)so, (void *)name, namelen));

	ASSERT(name != NULL);

	family = so->so_family;
	switch (family) {
	case AF_INET:
		if (name->sa_family != family) {
			eprintsoline(so, EAFNOSUPPORT);
			return (EAFNOSUPPORT);
		}
		if (namelen != (socklen_t)sizeof (struct sockaddr_in)) {
			eprintsoline(so, EINVAL);
			return (EINVAL);
		}
		break;
	case AF_INET6: {
#ifdef DEBUG
		struct sockaddr_in6 *sin6;
#endif /* DEBUG */

		if (name->sa_family != family) {
			eprintsoline(so, EAFNOSUPPORT);
			return (EAFNOSUPPORT);
		}
		if (namelen != (socklen_t)sizeof (struct sockaddr_in6)) {
			eprintsoline(so, EINVAL);
			return (EINVAL);
		}
#ifdef DEBUG
		/* Verify that apps don't forget to clear sin6_scope_id etc */
		sin6 = (struct sockaddr_in6 *)name;
		if (sin6->sin6_scope_id != 0 &&
		    !IN6_IS_ADDR_LINKSCOPE(&sin6->sin6_addr)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "connect/send* with uninitialized sin6_scope_id "
			    "(%d) on socket. Pid = %d\n",
			    (int)sin6->sin6_scope_id, (int)curproc->p_pid);
		}
#endif /* DEBUG */
		break;
	}
	case AF_UNIX:
		if (SOTOTPI(so)->sti_faddr_noxlate) {
			return (0);
		}
		if (namelen < (socklen_t)sizeof (short)) {
			eprintsoline(so, ENOENT);
			return (ENOENT);
		}
		if (name->sa_family != family) {
			eprintsoline(so, EAFNOSUPPORT);
			return (EAFNOSUPPORT);
		}
		/* MAXPATHLEN + soun_family + nul termination */
		if (namelen > (socklen_t)(MAXPATHLEN + sizeof (short) + 1)) {
			eprintsoline(so, ENAMETOOLONG);
			return (ENAMETOOLONG);
		}

		break;

	default:
		/*
		 * Default is don't do any length or sa_family check
		 * to allow non-sockaddr style addresses.
		 */
		break;
	}

	return (0);
}


/*
 * Translate an AF_UNIX sockaddr_un to the transport internal name.
 * Assumes caller has called so_addr_verify first.  The translated
 * (internal form) address is stored in sti->sti_ux_taddr.
 */
/*ARGSUSED*/
int
so_ux_addr_xlate(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, int checkaccess,
    void **addrp, socklen_t *addrlenp)
{
	int			error;
	struct sockaddr_un	*soun;
	vnode_t			*vp;
	void			*addr;
	socklen_t		addrlen;
	sotpi_info_t		*sti = SOTOTPI(so);

	dprintso(so, 1, ("so_ux_addr_xlate(%p, %p, %d, %d)\n",
	    (void *)so, (void *)name, namelen, checkaccess));

	ASSERT(name != NULL);
	ASSERT(so->so_family == AF_UNIX);
	ASSERT(!sti->sti_faddr_noxlate);
	ASSERT(namelen >= (socklen_t)sizeof (short));
	ASSERT(name->sa_family == AF_UNIX);
	soun = (struct sockaddr_un *)name;
	/*
	 * Lookup vnode for the specified path name and verify that
	 * it is a socket.
	 */
	error = so_ux_lookup(so, soun, checkaccess, &vp);
	if (error) {
		eprintsoline(so, error);
		return (error);
	}
	/*
	 * Use the address of the peer vnode as the address to send
	 * to. We release the peer vnode here. In case it has been
	 * closed by the time the T_CONN_REQ or T_UNITDATA_REQ reaches the
	 * transport the message will get an error or be dropped.
	 * Note that that soua_vp is never dereferenced; it's just a
	 * convenient value by which we can identify the peer.
	 */
	sti->sti_ux_taddr.soua_vp = vp;
	sti->sti_ux_taddr.soua_magic = SOU_MAGIC_EXPLICIT;
	addr = &sti->sti_ux_taddr;
	addrlen = (socklen_t)sizeof (sti->sti_ux_taddr);
	dprintso(so, 1, ("ux_xlate UNIX: addrlen %d, vp %p\n",
	    addrlen, (void *)vp));
	VN_RELE(vp);
	*addrp = addr;
	*addrlenp = (socklen_t)addrlen;
	return (0);
}

/*
 * Esballoc free function for messages that contain SO_FILEP option.
 * Decrement the reference count on the file pointers using closef.
 */
void
fdbuf_free(struct fdbuf *fdbuf)
{
	int	i;
	struct file *fp;

	dprint(1, ("fdbuf_free: %d fds\n", fdbuf->fd_numfd));
	for (i = 0; i < fdbuf->fd_numfd; i++) {
		/*
		 * We need pointer size alignment for fd_fds. On a LP64
		 * kernel, the required alignment is 8 bytes while
		 * the option headers and values are only 4 bytes
		 * aligned. So its safer to do a bcopy compared to
		 * assigning fdbuf->fd_fds[i] to fp.
		 */
		bcopy((char *)&fdbuf->fd_fds[i], (char *)&fp, sizeof (fp));
		dprint(1, ("fdbuf_free: [%d] = %p\n", i, (void *)fp));
		(void) closef(fp);
	}
	if (fdbuf->fd_ebuf != NULL)
		kmem_free(fdbuf->fd_ebuf, fdbuf->fd_ebuflen);
	kmem_free(fdbuf, fdbuf->fd_size);
}

/*
 * Allocate an esballoc'ed message for AF_UNIX file descriptor passing.
 * Waits if memory is not available.
 */
mblk_t *
fdbuf_allocmsg(int size, struct fdbuf *fdbuf)
{
	uchar_t	*buf;
	mblk_t	*mp;

	dprint(1, ("fdbuf_allocmsg: size %d, %d fds\n", size, fdbuf->fd_numfd));
	buf = kmem_alloc(size, KM_SLEEP);
	fdbuf->fd_ebuf = (caddr_t)buf;
	fdbuf->fd_ebuflen = size;
	fdbuf->fd_frtn.free_func = fdbuf_free;
	fdbuf->fd_frtn.free_arg = (caddr_t)fdbuf;

	mp = esballoc_wait(buf, size, BPRI_MED, &fdbuf->fd_frtn);
	mp->b_datap->db_type = M_PROTO;
	return (mp);
}

/*
 * Extract file descriptors from a fdbuf.
 * Return list in rights/rightslen.
 */
/*ARGSUSED*/
static int
fdbuf_extract(struct fdbuf *fdbuf, void *rights, int rightslen)
{
	int	i, fd;
	int	*rp;
	struct file *fp;
	int	numfd;

	dprint(1, ("fdbuf_extract: %d fds, len %d\n",
	    fdbuf->fd_numfd, rightslen));

	numfd = fdbuf->fd_numfd;
	ASSERT(rightslen == numfd * (int)sizeof (int));

	/*
	 * Allocate a file descriptor and increment the f_count.
	 * The latter is needed since we always call fdbuf_free
	 * which performs a closef.
	 */
	rp = (int *)rights;
	for (i = 0; i < numfd; i++) {
		if ((fd = ufalloc(0)) == -1)
			goto cleanup;
		/*
		 * We need pointer size alignment for fd_fds. On a LP64
		 * kernel, the required alignment is 8 bytes while
		 * the option headers and values are only 4 bytes
		 * aligned. So its safer to do a bcopy compared to
		 * assigning fdbuf->fd_fds[i] to fp.
		 */
		bcopy((char *)&fdbuf->fd_fds[i], (char *)&fp, sizeof (fp));
		mutex_enter(&fp->f_tlock);
		fp->f_count++;
		mutex_exit(&fp->f_tlock);
		setf(fd, fp);
		*rp++ = fd;
		if (AU_AUDITING())
			audit_fdrecv(fd, fp);
		dprint(1, ("fdbuf_extract: [%d] = %d, %p refcnt %d\n",
		    i, fd, (void *)fp, fp->f_count));
	}
	return (0);

cleanup:
	/*
	 * Undo whatever partial work the loop above has done.
	 */
	{
		int j;

		rp = (int *)rights;
		for (j = 0; j < i; j++) {
			dprint(0,
			    ("fdbuf_extract: cleanup[%d] = %d\n", j, *rp));
			(void) closeandsetf(*rp++, NULL);
		}
	}

	return (EMFILE);
}

/*
 * Insert file descriptors into an fdbuf.
 * Returns a kmem_alloc'ed fdbuf. The fdbuf should be freed
 * by calling fdbuf_free().
 */
int
fdbuf_create(void *rights, int rightslen, struct fdbuf **fdbufp)
{
	int		numfd, i;
	int		*fds;
	struct file	*fp;
	struct fdbuf	*fdbuf;
	int		fdbufsize;

	dprint(1, ("fdbuf_create: len %d\n", rightslen));

	numfd = rightslen / (int)sizeof (int);

	fdbufsize = (int)FDBUF_HDRSIZE + (numfd * (int)sizeof (struct file *));
	fdbuf = kmem_alloc(fdbufsize, KM_SLEEP);
	fdbuf->fd_size = fdbufsize;
	fdbuf->fd_numfd = 0;
	fdbuf->fd_ebuf = NULL;
	fdbuf->fd_ebuflen = 0;
	fds = (int *)rights;
	for (i = 0; i < numfd; i++) {
		if ((fp = getf(fds[i])) == NULL) {
			fdbuf_free(fdbuf);
			return (EBADF);
		}
		dprint(1, ("fdbuf_create: [%d] = %d, %p refcnt %d\n",
		    i, fds[i], (void *)fp, fp->f_count));
		mutex_enter(&fp->f_tlock);
		fp->f_count++;
		mutex_exit(&fp->f_tlock);
		/*
		 * The maximum alignment for fdbuf (or any option header
		 * and its value) it 4 bytes. On a LP64 kernel, the alignment
		 * is not sufficient for pointers (fd_fds in this case). Since
		 * we just did a kmem_alloc (we get a double word alignment),
		 * we don't need to do anything on the send side (we loose
		 * the double word alignment because fdbuf goes after an
		 * option header (eg T_unitdata_req) which is only 4 byte
		 * aligned). We take care of this when we extract the file
		 * descriptor in fdbuf_extract or fdbuf_free.
		 */
		fdbuf->fd_fds[i] = fp;
		fdbuf->fd_numfd++;
		releasef(fds[i]);
		if (AU_AUDITING())
			audit_fdsend(fds[i], fp, 0);
	}
	*fdbufp = fdbuf;
	return (0);
}

static int
fdbuf_optlen(int rightslen)
{
	int numfd;

	numfd = rightslen / (int)sizeof (int);

	return ((int)FDBUF_HDRSIZE + (numfd * (int)sizeof (struct file *)));
}

static t_uscalar_t
fdbuf_cmsglen(int fdbuflen)
{
	return (t_uscalar_t)((fdbuflen - FDBUF_HDRSIZE) /
	    (int)sizeof (struct file *) * (int)sizeof (int));
}


/*
 * Return non-zero if the mblk and fdbuf are consistent.
 */
static int
fdbuf_verify(mblk_t *mp, struct fdbuf *fdbuf, int fdbuflen)
{
	if (fdbuflen >= FDBUF_HDRSIZE &&
	    fdbuflen == fdbuf->fd_size) {
		frtn_t *frp = mp->b_datap->db_frtnp;
		/*
		 * Check that the SO_FILEP portion of the
		 * message has not been modified by
		 * the loopback transport. The sending sockfs generates
		 * a message that is esballoc'ed with the free function
		 * being fdbuf_free() and where free_arg contains the
		 * identical information as the SO_FILEP content.
		 *
		 * If any of these constraints are not satisfied we
		 * silently ignore the option.
		 */
		ASSERT(mp);
		if (frp != NULL &&
		    frp->free_func == fdbuf_free &&
		    frp->free_arg != NULL &&
		    bcmp(frp->free_arg, fdbuf, fdbuflen) == 0) {
			dprint(1, ("fdbuf_verify: fdbuf %p len %d\n",
			    (void *)fdbuf, fdbuflen));
			return (1);
		} else {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: mismatched fdbuf content (%p)",
			    (void *)mp);
			return (0);
		}
	} else {
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: mismatched fdbuf len %d, %d\n",
		    fdbuflen, fdbuf->fd_size);
		return (0);
	}
}

/*
 * When the file descriptors returned by sorecvmsg can not be passed
 * to the application this routine will cleanup the references on
 * the files. Start at startoff bytes into the buffer.
 */
static void
close_fds(void *fdbuf, int fdbuflen, int startoff)
{
	int *fds = (int *)fdbuf;
	int numfd = fdbuflen / (int)sizeof (int);
	int i;

	dprint(1, ("close_fds(%p, %d, %d)\n", fdbuf, fdbuflen, startoff));

	for (i = 0; i < numfd; i++) {
		if (startoff < 0)
			startoff = 0;
		if (startoff < (int)sizeof (int)) {
			/*
			 * This file descriptor is partially or fully after
			 * the offset
			 */
			dprint(0,
			    ("close_fds: cleanup[%d] = %d\n", i, fds[i]));
			(void) closeandsetf(fds[i], NULL);
		}
		startoff -= (int)sizeof (int);
	}
}

/*
 * Close all file descriptors contained in the control part starting at
 * the startoffset.
 */
void
so_closefds(void *control, t_uscalar_t controllen, int oldflg,
    int startoff)
{
	struct cmsghdr *cmsg;

	if (control == NULL)
		return;

	if (oldflg) {
		close_fds(control, controllen, startoff);
		return;
	}
	/* Scan control part for file descriptors. */
	for (cmsg = (struct cmsghdr *)control;
	    CMSG_VALID(cmsg, control, (uintptr_t)control + controllen);
	    cmsg = CMSG_NEXT(cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			close_fds(CMSG_CONTENT(cmsg),
			    (int)CMSG_CONTENTLEN(cmsg),
			    startoff - (int)sizeof (struct cmsghdr));
		}
		startoff -= cmsg->cmsg_len;
	}
}

/*
 * Returns a pointer/length for the file descriptors contained
 * in the control buffer. Returns with *fdlenp == -1 if there are no
 * file descriptor options present. This is different than there being
 * a zero-length file descriptor option.
 * Fail if there are multiple SCM_RIGHT cmsgs.
 */
int
so_getfdopt(void *control, t_uscalar_t controllen, int oldflg,
    void **fdsp, int *fdlenp)
{
	struct cmsghdr *cmsg;
	void *fds;
	int fdlen;

	if (control == NULL) {
		*fdsp = NULL;
		*fdlenp = -1;
		return (0);
	}

	if (oldflg) {
		*fdsp = control;
		if (controllen == 0)
			*fdlenp = -1;
		else
			*fdlenp = controllen;
		dprint(1, ("so_getfdopt: old %d\n", *fdlenp));
		return (0);
	}

	fds = NULL;
	fdlen = 0;

	for (cmsg = (struct cmsghdr *)control;
	    CMSG_VALID(cmsg, control, (uintptr_t)control + controllen);
	    cmsg = CMSG_NEXT(cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			if (fds != NULL)
				return (EINVAL);
			fds = CMSG_CONTENT(cmsg);
			fdlen = (int)CMSG_CONTENTLEN(cmsg);
			dprint(1, ("so_getfdopt: new %lu\n",
			    (size_t)CMSG_CONTENTLEN(cmsg)));
		}
	}
	if (fds == NULL) {
		dprint(1, ("so_getfdopt: NONE\n"));
		*fdlenp = -1;
	} else
		*fdlenp = fdlen;
	*fdsp = fds;
	return (0);
}

/*
 * Return the length of the options including any file descriptor options.
 */
t_uscalar_t
so_optlen(void *control, t_uscalar_t controllen, int oldflg)
{
	struct cmsghdr *cmsg;
	t_uscalar_t optlen = 0;
	t_uscalar_t len;

	if (control == NULL)
		return (0);

	if (oldflg)
		return ((t_uscalar_t)(sizeof (struct T_opthdr) +
		    fdbuf_optlen(controllen)));

	for (cmsg = (struct cmsghdr *)control;
	    CMSG_VALID(cmsg, control, (uintptr_t)control + controllen);
	    cmsg = CMSG_NEXT(cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			len = fdbuf_optlen((int)CMSG_CONTENTLEN(cmsg));
		} else {
			len = (t_uscalar_t)CMSG_CONTENTLEN(cmsg);
		}
		optlen += (t_uscalar_t)(_TPI_ALIGN_TOPT(len) +
		    sizeof (struct T_opthdr));
	}
	dprint(1, ("so_optlen: controllen %d, flg %d -> optlen %d\n",
	    controllen, oldflg, optlen));
	return (optlen);
}

/*
 * Copy options from control to the mblk. Skip any file descriptor options.
 */
void
so_cmsg2opt(void *control, t_uscalar_t controllen, int oldflg, mblk_t *mp)
{
	struct T_opthdr toh;
	struct cmsghdr *cmsg;

	if (control == NULL)
		return;

	if (oldflg) {
		/* No real options - caller has handled file descriptors */
		return;
	}
	for (cmsg = (struct cmsghdr *)control;
	    CMSG_VALID(cmsg, control, (uintptr_t)control + controllen);
	    cmsg = CMSG_NEXT(cmsg)) {
		/*
		 * Note: The caller handles file descriptors prior
		 * to calling this function.
		 */
		t_uscalar_t len;

		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS)
			continue;

		len = (t_uscalar_t)CMSG_CONTENTLEN(cmsg);
		toh.level = cmsg->cmsg_level;
		toh.name = cmsg->cmsg_type;
		toh.len = len + (t_uscalar_t)sizeof (struct T_opthdr);
		toh.status = 0;

		soappendmsg(mp, &toh, sizeof (toh));
		soappendmsg(mp, CMSG_CONTENT(cmsg), len);
		mp->b_wptr += _TPI_ALIGN_TOPT(len) - len;
		ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
	}
}

/*
 * Return the length of the control message derived from the options.
 * Exclude SO_SRCADDR and SO_UNIX_CLOSE options. Include SO_FILEP.
 * When oldflg is set only include SO_FILEP.
 * so_opt2cmsg and so_cmsglen are inter-related since so_cmsglen
 * allocates the space that so_opt2cmsg fills. If one changes, the other should
 * also be checked for any possible impacts.
 */
t_uscalar_t
so_cmsglen(mblk_t *mp, void *opt, t_uscalar_t optlen, int oldflg)
{
	t_uscalar_t cmsglen = 0;
	struct T_opthdr *tohp;
	t_uscalar_t len;
	t_uscalar_t last_roundup = 0;

	ASSERT(__TPI_TOPT_ISALIGNED(opt));

	for (tohp = (struct T_opthdr *)opt;
	    tohp && _TPI_TOPT_VALID(tohp, opt, (uintptr_t)opt + optlen);
	    tohp = _TPI_TOPT_NEXTHDR(opt, optlen, tohp)) {
		dprint(1, ("so_cmsglen: level 0x%x, name %d, len %d\n",
		    tohp->level, tohp->name, tohp->len));
		if (tohp->level == SOL_SOCKET &&
		    (tohp->name == SO_SRCADDR ||
		    tohp->name == SO_UNIX_CLOSE)) {
			continue;
		}
		if (tohp->level == SOL_SOCKET && tohp->name == SO_FILEP) {
			struct fdbuf *fdbuf;
			int fdbuflen;

			fdbuf = (struct fdbuf *)_TPI_TOPT_DATA(tohp);
			fdbuflen = (int)_TPI_TOPT_DATALEN(tohp);

			if (!fdbuf_verify(mp, fdbuf, fdbuflen))
				continue;
			if (oldflg) {
				cmsglen += fdbuf_cmsglen(fdbuflen);
				continue;
			}
			len = fdbuf_cmsglen(fdbuflen);
		} else if (tohp->level == SOL_SOCKET &&
		    tohp->name == SCM_TIMESTAMP) {
			if (oldflg)
				continue;

			if (get_udatamodel() == DATAMODEL_NATIVE) {
				len = sizeof (struct timeval);
			} else {
				len = sizeof (struct timeval32);
			}
		} else {
			if (oldflg)
				continue;
			len = (t_uscalar_t)_TPI_TOPT_DATALEN(tohp);
		}
		/*
		 * Exclude roundup for last option to not set
		 * MSG_CTRUNC when the cmsg fits but the padding doesn't fit.
		 */
		last_roundup = (t_uscalar_t)
		    (ROUNDUP_cmsglen(len + (int)sizeof (struct cmsghdr)) -
		    (len + (int)sizeof (struct cmsghdr)));
		cmsglen += (t_uscalar_t)(len + (int)sizeof (struct cmsghdr)) +
		    last_roundup;
	}
	cmsglen -= last_roundup;
	dprint(1, ("so_cmsglen: optlen %d, flg %d -> cmsglen %d\n",
	    optlen, oldflg, cmsglen));
	return (cmsglen);
}

/*
 * Copy options from options to the control. Convert SO_FILEP to
 * file descriptors.
 * Returns errno or zero.
 * so_opt2cmsg and so_cmsglen are inter-related since so_cmsglen
 * allocates the space that so_opt2cmsg fills. If one changes, the other should
 * also be checked for any possible impacts.
 */
int
so_opt2cmsg(mblk_t *mp, void *opt, t_uscalar_t optlen, int oldflg,
    void *control, t_uscalar_t controllen)
{
	struct T_opthdr *tohp;
	struct cmsghdr *cmsg;
	struct fdbuf *fdbuf;
	int fdbuflen;
	int error;
#if defined(DEBUG) || defined(__lint)
	struct cmsghdr *cend = (struct cmsghdr *)
	    (((uint8_t *)control) + ROUNDUP_cmsglen(controllen));
#endif
	cmsg = (struct cmsghdr *)control;

	ASSERT(__TPI_TOPT_ISALIGNED(opt));

	for (tohp = (struct T_opthdr *)opt;
	    tohp && _TPI_TOPT_VALID(tohp, opt, (uintptr_t)opt + optlen);
	    tohp = _TPI_TOPT_NEXTHDR(opt, optlen, tohp)) {
		dprint(1, ("so_opt2cmsg: level 0x%x, name %d, len %d\n",
		    tohp->level, tohp->name, tohp->len));

		if (tohp->level == SOL_SOCKET &&
		    (tohp->name == SO_SRCADDR ||
		    tohp->name == SO_UNIX_CLOSE)) {
			continue;
		}
		ASSERT((uintptr_t)cmsg <= (uintptr_t)control + controllen);
		if (tohp->level == SOL_SOCKET && tohp->name == SO_FILEP) {
			fdbuf = (struct fdbuf *)_TPI_TOPT_DATA(tohp);
			fdbuflen = (int)_TPI_TOPT_DATALEN(tohp);

			if (!fdbuf_verify(mp, fdbuf, fdbuflen))
				return (EPROTO);
			if (oldflg) {
				error = fdbuf_extract(fdbuf, control,
				    (int)controllen);
				if (error != 0)
					return (error);
				continue;
			} else {
				int fdlen;

				fdlen = (int)fdbuf_cmsglen(
				    (int)_TPI_TOPT_DATALEN(tohp));

				cmsg->cmsg_level = tohp->level;
				cmsg->cmsg_type = SCM_RIGHTS;
				cmsg->cmsg_len = (socklen_t)(fdlen +
				    sizeof (struct cmsghdr));

				error = fdbuf_extract(fdbuf,
				    CMSG_CONTENT(cmsg), fdlen);
				if (error != 0)
					return (error);
			}
		} else if (tohp->level == SOL_SOCKET &&
		    tohp->name == SCM_TIMESTAMP) {
			timestruc_t *timestamp;

			if (oldflg)
				continue;

			cmsg->cmsg_level = tohp->level;
			cmsg->cmsg_type = tohp->name;

			timestamp =
			    (timestruc_t *)P2ROUNDUP((intptr_t)&tohp[1],
			    sizeof (intptr_t));

			if (get_udatamodel() == DATAMODEL_NATIVE) {
				struct timeval tv;

				cmsg->cmsg_len = sizeof (struct timeval) +
				    sizeof (struct cmsghdr);
				tv.tv_sec = timestamp->tv_sec;
				tv.tv_usec = timestamp->tv_nsec /
				    (NANOSEC / MICROSEC);
				/*
				 * on LP64 systems, the struct timeval in
				 * the destination will not be 8-byte aligned,
				 * so use bcopy to avoid alignment trouble
				 */
				bcopy(&tv, CMSG_CONTENT(cmsg), sizeof (tv));
			} else {
				struct timeval32 *time32;

				cmsg->cmsg_len = sizeof (struct timeval32) +
				    sizeof (struct cmsghdr);
				time32 = (struct timeval32 *)CMSG_CONTENT(cmsg);
				time32->tv_sec = (time32_t)timestamp->tv_sec;
				time32->tv_usec =
				    (int32_t)(timestamp->tv_nsec /
				    (NANOSEC / MICROSEC));
			}

		} else {
			if (oldflg)
				continue;

			cmsg->cmsg_level = tohp->level;
			cmsg->cmsg_type = tohp->name;
			cmsg->cmsg_len = (socklen_t)(_TPI_TOPT_DATALEN(tohp) +
			    sizeof (struct cmsghdr));

			/* copy content to control data part */
			bcopy(&tohp[1], CMSG_CONTENT(cmsg),
			    CMSG_CONTENTLEN(cmsg));
		}
		/* move to next CMSG structure! */
		cmsg = CMSG_NEXT(cmsg);
	}
	dprint(1, ("so_opt2cmsg: buf %p len %d; cend %p; final cmsg %p\n",
	    control, controllen, (void *)cend, (void *)cmsg));
	ASSERT(cmsg <= cend);
	return (0);
}

/*
 * Extract the SO_SRCADDR option value if present.
 */
void
so_getopt_srcaddr(void *opt, t_uscalar_t optlen, void **srcp,
    t_uscalar_t *srclenp)
{
	struct T_opthdr		*tohp;

	ASSERT(__TPI_TOPT_ISALIGNED(opt));

	ASSERT(srcp != NULL && srclenp != NULL);
	*srcp = NULL;
	*srclenp = 0;

	for (tohp = (struct T_opthdr *)opt;
	    tohp && _TPI_TOPT_VALID(tohp, opt, (uintptr_t)opt + optlen);
	    tohp = _TPI_TOPT_NEXTHDR(opt, optlen, tohp)) {
		dprint(1, ("so_getopt_srcaddr: level 0x%x, name %d, len %d\n",
		    tohp->level, tohp->name, tohp->len));
		if (tohp->level == SOL_SOCKET &&
		    tohp->name == SO_SRCADDR) {
			*srcp = _TPI_TOPT_DATA(tohp);
			*srclenp = (t_uscalar_t)_TPI_TOPT_DATALEN(tohp);
		}
	}
}

/*
 * Verify if the SO_UNIX_CLOSE option is present.
 */
int
so_getopt_unix_close(void *opt, t_uscalar_t optlen)
{
	struct T_opthdr		*tohp;

	ASSERT(__TPI_TOPT_ISALIGNED(opt));

	for (tohp = (struct T_opthdr *)opt;
	    tohp && _TPI_TOPT_VALID(tohp, opt, (uintptr_t)opt + optlen);
	    tohp = _TPI_TOPT_NEXTHDR(opt, optlen, tohp)) {
		dprint(1,
		    ("so_getopt_unix_close: level 0x%x, name %d, len %d\n",
		    tohp->level, tohp->name, tohp->len));
		if (tohp->level == SOL_SOCKET &&
		    tohp->name == SO_UNIX_CLOSE)
			return (1);
	}
	return (0);
}

/*
 * Allocate an M_PROTO message.
 *
 * If allocation fails the behavior depends on sleepflg:
 *	_ALLOC_NOSLEEP	fail immediately
 *	_ALLOC_INTR	sleep for memory until a signal is caught
 *	_ALLOC_SLEEP	sleep forever. Don't return NULL.
 */
mblk_t *
soallocproto(size_t size, int sleepflg, cred_t *cr)
{
	mblk_t	*mp;

	/* Round up size for reuse */
	size = MAX(size, 64);
	if (cr != NULL)
		mp = allocb_cred(size, cr, curproc->p_pid);
	else
		mp = allocb(size, BPRI_MED);

	if (mp == NULL) {
		int error;	/* Dummy - error not returned to caller */

		switch (sleepflg) {
		case _ALLOC_SLEEP:
			if (cr != NULL) {
				mp = allocb_cred_wait(size, STR_NOSIG, &error,
				    cr, curproc->p_pid);
			} else {
				mp = allocb_wait(size, BPRI_MED, STR_NOSIG,
				    &error);
			}
			ASSERT(mp);
			break;
		case _ALLOC_INTR:
			if (cr != NULL) {
				mp = allocb_cred_wait(size, 0, &error, cr,
				    curproc->p_pid);
			} else {
				mp = allocb_wait(size, BPRI_MED, 0, &error);
			}
			if (mp == NULL) {
				/* Caught signal while sleeping for memory */
				eprintline(ENOBUFS);
				return (NULL);
			}
			break;
		case _ALLOC_NOSLEEP:
		default:
			eprintline(ENOBUFS);
			return (NULL);
		}
	}
	DB_TYPE(mp) = M_PROTO;
	return (mp);
}

/*
 * Allocate an M_PROTO message with a single component.
 * len is the length of buf. size is the amount to allocate.
 *
 * buf can be NULL with a non-zero len.
 * This results in a bzero'ed chunk being placed the message.
 */
mblk_t *
soallocproto1(const void *buf, ssize_t len, ssize_t size, int sleepflg,
    cred_t *cr)
{
	mblk_t	*mp;

	if (size == 0)
		size = len;

	ASSERT(size >= len);
	/* Round up size for reuse */
	size = MAX(size, 64);
	mp = soallocproto(size, sleepflg, cr);
	if (mp == NULL)
		return (NULL);
	mp->b_datap->db_type = M_PROTO;
	if (len != 0) {
		if (buf != NULL)
			bcopy(buf, mp->b_wptr, len);
		else
			bzero(mp->b_wptr, len);
		mp->b_wptr += len;
	}
	return (mp);
}

/*
 * Append buf/len to mp.
 * The caller has to ensure that there is enough room in the mblk.
 *
 * buf can be NULL with a non-zero len.
 * This results in a bzero'ed chunk being placed the message.
 */
void
soappendmsg(mblk_t *mp, const void *buf, ssize_t len)
{
	ASSERT(mp);

	if (len != 0) {
		/* Assert for room left */
		ASSERT(mp->b_datap->db_lim - mp->b_wptr >= len);
		if (buf != NULL)
			bcopy(buf, mp->b_wptr, len);
		else
			bzero(mp->b_wptr, len);
	}
	mp->b_wptr += len;
}

/*
 * Create a message using two kernel buffers.
 * If size is set that will determine the allocation size (e.g. for future
 * soappendmsg calls). If size is zero it is derived from the buffer
 * lengths.
 */
mblk_t *
soallocproto2(const void *buf1, ssize_t len1, const void *buf2, ssize_t len2,
    ssize_t size, int sleepflg, cred_t *cr)
{
	mblk_t *mp;

	if (size == 0)
		size = len1 + len2;
	ASSERT(size >= len1 + len2);

	mp = soallocproto1(buf1, len1, size, sleepflg, cr);
	if (mp)
		soappendmsg(mp, buf2, len2);
	return (mp);
}

/*
 * Create a message using three kernel buffers.
 * If size is set that will determine the allocation size (for future
 * soappendmsg calls). If size is zero it is derived from the buffer
 * lengths.
 */
mblk_t *
soallocproto3(const void *buf1, ssize_t len1, const void *buf2, ssize_t len2,
    const void *buf3, ssize_t len3, ssize_t size, int sleepflg, cred_t *cr)
{
	mblk_t *mp;

	if (size == 0)
		size = len1 + len2 +len3;
	ASSERT(size >= len1 + len2 + len3);

	mp = soallocproto1(buf1, len1, size, sleepflg, cr);
	if (mp != NULL) {
		soappendmsg(mp, buf2, len2);
		soappendmsg(mp, buf3, len3);
	}
	return (mp);
}

#ifdef DEBUG
char *
pr_state(uint_t state, uint_t mode)
{
	static char buf[1024];

	buf[0] = 0;
	if (state & SS_ISCONNECTED)
		(void) strcat(buf, "ISCONNECTED ");
	if (state & SS_ISCONNECTING)
		(void) strcat(buf, "ISCONNECTING ");
	if (state & SS_ISDISCONNECTING)
		(void) strcat(buf, "ISDISCONNECTING ");
	if (state & SS_CANTSENDMORE)
		(void) strcat(buf, "CANTSENDMORE ");

	if (state & SS_CANTRCVMORE)
		(void) strcat(buf, "CANTRCVMORE ");
	if (state & SS_ISBOUND)
		(void) strcat(buf, "ISBOUND ");
	if (state & SS_NDELAY)
		(void) strcat(buf, "NDELAY ");
	if (state & SS_NONBLOCK)
		(void) strcat(buf, "NONBLOCK ");

	if (state & SS_ASYNC)
		(void) strcat(buf, "ASYNC ");
	if (state & SS_ACCEPTCONN)
		(void) strcat(buf, "ACCEPTCONN ");
	if (state & SS_SAVEDEOR)
		(void) strcat(buf, "SAVEDEOR ");

	if (state & SS_RCVATMARK)
		(void) strcat(buf, "RCVATMARK ");
	if (state & SS_OOBPEND)
		(void) strcat(buf, "OOBPEND ");
	if (state & SS_HAVEOOBDATA)
		(void) strcat(buf, "HAVEOOBDATA ");
	if (state & SS_HADOOBDATA)
		(void) strcat(buf, "HADOOBDATA ");

	if (mode & SM_PRIV)
		(void) strcat(buf, "PRIV ");
	if (mode & SM_ATOMIC)
		(void) strcat(buf, "ATOMIC ");
	if (mode & SM_ADDR)
		(void) strcat(buf, "ADDR ");
	if (mode & SM_CONNREQUIRED)
		(void) strcat(buf, "CONNREQUIRED ");

	if (mode & SM_FDPASSING)
		(void) strcat(buf, "FDPASSING ");
	if (mode & SM_EXDATA)
		(void) strcat(buf, "EXDATA ");
	if (mode & SM_OPTDATA)
		(void) strcat(buf, "OPTDATA ");
	if (mode & SM_BYTESTREAM)
		(void) strcat(buf, "BYTESTREAM ");
	return (buf);
}

char *
pr_addr(int family, struct sockaddr *addr, t_uscalar_t addrlen)
{
	static char buf[1024];

	if (addr == NULL || addrlen == 0) {
		(void) sprintf(buf, "(len %d) %p", addrlen, (void *)addr);
		return (buf);
	}
	switch (family) {
	case AF_INET: {
		struct sockaddr_in sin;

		bcopy(addr, &sin, sizeof (sin));

		(void) sprintf(buf, "(len %d) %x/%d",
		    addrlen, ntohl(sin.sin_addr.s_addr), ntohs(sin.sin_port));
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 sin6;
		uint16_t *piece = (uint16_t *)&sin6.sin6_addr;

		bcopy((char *)addr, (char *)&sin6, sizeof (sin6));
		(void) sprintf(buf, "(len %d) %x:%x:%x:%x:%x:%x:%x:%x/%d",
		    addrlen,
		    ntohs(piece[0]), ntohs(piece[1]),
		    ntohs(piece[2]), ntohs(piece[3]),
		    ntohs(piece[4]), ntohs(piece[5]),
		    ntohs(piece[6]), ntohs(piece[7]),
		    ntohs(sin6.sin6_port));
		break;
	}
	case AF_UNIX: {
		struct sockaddr_un *soun = (struct sockaddr_un *)addr;

		(void) sprintf(buf, "(len %d) %s", addrlen,
		    (soun == NULL) ? "(none)" : soun->sun_path);
		break;
	}
	default:
		(void) sprintf(buf, "(unknown af %d)", family);
		break;
	}
	return (buf);
}

/* The logical equivalence operator (a if-and-only-if b) */
#define	EQUIVALENT(a, b)	(((a) && (b)) || (!(a) && (!(b))))

/*
 * Verify limitations and invariants on oob state.
 * Return 1 if OK, otherwise 0 so that it can be used as
 *	ASSERT(verify_oobstate(so));
 */
int
so_verify_oobstate(struct sonode *so)
{
	boolean_t havemark;

	ASSERT(MUTEX_HELD(&so->so_lock));

	/*
	 * The possible state combinations are:
	 *	0
	 *	SS_OOBPEND
	 *	SS_OOBPEND|SS_HAVEOOBDATA
	 *	SS_OOBPEND|SS_HADOOBDATA
	 *	SS_HADOOBDATA
	 */
	switch (so->so_state & (SS_OOBPEND|SS_HAVEOOBDATA|SS_HADOOBDATA)) {
	case 0:
	case SS_OOBPEND:
	case SS_OOBPEND|SS_HAVEOOBDATA:
	case SS_OOBPEND|SS_HADOOBDATA:
	case SS_HADOOBDATA:
		break;
	default:
		printf("Bad oob state 1 (%p): state %s\n",
		    (void *)so, pr_state(so->so_state, so->so_mode));
		return (0);
	}

	/* SS_RCVATMARK should only be set when SS_OOBPEND is set */
	if ((so->so_state & (SS_RCVATMARK|SS_OOBPEND)) == SS_RCVATMARK) {
		printf("Bad oob state 2 (%p): state %s\n",
		    (void *)so, pr_state(so->so_state, so->so_mode));
		return (0);
	}

	/*
	 * (havemark != 0 or SS_RCVATMARK) iff SS_OOBPEND
	 * For TPI, the presence of a "mark" is indicated by sti_oobsigcnt.
	 */
	havemark = (SOCK_IS_NONSTR(so)) ? so->so_oobmark > 0 :
	    SOTOTPI(so)->sti_oobsigcnt > 0;

	if (!EQUIVALENT(havemark || (so->so_state & SS_RCVATMARK),
	    so->so_state & SS_OOBPEND)) {
		printf("Bad oob state 3 (%p): state %s\n",
		    (void *)so, pr_state(so->so_state, so->so_mode));
		return (0);
	}

	/*
	 * Unless SO_OOBINLINE we have so_oobmsg != NULL iff SS_HAVEOOBDATA
	 */
	if (!(so->so_options & SO_OOBINLINE) &&
	    !EQUIVALENT(so->so_oobmsg != NULL, so->so_state & SS_HAVEOOBDATA)) {
		printf("Bad oob state 4 (%p): state %s\n",
		    (void *)so, pr_state(so->so_state, so->so_mode));
		return (0);
	}

	if (!SOCK_IS_NONSTR(so) &&
	    SOTOTPI(so)->sti_oobsigcnt < SOTOTPI(so)->sti_oobcnt) {
		printf("Bad oob state 5 (%p): counts %d/%d state %s\n",
		    (void *)so, SOTOTPI(so)->sti_oobsigcnt,
		    SOTOTPI(so)->sti_oobcnt,
		    pr_state(so->so_state, so->so_mode));
		return (0);
	}

	return (1);
}
#undef	EQUIVALENT
#endif /* DEBUG */

/* initialize sockfs zone specific kstat related items			*/
void *
sock_kstat_init(zoneid_t zoneid)
{
	kstat_t	*ksp;

	ksp = kstat_create_zone("sockfs", 0, "sock_unix_list", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VAR_SIZE|KSTAT_FLAG_VIRTUAL, zoneid);

	if (ksp != NULL) {
		ksp->ks_update = sockfs_update;
		ksp->ks_snapshot = sockfs_snapshot;
		ksp->ks_lock = &socklist.sl_lock;
		ksp->ks_private = (void *)(uintptr_t)zoneid;
		kstat_install(ksp);
	}

	return (ksp);
}

/* tear down sockfs zone specific kstat related items			*/
/*ARGSUSED*/
void
sock_kstat_fini(zoneid_t zoneid, void *arg)
{
	kstat_t *ksp = (kstat_t *)arg;

	if (ksp != NULL) {
		ASSERT(zoneid == (zoneid_t)(uintptr_t)ksp->ks_private);
		kstat_delete(ksp);
	}
}

/*
 * Zones:
 * Note that nactive is going to be different for each zone.
 * This means we require kstat to call sockfs_update and then sockfs_snapshot
 * for the same zone, or sockfs_snapshot will be taken into the wrong size
 * buffer. This is safe, but if the buffer is too small, user will not be
 * given details of all sockets. However, as this kstat has a ks_lock, kstat
 * driver will keep it locked between the update and the snapshot, so no
 * other process (zone) can currently get inbetween resulting in a wrong size
 * buffer allocation.
 */
static int
sockfs_update(kstat_t *ksp, int rw)
{
	uint_t	nactive = 0;		/* # of active AF_UNIX sockets	*/
	struct sonode	*so;		/* current sonode on socklist	*/
	zoneid_t	myzoneid = (zoneid_t)(uintptr_t)ksp->ks_private;

	ASSERT((zoneid_t)(uintptr_t)ksp->ks_private == getzoneid());

	if (rw == KSTAT_WRITE) {	/* bounce all writes		*/
		return (EACCES);
	}

	for (so = socklist.sl_list; so != NULL; so = SOTOTPI(so)->sti_next_so) {
		if (so->so_count != 0 && so->so_zoneid == myzoneid) {
			nactive++;
		}
	}
	ksp->ks_ndata = nactive;
	ksp->ks_data_size = nactive * sizeof (struct k_sockinfo);

	return (0);
}

static int
sockfs_snapshot(kstat_t *ksp, void *buf, int rw)
{
	int			ns;	/* # of sonodes we've copied	*/
	struct sonode		*so;	/* current sonode on socklist	*/
	struct k_sockinfo	*pksi;	/* where we put sockinfo data	*/
	t_uscalar_t		sn_len;	/* soa_len			*/
	zoneid_t		myzoneid = (zoneid_t)(uintptr_t)ksp->ks_private;
	sotpi_info_t 		*sti;

	ASSERT((zoneid_t)(uintptr_t)ksp->ks_private == getzoneid());

	ksp->ks_snaptime = gethrtime();

	if (rw == KSTAT_WRITE) {	/* bounce all writes		*/
		return (EACCES);
	}

	/*
	 * for each sonode on the socklist, we massage the important
	 * info into buf, in k_sockinfo format.
	 */
	pksi = (struct k_sockinfo *)buf;
	ns = 0;
	for (so = socklist.sl_list; so != NULL; so = SOTOTPI(so)->sti_next_so) {
		/* only stuff active sonodes and the same zone:		*/
		if (so->so_count == 0 || so->so_zoneid != myzoneid) {
			continue;
		}

		/*
		 * If the sonode was activated between the update and the
		 * snapshot, we're done - as this is only a snapshot.
		 */
		if ((caddr_t)(pksi) >= (caddr_t)buf + ksp->ks_data_size) {
			break;
		}

		sti = SOTOTPI(so);
		/* copy important info into buf:			*/
		pksi->ks_si.si_size = sizeof (struct k_sockinfo);
		pksi->ks_si.si_family = so->so_family;
		pksi->ks_si.si_type = so->so_type;
		pksi->ks_si.si_flag = so->so_flag;
		pksi->ks_si.si_state = so->so_state;
		pksi->ks_si.si_serv_type = sti->sti_serv_type;
		pksi->ks_si.si_ux_laddr_sou_magic =
		    sti->sti_ux_laddr.soua_magic;
		pksi->ks_si.si_ux_faddr_sou_magic =
		    sti->sti_ux_faddr.soua_magic;
		pksi->ks_si.si_laddr_soa_len = sti->sti_laddr.soa_len;
		pksi->ks_si.si_faddr_soa_len = sti->sti_faddr.soa_len;
		pksi->ks_si.si_szoneid = so->so_zoneid;
		pksi->ks_si.si_faddr_noxlate = sti->sti_faddr_noxlate;

		mutex_enter(&so->so_lock);

		if (sti->sti_laddr_sa != NULL) {
			ASSERT(sti->sti_laddr_sa->sa_data != NULL);
			sn_len = sti->sti_laddr_len;
			ASSERT(sn_len <= sizeof (short) +
			    sizeof (pksi->ks_si.si_laddr_sun_path));

			pksi->ks_si.si_laddr_family =
			    sti->sti_laddr_sa->sa_family;
			if (sn_len != 0) {
				/* AF_UNIX socket names are NULL terminated */
				(void) strncpy(pksi->ks_si.si_laddr_sun_path,
				    sti->sti_laddr_sa->sa_data,
				    sizeof (pksi->ks_si.si_laddr_sun_path));
				sn_len = strlen(pksi->ks_si.si_laddr_sun_path);
			}
			pksi->ks_si.si_laddr_sun_path[sn_len] = 0;
		}

		if (sti->sti_faddr_sa != NULL) {
			ASSERT(sti->sti_faddr_sa->sa_data != NULL);
			sn_len = sti->sti_faddr_len;
			ASSERT(sn_len <= sizeof (short) +
			    sizeof (pksi->ks_si.si_faddr_sun_path));

			pksi->ks_si.si_faddr_family =
			    sti->sti_faddr_sa->sa_family;
			if (sn_len != 0) {
				(void) strncpy(pksi->ks_si.si_faddr_sun_path,
				    sti->sti_faddr_sa->sa_data,
				    sizeof (pksi->ks_si.si_faddr_sun_path));
				sn_len = strlen(pksi->ks_si.si_faddr_sun_path);
			}
			pksi->ks_si.si_faddr_sun_path[sn_len] = 0;
		}

		mutex_exit(&so->so_lock);

		(void) sprintf(pksi->ks_straddr[0], "%p", (void *)so);
		(void) sprintf(pksi->ks_straddr[1], "%p",
		    (void *)sti->sti_ux_laddr.soua_vp);
		(void) sprintf(pksi->ks_straddr[2], "%p",
		    (void *)sti->sti_ux_faddr.soua_vp);

		ns++;
		pksi++;
	}

	ksp->ks_ndata = ns;
	return (0);
}

ssize_t
soreadfile(file_t *fp, uchar_t *buf, u_offset_t fileoff, int *err, size_t size)
{
	struct uio auio;
	struct iovec aiov[MSG_MAXIOVLEN];
	register vnode_t *vp;
	int ioflag, rwflag;
	ssize_t cnt;
	int error = 0;
	int iovcnt = 0;
	short fflag;

	vp = fp->f_vnode;
	fflag = fp->f_flag;

	rwflag = 0;
	aiov[0].iov_base = (caddr_t)buf;
	aiov[0].iov_len = size;
	iovcnt = 1;
	cnt = (ssize_t)size;
	(void) VOP_RWLOCK(vp, rwflag, NULL);

	auio.uio_loffset = fileoff;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = cnt;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, &auio, ioflag, fp->f_cred, NULL);
	cnt -= auio.uio_resid;

	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && cnt != 0)
		error = 0;
out:
	if (error != 0) {
		*err = error;
		return (0);
	} else {
		*err = 0;
		return (cnt);
	}
}

int
so_copyin(const void *from, void *to, size_t size, int fromkernel)
{
	if (fromkernel) {
		bcopy(from, to, size);
		return (0);
	}
	return (xcopyin(from, to, size));
}

int
so_copyout(const void *from, void *to, size_t size, int tokernel)
{
	if (tokernel) {
		bcopy(from, to, size);
		return (0);
	}
	return (xcopyout(from, to, size));
}
