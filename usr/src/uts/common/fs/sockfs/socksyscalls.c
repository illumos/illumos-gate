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
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/vmsystm.h>
#include <sys/policy.h>

#include <sys/socket.h>
#include <sys/socketvar.h>

#include <sys/isa_defs.h>
#include <sys/inttypes.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/filio.h>
#include <sys/sendfile.h>
#include <sys/ddi.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>
#include <fs/sockfs/nl7c.h>

#ifdef SOCK_TEST
int do_useracc = 1;		/* Controlled by setting SO_DEBUG to 4 */
#else
#define	do_useracc	1
#endif /* SOCK_TEST */

extern int xnet_truncate_print;

/*
 * Note: DEF_IOV_MAX is defined and used as it is in "fs/vncalls.c"
 *	 as there isn't a formal definition of IOV_MAX ???
 */
#define	MSG_MAXIOVLEN	16

/*
 * Kernel component of socket creation.
 *
 * The socket library determines which version number to use.
 * First the library calls this with a NULL devpath. If this fails
 * to find a transport (using solookup) the library will look in /etc/netconfig
 * for the appropriate transport. If one is found it will pass in the
 * devpath for the kernel to use.
 */
int
so_socket(int domain, int type, int protocol, char *devpath, int version)
{
	vnode_t *accessvp;
	struct sonode *so;
	vnode_t *vp;
	struct file *fp;
	int fd;
	int error;
	boolean_t wildcard = B_FALSE;
	int saved_error = 0;
	int sdomain = domain;

	dprint(1, ("so_socket(%d,%d,%d,%p,%d)\n",
	    domain, type, protocol, (void *)devpath, version));

	if (domain == AF_NCA) {
		/*
		 * The request is for an NCA socket so for NL7C use the
		 * INET domain instead and mark NL7C_AF_NCA below.
		 */
		domain = AF_INET;
		/*
		 * NL7C is not supported in non-global zones,
		 *  we enforce this restriction here.
		 */
		if (getzoneid() != GLOBAL_ZONEID) {
			return (set_errno(ENOTSUP));
		}
	}

	accessvp = solookup(domain, type, protocol, devpath, &error);
	if (accessvp == NULL) {
		/*
		 * If there is either an EPROTONOSUPPORT or EPROTOTYPE error
		 * it makes sense doing the wildcard lookup since the
		 * protocol might not be in the table.
		 */
		if (devpath != NULL || protocol == 0 ||
		    !(error == EPROTONOSUPPORT || error == EPROTOTYPE))
			return (set_errno(error));

		saved_error = error;

		/*
		 * Try wildcard lookup. Never use devpath for wildcards.
		 */
		accessvp = solookup(domain, type, 0, NULL, &error);
		if (accessvp == NULL) {
			/*
			 * Can't find in kernel table - have library
			 * fall back to /etc/netconfig and tell us
			 * the devpath (The library will do this if it didn't
			 * already pass in a devpath).
			 */
			if (saved_error != 0)
				error = saved_error;
			return (set_errno(error));
		}
		wildcard = B_TRUE;
	}

	/* Check the device policy */
	if ((error = secpolicy_spec_open(CRED(),
	    accessvp, FREAD|FWRITE)) != 0) {
		return (set_errno(error));
	}

	if (protocol == IPPROTO_SCTP) {
		so = sosctp_create(accessvp, domain, type, protocol, version,
		    NULL, &error);
	} else if (protocol == PROTO_SDP) {
		so = sosdp_create(accessvp, domain, type, protocol, version,
		    NULL, &error);
	} else {
		so = sotpi_create(accessvp, domain, type, protocol, version,
		    NULL, &error);
	}
	if (so == NULL) {
		return (set_errno(error));
	}
	if (sdomain == AF_NCA && domain == AF_INET) {
		so->so_nl7c_flags = NL7C_AF_NCA;
	}
	vp = SOTOV(so);

	if (wildcard) {
		/*
		 * Issue SO_PROTOTYPE setsockopt.
		 */
		error = SOP_SETSOCKOPT(so, SOL_SOCKET, SO_PROTOTYPE,
		    &protocol,
		    (t_uscalar_t)sizeof (protocol));
		if (error) {
			(void) VOP_CLOSE(vp, 0, 1, 0, CRED(), NULL);
			VN_RELE(vp);
			/*
			 * Setsockopt often fails with ENOPROTOOPT but socket()
			 * should fail with EPROTONOSUPPORT/EPROTOTYPE.
			 */
			if (saved_error != 0 && error == ENOPROTOOPT)
				error = saved_error;
			else
				error = EPROTONOSUPPORT;
			return (set_errno(error));
		}
	}
	if (error = falloc(vp, FWRITE|FREAD, &fp, &fd)) {
		(void) VOP_CLOSE(vp, 0, 1, 0, CRED(), NULL);
		VN_RELE(vp);
		return (set_errno(error));
	}

	/*
	 * Now fill in the entries that falloc reserved
	 */
	mutex_exit(&fp->f_tlock);
	setf(fd, fp);

	return (fd);
}

/*
 * Map from a file descriptor to a socket node.
 * Returns with the file descriptor held i.e. the caller has to
 * use releasef when done with the file descriptor.
 */
struct sonode *
getsonode(int sock, int *errorp, file_t **fpp)
{
	file_t *fp;
	vnode_t *vp;
	struct sonode *so;

	if ((fp = getf(sock)) == NULL) {
		*errorp = EBADF;
		eprintline(*errorp);
		return (NULL);
	}
	vp = fp->f_vnode;
	/* Check if it is a socket */
	if (vp->v_type != VSOCK) {
		releasef(sock);
		*errorp = ENOTSOCK;
		eprintline(*errorp);
		return (NULL);
	}
	/*
	 * Use the stream head to find the real socket vnode.
	 * This is needed when namefs sits above sockfs.
	 */
	if (vp->v_stream) {
		ASSERT(vp->v_stream->sd_vnode);
		vp = vp->v_stream->sd_vnode;

		so = VTOSO(vp);
		if (so->so_version == SOV_STREAM) {
			releasef(sock);
			*errorp = ENOTSOCK;
			eprintsoline(so, *errorp);
			return (NULL);
		}
	} else {
		so = VTOSO(vp);
	}
	if (fpp)
		*fpp = fp;
	return (so);
}

/*
 * Allocate and copyin a sockaddr.
 * Ensures NULL termination for AF_UNIX addresses by extending them
 * with one NULL byte if need be. Verifies that the length is not
 * excessive to prevent an application from consuming all of kernel
 * memory. Returns NULL when an error occurred.
 */
static struct sockaddr *
copyin_name(struct sonode *so, struct sockaddr *name, socklen_t *namelenp,
	    int *errorp)
{
	char	*faddr;
	size_t	namelen = (size_t)*namelenp;

	ASSERT(namelen != 0);
	if (namelen > SO_MAXARGSIZE) {
		*errorp = EINVAL;
		eprintsoline(so, *errorp);
		return (NULL);
	}

	faddr = (char *)kmem_alloc(namelen, KM_SLEEP);
	if (copyin(name, faddr, namelen)) {
		kmem_free(faddr, namelen);
		*errorp = EFAULT;
		eprintsoline(so, *errorp);
		return (NULL);
	}

	/*
	 * Add space for NULL termination if needed.
	 * Do a quick check if the last byte is NUL.
	 */
	if (so->so_family == AF_UNIX && faddr[namelen - 1] != '\0') {
		/* Check if there is any NULL termination */
		size_t	i;
		int foundnull = 0;

		for (i = sizeof (name->sa_family); i < namelen; i++) {
			if (faddr[i] == '\0') {
				foundnull = 1;
				break;
			}
		}
		if (!foundnull) {
			/* Add extra byte for NUL padding */
			char *nfaddr;

			nfaddr = (char *)kmem_alloc(namelen + 1, KM_SLEEP);
			bcopy(faddr, nfaddr, namelen);
			kmem_free(faddr, namelen);

			/* NUL terminate */
			nfaddr[namelen] = '\0';
			namelen++;
			ASSERT((socklen_t)namelen == namelen);
			*namelenp = (socklen_t)namelen;
			faddr = nfaddr;
		}
	}
	return ((struct sockaddr *)faddr);
}

/*
 * Copy from kaddr/klen to uaddr/ulen. Updates ulenp if non-NULL.
 */
static int
copyout_arg(void *uaddr, socklen_t ulen, void *ulenp,
		void *kaddr, socklen_t klen)
{
	if (uaddr != NULL) {
		if (ulen > klen)
			ulen = klen;

		if (ulen != 0) {
			if (copyout(kaddr, uaddr, ulen))
				return (EFAULT);
		}
	} else
		ulen = 0;

	if (ulenp != NULL) {
		if (copyout(&ulen, ulenp, sizeof (ulen)))
			return (EFAULT);
	}
	return (0);
}

/*
 * Copy from kaddr/klen to uaddr/ulen. Updates ulenp if non-NULL.
 * If klen is greater than ulen it still uses the non-truncated
 * klen to update ulenp.
 */
static int
copyout_name(void *uaddr, socklen_t ulen, void *ulenp,
		void *kaddr, socklen_t klen)
{
	if (uaddr != NULL) {
		if (ulen >= klen)
			ulen = klen;
		else if (ulen != 0 && xnet_truncate_print) {
			printf("sockfs: truncating copyout of address using "
			    "XNET semantics for pid = %d. Lengths %d, %d\n",
			    curproc->p_pid, klen, ulen);
		}

		if (ulen != 0) {
			if (copyout(kaddr, uaddr, ulen))
				return (EFAULT);
		} else
			klen = 0;
	} else
		klen = 0;

	if (ulenp != NULL) {
		if (copyout(&klen, ulenp, sizeof (klen)))
			return (EFAULT);
	}
	return (0);
}

/*
 * The socketpair() code in libsocket creates two sockets (using
 * the /etc/netconfig fallback if needed) before calling this routine
 * to connect the two sockets together.
 *
 * For a SOCK_STREAM socketpair a listener is needed - in that case this
 * routine will create a new file descriptor as part of accepting the
 * connection. The library socketpair() will check if svs[2] has changed
 * in which case it will close the changed fd.
 *
 * Note that this code could use the TPI feature of accepting the connection
 * on the listening endpoint. However, that would require significant changes
 * to soaccept.
 */
int
so_socketpair(int sv[2])
{
	int svs[2];
	struct sonode *so1, *so2;
	int error;
	struct sockaddr_ux *name;
	size_t namelen;

	dprint(1, ("so_socketpair(%p)\n", (void *)sv));

	error = useracc(sv, sizeof (svs), B_WRITE);
	if (error && do_useracc)
		return (set_errno(EFAULT));

	if (copyin(sv, svs, sizeof (svs)))
		return (set_errno(EFAULT));

	if ((so1 = getsonode(svs[0], &error, NULL)) == NULL)
		return (set_errno(error));

	if ((so2 = getsonode(svs[1], &error, NULL)) == NULL) {
		releasef(svs[0]);
		return (set_errno(error));
	}

	if (so1->so_family != AF_UNIX || so2->so_family != AF_UNIX) {
		error = EOPNOTSUPP;
		goto done;
	}

	/*
	 * The code below makes assumptions about the "sockfs" implementation.
	 * So make sure that the correct implementation is really used.
	 */
	ASSERT(so1->so_ops == &sotpi_sonodeops);
	ASSERT(so2->so_ops == &sotpi_sonodeops);

	if (so1->so_type == SOCK_DGRAM) {
		/*
		 * Bind both sockets and connect them with each other.
		 * Need to allocate name/namelen for soconnect.
		 */
		error = SOP_BIND(so1, NULL, 0, _SOBIND_UNSPEC);
		if (error) {
			eprintsoline(so1, error);
			goto done;
		}
		error = SOP_BIND(so2, NULL, 0, _SOBIND_UNSPEC);
		if (error) {
			eprintsoline(so2, error);
			goto done;
		}
		namelen = sizeof (struct sockaddr_ux);
		name = kmem_alloc(namelen, KM_SLEEP);
		name->sou_family = AF_UNIX;
		name->sou_addr = so2->so_ux_laddr;
		error = SOP_CONNECT(so1,
		    (struct sockaddr *)name,
		    (socklen_t)namelen,
		    0, _SOCONNECT_NOXLATE);
		if (error) {
			kmem_free(name, namelen);
			eprintsoline(so1, error);
			goto done;
		}
		name->sou_addr = so1->so_ux_laddr;
		error = SOP_CONNECT(so2,
		    (struct sockaddr *)name,
		    (socklen_t)namelen,
		    0, _SOCONNECT_NOXLATE);
		kmem_free(name, namelen);
		if (error) {
			eprintsoline(so2, error);
			goto done;
		}
		releasef(svs[0]);
		releasef(svs[1]);
	} else {
		/*
		 * Bind both sockets, with so1 being a listener.
		 * Connect so2 to so1 - nonblocking to avoid waiting for
		 * soaccept to complete.
		 * Accept a connection on so1. Pass out the new fd as sv[0].
		 * The library will detect the changed fd and close
		 * the original one.
		 */
		struct sonode *nso;
		struct vnode *nvp;
		struct file *nfp;
		int nfd;

		/*
		 * We could simply call SOP_LISTEN() here (which would do the
		 * binding automatically) if the code didn't rely on passing
		 * _SOBIND_NOXLATE to the TPI implementation of SOP_BIND().
		 */
		error = SOP_BIND(so1, NULL, 0, _SOBIND_UNSPEC|_SOBIND_NOXLATE|
		    _SOBIND_LISTEN|_SOBIND_SOCKETPAIR);
		if (error) {
			eprintsoline(so1, error);
			goto done;
		}
		error = SOP_BIND(so2, NULL, 0, _SOBIND_UNSPEC);
		if (error) {
			eprintsoline(so2, error);
			goto done;
		}

		namelen = sizeof (struct sockaddr_ux);
		name = kmem_alloc(namelen, KM_SLEEP);
		name->sou_family = AF_UNIX;
		name->sou_addr = so1->so_ux_laddr;
		error = SOP_CONNECT(so2,
		    (struct sockaddr *)name,
		    (socklen_t)namelen,
		    FNONBLOCK, _SOCONNECT_NOXLATE);
		kmem_free(name, namelen);
		if (error) {
			if (error != EINPROGRESS) {
				eprintsoline(so2, error);
				goto done;
			}
		}

		error = SOP_ACCEPT(so1, 0, &nso);
		if (error) {
			eprintsoline(so1, error);
			goto done;
		}

		/* wait for so2 being SS_CONNECTED ignoring signals */
		mutex_enter(&so2->so_lock);
		error = sowaitconnected(so2, 0, 1);
		mutex_exit(&so2->so_lock);
		nvp = SOTOV(nso);
		if (error != 0) {
			(void) VOP_CLOSE(nvp, 0, 1, 0, CRED(), NULL);
			VN_RELE(nvp);
			eprintsoline(so2, error);
			goto done;
		}

		if (error = falloc(nvp, FWRITE|FREAD, &nfp, &nfd)) {
			(void) VOP_CLOSE(nvp, 0, 1, 0, CRED(), NULL);
			VN_RELE(nvp);
			eprintsoline(nso, error);
			goto done;
		}
		/*
		 * fill in the entries that falloc reserved
		 */
		mutex_exit(&nfp->f_tlock);
		setf(nfd, nfp);

		releasef(svs[0]);
		releasef(svs[1]);
		svs[0] = nfd;

		/*
		 * The socketpair library routine will close the original
		 * svs[0] when this code passes out a different file
		 * descriptor.
		 */
		if (copyout(svs, sv, sizeof (svs))) {
			(void) closeandsetf(nfd, NULL);
			eprintline(EFAULT);
			return (set_errno(EFAULT));
		}
	}
	return (0);

done:
	releasef(svs[0]);
	releasef(svs[1]);
	return (set_errno(error));
}

int
bind(int sock, struct sockaddr *name, socklen_t namelen, int version)
{
	struct sonode *so;
	int error;

	dprint(1, ("bind(%d, %p, %d)\n",
	    sock, (void *)name, namelen));

	if ((so = getsonode(sock, &error, NULL)) == NULL)
		return (set_errno(error));

	/* Allocate and copyin name */
	/*
	 * X/Open test does not expect EFAULT with NULL name and non-zero
	 * namelen.
	 */
	if (name != NULL && namelen != 0) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		name = copyin_name(so, name, &namelen, &error);
		if (name == NULL) {
			releasef(sock);
			return (set_errno(error));
		}
	} else {
		name = NULL;
		namelen = 0;
	}

	switch (version) {
	default:
		error = SOP_BIND(so, name, namelen, 0);
		break;
	case SOV_XPG4_2:
		error = SOP_BIND(so, name, namelen, _SOBIND_XPG4_2);
		break;
	case SOV_SOCKBSD:
		error = SOP_BIND(so, name, namelen, _SOBIND_SOCKBSD);
		break;
	}
done:
	releasef(sock);
	if (name != NULL)
		kmem_free(name, (size_t)namelen);

	if (error)
		return (set_errno(error));
	return (0);
}

/* ARGSUSED2 */
int
listen(int sock, int backlog, int version)
{
	struct sonode *so;
	int error;

	dprint(1, ("listen(%d, %d)\n",
	    sock, backlog));

	if ((so = getsonode(sock, &error, NULL)) == NULL)
		return (set_errno(error));

	error = SOP_LISTEN(so, backlog);

	releasef(sock);
	if (error)
		return (set_errno(error));
	return (0);
}

/*ARGSUSED3*/
int
accept(int sock, struct sockaddr *name, socklen_t *namelenp, int version)
{
	struct sonode *so;
	file_t *fp;
	int error;
	socklen_t namelen;
	struct sonode *nso;
	struct vnode *nvp;
	struct file *nfp;
	int nfd;

	dprint(1, ("accept(%d, %p, %p)\n",
	    sock, (void *)name, (void *)namelenp));

	if ((so = getsonode(sock, &error, &fp)) == NULL)
		return (set_errno(error));

	if (name != NULL) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		if (copyin(namelenp, &namelen, sizeof (namelen))) {
			releasef(sock);
			return (set_errno(EFAULT));
		}
		if (namelen != 0) {
			error = useracc(name, (size_t)namelen, B_WRITE);
			if (error && do_useracc) {
				releasef(sock);
				return (set_errno(EFAULT));
			}
		} else
			name = NULL;
	} else {
		namelen = 0;
	}

	/*
	 * Allocate the user fd before SOP_ACCEPT() in order to
	 * catch EMFILE errors before calling SOP_ACCEPT().
	 */
	if ((nfd = ufalloc(0)) == -1) {
		eprintsoline(so, EMFILE);
		releasef(sock);
		return (set_errno(EMFILE));
	}
	error = SOP_ACCEPT(so, fp->f_flag, &nso);
	releasef(sock);
	if (error) {
		setf(nfd, NULL);
		return (set_errno(error));
	}

	nvp = SOTOV(nso);

	/*
	 * so_faddr_sa can not go away even though we are not holding so_lock.
	 * However, in theory its content could change from underneath us.
	 * But this is not possible in practice since it can only
	 * change due to either some socket system call
	 * or due to a T_CONN_CON being received from the stream head.
	 * Since the falloc/setf have not yet been done no thread
	 * can do any system call on nso and T_CONN_CON can not arrive
	 * on a socket that is already connected.
	 * Thus there is no reason to hold so_lock here.
	 *
	 * SOP_ACCEPT() is required to have set the valid bit for the faddr,
	 * but it could be instantly cleared by a disconnect from the transport.
	 * For that reason we ignore it here.
	 */
	ASSERT(MUTEX_NOT_HELD(&nso->so_lock));
	error = copyout_name(name, namelen, namelenp,
	    nso->so_faddr_sa, (socklen_t)nso->so_faddr_len);
	if (error) {
		setf(nfd, NULL);
		(void) VOP_CLOSE(nvp, 0, 1, 0, CRED(), NULL);
		VN_RELE(nvp);
		return (set_errno(error));
	}
	if (error = falloc(NULL, FWRITE|FREAD, &nfp, NULL)) {
		setf(nfd, NULL);
		(void) VOP_CLOSE(nvp, 0, 1, 0, CRED(), NULL);
		VN_RELE(nvp);
		eprintsoline(so, error);
		return (set_errno(error));
	}
	/*
	 * fill in the entries that falloc reserved
	 */
	nfp->f_vnode = nvp;
	mutex_exit(&nfp->f_tlock);
	setf(nfd, nfp);

	/*
	 * Copy FNDELAY and FNONBLOCK from listener to acceptor
	 */
	if (so->so_state & (SS_NDELAY|SS_NONBLOCK)) {
		uint_t oflag = nfp->f_flag;
		int arg = 0;

		if (so->so_state & SS_NONBLOCK)
			arg |= FNONBLOCK;
		else if (so->so_state & SS_NDELAY)
			arg |= FNDELAY;

		/*
		 * This code is a simplification of the F_SETFL code in fcntl()
		 * Ignore any errors from VOP_SETFL.
		 */
		if ((error = VOP_SETFL(nvp, oflag, arg, nfp->f_cred, NULL))
		    != 0) {
			eprintsoline(so, error);
			error = 0;
		} else {
			mutex_enter(&nfp->f_tlock);
			nfp->f_flag &= ~FMASK | (FREAD|FWRITE);
			nfp->f_flag |= arg;
			mutex_exit(&nfp->f_tlock);
		}
	}
	return (nfd);
}

int
connect(int sock, struct sockaddr *name, socklen_t namelen, int version)
{
	struct sonode *so;
	file_t *fp;
	int error;

	dprint(1, ("connect(%d, %p, %d)\n",
	    sock, (void *)name, namelen));

	if ((so = getsonode(sock, &error, &fp)) == NULL)
		return (set_errno(error));

	/* Allocate and copyin name */
	if (namelen != 0) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		name = copyin_name(so, name, &namelen, &error);
		if (name == NULL) {
			releasef(sock);
			return (set_errno(error));
		}
	} else
		name = NULL;

	error = SOP_CONNECT(so, name, namelen, fp->f_flag,
	    (version != SOV_XPG4_2) ? 0 : _SOCONNECT_XPG4_2);
	releasef(sock);
	if (name)
		kmem_free(name, (size_t)namelen);
	if (error)
		return (set_errno(error));
	return (0);
}

/*ARGSUSED2*/
int
shutdown(int sock, int how, int version)
{
	struct sonode *so;
	int error;

	dprint(1, ("shutdown(%d, %d)\n",
	    sock, how));

	if ((so = getsonode(sock, &error, NULL)) == NULL)
		return (set_errno(error));

	error = SOP_SHUTDOWN(so, how);

	releasef(sock);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * Common receive routine.
 */
static ssize_t
recvit(int sock,
	struct nmsghdr *msg,
	struct uio *uiop,
	int flags,
	socklen_t *namelenp,
	socklen_t *controllenp,
	int *flagsp)
{
	struct sonode *so;
	file_t *fp;
	void *name;
	socklen_t namelen;
	void *control;
	socklen_t controllen;
	ssize_t len;
	int error;

	if ((so = getsonode(sock, &error, &fp)) == NULL)
		return (set_errno(error));

	len = uiop->uio_resid;
	uiop->uio_fmode = fp->f_flag;
	uiop->uio_extflg = UIO_COPY_CACHED;

	name = msg->msg_name;
	namelen = msg->msg_namelen;
	control = msg->msg_control;
	controllen = msg->msg_controllen;

	msg->msg_flags = flags & (MSG_OOB | MSG_PEEK | MSG_WAITALL |
	    MSG_DONTWAIT | MSG_XPG4_2);

	error = SOP_RECVMSG(so, msg, uiop);
	if (error) {
		releasef(sock);
		return (set_errno(error));
	}
	lwp_stat_update(LWP_STAT_MSGRCV, 1);
	so_update_attrs(so, SOACC);
	releasef(sock);

	error = copyout_name(name, namelen, namelenp,
	    msg->msg_name, msg->msg_namelen);
	if (error)
		goto err;

	if (flagsp != NULL) {
		/*
		 * Clear internal flag.
		 */
		msg->msg_flags &= ~MSG_XPG4_2;

		/*
		 * Determine MSG_CTRUNC. sorecvmsg sets MSG_CTRUNC only
		 * when controllen is zero and there is control data to
		 * copy out.
		 */
		if (controllen != 0 &&
		    (msg->msg_controllen > controllen || control == NULL)) {
			dprint(1, ("recvit: CTRUNC %d %d %p\n",
			    msg->msg_controllen, controllen, control));

			msg->msg_flags |= MSG_CTRUNC;
		}
		if (copyout(&msg->msg_flags, flagsp,
		    sizeof (msg->msg_flags))) {
			error = EFAULT;
			goto err;
		}
	}
	/*
	 * Note: This MUST be done last. There can be no "goto err" after this
	 * point since it could make so_closefds run twice on some part
	 * of the file descriptor array.
	 */
	if (controllen != 0) {
		if (!(flags & MSG_XPG4_2)) {
			/*
			 * Good old msg_accrights can only return a multiple
			 * of 4 bytes.
			 */
			controllen &= ~((int)sizeof (uint32_t) - 1);
		}
		error = copyout_arg(control, controllen, controllenp,
		    msg->msg_control, msg->msg_controllen);
		if (error)
			goto err;

		if (msg->msg_controllen > controllen || control == NULL) {
			if (control == NULL)
				controllen = 0;
			so_closefds(msg->msg_control, msg->msg_controllen,
			    !(flags & MSG_XPG4_2), controllen);
		}
	}
	if (msg->msg_namelen != 0)
		kmem_free(msg->msg_name, (size_t)msg->msg_namelen);
	if (msg->msg_controllen != 0)
		kmem_free(msg->msg_control, (size_t)msg->msg_controllen);
	return (len - uiop->uio_resid);

err:
	/*
	 * If we fail and the control part contains file descriptors
	 * we have to close the fd's.
	 */
	if (msg->msg_controllen != 0)
		so_closefds(msg->msg_control, msg->msg_controllen,
		    !(flags & MSG_XPG4_2), 0);
	if (msg->msg_namelen != 0)
		kmem_free(msg->msg_name, (size_t)msg->msg_namelen);
	if (msg->msg_controllen != 0)
		kmem_free(msg->msg_control, (size_t)msg->msg_controllen);
	return (set_errno(error));
}

/*
 * Native system call
 */
ssize_t
recv(int sock, void *buffer, size_t len, int flags)
{
	struct nmsghdr lmsg;
	struct uio auio;
	struct iovec aiov[1];

	dprint(1, ("recv(%d, %p, %ld, %d)\n",
	    sock, buffer, len, flags));

	if ((ssize_t)len < 0) {
		return (set_errno(EINVAL));
	}

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	lmsg.msg_namelen = 0;
	lmsg.msg_controllen = 0;
	lmsg.msg_flags = 0;
	return (recvit(sock, &lmsg, &auio, flags, NULL, NULL, NULL));
}

ssize_t
recvfrom(int sock, void *buffer, size_t len, int flags,
	struct sockaddr *name, socklen_t *namelenp)
{
	struct nmsghdr lmsg;
	struct uio auio;
	struct iovec aiov[1];

	dprint(1, ("recvfrom(%d, %p, %ld, %d, %p, %p)\n",
	    sock, buffer, len, flags, (void *)name, (void *)namelenp));

	if ((ssize_t)len < 0) {
		return (set_errno(EINVAL));
	}

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	lmsg.msg_name = (char *)name;
	if (namelenp != NULL) {
		if (copyin(namelenp, &lmsg.msg_namelen,
		    sizeof (lmsg.msg_namelen)))
			return (set_errno(EFAULT));
	} else {
		lmsg.msg_namelen = 0;
	}
	lmsg.msg_controllen = 0;
	lmsg.msg_flags = 0;

	return (recvit(sock, &lmsg, &auio, flags, namelenp, NULL, NULL));
}

/*
 * Uses the MSG_XPG4_2 flag to determine if the caller is using
 * struct omsghdr or struct nmsghdr.
 */
ssize_t
recvmsg(int sock, struct nmsghdr *msg, int flags)
{
	STRUCT_DECL(nmsghdr, u_lmsg);
	STRUCT_HANDLE(nmsghdr, umsgptr);
	struct nmsghdr lmsg;
	struct uio auio;
	struct iovec aiov[MSG_MAXIOVLEN];
	int iovcnt;
	ssize_t len;
	int i;
	int *flagsp;
	model_t	model;

	dprint(1, ("recvmsg(%d, %p, %d)\n",
	    sock, (void *)msg, flags));

	model = get_udatamodel();
	STRUCT_INIT(u_lmsg, model);
	STRUCT_SET_HANDLE(umsgptr, model, msg);

	if (flags & MSG_XPG4_2) {
		if (copyin(msg, STRUCT_BUF(u_lmsg), STRUCT_SIZE(u_lmsg)))
			return (set_errno(EFAULT));
		flagsp = STRUCT_FADDR(umsgptr, msg_flags);
	} else {
		/*
		 * Assumes that nmsghdr and omsghdr are identically shaped
		 * except for the added msg_flags field.
		 */
		if (copyin(msg, STRUCT_BUF(u_lmsg),
		    SIZEOF_STRUCT(omsghdr, model)))
			return (set_errno(EFAULT));
		STRUCT_FSET(u_lmsg, msg_flags, 0);
		flagsp = NULL;
	}

	/*
	 * Code below us will kmem_alloc memory and hang it
	 * off msg_control and msg_name fields. This forces
	 * us to copy the structure to its native form.
	 */
	lmsg.msg_name = STRUCT_FGETP(u_lmsg, msg_name);
	lmsg.msg_namelen = STRUCT_FGET(u_lmsg, msg_namelen);
	lmsg.msg_iov = STRUCT_FGETP(u_lmsg, msg_iov);
	lmsg.msg_iovlen = STRUCT_FGET(u_lmsg, msg_iovlen);
	lmsg.msg_control = STRUCT_FGETP(u_lmsg, msg_control);
	lmsg.msg_controllen = STRUCT_FGET(u_lmsg, msg_controllen);
	lmsg.msg_flags = STRUCT_FGET(u_lmsg, msg_flags);

	iovcnt = lmsg.msg_iovlen;

	if (iovcnt <= 0 || iovcnt > MSG_MAXIOVLEN) {
		return (set_errno(EMSGSIZE));
	}

#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded, while ensuring
	 * that they can't move more than 2Gbytes of data in a single call.
	 */
	if (model == DATAMODEL_ILP32) {
		struct iovec32 aiov32[MSG_MAXIOVLEN];
		ssize32_t count32;

		if (copyin((struct iovec32 *)lmsg.msg_iov, aiov32,
		    iovcnt * sizeof (struct iovec32)))
			return (set_errno(EFAULT));

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32;

			iovlen32 = aiov32[i].iov_len;
			count32 += iovlen32;
			if (iovlen32 < 0 || count32 < 0)
				return (set_errno(EINVAL));
			aiov[i].iov_len = iovlen32;
			aiov[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
	} else
#endif /* _SYSCALL32_IMPL */
	if (copyin(lmsg.msg_iov, aiov, iovcnt * sizeof (struct iovec))) {
		return (set_errno(EFAULT));
	}
	len = 0;
	for (i = 0; i < iovcnt; i++) {
		ssize_t iovlen = aiov[i].iov_len;
		len += iovlen;
		if (iovlen < 0 || len < 0) {
			return (set_errno(EINVAL));
		}
	}
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	if (lmsg.msg_control != NULL &&
	    (do_useracc == 0 ||
	    useracc(lmsg.msg_control, lmsg.msg_controllen,
	    B_WRITE) != 0)) {
		return (set_errno(EFAULT));
	}

	return (recvit(sock, &lmsg, &auio, flags,
	    STRUCT_FADDR(umsgptr, msg_namelen),
	    STRUCT_FADDR(umsgptr, msg_controllen), flagsp));
}

/*
 * Common send function.
 */
static ssize_t
sendit(int sock, struct nmsghdr *msg, struct uio *uiop, int flags)
{
	struct sonode *so;
	file_t *fp;
	void *name;
	socklen_t namelen;
	void *control;
	socklen_t controllen;
	ssize_t len;
	int error;

	if ((so = getsonode(sock, &error, &fp)) == NULL)
		return (set_errno(error));

	uiop->uio_fmode = fp->f_flag;

	if (so->so_family == AF_UNIX)
		uiop->uio_extflg = UIO_COPY_CACHED;
	else
		uiop->uio_extflg = UIO_COPY_DEFAULT;

	/* Allocate and copyin name and control */
	name = msg->msg_name;
	namelen = msg->msg_namelen;
	if (name != NULL && namelen != 0) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		name = copyin_name(so,
		    (struct sockaddr *)name,
		    &namelen, &error);
		if (name == NULL)
			goto done3;
		/* copyin_name null terminates addresses for AF_UNIX */
		msg->msg_namelen = namelen;
		msg->msg_name = name;
	} else {
		msg->msg_name = name = NULL;
		msg->msg_namelen = namelen = 0;
	}

	control = msg->msg_control;
	controllen = msg->msg_controllen;
	if ((control != NULL) && (controllen != 0)) {
		/*
		 * Verify that the length is not excessive to prevent
		 * an application from consuming all of kernel memory.
		 */
		if (controllen > SO_MAXARGSIZE) {
			error = EINVAL;
			goto done2;
		}
		control = kmem_alloc(controllen, KM_SLEEP);

		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		if (copyin(msg->msg_control, control, controllen)) {
			error = EFAULT;
			goto done1;
		}
		msg->msg_control = control;
	} else {
		msg->msg_control = control = NULL;
		msg->msg_controllen = controllen = 0;
	}

	len = uiop->uio_resid;
	msg->msg_flags = flags;

	error = SOP_SENDMSG(so, msg, uiop);
done1:
	if (control != NULL)
		kmem_free(control, controllen);
done2:
	if (name != NULL)
		kmem_free(name, namelen);
done3:
	if (error != 0) {
		releasef(sock);
		return (set_errno(error));
	}
	lwp_stat_update(LWP_STAT_MSGSND, 1);
	so_update_attrs(so, SOMOD);
	releasef(sock);
	return (len - uiop->uio_resid);
}

/*
 * Native system call
 */
ssize_t
send(int sock, void *buffer, size_t len, int flags)
{
	struct nmsghdr lmsg;
	struct uio auio;
	struct iovec aiov[1];

	dprint(1, ("send(%d, %p, %ld, %d)\n",
	    sock, buffer, len, flags));

	if ((ssize_t)len < 0) {
		return (set_errno(EINVAL));
	}

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	lmsg.msg_name = NULL;
	lmsg.msg_control = NULL;
	if (!(flags & MSG_XPG4_2)) {
		/*
		 * In order to be compatible with the libsocket/sockmod
		 * implementation we set EOR for all send* calls.
		 */
		flags |= MSG_EOR;
	}
	return (sendit(sock, &lmsg, &auio, flags));
}

/*
 * Uses the MSG_XPG4_2 flag to determine if the caller is using
 * struct omsghdr or struct nmsghdr.
 */
ssize_t
sendmsg(int sock, struct nmsghdr *msg, int flags)
{
	struct nmsghdr lmsg;
	STRUCT_DECL(nmsghdr, u_lmsg);
	struct uio auio;
	struct iovec aiov[MSG_MAXIOVLEN];
	int iovcnt;
	ssize_t len;
	int i;
	model_t	model;

	dprint(1, ("sendmsg(%d, %p, %d)\n", sock, (void *)msg, flags));

	model = get_udatamodel();
	STRUCT_INIT(u_lmsg, model);

	if (flags & MSG_XPG4_2) {
		if (copyin(msg, (char *)STRUCT_BUF(u_lmsg),
		    STRUCT_SIZE(u_lmsg)))
			return (set_errno(EFAULT));
	} else {
		/*
		 * Assumes that nmsghdr and omsghdr are identically shaped
		 * except for the added msg_flags field.
		 */
		if (copyin(msg, (char *)STRUCT_BUF(u_lmsg),
		    SIZEOF_STRUCT(omsghdr, model)))
			return (set_errno(EFAULT));
		/*
		 * In order to be compatible with the libsocket/sockmod
		 * implementation we set EOR for all send* calls.
		 */
		flags |= MSG_EOR;
	}

	/*
	 * Code below us will kmem_alloc memory and hang it
	 * off msg_control and msg_name fields. This forces
	 * us to copy the structure to its native form.
	 */
	lmsg.msg_name = STRUCT_FGETP(u_lmsg, msg_name);
	lmsg.msg_namelen = STRUCT_FGET(u_lmsg, msg_namelen);
	lmsg.msg_iov = STRUCT_FGETP(u_lmsg, msg_iov);
	lmsg.msg_iovlen = STRUCT_FGET(u_lmsg, msg_iovlen);
	lmsg.msg_control = STRUCT_FGETP(u_lmsg, msg_control);
	lmsg.msg_controllen = STRUCT_FGET(u_lmsg, msg_controllen);
	lmsg.msg_flags = STRUCT_FGET(u_lmsg, msg_flags);

	iovcnt = lmsg.msg_iovlen;

	if (iovcnt <= 0 || iovcnt > MSG_MAXIOVLEN) {
		/*
		 * Unless this is XPG 4.2 we allow iovcnt == 0 to
		 * be compatible with SunOS 4.X and 4.4BSD.
		 */
		if (iovcnt != 0 || (flags & MSG_XPG4_2))
			return (set_errno(EMSGSIZE));
	}

#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded, while ensuring
	 * that they can't move more than 2Gbytes of data in a single call.
	 */
	if (model == DATAMODEL_ILP32) {
		struct iovec32 aiov32[MSG_MAXIOVLEN];
		ssize32_t count32;

		if (iovcnt != 0 &&
		    copyin((struct iovec32 *)lmsg.msg_iov, aiov32,
		    iovcnt * sizeof (struct iovec32)))
			return (set_errno(EFAULT));

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32;

			iovlen32 = aiov32[i].iov_len;
			count32 += iovlen32;
			if (iovlen32 < 0 || count32 < 0)
				return (set_errno(EINVAL));
			aiov[i].iov_len = iovlen32;
			aiov[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
	} else
#endif /* _SYSCALL32_IMPL */
	if (iovcnt != 0 &&
	    copyin(lmsg.msg_iov, aiov,
	    (unsigned)iovcnt * sizeof (struct iovec))) {
		return (set_errno(EFAULT));
	}
	len = 0;
	for (i = 0; i < iovcnt; i++) {
		ssize_t iovlen = aiov[i].iov_len;
		len += iovlen;
		if (iovlen < 0 || len < 0) {
			return (set_errno(EINVAL));
		}
	}
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	return (sendit(sock, &lmsg, &auio, flags));
}

ssize_t
sendto(int sock, void *buffer, size_t len, int flags,
    struct sockaddr *name, socklen_t namelen)
{
	struct nmsghdr lmsg;
	struct uio auio;
	struct iovec aiov[1];

	dprint(1, ("sendto(%d, %p, %ld, %d, %p, %d)\n",
	    sock, buffer, len, flags, (void *)name, namelen));

	if ((ssize_t)len < 0) {
		return (set_errno(EINVAL));
	}

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	lmsg.msg_name = (char *)name;
	lmsg.msg_namelen = namelen;
	lmsg.msg_control = NULL;
	if (!(flags & MSG_XPG4_2)) {
		/*
		 * In order to be compatible with the libsocket/sockmod
		 * implementation we set EOR for all send* calls.
		 */
		flags |= MSG_EOR;
	}
	return (sendit(sock, &lmsg, &auio, flags));
}

/*ARGSUSED3*/
int
getpeername(int sock, struct sockaddr *name, socklen_t *namelenp, int version)
{
	struct sonode *so;
	int error;
	socklen_t namelen;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sin;			/* Temporary buffer, common case */
	void *addr;		/* Temporary buffer, uncommon case */
	socklen_t addrlen, size;

	dprint(1, ("getpeername(%d, %p, %p)\n",
	    sock, (void *)name, (void *)namelenp));

	if ((so = getsonode(sock, &error, NULL)) == NULL)
		goto bad;

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	if (copyin(namelenp, &namelen, sizeof (namelen)) ||
	    (name == NULL && namelen != 0)) {
		error = EFAULT;
		goto rel_out;
	}
	/*
	 * If a connect or accept has been done, unless we're an Xnet socket,
	 * the remote address has already been updated in so_faddr_sa.
	 */
	if (so->so_version != SOV_SOCKSTREAM && so->so_version != SOV_SOCKBSD ||
	    !(so->so_state & SS_FADDR_VALID)) {
		if ((error = SOP_GETPEERNAME(so)) != 0)
			goto rel_out;
	}

	if (so->so_faddr_maxlen <= sizeof (sin)) {
		size = 0;
		addr = &sin;
	} else {
		/*
		 * Allocate temporary to avoid holding so_lock across
		 * copyout
		 */
		size = so->so_faddr_maxlen;
		addr = kmem_alloc(size, KM_SLEEP);
	}
	/* Prevent so_faddr_sa/len from changing while accessed */
	mutex_enter(&so->so_lock);
	if (!(so->so_state & SS_ISCONNECTED)) {
		mutex_exit(&so->so_lock);
		error = ENOTCONN;
		goto free_out;
	}
	addrlen = so->so_faddr_len;
	bcopy(so->so_faddr_sa, addr, addrlen);
	mutex_exit(&so->so_lock);

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	error = copyout_name(name, namelen, namelenp, addr,
	    (so->so_state & SS_FADDR_NOXLATE) ? 0 : addrlen);
free_out:
	if (size != 0)
		kmem_free(addr, size);
rel_out:
	releasef(sock);
bad:	return (error != 0 ? set_errno(error) : 0);
}

/*ARGSUSED3*/
int
getsockname(int sock, struct sockaddr *name,
		socklen_t *namelenp, int version)
{
	struct sonode *so;
	int error;
	socklen_t namelen;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sin;			/* Temporary buffer, common case */
	void *addr;		/* Temporary buffer, uncommon case */
	socklen_t addrlen, size;

	dprint(1, ("getsockname(%d, %p, %p)\n",
	    sock, (void *)name, (void *)namelenp));

	if ((so = getsonode(sock, &error, NULL)) == NULL)
		goto bad;

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	if (copyin(namelenp, &namelen, sizeof (namelen)) ||
	    (name == NULL && namelen != 0)) {
		error = EFAULT;
		goto rel_out;
	}

	/*
	 * If a bind or accept has been done, unless we're an Xnet endpoint,
	 * the local address has already been updated in so_laddr_sa.
	 */
	if ((so->so_version != SOV_SOCKSTREAM &&
	    so->so_version != SOV_SOCKBSD) ||
	    !(so->so_state & SS_LADDR_VALID)) {
		if ((error = SOP_GETSOCKNAME(so)) != 0)
			goto rel_out;
	}

	if (so->so_laddr_maxlen <= sizeof (sin)) {
		size = 0;
		addr = &sin;
	} else {
		/*
		 * Allocate temporary to avoid holding so_lock across
		 * copyout
		 */
		size = so->so_laddr_maxlen;
		addr = kmem_alloc(size, KM_SLEEP);
	}
	/* Prevent so_laddr_sa/len from changing while accessed */
	mutex_enter(&so->so_lock);
	addrlen = so->so_laddr_len;
	bcopy(so->so_laddr_sa, addr, addrlen);
	mutex_exit(&so->so_lock);

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	error = copyout_name(name, namelen, namelenp,
	    addr, addrlen);
	if (size != 0)
		kmem_free(addr, size);
rel_out:
	releasef(sock);
bad:	return (error != 0 ? set_errno(error) : 0);
}

/*ARGSUSED5*/
int
getsockopt(int sock,
	int level,
	int option_name,
	void *option_value,
	socklen_t *option_lenp,
	int version)
{
	struct sonode *so;
	socklen_t optlen, optlen_res;
	void *optval;
	int error;

	dprint(1, ("getsockopt(%d, %d, %d, %p, %p)\n",
	    sock, level, option_name, option_value, (void *)option_lenp));

	if ((so = getsonode(sock, &error, NULL)) == NULL)
		return (set_errno(error));

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	if (copyin(option_lenp, &optlen, sizeof (optlen))) {
		releasef(sock);
		return (set_errno(EFAULT));
	}
	/*
	 * Verify that the length is not excessive to prevent
	 * an application from consuming all of kernel memory.
	 */
	if (optlen > SO_MAXARGSIZE) {
		error = EINVAL;
		releasef(sock);
		return (set_errno(error));
	}
	optval = kmem_alloc(optlen, KM_SLEEP);
	optlen_res = optlen;
	error = SOP_GETSOCKOPT(so, level, option_name, optval,
	    &optlen_res, (version != SOV_XPG4_2) ? 0 : _SOGETSOCKOPT_XPG4_2);
	releasef(sock);
	if (error) {
		kmem_free(optval, optlen);
		return (set_errno(error));
	}
	error = copyout_arg(option_value, optlen, option_lenp,
	    optval, optlen_res);
	kmem_free(optval, optlen);
	if (error)
		return (set_errno(error));
	return (0);
}

/*ARGSUSED5*/
int
setsockopt(int sock,
	int level,
	int option_name,
	void *option_value,
	socklen_t option_len,
	int version)
{
	struct sonode *so;
	intptr_t buffer[2];
	void *optval = NULL;
	int error;

	dprint(1, ("setsockopt(%d, %d, %d, %p, %d)\n",
	    sock, level, option_name, option_value, option_len));

	if ((so = getsonode(sock, &error, NULL)) == NULL)
		return (set_errno(error));

	if (option_value != NULL) {
		if (option_len != 0) {
			/*
			 * Verify that the length is not excessive to prevent
			 * an application from consuming all of kernel memory.
			 */
			if (option_len > SO_MAXARGSIZE) {
				error = EINVAL;
				goto done2;
			}
			optval = option_len <= sizeof (buffer) ?
			    &buffer : kmem_alloc((size_t)option_len, KM_SLEEP);
			ASSERT(MUTEX_NOT_HELD(&so->so_lock));
			if (copyin(option_value, optval, (size_t)option_len)) {
				error = EFAULT;
				goto done1;
			}
		}
	} else
		option_len = 0;

	error = SOP_SETSOCKOPT(so, level, option_name, optval,
	    (t_uscalar_t)option_len);
done1:
	if (optval != buffer)
		kmem_free(optval, (size_t)option_len);
done2:
	releasef(sock);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * Add config info when devpath is non-NULL; delete info when devpath is NULL.
 * devpath is a user address.
 */
int
sockconfig(int domain, int type, int protocol, char *devpath)
{
	char *kdevpath;		/* Copied in devpath string */
	size_t kdevpathlen;
	int error = 0;

	dprint(1, ("sockconfig(%d, %d, %d, %p)\n",
	    domain, type, protocol, (void *)devpath));

	if (secpolicy_net_config(CRED(), B_FALSE) != 0)
		return (set_errno(EPERM));

	if (devpath == NULL) {
		/* Deleting an entry */
		kdevpath = NULL;
		kdevpathlen = 0;
	} else {
		/*
		 * Adding an entry.
		 * Copyin the devpath.
		 * This also makes it possible to check for too long pathnames.
		 * Compress the space needed for the devpath before passing it
		 * to soconfig - soconfig will store the string until
		 * the configuration is removed.
		 */
		char *buf;

		buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if ((error = copyinstr(devpath, buf, MAXPATHLEN,
		    &kdevpathlen)) != 0) {
			kmem_free(buf, MAXPATHLEN);
			goto done;
		}

		kdevpath = kmem_alloc(kdevpathlen, KM_SLEEP);
		bcopy(buf, kdevpath, kdevpathlen);
		kdevpath[kdevpathlen - 1] = '\0';

		kmem_free(buf, MAXPATHLEN);
	}
	error = soconfig(domain, type, protocol, kdevpath, (int)kdevpathlen);
done:
	if (error) {
		eprintline(error);
		return (set_errno(error));
	}
	return (0);
}


/*
 * Sendfile is implemented through two schemes, direct I/O or by
 * caching in the filesystem page cache. We cache the input file by
 * default and use direct I/O only if sendfile_max_size is set
 * appropriately as explained below. Note that this logic is consistent
 * with other filesystems where caching is turned on by default
 * unless explicitly turned off by using the DIRECTIO ioctl.
 *
 * We choose a slightly different scheme here. One can turn off
 * caching by setting sendfile_max_size to 0. One can also enable
 * caching of files <= sendfile_max_size by setting sendfile_max_size
 * to an appropriate value. By default sendfile_max_size is set to the
 * maximum value so that all files are cached. In future, we may provide
 * better interfaces for caching the file.
 *
 * Sendfile through Direct I/O (Zero copy)
 * --------------------------------------
 *
 * As disks are normally slower than the network, we can't have a
 * single thread that reads the disk and writes to the network. We
 * need to have parallelism. This is done by having the sendfile
 * thread create another thread that reads from the filesystem
 * and queues it for network processing. In this scheme, the data
 * is never copied anywhere i.e it is zero copy unlike the other
 * scheme.
 *
 * We have a sendfile queue (snfq) where each sendfile
 * request (snf_req_t) is queued for processing by a thread. Number
 * of threads is dynamically allocated and they exit if they are idling
 * beyond a specified amount of time. When each request (snf_req_t) is
 * processed by a thread, it produces a number of mblk_t structures to
 * be consumed by the sendfile thread. snf_deque and snf_enque are
 * used for consuming and producing mblks. Size of the filesystem
 * read is determined by the tunable (sendfile_read_size). A single
 * mblk holds sendfile_read_size worth of data (except the last
 * read of the file) which is sent down as a whole to the network.
 * sendfile_read_size is set to 1 MB as this seems to be the optimal
 * value for the UFS filesystem backed by a striped storage array.
 *
 * Synchronisation between read (producer) and write (consumer) threads.
 * --------------------------------------------------------------------
 *
 * sr_lock protects sr_ib_head and sr_ib_tail. The lock is held while
 * adding and deleting items in this list. Error can happen anytime
 * during read or write. There could be unprocessed mblks in the
 * sr_ib_XXX list when a read or write error occurs. Whenever error
 * is encountered, we need two things to happen :
 *
 * a) One of the threads need to clean the mblks.
 * b) When one thread encounters an error, the other should stop.
 *
 * For (a), we don't want to penalize the reader thread as it could do
 * some useful work processing other requests. For (b), the error can
 * be detected by examining sr_read_error or sr_write_error.
 * sr_lock protects sr_read_error and sr_write_error. If both reader and
 * writer encounters error, we need to report the write error back to
 * the application as that's what would have happened if the operations
 * were done sequentially. With this in mind, following should work :
 *
 * 	- Check for errors before read or write.
 *	- If the reader encounters error, set the error in sr_read_error.
 *	  Check sr_write_error, if it is set, send cv_signal as it is
 *	  waiting for reader to complete. If it is not set, the writer
 *	  is either running sinking data to the network or blocked
 *        because of flow control. For handling the latter case, we
 *	  always send a signal. In any case, it will examine sr_read_error
 *	  and return. sr_read_error is marked with SR_READ_DONE to tell
 *	  the writer that the reader is done in all the cases.
 *	- If the writer encounters error, set the error in sr_write_error.
 *	  The reader thread is either blocked because of flow control or
 *	  running reading data from the disk. For the former, we need to
 *	  wakeup the thread. Again to keep it simple, we always wake up
 *	  the reader thread. Then, wait for the read thread to complete
 *	  if it is not done yet. Cleanup and return.
 *
 * High and low water marks for the read thread.
 * --------------------------------------------
 *
 * If sendfile() is used to send data over a slow network, we need to
 * make sure that the read thread does not produce data at a faster
 * rate than the network. This can happen if the disk is faster than
 * the network. In such a case, we don't want to build a very large queue.
 * But we would still like to get all of the network throughput possible.
 * This implies that network should never block waiting for data.
 * As there are lot of disk throughput/network throughput combinations
 * possible, it is difficult to come up with an accurate number.
 * A typical 10K RPM disk has a max seek latency 17ms and rotational
 * latency of 3ms for reading a disk block. Thus, the total latency to
 * initiate a new read, transfer data from the disk and queue for
 * transmission would take about a max of 25ms. Todays max transfer rate
 * for network is 100MB/sec. If the thread is blocked because of flow
 * control, it would take 25ms to get new data ready for transmission.
 * We have to make sure that network is not idling, while we are initiating
 * new transfers. So, at 100MB/sec, to keep network busy we would need
 * 2.5MB of data. Rounding off, we keep the low water mark to be 3MB of data.
 * We need to pick a high water mark so that the woken up thread would
 * do considerable work before blocking again to prevent thrashing. Currently,
 * we pick this to be 10 times that of the low water mark.
 *
 * Sendfile with segmap caching (One copy from page cache to mblks).
 * ----------------------------------------------------------------
 *
 * We use the segmap cache for caching the file, if the size of file
 * is <= sendfile_max_size. In this case we don't use threads as VM
 * is reasonably fast enough to keep up with the network. If the underlying
 * transport allows, we call segmap_getmapflt() to map MAXBSIZE (8K) worth
 * of data into segmap space, and use the virtual address from segmap
 * directly through desballoc() to avoid copy. Once the transport is done
 * with the data, the mapping will be released through segmap_release()
 * called by the call-back routine.
 *
 * If zero-copy is not allowed by the transport, we simply call VOP_READ()
 * to copy the data from the filesystem into our temporary network buffer.
 *
 * To disable caching, set sendfile_max_size to 0.
 */

uint_t sendfile_read_size = 1024 * 1024;
#define	SENDFILE_REQ_LOWAT	3 * 1024 * 1024
uint_t sendfile_req_lowat = SENDFILE_REQ_LOWAT;
uint_t sendfile_req_hiwat = 10 * SENDFILE_REQ_LOWAT;
struct sendfile_stats sf_stats;
struct sendfile_queue *snfq;
clock_t snfq_timeout;
off64_t sendfile_max_size;

static void snf_enque(snf_req_t *, mblk_t *);
static mblk_t *snf_deque(snf_req_t *);

void
sendfile_init(void)
{
	snfq = kmem_zalloc(sizeof (struct sendfile_queue), KM_SLEEP);

	mutex_init(&snfq->snfq_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&snfq->snfq_cv, NULL, CV_DEFAULT, NULL);
	snfq->snfq_max_threads = max_ncpus;
	snfq_timeout = SNFQ_TIMEOUT;
	/* Cache all files by default. */
	sendfile_max_size = MAXOFFSET_T;
}

/*
 * Queues a mblk_t for network processing.
 */
static void
snf_enque(snf_req_t *sr, mblk_t *mp)
{
	mp->b_next = NULL;
	mutex_enter(&sr->sr_lock);
	if (sr->sr_mp_head == NULL) {
		sr->sr_mp_head = sr->sr_mp_tail = mp;
		cv_signal(&sr->sr_cv);
	} else {
		sr->sr_mp_tail->b_next = mp;
		sr->sr_mp_tail = mp;
	}
	sr->sr_qlen += MBLKL(mp);
	while ((sr->sr_qlen > sr->sr_hiwat) &&
	    (sr->sr_write_error == 0)) {
		sf_stats.ss_full_waits++;
		cv_wait(&sr->sr_cv, &sr->sr_lock);
	}
	mutex_exit(&sr->sr_lock);
}

/*
 * De-queues a mblk_t for network processing.
 */
static mblk_t *
snf_deque(snf_req_t *sr)
{
	mblk_t *mp;

	mutex_enter(&sr->sr_lock);
	/*
	 * If we have encountered an error on read or read is
	 * completed and no more mblks, return NULL.
	 * We need to check for NULL sr_mp_head also as
	 * the reads could have completed and there is
	 * nothing more to come.
	 */
	if (((sr->sr_read_error & ~SR_READ_DONE) != 0) ||
	    ((sr->sr_read_error & SR_READ_DONE) &&
	    sr->sr_mp_head == NULL)) {
		mutex_exit(&sr->sr_lock);
		return (NULL);
	}
	/*
	 * To start with neither SR_READ_DONE is marked nor
	 * the error is set. When we wake up from cv_wait,
	 * following are the possibilities :
	 *
	 *	a) sr_read_error is zero and mblks are queued.
	 *	b) sr_read_error is set to SR_READ_DONE
	 *	   and mblks are queued.
	 *	c) sr_read_error is set to SR_READ_DONE
	 *	   and no mblks.
	 *	d) sr_read_error is set to some error other
	 *	   than SR_READ_DONE.
	 */

	while ((sr->sr_read_error == 0) && (sr->sr_mp_head == NULL)) {
		sf_stats.ss_empty_waits++;
		cv_wait(&sr->sr_cv, &sr->sr_lock);
	}
	/* Handle (a) and (b) first  - the normal case. */
	if (((sr->sr_read_error & ~SR_READ_DONE) == 0) &&
	    (sr->sr_mp_head != NULL)) {
		mp = sr->sr_mp_head;
		sr->sr_mp_head = mp->b_next;
		sr->sr_qlen -= MBLKL(mp);
		if (sr->sr_qlen < sr->sr_lowat)
			cv_signal(&sr->sr_cv);
		mutex_exit(&sr->sr_lock);
		mp->b_next = NULL;
		return (mp);
	}
	/* Handle (c) and (d). */
	mutex_exit(&sr->sr_lock);
	return (NULL);
}

/*
 * Reads data from the filesystem and queues it for network processing.
 */
void
snf_async_read(snf_req_t *sr)
{
	size_t iosize;
	u_offset_t fileoff;
	u_offset_t size;
	int ret_size;
	int error;
	file_t *fp;
	mblk_t *mp;
	struct vnode *vp;
	int extra = 0;
	int maxblk = 0;
	int wroff = 0;
	struct sonode *so;

	fp = sr->sr_fp;
	size = sr->sr_file_size;
	fileoff = sr->sr_file_off;

	/*
	 * Ignore the error for filesystems that doesn't support DIRECTIO.
	 */
	(void) VOP_IOCTL(fp->f_vnode, _FIODIRECTIO, DIRECTIO_ON, 0,
	    kcred, NULL, NULL);

	vp = sr->sr_vp;
	if (vp->v_type == VSOCK) {
		stdata_t *stp;

		/*
		 * Get the extra space to insert a header and a trailer.
		 */
		so = VTOSO(vp);
		stp = vp->v_stream;
		wroff = (int)(stp->sd_wroff);
		maxblk = (int)(stp->sd_maxblk);
		extra = wroff + (int)(stp->sd_tail);
	}

	while ((size != 0) && (sr->sr_write_error == 0)) {

		iosize = (int)MIN(sr->sr_maxpsz, size);

		/*
		 * For sockets acting as an SSL proxy, we
		 * need to adjust the size to the maximum
		 * SSL record size set in the stream head.
		 */
		if (vp->v_type == VSOCK && so->so_kssl_ctx != NULL)
			iosize = (int)MIN(iosize, maxblk);

		if ((mp = allocb(iosize + extra, BPRI_MED)) == NULL) {
			error = EAGAIN;
			break;
		}

		mp->b_rptr += wroff;

		ret_size = soreadfile(fp, mp->b_rptr, fileoff, &error, iosize);

		/* Error or Reached EOF ? */
		if ((error != 0) || (ret_size == 0)) {
			freeb(mp);
			break;
		}
		mp->b_wptr = mp->b_rptr + ret_size;

		snf_enque(sr, mp);
		size -= ret_size;
		fileoff += ret_size;
	}
	(void) VOP_IOCTL(fp->f_vnode, _FIODIRECTIO, DIRECTIO_OFF, 0,
	    kcred, NULL, NULL);
	mutex_enter(&sr->sr_lock);
	sr->sr_read_error = error;
	sr->sr_read_error |= SR_READ_DONE;
	cv_signal(&sr->sr_cv);
	mutex_exit(&sr->sr_lock);
}

void
snf_async_thread(void)
{
	snf_req_t *sr;
	callb_cpr_t cprinfo;
	clock_t time_left = 1;
	clock_t now;

	CALLB_CPR_INIT(&cprinfo, &snfq->snfq_lock, callb_generic_cpr, "snfq");

	mutex_enter(&snfq->snfq_lock);
	for (;;) {
		/*
		 * If we didn't find a entry, then block until woken up
		 * again and then look through the queues again.
		 */
		while ((sr = snfq->snfq_req_head) == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			if (time_left <= 0) {
				snfq->snfq_svc_threads--;
				CALLB_CPR_EXIT(&cprinfo);
				thread_exit();
				/* NOTREACHED */
			}
			snfq->snfq_idle_cnt++;

			time_to_wait(&now, snfq_timeout);
			time_left = cv_timedwait(&snfq->snfq_cv,
			    &snfq->snfq_lock, now);
			snfq->snfq_idle_cnt--;

			CALLB_CPR_SAFE_END(&cprinfo, &snfq->snfq_lock);
		}
		snfq->snfq_req_head = sr->sr_next;
		snfq->snfq_req_cnt--;
		mutex_exit(&snfq->snfq_lock);
		snf_async_read(sr);
		mutex_enter(&snfq->snfq_lock);
	}
}


snf_req_t *
create_thread(int operation, struct vnode *vp, file_t *fp,
    u_offset_t fileoff, u_offset_t size)
{
	snf_req_t *sr;
	stdata_t *stp;

	sr = (snf_req_t *)kmem_zalloc(sizeof (snf_req_t), KM_SLEEP);

	sr->sr_vp = vp;
	sr->sr_fp = fp;
	stp = vp->v_stream;

	/*
	 * store sd_qn_maxpsz into sr_maxpsz while we have stream head.
	 * stream might be closed before thread returns from snf_async_read.
	 */
	if (stp->sd_qn_maxpsz > 0) {
		sr->sr_maxpsz = MIN(MAXBSIZE, stp->sd_qn_maxpsz);
	} else {
		sr->sr_maxpsz = MAXBSIZE;
	}

	sr->sr_operation = operation;
	sr->sr_file_off = fileoff;
	sr->sr_file_size = size;
	sr->sr_hiwat = sendfile_req_hiwat;
	sr->sr_lowat = sendfile_req_lowat;
	mutex_init(&sr->sr_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sr->sr_cv, NULL, CV_DEFAULT, NULL);
	/*
	 * See whether we need another thread for servicing this
	 * request. If there are already enough requests queued
	 * for the threads, create one if not exceeding
	 * snfq_max_threads.
	 */
	mutex_enter(&snfq->snfq_lock);
	if (snfq->snfq_req_cnt >= snfq->snfq_idle_cnt &&
	    snfq->snfq_svc_threads < snfq->snfq_max_threads) {
		(void) thread_create(NULL, 0, &snf_async_thread, 0, 0, &p0,
		    TS_RUN, minclsyspri);
		snfq->snfq_svc_threads++;
	}
	if (snfq->snfq_req_head == NULL) {
		snfq->snfq_req_head = snfq->snfq_req_tail = sr;
		cv_signal(&snfq->snfq_cv);
	} else {
		snfq->snfq_req_tail->sr_next = sr;
		snfq->snfq_req_tail = sr;
	}
	snfq->snfq_req_cnt++;
	mutex_exit(&snfq->snfq_lock);
	return (sr);
}

int
snf_direct_io(file_t *fp, file_t *rfp, u_offset_t fileoff, u_offset_t size,
    ssize_t *count)
{
	snf_req_t *sr;
	mblk_t *mp;
	int iosize;
	int error = 0;
	short fflag;
	struct vnode *vp;
	int ksize;

	ksize = 0;
	*count = 0;

	vp = fp->f_vnode;
	fflag = fp->f_flag;
	if ((sr = create_thread(READ_OP, vp, rfp, fileoff, size)) == NULL)
		return (EAGAIN);

	/*
	 * We check for read error in snf_deque. It has to check
	 * for successful READ_DONE and return NULL, and we might
	 * as well make an additional check there.
	 */
	while ((mp = snf_deque(sr)) != NULL) {

		if (ISSIG(curthread, JUSTLOOKING)) {
			freeb(mp);
			error = EINTR;
			break;
		}
		iosize = MBLKL(mp);

		if ((error = kstrwritemp(vp, mp, fflag)) != 0) {
			freeb(mp);
			break;
		}
		ksize += iosize;
	}
	*count = ksize;

	mutex_enter(&sr->sr_lock);
	sr->sr_write_error = error;
	/* Look at the big comments on why we cv_signal here. */
	cv_signal(&sr->sr_cv);

	/* Wait for the reader to complete always. */
	while (!(sr->sr_read_error & SR_READ_DONE)) {
		cv_wait(&sr->sr_cv, &sr->sr_lock);
	}
	/* If there is no write error, check for read error. */
	if (error == 0)
		error = (sr->sr_read_error & ~SR_READ_DONE);

	if (error != 0) {
		mblk_t *next_mp;

		mp = sr->sr_mp_head;
		while (mp != NULL) {
			next_mp = mp->b_next;
			mp->b_next = NULL;
			freeb(mp);
			mp = next_mp;
		}
	}
	mutex_exit(&sr->sr_lock);
	kmem_free(sr, sizeof (snf_req_t));
	return (error);
}

typedef struct {
	frtn_t		snfi_frtn;
	caddr_t		snfi_base;
	uint_t		snfi_mapoff;
	size_t		snfi_len;
	vnode_t		*snfi_vp;
} snf_smap_desbinfo;

/*
 * The callback function when the last ref of the mblk is dropped,
 * normally occurs when TCP receives the ack. But it can be the driver
 * too due to lazy reclaim.
 */
void
snf_smap_desbfree(snf_smap_desbinfo *snfi)
{
	if (! IS_KPM_ADDR(snfi->snfi_base)) {
		/*
		 * We don't need to call segmap_fault(F_SOFTUNLOCK) for
		 * segmap_kpm as long as the latter never falls back to
		 * "use_segmap_range". (See segmap_getmapflt().)
		 *
		 * Using S_OTHER saves an redundant hat_setref() in
		 * segmap_unlock()
		 */
		(void) segmap_fault(kas.a_hat, segkmap,
		    (caddr_t)(uintptr_t)(((uintptr_t)snfi->snfi_base +
		    snfi->snfi_mapoff) & PAGEMASK), snfi->snfi_len,
		    F_SOFTUNLOCK, S_OTHER);
	}
	(void) segmap_release(segkmap, snfi->snfi_base, SM_DONTNEED);
	VN_RELE(snfi->snfi_vp);
	kmem_free(snfi, sizeof (*snfi));
}

/*
 * Use segmap instead of bcopy to send down a desballoca'ed, mblk.  The mblk
 * contains a segmap slot of no more than MAXBSIZE.
 *
 * At the end of the whole sendfile() operation, we wait till the data from
 * the last mblk is ack'ed by the transport before returning so that the
 * caller of sendfile() can safely modify the file content.
 */
int
snf_segmap(file_t *fp, vnode_t *fvp, u_offset_t fileoff, u_offset_t size,
    ssize_t *count, boolean_t nowait)
{
	caddr_t base;
	int mapoff;
	vnode_t *vp;
	mblk_t *mp;
	int iosize;
	int error;
	short fflag;
	int ksize;
	snf_smap_desbinfo *snfi;
	struct vattr va;
	boolean_t dowait = B_FALSE;

	vp = fp->f_vnode;
	fflag = fp->f_flag;
	ksize = 0;
	for (;;) {
		if (ISSIG(curthread, JUSTLOOKING)) {
			error = EINTR;
			break;
		}

		mapoff = fileoff & MAXBOFFSET;
		iosize = MAXBSIZE - mapoff;
		if (iosize > size)
			iosize = size;
		/*
		 * we don't forcefault because we'll call
		 * segmap_fault(F_SOFTLOCK) next.
		 *
		 * S_READ will get the ref bit set (by either
		 * segmap_getmapflt() or segmap_fault()) and page
		 * shared locked.
		 */
		base = segmap_getmapflt(segkmap, fvp, fileoff, iosize,
		    segmap_kpm ? SM_FAULT : 0, S_READ);

		snfi = kmem_alloc(sizeof (*snfi), KM_SLEEP);
		snfi->snfi_len = (size_t)roundup(mapoff+iosize,
		    PAGESIZE)- (mapoff & PAGEMASK);
		/*
		 * We must call segmap_fault() even for segmap_kpm
		 * because that's how error gets returned.
		 * (segmap_getmapflt() never fails but segmap_fault()
		 * does.)
		 */
		if (segmap_fault(kas.a_hat, segkmap,
		    (caddr_t)(uintptr_t)(((uintptr_t)base + mapoff) & PAGEMASK),
		    snfi->snfi_len, F_SOFTLOCK, S_READ) != 0) {
			(void) segmap_release(segkmap, base, 0);
			kmem_free(snfi, sizeof (*snfi));
			error = EIO;
			goto out;
		}
		snfi->snfi_frtn.free_func = snf_smap_desbfree;
		snfi->snfi_frtn.free_arg = (caddr_t)snfi;
		snfi->snfi_base = base;
		snfi->snfi_mapoff = mapoff;
		mp = esballoca((uchar_t *)base + mapoff, iosize, BPRI_HI,
		    &snfi->snfi_frtn);

		if (mp == NULL) {
			(void) segmap_fault(kas.a_hat, segkmap,
			    (caddr_t)(uintptr_t)(((uintptr_t)base + mapoff)
			    & PAGEMASK), snfi->snfi_len, F_SOFTUNLOCK, S_OTHER);
			(void) segmap_release(segkmap, base, 0);
			kmem_free(snfi, sizeof (*snfi));
			freemsg(mp);
			error = EAGAIN;
			goto out;
		}
		VN_HOLD(fvp);
		snfi->snfi_vp = fvp;
		mp->b_wptr += iosize;

		/* Mark this dblk with the zero-copy flag */
		mp->b_datap->db_struioflag |= STRUIO_ZC;
		fileoff += iosize;
		size -= iosize;

		if (size == 0 && !nowait) {
			ASSERT(!dowait);
			dowait = B_TRUE;
			mp->b_datap->db_struioflag |= STRUIO_ZCNOTIFY;
		}
		VOP_RWUNLOCK(fvp, V_WRITELOCK_FALSE, NULL);
		if ((error = kstrwritemp(vp, mp, fflag)) != 0) {
			*count = ksize;
			freemsg(mp);
			return (error);
		}
		ksize += iosize;
		if (size == 0)
			goto done;

		(void) VOP_RWLOCK(fvp, V_WRITELOCK_FALSE, NULL);
		va.va_mask = AT_SIZE;
		error = VOP_GETATTR(fvp, &va, 0, kcred, NULL);
		if (error)
			break;
		/* Read as much as possible. */
		if (fileoff >= va.va_size)
			break;
		if (size + fileoff > va.va_size)
			size = va.va_size - fileoff;
	}
out:
	VOP_RWUNLOCK(fvp, V_WRITELOCK_FALSE, NULL);
done:
	*count = ksize;
	if (dowait) {
		stdata_t *stp;

		stp = vp->v_stream;
		mutex_enter(&stp->sd_lock);
		while (!(stp->sd_flag & STZCNOTIFY)) {
			if (cv_wait_sig(&stp->sd_zcopy_wait,
			    &stp->sd_lock) == 0) {
				error = EINTR;
				break;
			}
		}
		stp->sd_flag &= ~STZCNOTIFY;
		mutex_exit(&stp->sd_lock);
	}
	return (error);
}

int
snf_cache(file_t *fp, vnode_t *fvp, u_offset_t fileoff, u_offset_t size,
    uint_t maxpsz, ssize_t *count)
{
	struct vnode *vp;
	mblk_t *mp;
	int iosize;
	int extra = 0;
	int error;
	short fflag;
	int ksize;
	int ioflag;
	struct uio auio;
	struct iovec aiov;
	struct vattr va;
	int maxblk = 0;
	int wroff = 0;
	struct sonode *so;

	vp = fp->f_vnode;
	if (vp->v_type == VSOCK) {
		stdata_t *stp;

		/*
		 * Get the extra space to insert a header and a trailer.
		 */
		so = VTOSO(vp);
		stp = vp->v_stream;
		wroff = (int)(stp->sd_wroff);
		maxblk = (int)(stp->sd_maxblk);
		extra = wroff + (int)(stp->sd_tail);
	}

	fflag = fp->f_flag;
	ksize = 0;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;
	ioflag = auio.uio_fmode & (FSYNC|FDSYNC|FRSYNC);
	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	for (;;) {
		if (ISSIG(curthread, JUSTLOOKING)) {
			error = EINTR;
			break;
		}
		iosize = (int)MIN(maxpsz, size);

		/*
		 * For sockets acting as an SSL proxy, we
		 * need to adjust the size to the maximum
		 * SSL record size set in the stream head.
		 */
		if (vp->v_type == VSOCK && so->so_kssl_ctx != NULL)
			iosize = (int)MIN(iosize, maxblk);

		if ((mp = allocb(iosize + extra, BPRI_MED)) == NULL) {
			error = EAGAIN;
			break;
		}

		mp->b_rptr += wroff;

		aiov.iov_base = (caddr_t)mp->b_rptr;
		aiov.iov_len = iosize;
		auio.uio_loffset = fileoff;
		auio.uio_resid = iosize;

		error = VOP_READ(fvp, &auio, ioflag, fp->f_cred, NULL);
		iosize -= auio.uio_resid;

		if (error == EINTR && iosize != 0)
			error = 0;

		if (error != 0 || iosize == 0) {
			freeb(mp);
			break;
		}
		mp->b_wptr = mp->b_rptr + iosize;

		VOP_RWUNLOCK(fvp, V_WRITELOCK_FALSE, NULL);
		if ((error = kstrwritemp(vp, mp, fflag)) != 0) {
			*count = ksize;
			freeb(mp);
			return (error);
		}
		ksize += iosize;
		size -= iosize;
		if (size == 0)
			goto done;

		fileoff += iosize;
		(void) VOP_RWLOCK(fvp, V_WRITELOCK_FALSE, NULL);
		va.va_mask = AT_SIZE;
		error = VOP_GETATTR(fvp, &va, 0, kcred, NULL);
		if (error)
			break;
		/* Read as much as possible. */
		if (fileoff >= va.va_size)
			size = 0;
		else if (size + fileoff > va.va_size)
			size = va.va_size - fileoff;
	}
	VOP_RWUNLOCK(fvp, V_WRITELOCK_FALSE, NULL);
done:
	*count = ksize;
	return (error);
}

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
/*
 * Largefile support for 32 bit applications only.
 */
int
sosendfile64(file_t *fp, file_t *rfp, const struct ksendfilevec64 *sfv,
    ssize32_t *count32)
{
	ssize32_t sfv_len;
	u_offset_t sfv_off, va_size;
	struct vnode *vp, *fvp, *realvp;
	struct vattr va;
	stdata_t *stp;
	ssize_t count = 0;
	int error = 0;
	boolean_t dozcopy = B_FALSE;
	uint_t maxpsz;

	sfv_len = (ssize32_t)sfv->sfv_len;
	if (sfv_len < 0) {
		error = EINVAL;
		goto out;
	}

	if (sfv_len == 0) goto out;

	sfv_off = (u_offset_t)sfv->sfv_off;

	/* Same checks as in pread */
	if (sfv_off > MAXOFFSET_T) {
		error = EINVAL;
		goto out;
	}
	if (sfv_off + sfv_len > MAXOFFSET_T)
		sfv_len = (ssize32_t)(MAXOFFSET_T - sfv_off);

	/*
	 * There are no more checks on sfv_len. So, we cast it to
	 * u_offset_t and share the snf_direct_io/snf_cache code between
	 * 32 bit and 64 bit.
	 *
	 * TODO: should do nbl_need_check() like read()?
	 */
	if (sfv_len > sendfile_max_size) {
		sf_stats.ss_file_not_cached++;
		error = snf_direct_io(fp, rfp, sfv_off, (u_offset_t)sfv_len,
		    &count);
		goto out;
	}
	fvp = rfp->f_vnode;
	if (VOP_REALVP(fvp, &realvp, NULL) == 0)
		fvp = realvp;
	/*
	 * Grab the lock as a reader to prevent the file size
	 * from changing underneath.
	 */
	(void) VOP_RWLOCK(fvp, V_WRITELOCK_FALSE, NULL);
	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(fvp, &va, 0, kcred, NULL);
	va_size = va.va_size;
	if ((error != 0) || (va_size == 0) || (sfv_off >= va_size)) {
		VOP_RWUNLOCK(fvp, V_WRITELOCK_FALSE, NULL);
		goto out;
	}
	/* Read as much as possible. */
	if (sfv_off + sfv_len > va_size)
		sfv_len = va_size - sfv_off;

	vp = fp->f_vnode;
	stp = vp->v_stream;
	/*
	 * When the NOWAIT flag is not set, we enable zero-copy only if the
	 * transfer size is large enough. This prevents performance loss
	 * when the caller sends the file piece by piece.
	 */
	if (sfv_len >= MAXBSIZE && (sfv_len >= (va_size >> 1) ||
	    (sfv->sfv_flag & SFV_NOWAIT) || sfv_len >= 0x1000000) &&
	    !vn_has_flocks(fvp) && !(fvp->v_flag & VNOMAP)) {
		if ((stp->sd_copyflag & (STZCVMSAFE|STZCVMUNSAFE)) == 0) {
			int on = 1;

			if (SOP_SETSOCKOPT(VTOSO(vp), SOL_SOCKET,
			    SO_SND_COPYAVOID, &on, sizeof (on)) == 0)
				dozcopy = B_TRUE;
		} else {
			dozcopy = (stp->sd_copyflag & STZCVMSAFE);
		}
	}
	if (dozcopy) {
		sf_stats.ss_file_segmap++;
		error = snf_segmap(fp, fvp, sfv_off, (u_offset_t)sfv_len,
		    &count, ((sfv->sfv_flag & SFV_NOWAIT) != 0));
	} else {
		if (stp->sd_qn_maxpsz == INFPSZ)
			maxpsz = maxphys;
		else
			maxpsz = roundup(stp->sd_qn_maxpsz, MAXBSIZE);
		sf_stats.ss_file_cached++;
		error = snf_cache(fp, fvp, sfv_off, (u_offset_t)sfv_len,
		    maxpsz, &count);
	}
out:
	releasef(sfv->sfv_fd);
	*count32 = (ssize32_t)count;
	return (error);
}
#endif

#ifdef _SYSCALL32_IMPL
/*
 * recv32(), recvfrom32(), send32(), sendto32(): intentionally return a
 * ssize_t rather than ssize32_t; see the comments above read32 for details.
 */

ssize_t
recv32(int32_t sock, caddr32_t buffer, size32_t len, int32_t flags)
{
	return (recv(sock, (void *)(uintptr_t)buffer, (ssize32_t)len, flags));
}

ssize_t
recvfrom32(int32_t sock, caddr32_t buffer, size32_t len, int32_t flags,
	caddr32_t name, caddr32_t namelenp)
{
	return (recvfrom(sock, (void *)(uintptr_t)buffer, (ssize32_t)len, flags,
	    (void *)(uintptr_t)name, (void *)(uintptr_t)namelenp));
}

ssize_t
send32(int32_t sock, caddr32_t buffer, size32_t len, int32_t flags)
{
	return (send(sock, (void *)(uintptr_t)buffer, (ssize32_t)len, flags));
}

ssize_t
sendto32(int32_t sock, caddr32_t buffer, size32_t len, int32_t flags,
	caddr32_t name, socklen_t namelen)
{
	return (sendto(sock, (void *)(uintptr_t)buffer, (ssize32_t)len, flags,
	    (void *)(uintptr_t)name, namelen));
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Function wrappers (mostly around the sonode switch) for
 * backward compatibility.
 */

int
soaccept(struct sonode *so, int fflag, struct sonode **nsop)
{
	return (SOP_ACCEPT(so, fflag, nsop));
}

int
sobind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int backlog, int flags)
{
	int	error;

	error = SOP_BIND(so, name, namelen, flags);
	if (error == 0 && backlog != 0)
		return (SOP_LISTEN(so, backlog));

	return (error);
}

int
solisten(struct sonode *so, int backlog)
{
	return (SOP_LISTEN(so, backlog));
}

int
soconnect(struct sonode *so, const struct sockaddr *name, socklen_t namelen,
    int fflag, int flags)
{
	return (SOP_CONNECT(so, name, namelen, fflag, flags));
}

int
sorecvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	return (SOP_RECVMSG(so, msg, uiop));
}

int
sosendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	return (SOP_SENDMSG(so, msg, uiop));
}

int
sogetpeername(struct sonode *so)
{
	return (SOP_GETPEERNAME(so));
}

int
sogetsockname(struct sonode *so)
{
	return (SOP_GETSOCKNAME(so));
}

int
soshutdown(struct sonode *so, int how)
{
	return (SOP_SHUTDOWN(so, how));
}

int
sogetsockopt(struct sonode *so, int level, int option_name, void *optval,
    socklen_t *optlenp, int flags)
{
	return (SOP_GETSOCKOPT(so, level, option_name, optval, optlenp,
	    flags));
}

int
sosetsockopt(struct sonode *so, int level, int option_name, const void *optval,
    t_uscalar_t optlen)
{
	return (SOP_SETSOCKOPT(so, level, option_name, optval, optlen));
}

/*
 * Because this is backward compatibility interface it only needs to be
 * able to handle the creation of TPI sockfs sockets.
 */
struct sonode *
socreate(vnode_t *accessvp, int domain, int type, int protocol, int version,
    struct sonode *tso, int *errorp)
{
	return (sotpi_create(accessvp, domain, type, protocol, version, tso,
	    errorp));
}
