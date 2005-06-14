/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/pathname.h>
#include <sys/ddi.h>
#include <sys/kmem_impl.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sendfile.h>

#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>
#include <inet/nca/ncadoorhdr.h>
#include <inet/nca/ncaio.h>
#include <inet/nca/nca_debug.h>

#include <c2/audit.h>

int		nca_sendfilev(file_t *, struct sendfilevec *, int, ssize_t *);

/* NCAfs vnode operations */
int	socknca_read(struct vnode *, struct uio *, int, struct cred *,
	    struct caller_context *);
int	socknca_write(struct vnode *, struct uio *, int, struct cred *,
	    struct caller_context *);
int	nca_poll(struct vnode *, short, int, short *,
	    struct pollhead **);
int	socknca_close(struct vnode *, int, int, offset_t, struct cred *);
void	socknca_inactive(struct vnode *, struct cred *);

/* NCAfs sonode operations */
static int	sonca_bind(struct sonode *, struct sockaddr *, socklen_t, int);
static int	sonca_listen(struct sonode *, int);
static int	sonca_connect(struct sonode *, const struct sockaddr *,
		    socklen_t, int, int);
static int	sonca_accept(struct sonode *, int, struct sonode **);
static int	sonca_sendmsg(struct sonode *, struct nmsghdr *,
		    struct uio *);
static int	sonca_shutdown(struct sonode *, int);
static int	sonca_getsockname(struct sonode *so);

static struct kmem_cache *ncafs_cache;

#ifdef DEBUG
int nca_sendfilev_debug = 0;
#endif

typedef struct ncafs_priv {
	mblk_t		*iop_mp;
	mblk_t		*req_mp;
	uchar_t		*req_ptr;
	int		req_size;
	size_t		iop_dataleft;
	int		iop_more;
} ncafs_priv_t;

typedef struct so_ncafs {
	struct sonode	so;
	ncafs_priv_t	so_priv;
} so_ncafs_t;

static sonodeops_t ncafs_sonodeops = {
	sonca_accept,		/* sop_accept	*/
	sonca_bind,		/* sop_bind	*/
	sonca_listen,		/* sop_listen	*/
	sonca_connect,		/* sop_connect	*/
	sotpi_recvmsg,		/* sop_recvmsg	*/
	sonca_sendmsg,		/* sop_sendmsg	*/
	sotpi_getpeername,	/* sop_getpeername */
	sonca_getsockname,	/* sop_getsockname */
	sonca_shutdown,		/* sop_shutdown */
	sotpi_getsockopt,	/* sop_getsockopt */
	sotpi_setsockopt	/* sop_setsockopt */
};

/*ARGSUSED*/
static int
nca_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct sonode		*so = buf;
	struct vnode		*vp;

	so->so_oobmsg		= NULL;
	so->so_ack_mp		= NULL;
	so->so_conn_ind_head	= NULL;
	so->so_conn_ind_tail	= NULL;
	so->so_discon_ind_mp	= NULL;
	so->so_ux_bound_vp	= NULL;
	so->so_unbind_mp	= NULL;
	so->so_accessvp		= NULL;
	so->so_laddr_sa		= NULL;
	so->so_faddr_sa		= NULL;
	so->so_ops 		= &ncafs_sonodeops;

	vp = vn_alloc(KM_SLEEP);
	so->so_vnode = vp;

	(void) vn_setops(vp, socknca_vnodeops);
	vp->v_data = (caddr_t)so;

	mutex_init(&so->so_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&so->so_plumb_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&so->so_state_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_ack_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_connind_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_want_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED1*/
static void
nca_destructor(void *buf, void *cdrarg)
{
	struct sonode	*so = buf;
	struct vnode	*vp = SOTOV(so);

	ASSERT(so->so_oobmsg == NULL);
	ASSERT(so->so_ack_mp == NULL);
	ASSERT(so->so_conn_ind_head == NULL);
	ASSERT(so->so_conn_ind_tail == NULL);
	ASSERT(so->so_discon_ind_mp == NULL);
	ASSERT(so->so_ux_bound_vp == NULL);
	ASSERT(so->so_unbind_mp == NULL);
	ASSERT(so->so_ops == &ncafs_sonodeops);

	ASSERT(vn_matchops(vp, socknca_vnodeops));
	ASSERT(vp->v_data == (caddr_t)so);

	vn_free(vp);

	mutex_destroy(&so->so_lock);
	mutex_destroy(&so->so_plumb_lock);
	cv_destroy(&so->so_state_cv);
	cv_destroy(&so->so_ack_cv);
	cv_destroy(&so->so_connind_cv);
	cv_destroy(&so->so_want_cv);
}

void
sonca_init(void)
{
	ncafs_cache = kmem_cache_create("ncafs_cache", sizeof (so_ncafs_t),
	    0, nca_constructor, nca_destructor, NULL, NULL, NULL, 0);
}

/* ARGSUSED */
void
socknca_inactive(struct vnode *vp, struct cred *cr)
{
	struct sonode	*so = VTOSO(vp);
	mblk_t		*mp;

	ASSERT(so->so_family == AF_NCA);

	mutex_enter(&vp->v_lock);
	/*
	 * If no one has reclaimed the vnode, remove from the
	 * cache now.
	 */
	if (vp->v_count < 1)
		cmn_err(CE_PANIC, "socknca_inactive: Bad v_count");

	/*
	 * Drop the temporary hold by vn_rele now
	 */
	if (--vp->v_count != 0) {
		mutex_exit(&vp->v_lock);
		return;
	}

	mutex_exit(&vp->v_lock);

	/* We are the sole owner of so now */

	ASSERT(!vn_has_cached_data(vp));
	ASSERT(so->so_count == 0);
	ASSERT(so->so_accessvp);
	ASSERT(so->so_discon_ind_mp == NULL);
	vn_invalid(vp);

	vp = so->so_accessvp;
	VN_RELE(vp);

	mutex_enter(&so->so_lock);
	so->so_accessvp = NULL;
	mutex_exit(&so->so_lock);

	if ((mp = so->so_conn_ind_head) != NULL) {
		mblk_t *mp1;

		while (mp != NULL) {
			mp1 = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			mp = mp1;
		}
		so->so_conn_ind_head = so->so_conn_ind_tail = NULL;
		so->so_state &= ~SS_HASCONNIND;
	}

	if (so->so_laddr_sa != NULL) {
		ASSERT((caddr_t)so->so_faddr_sa ==
		    (caddr_t)so->so_laddr_sa + so->so_addr_size);
		ASSERT(so->so_faddr_maxlen == so->so_laddr_maxlen);
		so->so_state &= ~(SS_LADDR_VALID | SS_FADDR_VALID);
		kmem_free(so->so_laddr_sa, so->so_laddr_maxlen * 2);
		so->so_laddr_sa = NULL;
		so->so_laddr_len = so->so_laddr_maxlen = 0;
		so->so_faddr_sa = NULL;
		so->so_faddr_len = so->so_faddr_maxlen = 0;
	}

	if (so->so_peercred != NULL)
		crfree(so->so_peercred);

	kmem_cache_free(ncafs_cache, (so_ncafs_t *)so);
}

static int
nca_check(vnode_t *vp)
{
	struct strioctl strioc;
	int error;

	/* Check if NCA is enabled */
	strioc.ic_cmd = NCA_READY;
	strioc.ic_timout = 0;
	strioc.ic_len = 0;
	strioc.ic_dp = (char *)NULL;
	error = strdoioctl(vp->v_stream, &strioc, FNATIVE, K_TO_K, CRED(),
	    &error);
	return (error);
}

/*
 * Open stream and send down ioctl to make sure nca is supported.
 * Ensure that vnode is unchanged if check succeeds.
 */
static int
nca_open_and_check(vnode_t *vp)
{
	struct sonode *so;
	major_t maj;
	dev_t new_dev;
	int error;

	new_dev = vp->v_rdev;
	maj = getmajor(new_dev);
	ASSERT(maj < devcnt);
	ASSERT(STREAMSTAB(maj));

	if ((error = stropen(vp, &new_dev, FREAD|FWRITE, CRED())) != 0) {
		VN_RELE(vp);
		return (error);
	}

	so = VTOSO(vp);
	so->so_count++;

	/* release hold in clone_open() */
	if (so->so_flag & SOCLONE) {
		ASSERT(new_dev != vp->v_rdev);	/* dev_t must be cloned */
		ddi_rele_driver(getmajor(new_dev));
	}

	if ((error = nca_check(vp)) != 0) {
		(void) strclose(vp, FREAD|FWRITE, CRED());
		vp->v_stream = NULL;
		return (EPROTONOSUPPORT);
	}

	if (vp->v_stream != NULL) {
		strclean(vp);
		(void) strclose(vp, FREAD|FWRITE, CRED());
		vp->v_stream = NULL;
		so->so_count--;
	}
	return (0);
}

/* ARGSUSED */
struct sonode *
sonca_create(vnode_t *accessvp, int domain, int type, int protocol,
    int version, struct sonode *tso, int *errorp)
{
	struct sonode	*so;
	vnode_t		*vp;
	time_t 		now;
	dev_t 		dev;
	int		error;
	so_ncafs_t	*so_ncafs;
	ncafs_priv_t 	*so_priv;

	ASSERT(accessvp);
	ASSERT(domain == AF_NCA);

	so_ncafs = kmem_cache_alloc(ncafs_cache, KM_SLEEP);
	so = &so_ncafs->so;
	/*
	 * We rely on the "struct sonode" being the first element in the
	 * "so_ncfas_t" in sonca_inactive().
	 */
	so_priv = &so_ncafs->so_priv;
	so->so_priv = (void *)so_priv;
	so->so_cache = ncafs_cache;
	so->so_obj = so_ncafs;

	vp = SOTOV(so);
	now = gethrestime_sec();

	so->so_flag		= 0;
	ASSERT(so->so_accessvp == NULL);
	so->so_accessvp	= accessvp;
	so->so_dev = dev = accessvp->v_rdev;

	/*
	 * record in so_flag that it is a clone.
	 */
	if (getmajor(dev) == clone_major)
		so->so_flag |= SOCLONE;

	so->so_state	= 0;
	so->so_mode	= 0;

	so->so_fsid	= sockdev;
	so->so_atime	= now;
	so->so_mtime	= now;
	so->so_ctime	= now;		/* Never modified */
	so->so_count	= 0;

	so->so_family	= (short)domain;
	so->so_type	= (short)type;
	so->so_protocol	= (short)protocol;
	so->so_pushcnt	= 0;

	so->so_options	= 0;
	so->so_linger.l_onoff	= 0;
	so->so_linger.l_linger = 0;
	so->so_sndbuf	= 0;
	so->so_rcvbuf	= 0;
	so->so_error	= 0;
	so->so_delayed_error = 0;
	so->so_peercred = NULL;

	ASSERT(so->so_oobmsg == NULL);
	so->so_oobcnt	= 0;
	so->so_oobsigcnt = 0;
	so->so_pgrp	= 0;
	so->so_provinfo = NULL;
	so_priv->req_mp	= NULL;
	so_priv->req_size 	= 0;
	so_priv->iop_mp	= NULL;

	ASSERT(so->so_laddr_sa == NULL && so->so_faddr_sa == NULL);
	so->so_eaddr_mp = NULL;
	so->so_addr_size = (socklen_t)sizeof (struct sockaddr_in);

	so->so_laddr_maxlen = so->so_faddr_maxlen =
		    P2ROUNDUP(so->so_addr_size, KMEM_ALIGN);
	so->so_laddr_sa = kmem_zalloc(so->so_laddr_maxlen * 2, KM_SLEEP);
	so->so_faddr_sa = (struct sockaddr *)((caddr_t)so->so_laddr_sa +
		    so->so_laddr_maxlen);
	so->so_laddr_len = so->so_faddr_len = 0;

	ASSERT(!(so->so_state & (SS_FADDR_VALID | SS_LADDR_VALID)));
	ASSERT(so->so_ack_mp == NULL);
	ASSERT(so->so_conn_ind_head == NULL);
	ASSERT(so->so_conn_ind_tail == NULL);
	ASSERT(so->so_ux_bound_vp == NULL);
	ASSERT(so->so_unbind_mp == NULL);

	vn_reinit(vp);
	(void) vn_setops(vp, socknca_vnodeops);
	vp->v_vfsp	= rootvfs;
	vp->v_type	= VSOCK;
	vp->v_rdev	= so->so_dev;
	vn_exists(vp);

	so->so_version = SOV_SOCKSTREAM;

	/*
	 * We need to check if NCA is plumbed before letting this
	 * call succeed. If we are being called from nca_accept,
	 * don't bother.
	 */
	if ((tso == NULL) && ((error = nca_open_and_check(vp)) != 0)) {
		*errorp = error;
		kmem_free(so->so_laddr_sa, so->so_laddr_maxlen * 2);
		kmem_cache_free(ncafs_cache, so_ncafs);
		return (NULL);
	}

	/* Set up the Stream now */
	if (error = socktpi_open(&vp, FREAD|FWRITE, CRED())) {
		VN_RELE(vp);
		*errorp = error;
		kmem_free(so->so_laddr_sa, so->so_laddr_maxlen * 2);
		kmem_cache_free(ncafs_cache, so_ncafs);
		return (NULL);
	}

	so_installhooks(so);

	return (so);
}

int
sonca_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int flags)
{
	vnode_t		*vp;
	struct strioctl	strioc;
	int		error;

	if (name == NULL)
		return (EOPNOTSUPP);

	if (namelen != sizeof (struct sockaddr_in))
		return (EINVAL);

	if ((name->sa_family != AF_INET) && (name->sa_family != AF_NCA))
		return (EAFNOSUPPORT);

	ASSERT(so->so_family == AF_NCA);

	if (!(flags & _SOBIND_LOCK_HELD)) {
		mutex_enter(&so->so_lock);
		so_lock_single(so);	/* Set SOLOCKED */
	} else {
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}

	vp = SOTOV(so);
	strioc.ic_cmd = NCA_BIND;
	strioc.ic_timout = 0;
	strioc.ic_len = namelen;
	strioc.ic_dp = (char *)name;
	error = strdoioctl(vp->v_stream, &strioc, FNATIVE, K_TO_K, CRED(),
	    &error);
	if (error == 0) {
			so->so_laddr_len = (socklen_t)namelen;
			bcopy(name, so->so_laddr_sa, namelen);
			so->so_state |= SS_ISBOUND|SS_LADDR_VALID;
	}

	if (!(flags & _SOBIND_LOCK_HELD)) {
		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);
	} else {
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}

	return (error);
}

int
sonca_listen(struct sonode *so, int backlog)
{
	if (backlog <= 0)
		return (EOPNOTSUPP);

	if ((so->so_state & (SS_ISCONNECTED|SS_ISBOUND)) != SS_ISBOUND)
		return (EINVAL);

	if (!(so->so_state & SS_ACCEPTCONN)) {
		struct strioctl	strioc;
		int		error;

		/* Let NCA know that web server is ready */
		strioc.ic_cmd = NCA_LISTEN;
		strioc.ic_timout = 0;
		strioc.ic_len = so->so_laddr_len;
		strioc.ic_dp = (char *)so->so_laddr_sa;
		error = strdoioctl(SOTOV(so)->v_stream, &strioc, FNATIVE,
		    K_TO_K, CRED(), &error);
		if (error != 0)
			return (error);
	}

	mutex_enter(&so->so_lock);
	so->so_state |= SS_ACCEPTCONN;
	so->so_backlog = backlog;
	mutex_exit(&so->so_lock);

	return (0);
}

/*
 * Issue a downcall to NCA by sending a "downcallinfo_t" structure in an M_CTL
 * mblk downwards. We cannot use M_DATA mblks because they could carry
 * arbitrary data e.g. if a process opens "/dev/nca" directly and tries to
 * write to it. The M_CTL mblk is marked with a magic number to allow some
 * basic sanity tests inside NCA.
 */
static int
nca_downcall(struct sonode *so, nca_io2_t *iop, uio_t *uiop)
{
	mblk_t		*mp;
	downcallinfo_t	*dcip;
	int		error;

	if ((mp = allocb(sizeof (downcallinfo_t), BPRI_MED)) == NULL)
		return (ENOMEM);

	DB_TYPE(mp) = M_CTL;
	mp->b_wptr += sizeof (downcallinfo_t);

	dcip = (downcallinfo_t *)mp->b_rptr;
	dcip->dci_magic = DOWNCALLINFO_MAGIC;
	dcip->dci_iop = iop;
	dcip->dci_uiop = uiop;

	/*
	 * We must use kstrwritemp() here because we want to send down
	 * a M_CTL mblk which strwrite() doesn't support. kstrwritemp()
	 * has more lax checks which is allright in this case because
	 * NCA sockets always grant write permissions, we don't want
	 * the mblk_t to be split anyway and there will never be a
	 * M_HANGUP mblk on a NCA socket's stream.
	 */
	error = kstrwritemp(SOTOV(so), mp,
	    ((so->so_state & SS_NDELAY) ? FNDELAY : 0) |
	    ((so->so_state & SS_NONBLOCK) ? FNONBLOCK : 0));
	if (error != 0)
		freeb(mp);

	return (error);
}

/* ARGSUSED */
int
sonca_connect(struct sonode *so, const struct sockaddr *name, socklen_t namelen,
    int fflag, int flags)
{
	return (EINVAL);
}

int
nca_emptywrite(struct sonode *so, int more)
{
	ncafs_priv_t  	*so_priv = (ncafs_priv_t *)so->so_priv;
	nca_io2_t	*iop;

	iop = (nca_io2_t *)so_priv->iop_mp->b_rptr;
	iop->data_len = 0;
	iop->more = (uint8_t)more;

	return (nca_downcall(so, iop, NULL));
}

int
sonca_accept(struct sonode *so, int fflag, struct sonode **nsop)
{
	struct T_conn_ind	*conn_ind;
	int			error = 0;
	mblk_t			*mp;
	struct sonode		*nso;
	vnode_t			*nvp;
	void			*src;
	t_uscalar_t		srclen;
	void			*opt;
	t_uscalar_t		optlen;
	mblk_t			*iop_mp, *req_mp;
	nca_io2_t		*iop;
	ncafs_priv_t		*nso_priv;
#ifdef NCAFS_DEBUG2
	char 			*nca_request_ptr;
	char			buf[1024];
	int			len;
#endif

#ifdef NCAFS_DEBUG3
	hrtime_t		start, end, delta;
	static hrtime_t		total = 0;
#endif

	/*
	 * Check that the socket is a listener.
	 */
	if (!(so->so_state & SS_ACCEPTCONN)) {
		error = EINVAL;
		eprintsoline(so, error);
		return (error);
	}

	error = sowaitconnind(so, fflag, &mp);

	if (error != 0) {
		eprintsoline(so, error);
		return (error);
	}
	ASSERT(mp);
	conn_ind = (struct T_conn_ind *)mp->b_rptr;

	srclen = conn_ind->SRC_length;
	src = sogetoff(mp, conn_ind->SRC_offset, srclen, 1);
	if (src == NULL) {
		error = EPROTO;
		eprintsoline(so, error);
		goto disconnect_unlocked;
	}
	optlen = conn_ind->OPT_length;
	if (optlen != 0) {
		opt = sogetoff(mp, conn_ind->OPT_offset, optlen,
				__TPI_ALIGN_SIZE);
		if (opt == NULL) {
			error = EPROTO;
			eprintsoline(so, error);
			goto disconnect_unlocked;
		}
	}

	iop_mp = mp->b_cont;
	if (iop_mp == NULL) {
		cmn_err(CE_CONT, "sonca_accept: Got NULL iop_mp");
		freemsg(mp);
		return (EINVAL);
	}
	mp->b_cont = NULL;

	req_mp = iop_mp->b_cont;
	if (req_mp == NULL) {
		cmn_err(CE_CONT, "sonca_accept: Got NULL req_mp");
		freemsg(iop_mp);
		freemsg(mp);
		return (EINVAL);
	}
	iop_mp->b_cont = NULL;

	/*
	 * Create the new socket.
	 */
	VN_HOLD(so->so_accessvp);

#ifdef NCAFS_DEBUG3
	start = gethrtime();
#endif

	nso = sonca_create(so->so_accessvp, so->so_family, so->so_type,
	    so->so_protocol, so->so_version, so, &error);
#ifdef NCAFS_DEBUG3
	end = gethrtime();
	delta = end - start;
	total += delta;
	cmn_err(CE_CONT, "accept time = %lld. Total = %lld\n", delta, total);
#endif

	if (nso == NULL) {
		/*
		 * Accept can not fail with ENOBUFS. sonca_create sleeps
		 * waiting for memory until a signal is caught so return
		 * EINTR.
		 */
		if (error == ENOBUFS)
			error = EINTR;
		VN_RELE(so->so_accessvp);
		eprintsoline(so, error);
		cmn_err(CE_CONT, "sonca_accept: nso == NULL\n");
		goto disconnect_unlocked;
	}
	nvp = SOTOV(nso);
	nso_priv = nso->so_priv;

	nso->so_faddr_len = (socklen_t)srclen;
	ASSERT(so->so_faddr_len <= so->so_faddr_maxlen);
	bcopy(src, nso->so_faddr_sa, srclen);
	nso->so_state |= SS_FADDR_VALID;

	/* Do the automatic bind for the new socket */
	mutex_enter(&nso->so_lock);
	nso->so_state |= SS_ISBOUND|SS_HASDATA|SS_ISCONNECTED;
	nso->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING);

	iop = (nca_io2_t *)iop_mp->b_rptr;

	/*
	 * Copy local address from nca_io2_t.
	 */
	src = (void *)((size_t)iop + (size_t)iop->local);

#ifdef NCAFS_DEBUG2
	cmn_err(CE_CONT, "sonca_accept: iop = %p, src = %p, local = %d, "
		" local_len = %d, laddr_maxlen = %d", iop, src, iop->local,
		iop->local_len, nso->so_laddr_maxlen);
#endif

	nso->so_laddr_len = iop->local_len;
	ASSERT(nso->so_laddr_len <= nso->so_laddr_maxlen);
	bcopy(src, nso->so_laddr_sa, nso->so_laddr_len);
	nso->so_state |= SS_LADDR_VALID;

	ASSERT(iop->first == 1);

#ifdef NCAFS_DEBUG2
	nca_request_ptr = (char *)req_mp->b_rptr;
	len = req_mp->b_wptr - req_mp->b_rptr;
	len = (len > 1024) ? 1024 : len;
	bcopy(nca_request_ptr, buf, len);
	buf[len] = '\0';
	cmn_err(CE_CONT, "sonca_accept (%d): %s\n", len, buf);
#endif

	nso_priv->iop_mp = iop_mp;
	nso_priv->req_mp = req_mp;
	nso_priv->req_size = req_mp->b_wptr - req_mp->b_rptr;
	nso_priv->req_ptr = req_mp->b_rptr;
	nso_priv->iop_dataleft = 0;
	nso_priv->iop_more = 0;

	iop = (nca_io2_t *)nso_priv->iop_mp->b_rptr;
	if (iop->more == 1) {
		error = nca_emptywrite(nso, 1);
		iop->first = 0;
		if (error != 0) {
			mutex_exit(&nso->so_lock);
			goto disconnect_vp_unlocked;
		}
		nso_priv->iop_more = 1;
	}

	/*
	 * Pass out new socket.
	 */
	if (nsop != NULL)
		*nsop = nso;

	mutex_exit(&nso->so_lock);
	freemsg(mp);
	return (0);
disconnect_vp_unlocked:
	(void) VOP_CLOSE(nvp, 0, 1, 0, CRED());
	VN_RELE(nvp);
disconnect_unlocked:
	freemsg(mp);
	return (error);
}

/* ARGSUSED */
int
socknca_read(
	struct vnode	*vp,
	struct uio	*uiop,
	int		ioflag,
	struct cred	*cr,
	struct caller_context *ct)
{
	struct sonode	*so = VTOSO(vp);
	struct nmsghdr	lmsg;
	int		error = 0, len;
	struct iovec	*iov;
	struct iovec	read_iov;
	struct uio 	xuiop;
	ncafs_priv_t	*so_priv = (ncafs_priv_t *)so->so_priv;
	nca_io2_t	io;

	ASSERT(so->so_family == AF_NCA);
	ASSERT(vp->v_type == VSOCK);
	so_update_attrs(so, SOACC);

	mutex_enter(&so->so_lock);
	if (so->so_state & SS_HASDATA) {
		iov = uiop->uio_iov;
		len = so_priv->req_size;
		if (len > iov->iov_len) {
			len = iov->iov_len;
			error = uiomove(so_priv->req_ptr, len, UIO_READ, uiop);
			so_priv->req_ptr += len;
			so_priv->req_size -= len;
		} else {
			error = uiomove(so_priv->req_ptr, len, UIO_READ, uiop);
			so->so_state &= ~SS_HASDATA;
			so->so_state |= so_priv->iop_more ?
			    SS_MOREDATA : SS_DONEREAD;
		}
		mutex_exit(&so->so_lock);
	} else {
		if (so_priv->iop_dataleft > 0) {
			lmsg.msg_namelen = 0;
			lmsg.msg_controllen = 0;
			lmsg.msg_flags = 0;
			if (so_priv->iop_dataleft <= uiop->uio_resid) {
				size_t	saved_resid;

				saved_resid = uiop->uio_resid;
				uiop->uio_resid = so_priv->iop_dataleft;
				mutex_exit(&so->so_lock);
				error = SOP_RECVMSG(so, &lmsg, uiop);
				mutex_enter(&so->so_lock);
				uiop->uio_resid = saved_resid -
				    so_priv->iop_dataleft;
				so_priv->iop_dataleft = 0;
				if (!so_priv->iop_more) {
					so->so_state &= ~SS_MOREDATA;
					so->so_state |= SS_DONEREAD;
				}
				mutex_exit(&so->so_lock);
			} else {
				so_priv->iop_dataleft -= uiop->uio_resid;
				mutex_exit(&so->so_lock);
				error = SOP_RECVMSG(so, &lmsg, uiop);
			}
			return (error);
		}

		if (!so_priv->iop_more) {
			mutex_exit(&so->so_lock);
			return (0);
		}

		/*
		 * NCA will send more data along with nca_io2_t. We need to
		 * do a sorecvmsg with uiop sizeof (nca_io2_t). Based on that
		 * we should set so_priv->iop_more, and then do a sorecvmsg on
		 * user supplied uiop.
		 */
		read_iov.iov_base = (char *)&io;
		read_iov.iov_len = sizeof (nca_io2_t);
		xuiop.uio_iov = &read_iov;
		xuiop.uio_iovcnt = 1;
		xuiop.uio_loffset = 0;
		xuiop.uio_segflg = UIO_SYSSPACE;
		xuiop.uio_fmode = 0;
		xuiop.uio_extflg = UIO_COPY_CACHED;
		xuiop.uio_limit = 0;
		xuiop.uio_resid = read_iov.iov_len;

		lmsg.msg_namelen = 0;
		lmsg.msg_controllen = 0;
		lmsg.msg_flags = 0;
		mutex_exit(&so->so_lock);
		error = SOP_RECVMSG(so, &lmsg, &xuiop);
		if (error != 0)
			return (error);
		if (xuiop.uio_resid != 0) {
			/* Couldn't read entire nca_io2_t. Something is wrong */
			cmn_err(CE_CONT, "socknca_read: couldn't read full "
			    "nca_io2_t. Needed %d, read %d",
			    (int)sizeof (nca_io2_t),
			    (int)(sizeof (nca_io2_t) - xuiop.uio_resid));
			return (EBADMSG);
		}

		mutex_enter(&so->so_lock);
		ASSERT(io.version == NCA_HTTP_VERSION2);
		if (io.more) {
			nca_io2_t *iop;

			so_priv->iop_more = 1;
			error = nca_emptywrite(so, 1);
			iop = (nca_io2_t *)so_priv->iop_mp->b_rptr;
			iop->first = 0;
			if (error != 0) {
				mutex_exit(&so->so_lock);
				return (error);
			}
		} else {
			so_priv->iop_more = 0;
		}

		lmsg.msg_namelen = 0;
		lmsg.msg_controllen = 0;
		lmsg.msg_flags = 0;
		if (io.data_len <= uiop->uio_resid) {
			size_t	saved_resid;

			saved_resid = uiop->uio_resid;
			uiop->uio_resid = io.data_len;
			mutex_exit(&so->so_lock);
			error = SOP_RECVMSG(so, &lmsg, uiop);
			if (error != 0) {
				cmn_err(CE_CONT, "socknca_read: error reading "
				    "data. error = %d", error);
				return (error);
			}
			mutex_enter(&so->so_lock);
			uiop->uio_resid = saved_resid - io.data_len;
			so_priv->iop_dataleft = 0;
			if (so_priv->iop_more == 0) {
				so->so_state &= ~SS_MOREDATA;
				so->so_state |= SS_DONEREAD;
			}
			mutex_exit(&so->so_lock);
		} else {
			so_priv->iop_dataleft = io.data_len - uiop->uio_resid;
			mutex_exit(&so->so_lock);
			error = SOP_RECVMSG(so, &lmsg, uiop);
			if (error != 0) {
				cmn_err(CE_CONT, "socknca_read: error reading "
				    "data. error = %d", error);
				return (error);
			}
		}
	}

	return (error);
}

/* ARGSUSED2 */
int
socknca_write(
	struct vnode		*vp,
	struct uio		*uiop,
	int			ioflag,
	struct cred		*cr,
	struct caller_context	*ct)
{
	struct sonode	*so = VTOSO(vp);
	ncafs_priv_t  	*so_priv = (ncafs_priv_t *)so->so_priv;
	nca_io2_t	*iop;
	int		error;

	ASSERT(so_priv != NULL);

	if (so->so_state & SS_CANTSENDMORE) {
		tsignal(curthread, SIGPIPE);
		return (EPIPE);
	}

	if (so->so_error != 0) {
		mutex_enter(&so->so_lock);
		error = sogeterr(so);
		if (error != 0) {
			mutex_exit(&so->so_lock);
			return (error);
		}
		mutex_exit(&so->so_lock);
	}

	if ((so->so_state & (SS_ISCONNECTED|SS_ISBOUND)) !=
	    (SS_ISCONNECTED|SS_ISBOUND)) {
		return (ENOTCONN);
	}

	iop = (nca_io2_t *)so_priv->iop_mp->b_rptr;
	iop->data_len = uiop->uio_resid;
	iop->trailer_len = 0;
	iop->direct_len = 0;
	iop->direct_type = NCA_IO_DIRECT_NONE;
	iop->more = 1;

	error = nca_downcall(so, iop, uiop);
#ifdef NCAFS_DEBUG
	if (error != 0)
		cmn_err(CE_CONT, "socknca_write: write error %d\n", error);
#endif

	mutex_enter(&so->so_lock);
	iop->first = 0;
	mutex_exit(&so->so_lock);

	return (error);
}

int
socknca_ioctl(struct vnode *vp, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	switch (cmd) {
	case NCA_BIND:
	case NCA_LISTEN:
	case NCA_READY:
		/* Filter out internal ioctl()s used between NCA and NCAfs. */
		return (EINVAL);
	case I_PUSH:
	case I_POP:
		/*
		 * Prohibit popping "sockmod" or pushing a module above
		 * "sockfmod" for NCA sockets because NCAfs and NCA use
		 * a private M_CTL interface for data and no application
		 * using NCA (web servers) needs this feature.
		 */
		return (ENOTSUP);
	}

	return (socktpi_ioctl(vp, cmd, arg, mode, cr, rvalp));
}

static int
sonca_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	/*
	 * NCA doesn't support socket features like OOB data or bypassing
	 * the routing table. Reject anything except simple cases like
	 * "send(fd, msg, len, 0);".
	 */
	if ((msg->msg_control == NULL || msg->msg_controllen == 0) &&
	    !(msg->msg_flags & (MSG_OOB|MSG_DONTROUTE))) {
		return (socknca_write(SOTOV(so), uiop, 0, CRED(), NULL));
	}

	/*
	 * Return EINVAL instead of the more appropriate ENOTSUP because the
	 * later is not allowed as an error code returned by send(3SOCKET).
	 */
	return (EINVAL);
}

int
nca_poll(
	struct vnode	*vp,
	short		events,
	int		anyyet,
	short		*reventsp,
	struct pollhead **phpp)
{
	short origevents = events;
	short inevents;
	struct sonode *so = VTOSO(vp);
	int error;
	int so_state = so->so_state;	/* snapshot */

#ifdef NCAFS_DEBUG
	cmn_err(CE_CONT, "nca_poll: thread (%x) polling %x for events %x, "
	    "anyyet %d, state %x\n", (uint_t)curthread, so, events,
	    anyyet, so->so_state);
#endif
	ASSERT(vp->v_type == VSOCK);
	ASSERT(vp->v_stream != NULL);

	if (!(so_state & SS_ISCONNECTED)) {
		/* Not connected yet - turn off write side events */
		events &= ~(POLLOUT|POLLWRBAND);
	}
	/*
	 * Check for errors without calling strpoll if the caller wants them.
	 * In sockets the errors are represented as input/output events
	 * and there is no need to ask the stream head for this information.
	 */
	if (so->so_error != 0 &&
	    ((POLLIN|POLLRDNORM|POLLOUT) & origevents)) {
		*reventsp = (POLLIN|POLLRDNORM|POLLOUT) & origevents;
		return (0);
	}

	/*
	 * Check if NCA has HTTP request data available or is expecting
	 * more HTTP request data.
	 */
	inevents = 0;
	if (events & (POLLIN|POLLRDNORM|POLLRDBAND|POLLPRI)) {
		events &= ~(POLLIN|POLLRDNORM|POLLRDBAND|POLLPRI);
		if (so_state & (SS_HASDATA|SS_MOREDATA|SS_HASCONNIND)) {
			inevents = (POLLIN|POLLRDNORM) & origevents;
			if (events == 0) {
				*reventsp = inevents;
				return (0);
			}
		}

		if ((so_state & SS_DONEREAD) && (events == 0)) {
			/*
			 * Caller only asked for inputs events and
			 * no more data is coming.
			 */
			*reventsp = inevents;
			return (0);
		}
	}

	/*
	 * Ignore M_PROTO only messages such as the T_EXDATA_IND messages.
	 * These message with only an M_PROTO/M_PCPROTO part and no M_DATA
	 * will not trigger a POLLIN event with POLLRDDATA set.
	 * After shutdown(output) a stream head write error is set.
	 * However, we should not return output events.
	 */
	events |= POLLRDDATA|POLLNOERR;
	error = strpoll(vp->v_stream, events, anyyet,
			reventsp, phpp);
	if (error != 0)
		return (error);

	if (so->so_state & SS_HASCONNIND)
		inevents |= (POLLIN|POLLRDNORM) & origevents;
	*reventsp |= inevents;

	ASSERT(!(*reventsp & POLLERR));

	return (0);
}


int
sonca_shutdown(struct sonode *so, int how)
{
	int		error = 0;
	ncafs_priv_t  	*so_priv = (ncafs_priv_t *)so->so_priv;

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

	if (!(so->so_state & SS_ISCONNECTED)) {
		error = ENOTCONN;
		goto done;
	}

	switch (how) {
	case 0:
		so->so_state |= SS_CANTRCVMORE;
		break;
	case 2:
		so->so_state |= SS_CANTRCVMORE;
		/* FALLTHRU */
	case 1:
		so->so_state |= SS_CANTSENDMORE;
		if (so->so_state & SS_ISCONNECTED) {

			ASSERT(so_priv->iop_mp != NULL);
			ASSERT(so_priv->req_mp != NULL);

			(void) nca_emptywrite(so, 0);

			if (so_priv->req_mp != NULL) {
				freemsg(so_priv->req_mp);
				so_priv->req_mp = NULL;
				so_priv->req_size = 0;
			}
			if (so_priv->iop_mp != NULL) {
				freemsg(so_priv->iop_mp);
				so_priv->iop_mp = NULL;
			}
			so_priv->iop_more = 0;
			so->so_state &= ~SS_ISCONNECTED;
		}
		break;
	default:
		error = EINVAL;
		goto done;
	}

done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/* ARGSUSED */
int
socknca_close(
	struct vnode	*vp,
	int		flag,
	int		count,
	offset_t	offset,
	struct cred	*cr)
{
	struct sonode	*so = VTOSO(vp);
	dev_t		dev;
	int		error = 0;
	ncafs_priv_t	*so_priv = (ncafs_priv_t *)so->so_priv;

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

	if ((so->so_state & SS_ISCONNECTED) && (count <= 1)) {
		ASSERT(so_priv->iop_mp != NULL);
		ASSERT(so_priv->req_mp != NULL);

		(void) nca_emptywrite(so, 0);

		if (so_priv->req_mp != NULL) {
			freemsg(so_priv->req_mp);
			so_priv->req_mp = NULL;
			so_priv->req_size = 0;
		}
		if (so_priv->iop_mp != NULL) {
			freemsg(so_priv->iop_mp);
			so_priv->iop_mp = NULL;
		}
		so->so_state &= ~SS_ISCONNECTED;
	}
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	if (vp->v_stream != NULL)
		strclean(vp);
	if (count > 1)
		return (0);

	dev = so->so_dev;

	ASSERT(vp->v_type == VSOCK);
	ASSERT(STREAMSTAB(getmajor(dev)));

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */
	ASSERT(so->so_count > 0);
	so->so_count--;			/* one fewer open reference */

	/*
	 * Only call the close routine when the last open reference through
	 * any [s, v]node goes away.
	 */
	if (so->so_count == 0 && vp->v_stream != NULL) {
		mutex_exit(&so->so_lock);
		error = strclose(vp, flag, cr);
		vp->v_stream = NULL;
		mutex_enter(&so->so_lock);
	}

	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	/*
	 * Decrement the device driver's reference count for streams
	 * opened via the clone dip.  The driver was held in clone_open().
	 * The absence of clone_close() forces this asymmetry.
	 */
	if (so->so_flag & SOCLONE)
		ddi_rele_driver(getmajor(dev));
	return (error);
}

#define	SEND_MAX_CHUNK	16

int
nca_sendfilev(file_t *fp, struct sendfilevec *sfv, int sfvcnt,
	ssize_t *xferred)
{
	struct sonode		*so;
	struct vnode 		*vp;
	int 			error;
	uio_t			*uiop;
	iovec_t			*iovp;
	nca_io2_t		*iop;
	nca_sendvec_t		*nca_vecp;
	int			sfd = -1;
	int			size;

	ASSERT(sfvcnt <= SEND_MAX_CHUNK);

	vp = fp->f_vnode;
	so = VTOSO(vp);

	if (so->so_type != SOCK_STREAM)
		return (EPROTONOSUPPORT);

	if (so->so_state & SS_CANTSENDMORE) {
		tsignal(curthread, SIGPIPE);
		return (EPIPE);
	}

	if ((so->so_state & (SS_ISCONNECTED|SS_ISBOUND)) !=
	    (SS_ISCONNECTED|SS_ISBOUND)) {
		return (ENOTCONN);
	}

	iop = (nca_io2_t *)((ncafs_priv_t *)so->so_priv)->iop_mp->b_rptr;
	iop->more = 1;
	iop->data_len = 0;
	iop->trailer_len = 0;
	iop->direct_len = 0;

	size = sfvcnt * sizeof (nca_sendvec_t) +	/* nca_vecp */
	    sizeof (uio_t) +				/* uio */
	    sizeof (iovec_t);				/* iov */
	nca_vecp = kmem_alloc(size, KM_SLEEP);

	uiop = (uio_t *)&nca_vecp[sfvcnt];
	iovp = (iovec_t *)&uiop[1];

	/*
	 * There are 2 possibilities -
	 *
	 * i) A request has a single file fd and multiple optional headers
	 * and/or a single trailer. A trailer is defined as the last
	 * SFV_FD_SELF vector if no file fd is present or a single SFV_FD_SELF
	 * after a file fd. Request of this forms are processed as
	 * direct_type = NCA_IO_DIRECT_FILE_FD. nca_ncafs_srv() will
	 * make a single call to nca_httpd_data() to process this
	 * request.
	 *
	 * ii) All other requests containing more than 1 file fd are
	 * processed using direct_type of NCA_IO_SENDVEC. A special
	 * case here is 2 SFV_FD_SELF after a file fd.
	 */
	{
		sendfilevec_t 		*tmpsfv = sfv;
		uint8_t			direct_type =  NCA_IO_SENDVEC;
		nca_sendvec_t		*nsvp;
		int			i;

		for (i = 0, nsvp = nca_vecp, tmpsfv = sfv;
		    i < sfvcnt;
		    i++, nsvp++, tmpsfv++) {
			struct vnode 	*sfv_vp;

			if (tmpsfv->sfv_fd == SFV_FD_SELF) {
				/* Header Chunks */
#ifdef DEBUG
				if (nca_sendfilev_debug) {
					char *ptr;

					ptr = kmem_alloc(tmpsfv->sfv_len + 1,
					    KM_SLEEP);
					if (copyin((char *)tmpsfv->sfv_off,
					    ptr, tmpsfv->sfv_len)) {
						cmn_err(CE_CONT, "sendfilev: "
						    "error header "
						    "debug copyin");
						kmem_free(ptr,
						    tmpsfv->sfv_len + 1);
						goto fault;
					}
					ptr[tmpsfv->sfv_len] = 0;
					cmn_err(CE_CONT, "nca_sendfilev: "
					    "Header (%ld) is: %s",
					    tmpsfv->sfv_len, ptr);
					kmem_free(ptr, tmpsfv->sfv_len + 1);
				}
#endif
				/* There can only be one trailer */
				if (sfd >= 0 && (i != sfvcnt - 1))
					direct_type = NCA_IO_SENDVEC;
				sfv_vp = NULL;
			} else {
				direct_type = (sfd < 0) ?
				    NCA_IO_DIRECT_FILE_FD : NCA_IO_SENDVEC;

				sfd = tmpsfv->sfv_fd;
				NCA_DEBUG4_IF(nca_sendfilev_debug,
				    "nca_sendfilev: "
				    "fd is %d, len = %d, off = %d\n",
				    tmpsfv->sfv_fd,
				    (int)tmpsfv->sfv_len, (int)tmpsfv->sfv_off);

				if ((fp = getf(sfd)) == NULL)
					goto badf;
				if (!(fp->f_flag & FREAD))
					goto acces;
				sfv_vp = fp->f_vnode;
				releasef(sfd);
			}

			*xferred += tmpsfv->sfv_len;
			nsvp->sfv_fd = tmpsfv->sfv_fd;
			nsvp->sfv_flag = tmpsfv->sfv_flag;
			nsvp->sfv_off = tmpsfv->sfv_off;
			nsvp->sfv_len = tmpsfv->sfv_len;
			nsvp->sfv_vp = sfv_vp;
		}
		iop->direct_type = direct_type;
	}

	iovp->iov_base = (char *)nca_vecp;
	iovp->iov_len = sfvcnt * sizeof (nca_sendvec_t);
	iop->direct_len = sfvcnt;
	iop->direct = 0;
	uiop->uio_iovcnt = 1;
	uiop->uio_iov = iovp;
	uiop->uio_loffset = 0;
	uiop->uio_fmode = 0;
	uiop->uio_extflg = UIO_COPY_DEFAULT;
	uiop->uio_resid = 0;
	uiop->uio_segflg = UIO_SYSSPACE;
	uiop->uio_limit = 0;

	if (so->so_error != 0) {
		mutex_enter(&so->so_lock);
		error = sogeterr(so);
		mutex_exit(&so->so_lock);
		if (error != 0)
			goto out;
	}

	error = nca_downcall(so, iop, uiop);

	if (uiop->uio_resid != 0) {
		/* NCA consumes all uio data unless an error occur */
		error = EIO;
	}

	mutex_enter(&so->so_lock);
	iop->first = 0;
	mutex_exit(&so->so_lock);

out:
	kmem_free(nca_vecp, size);
	return (error);

fault:
	error = EFAULT;
	goto out;
badf:
	error = EBADF;
	goto out;
acces:
	releasef(sfd);
	error = EACCES;
	goto out;
}

/* ARGSUSED */
static int
sonca_getsockname(struct sonode *so)
{
	/*
	 * For AF_NCA type socket, the local address has already been updated
	 * in so_laddr_sa as part of accept.
	 */
	return (0);
}
