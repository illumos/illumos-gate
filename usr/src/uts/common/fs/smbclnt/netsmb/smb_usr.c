/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_usr.c,v 1.15 2004/12/13 00:25:18 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/policy.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>

static int smb_cpdatain(struct mbchain *mbp, int len, char *data, int seg);

/*
 * Ioctl function for SMBIOC_FLAGS2
 */
int
smb_usr_get_flags2(smb_dev_t *sdp, intptr_t arg, int flags)
{
	struct smb_vc *vcp = NULL;

	/* This ioctl requires a session. */
	if ((vcp = sdp->sd_vc) == NULL)
		return (ENOTCONN);

	/*
	 * Return the flags2 value.
	 */
	if (ddi_copyout(&vcp->vc_hflags2, (void *)arg,
	    sizeof (u_int16_t), flags))
		return (EFAULT);

	return (0);
}

/*
 * Ioctl function for SMBIOC_GETSSNKEY
 * Size copied out is SMBIOC_HASH_SZ.
 *
 * The RPC library needs this for encrypting things
 * like "set password" requests.  This is called
 * with an active RPC binding, so the connection
 * will already be active (but this checks).
 */
int
smb_usr_get_ssnkey(smb_dev_t *sdp, intptr_t arg, int flags)
{
	struct smb_vc *vcp = NULL;

	/* This ioctl requires an active session. */
	if ((vcp = sdp->sd_vc) == NULL)
		return (ENOTCONN);
	if (vcp->vc_state != SMBIOD_ST_VCACTIVE)
		return (ENOTCONN);

	/*
	 * Return the session key.
	 */
	if (ddi_copyout(vcp->vc_ssn_key, (void *)arg,
	    SMBIOC_HASH_SZ, flags))
		return (EFAULT);

	return (0);
}

/*
 * Ioctl function for SMBIOC_REQUEST
 */
int
smb_usr_simplerq(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	struct smb_share *ssp;
	smbioc_rq_t *ioc = NULL;
	struct smb_rq *rqp = NULL;
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint32_t rsz;
	int err, mbseg;

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	smb_credinit(&scred, cr);
	ioc = kmem_alloc(sizeof (*ioc), KM_SLEEP);
	if (ddi_copyin((void *) arg, ioc, sizeof (*ioc), flags)) {
		err = EFAULT;
		goto out;
	}

	/* See ddi_copyin, ddi_copyout */
	mbseg = (flags & FKIOCTL) ? MB_MSYSTEM : MB_MUSER;

	/*
	 * Lots of SMB commands could be safe, but
	 * these are the only ones used by libsmbfs.
	 */
	switch (ioc->ioc_cmd) {
		/* These are OK */
	case SMB_COM_CLOSE:
	case SMB_COM_FLUSH:
	case SMB_COM_NT_CREATE_ANDX:
	case SMB_COM_OPEN_PRINT_FILE:
	case SMB_COM_CLOSE_PRINT_FILE:
		break;

	default:
		err = EPERM;
		goto out;
	}

	err = smb_rq_alloc(SSTOCP(ssp), ioc->ioc_cmd, &scred, &rqp);
	if (err)
		goto out;

	mbp = &rqp->sr_rq;
	err = mb_put_mem(mbp, ioc->ioc_tbuf, ioc->ioc_tbufsz, mbseg);

	err = smb_rq_simple(rqp);
	if (err == 0) {
		/*
		 * This may have been an open, so save the
		 * generation ID of the share, which we
		 * check before trying read or write.
		 */
		sdp->sd_vcgenid = ssp->ss_vcgenid;

		/*
		 * Have reply data. to copyout.
		 * SMB header already parsed.
		 */
		mdp = &rqp->sr_rp;
		rsz = msgdsize(mdp->md_top) - SMB_HDRLEN;
		if (ioc->ioc_rbufsz < rsz) {
			err = EOVERFLOW;
			goto out;
		}
		ioc->ioc_rbufsz = rsz;
		err = md_get_mem(mdp, ioc->ioc_rbuf, rsz, mbseg);
		if (err)
			goto out;

	}

	ioc->ioc_errclass = rqp->sr_errclass;
	ioc->ioc_serror = rqp->sr_serror;
	ioc->ioc_error = rqp->sr_error;
	(void) ddi_copyout(ioc, (void *)arg, sizeof (*ioc), flags);

out:
	if (rqp != NULL)
		smb_rq_done(rqp); /* free rqp */
	if (ioc != NULL)
		kmem_free(ioc, sizeof (*ioc));
	smb_credrele(&scred);

	return (err);

}

/*
 * Ioctl function for SMBIOC_T2RQ
 */
int
smb_usr_t2request(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	struct smb_share *ssp;
	smbioc_t2rq_t *ioc = NULL;
	struct smb_t2rq *t2p = NULL;
	struct mdchain *mdp;
	int err, len, mbseg;

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	smb_credinit(&scred, cr);
	ioc = kmem_alloc(sizeof (*ioc), KM_SLEEP);
	if (ddi_copyin((void *) arg, ioc, sizeof (*ioc), flags)) {
		err = EFAULT;
		goto out;
	}

	/* See ddi_copyin, ddi_copyout */
	mbseg = (flags & FKIOCTL) ? MB_MSYSTEM : MB_MUSER;

	if (ioc->ioc_setupcnt > SMBIOC_T2RQ_MAXSETUP) {
		err = EINVAL;
		goto out;
	}

	t2p = kmem_alloc(sizeof (*t2p), KM_SLEEP);
	err = smb_t2_init(t2p, SSTOCP(ssp),
	    ioc->ioc_setup, ioc->ioc_setupcnt, &scred);
	if (err)
		goto out;
	len = t2p->t2_setupcount = ioc->ioc_setupcnt;
	if (len > 1)
		t2p->t2_setupdata = ioc->ioc_setup;

	/* This ioc member is a fixed-size array. */
	if (ioc->ioc_name[0]) {
		/* Get the name length - carefully! */
		ioc->ioc_name[SMBIOC_T2RQ_MAXNAME-1] = '\0';
		t2p->t_name_len = strlen(ioc->ioc_name);
		t2p->t_name = ioc->ioc_name;
	}
	t2p->t2_maxscount = 0;
	t2p->t2_maxpcount = ioc->ioc_rparamcnt;
	t2p->t2_maxdcount = ioc->ioc_rdatacnt;

	/* Transmit parameters */
	err = smb_cpdatain(&t2p->t2_tparam,
	    ioc->ioc_tparamcnt, ioc->ioc_tparam, mbseg);
	if (err)
		goto out;

	/* Transmit data */
	err = smb_cpdatain(&t2p->t2_tdata,
	    ioc->ioc_tdatacnt, ioc->ioc_tdata, mbseg);
	if (err)
		goto out;

	err = smb_t2_request(t2p);

	/* Copyout returned parameters. */
	mdp = &t2p->t2_rparam;
	if (err == 0 && mdp->md_top != NULL) {
		/* User's buffer large enough? */
		len = m_fixhdr(mdp->md_top);
		if (len > ioc->ioc_rparamcnt) {
			err = EMSGSIZE;
			goto out;
		}
		ioc->ioc_rparamcnt = (ushort_t)len;
		err = md_get_mem(mdp, ioc->ioc_rparam, len, mbseg);
		if (err)
			goto out;
	} else
		ioc->ioc_rparamcnt = 0;

	/* Copyout returned data. */
	mdp = &t2p->t2_rdata;
	if (err == 0 && mdp->md_top != NULL) {
		/* User's buffer large enough? */
		len = m_fixhdr(mdp->md_top);
		if (len > ioc->ioc_rdatacnt) {
			err = EMSGSIZE;
			goto out;
		}
		ioc->ioc_rdatacnt = (ushort_t)len;
		err = md_get_mem(mdp, ioc->ioc_rdata, len, mbseg);
		if (err)
			goto out;
	} else
		ioc->ioc_rdatacnt = 0;

	ioc->ioc_errclass = t2p->t2_sr_errclass;
	ioc->ioc_serror = t2p->t2_sr_serror;
	ioc->ioc_error = t2p->t2_sr_error;
	ioc->ioc_rpflags2 = t2p->t2_sr_rpflags2;

	(void) ddi_copyout(ioc, (void *)arg, sizeof (*ioc), flags);


out:
	if (t2p != NULL) {
		/* Note: t2p->t_name no longer allocated */
		smb_t2_done(t2p);
		kmem_free(t2p, sizeof (*t2p));
	}
	if (ioc != NULL)
		kmem_free(ioc, sizeof (*ioc));
	smb_credrele(&scred);

	return (err);
}

/* helper for _t2request */
static int
smb_cpdatain(struct mbchain *mbp, int len, char *data, int mbseg)
{
	int error;

	if (len == 0)
		return (0);
	error = mb_init(mbp);
	if (error)
		return (error);
	return (mb_put_mem(mbp, data, len, mbseg));
}

/*
 * Helper for nsmb_ioctl cases
 * SMBIOC_READ, SMBIOC_WRITE
 */
int
smb_usr_rw(smb_dev_t *sdp, int cmd, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	struct smb_share *ssp;
	smbioc_rw_t *ioc = NULL;
	struct iovec aiov[1];
	struct uio  auio;
	u_int16_t fh;
	int err;
	uio_rw_t rw;

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	/* After reconnect, force close+reopen */
	if (sdp->sd_vcgenid != ssp->ss_vcgenid)
		return (ESTALE);

	smb_credinit(&scred, cr);
	ioc = kmem_alloc(sizeof (*ioc), KM_SLEEP);
	if (ddi_copyin((void *) arg, ioc, sizeof (*ioc), flags)) {
		err = EFAULT;
		goto out;
	}

	switch (cmd) {
	case SMBIOC_READ:
		rw = UIO_READ;
		break;
	case SMBIOC_WRITE:
		rw = UIO_WRITE;
		break;
	default:
		err = ENODEV;
		goto out;
	}

	fh = ioc->ioc_fh;

	aiov[0].iov_base = ioc->ioc_base;
	aiov[0].iov_len = (size_t)ioc->ioc_cnt;

	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = ioc->ioc_offset;
	auio.uio_segflg = (flags & FKIOCTL) ?
	    UIO_SYSSPACE : UIO_USERSPACE;
	auio.uio_fmode = 0;
	auio.uio_resid = (size_t)ioc->ioc_cnt;

	err = smb_rwuio(ssp, fh, rw, &auio, &scred, 0);

	/*
	 * On return ioc_cnt holds the
	 * number of bytes transferred.
	 */
	ioc->ioc_cnt -= auio.uio_resid;

	(void) ddi_copyout(ioc, (void *)arg, sizeof (*ioc), flags);

out:
	if (ioc != NULL)
		kmem_free(ioc, sizeof (*ioc));
	smb_credrele(&scred);

	return (err);
}

/*
 * Ioctl functions: SMBIOC_SSN_FIND, SMBIOC_SSN_CREATE
 * Find or create a session (a.k.a. "VC" in here)
 */
int
smb_usr_get_ssn(smb_dev_t *sdp, int cmd, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	smbioc_ossn_t *ossn = NULL;
	struct smb_vc *vcp = NULL;
	int error = 0;
	uid_t realuid;

	/* Should be no VC */
	if (sdp->sd_vc != NULL)
		return (EISCONN);

	smb_credinit(&scred, cr);
	ossn = kmem_alloc(sizeof (*ossn), KM_SLEEP);
	if (ddi_copyin((void *)arg, ossn, sizeof (*ossn), flags)) {
		error = EFAULT;
		goto out;
	}

	/*
	 * Only superuser can specify a UID or GID.
	 */
	realuid = crgetruid(cr);
	if (ossn->ssn_owner == SMBM_ANY_OWNER)
		ossn->ssn_owner = realuid;
	else {
		/*
		 * Do we have the privilege to create with the
		 * specified uid?  (does uid == cr->cr_uid, etc.)
		 */
		if (secpolicy_vnode_owner(cr, ossn->ssn_owner)) {
			error = EPERM;
			goto out;
		}
		/* ossn->ssn_owner is OK */
	}

	/*
	 * Make sure the strings are null terminated.
	 */
	ossn->ssn_srvname[SMBIOC_MAX_NAME-1] = '\0';
	ossn->ssn_id.id_domain[ SMBIOC_MAX_NAME-1] = '\0';
	ossn->ssn_id.id_user[   SMBIOC_MAX_NAME-1] = '\0';

	if (cmd == SMBIOC_SSN_CREATE)
		ossn->ssn_vopt |= SMBVOPT_CREATE;
	else /* FIND */
		ossn->ssn_vopt &= ~SMBVOPT_CREATE;

	error = smb_vc_findcreate(ossn, &scred, &vcp);
	if (error)
		goto out;
	ASSERT(vcp != NULL);

	/*
	 * We have a VC, held, but not locked.
	 * If we're creating, mark this instance as
	 * an open from IOD so close can do cleanup.
	 *
	 * XXX: Would be nice to have a back pointer
	 * from the VC to this (IOD) sdp instance.
	 */
	if (cmd == SMBIOC_SSN_CREATE) {
		if (vcp->iod_thr != NULL) {
			error = EEXIST;
			goto out;
		}
		sdp->sd_flags |= NSMBFL_IOD;
	} else {
		/*
		 * Wait for it to finish connecting
		 * (or reconnect) if necessary.
		 */
		if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
			error = smb_iod_reconnect(vcp);
			if (error != 0)
				goto out;
		}
	}

	/*
	 * The VC has a hold from _findvc
	 * which we keep until _SSN_RELE
	 * or nsmb_close().
	 */
	sdp->sd_level = SMBL_VC;
	sdp->sd_vc = vcp;
	vcp = NULL;
	(void) ddi_copyout(ossn, (void *)arg, sizeof (*ossn), flags);

out:
	if (vcp) {
		/* Error path: rele hold from _findcreate */
		smb_vc_rele(vcp);
	}
	if (ossn != NULL)
		kmem_free(ossn, sizeof (*ossn));
	smb_credrele(&scred);

	return (error);
}

/*
 * Ioctl functions: SMBIOC_SSN_RELE, SMBIOC_SSN_KILL
 * Release or kill the current session.
 */
int
smb_usr_drop_ssn(smb_dev_t *sdp, int cmd)
{
	struct smb_vc *vcp = NULL;

	/* Must have a VC. */
	if ((vcp = sdp->sd_vc) == NULL)
		return (ENOTCONN);

	/* If we have a share ref, drop it too. */
	if (sdp->sd_share) {
		smb_share_rele(sdp->sd_share);
		sdp->sd_share = NULL;
		sdp->sd_level = SMBL_VC;
	}

	if (cmd == SMBIOC_SSN_KILL)
		smb_vc_kill(vcp);

	/* Drop the VC ref. */
	smb_vc_rele(vcp);
	sdp->sd_vc = NULL;
	sdp->sd_level = 0;

	return (0);
}

/*
 * Find or create a tree (connected share)
 */
int
smb_usr_get_tree(smb_dev_t *sdp, int cmd, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	smbioc_tcon_t *tcon = NULL;
	struct smb_vc *vcp = NULL;
	struct smb_share *ssp = NULL;
	int error = 0;

	/* Must have a VC. */
	if ((vcp = sdp->sd_vc) == NULL)
		return (ENOTCONN);
	/* Should not have a share. */
	if (sdp->sd_share != NULL)
		return (EISCONN);

	smb_credinit(&scred, cr);
	tcon = kmem_alloc(sizeof (*tcon), KM_SLEEP);
	if (ddi_copyin((void *)arg, tcon, sizeof (*tcon), flags)) {
		error = EFAULT;
		goto out;
	}

	/*
	 * Make sure the strings are null terminated.
	 */
	tcon->tc_sh.sh_name[SMBIOC_MAX_NAME-1] = '\0';
	tcon->tc_sh.sh_pass[SMBIOC_MAX_NAME-1] = '\0';
	tcon->tc_sh.sh_type_req[SMBIOC_STYPE_LEN-1] = '\0';
	bzero(tcon->tc_sh.sh_type_ret, SMBIOC_STYPE_LEN);

	if (cmd == SMBIOC_TREE_CONNECT)
		tcon->tc_opt |= SMBSOPT_CREATE;
	else /* FIND */
		tcon->tc_opt &= ~SMBSOPT_CREATE;

	error = smb_share_findcreate(tcon, vcp, &ssp, &scred);
	if (error)
		goto out;
	ASSERT(ssp != NULL);

	/*
	 * We have a share, held, but not locked.
	 * If we're creating, do tree connect now,
	 * otherwise let that wait for a request.
	 */
	if (cmd == SMBIOC_TREE_CONNECT) {
		error = smb_share_tcon(ssp, &scred);
		if (error)
			goto out;
	}

	/*
	 * Give caller the real share type from
	 * the tree connect response, so they can
	 * see if they got the requested type.
	 */
	(void) memcpy(tcon->tc_sh.sh_type_ret,
	    ssp->ss_type_ret, SMBIOC_STYPE_LEN);

	/*
	 * The share has a hold from _tcon
	 * which we keep until nsmb_close()
	 * or the SMBIOC_TDIS below.
	 */
	sdp->sd_level = SMBL_SHARE;
	sdp->sd_share = ssp;
	ssp = NULL;
	(void) ddi_copyout(tcon, (void *)arg, sizeof (*tcon), flags);

out:
	if (ssp) {
		/* Error path: rele hold from _findcreate */
		smb_share_rele(ssp);
	}
	if (tcon) {
		/*
		 * This structure may contain a
		 * cleartext password, so zap it.
		 */
		bzero(tcon, sizeof (*tcon));
		kmem_free(tcon, sizeof (*tcon));
	}
	smb_credrele(&scred);

	return (error);
}

/*
 * Ioctl functions: SMBIOC_TREE_RELE, SMBIOC_TREE_KILL
 * Release or kill the current tree
 */
int
smb_usr_drop_tree(smb_dev_t *sdp, int cmd)
{
	struct smb_share *ssp = NULL;

	/* Must have a VC and a share. */
	if (sdp->sd_vc == NULL)
		return (ENOTCONN);
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	if (cmd == SMBIOC_TREE_KILL)
		smb_share_kill(ssp);

	/* Drop the share ref. */
	smb_share_rele(sdp->sd_share);
	sdp->sd_share = NULL;
	sdp->sd_level = SMBL_VC;

	return (0);
}


/*
 * Ioctl function: SMBIOC_IOD_WORK
 *
 * Become the reader (IOD) thread, until either the connection is
 * reset by the server, or until the connection is idle longer than
 * some max time. (max idle time not yet implemented)
 */
int
smb_usr_iod_work(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_vc *vcp = NULL;
	int err = 0;

	/* Must have a valid session. */
	if ((vcp = sdp->sd_vc) == NULL)
		return (EINVAL);
	if (vcp->vc_flags & SMBV_GONE)
		return (EINVAL);

	/*
	 * Is there already an IOD for this VC?
	 * (Should never happen.)
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->iod_thr == NULL)
		vcp->iod_thr = curthread;
	else
		err = EEXIST;
	SMB_VC_UNLOCK(vcp);
	if (err)
		return (err);

	/*
	 * Copy the "work" state, etc. into the VC
	 * The MAC key is copied separately.
	 */
	if (ddi_copyin((void *)arg, &vcp->vc_work,
	    sizeof (smbioc_ssn_work_t), flags)) {
		err = EFAULT;
		goto out;
	}
	if (vcp->vc_u_maclen) {
		vcp->vc_mackeylen = vcp->vc_u_maclen;
		vcp->vc_mackey = kmem_alloc(vcp->vc_mackeylen, KM_SLEEP);
		if (ddi_copyin(vcp->vc_u_mackey.lp_ptr, vcp->vc_mackey,
		    vcp->vc_mackeylen, flags)) {
			err = EFAULT;
			goto out;
		}
	}

	err = smb_iod_vc_work(vcp, cr);

	/* Caller wants state here. */
	vcp->vc_work.wk_out_state = vcp->vc_state;

	(void) ddi_copyout(&vcp->vc_work, (void *)arg,
	    sizeof (smbioc_ssn_work_t), flags);

out:
	if (vcp->vc_mackey) {
		kmem_free(vcp->vc_mackey, vcp->vc_mackeylen);
		vcp->vc_mackey = NULL;
		vcp->vc_mackeylen = 0;
	}

	/*
	 * The IOD thread is leaving the driver.  Clear iod_thr,
	 * and wake up anybody waiting for us to quit.
	 */
	SMB_VC_LOCK(vcp);
	vcp->iod_thr = NULL;
	cv_broadcast(&vcp->vc_statechg);
	SMB_VC_UNLOCK(vcp);

	return (err);
}

/*
 * Ioctl functions: SMBIOC_IOD_IDLE, SMBIOC_IOD_RCFAIL
 *
 * Wait for user-level requests to be enqueued on this session,
 * and then return to the user-space helper, which will then
 * initiate a reconnect, etc.
 */
int
smb_usr_iod_ioctl(smb_dev_t *sdp, int cmd, intptr_t arg, int flags)
{
	struct smb_vc *vcp = NULL;
	int err = 0;

	/* Must have a valid session. */
	if ((vcp = sdp->sd_vc) == NULL)
		return (EINVAL);
	if (vcp->vc_flags & SMBV_GONE)
		return (EINVAL);

	/*
	 * Is there already an IOD for this VC?
	 * (Should never happen.)
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->iod_thr == NULL)
		vcp->iod_thr = curthread;
	else
		err = EEXIST;
	SMB_VC_UNLOCK(vcp);
	if (err)
		return (err);

	/* nothing to copyin */

	switch (cmd) {
	case SMBIOC_IOD_IDLE:
		err = smb_iod_vc_idle(vcp);
		break;

	case SMBIOC_IOD_RCFAIL:
		err = smb_iod_vc_rcfail(vcp);
		break;

	default:
		err = ENOTTY;
		goto out;
	}

	/* Both of these ioctls copy out the new state. */
	(void) ddi_copyout(&vcp->vc_state, (void *)arg,
	    sizeof (int), flags);

out:
	/*
	 * The IOD thread is leaving the driver.  Clear iod_thr,
	 * and wake up anybody waiting for us to quit.
	 */
	SMB_VC_LOCK(vcp);
	vcp->iod_thr = NULL;
	cv_broadcast(&vcp->vc_statechg);
	SMB_VC_UNLOCK(vcp);

	return (err);
}
