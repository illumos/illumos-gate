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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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
	if (vcp->vc_ssnkey == NULL ||
	    vcp->vc_ssnkeylen < SMBIOC_HASH_SZ)
		return (EINVAL);
	if (ddi_copyout(vcp->vc_ssnkey, (void *)arg,
	    SMBIOC_HASH_SZ, flags))
		return (EFAULT);

	return (0);
}

/*
 * Ioctl function for SMBIOC_XACTNP (transact named pipe)
 */
int
smb_usr_xnp(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	struct smb_share *ssp;
	smbioc_xnp_t *ioc = NULL;
	struct smb_t2rq *t2p = NULL;
	struct mdchain *mdp;
	int err, len, mbseg;
	uint16_t setup[2];

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
	 * Fill in the FID for libsmbfs transact named pipe.
	 */
	if (ioc->ioc_fh == -1) {
		if (sdp->sd_vcgenid != ssp->ss_vcgenid) {
			err = ESTALE;
			goto out;
		}
		ioc->ioc_fh = sdp->sd_smbfid;
	}

	setup[0] = TRANS_TRANSACT_NAMED_PIPE;
	setup[1] = (uint16_t)ioc->ioc_fh;

	t2p = kmem_alloc(sizeof (*t2p), KM_SLEEP);
	err = smb_t2_init(t2p, SSTOCP(ssp), setup, 2, &scred);
	if (err)
		goto out;
	t2p->t2_setupcount = 2;
	t2p->t2_setupdata  = setup;

	t2p->t_name = "\\PIPE\\";
	t2p->t_name_len = 6;

	t2p->t2_maxscount = 0;
	t2p->t2_maxpcount = 0;
	t2p->t2_maxdcount = ioc->ioc_rdlen;

	/* Transmit parameters (none) */

	/* Transmit data */
	err = smb_cpdatain(&t2p->t2_tdata,
	    ioc->ioc_tdlen, ioc->ioc_tdata, mbseg);
	if (err)
		goto out;

	err = smb_t2_request(t2p);

	/* No returned parameters. */

	/* Copyout returned data. */
	mdp = &t2p->t2_rdata;
	if (err == 0 && mdp->md_top != NULL) {
		/* User's buffer large enough? */
		len = m_fixhdr(mdp->md_top);
		if (len > ioc->ioc_rdlen) {
			err = EMSGSIZE;
			goto out;
		}
		ioc->ioc_rdlen = (ushort_t)len;
		err = md_get_mem(mdp, ioc->ioc_rdata, len, mbseg);
		if (err)
			goto out;
	} else
		ioc->ioc_rdlen = 0;

	if (t2p->t2_sr_error == NT_STATUS_BUFFER_OVERFLOW)
		ioc->ioc_more = 1;

	(void) ddi_copyout(ioc, (void *)arg, sizeof (*ioc), flags);


out:
	if (t2p != NULL) {
		/* Note: t2p->t_name no longer allocated */
		smb_t2_done(t2p);
		kmem_free(t2p, sizeof (*t2p));
	}
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
	uint16_t fh;
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

	/*
	 * If caller passes -1 in ioc_fh, then
	 * use the FID from SMBIOC_NTCREATE.
	 */
	if (ioc->ioc_fh == -1)
		fh = (uint16_t)sdp->sd_smbfid;
	else
		fh = (uint16_t)ioc->ioc_fh;

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
	kmem_free(ioc, sizeof (*ioc));
	smb_credrele(&scred);

	return (err);
}

/*
 * Helper for nsmb_ioctl case
 * SMBIOC_NTCREATE
 */
int
smb_usr_ntcreate(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	struct mbchain name_mb;
	struct smb_share *ssp;
	smbioc_ntcreate_t *ioc = NULL;
	uint16_t fid;
	int err, nmlen;

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	/* Must not be already open. */
	if (sdp->sd_smbfid != -1)
		return (EINVAL);

	mb_init(&name_mb);
	smb_credinit(&scred, cr);
	ioc = kmem_alloc(sizeof (*ioc), KM_SLEEP);
	if (ddi_copyin((void *) arg, ioc, sizeof (*ioc), flags)) {
		err = EFAULT;
		goto out;
	}

	/* Build name_mb */
	ioc->ioc_name[SMBIOC_MAX_NAME-1] = '\0';
	nmlen = strnlen(ioc->ioc_name, SMBIOC_MAX_NAME-1);
	err = smb_put_dmem(&name_mb, SSTOVC(ssp),
	    ioc->ioc_name, nmlen,
	    SMB_CS_NONE, NULL);
	if (err != 0)
		goto out;

	/* Do the OtW open, save the FID. */
	err = smb_smb_ntcreate(ssp, &name_mb,
	    0,	/* create flags */
	    ioc->ioc_req_acc,
	    ioc->ioc_efattr,
	    ioc->ioc_share_acc,
	    ioc->ioc_open_disp,
	    ioc->ioc_creat_opts,
	    NTCREATEX_IMPERSONATION_IMPERSONATION,
	    &scred,
	    &fid,
	    NULL,
	    NULL);
	if (err != 0)
		goto out;

	sdp->sd_smbfid = fid;
	sdp->sd_vcgenid = ssp->ss_vcgenid;

out:
	kmem_free(ioc, sizeof (*ioc));
	smb_credrele(&scred);
	mb_done(&name_mb);

	return (err);
}

/*
 * Helper for nsmb_ioctl case
 * SMBIOC_PRINTJOB
 */
int
smb_usr_printjob(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_cred scred;
	struct smb_share *ssp;
	smbioc_printjob_t *ioc = NULL;
	uint16_t fid;
	int err;

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	/* The share must be a print queue. */
	if (ssp->ss_type != STYPE_PRINTQ)
		return (EINVAL);

	/* Must not be already open. */
	if (sdp->sd_smbfid != -1)
		return (EINVAL);

	smb_credinit(&scred, cr);
	ioc = kmem_alloc(sizeof (*ioc), KM_SLEEP);
	if (ddi_copyin((void *) arg, ioc, sizeof (*ioc), flags)) {
		err = EFAULT;
		goto out;
	}
	ioc->ioc_title[SMBIOC_MAX_NAME-1] = '\0';

	/* Do the OtW open, save the FID. */
	err = smb_smb_open_prjob(ssp, ioc->ioc_title,
	    ioc->ioc_setuplen, ioc->ioc_prmode,
	    &scred, &fid);
	if (err != 0)
		goto out;

	sdp->sd_smbfid = fid;
	sdp->sd_vcgenid = ssp->ss_vcgenid;

out:
	kmem_free(ioc, sizeof (*ioc));
	smb_credrele(&scred);

	return (err);
}

/*
 * Helper for nsmb_ioctl case
 * SMBIOC_CLOSEFH
 */
int
smb_usr_closefh(smb_dev_t *sdp, cred_t *cr)
{
	struct smb_cred scred;
	struct smb_share *ssp;
	uint16_t fid;
	int err;

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	if (sdp->sd_smbfid == -1)
		return (0);
	fid = (uint16_t)sdp->sd_smbfid;
	sdp->sd_smbfid = -1;

	smb_credinit(&scred, cr);
	if (ssp->ss_type == STYPE_PRINTQ)
		err = smb_smb_close_prjob(ssp, fid, &scred);
	else
		err = smb_smb_close(ssp, fid, NULL, &scred);
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
	tcon->tc_sh.sh_type = ssp->ss_type;

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
	/*
	 * This structure may contain a
	 * cleartext password, so zap it.
	 */
	bzero(tcon, sizeof (*tcon));
	kmem_free(tcon, sizeof (*tcon));
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
 * Ioctl handler for all SMBIOC_IOD_...
 */
int
smb_usr_iod_ioctl(smb_dev_t *sdp, int cmd, intptr_t arg, int flags, cred_t *cr)
{
	struct smb_vc *vcp;
	int err = 0;

	/* Must be the IOD. */
	if ((sdp->sd_flags & NSMBFL_IOD) == 0)
		return (EINVAL);
	/* Must have a VC and no share. */
	if ((vcp = sdp->sd_vc) == NULL)
		return (EINVAL);
	if (sdp->sd_share != NULL)
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
	 * Copy the "work" state, etc. into the VC,
	 * and back to the caller on the way out.
	 * Clear the "out only" part.
	 */
	if (ddi_copyin((void *)arg, &vcp->vc_work,
	    sizeof (smbioc_ssn_work_t), flags)) {
		err = EFAULT;
		goto out;
	}
	vcp->vc_work.wk_out_state = 0;

	switch (cmd) {

	case SMBIOC_IOD_CONNECT:
		err = nsmb_iod_connect(vcp);
		break;

	case SMBIOC_IOD_NEGOTIATE:
		err = nsmb_iod_negotiate(vcp, cr);
		break;

	case SMBIOC_IOD_SSNSETUP:
		err = nsmb_iod_ssnsetup(vcp, cr);
		break;

	case SMBIOC_IOD_WORK:
		err = smb_iod_vc_work(vcp, flags, cr);
		break;

	case SMBIOC_IOD_IDLE:
		err = smb_iod_vc_idle(vcp);
		break;

	case SMBIOC_IOD_RCFAIL:
		err = smb_iod_vc_rcfail(vcp);
		break;

	default:
		err = ENOTTY;
		break;
	}

out:
	vcp->vc_work.wk_out_state = vcp->vc_state;
	(void) ddi_copyout(&vcp->vc_work, (void *)arg,
	    sizeof (smbioc_ssn_work_t), flags);

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

int
smb_usr_ioctl(smb_dev_t *sdp, int cmd, intptr_t arg, int flags, cred_t *cr)
{
	int err;

	/*
	 * Serialize ioctl calls.  The smb_usr_... functions
	 * don't expect concurrent calls on a given sdp.
	 */
	mutex_enter(&sdp->sd_lock);
	if ((sdp->sd_flags & NSMBFL_IOCTL) != 0) {
		mutex_exit(&sdp->sd_lock);
		return (EBUSY);
	}
	sdp->sd_flags |= NSMBFL_IOCTL;
	mutex_exit(&sdp->sd_lock);

	err = 0;
	switch (cmd) {
	case SMBIOC_GETVERS:
		(void) ddi_copyout(&nsmb_version, (void *)arg,
		    sizeof (nsmb_version), flags);
		break;

	case SMBIOC_GETSSNKEY:
		err = smb_usr_get_ssnkey(sdp, arg, flags);
		break;

	case SMBIOC_DUP_DEV:
		err = smb_usr_dup_dev(sdp, arg, flags);
		break;

	case SMBIOC_XACTNP:
		err = smb_usr_xnp(sdp, arg, flags, cr);
		break;

	case SMBIOC_READ:
	case SMBIOC_WRITE:
		err = smb_usr_rw(sdp, cmd, arg, flags, cr);
		break;

	case SMBIOC_NTCREATE:
		err = smb_usr_ntcreate(sdp, arg, flags, cr);
		break;

	case SMBIOC_PRINTJOB:
		err = smb_usr_printjob(sdp, arg, flags, cr);
		break;

	case SMBIOC_CLOSEFH:
		err = smb_usr_closefh(sdp, cr);
		break;

	case SMBIOC_SSN_CREATE:
	case SMBIOC_SSN_FIND:
		err = smb_usr_get_ssn(sdp, cmd, arg, flags, cr);
		break;

	case SMBIOC_SSN_KILL:
	case SMBIOC_SSN_RELE:
		err = smb_usr_drop_ssn(sdp, cmd);
		break;

	case SMBIOC_TREE_CONNECT:
	case SMBIOC_TREE_FIND:
		err = smb_usr_get_tree(sdp, cmd, arg, flags, cr);
		break;

	case SMBIOC_TREE_KILL:
	case SMBIOC_TREE_RELE:
		err = smb_usr_drop_tree(sdp, cmd);
		break;

	case SMBIOC_IOD_CONNECT:
	case SMBIOC_IOD_NEGOTIATE:
	case SMBIOC_IOD_SSNSETUP:
	case SMBIOC_IOD_WORK:
	case SMBIOC_IOD_IDLE:
	case SMBIOC_IOD_RCFAIL:
		err = smb_usr_iod_ioctl(sdp, cmd, arg, flags, cr);
		break;

	case SMBIOC_PK_ADD:
	case SMBIOC_PK_DEL:
	case SMBIOC_PK_CHK:
	case SMBIOC_PK_DEL_OWNER:
	case SMBIOC_PK_DEL_EVERYONE:
		err = smb_pkey_ioctl(cmd, arg, flags, cr);
		break;

	default:
		err = ENOTTY;
		break;
	}

	mutex_enter(&sdp->sd_lock);
	sdp->sd_flags &= ~NSMBFL_IOCTL;
	mutex_exit(&sdp->sd_lock);

	return (err);
}
