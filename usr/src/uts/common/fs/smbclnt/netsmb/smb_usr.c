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
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
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

#include <smb/winioctl.h>
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
	struct smb_fh *fhp;
	smbioc_xnp_t *ioc = NULL;
	struct mbchain send_mb;
	struct mdchain recv_md;
	uint32_t rdlen;
	int err, mbseg;

	/* This ioctl requires a file handle. */
	if ((fhp = sdp->sd_fh) == NULL)
		return (EINVAL);
	ssp = FHTOSS(fhp);

	/* After reconnect, force close+reopen */
	if (fhp->fh_vcgenid != ssp->ss_vcgenid)
		return (ESTALE);

	bzero(&send_mb, sizeof (send_mb));
	bzero(&recv_md, sizeof (recv_md));

	ioc = kmem_alloc(sizeof (*ioc), KM_SLEEP);
	if (ddi_copyin((void *) arg, ioc, sizeof (*ioc), flags)) {
		err = EFAULT;
		goto out;
	}

	/*
	 * Copyin the send data, into an mbchain,
	 * save output buffer size.
	 */
	mbseg = (flags & FKIOCTL) ? MB_MSYSTEM : MB_MUSER;
	err = smb_cpdatain(&send_mb, ioc->ioc_tdlen, ioc->ioc_tdata, mbseg);
	if (err)
		goto out;
	rdlen = ioc->ioc_rdlen;

	/*
	 * Run the SMB2 ioctl or SMB1 trans2
	 */
	smb_credinit(&scred, cr);
	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		err = smb2_smb_ioctl(ssp, &fhp->fh_fid2,
		    &send_mb, &recv_md, &rdlen,
		    FSCTL_PIPE_TRANSCEIVE, &scred);
	} else {
		err = smb_t2_xnp(ssp, fhp->fh_fid1,
		    &send_mb, &recv_md, &rdlen,
		    &ioc->ioc_more, &scred);
	}
	smb_credrele(&scred);

	/* Copyout returned data. */
	if (err == 0 && recv_md.md_top != NULL) {
		/* User's buffer large enough for copyout? */
		size_t len = m_fixhdr(recv_md.md_top);
		if (len > ioc->ioc_rdlen) {
			err = EMSGSIZE;
			goto out;
		}
		err = md_get_mem(&recv_md, ioc->ioc_rdata, len, mbseg);
		if (err)
			goto out;
	} else
		ioc->ioc_rdlen = 0;

	/* Tell caller received length */
	if (rdlen <= ioc->ioc_rdlen) {
		/* Normal case */
		ioc->ioc_rdlen = rdlen;
	} else {
		/* Buffer overlow. Leave ioc_rdlen */
		ioc->ioc_more = 1;
	}

	(void) ddi_copyout(ioc, (void *)arg, sizeof (*ioc), flags);

out:
	kmem_free(ioc, sizeof (*ioc));
	md_done(&recv_md);
	mb_done(&send_mb);

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
	struct smb_fh *fhp;
	smbioc_rw_t *ioc = NULL;
	struct iovec aiov[1];
	struct uio  auio;
	int err;
	uio_rw_t rw;

	/* This ioctl requires a file handle. */
	if ((fhp = sdp->sd_fh) == NULL)
		return (EINVAL);
	ssp = FHTOSS(fhp);

	/* After reconnect, force close+reopen */
	if (fhp->fh_vcgenid != ssp->ss_vcgenid)
		return (ESTALE);

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

	aiov[0].iov_base = ioc->ioc_base;
	aiov[0].iov_len = (size_t)ioc->ioc_cnt;

	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = ioc->ioc_offset;
	auio.uio_segflg = (flags & FKIOCTL) ?
	    UIO_SYSSPACE : UIO_USERSPACE;
	auio.uio_fmode = 0;
	auio.uio_resid = (size_t)ioc->ioc_cnt;

	smb_credinit(&scred, cr);
	err = smb_rwuio(fhp, rw, &auio, &scred, 0);
	smb_credrele(&scred);

	/*
	 * On return ioc_cnt holds the
	 * number of bytes transferred.
	 */
	ioc->ioc_cnt -= auio.uio_resid;

	(void) ddi_copyout(ioc, (void *)arg, sizeof (*ioc), flags);

out:
	kmem_free(ioc, sizeof (*ioc));

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
	struct smb_fh *fhp = NULL;
	smbioc_ntcreate_t *ioc = NULL;
	int err, nmlen;

	mb_init(&name_mb);

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	/* Must not already have a file handle. */
	if (sdp->sd_fh != NULL)
		return (EINVAL);

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

	err = smb_fh_create(ssp, &fhp);
	if (err != 0)
		goto out;

	/*
	 * Do the OtW open, save the FID.
	 */
	smb_credinit(&scred, cr);
	err = smb_smb_ntcreate(ssp, &name_mb,
	    0,	/* create flags */
	    ioc->ioc_req_acc,
	    ioc->ioc_efattr,
	    ioc->ioc_share_acc,
	    ioc->ioc_open_disp,
	    ioc->ioc_creat_opts,
	    NTCREATEX_IMPERSONATION_IMPERSONATION,
	    &scred,
	    fhp,
	    NULL,
	    NULL);
	smb_credrele(&scred);
	if (err != 0)
		goto out;

	fhp->fh_rights = ioc->ioc_req_acc;
	smb_fh_opened(fhp);
	sdp->sd_fh = fhp;
	fhp = NULL;

out:
	if (fhp != NULL)
		smb_fh_rele(fhp);
	kmem_free(ioc, sizeof (*ioc));
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
	static const char invalid_chars[] = SMB_FILENAME_INVALID_CHARS;
	struct smb_cred scred;
	struct mbchain name_mb;
	struct smb_share *ssp;
	struct smb_fh *fhp = NULL;
	smbioc_printjob_t *ioc = NULL;
	int err, cklen, nmlen;
	uint32_t access = SA_RIGHT_FILE_WRITE_DATA |
	    SA_RIGHT_FILE_READ_ATTRIBUTES;

	mb_init(&name_mb);

	/* This ioctl requires a share. */
	if ((ssp = sdp->sd_share) == NULL)
		return (ENOTCONN);

	/* The share must be a print queue. */
	if (ssp->ss_type != STYPE_PRINTQ)
		return (EINVAL);

	/* Must not already have a file handle. */
	if (sdp->sd_fh != NULL)
		return (EINVAL);

	smb_credinit(&scred, cr);
	ioc = kmem_alloc(sizeof (*ioc), KM_SLEEP);
	if (ddi_copyin((void *) arg, ioc, sizeof (*ioc), flags)) {
		err = EFAULT;
		goto out;
	}

	/*
	 * Use the print job title as the file name to open, but
	 * check for invalid characters first.  See the notes in
	 * libsmbfs/smb/print.c about job name sanitizing.
	 */
	ioc->ioc_title[SMBIOC_MAX_NAME-1] = '\0';
	nmlen = strnlen(ioc->ioc_title, SMBIOC_MAX_NAME-1);
	cklen = strcspn(ioc->ioc_title, invalid_chars);
	if (cklen < nmlen) {
		err = EINVAL;
		goto out;
	}

	/* Build name_mb */
	err = smb_put_dmem(&name_mb, SSTOVC(ssp),
	    ioc->ioc_title, nmlen,
	    SMB_CS_NONE, NULL);
	if (err != 0)
		goto out;

	err = smb_fh_create(ssp, &fhp);
	if (err != 0)
		goto out;

	/*
	 * Do the OtW open, save the FID.
	 */
	smb_credinit(&scred, cr);
	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		err = smb2_smb_ntcreate(ssp, &name_mb,
		    NULL, NULL, /* cctx in, out */
		    0,	/* create flags */
		    access,
		    SMB_EFA_NORMAL,
		    NTCREATEX_SHARE_ACCESS_NONE,
		    NTCREATEX_DISP_CREATE,
		    NTCREATEX_OPTIONS_NON_DIRECTORY_FILE,
		    NTCREATEX_IMPERSONATION_IMPERSONATION,
		    &scred,
		    &fhp->fh_fid2,
		    NULL,
		    NULL);
	} else {
		err = smb_smb_open_prjob(ssp, ioc->ioc_title,
		    ioc->ioc_setuplen, ioc->ioc_prmode,
		    &scred, &fhp->fh_fid1);
	}
	smb_credrele(&scred);
	if (err != 0)
		goto out;

	fhp->fh_rights = access;
	smb_fh_opened(fhp);
	sdp->sd_fh = fhp;
	fhp = NULL;

out:
	if (fhp != NULL)
		smb_fh_rele(fhp);
	kmem_free(ioc, sizeof (*ioc));
	mb_done(&name_mb);

	return (err);
}

/*
 * Helper for nsmb_ioctl case
 * SMBIOC_CLOSEFH
 */
/*ARGSUSED*/
int
smb_usr_closefh(smb_dev_t *sdp, cred_t *cr)
{
	struct smb_fh *fhp;

	/* This ioctl requires a file handle. */
	if ((fhp = sdp->sd_fh) == NULL)
		return (EINVAL);
	sdp->sd_fh = NULL;

	smb_fh_close(fhp);
	smb_fh_rele(fhp);

	return (0);
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
		err = nsmb_iod_connect(vcp, cr);
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
