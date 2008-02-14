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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/policy.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/cmn_err.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#include <sys/smb_iconv.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>

/*
 * helpers for nsmb device. Can be moved to the smb_dev.c file.
 */
static void smb_usr_vcspec_free(struct smb_vcspec *spec);

/*
 * Moved the access checks here, just becuase
 * this was a more convenient place to do it
 * than in every function calling this.
 */
static int
smb_usr_ioc2vcspec(struct smbioc_ossn *dp, struct smb_vcspec *spec)
{
	cred_t *cr = CRED();
	uid_t realuid;

	/*
	 * Only superuser can specify a UID or GID.
	 */
	realuid = crgetruid(cr);
	if (dp->ioc_owner == SMBM_ANY_OWNER)
		spec->owner = realuid;
	else {
		/*
		 * Do we have the privilege to create with the
		 * specified uid?  (does uid == cr->cr_uid, etc.)
		 * MacOS would want suser(), or similar here.
		 */
		if (secpolicy_vnode_owner(cr, dp->ioc_owner))
			return (EPERM);
		spec->owner = dp->ioc_owner;
	}
	if (dp->ioc_group == SMBM_ANY_GROUP)
		spec->group = crgetgid(cr);
	else {
		/*
		 * Do we have the privilege to create with the
		 * specified gid?  (one of our groups?)
		 */
		if (groupmember(dp->ioc_group, cr) ||
		    secpolicy_vnode_create_gid(cr) == 0)
			spec->group = dp->ioc_group;
		else
			return (EPERM);
	}

	/*
	 * Valid codesets?  XXX
	 */
	if (dp->ioc_localcs[0] == 0) {
		spec->localcs = "ISO8859-1";
#ifdef NOTYETRESOLVED
		SMBERROR("no local charset ? dp->ioc_localcs[0]: %d\n",
		    dp->ioc_localcs[0]);
		return (EINVAL);
#endif
	} else
		spec->localcs = spec->localcs;

	/*
	 * Check for valid sa_family.
	 * XXX: Just NetBIOS for now.
	 */
	if (dp->ioc_server.sa.sa_family != AF_NETBIOS)
		return (EINVAL);
	spec->sap = &dp->ioc_server.sa;

	if (dp->ioc_local.sa.sa_family) {
		/* If specified, local AF must be the same. */
		if (dp->ioc_local.sa.sa_family !=
		    dp->ioc_server.sa.sa_family)
			return (EINVAL);
		spec->lap = &dp->ioc_local.sa;
	}

	if (dp->ioc_intok) {
		spec->tok = smb_memdupin(dp->ioc_intok, dp->ioc_intoklen);
		if (spec->tok == NULL)
			return (EFAULT);
		spec->toklen = dp->ioc_intoklen;
	}

	spec->srvname = dp->ioc_srvname;
	spec->pass = dp->ioc_password;
	spec->domain = dp->ioc_workgroup;
	spec->username = dp->ioc_user;
	spec->mode = dp->ioc_mode;
	spec->rights = dp->ioc_rights;
	spec->servercs = dp->ioc_servercs;
	spec->optflags = dp->ioc_opt;

	return (0);
}

static void
smb_usr_shspec_free(struct smb_sharespec *sspec)
{
	kmem_free(sspec, sizeof (struct smb_sharespec));
}

static void
smb_usr_vcspec_free(struct smb_vcspec *spec)
{

	if (spec->tok) {
		kmem_free(spec->tok, spec->toklen);
	}
	kmem_free(spec, sizeof (*spec));
}

static int
smb_usr_ioc2sharespec(struct smbioc_oshare *dp, struct smb_sharespec *spec)
{
	bzero(spec, sizeof (*spec));
	spec->name = dp->ioc_share;
	spec->pass = dp->ioc_password;
	spec->mode = dp->ioc_mode;
	spec->rights = dp->ioc_rights;
	spec->owner = dp->ioc_owner;
	spec->group = dp->ioc_group;
	spec->stype = dp->ioc_stype;
	spec->optflags = dp->ioc_opt;
	return (0);
}

int
smb_usr_negotiate(struct smbioc_lookup *dp, struct smb_cred *scred,
	struct smb_vc **vcpp)
{
	struct smb_vc *vcp = NULL;
	struct smb_vcspec *vspec = NULL;
	struct smb_sharespec *sspecp = NULL;
	int error = 0;

	if (dp->ioc_level < SMBL_VC || dp->ioc_level > SMBL_SHARE)
		return (EINVAL);
	vspec = kmem_zalloc(sizeof (struct smb_vcspec), KM_SLEEP);
	error = smb_usr_ioc2vcspec(&dp->ioc_ssn, vspec);
	if (error)
		return (error);
	if (dp->ioc_flags & SMBLK_CREATE)
		vspec->optflags |= SMBVOPT_CREATE;
	if (dp->ioc_level >= SMBL_SHARE) {
		sspecp = kmem_alloc(sizeof (*sspecp), KM_SLEEP);
		error = smb_usr_ioc2sharespec(&dp->ioc_sh, sspecp);
		if (error)
			goto out;
	}
	error = smb_sm_negotiate(vspec, scred, &vcp);
	if (error == 0) {
		*vcpp =  vcp;
		/*
		 * Used to copyout ioc_outtok, outtoklen here,
		 * but that's now in smb_dev. (our caller)
		 *
		 * If this call asked for extended security and
		 * the server does not support it, clear the
		 * flag so the caller knows this.
		 *
		 * XXX: Should just add sv_caps to ioc_ssn,
		 * set the new sv_caps field here, and let
		 * let the copyout of ioc_ssn handle it.
		 */
		if (!(vcp->vc_sopt.sv_caps & SMB_CAP_EXT_SECURITY) &&
		    (dp->ioc_ssn.ioc_opt & SMBVOPT_EXT_SEC)) {
			dp->ioc_ssn.ioc_opt &= ~SMBVOPT_EXT_SEC;
			SMBSDEBUG("turned off extended security");
		}
	}
out:
	smb_usr_vcspec_free(vspec);
	smb_usr_shspec_free(sspecp);
	return (error);
}

int
smb_usr_ssnsetup(struct smbioc_lookup *dp, struct smb_cred *scred,
	struct smb_vc *vcp)
{
	struct smb_vcspec *vspec = NULL;
	int error;

	if (dp->ioc_level < SMBL_VC || dp->ioc_level > SMBL_SHARE)
		return (EINVAL);

	vspec = kmem_zalloc(sizeof (struct smb_vcspec), KM_SLEEP);
	error = smb_usr_ioc2vcspec(&dp->ioc_ssn, vspec);
	if (error)
		goto out;

	error = smb_sm_ssnsetup(vspec, scred, vcp);
	/*
	 * Moved the copyout of ioc_outtok to
	 * smb_dev.c (our caller)
	 */

out:
	smb_usr_vcspec_free(vspec);
	return (error);
}


int
smb_usr_tcon(struct smbioc_lookup *dp, struct smb_cred *scred,
	struct smb_vc *vcp, struct smb_share **sspp)
{
	struct smb_sharespec *sspecp = NULL;
	int error;

	if (dp->ioc_level < SMBL_VC || dp->ioc_level > SMBL_SHARE)
		return (EINVAL);

	if (dp->ioc_level >= SMBL_SHARE) {
		sspecp = kmem_alloc(sizeof (*sspecp), KM_SLEEP);
		error = smb_usr_ioc2sharespec(&dp->ioc_sh, sspecp);
		if (error)
			goto out;
	}
	error = smb_sm_tcon(sspecp, scred, vcp, sspp);

out:
	if (sspecp)
		smb_usr_shspec_free(sspecp);

	return (error);
}

/*
 * Connect to the resource specified by smbioc_ossn structure.
 * It may either find an existing connection or try to establish a new one.
 * If no errors occured smb_vc returned locked and referenced.
 */

int
smb_usr_simplerequest(struct smb_share *ssp, struct smbioc_rq *dp,
	struct smb_cred *scred)
{
	struct smb_rq rq, *rqp = &rq;
	struct mbchain *mbp;
	struct mdchain *mdp;
	char *p;
	size_t wc2;
	u_int8_t wc;
	u_int16_t bc;
	int error;

	switch (dp->ioc_cmd) {
	case SMB_COM_TRANSACTION2:
	case SMB_COM_TRANSACTION2_SECONDARY:
	case SMB_COM_CLOSE_AND_TREE_DISC:
	case SMB_COM_TREE_CONNECT:
	case SMB_COM_TREE_DISCONNECT:
	case SMB_COM_NEGOTIATE:
	case SMB_COM_SESSION_SETUP_ANDX:
	case SMB_COM_LOGOFF_ANDX:
	case SMB_COM_TREE_CONNECT_ANDX:
		return (EPERM);
	}
	error = smb_rq_init(rqp, SSTOCP(ssp), dp->ioc_cmd, scred);
	if (error)
		return (error);
	mbp = &rqp->sr_rq;
	smb_rq_wstart(rqp);
	error = mb_put_mem(mbp, dp->ioc_twords,
	    dp->ioc_twc * 2, MB_MUSER);
	if (error)
		goto bad;
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	error = mb_put_mem(mbp, dp->ioc_tbytes,
	    dp->ioc_tbc, MB_MUSER);
	if (error)
		goto bad;
	smb_rq_bend(rqp);
	error = smb_rq_simple(rqp);
	if (error)
		goto bad;
	mdp = &rqp->sr_rp;
	md_get_uint8(mdp, &wc);
	dp->ioc_rwc = wc;
	wc2 = wc * 2;
	if (wc2 > dp->ioc_rpbufsz) {
		error = EBADRPC;
		goto bad;
	}
	error = md_get_mem(mdp, dp->ioc_rpbuf, wc2, MB_MUSER);
	if (error)
		goto bad;
	md_get_uint16le(mdp, &bc);
	if ((wc2 + bc) > dp->ioc_rpbufsz) {
		error = EBADRPC;
		goto bad;
	}
	dp->ioc_rbc = bc;
	p = dp->ioc_rpbuf;
	error = md_get_mem(mdp, p + wc2, bc, MB_MUSER);
bad:
	dp->ioc_errclass = rqp->sr_errclass;
	dp->ioc_serror = rqp->sr_serror;
	dp->ioc_error = rqp->sr_error;
	smb_rq_done(rqp);
	return (error);

}

static int
smb_cpdatain(struct mbchain *mbp, int len, char *data)
{
	int error;

	if (len == 0)
		return (0);
	error = mb_init(mbp);
	if (error)
		return (error);
	return (mb_put_mem(mbp, data, len, MB_MUSER));
}

int
smb_usr_t2request(struct smb_share *ssp, smbioc_t2rq_t *dp,
	struct smb_cred *scred)
{
	struct smb_t2rq t2, *t2p = &t2;
	struct mdchain *mdp;
	int error, len;

	if (dp->ioc_setupcnt > SMB_MAXSETUPWORDS)
		return (EINVAL);

	t2p = (struct smb_t2rq *)kmem_alloc(sizeof (struct smb_t2rq), KM_SLEEP);
	if (t2p == NULL)
		return (ENOMEM);
	error = smb_t2_init(t2p, SSTOCP(ssp), dp->ioc_setup, dp->ioc_setupcnt,
	    scred);
	if (error)
		return (error);
	len = t2p->t2_setupcount = dp->ioc_setupcnt;
	if (len > 1)
		t2p->t2_setupdata = dp->ioc_setup;
	if (dp->ioc_name) {
		bcopy(dp->ioc_name, t2p->t_name, 128);
		if (t2p->t_name == NULL) {
			error = ENOMEM;
			goto bad;
		}
	}
	t2p->t2_maxscount = 0;
	t2p->t2_maxpcount = dp->ioc_rparamcnt;
	t2p->t2_maxdcount = dp->ioc_rdatacnt;
	error = smb_cpdatain(&t2p->t2_tparam, dp->ioc_tparamcnt,
	    dp->ioc_tparam);
	if (error)
		goto bad;
	error = smb_cpdatain(&t2p->t2_tdata,
	    dp->ioc_tdatacnt, dp->ioc_tdata);
	if (error)
		goto bad;
	error = smb_t2_request(t2p);
	dp->ioc_errclass = t2p->t2_sr_errclass;
	dp->ioc_serror = t2p->t2_sr_serror;
	dp->ioc_error = t2p->t2_sr_error;
	dp->ioc_rpflags2 = t2p->t2_sr_rpflags2;
	if (error)
		goto bad;
	mdp = &t2p->t2_rparam;
	if (mdp->md_top) {
		mblk_t *m = mdp->md_top;
#ifdef lint
		m = m;
#endif
		len = m_fixhdr(mdp->md_top);
		if (len > dp->ioc_rparamcnt) {
			error = EMSGSIZE;
			goto bad;
		}
		dp->ioc_rparamcnt = (ushort_t)len;
		error = md_get_mem(mdp, dp->ioc_rparam,
		    len, MB_MUSER);
		if (error) {
			goto bad;
		}
	} else
		dp->ioc_rparamcnt = 0;
	mdp = &t2p->t2_rdata;
	if (mdp->md_top) {
		mblk_t *m = mdp->md_top;
#ifdef lint
		m = m;
#endif
		len = m_fixhdr(mdp->md_top);
		if (len > dp->ioc_rdatacnt) {
			error = EMSGSIZE;
			goto bad;
		}
		dp->ioc_rdatacnt = (ushort_t)len;
		error = md_get_mem(mdp, dp->ioc_rdata,
		    len, MB_MUSER);
		if (error) {
			goto bad;
		}
	} else
		dp->ioc_rdatacnt = 0;
bad:
	smb_t2_done(t2p);
	return (error);
}

/*
 * Helper for nsmb_ioctl cases
 * SMBIOC_READ, SMBIOC_WRITE
 */
int
smb_usr_rw(struct smb_share *ssp, smbioc_rw_t *rwrq,
    int cmd, struct smb_cred *scred)
{
	struct iovec aiov[1];
	struct uio  auio;
	u_int16_t fh;
	int error;
	uio_rw_t rw;

	switch (cmd) {
	case SMBIOC_READ:
		rw = UIO_READ;
		break;
	case SMBIOC_WRITE:
		rw = UIO_WRITE;
		break;
	default:
		return (ENODEV);
	}

	fh = htoles(rwrq->ioc_fh);

	aiov[0].iov_base = rwrq->ioc_base;
	aiov[0].iov_len = (size_t)rwrq->ioc_cnt;

	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = rwrq->ioc_offset;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_fmode = 0;
	auio.uio_resid = (size_t)rwrq->ioc_cnt;

	error = smb_rwuio(ssp, fh, rw, &auio, scred, 0);

	/*
	 * On return ioc_cnt holds the
	 * number of bytes transferred.
	 */
	rwrq->ioc_cnt -= auio.uio_resid;

	return (error);
}
