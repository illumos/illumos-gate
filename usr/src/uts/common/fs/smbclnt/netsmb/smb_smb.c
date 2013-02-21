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
 * $Id: smb_smb.c,v 1.35.100.2 2005/06/02 00:55:39 lindak Exp $
 */

/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * various SMB requests. Most of the routines merely packs data into mbufs.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <sys/note.h>
#include <sys/cmn_err.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>

#define	STYPE_LEN	8	/* share type strings */

/*
 * Largest size to use with LARGE_READ/LARGE_WRITE.
 * Specs say up to 64k data bytes, but Windows traffic
 * uses 60k... no doubt for some good reason.
 * (Probably to keep 4k block alignment.)
 * XXX: Move to smb.h maybe?
 */
#define	SMB_MAX_LARGE_RW_SIZE (60*1024)

/*
 * Default timeout values, all in seconds.
 * Make these tunable (only via mdb for now).
 */
int smb_timo_notice = 15;
int smb_timo_default = 30;	/* was SMB_DEFRQTIMO */
int smb_timo_open = 45;
int smb_timo_read = 45;
int smb_timo_write = 60;	/* was SMBWRTTIMO */
int smb_timo_append = 90;

static int smb_smb_read(struct smb_share *ssp, uint16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);
static int smb_smb_write(struct smb_share *ssp, uint16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);

static int smb_smb_readx(struct smb_share *ssp, uint16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);
static int smb_smb_writex(struct smb_share *ssp, uint16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);

/*
 * Get the string representation of a share "use" type,
 * as needed for the "service" in tree connect.
 */
static const char *
smb_share_typename(uint32_t stype)
{
	const char *p;

	switch (stype) {
	case STYPE_DISKTREE:
		p = "A:";
		break;
	case STYPE_PRINTQ:
		p = "LPT1:";
		break;
	case STYPE_DEVICE:
		p = "COMM";
		break;
	case STYPE_IPC:
		p = "IPC";
		break;
	case STYPE_UNKNOWN:
	default:
		p = "?????";
		break;
	}
	return (p);
}

/*
 * Parse a share type name (inverse of above)
 */
static uint32_t
smb_share_parsetype(char *name)
{
	int stype;

	switch (*name) {
	case 'A':	/* A: */
		stype = STYPE_DISKTREE;
		break;
	case 'C':	/* COMM */
		stype = STYPE_DEVICE;
		break;
	case 'I':	/* IPC */
		stype = STYPE_IPC;
		break;
	case 'L':	/* LPT: */
		stype = STYPE_PRINTQ;
		break;
	default:
		stype = STYPE_UNKNOWN;
		break;
	}
	return (stype);
}

int
smb_smb_treeconnect(struct smb_share *ssp, struct smb_cred *scred)
{
	struct smb_vc *vcp;
	struct smb_rq *rqp = NULL;
	struct mbchain *mbp;
	struct mdchain *mdp;
	const char *tname;
	char *pbuf, *unc_name = NULL;
	int error, tlen, plen, unc_len;
	uint16_t bcnt, options;
	uint8_t wc;
	char stype_str[STYPE_LEN];

	vcp = SSTOVC(ssp);

	/*
	 * Make this a "VC-level" request, so it will have
	 * rqp->sr_share == NULL, and smb_iod_sendrq()
	 * will send it with TID = SMB_TID_UNKNOWN
	 *
	 * This also serves to bypass the wait for
	 * share state changes, which this call is
	 * trying to carry out.
	 */
	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_TREE_CONNECT_ANDX,
	    scred, &rqp);
	if (error)
		return (error);

	/*
	 * Build the UNC name, i.e. "//server/share"
	 * but with backslashes of course.
	 * size math: three slashes, one null.
	 */
	unc_len = 4 + strlen(vcp->vc_srvname) + strlen(ssp->ss_name);
	unc_name = kmem_alloc(unc_len, KM_SLEEP);
	(void) snprintf(unc_name, unc_len, "\\\\%s\\%s",
	    vcp->vc_srvname, ssp->ss_name);
	SMBSDEBUG("unc_name: \"%s\"", unc_name);


	/*
	 * Share-level password (pre-computed in user-space)
	 * MS-SMB 2.2.6 says this should be null terminated,
	 * and the pw length includes the null.
	 */
	pbuf = ssp->ss_pass;
	plen = strlen(pbuf) + 1;

	/*
	 * Build the request.
	 */
	mbp = &rqp->sr_rq;
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);
	mb_put_uint8(mbp, 0);
	mb_put_uint16le(mbp, 0);
	mb_put_uint16le(mbp, 0);		/* Flags */
	mb_put_uint16le(mbp, plen);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);

	/* Tree connect password, if any */
	error = mb_put_mem(mbp, pbuf, plen, MB_MSYSTEM);
	if (error)
		goto out;

	/* UNC resource name */
	error = smb_put_dstring(mbp, vcp, unc_name, SMB_CS_NONE);
	if (error)
		goto out;

	/*
	 * Put the type string (always ASCII),
	 * including the null.
	 */
	tname = smb_share_typename(ssp->ss_use);
	tlen = strlen(tname) + 1;
	error = mb_put_mem(mbp, tname, tlen, MB_MSYSTEM);
	if (error)
		goto out;

	smb_rq_bend(rqp);

	/*
	 * Run the request.
	 *
	 * Using NOINTR_RECV because we don't want to risk
	 * missing a successful tree connect response,
	 * which would "leak" Tree IDs.
	 */
	rqp->sr_flags |= SMBR_NOINTR_RECV;
	error = smb_rq_simple(rqp);
	SMBSDEBUG("%d\n", error);
	if (error) {
		/*
		 * If we get the server name wrong, i.e. due to
		 * mis-configured name services, this will be
		 * NT_STATUS_DUPLICATE_NAME.  Log this error.
		 */
		SMBERROR("(%s) failed, status=0x%x",
		    unc_name, rqp->sr_error);
		goto out;
	}

	/*
	 * Parse the TCON response
	 */
	smb_rq_getreply(rqp, &mdp);
	md_get_uint8(mdp, &wc);
	if (wc != 3 && wc != 7) {
		error = EBADRPC;
		goto out;
	}
	md_get_uint16le(mdp, NULL);		/* AndX cmd */
	md_get_uint16le(mdp, NULL);		/* AndX off */
	md_get_uint16le(mdp, &options);		/* option bits (DFS, search) */
	if (wc == 7) {
		md_get_uint32le(mdp, NULL);	/* MaximalShareAccessRights */
		md_get_uint32le(mdp, NULL);	/* GuestMaximalShareAcc... */
	}
	error = md_get_uint16le(mdp, &bcnt);	/* byte count */
	if (error)
		goto out;

	/*
	 * Get the returned share type string, i.e. "IPC" or whatever.
	 * (See smb_share_typename, smb_share_parsetype).  If we get
	 * an error reading the type, just say STYPE_UNKNOWN.
	 */
	tlen = STYPE_LEN;
	bzero(stype_str, tlen--);
	if (tlen > bcnt)
		tlen = bcnt;
	md_get_mem(mdp, stype_str, tlen, MB_MSYSTEM);
	stype_str[tlen] = '\0';
	ssp->ss_type = smb_share_parsetype(stype_str);

	/* Success! */
	SMB_SS_LOCK(ssp);
	ssp->ss_tid = rqp->sr_rptid;
	ssp->ss_vcgenid = vcp->vc_genid;
	ssp->ss_options = options;
	ssp->ss_flags |= SMBS_CONNECTED;
	SMB_SS_UNLOCK(ssp);

out:
	if (unc_name)
		kmem_free(unc_name, unc_len);
	smb_rq_done(rqp);
	return (error);
}

int
smb_smb_treedisconnect(struct smb_share *ssp, struct smb_cred *scred)
{
	struct smb_vc *vcp;
	struct smb_rq *rqp;
	int error;

	if (ssp->ss_tid == SMB_TID_UNKNOWN)
		return (0);

	/*
	 * Build this as a "VC-level" request, so it will
	 * avoid testing the _GONE flag on the share,
	 * which has already been set at this point.
	 * Add the share pointer "by hand" below, so
	 * smb_iod_sendrq will plug in the TID.
	 */
	vcp = SSTOVC(ssp);
	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_TREE_DISCONNECT, scred, &rqp);
	if (error)
		return (error);
	rqp->sr_share = ssp; /* by hand */

	smb_rq_wstart(rqp);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);

	/*
	 * Run this with a relatively short timeout. (5 sec.)
	 * We don't really care about the result here, but we
	 * do need to make sure we send this out, or we could
	 * "leak" active tree IDs on interrupt or timeout.
	 * The NOINTR_SEND flag makes this request immune to
	 * interrupt or timeout until the send is done.
	 * Also, don't reconnect for this, of course!
	 */
	rqp->sr_flags |= (SMBR_NOINTR_SEND | SMBR_NORECONNECT);
	error = smb_rq_simple_timed(rqp, 5);
	SMBSDEBUG("%d\n", error);
	smb_rq_done(rqp);
	ssp->ss_tid = SMB_TID_UNKNOWN;
	return (error);
}

/*
 * Modern create/open of file or directory.
 */
int
smb_smb_ntcreate(
	struct smb_share *ssp,
	struct mbchain	*name_mb,
	uint32_t cr_flags,	/* create flags */
	uint32_t req_acc,	/* requested access */
	uint32_t efa,		/* ext. file attrs (DOS attr +) */
	uint32_t share_acc,
	uint32_t open_disp,	/* open disposition */
	uint32_t createopt,	/* NTCREATEX_OPTIONS_ */
	uint32_t impersonate,	/* NTCREATEX_IMPERSONATION_... */
	struct smb_cred *scrp,
	uint16_t *fidp,		/* returned FID */
	uint32_t *cr_act_p,	/* optional create action */
	struct smbfattr *fap)	/* optional attributes */
{
	struct smb_rq rq, *rqp = &rq;
	struct smb_vc *vcp = SSTOVC(ssp);
	struct mbchain *mbp;
	struct mdchain *mdp;
	struct smbfattr fa;
	uint64_t llongint;
	uint32_t longint, createact;
	uint16_t fid;
	uint8_t wc;
	int error;

	bzero(&fa, sizeof (fa));
	error = smb_rq_init(rqp, SSTOCP(ssp), SMB_COM_NT_CREATE_ANDX, scrp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);

	/* Word parameters */
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);	/* secondary command */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, 0);	/* offset to next command (none) */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, name_mb->mb_count);
	mb_put_uint32le(mbp, cr_flags);	/* NTCREATEX_FLAGS_* */
	mb_put_uint32le(mbp, 0);	/* FID - basis for path if not root */
	mb_put_uint32le(mbp, req_acc);
	mb_put_uint64le(mbp, 0);	/* "initial allocation size" */
	mb_put_uint32le(mbp, efa);
	mb_put_uint32le(mbp, share_acc);
	mb_put_uint32le(mbp, open_disp);
	mb_put_uint32le(mbp, createopt);
	mb_put_uint32le(mbp, impersonate);
	mb_put_uint8(mbp, 0);   /* security flags (?) */
	smb_rq_wend(rqp);

	/*
	 * Byte parameters: Just the path name, aligned.
	 * Note: mb_put_mbuf consumes mb_top, so clear it.
	 */
	smb_rq_bstart(rqp);
	if (SMB_UNICODE_STRINGS(vcp))
		mb_put_padbyte(mbp);
	mb_put_mbuf(mbp, name_mb->mb_top);
	bzero(name_mb, sizeof (*name_mb));
	smb_rq_bend(rqp);

	/*
	 * Don't want to risk missing a successful
	 * open response, or we could "leak" FIDs.
	 */
	rqp->sr_flags |= SMBR_NOINTR_RECV;
	error = smb_rq_simple_timed(rqp, smb_timo_open);
	if (error)
		goto done;
	smb_rq_getreply(rqp, &mdp);
	/*
	 * spec says 26 for word count, but 34 words are defined
	 * and observed from win2000
	 */
	error = md_get_uint8(mdp, &wc);
	if (error)
		goto done;
	if (wc != 26 && wc < 34) {
		error = EBADRPC;
		goto done;
	}
	md_get_uint8(mdp, NULL);		/* secondary cmd */
	md_get_uint8(mdp, NULL);		/* mbz */
	md_get_uint16le(mdp, NULL);		/* andxoffset */
	md_get_uint8(mdp, NULL);		/* oplock lvl granted */
	md_get_uint16le(mdp, &fid);		/* file ID */
	md_get_uint32le(mdp, &createact);	/* create_action */

	md_get_uint64le(mdp, &llongint);	/* creation time */
	smb_time_NT2local(llongint, &fa.fa_createtime);
	md_get_uint64le(mdp, &llongint);	/* access time */
	smb_time_NT2local(llongint, &fa.fa_atime);
	md_get_uint64le(mdp, &llongint);	/* write time */
	smb_time_NT2local(llongint, &fa.fa_mtime);
	md_get_uint64le(mdp, &llongint);	/* change time */
	smb_time_NT2local(llongint, &fa.fa_ctime);

	md_get_uint32le(mdp, &longint);		/* attributes */
	fa.fa_attr = longint;
	md_get_uint64le(mdp, &llongint);	/* allocation size */
	fa.fa_allocsz = llongint;
	md_get_uint64le(mdp, &llongint);	/* EOF position */
	fa.fa_size = llongint;

	error = md_get_uint16le(mdp, NULL);	/* file type */
	/* other stuff we don't care about */

done:
	smb_rq_done(rqp);
	if (error)
		return (error);

	*fidp = fid;
	if (cr_act_p)
		*cr_act_p = createact;
	if (fap)
		*fap = fa; /* struct copy */

	return (0);
}

int
smb_smb_close(struct smb_share *ssp, uint16_t fid, struct timespec *mtime,
	struct smb_cred *scrp)
{
	struct smb_rq rq, *rqp = &rq;
	struct mbchain *mbp;
	long time;
	int error;

	error = smb_rq_init(rqp, SSTOCP(ssp), SMB_COM_CLOSE, scrp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, fid);
	if (mtime) {
		int sv_tz = SSTOVC(ssp)->vc_sopt.sv_tz;
		smb_time_local2server(mtime, sv_tz, &time);
	} else {
		time = 0;
	}
	mb_put_uint32le(mbp, time);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);

	/* Make sure we send, but only if already connected */
	rqp->sr_flags |= (SMBR_NOINTR_SEND | SMBR_NORECONNECT);
	error = smb_rq_simple(rqp);
	smb_rq_done(rqp);
	return (error);
}

int
smb_smb_open_prjob(
	struct smb_share *ssp,
	char	*title,
	uint16_t setuplen,
	uint16_t mode,
	struct smb_cred *scrp,
	uint16_t *fidp)
{
	struct smb_rq rq, *rqp = &rq;
	struct smb_vc *vcp = SSTOVC(ssp);
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint16_t fid;
	uint8_t wc;
	int error;

	error = smb_rq_init(rqp, SSTOCP(ssp), SMB_COM_OPEN_PRINT_FILE, scrp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);

	/* Word parameters */
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, setuplen);
	mb_put_uint16le(mbp, mode);
	smb_rq_wend(rqp);

	/*
	 * Byte parameters: Just the title
	 */
	smb_rq_bstart(rqp);
	mb_put_uint8(mbp, SMB_DT_ASCII);
	error = smb_put_dstring(mbp, vcp, title, SMB_CS_NONE);
	smb_rq_bend(rqp);
	if (error)
		goto done;

	/*
	 * Don't want to risk missing a successful
	 * open response, or we could "leak" FIDs.
	 */
	rqp->sr_flags |= SMBR_NOINTR_RECV;
	error = smb_rq_simple_timed(rqp, smb_timo_open);
	if (error)
		goto done;

	smb_rq_getreply(rqp, &mdp);
	error = md_get_uint8(mdp, &wc);
	if (error || wc < 1) {
		error = EBADRPC;
		goto done;
	}
	error = md_get_uint16le(mdp, &fid);

done:
	smb_rq_done(rqp);
	if (error)
		return (error);

	*fidp = fid;
	return (0);
}

/*
 * Like smb_smb_close, but for print shares.
 */
int
smb_smb_close_prjob(struct smb_share *ssp, uint16_t fid,
	struct smb_cred *scrp)
{
	struct smb_rq rq, *rqp = &rq;
	struct mbchain *mbp;
	int error;

	error = smb_rq_init(rqp, SSTOCP(ssp),
	    SMB_COM_CLOSE_PRINT_FILE, scrp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, fid);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);

	/* Make sure we send but only if already connected */
	rqp->sr_flags |= (SMBR_NOINTR_SEND | SMBR_NORECONNECT);
	error = smb_rq_simple(rqp);
	smb_rq_done(rqp);
	return (error);
}

/*
 * Common function for read/write with UIO.
 * Called by netsmb smb_usr_rw,
 *  smbfs_readvnode, smbfs_writevnode
 */
int
smb_rwuio(struct smb_share *ssp, uint16_t fid, uio_rw_t rw,
	uio_t *uiop, smb_cred_t *scred, int timo)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	ssize_t  save_resid;
	uint32_t len, rlen, maxlen;
	int error = 0;
	int (*iofun)(struct smb_share *, uint16_t, uint32_t *,
	    uio_t *, smb_cred_t *, int);

	/*
	 * Determine which function to use,
	 * and the transfer size per call.
	 */
	if (SMB_DIALECT(vcp) >= SMB_DIALECT_NTLM0_12) {
		/*
		 * Using NT LM 0.12, so readx, writex.
		 * Make sure we can represent the offset.
		 */
		if ((vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_FILES) == 0 &&
		    (uiop->uio_loffset + uiop->uio_resid) > UINT32_MAX)
			return (EFBIG);

		if (rw == UIO_READ) {
			iofun = smb_smb_readx;
			if (vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_READX)
				maxlen = SMB_MAX_LARGE_RW_SIZE;
			else
				maxlen = vcp->vc_rxmax;
		} else { /* UIO_WRITE */
			iofun = smb_smb_writex;
			if (vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_WRITEX)
				maxlen = SMB_MAX_LARGE_RW_SIZE;
			else
				maxlen = vcp->vc_wxmax;
		}
	} else {
		/*
		 * Using the old SMB_READ and SMB_WRITE so
		 * we're limited to 32-bit offsets, etc.
		 * XXX: Someday, punt the old dialects.
		 */
		if ((uiop->uio_loffset + uiop->uio_resid) > UINT32_MAX)
			return (EFBIG);

		if (rw == UIO_READ) {
			iofun = smb_smb_read;
			maxlen = vcp->vc_rxmax;
		} else { /* UIO_WRITE */
			iofun = smb_smb_write;
			maxlen = vcp->vc_wxmax;
		}
	}

	save_resid = uiop->uio_resid;
	while (uiop->uio_resid > 0) {
		/* Lint: uio_resid may be 64-bits */
		rlen = len = (uint32_t)min(maxlen, uiop->uio_resid);
		error = (*iofun)(ssp, fid, &rlen, uiop, scred, timo);

		/*
		 * Note: the iofun called uio_update, so
		 * not doing that here as one might expect.
		 *
		 * Quit the loop either on error, or if we
		 * transferred less then requested.
		 */
		if (error || (rlen < len))
			break;

		timo = 0; /* only first I/O should wait */
	}
	if (error && (save_resid != uiop->uio_resid)) {
		/*
		 * Stopped on an error after having
		 * successfully transferred data.
		 * Suppress this error.
		 */
		SMBSDEBUG("error %d suppressed\n", error);
		error = 0;
	}

	return (error);
}

static int
smb_smb_readx(struct smb_share *ssp, uint16_t fid, uint32_t *lenp,
	uio_t *uiop, smb_cred_t *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;
	uint32_t offlo, offhi, rlen;
	uint16_t lenhi, lenlo, off, doff;
	uint8_t wc;

	lenhi = (uint16_t)(*lenp >> 16);
	lenlo = (uint16_t)*lenp;
	offhi = (uint32_t)(uiop->uio_loffset >> 32);
	offlo = (uint32_t)uiop->uio_loffset;

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_READ_ANDX, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);	/* no secondary command */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, 0);	/* offset to secondary */
	mb_put_uint16le(mbp, fid);
	mb_put_uint32le(mbp, offlo);	/* offset (low part) */
	mb_put_uint16le(mbp, lenlo);	/* MaxCount */
	mb_put_uint16le(mbp, 1);	/* MinCount */
					/* (only indicates blocking) */
	mb_put_uint32le(mbp, lenhi);	/* MaxCountHigh */
	mb_put_uint16le(mbp, lenlo);	/* Remaining ("obsolete") */
	mb_put_uint32le(mbp, offhi);	/* offset (high part) */
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);

	if (timo == 0)
		timo = smb_timo_read;
	error = smb_rq_simple_timed(rqp, timo);
	if (error)
		goto out;

	smb_rq_getreply(rqp, &mdp);
	error = md_get_uint8(mdp, &wc);
	if (error)
		goto out;
	if (wc != 12) {
		error = EBADRPC;
		goto out;
	}
	md_get_uint8(mdp, NULL);
	md_get_uint8(mdp, NULL);
	md_get_uint16le(mdp, NULL);
	md_get_uint16le(mdp, NULL);
	md_get_uint16le(mdp, NULL);	/* data compaction mode */
	md_get_uint16le(mdp, NULL);
	md_get_uint16le(mdp, &lenlo);	/* data len ret. */
	md_get_uint16le(mdp, &doff);	/* data offset */
	md_get_uint16le(mdp, &lenhi);
	rlen = (lenhi << 16) | lenlo;
	md_get_mem(mdp, NULL, 4 * 2, MB_MSYSTEM);
	error = md_get_uint16le(mdp, NULL);	/* ByteCount */
	if (error)
		goto out;
	/*
	 * Does the data offset indicate padding?
	 * The current offset is a constant, found
	 * by counting the md_get_ calls above.
	 */
	off = SMB_HDRLEN + 3 + (12 * 2); /* =59 */
	if (doff > off)	/* pad byte(s)? */
		md_get_mem(mdp, NULL, doff - off, MB_MSYSTEM);
	if (rlen == 0) {
		*lenp = rlen;
		goto out;
	}
	/* paranoid */
	if (rlen > *lenp) {
		SMBSDEBUG("bad server! rlen %d, len %d\n",
		    rlen, *lenp);
		rlen = *lenp;
	}
	error = md_get_uio(mdp, uiop, rlen);
	if (error)
		goto out;

	/* Success */
	*lenp = rlen;

out:
	smb_rq_done(rqp);
	return (error);
}

static int
smb_smb_writex(struct smb_share *ssp, uint16_t fid, uint32_t *lenp,
	uio_t *uiop, smb_cred_t *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;
	uint32_t offlo, offhi, rlen;
	uint16_t lenhi, lenlo;
	uint8_t wc;

	lenhi = (uint16_t)(*lenp >> 16);
	lenlo = (uint16_t)*lenp;
	offhi = (uint32_t)(uiop->uio_loffset >> 32);
	offlo = (uint32_t)uiop->uio_loffset;

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_WRITE_ANDX, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);	/* no secondary command */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, 0);	/* offset to secondary */
	mb_put_uint16le(mbp, fid);
	mb_put_uint32le(mbp, offlo);	/* offset (low part) */
	mb_put_uint32le(mbp, 0);	/* MBZ (timeout) */
	mb_put_uint16le(mbp, 0);	/* !write-thru */
	mb_put_uint16le(mbp, 0);
	mb_put_uint16le(mbp, lenhi);
	mb_put_uint16le(mbp, lenlo);
	mb_put_uint16le(mbp, 64);	/* data offset from header start */
	mb_put_uint32le(mbp, offhi);	/* offset (high part) */
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);

	mb_put_uint8(mbp, 0);	/* pad byte */
	error = mb_put_uio(mbp, uiop, *lenp);
	if (error)
		goto out;
	smb_rq_bend(rqp);
	if (timo == 0)
		timo = smb_timo_write;
	error = smb_rq_simple_timed(rqp, timo);
	if (error)
		goto out;
	smb_rq_getreply(rqp, &mdp);
	error = md_get_uint8(mdp, &wc);
	if (error)
		goto out;
	if (wc != 6) {
		error = EBADRPC;
		goto out;
	}
	md_get_uint8(mdp, NULL);	/* andx cmd */
	md_get_uint8(mdp, NULL);	/* reserved */
	md_get_uint16le(mdp, NULL);	/* andx offset */
	md_get_uint16le(mdp, &lenlo);	/* data len ret. */
	md_get_uint16le(mdp, NULL);	/* remaining */
	error = md_get_uint16le(mdp, &lenhi);
	if (error)
		goto out;

	/* Success */
	rlen = (lenhi << 16) | lenlo;
	*lenp = rlen;

out:
	smb_rq_done(rqp);
	return (error);
}

static int
smb_smb_read(struct smb_share *ssp, uint16_t fid, uint32_t *lenp,
	uio_t *uiop, smb_cred_t *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;
	uint32_t off32;
	uint16_t bc, cnt, dlen, rcnt, todo;
	uint8_t wc;

	ASSERT(uiop->uio_loffset <= UINT32_MAX);
	off32 = (uint32_t)uiop->uio_loffset;
	ASSERT(*lenp <= UINT16_MAX);
	cnt = (uint16_t)*lenp;
	/* This next is an "estimate" of planned reads. */
	todo = (uint16_t)min(uiop->uio_resid, UINT16_MAX);

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_READ, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, fid);
	mb_put_uint16le(mbp, cnt);
	mb_put_uint32le(mbp, off32);
	mb_put_uint16le(mbp, todo);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);

	if (timo == 0)
		timo = smb_timo_read;
	error = smb_rq_simple_timed(rqp, timo);
	if (error)
		goto out;
	smb_rq_getreply(rqp, &mdp);
	error = md_get_uint8(mdp, &wc);
	if (error)
		goto out;
	if (wc != 5) {
		error = EBADRPC;
		goto out;
	}
	md_get_uint16le(mdp, &rcnt);		/* ret. count */
	md_get_mem(mdp, NULL, 4 * 2, MB_MSYSTEM);  /* res. */
	md_get_uint16le(mdp, &bc);		/* byte count */
	md_get_uint8(mdp, NULL);		/* buffer format */
	error = md_get_uint16le(mdp, &dlen);	/* data len */
	if (error)
		goto out;
	if (dlen < rcnt) {
		SMBSDEBUG("oops: dlen=%d rcnt=%d\n",
		    (int)dlen, (int)rcnt);
		rcnt = dlen;
	}
	if (rcnt == 0) {
		*lenp = 0;
		goto out;
	}
	/* paranoid */
	if (rcnt > cnt) {
		SMBSDEBUG("bad server! rcnt %d, cnt %d\n",
		    (int)rcnt, (int)cnt);
		rcnt = cnt;
	}
	error = md_get_uio(mdp, uiop, (int)rcnt);
	if (error)
		goto out;

	/* success */
	*lenp = (int)rcnt;

out:
	smb_rq_done(rqp);
	return (error);
}

static int
smb_smb_write(struct smb_share *ssp, uint16_t fid, uint32_t *lenp,
	uio_t *uiop, smb_cred_t *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;
	uint32_t off32;
	uint16_t cnt, rcnt, todo;
	uint8_t wc;

	ASSERT(uiop->uio_loffset <= UINT32_MAX);
	off32 = (uint32_t)uiop->uio_loffset;
	ASSERT(*lenp <= UINT16_MAX);
	cnt = (uint16_t)*lenp;
	/* This next is an "estimate" of planned writes. */
	todo = (uint16_t)min(uiop->uio_resid, UINT16_MAX);

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_WRITE, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, fid);
	mb_put_uint16le(mbp, cnt);
	mb_put_uint32le(mbp, off32);
	mb_put_uint16le(mbp, todo);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	mb_put_uint8(mbp, SMB_DT_DATA);
	mb_put_uint16le(mbp, cnt);

	error = mb_put_uio(mbp, uiop, *lenp);
	if (error)
		goto out;
	smb_rq_bend(rqp);
	if (timo == 0)
		timo = smb_timo_write;
	error = smb_rq_simple_timed(rqp, timo);
	if (error)
		goto out;
	smb_rq_getreply(rqp, &mdp);
	error = md_get_uint8(mdp, &wc);
	if (error)
		goto out;
	if (wc != 1) {
		error = EBADRPC;
		goto out;
	}
	error = md_get_uint16le(mdp, &rcnt);
	if (error)
		goto out;
	*lenp = rcnt;

out:
	smb_rq_done(rqp);
	return (error);
}


static u_int32_t	smbechoes = 0;

int
smb_smb_echo(struct smb_vc *vcp, struct smb_cred *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_ECHO, scred, &rqp);
	if (error)
		return (error);
	mbp = &rqp->sr_rq;
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, 1); /* echo count */
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	mb_put_uint32le(mbp, atomic_inc_32_nv(&smbechoes));
	smb_rq_bend(rqp);
	/*
	 * Note: the IOD calls this, so
	 * this request must not wait for
	 * connection state changes, etc.
	 */
	rqp->sr_flags |= SMBR_NORECONNECT;
	error = smb_rq_simple_timed(rqp, timo);
	SMBSDEBUG("%d\n", error);
	smb_rq_done(rqp);
	return (error);
}
