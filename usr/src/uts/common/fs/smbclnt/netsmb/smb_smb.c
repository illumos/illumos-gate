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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#ifdef APPLE
#include <sys/smb_apple.h>
#include <sys/utfconv.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>

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

/*
 * Debug/test feature to disable NTMLv2.
 * Set this to zero to skip NTLMv2
 */
int nsmb_enable_ntlmv2 = 1;

static int smb_smb_read(struct smb_share *ssp, u_int16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);
static int smb_smb_write(struct smb_share *ssp, u_int16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);

static int smb_smb_readx(struct smb_share *ssp, u_int16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);
static int smb_smb_writex(struct smb_share *ssp, u_int16_t fid,
	uint32_t *lenp, uio_t *uiop, smb_cred_t *scred, int timo);

struct smb_dialect {
	int		d_id;
	const char	*d_name;
};

smb_unichar smb_unieol = 0;

static struct smb_dialect smb_dialects[] = {
	{SMB_DIALECT_CORE,	"PC NETWORK PROGRAM 1.0"},
	{SMB_DIALECT_LANMAN1_0,	"LANMAN1.0"},
	{SMB_DIALECT_LANMAN2_0,	"LM1.2X002"},
	{SMB_DIALECT_LANMAN2_1,	"LANMAN2.1"},
	{SMB_DIALECT_NTLM0_12,	"NT LM 0.12"},
	{-1,			NULL}
};

#define	SMB_DIALECT_MAX \
	(sizeof (smb_dialects) / sizeof (struct smb_dialect) - 2)

/*
 * Number of seconds between 1970 and 1601 year
 */
const u_int64_t DIFF1970TO1601 = 11644473600ULL;

void
smb_time_local2server(struct timespec *tsp, int tzoff, long *seconds)
{
	/*
	 * XXX - what if we connected to the server when it was in
	 * daylight savings/summer time and we've subsequently switched
	 * to standard time, or vice versa, so that the time zone
	 * offset we got from the server is now wrong?
	 */
	*seconds = tsp->tv_sec - tzoff * 60;
	/* - tz.tz_minuteswest * 60 - (wall_cmos_clock ? adjkerntz : 0) */
}

void
smb_time_server2local(ulong_t seconds, int tzoff, struct timespec *tsp)
{
	/*
	 * XXX - what if we connected to the server when it was in
	 * daylight savings/summer time and we've subsequently switched
	 * to standard time, or vice versa, so that the time zone
	 * offset we got from the server is now wrong?
	 */
	tsp->tv_sec = seconds + tzoff * 60;
	    /* + tz.tz_minuteswest * 60 + (wall_cmos_clock ? adjkerntz : 0); */
	tsp->tv_nsec = 0;
}

/*
 * Time from server comes as UTC, so no need to use tz
 */
/*ARGSUSED*/
void
smb_time_NT2local(u_int64_t nsec, int tzoff, struct timespec *tsp)
{
	smb_time_server2local(nsec / 10000000 - DIFF1970TO1601, 0, tsp);
}

/*ARGSUSED*/
void
smb_time_local2NT(struct timespec *tsp, int tzoff, u_int64_t *nsec)
{
	long seconds;

	smb_time_local2server(tsp, 0, &seconds);
	*nsec = (((u_int64_t)(seconds) & ~1) + DIFF1970TO1601) *
	    (u_int64_t)10000000;
}

#if defined(NOICONVSUPPORT) || defined(lint)
extern int iconv_open(const char *to, const char *from, void **handle);
extern int iconv_close(void *handle);
#endif

int
smb_smb_negotiate(struct smb_vc *vcp, struct smb_cred *scred)
{
	struct smb_dialect *dp;
	struct smb_sopt *sp = NULL;
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	u_int8_t wc, stime[8], sblen;
	u_int16_t dindex, tw, tw1, swlen, bc;
	int error;
	int unicode = 0;
	char *servercs;
	void *servercshandle = NULL;
	void *localcshandle = NULL;
	int negotiated_signing = 0;
	u_int16_t toklen;

	/*
	 * We set various flags below to keep track of
	 * interesting things we learn from negotiation.
	 * Clear all the flags except these two, which
	 * are operational rather than protocol info.
	 */
	SMB_VC_LOCK(vcp);
	vcp->vc_flags &= (SMBV_GONE | SMBV_RECONNECTING);
	SMB_VC_UNLOCK(vcp);

	/*
	 * Now vc_hflags and vc_hflags2.  Careful with this:
	 * Leave SMB_FLAGS2_UNICODE off so mb_put_dstring
	 * marshalls the dialect strings in plain ascii.
	 * We'll turn that on below, if appropriate.
	 *
	 * Note: These flags are marshalled into the request
	 * when we call smb_rq_alloc, so changing them after
	 * this point does not affect THIS request.
	 */
	vcp->vc_hflags = SMB_FLAGS_CASELESS;
	vcp->vc_hflags2 = (SMB_FLAGS2_ERR_STATUS |
	    SMB_FLAGS2_KNOWS_LONG_NAMES);

	/* User-level may ask for extended security. */
	if (vcp->vc_vopt & SMBVOPT_EXT_SEC)
		vcp->vc_hflags2 |= SMB_FLAGS2_EXT_SEC;

	/* Also clear any old key (for reconnect) */
	if (vcp->vc_mackey != NULL) {
		kmem_free(vcp->vc_mackey, vcp->vc_mackeylen);
		vcp->vc_mackey = NULL;
		vcp->vc_mackeylen = 0;
		vcp->vc_seqno = 0;
	}

	sp = &vcp->vc_sopt;
	bzero(sp, sizeof (struct smb_sopt));
	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_NEGOTIATE, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	for (dp = smb_dialects; dp->d_id != -1; dp++) {
		mb_put_uint8(mbp, SMB_DT_DIALECT);
		smb_put_dstring(mbp, vcp, dp->d_name, SMB_CS_NONE);
	}
	smb_rq_bend(rqp);

	/*
	 * This request should not wait for
	 * connection state changes, etc.
	 */
	rqp->sr_flags |= SMBR_INTERNAL;
	error = smb_rq_simple(rqp);
	SMBSDEBUG("%d\n", error);
	if (error)
		goto bad;

	smb_rq_getreply(rqp, &mdp);
	do {
		error = md_get_uint8(mdp, &wc);
		if (error)
			break;
		error = md_get_uint16le(mdp, &dindex);
		if (error)
			break;
		error = EBADRPC;
		if (dindex > SMB_DIALECT_MAX) {
			SMBERROR(
			    "Don't know how to talk with server %s (%d)\n",
			    vcp->vc_srvname, dindex);
			break;
		}
		dp = smb_dialects + dindex;
		if (dindex < SMB_DIALECT_MAX) {
			SMBERROR(
			    "Server %s negotiated old dialect (%s)\n",
			    vcp->vc_srvname, dp->d_name);
		}
		sp->sv_proto = dp->d_id;
		SMBSDEBUG("Dialect %s (%d, %d)\n", dp->d_name, dindex, wc);
		if (dp->d_id >= SMB_DIALECT_NTLM0_12) {
			if (wc != 17)
				break;
			md_get_uint8(mdp, &sp->sv_sm);
			md_get_uint16le(mdp, &sp->sv_maxmux);
			md_get_uint16le(mdp, &sp->sv_maxvcs);
			md_get_uint32le(mdp, &sp->sv_maxtx);
			md_get_uint32le(mdp, &sp->sv_maxraw);
			md_get_uint32le(mdp, &sp->sv_skey);
			md_get_uint32le(mdp, &sp->sv_caps);
			md_get_mem(mdp, (char *)stime, 8, MB_MSYSTEM);
			md_get_uint16le(mdp, (u_int16_t *)&sp->sv_tz);
			md_get_uint8(mdp, &sblen);
			error = md_get_uint16le(mdp, &bc);
			if (error)
				break;

			/* BEGIN CSTYLED */
	/*
	 * Will we do SMB signing?  Or block the connection?
	 * The table below describes this logic.  References:
	 * [Windows Server Protocols: MS-SMB, sec. 3.2.4.2.3]
	 * http://msdn.microsoft.com/en-us/library/cc212511.aspx
	 * http://msdn.microsoft.com/en-us/library/cc212929.aspx
	 *
	 * Srv/Cli     | Required | Enabled    | If Required | Disabled
	 * ------------+----------+------------+-------------+-----------
	 * Required    | Signed   | Signed     | Signed      | Blocked [1]
	 * ------------+----------+------------+-------------+-----------
	 * Enabled     | Signed   | Signed     | Not Signed  | Not Signed
	 * ------------+----------+------------+-------------+-----------
	 * If Required | Signed   | Not Signed | Not Signed  | Not Signed
	 * ------------+----------+------------+-------------+-----------
	 * Disabled    | Blocked  | Not Signed | Not Signed  | Not Signed
	 *
	 * [1] Like Windows 2003 and later, we don't really implement
	 * the "Disabled" setting.  Instead we implement "If Required",
	 * so we always sign if the server requires signing.
	 */
			/* END CSTYLED */

			if (sp->sv_sm & SMB_SM_SIGS_REQUIRE) {
				/*
				 * Server requires signing.
				 */
				negotiated_signing = 1;
			} else if (sp->sv_sm & SMB_SM_SIGS) {
				/*
				 * Server enables signing (client's option).
				 * If enabled locally, do signing.
				 */
				if (vcp->vc_vopt & SMBVOPT_SIGNING_ENABLED)
					negotiated_signing = 1;
				/* else not signing. */
			} else {
				/*
				 * Server does not support signing.
				 * If we "require" it, bail now.
				 */
				if (vcp->vc_vopt & SMBVOPT_SIGNING_REQUIRED) {
					SMBERROR("Client requires signing "
					    "but server has it disabled.\n");
					error = EBADRPC;
					break;
				}
			}
			SMBSDEBUG("Security signatures: %d\n",
			    negotiated_signing);
			if (negotiated_signing) {
				SMB_VC_LOCK(vcp);
				vcp->vc_flags |= SMBV_WILL_SIGN;
				SMB_VC_UNLOCK(vcp);
			}

			if (sp->sv_caps & SMB_CAP_UNICODE) {
				SMB_VC_LOCK(vcp);
				vcp->vc_flags |= SMBV_UNICODE;
				SMB_VC_UNLOCK(vcp);
				unicode = 1;
			}
			if (!(sp->sv_caps & SMB_CAP_STATUS32)) {
				/*
				 * They don't do NT error codes.
				 *
				 * If we send requests with
				 * SMB_FLAGS2_ERR_STATUS set in
				 * Flags2, Windows 98, at least,
				 * appears to send replies with that
				 * bit set even though it sends back
				 * DOS error codes.  (They probably
				 * just use the request header as
				 * a template for the reply header,
				 * and don't bother clearing that bit.)
				 *
				 * Therefore, we clear that bit in
				 * our vc_hflags2 field.
				 */
				vcp->vc_hflags2 &= ~SMB_FLAGS2_ERR_STATUS;
			}
			if (dp->d_id == SMB_DIALECT_NTLM0_12 &&
			    sp->sv_maxtx < 4096 &&
			    (sp->sv_caps & SMB_CAP_NT_SMBS) == 0) {
				SMB_VC_LOCK(vcp);
				vcp->vc_flags |= SMBV_WIN95;
				SMB_VC_UNLOCK(vcp);
				SMBSDEBUG("Win95 detected\n");
			}

			/*
			 * 3 cases here:
			 *
			 * 1) Extended security.
			 * Read bc bytes below for security blob.
			 * Note that we DON'T put the Caps flag in outtok.
			 * outtoklen = bc
			 *
			 * 2) No extended security, have challenge data and
			 * possibly a domain name (which might be zero
			 * bytes long, meaning "missing").
			 * Copy challenge stuff to vcp->vc_ch (sblen bytes),
			 * then copy Cap flags and domain name (bc-sblen
			 * bytes) to outtok.
			 * outtoklen = bc-sblen+4, where the 4 is for the
			 * Caps flag.
			 *
			 * 3) No extended security, no challenge data, just
			 * possibly a domain name.
			 * Copy Capsflags and domain name (bc) to outtok.
			 * outtoklen = bc+4, where 4 is for the Caps flag
			 */

			/*
			 * Sanity check: make sure the challenge length
			 * isn't bigger than the byte count.
			 */
			if (sblen > bc) {
				error = EBADRPC;
				break;
			}
			toklen = bc;

			if (sblen && sblen <= SMB_MAXCHALLENGELEN &&
			    sp->sv_sm & SMB_SM_ENCRYPT) {
				error = md_get_mem(mdp,
				    (char *)vcp->vc_challenge,
				    sblen, MB_MSYSTEM);
				if (error)
					break;
				vcp->vc_chlen = sblen;
				toklen -= sblen;

				SMB_VC_LOCK(vcp);
				vcp->vc_flags |= SMBV_ENCRYPT;
				SMB_VC_UNLOCK(vcp);
			}

			/*
			 * For servers that don't support unicode
			 * there are 2 things we could do:
			 * 1) Pass the server Caps flags up to the
			 * user level so the logic up there will
			 * know whether the domain name is unicode
			 * (this is what I did).
			 * 2) Try to convert the non-unicode string
			 * to unicode. This doubles the length of
			 * the outtok buffer and would be guessing that
			 * the string was single-byte ascii, and that
			 * might be wrong. Why ask for trouble?
			 */

			/* Warning: NetApp may omit the GUID */

			if (!(sp->sv_caps & SMB_CAP_EXT_SECURITY)) {
				/*
				 * No extended security.
				 * Stick domain name, if present,
				 * and caps in outtok.
				 */
				toklen = toklen + 4; /* space for Caps flags */
				vcp->vc_outtoklen =  toklen;
				vcp->vc_outtok = kmem_alloc(toklen, KM_SLEEP);
				/* first store server capability bits */
				/*LINTED*/
				ASSERT(vcp->vc_outtok ==
				    (caddr_t)(((u_int32_t *)vcp->vc_outtok)));
				/*LINTED*/
				*(u_int32_t *)(vcp->vc_outtok) = sp->sv_caps;

				/*
				 * Then store the domain name if present;
				 * be sure to subtract 4 from the length
				 * for the Caps flag.
				 */
				if (toklen > 4) {
					error = md_get_mem(mdp,
					    vcp->vc_outtok+4, toklen-4,
					    MB_MSYSTEM);
				}
			} else {
				/*
				 * Extended security.
				 * Stick the rest of the buffer in outtok.
				 */
				vcp->vc_outtoklen =  toklen;
				vcp->vc_outtok = kmem_alloc(toklen, KM_SLEEP);
				error = md_get_mem(mdp, vcp->vc_outtok, toklen,
				    MB_MSYSTEM);
			}
			break;
		}
		vcp->vc_hflags2 &= ~(SMB_FLAGS2_EXT_SEC|SMB_FLAGS2_DFS|
		    SMB_FLAGS2_ERR_STATUS|SMB_FLAGS2_UNICODE);
		if (dp->d_id > SMB_DIALECT_CORE) {
			md_get_uint16le(mdp, &tw);
			sp->sv_sm = (uchar_t)tw;
			md_get_uint16le(mdp, &tw);
			sp->sv_maxtx = tw;
			md_get_uint16le(mdp, &sp->sv_maxmux);
			md_get_uint16le(mdp, &sp->sv_maxvcs);
			md_get_uint16le(mdp, &tw);	/* rawmode */
			md_get_uint32le(mdp, &sp->sv_skey);
			if (wc == 13) {		/* >= LANMAN1 */
				md_get_uint16(mdp, &tw);	/* time */
				md_get_uint16(mdp, &tw1);	/* date */
				md_get_uint16le(mdp, (u_int16_t *)&sp->sv_tz);
				md_get_uint16le(mdp, &swlen);
				if (swlen > SMB_MAXCHALLENGELEN)
					break;
				md_get_uint16(mdp, NULL);	/* mbz */
				if (md_get_uint16le(mdp, &bc) != 0)
					break;
				if (bc < swlen)
					break;
				if (swlen && (sp->sv_sm & SMB_SM_ENCRYPT)) {
					error = md_get_mem(mdp,
					    (char *)vcp->vc_challenge,
					    swlen, MB_MSYSTEM);
					if (error)
						break;
					vcp->vc_chlen = swlen;

					SMB_VC_LOCK(vcp);
					vcp->vc_flags |= SMBV_ENCRYPT;
					SMB_VC_UNLOCK(vcp);
				}
			}
		} else {	/* an old CORE protocol */
			vcp->vc_hflags2 &= ~SMB_FLAGS2_KNOWS_LONG_NAMES;
			sp->sv_maxmux = 1;
		}
		error = 0;
		/*LINTED*/
	} while (0);
	if (error == 0) {
		uint32_t x;

		/*
		 * Maximum outstanding requests.
		 */
		if (vcp->vc_maxmux < 1)
			vcp->vc_maxmux = 1;

		/*
		 * Max VCs between server and client.
		 * We only use one.
		 */
		vcp->vc_maxvcs = sp->sv_maxvcs;
		if (vcp->vc_maxvcs < 1)
			vcp->vc_maxvcs = 1;

		/*
		 * Maximum transfer size.
		 * Sanity checks:
		 *
		 * Spec. says lower limit is 1024.  OK.
		 *
		 * Let's be conservative about an upper limit here.
		 * Win2k uses 16644 (and others) so 32k should be a
		 * reasonable sanity limit for this value.
		 *
		 * Note that this limit does NOT affect READX/WRITEX
		 * with CAP_LARGE_xxx, which we nearly always use.
		 */
		vcp->vc_txmax = sp->sv_maxtx;
		if (vcp->vc_txmax < 1024)
			vcp->vc_txmax = 1024;
		if (vcp->vc_txmax > 0x8000)
			vcp->vc_txmax = 0x8000;

		/*
		 * Max read/write sizes, WITHOUT overhead.
		 * This is just the payload size, so we must
		 * leave room for the SMB headers, etc.
		 * This is just the vc_txmax value, but
		 * reduced and rounded down.  Tricky bit:
		 *
		 * Servers typically give us a value that's
		 * some nice "round" number, i.e 0x4000 plus
		 * some overhead, i.e. Win2k: 16644==0x4104
		 * Subtract for the SMB header (32) and the
		 * SMB command word and byte vectors (34?),
		 * then round down to a 512 byte multiple.
		 */
		x = (vcp->vc_txmax - 68) & 0xFE00;
		vcp->vc_rxmax = x;
		vcp->vc_wxmax = x;

		SMBSDEBUG("TZ = %d\n", sp->sv_tz);
		SMBSDEBUG("CAPS = %x\n", sp->sv_caps);

		SMBSDEBUG("maxmux = %d\n", vcp->vc_maxmux);
		SMBSDEBUG("maxvcs = %d\n", vcp->vc_maxvcs);
		SMBSDEBUG("txmax = %d\n", vcp->vc_txmax);
		SMBSDEBUG("rxmax = %d\n", vcp->vc_rxmax);
		SMBSDEBUG("wxmax = %d\n", vcp->vc_wxmax);
	}

	/*
	 * If the server supports Unicode, set up to use Unicode
	 * when talking to them.  Othewise, use code page 437.
	 */
	if (unicode)
		servercs = "ucs-2";
	else {
		/*
		 * todo: if we can't determine the server's encoding, we
		 * need to try a best-guess here.
		 */
		servercs = "cp437";
	}
#if defined(NOICONVSUPPORT) || defined(lint)
	/*
	 * REVISIT
	 */
	error = iconv_open(servercs, "utf-8", &servercshandle);
	if (error != 0)
		goto bad;
	error = iconv_open("utf-8", servercs, &localcshandle);
	if (error != 0) {
		iconv_close(servercshandle);
		goto bad;
	}
	if (vcp->vc_toserver)
		iconv_close(vcp->vc_toserver);
	if (vcp->vc_tolocal)
		iconv_close(vcp->vc_tolocal);
	vcp->vc_toserver = servercshandle;
	vcp->vc_tolocal  = localcshandle;
#endif
	if (unicode)
		vcp->vc_hflags2 |= SMB_FLAGS2_UNICODE;
bad:
	smb_rq_done(rqp);
	return (error);
}

static void
get_ascii_password(struct smb_vc *vcp, int upper, char *pbuf)
{
	const char *pw = smb_vc_getpass(vcp);
	if (upper)
		smb_toupper(pw, pbuf, SMB_MAXPASSWORDLEN);
	else
		strncpy(pbuf, pw, SMB_MAXPASSWORDLEN);
	pbuf[SMB_MAXPASSWORDLEN] = '\0';
}

#ifdef APPLE
static void
get_unicode_password(struct smb_vc *vcp, char *pbuf)
{
	strncpy(pbuf, smb_vc_getpass(vcp), SMB_MAXPASSWORDLEN);
	pbuf[SMB_MAXPASSWORDLEN] = '\0';
}
#endif

/*ARGSUSED*/
static uchar_t *
add_name_to_blob(uchar_t *blobnames, struct smb_vc *vcp, const uchar_t *name,
    size_t namelen, int nametype, int uppercase)
{
	struct ntlmv2_namehdr namehdr;
	char *namebuf;
	u_int16_t *uninamebuf;
	size_t uninamelen;

	if (name != NULL) {
		uninamebuf = kmem_alloc(2 * namelen, KM_SLEEP);
		if (uppercase) {
			namebuf = kmem_alloc(namelen + 1, KM_SLEEP);
			smb_toupper((const char *)name, namebuf, namelen);
			namebuf[namelen] = '\0';
			uninamelen = smb_strtouni(uninamebuf, namebuf, namelen,
			    UCONV_IGNORE_NULL);
			kmem_free(namebuf, namelen + 1);
		} else {
			uninamelen = smb_strtouni(uninamebuf, (char *)name,
			    namelen, UCONV_IGNORE_NULL);
		}
	} else {
		uninamelen = 0;
		uninamebuf = NULL;
	}
	namehdr.type = htoles(nametype);
	namehdr.len = htoles(uninamelen);
	bcopy(&namehdr, blobnames, sizeof (namehdr));
	blobnames += sizeof (namehdr);
	if (uninamebuf != NULL) {
		bcopy(uninamebuf, blobnames, uninamelen);
		blobnames += uninamelen;
		kmem_free(uninamebuf, namelen * 2);
	}
	return (blobnames);
}

static uchar_t *
make_ntlmv2_blob(struct smb_vc *vcp, u_int64_t client_nonce,
	size_t *bloblen, size_t *blob_allocsz)
{
	uchar_t *blob;
	size_t blobsize;
	size_t domainlen, srvlen;
	struct ntlmv2_blobhdr *blobhdr;
	struct timespec now;
	u_int64_t timestamp;
	uchar_t *blobnames;
	ptrdiff_t diff;

	/*
	 * XXX - the information at
	 *
	 * http://davenport.sourceforge.net/ntlm.html#theNtlmv2Response
	 *
	 * says that the "target information" comes from the Type 2 message,
	 * but, as we're not doing NTLMSSP, we don't have that.
	 *
	 * Should we use the names from the NegProt response?  Can we trust
	 * the NegProt response?  (I've seen captures where the primary
	 * domain name has an extra byte in front of it.)
	 *
	 * For now, we don't trust it - we use vcp->vc_domain and
	 * vcp->vc_srvname, instead.  We upper-case them and convert
	 * them to Unicode, as that's what's supposed to be in the blob.
	 */
	domainlen = strlen(vcp->vc_domain);
	srvlen = strlen(vcp->vc_srvname);
	blobsize = sizeof (struct ntlmv2_blobhdr)
	    + 3*sizeof (struct ntlmv2_namehdr) + 4 + 2*domainlen + 2*srvlen;
	*blob_allocsz = blobsize;
	blobhdr = kmem_zalloc(blobsize, KM_SLEEP);
	blob = (uchar_t *)blobhdr;
	blobhdr->header = htolel(0x00000101);
	gethrestime(&now);
	smb_time_local2NT(&now, 0, &timestamp);
	blobhdr->timestamp = htoleq(timestamp);
	blobhdr->client_nonce = client_nonce;
	blobnames = blob + sizeof (struct ntlmv2_blobhdr);
	blobnames = add_name_to_blob(blobnames, vcp, (uchar_t *)vcp->vc_domain,
	    domainlen, NAMETYPE_DOMAIN_NB, 1);
	blobnames = add_name_to_blob(blobnames, vcp, (uchar_t *)vcp->vc_srvname,
	    srvlen, NAMETYPE_MACHINE_NB, 1);
	blobnames = add_name_to_blob(blobnames, vcp, NULL, 0, NAMETYPE_EOL, 0);
	diff = (intptr_t)blobnames - (intptr_t)blob;
	ASSERT(diff == (ptrdiff_t)((size_t)diff));
	*bloblen = (size_t)diff;
	return (blob);
}

/*
 * When not doing Kerberos, we can try, in order:
 *
 *	NTLMv2
 *	NTLM (and maybe LM)
 *
 * if the server supports encrypted passwords, or
 *
 *	plain-text with the ASCII password not upper-cased
 *	plain-text with the ASCII password upper-cased
 *
 * if it doesn't.
 */
typedef enum {
	ClearUC,	/* Cleartext p/w, upper case */
	ClearMC,	/* Cleartext p/w, mixed case */
	NTLMv1,
	NTLMv2,
	ExtSec,		/* Extended Security (Kerberos) */
	NullSes		/* Null session (keep last) */
} authtype_t;

int
smb_smb_ssnsetup(struct smb_vc *vcp, struct smb_cred *scred)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	u_int8_t wc;
	int minauth;
	smb_uniptr unipp = NULL, ntencpass = NULL;
	char *pp = NULL, *up = NULL, *ucup = NULL;
	char *ucdp = vcp->vc_domain; /* already upper case */
	char *encpass = NULL;
	int error = 0;
	size_t plen = 0, plen_alloc = 0;
	size_t uniplen = 0, uniplen_alloc = 0;
	size_t ucup_sl = 0;
	authtype_t authtype;
	size_t ntlmv2_bloblen, ntlmv2_blob_allocsz;
	uchar_t *ntlmv2_blob;
	u_int64_t client_nonce;
	u_int32_t caps;
	u_int16_t bl; /* BLOB length */
	u_int16_t bc; /* byte count */
	u_int16_t action;
	u_int16_t rpflags2;
	int declinedguest = 0;
	uchar_t v2hash[16];
	static const char NativeOS[] = "Solaris";
	static const char LanMan[] = "NETSMB";
	/*
	 * Most of the "capability" bits we offer should be copied
	 * from those offered by the server, with a mask applied.
	 * This is the mask of capabilies copied from the server.
	 * Some others get special handling below.
	 */
	static const uint32_t caps_mask =
	    SMB_CAP_UNICODE |
	    SMB_CAP_LARGE_FILES |
	    SMB_CAP_NT_SMBS |
	    SMB_CAP_STATUS32;

	caps = vcp->vc_sopt.sv_caps & caps_mask;
	minauth = vcp->vc_vopt & SMBVOPT_MINAUTH;

	/*
	 * This function tries authentication types in a
	 * sequence going stronger to weaker, until it
	 * succeeds or runs into "minauth" and fails.
	 *
	 * Extended security is a special case because
	 * fall-back requires a return to user-level and
	 * a new connection, new SMB negotiate, etc.
	 * Null session is also special - no fall-back.
	 *
	 * Otherwise if the server supports encryption,
	 * try NTLMv2, then NTLM, etc.
	 */
	if (vcp->vc_intok)
		authtype = ExtSec;
	else if (vcp->vc_username[0] == '\0')
		authtype = NullSes;
	else if ((vcp->vc_sopt.sv_sm & SMB_SM_USER) == 0) {
		/* Share-level security. */
		authtype = NullSes;
	} else {
		/* Have SMB_SM_USER.  Encryption? */
		if (vcp->vc_sopt.sv_sm & SMB_SM_ENCRYPT) {
			if (nsmb_enable_ntlmv2)
				authtype = NTLMv2;
			else
				authtype = NTLMv1;
		} else {
			/*
			 * This is normally disallowed
			 * by the minauth check below.
			 */
			authtype = ClearMC;
		}
	}

	/*
	 * If server does not support encryption,
	 * disable unicode too.  (Spec. for this?)
	 */
	if ((vcp->vc_sopt.sv_sm & SMB_SM_ENCRYPT) == 0) {
		if (vcp->vc_flags & SMBV_UNICODE) {
			vcp->vc_hflags2 &= ~SMB_FLAGS2_UNICODE;
			vcp->vc_toserver = 0;
		}
	}

again:
	SMBSDEBUG("authtype = %d\n", authtype);

	/*
	 * Now disallow auth. types that fall below
	 * the minimum strength configured.
	 * We hold no kmem here.
	 */
	switch (minauth) {

	case SMBVOPT_MINAUTH_NONE:
		break;

	case SMBVOPT_MINAUTH_LM:
	case SMBVOPT_MINAUTH_NTLM:
		if (authtype < NTLMv1) {
			error = EAUTH;
			goto ssn_exit;
		}
		break;

	case SMBVOPT_MINAUTH_NTLMV2:
		if (authtype < NTLMv2) {
			error = EAUTH;
			goto ssn_exit;
		}
		break;

	case SMBVOPT_MINAUTH_KERBEROS:
		if (authtype < ExtSec) {
			error = EAUTH;
			goto ssn_exit;
		}
		break;

	default:
		SMBSDEBUG("bad minauth 0x%x\n", minauth);
		error = EAUTH;
		goto ssn_exit;
	}

	/*
	 * See comment in smb_iod_sendrq()
	 * about vc_smbuid initialization.
	 */
	vcp->vc_smbuid = SMB_UID_UNKNOWN;

	/*
	 * Within this switch, we may allocate either or both:
	 * encpass, ntencpass (len: plen_alloc, uniplen_alloc)
	 * and will free these below (see the label "bad")
	 */
	switch (authtype) {

	case ExtSec:
		/*
		 * With extended security, the whole blob is
		 * passed in from user-level (vc_intok)
		 */
		ASSERT(vcp->vc_intok != NULL);
		caps |= SMB_CAP_EXT_SECURITY;
		/* XXX Need Session Key  */
		if (vcp->vc_intoklen > 65536 ||
		    !(vcp->vc_hflags2 & SMB_FLAGS2_EXT_SEC) ||
		    SMB_DIALECT(vcp) < SMB_DIALECT_NTLM0_12) {
			/* We hold no kmem here. */
			error = EINVAL;
			goto ssn_exit;
		}
		vcp->vc_smbuid = 0;
		break;

	case NullSes:
		pp = "";
		plen = 1;
		unipp = &smb_unieol;
		uniplen = sizeof (smb_unieol);
		break;

	case NTLMv2:
		/*
		 * Compute the LMv2 and NTLMv2 responses,
		 * derived from the challenge, the user name,
		 * the domain/workgroup into which we're
		 * logging, and the Unicode password.
		 */

		/*
		 * Construct the client nonce by getting
		 * a bunch of random data.
		 */
		(void) random_get_pseudo_bytes((void *)
		    &client_nonce,  sizeof (client_nonce));

		/*
		 * Convert the user name to upper-case, as
		 * that's what's used when computing LMv2
		 * and NTLMv2 responses.
		 */
		ucup_sl = strlen(vcp->vc_username);
		ucup = kmem_alloc(ucup_sl + 1, KM_SLEEP);
		smb_toupper((const char *)vcp->vc_username,
		    ucup, ucup_sl);
		ucup[ucup_sl] = '\0';

		/*
		 * Compute the NTLMv2 hash, which is
		 * derived from the NTLMv1 hash and
		 * the upper-case user + domain.
		 */
		smb_ntlmv2hash(vcp->vc_nthash,
		    ucup, ucdp, v2hash);

		/*
		 * Compute the LMv2 response, derived from
		 * the v2hash, the server challenge, and
		 * the client nonce (random bits).
		 * Note: kmem_alloc encpass (plen)
		 */
		smb_ntlmv2response(v2hash,
		    vcp->vc_challenge,
		    (uchar_t *)&client_nonce, 8,
		    (uchar_t **)&encpass, &plen);
		plen_alloc = plen;
		pp = encpass;

		/*
		 * Construct the blob.
		 * Note: kmem_alloc ntlmv2_blob
		 */
		ntlmv2_blob = make_ntlmv2_blob(vcp,
		    client_nonce, &ntlmv2_bloblen,
		    &ntlmv2_blob_allocsz);

		/*
		 * Compute the NTLMv2 response, derived
		 * from the server challenge, the
		 * user name, the domain/workgroup
		 * into which we're logging, the
		 * blob, and the v2 hash.
		 * Note: kmem_alloc ntencpass (uniplen)
		 */
		smb_ntlmv2response(v2hash,
		    vcp->vc_challenge,
		    ntlmv2_blob, ntlmv2_bloblen,
		    (uchar_t **)&ntencpass, &uniplen);
		uniplen_alloc = uniplen;
		unipp = ntencpass;

		/*
		 * If we negotiated signing, compute the MAC key
		 * and start signing messages, but only on the
		 * first non-null session login.
		 */
		if ((vcp->vc_flags & SMBV_WILL_SIGN) &&
		    !(vcp->vc_hflags2 & SMB_FLAGS2_SECURITY_SIGNATURE)) {
			vcp->vc_hflags2 |= SMB_FLAGS2_SECURITY_SIGNATURE;
			smb_calcv2mackey(vcp, v2hash,
			    (uchar_t *)ntencpass, uniplen);
		}
		kmem_free(ucup, ucup_sl + 1);
		kmem_free(ntlmv2_blob, ntlmv2_blob_allocsz);
		break;

	case NTLMv1:
		/*
		 * Compute the LM response, derived
		 * from the challenge and the ASCII
		 * password.  (If minauth allows it.)
		 */
		plen_alloc = plen = 24;
		encpass = kmem_zalloc(plen, KM_SLEEP);
		if (minauth < SMBVOPT_MINAUTH_NTLM) {
			smb_lmresponse(vcp->vc_lmhash,
			    vcp->vc_challenge,
			    (uchar_t *)encpass);
		}
		pp = encpass;

		/*
		 * Compute the NTLM response, derived from
		 * the challenge and the NT hash.
		 */
		uniplen_alloc = uniplen = 24;
		ntencpass = kmem_alloc(uniplen, KM_SLEEP);
		smb_lmresponse(vcp->vc_nthash,
		    vcp->vc_challenge,
		    (uchar_t *)ntencpass);
		unipp = ntencpass;

		/*
		 * If we negotiated signing, compute the MAC key
		 * and start signing messages, but only on the
		 * first non-null session login.
		 */
		if ((vcp->vc_flags & SMBV_WILL_SIGN) &&
		    !(vcp->vc_hflags2 & SMB_FLAGS2_SECURITY_SIGNATURE)) {
			vcp->vc_hflags2 |= SMB_FLAGS2_SECURITY_SIGNATURE;
			smb_calcmackey(vcp, vcp->vc_nthash,
			    (uchar_t *)ntencpass, uniplen);
		}
		break;

	case ClearMC:
	case ClearUC:
		/*
		 * We try w/o uppercasing first so Samba mixed case
		 * passwords work.  If that fails, we come back and
		 * try uppercasing to satisfy OS/2 and Windows for
		 * Workgroups.
		 */
		plen_alloc = plen = SMB_MAXPASSWORDLEN + 1;
		encpass = kmem_zalloc(plen, KM_SLEEP);
		get_ascii_password(vcp, (authtype == ClearUC), encpass);
		plen = strlen(encpass) + 1;
		pp = encpass;
		uniplen_alloc = uniplen = plen * 2;
		ntencpass = kmem_alloc(uniplen, KM_SLEEP);
		(void) smb_strtouni(ntencpass, smb_vc_getpass(vcp), 0, 0);
		plen--;
		/*
		 * The uniplen is zeroed because Samba cannot deal
		 * with this 2nd cleartext password.  This Samba
		 * "bug" is actually a workaround for problems in
		 * Microsoft clients.
		 */
		uniplen = 0; /* -= 2 */
		unipp = ntencpass;
		break;

	default:
		ASSERT(0);
		error = EAUTH;
		goto ssn_exit;

	} /* switch authtype */


	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_SESSION_SETUP_ANDX,
	    scred, &rqp);
	if (error)
		goto bad;

	/*
	 * Build the request.
	 */
	smb_rq_wstart(rqp);
	mbp = &rqp->sr_rq;
	up = vcp->vc_username;
	/*
	 * If userid is null we are attempting anonymous browse login
	 * so passwords must be zero length.
	 */
	if (*up == '\0') {
		plen = uniplen = 0;
	}
	mb_put_uint8(mbp, 0xff);
	mb_put_uint8(mbp, 0);
	mb_put_uint16le(mbp, 0);
	mb_put_uint16le(mbp, vcp->vc_sopt.sv_maxtx);
	mb_put_uint16le(mbp, vcp->vc_sopt.sv_maxmux);
	mb_put_uint16le(mbp, vcp->vc_number);
	mb_put_uint32le(mbp, vcp->vc_sopt.sv_skey);
	if ((SMB_DIALECT(vcp)) < SMB_DIALECT_NTLM0_12) {
		mb_put_uint16le(mbp, plen);
		mb_put_uint32le(mbp, 0);
		smb_rq_wend(rqp);
		smb_rq_bstart(rqp);
		mb_put_mem(mbp, pp, plen, MB_MSYSTEM);
		smb_put_dstring(mbp, vcp, up, SMB_CS_NONE); /* user */
		smb_put_dstring(mbp, vcp, ucdp, SMB_CS_NONE); /* domain */
	} else {
		if (vcp->vc_intok) {
			mb_put_uint16le(mbp, vcp->vc_intoklen);
			mb_put_uint32le(mbp, 0);		/* reserved */
			mb_put_uint32le(mbp, caps);		/* my caps */
			smb_rq_wend(rqp);
			smb_rq_bstart(rqp);
			mb_put_mem(mbp, vcp->vc_intok, vcp->vc_intoklen,
			    MB_MSYSTEM);	/* security blob */
		} else {
			mb_put_uint16le(mbp, plen);
			mb_put_uint16le(mbp, uniplen);
			mb_put_uint32le(mbp, 0);		/* reserved */
			mb_put_uint32le(mbp, caps);		/* my caps */
			smb_rq_wend(rqp);
			smb_rq_bstart(rqp);
			mb_put_mem(mbp, pp, plen, MB_MSYSTEM); /* password */
			mb_put_mem(mbp, (caddr_t)unipp, uniplen, MB_MSYSTEM);
			smb_put_dstring(mbp, vcp, up, SMB_CS_NONE); /* user */
			smb_put_dstring(mbp, vcp, ucdp, SMB_CS_NONE); /* dom */
		}
	}
	smb_put_dstring(mbp, vcp, NativeOS, SMB_CS_NONE); /* OS */
	smb_put_dstring(mbp, vcp, LanMan, SMB_CS_NONE); /* LAN Mgr */
	smb_rq_bend(rqp);

	/*
	 * This request should not wait for
	 * connection state changes, etc.
	 */
	rqp->sr_flags |= SMBR_INTERNAL;
	error = smb_rq_simple_timed(rqp, SMBSSNSETUPTIMO);
	SMBSDEBUG("%d\n", error);
	if (error) {
		if (rqp->sr_errclass == ERRDOS &&
		    rqp->sr_serror == ERRnoaccess)
			error = EAUTH;
		if (!(rqp->sr_errclass == ERRDOS &&
		    rqp->sr_serror == ERRmoredata))
			goto bad;
	}

	/*
	 * Parse the reply
	 */
	rpflags2 = rqp->sr_rpflags2;
	vcp->vc_smbuid = rqp->sr_rpuid;
	smb_rq_getreply(rqp, &mdp);
	error = md_get_uint8(mdp, &wc);
	if (error)
		goto bad;
	error = EBADRPC;
	if (vcp->vc_intok) {
		if (wc != 4)
			goto bad;
	} else if (wc != 3)
		goto bad;
	md_get_uint8(mdp, NULL);	/* secondary cmd */
	md_get_uint8(mdp, NULL);	/* mbz */
	md_get_uint16le(mdp, NULL);	/* andxoffset */
	md_get_uint16le(mdp, &action);	/* action */
	if (vcp->vc_intok)
		md_get_uint16le(mdp, &bl);	/* ext security */
	md_get_uint16le(mdp, &bc); /* byte count */
	if (vcp->vc_intok) {
		vcp->vc_outtoklen = bl;
		vcp->vc_outtok = kmem_alloc(bl, KM_SLEEP);
		error = md_get_mem(mdp, vcp->vc_outtok, bl, MB_MSYSTEM);
		if (error)
			goto bad;
	}

	/*
	 * Server OS, LANMGR, & Domain follow here.
	 * XXX: Should store these strings (later).
	 *
	 * Windows systems do not suport CAP_LARGE_...
	 * when signing is enabled, so adjust sv_caps.
	 * Match first 8 characters of server's OS
	 * with the UCS-2LE string: "Windows "
	 */
	if (bc > 16) {
		static const char WindowsU[16] =
		    "W\0i\0n\0d\0o\0w\0s\0 ";
		char osbuf[16];

		/* align(2) */
		if (((uintptr_t)mdp->md_pos) & 1)
			md_get_uint8(mdp, NULL);

		bzero(osbuf, sizeof (osbuf));
		md_get_mem(mdp, osbuf, sizeof (osbuf), MB_MSYSTEM);
		if (0 == bcmp(WindowsU, osbuf, sizeof (osbuf))) {
			SMBSDEBUG("Server is Windows\n");
			if (vcp->vc_flags & SMBV_WILL_SIGN) {
				SMBSDEBUG("disable CAP_LARGE_(r/w)\n");
				vcp->vc_sopt.sv_caps &=
				    ~(SMB_CAP_LARGE_READX
				    | SMB_CAP_LARGE_WRITEX);
			}
		}
	}

	/* success! */
	error = 0;

bad:

	/*
	 * When authentication fails and we're (possibly) doing
	 * fall-back to another method, we have to reset things.
	 */
	if (error && vcp->vc_mackey) {
		vcp->vc_hflags2 &= ~SMB_FLAGS2_SECURITY_SIGNATURE;
		kmem_free(vcp->vc_mackey, vcp->vc_mackeylen);
		vcp->vc_mackey = NULL;
		vcp->vc_mackeylen = 0;
		vcp->vc_seqno = 0;
	}

	if (rqp) {
		smb_rq_done(rqp);
		rqp = NULL;
	}
	if (encpass) {
		kmem_free(encpass, plen_alloc);
		encpass = NULL;
	}
	if (ntencpass) {
		kmem_free(ntencpass, uniplen_alloc);
		ntencpass = NULL;
	}

	/*
	 * Shall we try again with another auth type?
	 * Note: We hold no kmem here.
	 */
	switch (authtype) {

	case NullSes:
	case ExtSec:
		/* Error or not, we're done. (no fallback) */
		break;

	case NTLMv2:
		/*
		 * We're doing user-level authentication (so we are actually
		 * sending authentication stuff over the wire), and we're
		 * not doing extended security, and the stuff we tried
		 * failed (or we we're trying to login a real user but
		 * got granted guest access instead.)
		 *
		 * See radar 4134676.  This check works around the way a
		 * certain old server grants limited Guest access when we
		 * try NTLMv2, but works fine with NTLM.  The fingerprint
		 * we are looking for is DOS error codes and no-Unicode.
		 * Note XP grants Guest access but uses Unicode and
		 * NT error codes.
		 */
		if (error == 0 && (action & SMB_ACT_GUEST) &&
		    !(rpflags2 & SMB_FLAGS2_ERR_STATUS) &&
		    !(rpflags2 & SMB_FLAGS2_UNICODE)) {
			/* force fallback */
			declinedguest = 1;
			error = EAUTH;
		}
		/* FALLTHROUGH */
	case NTLMv1:
	case ClearMC:
		if (error) {
			authtype = authtype - 1;
			goto again;
		}
		break;

	case ClearUC:
	default:
		/* no more fallbacks */
		break;
	}

ssn_exit:
	if (error && declinedguest)
		SMBERROR("we declined ntlmv2 guest access. errno will be %d\n",
		    error);

	return (error);
}

int
smb_smb_ssnclose(struct smb_vc *vcp, struct smb_cred *scred)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	if (vcp->vc_smbuid == SMB_UID_UNKNOWN)
		return (0);

	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_LOGOFF_ANDX, scred, &rqp);
	if (error)
		return (error);
	mbp = &rqp->sr_rq;
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);
	mb_put_uint8(mbp, 0);
	mb_put_uint16le(mbp, 0);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);
	/*
	 * Run this with a relatively short timeout.
	 * We don't really care about the result,
	 * as we're just trying to play nice and
	 * "say goodbye" before we hangup.
	 * XXX: Add SMBLOGOFFTIMO somewhere?
	 */
	error = smb_rq_simple_timed(rqp, 5);
	SMBSDEBUG("%d\n", error);
	smb_rq_done(rqp);
	return (error);
}

static char smb_any_share[] = "?????";

static char *
smb_share_typename(int stype)
{
	char *pp;

	switch (stype) {
	case STYPE_DISKTREE:
		pp = "A:";
		break;
	case STYPE_PRINTQ:
		pp = smb_any_share;		/* can't use LPT: here... */
		break;
	case STYPE_DEVICE:
		pp = "COMM";
		break;
	case STYPE_IPC:
		pp = "IPC";
		break;
	default:
		pp = smb_any_share;
		break;
	}
	return (pp);
}

int
smb_smb_treeconnect(struct smb_share *ssp, struct smb_cred *scred)
{
	struct smb_vc *vcp;
	struct smb_rq rq, *rqp = &rq;
	struct mbchain *mbp;
	char *pp, *pbuf, *encpass;
	const char *pw;
	uchar_t hash[SMB_PWH_MAX];
	int error, plen, caseopt;
	int upper = 0;

again:
	vcp = SSTOVC(ssp);

	/*
	 * Make this a "VC-level" request, so it will have
	 * rqp->sr_share == NULL, and smb_iod_sendrq()
	 * will send it with TID = SMB_TID_UNKNOWN
	 *
	 * This also serves to bypass the wait for
	 * share state changes, which this call is
	 * trying to carry out.
	 *
	 * No longer need to set ssp->ss_tid
	 * here, but it's harmless enough.
	 */
	ssp->ss_tid = SMB_TID_UNKNOWN;
	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_TREE_CONNECT_ANDX,
	    scred, &rqp);
	if (error)
		return (error);
	caseopt = SMB_CS_NONE;
	if (vcp->vc_sopt.sv_sm & SMB_SM_USER) {
		plen = 1;
		pp = "";
		pbuf = NULL;
		encpass = NULL;
	} else {
		pbuf = kmem_alloc(SMB_MAXPASSWORDLEN + 1, KM_SLEEP);
		encpass = kmem_alloc(24, KM_SLEEP);
		pw = smb_share_getpass(ssp);
		/*
		 * We try w/o uppercasing first so Samba mixed case
		 * passwords work.  If that fails we come back and try
		 * uppercasing to satisfy OS/2 and Windows for Workgroups.
		 */
		if (upper++) {
			smb_toupper(pw, pbuf, SMB_MAXPASSWORDLEN);
			smb_oldlm_hash(pw, hash);
		} else {
			strncpy(pbuf, pw, SMB_MAXPASSWORDLEN);
			smb_ntlmv1hash(pw, hash);
		}
		pbuf[SMB_MAXPASSWORDLEN] = '\0';

#ifdef NOICONVSUPPORT
		/*
		 * We need to convert here to the server codeset.
		 * Initially we will send the same stuff and see what happens
		 * witout the conversion.  REVISIT.
		 */
		iconv_convstr(vcp->vc_toserver, pbuf, pbuf, SMB_MAXPASSWORDLEN);
#endif
		if (vcp->vc_sopt.sv_sm & SMB_SM_ENCRYPT) {
			plen = 24;
			smb_lmresponse(hash,
			    vcp->vc_challenge,
			    (uchar_t *)encpass);
			pp = encpass;
		} else {
			plen = strlen(pbuf) + 1;
			pp = pbuf;
		}
	}
	mbp = &rqp->sr_rq;
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);
	mb_put_uint8(mbp, 0);
	mb_put_uint16le(mbp, 0);
	mb_put_uint16le(mbp, 0);		/* Flags */
	mb_put_uint16le(mbp, plen);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	error = mb_put_mem(mbp, pp, plen, MB_MSYSTEM);
	if (error) {
		SMBSDEBUG("error %d from mb_put_mem for pp\n", error);
		goto bad;
	}
	smb_put_dmem(mbp, vcp, "\\\\", 2, caseopt, NULL);
	pp = vcp->vc_srvname;
	error = smb_put_dmem(mbp, vcp, pp, strlen(pp), caseopt, NULL);
	if (error) {
		SMBSDEBUG("error %d from smb_put_dmem for srvname\n", error);
		goto bad;
	}
	smb_put_dmem(mbp, vcp, "\\", 1, caseopt, NULL);
	pp = ssp->ss_name;
	error = smb_put_dstring(mbp, vcp, pp, caseopt);
	if (error) {
		SMBSDEBUG("error %d from smb_put_dstring for ss_name\n", error);
		goto bad;
	}
	/* The type name is always ASCII */
	pp = smb_share_typename(ssp->ss_type);
	error = mb_put_mem(mbp, pp, strlen(pp) + 1, MB_MSYSTEM);
	if (error) {
		SMBSDEBUG("error %d from mb_put_mem for ss_type\n", error);
		goto bad;
	}
	smb_rq_bend(rqp);
	/*
	 * Don't want to risk missing a successful
	 * tree connect response.
	 */
	rqp->sr_flags |= SMBR_NOINTR_RECV;
	error = smb_rq_simple(rqp);
	SMBSDEBUG("%d\n", error);
	if (error)
		goto bad;

	/* Success! */
	SMB_SS_LOCK(ssp);
	ssp->ss_tid = rqp->sr_rptid;
	ssp->ss_vcgenid = vcp->vc_genid;
	ssp->ss_flags |= SMBS_CONNECTED;
	SMB_SS_UNLOCK(ssp);

bad:
	if (encpass)
		kmem_free(encpass, 24);
	if (pbuf)
		kmem_free(pbuf, SMB_MAXPASSWORDLEN + 1);
	smb_rq_done(rqp);
	if (error && upper == 1)
		goto again;
	return (error);
}

int
smb_smb_treedisconnect(struct smb_share *ssp, struct smb_cred *scred)
{
	struct smb_vc *vcp;
	struct smb_rq *rqp;
	struct mbchain *mbp;
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
	mbp = &rqp->sr_rq;
#ifdef lint
	mbp = mbp;
#endif
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
	 */
	rqp->sr_flags |= SMBR_NOINTR_SEND;
	error = smb_rq_simple_timed(rqp, 5);
	SMBSDEBUG("%d\n", error);
	smb_rq_done(rqp);
	ssp->ss_tid = SMB_TID_UNKNOWN;
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

		SMBSDEBUG("rw=%d, off %lld, len %d\n",
		    rw, uiop->uio_loffset, len);

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
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
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
	do {
		if (timo == 0)
			timo = smb_timo_read;
		error = smb_rq_simple_timed(rqp, timo);
		if (error)
			break;
		smb_rq_getreply(rqp, &mdp);
		md_get_uint8(mdp, &wc);
		if (wc != 12) {
			error = EBADRPC;
			break;
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
		md_get_uint16le(mdp, NULL);	/* ByteCount */
		/*
		 * Does the data offset indicate padding?
		 * Add up the gets above, we have:
		 */
		off = SMB_HDRLEN + 3 + (12 * 2); /* =59 */
		if (doff > off)	/* pad byte(s)? */
			md_get_mem(mdp, NULL, doff - off, MB_MSYSTEM);
		if (rlen == 0) {
			*lenp = rlen;
			break;
		}
		/* paranoid */
		if (rlen > *lenp) {
			SMBSDEBUG("bad server! rlen %d, len %d\n",
			    rlen, *lenp);
			rlen = *lenp;
		}
		error = md_get_uio(mdp, uiop, rlen);
		if (error)
			break;
		*lenp = rlen;
		/*LINTED*/
	} while (0);
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
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
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
	do {
		mb_put_uint8(mbp, 0);	/* pad byte */
		error = mb_put_uio(mbp, uiop, *lenp);
		if (error)
			break;
		smb_rq_bend(rqp);
		if (timo == 0)
			timo = smb_timo_write;
		error = smb_rq_simple_timed(rqp, timo);
		if (error)
			break;
		smb_rq_getreply(rqp, &mdp);
		md_get_uint8(mdp, &wc);
		if (wc != 6) {
			error = EBADRPC;
			break;
		}
		md_get_uint8(mdp, NULL);	/* andx cmd */
		md_get_uint8(mdp, NULL);	/* reserved */
		md_get_uint16le(mdp, NULL);	/* andx offset */
		md_get_uint16le(mdp, &lenlo);	/* data len ret. */
		md_get_uint16le(mdp, NULL);	/* remaining */
		md_get_uint16le(mdp, &lenhi);
		rlen = (lenhi << 16) | lenlo;
		*lenp = rlen;
		/*LINTED*/
	} while (0);

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
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
	mb_put_uint16le(mbp, cnt);
	mb_put_uint32le(mbp, off32);
	mb_put_uint16le(mbp, todo);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);
	do {
		if (timo == 0)
			timo = smb_timo_read;
		error = smb_rq_simple_timed(rqp, timo);
		if (error)
			break;
		smb_rq_getreply(rqp, &mdp);
		md_get_uint8(mdp, &wc);
		if (wc != 5) {
			error = EBADRPC;
			break;
		}
		md_get_uint16le(mdp, &rcnt);	/* ret. count */
		md_get_mem(mdp, NULL, 4 * 2, MB_MSYSTEM);  /* res. */
		md_get_uint16le(mdp, &bc);	/* byte count */
		md_get_uint8(mdp, NULL);	/* buffer format */
		md_get_uint16le(mdp, &dlen);	/* data len */
		if (dlen < rcnt) {
			SMBSDEBUG("oops: dlen=%d rcnt=%d\n",
			    (int)dlen, (int)rcnt);
			rcnt = dlen;
		}
		if (rcnt == 0) {
			*lenp = 0;
			break;
		}
		/* paranoid */
		if (rcnt > cnt) {
			SMBSDEBUG("bad server! rcnt %d, cnt %d\n",
			    (int)rcnt, (int)cnt);
			rcnt = cnt;
		}
		error = md_get_uio(mdp, uiop, (int)rcnt);
		if (error)
			break;
		*lenp = (int)rcnt;
		/*LINTED*/
	} while (0);
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
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
	mb_put_uint16le(mbp, cnt);
	mb_put_uint32le(mbp, off32);
	mb_put_uint16le(mbp, todo);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	mb_put_uint8(mbp, SMB_DT_DATA);
	mb_put_uint16le(mbp, cnt);
	do {
		error = mb_put_uio(mbp, uiop, *lenp);
		if (error)
			break;
		smb_rq_bend(rqp);
		if (timo == 0)
			timo = smb_timo_write;
		error = smb_rq_simple_timed(rqp, timo);
		if (error)
			break;
		smb_rq_getreply(rqp, &mdp);
		md_get_uint8(mdp, &wc);
		if (wc != 1) {
			error = EBADRPC;
			break;
		}
		md_get_uint16le(mdp, &rcnt);
		*lenp = rcnt;
		/*LINTED*/
	} while (0);
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
	rqp->sr_flags |= SMBR_INTERNAL;
	error = smb_rq_simple_timed(rqp, timo);
	SMBSDEBUG("%d\n", error);
	smb_rq_done(rqp);
	return (error);
}

#ifdef APPLE
int
smb_smb_checkdir(struct smb_share *ssp, void *dnp, char *name,
		int nmlen, struct smb_cred *scred)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_CHECK_DIRECTORY, scred, &rqp);
	if (error)
		return (error);

	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	mb_put_uint8(mbp, SMB_DT_ASCII);
	/*
	 * All we need to do is marshall the path: "\\"
	 * (the root of the share) into this request.
	 * We essentially in-line smbfs_fullpath() here,
	 * except no mb_put_padbyte (already aligned).
	 */
	smb_put_dstring(mbp, SSTOVC(ssp), "\\", SMB_CS_NONE);
	smb_rq_bend(rqp);

	error = smb_rq_simple(rqp);
	SMBSDEBUG("%d\n", error);
	smb_rq_done(rqp);

	return (error);
}
#endif /* APPLE */
