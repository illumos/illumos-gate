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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static int smb_smb_read(struct smb_share *ssp, u_int16_t fid,
	int *len, int *rresid, uio_t *uiop, struct smb_cred *scred, int timo);
static int smb_smb_write(struct smb_share *ssp, u_int16_t fid,
	int *len, int *rresid, uio_t *uiop, struct smb_cred *scred, int timo);

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
	u_int16_t toklen;

	vcp->vc_hflags = SMB_FLAGS_CASELESS;	/* XXX on Unix? */
	/*
	 * Make sure SMB_FLAGS2_UNICODE is "off" so mb_put_dstring
	 * marshalls the dialect strings in plain ascii.
	 */
	vcp->vc_hflags2 &= ~SMB_FLAGS2_UNICODE;
	vcp->vc_hflags2 |= SMB_FLAGS2_ERR_STATUS;

	SMB_VC_LOCK(vcp);
	vcp->vc_flags &= ~(SMBV_ENCRYPT);
	SMB_VC_UNLOCK(vcp);

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
			if (sp->sv_sm & SMB_SM_SIGS_REQUIRE)
				SMBERROR("server configuration requires "
				    "packet signing, which we dont support: "
				    "sp->sv_sm %d\n", sp->sv_sm);
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
		 *
		 * With CAP_LARGE_xxx, always use 60k.
		 * Otherwise use the vc_txmax value, but
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
		if (sp->sv_caps & SMB_CAP_LARGE_READX)
			vcp->vc_rxmax = SMB_MAX_LARGE_RW_SIZE;
		else
			vcp->vc_rxmax = x;
		if (sp->sv_caps & SMB_CAP_LARGE_WRITEX)
			vcp->vc_wxmax = SMB_MAX_LARGE_RW_SIZE;
		else
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
make_ntlmv2_blob(struct smb_vc *vcp, u_int64_t client_nonce, size_t *bloblen)
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
	blob = kmem_zalloc(blobsize, KM_SLEEP);
	/*LINTED*/
	ASSERT(blob == (uchar_t *)((struct ntlmv2_blobhdr *)blob));
	/*LINTED*/
	blobhdr = (struct ntlmv2_blobhdr *)blob;
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
 * See radar 4134676.  This define helps us avoid how a certain old server
 * grants limited Guest access when we try NTLMv2, but works fine with NTLM.
 * The fingerprint we are looking for here is DOS error codes and no-Unicode.
 * Note XP grants Guest access but uses Unicode and NT error codes.
 */
#define	smb_antique(rqp) (!((rqp)->sr_rpflags2 & SMB_FLAGS2_ERR_STATUS) && \
	!((rqp)->sr_rpflags2 & SMB_FLAGS2_UNICODE))

/*
 * When not doing Kerberos, we can try, in order:
 *
 *	NTLMv2
 *	NTLM with the ASCII password not upper-cased
 *	NTLM with the ASCII password upper-cased
 *
 * if the server supports encrypted passwords, or
 *
 *	plain-text with the ASCII password not upper-cased
 *	plain-text with the ASCII password upper-cased
 *
 * if it doesn't.
 */
#define	STATE_NTLMV2	0
#define	STATE_NOUCPW	1
#define	STATE_UCPW	2

int
smb_smb_ssnsetup(struct smb_vc *vcp, struct smb_cred *scred)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	u_int8_t wc;
	int minauth;
	smb_uniptr unipp = NULL, ntencpass = NULL;
	char *pp = NULL, *up = NULL, *ucup = NULL, *ucdp = NULL;
	char *pbuf = NULL;
	char *encpass = NULL;
	int error = 0;
	size_t plen = 0, uniplen = 0, uniplen2 = 0, tmplen;
	size_t ucup_sl = 0, ucdp_sl = 0;
	int state;
	size_t ntlmv2_bloblen;
	uchar_t *ntlmv2_blob;
	u_int64_t client_nonce;
	u_int32_t caps;
	u_int16_t bl; /* BLOB length */
	u_int16_t saveflags2 = vcp->vc_hflags2;
	void *	savetoserver = vcp->vc_toserver;
	u_int16_t action;
	int declinedguest = 0;
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
	    SMB_CAP_STATUS32 |
	    SMB_CAP_LARGE_READX |
	    SMB_CAP_LARGE_WRITEX;

	caps = vcp->vc_sopt.sv_caps & caps_mask;

	/* No unicode unless server supports and encryption on */
	if (!((vcp->vc_sopt.sv_sm & SMB_SM_ENCRYPT) &&
	    (vcp->vc_flags & SMBV_UNICODE))) {
		vcp->vc_hflags2 &= 0xffff - SMB_FLAGS2_UNICODE;
		vcp->vc_toserver = 0;
	}

	minauth = vcp->vc_vopt & SMBVOPT_MINAUTH;
	if (vcp->vc_intok) {
		if (vcp->vc_intoklen > 65536 ||
		    !(vcp->vc_hflags2 & SMB_FLAGS2_EXT_SEC) ||
		    SMB_DIALECT(vcp) < SMB_DIALECT_NTLM0_12) {
			error = EINVAL;
			goto ssn_exit;
		}
		vcp->vc_smbuid = 0;
	}

	/*
	 * Try only plain text passwords.
	 */
	if (vcp->vc_sopt.sv_sm & SMB_SM_ENCRYPT) {
		state = STATE_NTLMV2;	/* try NTLMv2 first */
	} else {
		state = STATE_NOUCPW;	/* try plain-text mixed-case first */
	}
again:

	if (!vcp->vc_intok)
		vcp->vc_smbuid = SMB_UID_UNKNOWN;

	if (!vcp->vc_intok) {
		/*
		 * We're not doing extended security, which, for
		 * now, means we're not doing Kerberos.
		 * Fail if the minimum authentication level is
		 * Kerberos.
		 */
		if (minauth >= SMBVOPT_MINAUTH_KERBEROS) {
			error = EAUTH;
			goto ssn_exit;
		}
		if (vcp->vc_sopt.sv_sm & SMB_SM_ENCRYPT) {
			/*
			 * Server wants encrypted passwords.
			 */
			if (state > STATE_NTLMV2) {
				/*
				 * We tried NTLMv2 in STATE_NTLMV2.
				 * Shall we allow fallback? (to NTLM)
				 */
				if (minauth >= SMBVOPT_MINAUTH_NTLMV2) {
					error = EAUTH;
					goto ssn_exit;
				}
			}
			if (state > STATE_NOUCPW) {
				/*
				 * We tried NTLM in STATE_NOUCPW.
				 * No need to try it again.
				 */
				error = EAUTH;
				goto ssn_exit;
			}
		} else {
			/*
			 * Plain-text passwords.
			 * Fail if the minimum authentication level is
			 * LM or better.
			 */
			if (minauth > SMBVOPT_MINAUTH_NTLM) {
				error = EAUTH;
				goto ssn_exit;
			}
		}
	}

	error = smb_rq_alloc(VCTOCP(vcp), SMB_COM_SESSION_SETUP_ANDX,
	    scred, &rqp);
	if (error)
		goto ssn_exit;

	/*
	 * Domain name must be upper-case, as that's what's used
	 * when computing LMv2 and NTLMv2 responses - and, for NTLMv2,
	 * the domain name in the request has to be upper-cased as well.
	 * (That appears not to be the case for the user name.  Go
	 * figure.)
	 *
	 * don't need to uppercase domain string. It's already uppercase UTF-8.
	 */

	ucdp_sl = strlen(vcp->vc_domain);
	ucdp = kmem_zalloc(ucdp_sl + 1, KM_SLEEP);
	memcpy(ucdp, vcp->vc_domain, ucdp_sl + 1);

	if (vcp->vc_intok) {
		caps |= SMB_CAP_EXT_SECURITY;
	} else if (!(vcp->vc_sopt.sv_sm & SMB_SM_USER)) {
		/*
		 * In the share security mode password will be used
		 * only in the tree authentication
		 */
		pp = "";
		plen = 1;
		unipp = &smb_unieol;
		uniplen = sizeof (smb_unieol);
	} else {
		pbuf = kmem_alloc(SMB_MAXPASSWORDLEN + 1, KM_SLEEP);
		if (vcp->vc_sopt.sv_sm & SMB_SM_ENCRYPT) {
			if (state == STATE_NTLMV2) {
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
				 * Compute the LMv2 response, derived
				 * from the server challenge, the
				 * user name, the domain/workgroup
				 * into which we're logging, the
				 * client nonce, and the NT hash.
				 */
				smb_ntlmv2response(vcp->vc_nthash,
				    (uchar_t *)ucup, (uchar_t *)ucdp,
				    vcp->vc_challenge,
				    (uchar_t *)&client_nonce, 8,
				    (uchar_t **)&encpass, &plen);
				pp = encpass;

				/*
				 * Construct the blob.
				 */
				ntlmv2_blob = make_ntlmv2_blob(vcp,
				    client_nonce, &ntlmv2_bloblen);

				/*
				 * Compute the NTLMv2 response, derived
				 * from the server challenge, the
				 * user name, the domain/workgroup
				 * into which we're logging, the
				 * blob, and the NT hash.
				 */
				smb_ntlmv2response(vcp->vc_nthash,
				    (uchar_t *)ucup, (uchar_t *)ucdp,
				    vcp->vc_challenge,
				    ntlmv2_blob, ntlmv2_bloblen,
				    (uchar_t **)&ntencpass, &uniplen);
				uniplen2 = uniplen;
				unipp = ntencpass;
				tmplen = plen;

				kmem_free(ucup, ucup_sl + 1);
				kmem_free((char *)ntlmv2_blob,
				    sizeof (struct ntlmv2_blobhdr) +
				    3 * sizeof (struct ntlmv2_namehdr) +
				    4 +
				    2 *  strlen(vcp->vc_domain) +
				    2 * strlen(vcp->vc_srvname));
			} else {
				plen = 24;
				encpass = kmem_zalloc(plen, KM_SLEEP);
				/*
				 * Compute the LM response, derived
				 * from the challenge and the ASCII
				 * password.
				 */
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
				uniplen = 24;
				uniplen2 = uniplen;
				ntencpass = kmem_alloc(uniplen, KM_SLEEP);
				smb_lmresponse(vcp->vc_nthash,
				    vcp->vc_challenge,
				    (uchar_t *)ntencpass);
				unipp = ntencpass;
			}
		} else {
			/*
			 * We try w/o uppercasing first so Samba mixed case
			 * passwords work.  If that fails, we come back and
			 * try uppercasing to satisfy OS/2 and Windows for
			 * Workgroups.
			 */
			get_ascii_password(vcp, (state == STATE_UCPW), pbuf);
			plen = strlen(pbuf) + 1;
			pp = pbuf;
			uniplen = plen * 2;
			uniplen2 = uniplen;
			ntencpass = kmem_alloc(uniplen, KM_SLEEP);
			(void) smb_strtouni(ntencpass, smb_vc_getpass(vcp),
			    0, 0);
			plen--;
			/*
			 * The uniplen is zeroed because Samba cannot deal
			 * with this 2nd cleartext password.  This Samba
			 * "bug" is actually a workaround for problems in
			 * Microsoft clients.
			 */
			uniplen = 0; /* -= 2 */
			unipp = ntencpass;
		}
	}
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
	if (ntencpass) {
		kmem_free(ntencpass, uniplen2);
		ntencpass = NULL;
	}
	if (encpass) {
		kmem_free(encpass, 24);
		encpass = NULL;
	}
	if (ucdp) {
		kmem_free(ucdp, ucdp_sl + 1);
		ucdp = NULL;
	}

	/*
	 * This request should not wait for
	 * connection state changes, etc.
	 */
	rqp->sr_flags |= SMBR_INTERNAL;
	error = smb_rq_simple_timed(rqp, SMBSSNSETUPTIMO);
	SMBSDEBUG("%d\n", error);
	if (error) {
		if (rqp->sr_errclass == ERRDOS && rqp->sr_serror == ERRnoaccess)
			error = EAUTH;
		if (!(rqp->sr_errclass == ERRDOS &&
		    rqp->sr_serror == ERRmoredata))
			goto bad;
	}
	vcp->vc_smbuid = rqp->sr_rpuid;
	smb_rq_getreply(rqp, &mdp);
	do {
		error = md_get_uint8(mdp, &wc);
		if (error)
			break;
		error = EBADRPC;
		if (vcp->vc_intok) {
			if (wc != 4)
				break;
		} else if (wc != 3)
			break;
		md_get_uint8(mdp, NULL);	/* secondary cmd */
		md_get_uint8(mdp, NULL);	/* mbz */
		md_get_uint16le(mdp, NULL);	/* andxoffset */
		md_get_uint16le(mdp, &action);	/* action */
		if (vcp->vc_intok)
			md_get_uint16le(mdp, &bl);	/* ext security */
		md_get_uint16le(mdp, NULL); /* byte count */
		if (vcp->vc_intok) {
			vcp->vc_outtoklen =  bl;
			vcp->vc_outtok = kmem_alloc(bl, KM_SLEEP);
			error = md_get_mem(mdp, vcp->vc_outtok, bl, MB_MSYSTEM);
			if (error)
				break;
		}
		/* server OS, LANMGR, & Domain here */
		error = 0;
		/*LINTED*/
	} while (0);
bad:
	if (encpass) {
		kmem_free(encpass, tmplen);
		encpass = NULL;
	}
	if (pbuf) {
		kmem_free(pbuf, SMB_MAXPASSWORDLEN + 1);
		pbuf = NULL;
	}
	if (vcp->vc_sopt.sv_sm & SMB_SM_USER && !vcp->vc_intok &&
	    (error || (*up != '\0' && action & SMB_ACT_GUEST &&
	    state == STATE_NTLMV2 && smb_antique(rqp)))) {
		/*
		 * We're doing user-level authentication (so we are actually
		 * sending authentication stuff over the wire), and we're
		 * not doing extended security, and the stuff we tried
		 * failed (or we we're trying to login a real user but
		 * got granted guest access instead.)
		 */
		if (!error)
			declinedguest = 1;
		/*
		 * Should we try the next type of authentication?
		 */
		if (state < STATE_UCPW) {
			/*
			 * Yes, we still have more to try.
			 */
			state++;
			smb_rq_done(rqp);
			goto again;
		}
	}
	smb_rq_done(rqp);

ssn_exit:
	if (error && declinedguest)
		SMBERROR("we declined ntlmv2 guest access. errno will be %d\n",
		    error);
	/* Restore things we changed and return */
	vcp->vc_hflags2 = saveflags2;
	vcp->vc_toserver = savetoserver;
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

static int
smb_smb_readx(struct smb_share *ssp, u_int16_t fid, int *len, int *rresid,
	uio_t *uiop, struct smb_cred *scred, int timo)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	u_int8_t wc;
	int error;
	u_int16_t residhi, residlo, off, doff;
	u_int32_t resid;

	if ((vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_READX) == 0) {
		/* Fall back to the old cmd. */
		return (smb_smb_read(ssp, fid, len, rresid, uiop,
		    scred, timo));
	}
	if ((vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_FILES) == 0) {
		/* Have ReadX but not large files? */
		if ((uiop->uio_loffset + *len) > UINT32_MAX)
			return (EFBIG);
	}
	*len = min(*len, vcp->vc_rxmax);

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_READ_ANDX, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);	/* no secondary command */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, 0);	/* offset to secondary */
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
	mb_put_uint32le(mbp, (u_int32_t)(uiop->uio_offset));
	mb_put_uint16le(mbp, (u_int16_t)*len);	/* MaxCount */
	mb_put_uint16le(mbp, (u_int16_t)*len);	/* MinCount */
						/* (only indicates blocking) */
	mb_put_uint32le(mbp, (unsigned)*len >> 16);	/* MaxCountHigh */
	mb_put_uint16le(mbp, (u_int16_t)*len);	/* Remaining ("obsolete") */
	mb_put_uint32le(mbp, (u_int32_t)((uiop->uio_loffset) >> 32));
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
		off = SMB_HDRLEN;
		md_get_uint8(mdp, &wc);
		off++;
		if (wc != 12) {
			error = EBADRPC;
			break;
		}
		md_get_uint8(mdp, NULL);
		off++;
		md_get_uint8(mdp, NULL);
		off++;
		md_get_uint16le(mdp, NULL);
		off += 2;
		md_get_uint16le(mdp, NULL);
		off += 2;
		md_get_uint16le(mdp, NULL);	/* data compaction mode */
		off += 2;
		md_get_uint16le(mdp, NULL);
		off += 2;
		md_get_uint16le(mdp, &residlo);
		off += 2;
		md_get_uint16le(mdp, &doff);	/* data offset */
		off += 2;
		md_get_uint16le(mdp, &residhi);
		off += 2;
		resid = (residhi << 16) | residlo;
		md_get_mem(mdp, NULL, 4 * 2, MB_MSYSTEM);
		off += 4*2;
		md_get_uint16le(mdp, NULL);	/* ByteCount */
		off += 2;
		if (doff > off)	/* pad byte(s)? */
			md_get_mem(mdp, NULL, doff - off, MB_MSYSTEM);
		if (resid == 0) {
			*rresid = resid;
			break;
		}
		error = md_get_uio(mdp, uiop, resid);
		if (error)
			break;
		*rresid = resid;
		/*LINTED*/
	} while (0);
	smb_rq_done(rqp);
	return (error);
}

static int
smb_smb_writex(struct smb_share *ssp, u_int16_t fid, int *len, int *rresid,
	uio_t *uiop, struct smb_cred *scred, int timo)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;
	u_int8_t wc;
	u_int16_t resid;

	if ((vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_WRITEX) == 0) {
		/* Fall back to the old cmd. */
		return (smb_smb_write(ssp, fid, len, rresid, uiop,
		    scred, timo));
	}
	if ((vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_FILES) == 0) {
		/* Have WriteX but not large files? */
		if ((uiop->uio_loffset + *len) > UINT32_MAX)
			return (EFBIG);
	}
	*len = min(*len, vcp->vc_wxmax);

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_WRITE_ANDX, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);	/* no secondary command */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, 0);	/* offset to secondary */
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
	mb_put_uint32le(mbp, (u_int32_t)(uiop->uio_offset));
	mb_put_uint32le(mbp, 0);	/* MBZ (timeout) */
	mb_put_uint16le(mbp, 0);	/* !write-thru */
	mb_put_uint16le(mbp, 0);
	mb_put_uint16le(mbp, (u_int16_t)((unsigned)*len >> 16));
	mb_put_uint16le(mbp, (u_int16_t)*len);
	mb_put_uint16le(mbp, 64);	/* data offset from header start */
	mb_put_uint32le(mbp, (u_int32_t)((uiop->uio_loffset) >> 32));
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	do {
		mb_put_uint8(mbp, 0xee);	/* mimic xp pad byte! */
		error = mb_put_uio(mbp, uiop, *len);
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
		md_get_uint8(mdp, NULL);
		md_get_uint8(mdp, NULL);
		md_get_uint16le(mdp, NULL);
		md_get_uint16le(mdp, &resid); /* actually is # written */
		*rresid = resid;
		/*
		 * if LARGE_WRITEX then there's one more bit of # written
		 */
		if ((vcp->vc_sopt.sv_caps & SMB_CAP_LARGE_WRITEX)) {
			md_get_uint16le(mdp, NULL);
			md_get_uint16le(mdp, &resid);
			*rresid |= (int)(resid & 1) << 16;
		}
		/*LINTED*/
	} while (0);

	smb_rq_done(rqp);
	return (error);
}

static int
smb_smb_read(struct smb_share *ssp, u_int16_t fid, int *len, int *rresid,
	uio_t *uiop, struct smb_cred *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	u_int16_t resid, bc;
	u_int8_t wc;
	int error, rlen;

	/* This cmd is limited to 32-bit offsets. */
	if ((uiop->uio_loffset + *len) > UINT32_MAX)
		return (EFBIG);
	*len = rlen = min(*len, SSTOVC(ssp)->vc_rxmax);

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_READ, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
	mb_put_uint16le(mbp, (u_int16_t)rlen);
	mb_put_uint32le(mbp, (u_int32_t)uiop->uio_offset);
	mb_put_uint16le(mbp, (u_int16_t)min(uiop->uio_resid, 0xffff));
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
		md_get_uint16le(mdp, &resid);
		md_get_mem(mdp, NULL, 4 * 2, MB_MSYSTEM);
		md_get_uint16le(mdp, &bc);
		md_get_uint8(mdp, NULL);		/* ignore buffer type */
		md_get_uint16le(mdp, &resid);
		if (resid == 0) {
			*rresid = resid;
			break;
		}
		error = md_get_uio(mdp, uiop, resid);
		if (error)
			break;
		*rresid = resid;
		/*LINTED*/
	} while (0);
	smb_rq_done(rqp);
	return (error);
}

static int
smb_smb_write(struct smb_share *ssp, u_int16_t fid, int *len, int *rresid,
	uio_t *uiop, struct smb_cred *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	u_int16_t resid;
	u_int8_t wc;
	int error;

	/* This cmd is limited to 32-bit offsets. */
	if ((uiop->uio_loffset + *len) > UINT32_MAX)
		return (EFBIG);
	*len = resid = min(*len, SSTOVC(ssp)->vc_wxmax);

	error = smb_rq_alloc(SSTOCP(ssp), SMB_COM_WRITE, scred, &rqp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_mem(mbp, (caddr_t)&fid, sizeof (fid), MB_MSYSTEM);
	mb_put_uint16le(mbp, resid);
	mb_put_uint32le(mbp, (u_int32_t)uiop->uio_offset);
	mb_put_uint16le(mbp, (u_int16_t)min(uiop->uio_resid, 0xffff));
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	mb_put_uint8(mbp, SMB_DT_DATA);
	mb_put_uint16le(mbp, resid);
	do {
		error = mb_put_uio(mbp, uiop, resid);
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
		md_get_uint16le(mdp, &resid);
		*rresid = resid;
		/*LINTED*/
	} while (0);
	smb_rq_done(rqp);
	return (error);
}

/*
 * Common function for read/write with UIO.
 * Called by netsmb smb_usr_rw,
 *  smbfs_readvnode, smbfs_writevnode
 */
int
smb_rwuio(struct smb_share *ssp, u_int16_t fid, uio_rw_t rw,
	uio_t *uiop, struct smb_cred *scred, int timo)
{
	ssize_t  old_resid, tsize;
	offset_t  old_offset;
	int len, resid;
	int error = 0;

	old_offset = uiop->uio_loffset;
	old_resid = tsize = uiop->uio_resid;

	while (tsize > 0) {
		/* Lint: tsize may be 64-bits */
		len = SMB_MAX_LARGE_RW_SIZE;
		if (len > tsize)
			len = (int)tsize;

		if (rw == UIO_READ)
			error = smb_smb_readx(ssp, fid, &len, &resid, uiop,
			    scred, timo);
		else
			error = smb_smb_writex(ssp, fid, &len, &resid, uiop,
			    scred, timo);
		if (error)
			break;

		if (resid < len) {
			error = EIO;
			break;
		}

		tsize -= resid;
		timo = 0; /* only first write is special */
	}

	if (error) {
		/*
		 * Errors can happen in copyin/copyout, the rpc, etc. so
		 * they imply resid is unreliable.  The only safe thing is
		 * to pretend zero bytes made it.  We needn't restore the
		 * iovs because callers don't depend on them in error
		 * paths - uio_resid and uio_offset are what matter.
		 */
		uiop->uio_loffset = old_offset;
		uiop->uio_resid = old_resid;
	}

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
