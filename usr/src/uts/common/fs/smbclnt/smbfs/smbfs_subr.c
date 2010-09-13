/*
 * Copyright (c) 2000-2001, Boris Popov
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
 * $Id: smbfs_subr.c,v 1.18 2005/02/02 00:22:23 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/sunddi.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_rq.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

/*
 * In the Darwin code, this function used to compute the full path
 * by following the chain of n_parent pointers back to the root.
 * In the Solaris port we found the n_parent pointers inconvenient
 * because they hold parent nodes busy.  We now keep the full path
 * in every node, so this function need only marshall the directory
 * path, and (if provided) the separator and last component name.
 *
 * Note that this logic must match that in smbfs_getino
 */
int
smbfs_fullpath(struct mbchain *mbp, struct smb_vc *vcp, struct smbnode *dnp,
	const char *name, int *lenp, u_int8_t sep)
{
	int caseopt = SMB_CS_NONE;
	int error, len = 0;
	int unicode = (SMB_UNICODE_STRINGS(vcp)) ? 1 : 0;

	if (SMB_DIALECT(vcp) < SMB_DIALECT_LANMAN1_0)
		caseopt |= SMB_CS_UPPER;

	if (lenp) {
		len = *lenp;
		*lenp = 0;
	}
	if (unicode) {
		error = mb_put_padbyte(mbp);
		if (error)
			return (error);
	}

	error = smb_put_dmem(mbp, vcp,
	    dnp->n_rpath, dnp->n_rplen,
	    caseopt, lenp);
	if (name) {
		/*
		 * Special case at share root:
		 * Don't put another slash.
		 */
		if (dnp->n_rplen <= 1 && sep == '\\')
			sep = 0;
		/*
		 * More special cases, now for XATTR:
		 * Our "faked up" XATTR directories use a
		 * full path name ending with ":" so as to
		 * avoid conflicts with any real paths.
		 * (It is not a valid CIFS path name.)
		 * Therefore, when we're composing a full
		 * path name from an XATTR directory, we
		 * need to _ommit_ the ":" separator and
		 * instead copy the one from the "fake"
		 * parent node's path name.
		 */
		if (dnp->n_flag & N_XATTR)
			sep = 0;

		if (sep) {
			/* Put the separator */
			if (unicode)
				error = mb_put_uint16le(mbp, sep);
			else
				error = mb_put_uint8(mbp, sep);
			if (!error && lenp)
				*lenp += (unicode + 1);
			if (error)
				return (error);
		}
		/* Put the name */
		error = smb_put_dmem(mbp, vcp,
		    name, len, caseopt, lenp);
		if (error)
			return (error);
	}
	/* Put NULL termination. */
	if (unicode)
		error = mb_put_uint16le(mbp, 0);
	else
		error = mb_put_uint8(mbp, 0);
	if (!error && lenp)
		*lenp += (unicode + 1);

	return (error);
}

/*
 * Convert a Unicode directory entry to UTF-8
 */
void
smbfs_fname_tolocal(struct smbfs_fctx *ctx)
{
	uchar_t tmpbuf[SMB_MAXFNAMELEN+1];
	struct smb_vc *vcp = SSTOVC(ctx->f_ssp);
	uchar_t *dst;
	const ushort_t *src;
	size_t inlen, outlen;
	int flags;

	if (ctx->f_nmlen == 0)
		return;

	if (!SMB_UNICODE_STRINGS(vcp))
		return;

	if (ctx->f_namesz < sizeof (tmpbuf)) {
		ASSERT(0);
		goto errout;
	}

	/*
	 * In-place conversions are not supported,
	 * so convert into tmpbuf and copy.
	 */
	dst = tmpbuf;
	outlen = SMB_MAXFNAMELEN;
	/*LINTED*/
	src = (const ushort_t *)ctx->f_name;
	inlen = ctx->f_nmlen / 2;	/* number of UCS-2 characters */
	flags = UCONV_IN_LITTLE_ENDIAN;

	if (uconv_u16tou8(src, &inlen, dst, &outlen, flags) != 0)
		goto errout;

	ASSERT(outlen < sizeof (tmpbuf));
	tmpbuf[outlen] = '\0';
	bcopy(tmpbuf, ctx->f_name, outlen + 1);
	ctx->f_nmlen = (int)outlen;
	return;

errout:
	/*
	 * Conversion failed, but our caller does not
	 * deal with errors here, so just put a "?".
	 * Don't expect to ever see this.
	 */
	(void) strlcpy(ctx->f_name, "?", ctx->f_namesz);
}
