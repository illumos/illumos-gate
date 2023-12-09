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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/sunddi.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb2.h>
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
	const char *name, int nmlen, u_int8_t sep)
{
	int caseopt = SMB_CS_NONE;
	int unicode = (SMB_UNICODE_STRINGS(vcp)) ? 1 : 0;
	int error;

	/*
	 * SMB1 may need an alignment pad before (not SMB2)
	 */
	if (((vcp)->vc_flags & SMBV_SMB2) == 0 &&
	    ((vcp)->vc_hflags2 & SMB_FLAGS2_UNICODE) != 0) {
		error = mb_put_padbyte(mbp);
		if (error)
			return (error);
	}

	error = smb_put_dmem(mbp, vcp,
	    dnp->n_rpath, dnp->n_rplen,
	    caseopt, NULL);
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
			if (error)
				return (error);
		}
		/* Put the name */
		error = smb_put_dmem(mbp, vcp,
		    name, nmlen, caseopt, NULL);
		if (error)
			return (error);
	}

	/* SMB1 wants NULL termination. */
	if (((vcp)->vc_flags & SMBV_SMB2) == 0) {
		if (unicode)
			error = mb_put_uint16le(mbp, 0);
		else
			error = mb_put_uint8(mbp, 0);
	}

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

/*
 * Decode a directory entry from OtW form into ctx->f_attr
 *
 * Caller already put some (wire-format) directory entries
 * into ctx->f_mdchain and we expect to find one.
 *
 * Advancing correctly through the buffer can be tricky if one
 * tries to add up the size of an entry as you go (which is how
 * the darwin code this is derived from did it).  The easiest way
 * to correctly advance the position is to get a whole dirent
 * into another mdchain (entry_mdc) based on NextEntryOffset,
 * and then scan the data from that mdchain.  On the last entry,
 * we don't know the entire length, so just scan directly from
 * what remains of the multi-entry buffer instead of trying to
 * figure out the length to copy into a separate mdchain.
 */
int
smbfs_decode_dirent(struct smbfs_fctx *ctx)
{
	struct mdchain entry_mdc;
	struct mdchain *mdp = &ctx->f_mdchain;
	size_t nmlen;
	uint64_t llongint;
	uint32_t nmsize, dattr;
	uint32_t nextoff = 0;
	int error;

	/* In case we error out... */
	ctx->f_nmlen = 0;
	ctx->f_rkey = (uint32_t)-1;
	bzero(&entry_mdc, sizeof (entry_mdc));

	/*
	 * Setup mdp to point to an mbchain holding
	 * what should be a single directory entry.
	 */
	error = md_get_uint32le(mdp, &nextoff);
	if (error != 0)
		goto errout;
	if (nextoff >= 4) {
		/*
		 * More entries follow.  Make a new mbchain
		 * holding just this one entry, then advance.
		 */
		mblk_t *m = NULL;
		error = md_get_mbuf(mdp, nextoff - 4, &m);
		if (error != 0)
			goto errout;
		md_initm(&entry_mdc, m);
		mdp = &entry_mdc;
		ctx->f_eofs += nextoff;
	} else {
		/* Scan directly from ctx->f_mdchain */
		ctx->f_eofs = ctx->f_left;
	}

	/*
	 * Decode the fixed-size parts
	 */
	switch (ctx->f_infolevel) {
	case FileFullDirectoryInformation:
	case SMB_FIND_FULL_DIRECTORY_INFO:
		md_get_uint32le(mdp, &ctx->f_rkey);	/* resume key (idx) */
		md_get_uint64le(mdp, &llongint);	/* creation time */
		smb_time_NT2local(llongint, &ctx->f_attr.fa_createtime);
		md_get_uint64le(mdp, &llongint);
		smb_time_NT2local(llongint, &ctx->f_attr.fa_atime);
		md_get_uint64le(mdp, &llongint);
		smb_time_NT2local(llongint, &ctx->f_attr.fa_mtime);
		md_get_uint64le(mdp, &llongint);
		smb_time_NT2local(llongint, &ctx->f_attr.fa_ctime);
		md_get_uint64le(mdp, &llongint);	/* file size */
		ctx->f_attr.fa_size = llongint;
		md_get_uint64le(mdp, &llongint);	/* alloc. size */
		ctx->f_attr.fa_allocsz = llongint;
		md_get_uint32le(mdp, &dattr);	/* ext. file attributes */
		ctx->f_attr.fa_attr = dattr;
		error = md_get_uint32le(mdp, &nmsize);	/* name size (otw) */
		if (error)
			goto errout;
		md_get_uint32le(mdp, NULL);	/* Ea size */
		break;

	case FileStreamInformation:
		error = md_get_uint32le(mdp, &nmsize);	/* name size (otw) */
		md_get_uint64le(mdp, &llongint);	/* file size */
		ctx->f_attr.fa_size = llongint;
		md_get_uint64le(mdp, &llongint);	/* alloc. size */
		ctx->f_attr.fa_allocsz = llongint;
		/*
		 * Stream names start with a ':' that we want to skip.
		 * This is the easiest place to take care of that.
		 * Always unicode here.
		 */
		if (nmsize >= 2) {
			struct mdchain save_mdc;
			uint16_t wch;
			save_mdc = *mdp;
			md_get_uint16le(mdp, &wch);
			if (wch == ':') {
				/* OK, we skipped the ':' */
				nmsize -= 2;
			} else {
				SMBVDEBUG("No leading : in stream?\n");
				/* restore position */
				*mdp = save_mdc;
			}
		}
		break;

	default:
		SMBVDEBUG("unexpected info level %d\n", ctx->f_infolevel);
		error = EINVAL;
		goto errout;
	}

	/*
	 * Get the filename, and convert to utf-8
	 * Allocated f_name in findopen
	 */
	nmlen = ctx->f_namesz;
	error = smb_get_dstring(mdp, SSTOVC(ctx->f_ssp),
	    ctx->f_name, &nmlen, nmsize);
	if (error != 0)
		goto errout;
	ctx->f_nmlen = (int)nmlen;
	md_done(&entry_mdc);
	return (0);

errout:
	/*
	 * Something bad has happened and we ran out of data
	 * before we could parse all f_ecnt entries expected.
	 * Give up on the current buffer.
	 */
	SMBVDEBUG("ran out of data\n");
	ctx->f_eofs = ctx->f_left;
	md_done(&entry_mdc);
	return (error);
}

/*
 * Decode FileAllInformation
 *
 * The data is a concatenation of:
 *	FileBasicInformation
 *	FileStandardInformation
 *	FileInternalInformation
 *	FileEaInformation
 *	FileAccessInformation
 *	FilePositionInformation
 *	FileModeInformation
 *	FileAlignmentInformation
 *	FileNameInformation
 */
/*ARGSUSED*/
int
smbfs_decode_file_all_info(struct smb_share *ssp,
	struct mdchain *mdp, struct smbfattr *fap)
{
	uint64_t llongint, lsize;
	uint32_t dattr;
	int error;

	/*
	 * This part is: FileBasicInformation
	 */

	/* creation time */
	md_get_uint64le(mdp, &llongint);
	smb_time_NT2local(llongint, &fap->fa_createtime);

	/* last access time */
	md_get_uint64le(mdp, &llongint);
	smb_time_NT2local(llongint, &fap->fa_atime);

	/* last write time */
	md_get_uint64le(mdp, &llongint);
	smb_time_NT2local(llongint, &fap->fa_mtime);

	/* last change time */
	md_get_uint64le(mdp, &llongint);
	smb_time_NT2local(llongint, &fap->fa_ctime);

	/* attributes */
	md_get_uint32le(mdp, &dattr);
	fap->fa_attr = dattr;

	/* reserved */
	md_get_uint32le(mdp, NULL);

	/*
	 * This part is: FileStandardInformation
	 */

	/* allocation size */
	md_get_uint64le(mdp, &lsize);
	fap->fa_allocsz = lsize;

	/* File size */
	error = md_get_uint64le(mdp, &lsize);
	fap->fa_size = lsize;

	/*
	 * There's more after this but we don't need it:
	 * Remainder of FileStandardInformation
	 *	NumLlinks, DeletOnClose, IsDir, reserved.
	 * Then:
	 *	FileInternalInformation
	 *	FileEaInformation
	 *	FileAccessInformation
	 *	FilePositionInformation
	 *	FileModeInformation
	 *	FileAlignmentInformation
	 *	FileNameInformation
	 */

	return (error);
}

/*
 * Decode FileFsAttributeInformation
 *
 *    ULONG FileSystemAttributes;
 *    LONG MaximumComponentNameLength;
 *    ULONG FileSystemNameLength;
 *    WCHAR FileSystemName[1];
 */
int
smbfs_decode_fs_attr_info(struct smb_share *ssp,
	struct mdchain *mdp, struct smb_fs_attr_info *fsa)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	uint32_t nlen;
	int error;

	md_get_uint32le(mdp, &fsa->fsa_aflags);
	md_get_uint32le(mdp, &fsa->fsa_maxname);
	error = md_get_uint32le(mdp, &nlen);	/* fs name length */
	if (error)
		goto out;

	/*
	 * Get the FS type name.
	 */
	bzero(fsa->fsa_tname, FSTYPSZ);
	if (SMB_UNICODE_STRINGS(vcp)) {
		uint16_t tmpbuf[FSTYPSZ];
		size_t tmplen, outlen;

		if (nlen > sizeof (tmpbuf))
			nlen = sizeof (tmpbuf);
		error = md_get_mem(mdp, tmpbuf, nlen, MB_MSYSTEM);
		if (error != 0)
			goto out;
		tmplen = nlen / 2;	/* UCS-2 chars */
		outlen = FSTYPSZ - 1;
		error = uconv_u16tou8(tmpbuf, &tmplen,
		    (uchar_t *)fsa->fsa_tname, &outlen,
		    UCONV_IN_LITTLE_ENDIAN);
	} else {
		if (nlen > (FSTYPSZ - 1))
			nlen = FSTYPSZ - 1;
		error = md_get_mem(mdp, fsa->fsa_tname, nlen, MB_MSYSTEM);
	}

out:
	return (error);
}
