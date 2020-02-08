/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Simple nfs V4 ops
 */

#include <rpc/types.h>
#include <rpc/auth.h>
#include <sys/t_lock.h>
#include "clnt.h"
#include <sys/fcntl.h>
#include <sys/vfs.h>
#include <errno.h>
#include <sys/promif.h>
#include <rpc/xdr.h>
#include "nfs_inet.h"
#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/bootdebug.h>
#include <sys/salib.h>
#include <sys/sacache.h>
#include <rpc/rpc.h>
#include "brpc.h"
#include <rpcsvc/nfs4_prot.h>

#define	dprintf	if (boothowto & RB_DEBUG) printf

static struct timeval zero_timeout = {0, 0};	/* default */

/*
 * NFS Version 4 specific functions
 */

ssize_t
nfs4read(struct nfs_file *filep, char *buf, size_t size)
{
	enum clnt_stat	status;
	read4arg_t	readargs;
	read4res_t	readres;
	char		*buf_offset;
	uint_t		count = 0;
	uint_t		readcnt = 0;
	bool_t		done = FALSE;
	struct timeval	timeout;
	int		framing_errs = 0;
	static uint_t	pos;
	static char	ind[] = "|/-\\";
	static int	blks_read;
	utf8string	str;
	char		tagname[] = "inetboot read";

	bzero(&readres, sizeof (readres));

	str.utf8string_len = sizeof (tagname) - 1;
	str.utf8string_val = tagname;

	/*
	 * read
	 */
	buf_offset = buf;

	if (nfs_readsize == 0)
		nfs_readsize = READ4_SIZE;

	if (size < nfs_readsize)
		readargs.r_count = size;
	else
		readargs.r_count = nfs_readsize;

	if (filep->fh.fh4.len > 0)
		compound_init(&readargs.r_arg, &str, 0, 2, &filep->fh.fh4);
	else
		compound_init(&readargs.r_arg, &str, 0, 2, NULL);

	readargs.r_opread = OP_READ;
	/*
	 * zero out the stateid field
	 */
	bzero(&readargs.r_stateid, sizeof (readargs.r_stateid));
	readargs.r_offset = filep->offset;

	do {
		readres.r_data_val = buf_offset;

		if ((count + readargs.r_count) > size)
			readargs.r_count = size - count;

		timeout.tv_sec = NFS_REXMIT_MIN;
		timeout.tv_usec = 0;

		do {
			status = CLNT_CALL(root_CLIENT, NFSPROC4_COMPOUND,
			    xdr_read4_args, (caddr_t)&readargs,
			    xdr_read4_res, (caddr_t)&readres,
			    timeout);

			if (status == RPC_TIMEDOUT) {
				dprintf("NFS read(%d) timed out. Retrying...\n",
				    readargs.r_count);
				if (errno == ETIMEDOUT)
					framing_errs++;

				if (framing_errs > NFS_MAX_FERRS &&
				    readargs.r_count > NFS_READ_DECR) {
					readargs.r_count /= 2;
					nfs_readsize /= 2;
					dprintf("NFS read size now %d.\n",
					    nfs_readsize);
					timeout.tv_sec = NFS_REXMIT_MIN;
					framing_errs = 0;
				} else {
					if (timeout.tv_sec < NFS_REXMIT_MAX)
						timeout.tv_sec++;
					else
						timeout.tv_sec = 0;
				}
			}
		} while (status == RPC_TIMEDOUT);

		if (status != RPC_SUCCESS)
			return (-1);

		if (readres.r_status != NFS4_OK) {
			nfs4_error(readres.r_status);
			return (-1);
		}

		readcnt = readres.r_data_len;

		if (readres.r_eof == TRUE)
			done = TRUE;

		if (readcnt < readargs.r_count) {
#ifdef NFS_OPS_DEBUG
			if ((boothowto & DBFLAGS) == DBFLAGS)
				printf("nfs4read: partial read %d instead "
				"of %d\n", readcnt, readargs.count);
#endif
			done = TRUE;
		}

		count += readcnt;
		filep->offset += readcnt;
		buf_offset += readcnt;
		readargs.r_offset += readcnt;
		if ((blks_read++ & 0x3) == 0)
			printf("%c\b", ind[pos++ & 3]);
	} while (count < size && !done);

	return (count);
}


static vtype_t nf4_to_vt[] = {
	VBAD, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO
};

int
nfs4getattr(struct nfs_file *nfp, struct vattr *vap)
{
	enum clnt_stat	status;
	attr4_bitmap1_t bitmap1;
	attr4_bitmap2_t bitmap2;
	getattr4arg_t	getattrargs;
	getattr4res_t	getattrres;
	b_fattr4_t	*bfattr4;
	utf8string	str;
	char		tagname[] = "inetboot getattr";

	bzero(&getattrres, sizeof (getattrres));
	/*
	 * Putfh
	 */
	str.utf8string_len = sizeof (tagname) - 1;
	str.utf8string_val = tagname;

	if (nfp->fh.fh4.len > 0)
		compound_init(&getattrargs.ga_arg, &str, 0, 2, &nfp->fh.fh4);
	else
		compound_init(&getattrargs.ga_arg, &str, 0, 2, NULL);

	/*
	 * getattr
	 */
	getattrargs.ga_opgetattr = OP_GETATTR;
	/*
	 * Set up the attribute bitmap.  We pretty much need everything
	 * except for the filehandle and supported attrs.
	 */
	bitmap1.word = 0;
	bitmap1.bm_fattr4_type = 1;
	bitmap1.bm_fattr4_size = 1;
	bitmap1.bm_fattr4_fileid = 1;
	bitmap2.word = 0;
	bitmap2.bm_fattr4_mode = 1;
	bitmap2.bm_fattr4_time_access = 1;
	bitmap2.bm_fattr4_time_metadata = 1;
	bitmap2.bm_fattr4_time_modify = 1;

	getattrargs.ga_attr_req.b_bitmap_len = NFS4_MAX_BITWORDS;
	getattrargs.ga_attr_req.b_bitmap_val[0] = bitmap1.word;
	getattrargs.ga_attr_req.b_bitmap_val[1] = bitmap2.word;

	status = CLNT_CALL(root_CLIENT, NFSPROC4_COMPOUND, xdr_getattr4_args,
	    (caddr_t)&getattrargs, xdr_getattr4_res,
	    (caddr_t)&getattrres, zero_timeout);

	if (status != RPC_SUCCESS) {
		dprintf("nfs4getattr: RPC error %d\n", status);
		return (-1);
	}

	if (getattrres.gr_attr_status != NFS4_OK) {
		nfs4_error(getattrres.gr_attr_status);
		return (getattrres.gr_attr_status);
	}

	bfattr4 = &getattrres.gr_attrs;
	if (vap->va_mask & AT_TYPE) {
		if (bfattr4->b_fattr4_type < NF4REG ||
		    bfattr4->b_fattr4_type > NF4FIFO)
			vap->va_type = VBAD;
		else
			vap->va_type = nf4_to_vt[bfattr4->b_fattr4_type];
	}
	if (vap->va_mask & AT_MODE)
		vap->va_mode = (mode_t)bfattr4->b_fattr4_mode;
	if (vap->va_mask & AT_SIZE)
		vap->va_size = (u_offset_t)bfattr4->b_fattr4_size;
	if (vap->va_mask & AT_NODEID)
		vap->va_nodeid = (uint64_t)bfattr4->b_fattr4_fileid;
	/*
	 * XXX - may need to do something more here.
	 */
	if (vap->va_mask & AT_ATIME) {
		vap->va_atime.tv_sec = bfattr4->b_fattr4_time_access.seconds;
		vap->va_atime.tv_nsec = bfattr4->b_fattr4_time_access.nseconds;
	}
	if (vap->va_mask & AT_CTIME) {
		vap->va_ctime.tv_sec = bfattr4->b_fattr4_time_metadata.seconds;
		vap->va_ctime.tv_nsec =
		    bfattr4->b_fattr4_time_metadata.nseconds;
	}
	if (vap->va_mask & AT_MTIME) {
		vap->va_mtime.tv_sec = bfattr4->b_fattr4_time_modify.seconds;
		vap->va_mtime.tv_nsec = bfattr4->b_fattr4_time_modify.nseconds;
	}

	return (NFS4_OK);
}

/*
 * Display nfs error messages.
 */
/*ARGSUSED*/
void
nfs4_error(enum nfsstat4 status)
{
	if (!(boothowto & RB_DEBUG))
		return;

	switch (status) {
	case NFS4_OK:
		printf("NFS: No error.\n");
		break;
	case NFS4ERR_PERM:
		printf("NFS: Not owner.\n");
		break;
	case NFS4ERR_NOENT:
#ifdef	NFS_OPS_DEBUG
		printf("NFS: No such file or directory.\n");
#endif	/* NFS_OPS_DEBUG */
		break;
	case NFS4ERR_IO:
		printf("NFS: IO ERROR occurred on NFS server.\n");
		break;
	case NFS4ERR_NXIO:
		printf("NFS: No such device or address.\n");
		break;
	case NFS4ERR_ACCESS:
		printf("NFS: Permission denied.\n");
		break;
	case NFS4ERR_EXIST:
		printf("NFS: File exists.\n");
		break;
	case NFS4ERR_XDEV:
		printf("NFS: Cross device hard link.\n");
		break;
	case NFS4ERR_NOTDIR:
		printf("NFS: Not a directory.\n");
		break;
	case NFS4ERR_ISDIR:
		printf("NFS: Is a directory.\n");
		break;
	case NFS4ERR_INVAL:
		printf("NFS: Invalid argument.\n");
		break;
	case NFS4ERR_FBIG:
		printf("NFS: File too large.\n");
		break;
	case NFS4ERR_NOSPC:
		printf("NFS: No space left on device.\n");
		break;
	case NFS4ERR_ROFS:
		printf("NFS: Read-only filesystem.\n");
		break;
	case NFS4ERR_MLINK:
		printf("NFS: Too many hard links.\n");
		break;
	case NFS4ERR_NAMETOOLONG:
		printf("NFS: File name too long.\n");
		break;
	case NFS4ERR_NOTEMPTY:
		printf("NFS: Directory not empty.\n");
		break;
	case NFS4ERR_DQUOT:
		printf("NFS: Disk quota exceeded.\n");
		break;
	case NFS4ERR_STALE:
		printf("NFS: Stale file handle.\n");
		break;
	case NFS4ERR_BADHANDLE:
		printf("NFS: Illegal NFS file handle.\n");
		break;
	case NFS4ERR_BAD_COOKIE:
		printf("NFS: Stale Cookie.\n");
		break;
	case NFS4ERR_NOTSUPP:
		printf("NFS: Operation is not supported.\n");
		break;
	case NFS4ERR_TOOSMALL:
		printf("NFS: Buffer too small.\n");
		break;
	case NFS4ERR_SERVERFAULT:
		printf("NFS: Server fault.\n");
		break;
	case NFS4ERR_BADTYPE:
		printf("NFS: Unsupported object type.\n");
		break;
	case NFS4ERR_BAD_STATEID:
		printf("NFS: Bad stateid\n");
		break;
	case NFS4ERR_BAD_SEQID:
		printf("NFS: Bad seqid\n");
		break;
	default:
		printf("NFS: unknown error.\n");
		break;
	}
}

/*
 * lookup one component.  for multicomponent lookup use a driver like lookup().
 */
struct nfs_file *
nfs4lookup(struct nfs_file *dir, char *name, int *nstat)
{
	static struct nfs_file	cd;
	attr4_bitmap1_t		bitmap1;
	lookup4arg_t		lookupargs;
	lookup4res_t		lookupres;
	enum clnt_stat		status;
	utf8string		str;
	char			tagname[] = "inetboot lookup";

	/*
	 * NFSv4 uses a special LOOKUPP op
	 * for looking up the parent directory.
	 */
	if (strcmp(name, "..") == 0)
		return (nfs4lookupp(dir, nstat, NULL));

	*nstat = (int)NFS4_OK;

	bzero(&lookupres, sizeof (lookupres));

	/*
	 * Check if we have a filehandle and initialize the compound
	 * with putfh or putrootfh appropriately.
	 */
	str.utf8string_len = sizeof (tagname) - 1;
	str.utf8string_val = tagname;

	if (dir->fh.fh4.len > 0)
		compound_init(&lookupargs.la_arg, &str, 0, 3, &dir->fh.fh4);
	else
		compound_init(&lookupargs.la_arg, &str, 0, 3, NULL);

	/*
	 * lookup
	 */
	lookupargs.la_oplookup = OP_LOOKUP;
	/*
	 * convert the pathname from char * to utf8string
	 */
	lookupargs.la_pathname.utf8string_len = strlen(name);
	lookupargs.la_pathname.utf8string_val =
	    bkmem_alloc(lookupargs.la_pathname.utf8string_len);
	if (lookupargs.la_pathname.utf8string_val == NULL) {
		dprintf("nfs4lookup: bkmem_alloc failed\n");
		return (NULL);
	}
	bcopy(name, lookupargs.la_pathname.utf8string_val,
	    lookupargs.la_pathname.utf8string_len);

	/*
	 * Setup the attr bitmap.  All we need is the type and filehandle info
	 */
	lookupargs.la_opgetattr = OP_GETATTR;
	bitmap1.word = 0;
	bitmap1.bm_fattr4_type = 1;
	bitmap1.bm_fattr4_filehandle = 1;
	lookupargs.la_attr_req.b_bitmap_len = 1;
	lookupargs.la_attr_req.b_bitmap_val[0] = bitmap1.word;
	lookupargs.la_attr_req.b_bitmap_val[1] = 0;

	status = CLNT_CALL(root_CLIENT, NFSPROC4_COMPOUND, xdr_lookup4_args,
	    (caddr_t)&lookupargs, xdr_lookup4_res,
	    (caddr_t)&lookupres, zero_timeout);

	if (status != RPC_SUCCESS) {
		dprintf("nfs4lookup: RPC error. status %d\n", status);
		return (NULL);
	}

	if (lookupres.lr_lookup_status != NFS4_OK) {
#ifdef DEBUG
		dprintf("nfs4lookup: lookup status = %d\n",
		    lookupres.lr_lookup_status);
#endif
		nfs4_error(lookupres.lr_lookup_status);
		*nstat = (int)lookupres.lr_lookup_status;
		if (lookupargs.la_pathname.utf8string_val != NULL)
			bkmem_free(lookupargs.la_pathname.utf8string_val,
			    lookupargs.la_pathname.utf8string_len);
		return (NULL);
	}

	if (lookupres.lr_attr_status != NFS4_OK) {
#ifdef DEBUG
		dprintf("nfs4lookup: getattr status = %d\n",
		    lookupres.lr_attr_status);
#endif
		nfs4_error(lookupres.lr_attr_status);
		*nstat = (int)lookupres.lr_attr_status;
		if (lookupargs.la_pathname.utf8string_val != NULL)
			bkmem_free(lookupargs.la_pathname.utf8string_val,
			    lookupargs.la_pathname.utf8string_len);
		return (NULL);
	}

	/*
	 * We have all the information we need to update the file pointer
	 */
	bzero((caddr_t)&cd, sizeof (struct nfs_file));
	cd.version = NFS_V4;
	cd.ftype.type4 = lookupres.lr_attrs.b_fattr4_type;
	cd.fh.fh4.len = lookupres.lr_attrs.b_fattr4_filehandle.len;
	bcopy(lookupres.lr_attrs.b_fattr4_filehandle.data, cd.fh.fh4.data,
	    cd.fh.fh4.len);

	/*
	 * Free the arg string
	 */
	if (lookupargs.la_pathname.utf8string_val != NULL)
		bkmem_free(lookupargs.la_pathname.utf8string_val,
		    lookupargs.la_pathname.utf8string_len);

	return (&cd);
}

/*
 * lookup parent directory.
 */
struct nfs_file *
nfs4lookupp(struct nfs_file *dir, int *nstat, uint64_t *fileid)
{
	static struct nfs_file	cd;
	attr4_bitmap1_t		bitmap1;
	lookupp4arg_t		lookuppargs;
	lookup4res_t		lookupres;
	enum clnt_stat		status;
	utf8string		str;
	char			tagname[] = "inetboot lookupp";

	*nstat = (int)NFS4_OK;

	bzero(&lookupres, sizeof (lookupres));

	/*
	 * Check if we have a filehandle and initialize the compound
	 * with putfh or putrootfh appropriately.
	 */
	str.utf8string_len = sizeof (tagname) - 1;
	str.utf8string_val = tagname;

	if (dir->fh.fh4.len > 0)
		compound_init(&lookuppargs.la_arg, &str, 0, 3, &dir->fh.fh4);
	else
		compound_init(&lookuppargs.la_arg, &str, 0, 3, NULL);

	/*
	 * lookupp
	 */
	lookuppargs.la_oplookupp = OP_LOOKUPP;
	/*
	 * Setup the attr bitmap.  Normally, all we need is the type and
	 * filehandle info, but getdents might require the fileid of the
	 * parent.
	 */
	lookuppargs.la_opgetattr = OP_GETATTR;
	bitmap1.word = 0;
	bitmap1.bm_fattr4_type = 1;
	bitmap1.bm_fattr4_filehandle = 1;
	if (fileid != NULL)
		bitmap1.bm_fattr4_fileid = 1;
	lookuppargs.la_attr_req.b_bitmap_len = 1;
	lookuppargs.la_attr_req.b_bitmap_val[0] = bitmap1.word;
	lookuppargs.la_attr_req.b_bitmap_val[1] = 0;

	status = CLNT_CALL(root_CLIENT, NFSPROC4_COMPOUND, xdr_lookupp4_args,
	    (caddr_t)&lookuppargs, xdr_lookup4_res,
	    (caddr_t)&lookupres, zero_timeout);

	if (status != RPC_SUCCESS) {
		dprintf("nfs4lookupp: RPC error. status %d\n", status);
		return (NULL);
	}

	if (lookupres.lr_lookup_status != NFS4_OK) {
#ifdef DEBUG
		dprintf("nfs4lookupp: lookupp status = %d\n",
		    lookupres.lr_lookup_status);
#endif
		nfs4_error(lookupres.lr_lookup_status);
		*nstat = (int)lookupres.lr_lookup_status;
		return (NULL);
	}

	if (lookupres.lr_attr_status != NFS4_OK) {
#ifdef DEBUG
		dprintf("nfs4lookupp: getattr status = %d\n",
		    lookupres.lr_attr_status);
#endif
		nfs4_error(lookupres.lr_attr_status);
		*nstat = (int)lookupres.lr_attr_status;
		return (NULL);
	}

	/*
	 * We have all the information we need to update the file pointer
	 */
	bzero((caddr_t)&cd, sizeof (struct nfs_file));
	cd.version = NFS_V4;
	cd.ftype.type4 = lookupres.lr_attrs.b_fattr4_type;
	cd.fh.fh4.len = lookupres.lr_attrs.b_fattr4_filehandle.len;
	bcopy(lookupres.lr_attrs.b_fattr4_filehandle.data, cd.fh.fh4.data,
	    cd.fh.fh4.len);

	/*
	 * Fill in the fileid if the user passed in one
	 */
	if (fileid != NULL)
		*fileid = lookupres.lr_attrs.b_fattr4_fileid;

	return (&cd);
}

/*
 * Gets symbolic link into pathname.
 */
int
nfs4getsymlink(struct nfs_file *cfile, char **path)
{
	enum clnt_stat	status;
	readlink4arg_t	readlinkargs;
	readlink4res_t	readlinkres;
	static char	symlink_path[NFS_MAXPATHLEN];
	int		spathlen;
	utf8string	str;
	char		tagname[] = "inetboot getsymlink";
	int		error = NFS4_OK;

	bzero(&readlinkres, sizeof (readlinkres));

	/*
	 * readlink
	 */
	str.utf8string_len = sizeof (tagname) - 1;
	str.utf8string_val = tagname;

	if (cfile->fh.fh4.len > 0)
		compound_init(&readlinkargs.rl_arg, &str, 0, 2,
		    &cfile->fh.fh4);
	else
		compound_init(&readlinkargs.rl_arg, &str, 0, 2,	NULL);

	readlinkargs.rl_opreadlink = OP_READLINK;
	status = CLNT_CALL(root_CLIENT, NFSPROC4_COMPOUND, xdr_readlink4_args,
	    (caddr_t)&readlinkargs, xdr_readlink4_res,
	    (caddr_t)&readlinkres, zero_timeout);

	if (status != RPC_SUCCESS) {
		dprintf("nfs4getsymlink: RPC readlink error %d\n", status);
		error = -1;
		goto out;
	}

	if (readlinkres.rl_status != NFS4_OK) {
		nfs4_error(readlinkres.rl_status);
		error = readlinkres.rl_status;
		goto out;
	}

	/*
	 * Convert the utf8string to a normal character string
	 */
	spathlen = readlinkres.rl_link.utf8string_len;
	if (spathlen <= 0 || readlinkres.rl_link.utf8string_val == NULL) {
		*path = NULL;
		error = readlinkres.rl_status;
		goto out;
	}

	bcopy(readlinkres.rl_link.utf8string_val, symlink_path, spathlen);
	symlink_path[spathlen] = '\0';
	*path = symlink_path;

out:
	/*
	 * Free the results
	 */
	if (readlinkres.rl_link.utf8string_val != NULL)
		bkmem_free(readlinkres.rl_link.utf8string_val, spathlen);

	return (error);
}

/*
 * Should just forget about the tag, but will leave in support for the time
 * being.
 */
void
compound_init(b_compound_t *cp, utf8string *str, uint_t mvers, uint_t arglen,
		struct nfs_bfh4 *pfh)
{
	if (str == NULL || str->utf8string_len == 0) {
		cp->ca_tag.utf8string_len = 0;
		cp->ca_tag.utf8string_val = NULL;
	} else {
		cp->ca_tag.utf8string_len = str->utf8string_len;
		cp->ca_tag.utf8string_val = str->utf8string_val;
	}
	cp->ca_minorversion = mvers;
	cp->ca_argarray_len = arglen;
	if (pfh == NULL) {
		cp->ca_isputrootfh = TRUE;
		cp->ca_opputfh.pf_opnum = OP_PUTROOTFH;
	} else {
		cp->ca_isputrootfh = FALSE;
		cp->ca_opputfh.pf_opnum = OP_PUTFH;
		cp->ca_opputfh.pf_filehandle.len = pfh->len;
		bcopy(pfh->data, cp->ca_opputfh.pf_filehandle.data, pfh->len);
	}
}
