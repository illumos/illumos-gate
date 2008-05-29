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
 * Simple nfs V3 ops
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <rpcsvc/nfs_prot.h>

#define	dprintf	if (boothowto & RB_DEBUG) printf

/*
 * NFS Version 3 specific functions
 */

ssize_t
nfs3read(struct nfs_file *filep, char *buf, size_t size)
{
	READ3args		read_args;
	READ3res		read_res;
	enum clnt_stat		read_stat;
	uint_t			readcnt = 0;	/* # bytes read by nfs */
	uint_t			count = 0;	/* # bytes transferred to buf */
	int			done = FALSE;	/* last block has come in */
	int			framing_errs = 0;	/* stack errors */
	char			*buf_offset;	/* current buffer offset */
	struct timeval		timeout;
	static uint_t		pos;		/* progress indicator counter */
	static char		ind[] = "|/-\\";	/* progress indicator */
	static int		blks_read;

	read_args.file.data.data_len = filep->fh.fh3.len;
	read_args.file.data.data_val = filep->fh.fh3.data;
	read_args.offset = filep->offset;

	bzero(&read_res, sizeof (read_res));

	buf_offset = buf;

	/* Optimize for reads of less than one block size */

	if (nfs_readsize == 0)
		nfs_readsize = READ3_SIZE;

	if (size < nfs_readsize)
		read_args.count = size;
	else
		read_args.count = nfs_readsize;

	do {
		/* use the user's buffer to stuff the data into. */
		read_res.READ3res_u.resok.data.data_val = buf_offset;

		/*
		 * Handle the case where the file does not end
		 * on a block boundary.
		 */
		if ((count + read_args.count) > size)
			read_args.count = size - count;

		timeout.tv_sec = NFS_REXMIT_MIN; /* Total wait for call */
		timeout.tv_usec = 0;
		do {
			read_stat = CLNT_CALL(root_CLIENT, NFSPROC3_READ,
			    xdr_READ3args, (caddr_t)&read_args,
			    xdr_READ3res, (caddr_t)&read_res, timeout);

			if (read_stat == RPC_TIMEDOUT) {
				dprintf("NFS read(%d) timed out. Retrying...\n",
				    read_args.count);
				/*
				 * If the remote is there and trying to respond,
				 * but our stack is having trouble reassembling
				 * the reply, reduce the read size in an
				 * attempt to compensate. Reset the
				 * transmission and reply wait timers.
				 */
				if (errno == ETIMEDOUT)
					framing_errs++;

				if (framing_errs > NFS_MAX_FERRS &&
				    read_args.count > NFS_READ_DECR) {
					read_args.count /= 2;
					nfs_readsize /= 2;
					dprintf("NFS Read size now %d.\n",
					    nfs_readsize);
					timeout.tv_sec = NFS_REXMIT_MIN;
					framing_errs = 0;
				} else {
					if (timeout.tv_sec < NFS_REXMIT_MAX)
						timeout.tv_sec++;
					else
						timeout.tv_sec = 0;
							/* default RPC */
				}
			}
		} while (read_stat == RPC_TIMEDOUT);

		if (read_stat != RPC_SUCCESS)
			return (-1);

		if (read_res.status != NFS3_OK)
			return (-1);

		readcnt = read_res.READ3res_u.resok.data.data_len;
		/*
		 * If we are at EOF, update counts and exit
		 */
		if (read_res.READ3res_u.resok.eof == TRUE)
			done = TRUE;

		/*
		 * Handle the case where the file is smaller than
		 * the size of the read request, thus the request
		 * couldn't be completely filled.
		 */
		if (readcnt < read_args.count) {
#ifdef NFS_OPS_DEBUG
			if ((boothowto & DBFLAGS) == DBFLAGS)
				printf("nfs3read(): partial read %d"
				    " instead of %d\n",
				    readcnt, read_args.count);
#endif
			done = TRUE; /* update the counts and exit */
		}

		/* update various offsets */
		count += readcnt;
		filep->offset += readcnt;
		buf_offset += readcnt;
		read_args.offset += readcnt;
		/*
		 * round and round she goes (though not on every block..
		 * - OBP's take a fair bit of time to actually print stuff)
		 */
		if ((blks_read++ & 0x3) == 0)
			printf("%c\b", ind[pos++ & 3]);
	} while (count < size && !done);

	return (count);
}

int
nfs3getattr(struct nfs_file *nfp, struct vattr *vap)
{
	enum clnt_stat getattr_stat;
	GETATTR3args getattr_args;
	GETATTR3res getattr_res;
	fattr3 *na;
	struct timeval timeout = {0, 0};	/* default */
	vtype_t nf3_to_vt[] =
			{ VBAD, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO };


	bzero(&getattr_args, sizeof (getattr_args));
	getattr_args.object.data.data_len = nfp->fh.fh3.len;
	getattr_args.object.data.data_val = nfp->fh.fh3.data;

	bzero(&getattr_res, sizeof (getattr_res));

	getattr_stat = CLNT_CALL(root_CLIENT, NFSPROC3_GETATTR,
	    xdr_GETATTR3args, (caddr_t)&getattr_args,
	    xdr_GETATTR3res, (caddr_t)&getattr_res, timeout);

	if (getattr_stat != RPC_SUCCESS) {
		dprintf("nfs_getattr: RPC error %d\n", getattr_stat);
		return (-1);
	}
	if (getattr_res.status != NFS3_OK) {
		nfs3_error(getattr_res.status);
		return (getattr_res.status);
	}

	na = &getattr_res.GETATTR3res_u.resok.obj_attributes;
	if (vap->va_mask & AT_TYPE) {
		if (na->type < NF3REG || na->type > NF3FIFO)
			vap->va_type = VBAD;
		else
			vap->va_type = nf3_to_vt[na->type];
	}
	if (vap->va_mask & AT_MODE)
		vap->va_mode = (mode_t)na->mode;
	if (vap->va_mask & AT_SIZE)
		vap->va_size = (u_offset_t)na->size;
	if (vap->va_mask & AT_NODEID)
		vap->va_nodeid = (u_longlong_t)na->fileid;
	if (vap->va_mask & AT_ATIME) {
		vap->va_atime.tv_sec  = na->atime.seconds;
		vap->va_atime.tv_nsec = na->atime.nseconds;
	}
	if (vap->va_mask & AT_CTIME) {
		vap->va_ctime.tv_sec  = na->ctime.seconds;
		vap->va_ctime.tv_nsec = na->ctime.nseconds;
	}
	if (vap->va_mask & AT_MTIME) {
		vap->va_mtime.tv_sec  = na->mtime.seconds;
		vap->va_mtime.tv_nsec = na->mtime.nseconds;
	}

	return (NFS3_OK);
}

/*
 * Display nfs error messages.
 */
/*ARGSUSED*/
void
nfs3_error(enum nfsstat3 status)
{
	if (!(boothowto & RB_DEBUG))
		return;

	switch (status) {
	case NFS3_OK:
		printf("NFS: No error.\n");
		break;
	case NFS3ERR_PERM:
		printf("NFS: Not owner.\n");
		break;
	case NFS3ERR_NOENT:
#ifdef	NFS_OPS_DEBUG
		printf("NFS: No such file or directory.\n");
#endif	/* NFS_OPS_DEBUG */
		break;
	case NFS3ERR_IO:
		printf("NFS: IO ERROR occurred on NFS server.\n");
		break;
	case NFS3ERR_NXIO:
		printf("NFS: No such device or address.\n");
		break;
	case NFS3ERR_ACCES:
		printf("NFS: Permission denied.\n");
		break;
	case NFS3ERR_EXIST:
		printf("NFS: File exists.\n");
		break;
	case NFS3ERR_XDEV:
		printf("NFS: Cross device hard link.\n");
		break;
	case NFS3ERR_NODEV:
		printf("NFS: No such device.\n");
		break;
	case NFS3ERR_NOTDIR:
		printf("NFS: Not a directory.\n");
		break;
	case NFS3ERR_ISDIR:
		printf("NFS: Is a directory.\n");
		break;
	case NFS3ERR_INVAL:
		printf("NFS: Invalid argument.\n");
		break;
	case NFS3ERR_FBIG:
		printf("NFS: File too large.\n");
		break;
	case NFS3ERR_NOSPC:
		printf("NFS: No space left on device.\n");
		break;
	case NFS3ERR_ROFS:
		printf("NFS: Read-only filesystem.\n");
		break;
	case NFS3ERR_MLINK:
		printf("NFS: Too many hard links.\n");
		break;
	case NFS3ERR_NAMETOOLONG:
		printf("NFS: File name too long.\n");
		break;
	case NFS3ERR_NOTEMPTY:
		printf("NFS: Directory not empty.\n");
		break;
	case NFS3ERR_DQUOT:
		printf("NFS: Disk quota exceeded.\n");
		break;
	case NFS3ERR_STALE:
		printf("NFS: Stale file handle.\n");
		break;
	case NFS3ERR_REMOTE:
		printf("NFS: Remote file in path.\n");
		break;
	case NFS3ERR_BADHANDLE:
		printf("NFS: Illegal NFS file handle.\n");
		break;
	case NFS3ERR_NOT_SYNC:
		printf("NFS: Synchronization mismatch.\n");
		break;
	case NFS3ERR_BAD_COOKIE:
		printf("NFS: Stale Cookie.\n");
		break;
	case NFS3ERR_NOTSUPP:
		printf("NFS: Operation is not supported.\n");
		break;
	case NFS3ERR_TOOSMALL:
		printf("NFS: Buffer too small.\n");
		break;
	case NFS3ERR_SERVERFAULT:
		printf("NFS: Server fault.\n");
		break;
	case NFS3ERR_BADTYPE:
		printf("NFS: Unsupported object type.\n");
		break;
	case NFS3ERR_JUKEBOX:
		printf("NFS: Resource temporarily unavailable.\n");
		break;
	default:
		printf("NFS: unknown error.\n");
		break;
	}
}

struct nfs_file *
nfs3lookup(struct nfs_file *dir, char *name, int *nstat)
{
	struct timeval zero_timeout = {0, 0};	/* default */
	static struct nfs_file cd;
	LOOKUP3args dirop;
	LOOKUP3res res_lookup;
	enum clnt_stat status;

	*nstat = (int)NFS3_OK;

	bzero((caddr_t)&dirop, sizeof (LOOKUP3args));
	bzero((caddr_t)&res_lookup, sizeof (LOOKUP3res));

	dirop.what.dir.data.data_len = dir->fh.fh3.len;
	dirop.what.dir.data.data_val = dir->fh.fh3.data;
	dirop.what.name = name;

	status = CLNT_CALL(root_CLIENT, NFSPROC3_LOOKUP, xdr_LOOKUP3args,
	    (caddr_t)&dirop, xdr_LOOKUP3res, (caddr_t)&res_lookup,
	    zero_timeout);
	if (status != RPC_SUCCESS) {
		dprintf("lookup: RPC error.\n");
		return (NULL);
	}
	if (res_lookup.status != NFS3_OK) {
		nfs3_error(res_lookup.status);
		*nstat = (int)res_lookup.status;
		(void) CLNT_FREERES(root_CLIENT,
		    xdr_LOOKUP3res, (caddr_t)&res_lookup);
		return (NULL);
	}

	bzero((caddr_t)&cd, sizeof (struct nfs_file));
	cd.version = NFS_V3;
	/*
	 * Server must supply post_op_attr's
	 */
	if (res_lookup.LOOKUP3res_u.resok.obj_attributes.attributes_follow ==
	    FALSE) {
		printf("nfs3lookup: server fails to return post_op_attr\n");
		(void) CLNT_FREERES(root_CLIENT,
		    xdr_LOOKUP3res, (caddr_t)&res_lookup);
		return (NULL);
	}

	cd.ftype.type3 = res_lookup.LOOKUP3res_u.resok.obj_attributes
	    .post_op_attr_u.attributes.type;
	cd.fh.fh3.len = res_lookup.LOOKUP3res_u.resok.object.data.data_len;
	bcopy(res_lookup.LOOKUP3res_u.resok.object.data.data_val,
	    cd.fh.fh3.data, cd.fh.fh3.len);
	(void) CLNT_FREERES(root_CLIENT, xdr_LOOKUP3res, (caddr_t)&res_lookup);
	return (&cd);
}

/*
 * Gets symbolic link into pathname.
 */
int
nfs3getsymlink(struct nfs_file *cfile, char **path)
{
	struct timeval zero_timeout = {0, 0};	/* default */
	enum clnt_stat status;
	struct READLINK3res linkres;
	struct READLINK3args linkargs;
	static char symlink_path[NFS_MAXPATHLEN];

	bzero(&linkargs, sizeof (linkargs));
	linkargs.symlink.data.data_len = cfile->fh.fh3.len;
	linkargs.symlink.data.data_val = cfile->fh.fh3.data;

	/*
	 * linkres needs a zeroed buffer to place path data into:
	 */
	bzero(&linkres, sizeof (linkres));
	bzero(symlink_path, NFS_MAXPATHLEN);
	linkres.READLINK3res_u.resok.data = symlink_path;

	status = CLNT_CALL(root_CLIENT, NFSPROC3_READLINK,
	    xdr_READLINK3args, (caddr_t)&linkargs,
	    xdr_READLINK3res, (caddr_t)&linkres, zero_timeout);
	if (status != RPC_SUCCESS) {
		dprintf("nfs3getsymlink: RPC call failed.\n");
		return (-1);
	}
	if (linkres.status != NFS3_OK) {
		nfs3_error(linkres.status);
		return (linkres.status);
	}

	*path = symlink_path;

	return (NFS3_OK);
}
