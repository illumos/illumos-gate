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
 * Simple nfs ops - open, close, read, and lseek.
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

static struct timeval zero_timeout = {0, 0};	/* default */

/*
 * NFS Version 2 specific functions
 */

ssize_t
nfsread(struct nfs_file *filep, char *buf, size_t size)
{
	readargs		read_args;
	readres			read_res;
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

	read_args.file = filep->fh.fh2;		/* structure copy */
	read_args.offset = filep->offset;
	buf_offset = buf;

	/* Optimize for reads of less than one block size */

	if (nfs_readsize == 0)
		nfs_readsize = READ_SIZE;

	if (size < nfs_readsize)
		read_args.count = size;
	else
		read_args.count = nfs_readsize;

	do {
		/* use the user's buffer to stuff the data into. */
		read_res.readres_u.reply.data.data_val = buf_offset;

		/*
		 * Handle the case where the file does not end
		 * on a block boundary.
		 */
		if ((count + read_args.count) > size)
			read_args.count = size - count;

		timeout.tv_sec = NFS_REXMIT_MIN; /* Total wait for call */
		timeout.tv_usec = 0;
		do {
			read_stat = CLNT_CALL(root_CLIENT, NFSPROC_READ,
			    xdr_readargs, (caddr_t)&read_args,
			    xdr_readres, (caddr_t)&read_res, timeout);

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
					read_args.count -= NFS_READ_DECR;
					nfs_readsize -= NFS_READ_DECR;
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

		readcnt = read_res.readres_u.reply.data.data_len;
		/*
		 * Handle the case where the file is simply empty, and
		 * nothing could be read.
		 */
		if (readcnt == 0)
			break; /* eof */

		/*
		 * Handle the case where the file is smaller than
		 * the size of the read request, thus the request
		 * couldn't be completely filled.
		 */
		if (readcnt < read_args.count) {
#ifdef NFS_OPS_DEBUG
		if ((boothowto & DBFLAGS) == DBFLAGS)
			printf("nfsread(): partial read %d"
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

static vtype_t nf_to_vt[] = {
	VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK
};

int
nfsgetattr(struct nfs_file *nfp, struct vattr *vap)
{
	enum clnt_stat getattr_stat;
	attrstat getattr_res;
	fattr *na;
	struct timeval timeout = {0, 0};	/* default */

	getattr_stat = CLNT_CALL(root_CLIENT, NFSPROC_GETATTR,
	    xdr_nfs_fh, (caddr_t)&(nfp->fh.fh2),
	    xdr_attrstat, (caddr_t)&getattr_res, timeout);

	if (getattr_stat != RPC_SUCCESS) {
		dprintf("nfs_getattr: RPC error %d\n", getattr_stat);
		return (-1);
	}
	if (getattr_res.status != NFS_OK) {
		nfs_error(getattr_res.status);
		return (getattr_res.status);
	}

	/* adapted from nattr_to_vattr() in nfs_client.c */

	na = &getattr_res.attrstat_u.attributes;
	if (vap->va_mask & AT_TYPE) {
		if (na->type < NFNON || na->type > NFSOCK)
			vap->va_type = VBAD;
		else
			vap->va_type = nf_to_vt[na->type];
	}
	if (vap->va_mask & AT_MODE)
		vap->va_mode = na->mode;
	if (vap->va_mask & AT_SIZE)
		vap->va_size = na->size;
	if (vap->va_mask & AT_NODEID)
		vap->va_nodeid = na->fileid;
	if (vap->va_mask & AT_ATIME) {
		vap->va_atime.tv_sec  = na->atime.seconds;
		vap->va_atime.tv_nsec = na->atime.useconds * 1000;
	}
	if (vap->va_mask & AT_CTIME) {
		vap->va_ctime.tv_sec  = na->ctime.seconds;
		vap->va_ctime.tv_nsec = na->ctime.useconds * 1000;
	}
	if (vap->va_mask & AT_MTIME) {
		vap->va_mtime.tv_sec  = na->mtime.seconds;
		vap->va_mtime.tv_nsec = na->mtime.useconds * 1000;
	}

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("nfs_getattr(): done.\n");
#endif
	return (getattr_res.status);
}

/*
 * Display nfs error messages.
 */
/*ARGSUSED*/
void
nfs_error(enum nfsstat status)
{
	if (!(boothowto & RB_DEBUG))
		return;

	switch (status) {
	case NFSERR_PERM:
		printf("NFS: Not owner.\n");
		break;
	case NFSERR_NOENT:
#ifdef	NFS_OPS_DEBUG
		printf("NFS: No such file or directory.\n");
#endif	/* NFS_OPS_DEBUG */
		break;
	case NFSERR_IO:
		printf("NFS: IO ERROR occurred on NFS server.\n");
		break;
	case NFSERR_NXIO:
		printf("NFS: No such device or address.\n");
		break;
	case NFSERR_ACCES:
		printf("NFS: Permission denied.\n");
		break;
	case NFSERR_EXIST:
		printf("NFS: File exists.\n");
		break;
	case NFSERR_NODEV:
		printf("NFS: No such device.\n");
		break;
	case NFSERR_NOTDIR:
		printf("NFS: Not a directory.\n");
		break;
	case NFSERR_ISDIR:
		printf("NFS: Is a directory.\n");
		break;
	case NFSERR_FBIG:
		printf("NFS: File too large.\n");
		break;
	case NFSERR_NOSPC:
		printf("NFS: No space left on device.\n");
		break;
	case NFSERR_ROFS:
		printf("NFS: Read-only filesystem.\n");
		break;
	case NFSERR_NAMETOOLONG:
		printf("NFS: File name too long.\n");
		break;
	case NFSERR_NOTEMPTY:
		printf("NFS: Directory not empty.\n");
		break;
	case NFSERR_DQUOT:
		printf("NFS: Disk quota exceeded.\n");
		break;
	case NFSERR_STALE:
		printf("NFS: Stale file handle.\n");
		break;
	case NFSERR_WFLUSH:
		printf("NFS: server's write cache has been flushed.\n");
		break;
	default:
		printf("NFS: unknown error.\n");
		break;
	}
}

struct nfs_file *
nfslookup(struct nfs_file *dir, char *name, int *nstat)
{
	static struct nfs_file cd;
	diropargs dirop;
	diropres res_lookup;
	enum clnt_stat status;

	*nstat = (int)NFS_OK;

	bcopy(&dir->fh.fh2, &dirop.dir, NFS_FHSIZE);
	dirop.name = name;

	status = CLNT_CALL(root_CLIENT, NFSPROC_LOOKUP, xdr_diropargs,
	    (caddr_t)&dirop, xdr_diropres, (caddr_t)&res_lookup,
	    zero_timeout);
	if (status != RPC_SUCCESS) {
		dprintf("lookup: RPC error.\n");
		return (NULL);
	}
	if (res_lookup.status != NFS_OK) {
		nfs_error(res_lookup.status);
		*nstat = (int)res_lookup.status;
		return (NULL);
	}

	bzero((caddr_t)&cd, sizeof (struct nfs_file));
	cd.version = NFS_VERSION;
	cd.ftype.type2 = res_lookup.diropres_u.diropres.attributes.type;
	bcopy(&res_lookup.diropres_u.diropres.file, &cd.fh.fh2, NFS_FHSIZE);
	return (&cd);
}

/*
 * Gets symbolic link into pathname.
 */
int
nfsgetsymlink(struct nfs_file *cfile, char **path)
{
	enum clnt_stat status;
	struct readlinkres linkres;
	static char symlink_path[NFS_MAXPATHLEN];

	/*
	 * linkres needs a zeroed buffer to place path data into:
	 */
	bzero(symlink_path, NFS_MAXPATHLEN);
	linkres.readlinkres_u.data = &symlink_path[0];

	status = CLNT_CALL(root_CLIENT, NFSPROC_READLINK,
	    xdr_nfs_fh, (caddr_t)&cfile->fh.fh2,
	    xdr_readlinkres, (caddr_t)&linkres, zero_timeout);
	if (status != RPC_SUCCESS) {
		dprintf("nfsgetsymlink: RPC call failed.\n");
		return (-1);
	}
	if (linkres.status != NFS_OK) {
		nfs_error(linkres.status);
		return (linkres.status);
	}

	*path = linkres.readlinkres_u.data;

	return (NFS_OK);
}
