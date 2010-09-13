/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Stuff relating to NFSv4 directory reading ...
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/xdr.h>
#include "clnt.h"
#include <rpc/rpc_msg.h>
#include <sys/t_lock.h>
#include "nfs_inet.h"
#include <rpc/rpc.h>
#include "brpc.h"
#include <rpcsvc/nfs_prot.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/sysmacros.h>
#include "socket_inet.h"
#include <sys/salib.h>
#include <sys/bootdebug.h>

#define	MAXDENTS 16
#define	MINSIZ 20

/*
 * Boot needs to be cleaned up to use either dirent32 or dirent64,
 * in the meantime use dirent_t and always round to 8 bytes
 */
#define	BDIRENT_RECLEN(namelen) \
	((offsetof(dirent_t, d_name[0]) + 1 + (namelen) + 7) & ~ 7)

#define	dprintf	if (boothowto & RB_DEBUG) printf

/*
 *  Get directory entries:
 *
 *	Uses the nfs "READDIR" operation to read directory entries
 *	into a local buffer.  These are then translated into file
 *	system independent "dirent" structs and returned in the
 *	caller's buffer.  Returns the number of entries converted
 *	(-1 if there's an error).
 *
 *	Although the xdr functions can allocate memory, we have
 *	a limited heap so we allocate our own space,
 *	assuming the worst case of 256 byte names.
 *	This is a space hog in our local buffer, so we want
 *	the number of buffers to be small. To make sure we don't
 *	get more names than we can handle, we tell the rpc
 *	routine that we only have space for MAXDENT names if
 *	they are all the minimum size. This keeps the return
 *	packet unfragmented, but may result in lots of reads
 *	to process a large directory. Since this is standalone
 *	we don't worry about speed. With MAXDENTs at 16, the
 *	local buffer is 4k.
 */

int
nfs4getdents(struct nfs_file *nfp, struct dirent *dep, unsigned size)
{
	int		cnt = 0;
	b_entry4_t	*ep;
	readdir4arg_t	readdir_args;
	readdir4res_t	readdir_res;
	attr4_bitmap1_t	bitmap1;
	enum clnt_stat	status;
	struct {
		b_entry4_t etlist[MAXDENTS];
		char names[MAXDENTS][NFS_MAXNAMLEN+1];
	} rdbuf;
	int		j;
	struct timeval	zero_timeout = {0, 0};   /* default */
	utf8string	str;
	char		tagname[] = "inetboot readdir";

	bzero((caddr_t)&readdir_res, sizeof (readdir4res_t));
	bzero((caddr_t)&readdir_args, sizeof (readdir4arg_t));
	bzero((caddr_t)rdbuf.etlist, sizeof (rdbuf.etlist));

	str.utf8string_len = sizeof (tagname) - 1;
	str.utf8string_val = tagname;

	if (nfp->fh.fh4.len > 0)
		compound_init(&readdir_args.rd_arg, &str, 0, 2, &nfp->fh.fh4);
	else
		compound_init(&readdir_args.rd_arg, &str, 0, 2, NULL);

	readdir_args.rd_opreaddir = OP_READDIR;
	readdir_args.rd_cookie = nfp->cookie.cookie4;

	while (!readdir_res.rd_eof) {
		/*
		 *  Keep issuing nfs calls until EOF is reached on
		 *  the directory or the user buffer is filled.
		 */
		for (j = 0; j < MAXDENTS; j++) {
			/*
			 *  Link our buffers together for the benefit of
			 *  XDR.  We do this each time we issue the rpc call
			 *  JIC the xdr decode
			 *  routines screw up the linkage!
			 */
			rdbuf.etlist[j].b_name.utf8string_len = NFS_MAXNAMLEN;
			rdbuf.etlist[j].b_name.utf8string_val =
				rdbuf.names[(MAXDENTS-1) - j];
			rdbuf.etlist[j].b_nextentry =
				(j < (MAXDENTS-1)) ? &rdbuf.etlist[j+1] : 0;
		}

		readdir_res.rd_entries = rdbuf.etlist;
		/*
		 * Cannot give the whole buffer unless every name is
		 * 256 bytes! Assume the worst case of all 1 byte names.
		 * This results in MINSIZ bytes/name in the xdr stream.
		 */
		readdir_args.rd_dircount = MAXDENTS * MINSIZ;
		readdir_args.rd_maxcount = sizeof (readdir4res_t) +
							(MAXDENTS * MINSIZ);
		bzero((caddr_t)rdbuf.names, sizeof (rdbuf.names));

		/*
		 * Set the attr bitmap, so we get the fileid back.
		 */
		bitmap1.word = 0;
		bitmap1.bm_fattr4_fileid = 1;
		readdir_args.rd_attr_req.b_bitmap_len = 1;
		readdir_args.rd_attr_req.b_bitmap_val[0] = bitmap1.word;

		status = CLNT_CALL(root_CLIENT, NFSPROC4_COMPOUND,
			xdr_readdir4_args, (caddr_t)&readdir_args,
			xdr_readdir4_res, (caddr_t)&readdir_res, zero_timeout);

		if (status != RPC_SUCCESS) {
			dprintf("nfs4_getdents: RPC error\n");
			return (-1);
		}
		if (readdir_res.rd_status != NFS4_OK) {
			/*
			 *  The most common failure here would be trying to
			 *  issue a getdents call on a non-directory!
			 */

			nfs4_error(readdir_res.rd_status);
			return (-1);
		}

		/*
		 * If we are reading from the beginning of the
		 * directory we will need to create the "." and ".."
		 * since we won't be getting them from the server.  To obtain
		 * the fileid's just issue a couple otw lookups to get the
		 * info we need.
		 */
		if (readdir_args.rd_cookie == 0 &&
		    rdbuf.etlist[0].b_cookie > 2) {
			int n;
			int error;
			uint64_t fileid;
			struct vattr va;

			/*
			 * Do a getattr for the '.'
			 */
			error = nfs4getattr(nfp, &va);
			if (error)
				return (-1);

			dep->d_name[0] = '.';
			dep->d_name[1] = '\0';
			dep->d_ino = va.va_nodeid;
			dep->d_off = 1;
			n = BDIRENT_RECLEN(1);
			dep->d_reclen = n;
			dep = (struct dirent *)((char *)dep + n);

			/*
			 * Do a lookupp for the '..'
			 */
			(void) nfs4lookupp(nfp, &error, &fileid);
			if (error)
				return (-1);

			dep->d_name[0] = '.';
			dep->d_name[1] = '.';
			dep->d_name[2] = '\0';
			dep->d_ino = fileid;
			dep->d_off = 2;
			n = BDIRENT_RECLEN(2);
			dep->d_reclen = n;
			dep = (struct dirent *)((char *)dep + n);
		}

		for (ep = rdbuf.etlist; ep; ep = ep->b_nextentry) {
			/*
			 *  Step thru all entries returned by NFS, converting
			 *  to the cannonical form and copying out to the
			 *  user's buffer.
			 */
			int n;
			int namlen;

			/*
			 * catch the case user called at EOF
			 */
			if ((namlen = ep->b_name.utf8string_len) == 0)
				return (cnt);

			n = BDIRENT_RECLEN(namlen);

			if (n > size)
				return (cnt);
			size -= n;

			bcopy(ep->b_name.utf8string_val, dep->d_name, namlen);
			dep->d_name[namlen] = '\0';
			dep->d_ino = ep->b_fileid;
			dep->d_off = (off_t)ep->b_cookie;
			dep->d_reclen = (ushort_t)n;

			dep = (struct dirent *)((char *)dep + n);
			readdir_args.rd_cookie = ep->b_cookie;
			nfp->cookie.cookie4 = ep->b_cookie;
			cnt++;
		}
	}

	return (cnt);
}
