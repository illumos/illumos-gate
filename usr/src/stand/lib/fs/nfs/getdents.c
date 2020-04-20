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
 *  Stuff relating to directory reading ...
 */

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
nfsgetdents(struct nfs_file *nfp, struct dirent *dep, unsigned size)
{
	entry *ep;
	readdirargs rda;
	readdirres  res;
	enum clnt_stat status;
	struct {
		entry etlist[MAXDENTS];
		char names[MAXDENTS][NFS_MAXNAMLEN+1];
	} rdbuf;
	uint32_t offset;
	int j, cnt = 0;
	struct timeval zero_timeout = {0, 0};	/* default */

	bzero((caddr_t)&res, sizeof (res));
	bzero((caddr_t)&rda, sizeof (rda));
	bzero((caddr_t)rdbuf.etlist, sizeof (rdbuf.etlist));
	bcopy((caddr_t)&nfp->fh.fh2, (caddr_t)&rda.dir, NFS_FHSIZE);
	bcopy((caddr_t)nfp->cookie.cookie2, (caddr_t)rda.cookie,
						sizeof (nfscookie));

	while (!res.readdirres_u.reply.eof) {
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

			rdbuf.etlist[j].name = rdbuf.names[(MAXDENTS-1) - j];
			rdbuf.etlist[j].nextentry =
				(j < (MAXDENTS-1)) ? &rdbuf.etlist[j+1] : 0;
		}

		res.readdirres_u.reply.entries = rdbuf.etlist;
		/*
		 * Cannot give the whole buffer unless every name is
		 * 256 bytes! Assume the worst case of all 1 byte names.
		 * This results in MINSIZ bytes/name in the xdr stream.
		 */
		rda.count = sizeof (res) + MAXDENTS*MINSIZ;
		bzero((caddr_t)rdbuf.names, sizeof (rdbuf.names));

		status = CLNT_CALL(root_CLIENT, NFSPROC_READDIR,
		    xdr_readdirargs, (caddr_t)&rda,
		    xdr_readdirres, (caddr_t)&res, zero_timeout);

		if (status != RPC_SUCCESS) {
			dprintf("nfs_getdents: RPC error\n");
			return (-1);
		}
		if (res.status != NFS_OK) {
			/*
			 *  The most common failure here would be trying to
			 *  issue a getdents call on a non-directory!
			 */

			nfs_error(res.status);
			return (-1);
		}

		for (ep = rdbuf.etlist; ep; ep = ep->nextentry) {
			/*
			 *  Step thru all entries returned by NFS, converting
			 *  to the cannonical form and copying out to the
			 *  user's buffer.
			 */

			int n;

			/*
			 * catch the case user called at EOF
			 */
			if ((n = strlen(ep->name)) == 0)
				return (cnt);

			n = BDIRENT_RECLEN(n);

			if (n > size)
				return (cnt);
			size -= n;

			(void) strlcpy(dep->d_name, ep->name,
			    strlen(ep->name) + 1);
			dep->d_ino = ep->fileid;
			bcopy(ep->cookie, &offset, sizeof (nfscookie));
			dep->d_off = offset;
			dep->d_reclen = (ushort_t)n;

			dep = (struct dirent *)((char *)dep + n);
			bcopy(ep->cookie, rda.cookie, sizeof (nfscookie));
			bcopy(ep->cookie, nfp->cookie.cookie2,
							sizeof (nfscookie));
			cnt++;
		}
	}

	return (cnt);
}
