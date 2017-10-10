/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013  Peter Grehan <grehan@freebsd.org>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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
 * $FreeBSD$
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/queue.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/limits.h>
#include <sys/uio.h>
#ifndef __FreeBSD__
#include <sys/dkio.h>
#endif

#include <assert.h>
#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <sysexits.h>
#include <unistd.h>

#include <machine/atomic.h>

#include "bhyverun.h"
#ifdef	__FreeBSD__
#include "mevent.h"
#endif
#include "block_if.h"

#define BLOCKIF_SIG	0xb109b109

#ifdef __FreeBSD__
#define BLOCKIF_NUMTHR	8
#else
/* Enlarge to keep pace with the virtio-block ring size */
#define BLOCKIF_NUMTHR	16
#endif
#define BLOCKIF_MAXREQ	(BLOCKIF_RING_MAX + BLOCKIF_NUMTHR)

enum blockop {
	BOP_READ,
	BOP_WRITE,
#ifndef __FreeBSD__
	BOP_WRITE_SYNC,
#endif
	BOP_FLUSH,
	BOP_DELETE
};

enum blockstat {
	BST_FREE,
	BST_BLOCK,
	BST_PEND,
	BST_BUSY,
	BST_DONE
};

struct blockif_elem {
	TAILQ_ENTRY(blockif_elem) be_link;
	struct blockif_req  *be_req;
	enum blockop	     be_op;
	enum blockstat	     be_status;
	pthread_t            be_tid;
	off_t		     be_block;
};

#ifndef __FreeBSD__
enum blockif_wce {
	WCE_NONE = 0,
	WCE_IOCTL,
	WCE_FCNTL
};
#endif

struct blockif_ctxt {
	int			bc_magic;
	int			bc_fd;
	int			bc_ischr;
	int			bc_isgeom;
	int			bc_candelete;
#ifndef __FreeBSD__
	enum blockif_wce	bc_wce;
#endif
	int			bc_rdonly;
	off_t			bc_size;
	int			bc_sectsz;
	int			bc_psectsz;
	int			bc_psectoff;
	int			bc_closing;
	pthread_t		bc_btid[BLOCKIF_NUMTHR];
	pthread_mutex_t		bc_mtx;
	pthread_cond_t		bc_cond;

	/* Request elements and free/pending/busy queues */
	TAILQ_HEAD(, blockif_elem) bc_freeq;       
	TAILQ_HEAD(, blockif_elem) bc_pendq;
	TAILQ_HEAD(, blockif_elem) bc_busyq;
	struct blockif_elem	bc_reqs[BLOCKIF_MAXREQ];
};

static pthread_once_t blockif_once = PTHREAD_ONCE_INIT;

struct blockif_sig_elem {
	pthread_mutex_t			bse_mtx;
	pthread_cond_t			bse_cond;
	int				bse_pending;
	struct blockif_sig_elem		*bse_next;
};

static struct blockif_sig_elem *blockif_bse_head;

static int
blockif_enqueue(struct blockif_ctxt *bc, struct blockif_req *breq,
		enum blockop op)
{
	struct blockif_elem *be, *tbe;
	off_t off;
	int i;

	be = TAILQ_FIRST(&bc->bc_freeq);
	assert(be != NULL);
	assert(be->be_status == BST_FREE);
	TAILQ_REMOVE(&bc->bc_freeq, be, be_link);
	be->be_req = breq;
	be->be_op = op;
	switch (op) {
	case BOP_READ:
	case BOP_WRITE:
#ifndef __FreeBSD__
	case BOP_WRITE_SYNC:
#endif
	case BOP_DELETE:
		off = breq->br_offset;
		for (i = 0; i < breq->br_iovcnt; i++)
			off += breq->br_iov[i].iov_len;
		break;
	default:
		off = OFF_MAX;
	}
	be->be_block = off;
	TAILQ_FOREACH(tbe, &bc->bc_pendq, be_link) {
		if (tbe->be_block == breq->br_offset)
			break;
	}
	if (tbe == NULL) {
		TAILQ_FOREACH(tbe, &bc->bc_busyq, be_link) {
			if (tbe->be_block == breq->br_offset)
				break;
		}
	}
	if (tbe == NULL)
		be->be_status = BST_PEND;
	else
		be->be_status = BST_BLOCK;
	TAILQ_INSERT_TAIL(&bc->bc_pendq, be, be_link);
	return (be->be_status == BST_PEND);
}

static int
blockif_dequeue(struct blockif_ctxt *bc, pthread_t t, struct blockif_elem **bep)
{
	struct blockif_elem *be;

	TAILQ_FOREACH(be, &bc->bc_pendq, be_link) {
		if (be->be_status == BST_PEND)
			break;
		assert(be->be_status == BST_BLOCK);
	}
	if (be == NULL)
		return (0);
	TAILQ_REMOVE(&bc->bc_pendq, be, be_link);
	be->be_status = BST_BUSY;
	be->be_tid = t;
	TAILQ_INSERT_TAIL(&bc->bc_busyq, be, be_link);
	*bep = be;
	return (1);
}

static void
blockif_complete(struct blockif_ctxt *bc, struct blockif_elem *be)
{
	struct blockif_elem *tbe;

	if (be->be_status == BST_DONE || be->be_status == BST_BUSY)
		TAILQ_REMOVE(&bc->bc_busyq, be, be_link);
	else
		TAILQ_REMOVE(&bc->bc_pendq, be, be_link);
	TAILQ_FOREACH(tbe, &bc->bc_pendq, be_link) {
		if (tbe->be_req->br_offset == be->be_block)
			tbe->be_status = BST_PEND;
	}
	be->be_tid = 0;
	be->be_status = BST_FREE;
	be->be_req = NULL;
	TAILQ_INSERT_TAIL(&bc->bc_freeq, be, be_link);
}

static void
blockif_proc(struct blockif_ctxt *bc, struct blockif_elem *be, uint8_t *buf)
{
	struct blockif_req *br;
#ifdef	__FreeBSD__
	off_t arg[2];
#endif
	ssize_t clen, len, off, boff, voff;
	int i, err;

	br = be->be_req;
	if (br->br_iovcnt <= 1)
		buf = NULL;
	err = 0;
	switch (be->be_op) {
	case BOP_READ:
		if (buf == NULL) {
			if ((len = preadv(bc->bc_fd, br->br_iov, br->br_iovcnt,
				   br->br_offset)) < 0)
				err = errno;
			else
				br->br_resid -= len;
			break;
		}
		i = 0;
		off = voff = 0;
		while (br->br_resid > 0) {
			len = MIN(br->br_resid, MAXPHYS);
			if (pread(bc->bc_fd, buf, len, br->br_offset +
			    off) < 0) {
				err = errno;
				break;
			}
			boff = 0;
			do {
				clen = MIN(len - boff, br->br_iov[i].iov_len -
				    voff);
				memcpy(br->br_iov[i].iov_base + voff,
				    buf + boff, clen);
				if (clen < br->br_iov[i].iov_len - voff)
					voff += clen;
				else {
					i++;
					voff = 0;
				}
				boff += clen;
			} while (boff < len);
			off += len;
			br->br_resid -= len;
		}
		break;
	case BOP_WRITE:
		if (bc->bc_rdonly) {
			err = EROFS;
			break;
		}
		if (buf == NULL) {
			if ((len = pwritev(bc->bc_fd, br->br_iov, br->br_iovcnt,
				    br->br_offset)) < 0)
				err = errno;
			else
				br->br_resid -= len;
			break;
		}
		i = 0;
		off = voff = 0;
		while (br->br_resid > 0) {
			len = MIN(br->br_resid, MAXPHYS);
			boff = 0;
			do {
				clen = MIN(len - boff, br->br_iov[i].iov_len -
				    voff);
				memcpy(buf + boff,
				    br->br_iov[i].iov_base + voff, clen);
				if (clen < br->br_iov[i].iov_len - voff)
					voff += clen;
				else {
					i++;
					voff = 0;
				}
				boff += clen;
			} while (boff < len);
			if (pwrite(bc->bc_fd, buf, len, br->br_offset +
			    off) < 0) {
				err = errno;
				break;
			}
			off += len;
			br->br_resid -= len;
		}
		break;
	case BOP_FLUSH:
#ifdef	__FreeBSD__
		if (bc->bc_ischr) {
			if (ioctl(bc->bc_fd, DIOCGFLUSH))
				err = errno;
		} else if (fsync(bc->bc_fd))
			err = errno;
#else
		/*
		 * This fsync() should be adequate to flush the cache of a file
		 * or device.  In VFS, the VOP_SYNC operation is converted to
		 * the appropriate ioctl in both sdev (for real devices) and
		 * zfs (for zvols).
		 */
		if (fsync(bc->bc_fd))
			err = errno;
#endif
		break;
	case BOP_DELETE:
		if (!bc->bc_candelete)
			err = EOPNOTSUPP;
		else if (bc->bc_rdonly)
			err = EROFS;
#ifdef	__FreeBSD__
		else if (bc->bc_ischr) {
			arg[0] = br->br_offset;
			arg[1] = br->br_resid;
			if (ioctl(bc->bc_fd, DIOCGDELETE, arg))
				err = errno;
			else
				br->br_resid = 0;
		}
#endif
		else
			 err = EOPNOTSUPP;
		break;
	default:
		err = EINVAL;
		break;
	}

	be->be_status = BST_DONE;

	(*br->br_callback)(br, err);
}

static void *
blockif_thr(void *arg)
{
	struct blockif_ctxt *bc;
	struct blockif_elem *be;
	pthread_t t;
	uint8_t *buf;

	bc = arg;
	if (bc->bc_isgeom)
		buf = malloc(MAXPHYS);
	else
		buf = NULL;
	t = pthread_self();

	pthread_mutex_lock(&bc->bc_mtx);
	for (;;) {
		while (blockif_dequeue(bc, t, &be)) {
			pthread_mutex_unlock(&bc->bc_mtx);
			blockif_proc(bc, be, buf);
			pthread_mutex_lock(&bc->bc_mtx);
			blockif_complete(bc, be);
		}
		/* Check ctxt status here to see if exit requested */
		if (bc->bc_closing)
			break;
		pthread_cond_wait(&bc->bc_cond, &bc->bc_mtx);
	}
	pthread_mutex_unlock(&bc->bc_mtx);

	if (buf)
		free(buf);
	pthread_exit(NULL);
	return (NULL);
}

#ifdef	__FreeBSD__
static void
blockif_sigcont_handler(int signal, enum ev_type type, void *arg)
#else
static void
blockif_sigcont_handler(int signal)
#endif
{
	struct blockif_sig_elem *bse;

	for (;;) {
		/*
		 * Process the entire list even if not intended for
		 * this thread.
		 */
		do {
			bse = blockif_bse_head;
			if (bse == NULL)
				return;
		} while (!atomic_cmpset_ptr((uintptr_t *)&blockif_bse_head,
					    (uintptr_t)bse,
					    (uintptr_t)bse->bse_next));

		pthread_mutex_lock(&bse->bse_mtx);
		bse->bse_pending = 0;
		pthread_cond_signal(&bse->bse_cond);
		pthread_mutex_unlock(&bse->bse_mtx);
	}
}

static void
blockif_init(void)
{
#ifdef	__FreeBSD__
	mevent_add(SIGCONT, EVF_SIGNAL, blockif_sigcont_handler, NULL);
	(void) signal(SIGCONT, SIG_IGN);
#else
	(void) sigset(SIGCONT, blockif_sigcont_handler);
#endif
}

struct blockif_ctxt *
blockif_open(const char *optstr, const char *ident)
{
	char tname[MAXCOMLEN + 1];
#ifdef	__FreeBSD__
	char name[MAXPATHLEN];
	char *nopt, *xopts, *cp;
#else
	char *nopt, *xopts, *cp = NULL;
#endif
	struct blockif_ctxt *bc;
	struct stat sbuf;
#ifdef	__FreeBSD__
	struct diocgattr_arg arg;
#else
	enum blockif_wce wce = WCE_NONE;
#endif
	off_t size, psectsz, psectoff;
	int extra, fd, i, sectsz;
	int nocache, sync, ro, candelete, geom, ssopt, pssopt;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { DIOCGFLUSH, DIOCGDELETE };
#endif

	pthread_once(&blockif_once, blockif_init);

	fd = -1;
	ssopt = 0;
	nocache = 0;
	sync = 0;
	ro = 0;

	/*
	 * The first element in the optstring is always a pathname.
	 * Optional elements follow
	 */
	nopt = xopts = strdup(optstr);
	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt)		/* file or device pathname */
			continue;
		else if (!strcmp(cp, "nocache"))
			nocache = 1;
		else if (!strcmp(cp, "sync") || !strcmp(cp, "direct"))
			sync = 1;
		else if (!strcmp(cp, "ro"))
			ro = 1;
		else if (sscanf(cp, "sectorsize=%d/%d", &ssopt, &pssopt) == 2)
			;
		else if (sscanf(cp, "sectorsize=%d", &ssopt) == 1)
			pssopt = ssopt;
		else {
			fprintf(stderr, "Invalid device option \"%s\"\n", cp);
			goto err;
		}
	}

	extra = 0;
	if (nocache)
		extra |= O_DIRECT;
	if (sync)
		extra |= O_SYNC;

	fd = open(nopt, (ro ? O_RDONLY : O_RDWR) | extra);
	if (fd < 0 && !ro) {
		/* Attempt a r/w fail with a r/o open */
		fd = open(nopt, O_RDONLY | extra);
		ro = 1;
	}

	if (fd < 0) {
		warn("Could not open backing file: %s", nopt);
		goto err;
	}

        if (fstat(fd, &sbuf) < 0) {
		warn("Could not stat backing file %s", nopt);
		goto err;
        }

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_FSYNC, CAP_IOCTL, CAP_READ, CAP_SEEK,
	    CAP_WRITE);
	if (ro)
		cap_rights_clear(&rights, CAP_FSYNC, CAP_WRITE);

	if (caph_rights_limit(fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

        /*
	 * Deal with raw devices
	 */
        size = sbuf.st_size;
	sectsz = DEV_BSIZE;
	psectsz = psectoff = 0;
	candelete = geom = 0;
#ifdef	__FreeBSD__
	if (S_ISCHR(sbuf.st_mode)) {
		if (ioctl(fd, DIOCGMEDIASIZE, &size) < 0 ||
		    ioctl(fd, DIOCGSECTORSIZE, &sectsz)) {
			perror("Could not fetch dev blk/sector size");
			goto err;
		}
		assert(size != 0);
		assert(sectsz != 0);
		if (ioctl(fd, DIOCGSTRIPESIZE, &psectsz) == 0 && psectsz > 0)
			ioctl(fd, DIOCGSTRIPEOFFSET, &psectoff);
		strlcpy(arg.name, "GEOM::candelete", sizeof(arg.name));
		arg.len = sizeof(arg.value.i);
		if (ioctl(fd, DIOCGATTR, &arg) == 0)
			candelete = arg.value.i;
		if (ioctl(fd, DIOCGPROVIDERNAME, name) == 0)
			geom = 1;
	} else {
		psectsz = sbuf.st_blksize;
	}
#else
	psectsz = sbuf.st_blksize;
	if (S_ISCHR(sbuf.st_mode)) {
		struct dk_minfo_ext dkmext;
		int wce_val;

		/* Look for a more accurate physical blocksize */
		if (ioctl(fd, DKIOCGMEDIAINFOEXT, &dkmext) == 0) {
			psectsz = dkmext.dki_pbsize;
		}
		/* See if a configurable write cache is present and working */
		if (ioctl(fd, DKIOCGETWCE, &wce_val) == 0) {
			/*
			 * If WCE is already active, disable it until the
			 * specific device driver calls for its return.  If it
			 * is not active, toggle it on and off to verify that
			 * such actions are possible.
			 */
			if (wce_val != 0) {
				wce_val = 0;
				/*
				 * Inability to disable the cache is a threat
				 * to data durability.
				 */
				assert(ioctl(fd, DKIOCSETWCE, &wce_val) == 0);
				wce = WCE_IOCTL;
			} else {
				int r1, r2;

				wce_val = 1;
				r1 = ioctl(fd, DKIOCSETWCE, &wce_val);
				wce_val = 0;
				r2 = ioctl(fd, DKIOCSETWCE, &wce_val);

				if (r1 == 0 && r2 == 0) {
					wce = WCE_IOCTL;
				} else {
					/*
					 * If the cache cache toggle was not
					 * successful, ensure that the cache
					 * was not left enabled.
					 */
					assert(r1 != 0);
				}
			}
		}
	} else {
		int flags;

		if ((flags = fcntl(fd, F_GETFL)) >= 0) {
			flags |= O_DSYNC;
			if (fcntl(fd, F_SETFL, flags) != -1) {
				wce = WCE_FCNTL;
			}
		}
	}
#endif

#ifndef WITHOUT_CAPSICUM
	if (caph_ioctls_limit(fd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	if (ssopt != 0) {
		if (!powerof2(ssopt) || !powerof2(pssopt) || ssopt < 512 ||
		    ssopt > pssopt) {
			fprintf(stderr, "Invalid sector size %d/%d\n",
			    ssopt, pssopt);
			goto err;
		}

		/*
		 * Some backend drivers (e.g. cd0, ada0) require that the I/O
		 * size be a multiple of the device's sector size.
		 *
		 * Validate that the emulated sector size complies with this
		 * requirement.
		 */
		if (S_ISCHR(sbuf.st_mode)) {
			if (ssopt < sectsz || (ssopt % sectsz) != 0) {
				fprintf(stderr, "Sector size %d incompatible "
				    "with underlying device sector size %d\n",
				    ssopt, sectsz);
				goto err;
			}
		}

		sectsz = ssopt;
		psectsz = pssopt;
		psectoff = 0;
	}

	bc = calloc(1, sizeof(struct blockif_ctxt));
	if (bc == NULL) {
		perror("calloc");
		goto err;
	}

	bc->bc_magic = BLOCKIF_SIG;
	bc->bc_fd = fd;
	bc->bc_ischr = S_ISCHR(sbuf.st_mode);
	bc->bc_isgeom = geom;
	bc->bc_candelete = candelete;
#ifndef __FreeBSD__
	bc->bc_wce = wce;
#endif
	bc->bc_rdonly = ro;
	bc->bc_size = size;
	bc->bc_sectsz = sectsz;
	bc->bc_psectsz = psectsz;
	bc->bc_psectoff = psectoff;
	pthread_mutex_init(&bc->bc_mtx, NULL);
	pthread_cond_init(&bc->bc_cond, NULL);
	TAILQ_INIT(&bc->bc_freeq);
	TAILQ_INIT(&bc->bc_pendq);
	TAILQ_INIT(&bc->bc_busyq);
	for (i = 0; i < BLOCKIF_MAXREQ; i++) {
		bc->bc_reqs[i].be_status = BST_FREE;
		TAILQ_INSERT_HEAD(&bc->bc_freeq, &bc->bc_reqs[i], be_link);
	}

	for (i = 0; i < BLOCKIF_NUMTHR; i++) {
		pthread_create(&bc->bc_btid[i], NULL, blockif_thr, bc);
		snprintf(tname, sizeof(tname), "blk-%s-%d", ident, i);
		pthread_set_name_np(bc->bc_btid[i], tname);
	}

	return (bc);
err:
	if (fd >= 0)
		close(fd);
	free(nopt);
	return (NULL);
}

static int
blockif_request(struct blockif_ctxt *bc, struct blockif_req *breq,
		enum blockop op)
{
	int err;

	err = 0;

	pthread_mutex_lock(&bc->bc_mtx);
	if (!TAILQ_EMPTY(&bc->bc_freeq)) {
		/*
		 * Enqueue and inform the block i/o thread
		 * that there is work available
		 */
		if (blockif_enqueue(bc, breq, op))
			pthread_cond_signal(&bc->bc_cond);
	} else {
		/*
		 * Callers are not allowed to enqueue more than
		 * the specified blockif queue limit. Return an
		 * error to indicate that the queue length has been
		 * exceeded.
		 */
		err = E2BIG;
	}
	pthread_mutex_unlock(&bc->bc_mtx);

	return (err);
}

int
blockif_read(struct blockif_ctxt *bc, struct blockif_req *breq)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (blockif_request(bc, breq, BOP_READ));
}

int
blockif_write(struct blockif_ctxt *bc, struct blockif_req *breq)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (blockif_request(bc, breq, BOP_WRITE));
}

int
blockif_flush(struct blockif_ctxt *bc, struct blockif_req *breq)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (blockif_request(bc, breq, BOP_FLUSH));
}

int
blockif_delete(struct blockif_ctxt *bc, struct blockif_req *breq)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (blockif_request(bc, breq, BOP_DELETE));
}

int
blockif_cancel(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	struct blockif_elem *be;

	assert(bc->bc_magic == BLOCKIF_SIG);

	pthread_mutex_lock(&bc->bc_mtx);
	/*
	 * Check pending requests.
	 */
	TAILQ_FOREACH(be, &bc->bc_pendq, be_link) {
		if (be->be_req == breq)
			break;
	}
	if (be != NULL) {
		/*
		 * Found it.
		 */
		blockif_complete(bc, be);
		pthread_mutex_unlock(&bc->bc_mtx);

		return (0);
	}

	/*
	 * Check in-flight requests.
	 */
	TAILQ_FOREACH(be, &bc->bc_busyq, be_link) {
		if (be->be_req == breq)
			break;
	}
	if (be == NULL) {
		/*
		 * Didn't find it.
		 */
		pthread_mutex_unlock(&bc->bc_mtx);
		return (EINVAL);
	}

	/*
	 * Interrupt the processing thread to force it return
	 * prematurely via it's normal callback path.
	 */
	while (be->be_status == BST_BUSY) {
		struct blockif_sig_elem bse, *old_head;

		pthread_mutex_init(&bse.bse_mtx, NULL);
		pthread_cond_init(&bse.bse_cond, NULL);

		bse.bse_pending = 1;

		do {
			old_head = blockif_bse_head;
			bse.bse_next = old_head;
		} while (!atomic_cmpset_ptr((uintptr_t *)&blockif_bse_head,
					    (uintptr_t)old_head,
					    (uintptr_t)&bse));

		pthread_kill(be->be_tid, SIGCONT);

		pthread_mutex_lock(&bse.bse_mtx);
		while (bse.bse_pending)
			pthread_cond_wait(&bse.bse_cond, &bse.bse_mtx);
		pthread_mutex_unlock(&bse.bse_mtx);
	}

	pthread_mutex_unlock(&bc->bc_mtx);

	/*
	 * The processing thread has been interrupted.  Since it's not
	 * clear if the callback has been invoked yet, return EBUSY.
	 */
	return (EBUSY);
}

int
blockif_close(struct blockif_ctxt *bc)
{
	void *jval;
	int i;

	assert(bc->bc_magic == BLOCKIF_SIG);

	/*
	 * Stop the block i/o thread
	 */
	pthread_mutex_lock(&bc->bc_mtx);
	bc->bc_closing = 1;
	pthread_mutex_unlock(&bc->bc_mtx);
	pthread_cond_broadcast(&bc->bc_cond);
	for (i = 0; i < BLOCKIF_NUMTHR; i++)
		pthread_join(bc->bc_btid[i], &jval);

	/* XXX Cancel queued i/o's ??? */

	/*
	 * Release resources
	 */
	bc->bc_magic = 0;
	close(bc->bc_fd);
	free(bc);

	return (0);
}

/*
 * Return virtual C/H/S values for a given block. Use the algorithm
 * outlined in the VHD specification to calculate values.
 */
void
blockif_chs(struct blockif_ctxt *bc, uint16_t *c, uint8_t *h, uint8_t *s)
{
	off_t sectors;		/* total sectors of the block dev */
	off_t hcyl;		/* cylinders times heads */
	uint16_t secpt;		/* sectors per track */
	uint8_t heads;

	assert(bc->bc_magic == BLOCKIF_SIG);

	sectors = bc->bc_size / bc->bc_sectsz;

	/* Clamp the size to the largest possible with CHS */
	if (sectors > 65535UL*16*255)
		sectors = 65535UL*16*255;

	if (sectors >= 65536UL*16*63) {
		secpt = 255;
		heads = 16;
		hcyl = sectors / secpt;
	} else {
		secpt = 17;
		hcyl = sectors / secpt;
		heads = (hcyl + 1023) / 1024;

		if (heads < 4)
			heads = 4;

		if (hcyl >= (heads * 1024) || heads > 16) {
			secpt = 31;
			heads = 16;
			hcyl = sectors / secpt;
		}
		if (hcyl >= (heads * 1024)) {
			secpt = 63;
			heads = 16;
			hcyl = sectors / secpt;
		}
	}

	*c = hcyl / heads;
	*h = heads;
	*s = secpt;
}

/*
 * Accessors
 */
off_t
blockif_size(struct blockif_ctxt *bc)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (bc->bc_size);
}

int
blockif_sectsz(struct blockif_ctxt *bc)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (bc->bc_sectsz);
}

void
blockif_psectsz(struct blockif_ctxt *bc, int *size, int *off)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	*size = bc->bc_psectsz;
	*off = bc->bc_psectoff;
}

int
blockif_queuesz(struct blockif_ctxt *bc)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (BLOCKIF_MAXREQ - 1);
}

int
blockif_is_ro(struct blockif_ctxt *bc)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (bc->bc_rdonly);
}

int
blockif_candelete(struct blockif_ctxt *bc)
{

	assert(bc->bc_magic == BLOCKIF_SIG);
	return (bc->bc_candelete);
}

#ifndef __FreeBSD__
int
blockif_set_wce(struct blockif_ctxt *bc, int wc_enable)
{
	int res = 0, flags;
	int clean_val = (wc_enable != 0) ? 1 : 0;

	(void) pthread_mutex_lock(&bc->bc_mtx);
	switch (bc->bc_wce) {
	case WCE_IOCTL:
		res = ioctl(bc->bc_fd, DKIOCSETWCE, &clean_val);
		break;
	case WCE_FCNTL:
		if ((flags = fcntl(bc->bc_fd, F_GETFL)) >= 0) {
			if (wc_enable == 0) {
				flags |= O_DSYNC;
			} else {
				flags &= ~O_DSYNC;
			}
			if (fcntl(bc->bc_fd, F_SETFL, flags) == -1) {
				res = -1;
			}
		} else {
			res = -1;
		}
		break;
	default:
		break;
	}

	/*
	 * After a successful disable of the write cache, ensure that any
	 * lingering data in the cache is synced out.
	 */
	if (res == 0 && wc_enable == 0) {
		res = fsync(bc->bc_fd);
	}
	(void) pthread_mutex_unlock(&bc->bc_mtx);

	return (res);
}
#endif /* __FreeBSD__ */
