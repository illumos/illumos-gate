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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nfs log - read buffer file and return structs in usable form
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <strings.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <limits.h>
#include <libintl.h>
#include <values.h>
#include <search.h>
#include <pwd.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <netdir.h>
#include <nfs/nfs_sec.h>
#include <nfs/export.h>
#include <rpc/auth.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <rpc/clnt.h>
#include <nfs/nfs.h>
#include <nfs/nfs_log.h>
#include "nfslogd.h"

#define	MAX_LRS_READ_AHEAD 2048
#define	MAX_RECS_TO_DELAY 32768

static int 		nfslog_init_buf(char *, struct nfslog_buf *, int *);
static void		nfslog_free_buf(struct nfslog_buf *, int);
static struct nfslog_lr *nfslog_read_buffer(struct nfslog_buf *);
static void		free_lrp(struct nfslog_lr *);
static struct nfslog_lr *remove_lrp_from_lb(struct nfslog_buf *,
			struct nfslog_lr *);
static void		insert_lrp_to_lb(struct nfslog_buf *,
			struct nfslog_lr *);
static void		nfslog_rewrite_bufheader(struct nfslog_buf *);

/*
 * Treat the provided path name as an NFS log buffer file.
 * Allocate a data structure for its handling and initialize it.
 * *error contains the previous error condition encountered for
 * this object. This value can be used to avoid printing the last
 * error endlessly.
 * It will set *error appropriately after processing.
 */
struct nfslog_buf *
nfslog_open_buf(char *bufpath, int *error)
{
	struct nfslog_buf	*lbp = NULL;

	if (bufpath == NULL) {
		*error = EINVAL;
		return (NULL);
	}

	if ((lbp = malloc(sizeof (struct nfslog_buf))) == NULL) {
		*error = ENOMEM;
		return (NULL);
	}
	bzero(lbp, sizeof (struct nfslog_buf));

	if (nfslog_init_buf(bufpath, lbp, error)) {
		free(lbp);
		return (NULL);
	}
	return (lbp);
}

/*
 * Free the log buffer struct with all of its baggage and free the data struct
 */
void
nfslog_close_buf(struct nfslog_buf *lbp, int close_quick)
{
	nfslog_free_buf(lbp, close_quick);
	free(lbp);
}

/*
 * Set up the log buffer struct; simple things are opening and locking
 * the buffer file and then on to mmap()ing it for later use by the
 * XDR decode path.  Make sure to read the buffer header before
 * returning so that we will be at the first true log record.
 *
 * *error contains the last error encountered on this object. It can
 * be used to avoid reporting the same error endlessly. It is reset
 * to the current error code on return.
 */
static int
nfslog_init_buf(char *bufpath, struct nfslog_buf *lbp, int *error)
{
	struct stat sb;
	int preverror = *error;

	lbp->next = lbp;
	lbp->prev = lbp;
	/*
	 * set these values so that the free routine will know what to do
	 */
	lbp->mmap_addr = (intptr_t)MAP_FAILED;
	lbp->last_rec_id = MAXINT - 1;
	lbp->bh.bh_length = 0;
	lbp->bh_lrp = NULL;
	lbp->num_lrps = 0;
	lbp->lrps = NULL;
	lbp->last_record_offset = 0;
	lbp->prp = NULL;
	lbp->num_pr_queued = 0;

	lbp->bufpath = strdup(bufpath);
	if (lbp->bufpath == NULL) {
		*error = ENOMEM;
		if (preverror != *error) {
			syslog(LOG_ERR, gettext("Cannot strdup '%s': %s"),
				bufpath, strerror(*error));
		}
		nfslog_free_buf(lbp, FALSE);
		return (*error);
	}

	if ((lbp->fd = open(bufpath, O_RDWR)) < 0) {
		*error = errno;
		if (preverror != *error) {
			syslog(LOG_ERR, gettext("Cannot open '%s': %s"),
				bufpath, strerror(*error));
		}
		nfslog_free_buf(lbp, FALSE);
		return (*error);
	}

	/*
	 * Lock the entire buffer file to prevent conflicting access.
	 * We get a write lock because we want only 1 process to be
	 * generating records from it.
	 */
	lbp->fl.l_type = F_WRLCK;
	lbp->fl.l_whence = SEEK_SET;		/* beginning of file */
	lbp->fl.l_start = (offset_t)0;
	lbp->fl.l_len = 0;			/* entire file */
	lbp->fl.l_sysid = 0;
	lbp->fl.l_pid = 0;
	if (fcntl(lbp->fd, F_SETLKW, &lbp->fl) == -1) {
		*error = errno;
		if (preverror != *error) {
			syslog(LOG_ERR, gettext("Cannot lock (%s): %s"),
				bufpath, strerror(*error));
		}
		nfslog_free_buf(lbp, FALSE);
		return (*error);
	}

	if (fstat(lbp->fd, &sb)) {
		*error = errno;
		if (preverror != *error) {
			syslog(LOG_ERR, gettext("Cannot stat (%s): %s"),
				bufpath, strerror(*error));
		}
		nfslog_free_buf(lbp, FALSE);
		return (*error);
	}
	lbp->filesize = sb.st_size;

	lbp->mmap_addr = (intptr_t)mmap(0, lbp->filesize, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_NORESERVE, lbp->fd, 0);

	/* This is part of the duality of the use of either mmap()|read() */
	if (lbp->mmap_addr == (intptr_t)MAP_FAILED) {
		lbp->next_rec = 0;
	} else {
		lbp->next_rec = lbp->mmap_addr;
	}

	/* Read the header */
	if ((lbp->bh_lrp = nfslog_read_buffer(lbp)) == NULL) {
		*error = EIO;
		if (preverror != *error) {
			syslog(LOG_ERR, gettext(
				"error in reading file '%s': %s"),
				bufpath, strerror(EIO));
		}
		nfslog_free_buf(lbp, FALSE);
		return (*error);
	}

	if (!xdr_nfslog_buffer_header(&lbp->bh_lrp->xdrs, &lbp->bh)) {
		*error = EIO;
		if (preverror != *error) {
			syslog(LOG_ERR, gettext(
				"error in reading file '%s': %s"),
				bufpath, strerror(*error));
		}
		nfslog_free_buf(lbp, FALSE);
		return (*error);
	}

	/*
	 * Set the pointer to the next record based on the buffer header.
	 * 'lbp->bh.bh_offset' contains the offset of where to begin
	 * processing relative to the buffer header.
	 */
	lbp->next_rec += lbp->bh.bh_offset;

	/*
	 * If we are going to be using read() for file data, then we may
	 * have to adjust the current file pointer to take into account
	 * a starting point other than the beginning of the file.
	 * If mmap is being used, this is taken care of as a side effect of
	 * setting up the value of next_rec.
	 */
	if (lbp->mmap_addr == (intptr_t)MAP_FAILED && lbp->next_rec != 0) {
		(void) lseek(lbp->fd, lbp->next_rec, SEEK_SET);
		/* This is a special case of setting the last_record_offset */
		lbp->last_record_offset = lbp->next_rec;
	} else {
		lbp->last_record_offset = lbp->next_rec - lbp->mmap_addr;
	}

	return (*error = 0);
}

/*
 * Free the nfslog buffer and its associated allocations
 */
static void
nfslog_free_buf(struct nfslog_buf *lbp, int close_quick)
{
	XDR	xdrs;
	int	error;
	caddr_t buffer;
	struct nfslog_lr *lrp, *lrp_next;
	struct processed_records *prp, *tprp;

	/* work to free the offset records and rewrite header */
	if (lbp->prp) {
		if (lbp->last_record_offset == lbp->prp->start_offset) {

			/* adjust the offset for the entire buffer */
			lbp->last_record_offset =
				lbp->prp->start_offset + lbp->prp->len;

			nfslog_rewrite_bufheader(lbp);
		}
		if (close_quick)
			return;
		prp = lbp->prp;
		do {
			tprp = prp->next;
			free(prp);
			prp = tprp;
		} while (lbp->prp != prp);
	}

	if (close_quick)
		return;

	/* Take care of the queue log records first */
	if (lbp->lrps != NULL) {
		lrp = lbp->lrps;
		do {
			lrp_next = lrp->next;
			nfslog_free_logrecord(lrp, FALSE);
			lrp = lrp_next;
		} while (lrp != lbp->lrps);
		lbp->lrps = NULL;
	}

	/* The buffer header was decoded and needs to be freed */
	if (lbp->bh.bh_length != 0) {
		buffer = (lbp->bh_lrp->buffer != NULL ?
			lbp->bh_lrp->buffer : (caddr_t)lbp->mmap_addr);
		xdrmem_create(&xdrs, buffer, lbp->bh_lrp->recsize, XDR_FREE);
		(void) xdr_nfslog_buffer_header(&xdrs, &lbp->bh);
		lbp->bh.bh_length = 0;
	}

	/* get rid of the bufheader lrp */
	if (lbp->bh_lrp != NULL) {
		free_lrp(lbp->bh_lrp);
		lbp->bh_lrp = NULL;
	}

	/* Clean up for mmap() usage */
	if (lbp->mmap_addr != (intptr_t)MAP_FAILED) {
		if (munmap((void *)lbp->mmap_addr, lbp->filesize)) {
			error = errno;
			syslog(LOG_ERR, gettext("munmap failed: %s: %s"),
				(lbp->bufpath != NULL ? lbp->bufpath : ""),
				strerror(error));
		}
		lbp->mmap_addr = (intptr_t)MAP_FAILED;
	}

	/* Finally close the buffer file */
	if (lbp->fd >= 0) {
		lbp->fl.l_type = F_UNLCK;
		if (fcntl(lbp->fd, F_SETLK, &lbp->fl) == -1) {
			error = errno;
			syslog(LOG_ERR,
				gettext("Cannot unlock file %s: %s"),
				(lbp->bufpath != NULL ? lbp->bufpath : ""),
				strerror(error));
		}
		(void) close(lbp->fd);
		lbp->fd = -1;
	}
	if (lbp->bufpath != NULL)
		free(lbp->bufpath);
}

/*
 * We are reading a record from the log buffer file.  Since we are reading
 * an XDR stream, we first have to read the first integer to determine
 * how much to read in whole for this record.  Our preference is to use
 * mmap() but if failed initially we will be using read().  Need to be
 * careful about proper initialization of the log record both from a field
 * perspective and for XDR decoding.
 */
static struct nfslog_lr *
nfslog_read_buffer(struct nfslog_buf *lbp)
{
	XDR xdrs;
	unsigned int	record_size;
	struct nfslog_lr *lrp;
	char		*sizebuf, tbuf[16];
	caddr_t		buffer;
	offset_t	next_rec;

	lrp = (struct nfslog_lr *)malloc(sizeof (*lrp));
	bzero(lrp, sizeof (*lrp));

	/* Check to see if mmap worked */
	if (lbp->mmap_addr == (intptr_t)MAP_FAILED) {
		/*
		 * EOF or other failure; we don't try to recover, just return
		 */
		if (read(lbp->fd, tbuf, BYTES_PER_XDR_UNIT) <= 0) {
			free_lrp(lrp);
			return (NULL);
		}
		sizebuf = tbuf;
	} else {
		/* EOF check for the mmap() case */
		if (lbp->filesize <= lbp->next_rec - lbp->mmap_addr) {
			free_lrp(lrp);
			return (NULL);
		}
		sizebuf = (char *)(uintptr_t)lbp->next_rec;
	}

	/* We have to XDR the first int so we know how much is in this record */
	xdrmem_create(&xdrs, sizebuf, sizeof (unsigned int), XDR_DECODE);

	if (!xdr_u_int(&xdrs, &record_size)) {
		free_lrp(lrp);
		return (NULL);
	}

	lrp->recsize = record_size;
	next_rec = lbp->next_rec + lrp->recsize;

	if (lbp->mmap_addr == (intptr_t)MAP_FAILED) {
		/*
		 * Read() case - shouldn't be used very much.
		 * Note: The 'buffer' field is used later on
		 * to determine which method is being used mmap()|read()
		 */
		if (lbp->filesize < next_rec) {
			/* partial record from buffer */
			syslog(LOG_ERR, gettext(
				"Last partial record in work buffer %s "
				"discarded\n"), lbp->bufpath);
			free_lrp(lrp);
			return (NULL);
		}

		if ((lrp->buffer = malloc(lrp->recsize)) == NULL) {
			free_lrp(lrp);
			return (NULL);
		}
		bcopy(sizebuf, lrp->buffer, BYTES_PER_XDR_UNIT);
		if (read(lbp->fd, &lrp->buffer[BYTES_PER_XDR_UNIT],
			lrp->recsize - BYTES_PER_XDR_UNIT) <= 0) {
			free_lrp(lrp);
			return (NULL);
		}
	} else if (lbp->filesize < next_rec - lbp->mmap_addr) {
			/* partial record from buffer */
			syslog(LOG_ERR, gettext(
				"Last partial record in work buffer %s "
				"discarded\n"), lbp->bufpath);
			free_lrp(lrp);
			return (NULL);
	}


	/* other initializations */
	lrp->next = lrp->prev = lrp;
	/* Keep track of the offset at which this record was read */
	if (lbp->mmap_addr == (intptr_t)MAP_FAILED)
		lrp->f_offset = lbp->next_rec;
	else
		lrp->f_offset = lbp->next_rec - lbp->mmap_addr;
	/* This is the true address of the record */
	lrp->record = lbp->next_rec;
	lrp->xdrargs = lrp->xdrres = NULL;
	lrp->lbp = lbp;

	/* Here is the logic for mmap() vs. read() */
	buffer = (lrp->buffer != NULL ? lrp->buffer : (caddr_t)lrp->record);

	/* Setup for the 'real' XDR decode of the entire record */
	xdrmem_create(&lrp->xdrs, buffer, lrp->recsize, XDR_DECODE);

	/* calculate the offset for the next record */
	lbp->next_rec = next_rec;

	return (lrp);
}

/*
 * Simple removal of the log record from the log buffer queue.
 * Make sure to manage the count of records queued.
 */
static struct nfslog_lr *
remove_lrp_from_lb(struct nfslog_buf *lbp, struct nfslog_lr *lrp)
{
	if (lbp->lrps == lrp) {
		if (lbp->lrps == lbp->lrps->next) {
			lbp->lrps = NULL;
		} else {
			lbp->lrps = lrp->next;
			remque(lrp);
		}
	} else {
		remque(lrp);
	}
	lbp->num_lrps--;
	return (lrp);
}

/*
 * Insert a log record struct on the log buffer struct.  The log buffer
 * has a pointer to the head of a queue of log records that have been
 * read from the buffer file but have not been processed yet because
 * the record id did not match the sequence desired for processing.
 * The insertion must be in the 'correct'/sorted order which adds
 * to the complexity of this function.
 */
static void
insert_lrp_to_lb(struct nfslog_buf *lbp, struct nfslog_lr *lrp)
{
	int ins_rec_id = lrp->log_record.re_header.rh_rec_id;
	struct nfslog_lr *curlrp;

	if (lbp->lrps == NULL) {
		/* that was easy */
		lbp->lrps = lrp;
	} else {
		/*
		 * Does this lrp go before the first on the list?
		 * If so, do the insertion by hand since insque is not
		 * as flexible when queueing an element to the head of
		 * a list.
		 */
		if (ins_rec_id < lbp->lrps->log_record.re_header.rh_rec_id) {
			lrp->next = lbp->lrps;
			lrp->prev = lbp->lrps->prev;
			lbp->lrps->prev->next = lrp;
			lbp->lrps->prev = lrp;
			lbp->lrps = lrp;
		} else {
			/*
			 * Search the queue for the correct insertion point.
			 * Be careful about the insque so that the record
			 * ends up in the right place.
			 */
			curlrp = lbp->lrps;
			do {
				if (ins_rec_id <
				curlrp->next->log_record.re_header.rh_rec_id)
					break;
				curlrp = curlrp->next;
			} while (curlrp != lbp->lrps);
			if (curlrp == lbp->lrps)
				insque(lrp, lbp->lrps->prev);
			else
				insque(lrp, curlrp);
		}
	}
	/* always keep track of how many we have */
	lbp->num_lrps++;
}

/*
 * We are rewriting the buffer header at the start of the log buffer
 * for the sole purpose of resetting the bh_offset field.  This is
 * supposed to represent the progress that the nfslogd daemon has made
 * in its processing of the log buffer file.
 * 'lbp->last_record_offset' contains the absolute offset of the end
 * of the last element processed. The on-disk buffer offset is relative
 * to the buffer header, therefore we subtract the length of the buffer
 * header from the absolute offset.
 */
static void
nfslog_rewrite_bufheader(struct nfslog_buf *lbp)
{
	XDR xdrs;
	nfslog_buffer_header bh;
	/* size big enough for buffer header encode */
#define	XBUFSIZE 128
	char buffer[XBUFSIZE];
	unsigned int wsize;

	/*
	 * if version 1 buffer is large and the current offset cannot be
	 * represented, then don't update the offset in the buffer.
	 */
	if (lbp->bh.bh_flags & NFSLOG_BH_OFFSET_OVERFLOW) {
		/* No need to update the header - offset too big */
		return;
	}
	/*
	 * build the buffer header from the original that was saved
	 * on initialization; note that the offset is taken from the
	 * last record processed (the last offset that represents
	 * all records processed without any holes in the processing)
	 */
	bh = lbp->bh;

	/*
	 * if version 1 buffer is large and the current offset cannot be
	 * represented in 32 bits, then save only the last valid offset
	 * in the buffer and mark the flags to indicate that.
	 */
	if ((bh.bh_version > 1) ||
		(lbp->last_record_offset - bh.bh_length < UINT32_MAX)) {
		bh.bh_offset = lbp->last_record_offset - bh.bh_length;
	} else {
		/* don't update the offset in the buffer */
		bh.bh_flags |= NFSLOG_BH_OFFSET_OVERFLOW;
		lbp->bh.bh_flags = bh.bh_flags;
		syslog(LOG_ERR, gettext(
			"nfslog_rewrite_bufheader: %s: offset does not fit "
			"in a 32 bit field\n"), lbp->bufpath);
	}

	xdrmem_create(&xdrs, buffer, XBUFSIZE, XDR_ENCODE);

	if (!xdr_nfslog_buffer_header(&xdrs, &bh)) {
		syslog(LOG_ERR, gettext(
			"error in re-writing buffer file %s header\n"),
			lbp->bufpath);
		return;
	}

	wsize = xdr_getpos(&xdrs);

	if (lbp->mmap_addr == (intptr_t)MAP_FAILED) {
		/* go to the beginning of the file */
		(void) lseek(lbp->fd, 0, SEEK_SET);
		(void) write(lbp->fd, buffer, wsize);
		(void) lseek(lbp->fd, lbp->next_rec, SEEK_SET);
		(void) fsync(lbp->fd);
	} else {
		bcopy(buffer, (void *)lbp->mmap_addr, wsize);
		(void) msync((void *)lbp->mmap_addr, wsize, MS_SYNC);
	}
}

/*
 * With the provided lrp, we will take and 'insert' the range that the
 * record covered in the buffer file into a list of processed ranges
 * for the buffer file.  These ranges represent the records processed
 * but not 'marked' in the buffer header as being processed.
 * This insertion process is being done for two reasons.  The first is that
 * we do not want to pay the performance penalty of re-writing the buffer header
 * for each record that we process.  The second reason is that the records
 * may be processed out of order because of the unique ids.  This will occur
 * if the kernel has written the records to the buffer file out of order.
 * The read routine will 'sort' them as the records are read.
 *
 * We do not want to re-write the buffer header such that a record is
 * represented and being processed when it has not been.  In the case
 * that the nfslogd daemon restarts processing and the buffer header
 * has been re-written improperly, some records could be skipped.
 * We will be taking the conservative approach and only writing buffer
 * header offsets when the entire offset range has been processed.
 */
static void
nfslog_ins_last_rec_processed(struct nfslog_lr *lrp)
{
	struct processed_records *prp, *tp;

	/* init the data struct as if it were the only one */
	prp = malloc(sizeof (*prp));
	prp->next = prp->prev = prp;
	prp->start_offset = lrp->f_offset;
	prp->len = lrp->recsize;
	prp->num_recs = 1;

	/* always add since we know we are going to insert */
	lrp->lbp->num_pr_queued++;

	/* Is this the first one?  If so, take the easy way out */
	if (lrp->lbp->prp == NULL) {
		lrp->lbp->prp = prp;
	} else {
		/* sort on insertion... */
		tp = lrp->lbp->prp;
		do {
			if (prp->start_offset < tp->start_offset)
				break;
			tp = tp->next;
		} while (tp != lrp->lbp->prp);
		/* insert where appropriate (before the one we found */
		insque(prp, tp->prev);
		/*
		 * special case where the insertion was done at the
		 * head of the list
		 */
		if (tp == lrp->lbp->prp && prp->start_offset < tp->start_offset)
			lrp->lbp->prp = prp;

		/*
		 * now that the entry is in place, we need to see if it can
		 * be combined with the previous or following entries.
		 * combination is done by adding to the length.
		 */
		if (prp->start_offset ==
			(prp->prev->start_offset + prp->prev->len)) {
			tp = prp->prev;
			remque(prp);
			tp->len += prp->len;
			tp->num_recs += prp->num_recs;
			free(prp);
			prp = tp;
		}
		if (prp->next->start_offset ==
			(prp->start_offset + prp->len)) {
			prp->len += prp->next->len;
			prp->num_recs += prp->next->num_recs;
			tp = prp->next;
			remque(tp);
			free(tp);
		}
	}

	if (lrp->lbp->num_pr_queued > MAX_RECS_TO_DELAY) {
		prp = lrp->lbp->prp;
		if (lrp->lbp->last_record_offset ==
			prp->start_offset) {

			/* adjust the offset for the entire buffer */
			lrp->lbp->last_record_offset =
				prp->start_offset + prp->len;

			nfslog_rewrite_bufheader(lrp->lbp);

			tp = prp->next;
			if (tp != prp)
				remque(prp);
			else
				tp = NULL;
			lrp->lbp->prp = tp;
			lrp->lbp->num_pr_queued -= prp->num_recs;
			free(prp);
		}
	}
}

/*
 * nfslog_get_logrecord is responsible for retrieving the next log record
 * from the buffer file. This would normally be very straightforward but there
 * is the added complexity of attempting to order the requests coming out of
 * the buffer file.  The fundamental problems is that the kernel nfs logging
 * functionality does not guarantee that the records were written to the file
 * in the order that the NFS server processed them.  This can cause a problem
 * in the fh -> pathname mapping in the case were a lookup for a file comes
 * later in the buffer file than other operations on the lookup's target.
 * The fh mapping database will not have an entry and will therefore not
 * be able to map the fh to a name.
 *
 * So to solve this problem, the kernel nfs logging code tags each record
 * with a monotonically increasing id and is guaranteed to be allocated
 * in the order that the requests were processed.  Realize however that
 * this processing guarantee is essentially for one thread on one client.
 * This id mechanism does not order all requests since it is only the
 * single client/single thread case that is most concerning to us here.
 *
 * This function will do the 'sorting' of the requests as they are
 * read from the buffer file.  The sorting needs to take into account
 * that some ids may be missing (operations not logged but ids allocated)
 * and that the id field will eventually wrap over MAXINT.
 *
 * Complexity to solve the fh -> pathname mapping issue.
 */
struct nfslog_lr *
nfslog_get_logrecord(struct nfslog_buf *lbp)
{
	/* figure out what the next should be if the world were perfect */
	unsigned int next_rec_id = lbp->last_rec_id + 1;
	struct nfslog_lr *lrp = NULL;

	/*
	 * First we check the queued records on the log buffer struct
	 * to see if the one we want is there.  The records are sorted
	 * on the record id during the insertions to the queue so that
	 * this check is easy.
	 */
	if (lbp->lrps != NULL) {
		/* Does the first record match ? */
		if (lbp->lrps->log_record.re_header.rh_rec_id == next_rec_id) {
			lrp = remove_lrp_from_lb(lbp, lbp->lrps);
			lbp->last_rec_id = lrp->log_record.re_header.rh_rec_id;
		} else {
			/*
			 * Here we are checking for wrap of the record id
			 * since it is an unsigned in.  The idea is that
			 * if there is a huge span between what we expect
			 * and what is queued then we need to flush/empty
			 * the queued records first.
			 */
			if (next_rec_id <
				lbp->lrps->log_record.re_header.rh_rec_id &&
				((lbp->lrps->log_record.re_header.rh_rec_id -
					next_rec_id) > (MAXINT / 2))) {

				lrp = remove_lrp_from_lb(lbp, lbp->lrps);
				lbp->last_rec_id =
					lrp->log_record.re_header.rh_rec_id;
			}
		}
	}
	/*
	 * So the first queued record didn't match (or there were no queued
	 * records to look at).  Now we go to the buffer file looking for
	 * the expected log record based on its id.  We loop looking for
	 * a matching records and save/queue the records that don't match.
	 * Note that we will queue a maximum number to handle the case
	 * of a missing record id or a queue that is very confused.  We don't
	 * want to consume too much memory.
	 */
	while (lrp == NULL) {
		/* Have we queued too many for this buffer? */
		if (lbp->num_lrps >= MAX_LRS_READ_AHEAD) {
			lrp = remove_lrp_from_lb(lbp, lbp->lrps);
			lbp->last_rec_id = lrp->log_record.re_header.rh_rec_id;
			break;
		}
		/*
		 * Get a record from the buffer file.  If none are available,
		 * this is probably and EOF condition (could be a read error
		 * as well but that is masked. :-().  No records in the
		 * file means that we need to pull any queued records
		 * so that we don't miss any in the processing.
		 */
		if ((lrp = nfslog_read_buffer(lbp)) == NULL) {
			if (lbp->lrps != NULL) {
				lrp = remove_lrp_from_lb(lbp, lbp->lrps);
				lbp->last_rec_id =
					lrp->log_record.re_header.rh_rec_id;
			} else {
				return (NULL);  /* it was really and EOF */
			}
		} else {
			/*
			 * Just read a record from the buffer file and now we
			 * need to XDR the record header so that we can take
			 * a look at the record id.
			 */
			if (!xdr_nfslog_request_record(&lrp->xdrs,
				&lrp->log_record)) {
				/* Free and return EOF/NULL on error */
				nfslog_free_logrecord(lrp, FALSE);
				return (NULL);
			}
			/*
			 * If the new record is less than or matches the
			 * expected record id, then we return this record
			 */
			if (lrp->log_record.re_header.rh_rec_id <=
				next_rec_id) {

				lbp->last_rec_id =
					lrp->log_record.re_header.rh_rec_id;
			} else {
				/*
				 * This is not the one we were looking
				 * for; queue it for later processing
				 * (queueing sorts on record id)
				 */
				insert_lrp_to_lb(lbp, lrp);
				lrp = NULL;
			}
		}
	}
	return (lrp);
}

/*
 * Free the log record provided.
 * This is complex because the associated XDR streams also need to be freed
 * since allocation could have occured during the DECODE phase.  The record
 * header, args and results need to be XDR_FREEd.  The xdr funtions will
 * be provided if a free needs to be done.
 *
 * Note that caller tells us if the record being freed was processed.
 * If so, then the buffer header should be updated.  Updating the buffer
 * header keeps track of where the nfslogd daemon left off in its processing
 * if it is unable to complete the entire file.
 */
void
nfslog_free_logrecord(struct nfslog_lr *lrp, bool_t processing_complete)
{
	caddr_t			buffer;
	nfslog_request_record 	*reqrec;

	if (processing_complete) {
		nfslog_ins_last_rec_processed(lrp);
	}

	reqrec = &lrp->log_record;

	buffer = (lrp->buffer != NULL ? lrp->buffer : (caddr_t)lrp->record);

	xdrmem_create(&lrp->xdrs, buffer, lrp->recsize, XDR_FREE);

	(void) xdr_nfslog_request_record(&lrp->xdrs, reqrec);

	if (lrp->xdrargs != NULL && reqrec->re_rpc_arg)
		(*lrp->xdrargs)(&lrp->xdrs, reqrec->re_rpc_arg);

	if (reqrec->re_rpc_arg)
		free(reqrec->re_rpc_arg);

	if (lrp->xdrres != NULL && reqrec->re_rpc_res)
		(*lrp->xdrres)(&lrp->xdrs, reqrec->re_rpc_res);

	if (reqrec->re_rpc_res)
		free(reqrec->re_rpc_res);

	free_lrp(lrp);
}

static void
free_lrp(struct nfslog_lr *lrp)
{
	if (lrp->buffer != NULL)
		free(lrp->buffer);
	free(lrp);
}

/*
 * Utility function used elsewhere
 */
void
nfslog_opaque_print_buf(void *buf, int len, char *outbuf, int *outbufoffsetp,
	int maxoffset)
{
	int	i, j;
	uint_t	*ip;
	uchar_t	*u_buf = (uchar_t *)buf;
	int	outbufoffset = *outbufoffsetp;

	outbufoffset += sprintf(&outbuf[outbufoffset], " \"");
	if (len <= sizeof (int)) {
		for (j = 0; (j < len) && (outbufoffset < maxoffset);
			j++, u_buf++)
			outbufoffset += sprintf(&outbuf[outbufoffset],
						"%02x", *u_buf);
		return;
	}
	/* More than 4 bytes, print with spaces in integer offsets */
	j = (int)((uintptr_t)buf % sizeof (int));
	i = 0;
	if (j > 0) {
		i = sizeof (int) - j;
		for (; (j < sizeof (int)) && (outbufoffset < maxoffset);
			j++, u_buf++)
			outbufoffset += sprintf(&outbuf[outbufoffset],
						"%02x", *u_buf);
	}
	/* LINTED */
	ip = (uint_t *)u_buf;
	for (; ((i + sizeof (int)) <= len) && (outbufoffset < maxoffset);
		i += sizeof (int), ip++) {
		outbufoffset += sprintf(&outbuf[outbufoffset], " %08x", *ip);
	}
	if (i < len) {
		/* Last element not int */
		u_buf = (uchar_t *)ip;
		if (i > j)	/* not first element */
			outbufoffset += sprintf(&outbuf[outbufoffset], " ");
		for (; (i < len) && (outbufoffset < maxoffset); i++, u_buf++) {
			outbufoffset += sprintf(&outbuf[outbufoffset],
						"%02x", *u_buf);
		}
	}
	if (outbufoffset < maxoffset)
		outbufoffset += sprintf(&outbuf[outbufoffset], "\"");
	*outbufoffsetp = outbufoffset;
}
