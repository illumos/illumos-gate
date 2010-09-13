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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <strings.h>
#include <stddef.h>
#include <search.h>
#include <syslog.h>
#include <libintl.h>
#include <unistd.h>
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
#include <assert.h>
#include "fhtab.h"
#include "nfslogd.h"

/*
 * How long should an entry stay in the list before being forced
 * out and a trans log entry printed
 */
#define	TRANS_ENTRY_TIMEOUT	60

extern char *addrtoname(void *);

struct transentry {
	struct transentry *next;
	struct transentry *prev;
	timestruc32_t	starttime;	/* when did transaction start? */
	timestruc32_t	lastupdate;	/* last operation for this entry */
#define	TRANS_OPER_READ		1
#define	TRANS_OPER_WRITE	2
#define	TRANS_OPER_SETATTR	3
#define	TRANS_OPER_REMOVE	4
#define	TRANS_OPER_MKDIR	5
#define	TRANS_OPER_CREATE	6
#define	TRANS_OPER_RMDIR	7
#define	TRANS_OPER_RENAME	8
#define	TRANS_OPER_MKNOD	9
#define	TRANS_OPER_LINK		10
#define	TRANS_OPER_SYMLINK	11
	uchar_t		optype;		/* read, write, ...? */
#define	TRANS_DATATYPE_NA		/* not applicable data type */
#define	TRANS_DATATYPE_ASCII	0	/* transfer done as ascii */
#define	TRANS_DATATYPE_BINARY	1	/* transfer done as binary */
	uchar_t		datatype;
/*
 * Action taken by server before transfer was made -- noaction,
 * compressed, tar or uncompressed.
 */
#define	TRANS_OPTION_NOACTION	0
	uchar_t		transoption;
	char		*pathname;
	struct netbuf	*pnb;
	uid_t		uid;
	int		nfsvers;
	char		*netid;
	char		*principal_name;
	uint64_t	totalbytes;	/* total operated upon in history */
	union {
		fhandle_t fh;
		nfs_fh3 fh3;
	} fh_u;
};

struct nfslog_trans_file {
	struct nfslog_trans_file	*next;	/* next file in list */
	struct nfslog_trans_file	*prev;	/* next file in list */
	int	refcnt;		/* number of references to this struct */
	char	*path;		/* pathname of file */
	FILE	*fp;		/* file pointer */
	/* timestamp of the last transaction processed for this file */
	timestruc32_t	lasttrans_timestamp;
	/* 'current' time that last trans was processed */
	time_t		last_trans_read;
	uint32_t trans_to_log;	/* transactions that are to be logged */
	uint32_t trans_output_type;
	struct transentry *te_list_v3_read;
	struct transentry *te_list_v3_write;
	struct transentry *te_list_v2_read;
	struct transentry *te_list_v2_write;
};

static struct nfslog_trans_file *trans_file_head = NULL;

static void nfslog_print_trans_logentry(struct transentry *,
	struct nfslog_trans_file *);


static struct netbuf *
netbufdup(struct netbuf *pnb)
{
	struct netbuf *pnewnb;
	uint32_t	size;

	size = offsetof(struct netbuf, buf);
	size += pnb->len;

	if ((pnewnb = (struct netbuf *)malloc(sizeof (*pnewnb))) == NULL)
		return (NULL);
	if ((pnewnb->buf = malloc(pnb->len)) == NULL) {
		free(pnewnb);
		return (NULL);
	}

	pnewnb->maxlen = pnb->maxlen;
	pnewnb->len = pnb->len;
	bcopy(pnb->buf, pnewnb->buf, pnb->len);
	return (pnewnb);
}

static void
freenetbuf(struct netbuf *pnb)
{
	free(pnb->buf);
	free(pnb);
}

static struct transentry *
create_te()
{
	struct transentry *pte;

	if ((pte = (struct transentry *)calloc(1, sizeof (*pte))) == NULL) {
		/* failure message or action */
		return (NULL);
	}

	pte->next = pte->prev = NULL;

	return (pte);
}

static struct transentry *
insert_te(
	struct transentry *te_list,
	struct transentry *entry)
{
	struct transentry *pte;

	/*
	 * First check for any non-filehandle comparisons that may be needed.
	 */
	switch (entry->optype) {
	case TRANS_OPER_REMOVE:
	case TRANS_OPER_RENAME:
		for (pte = te_list->next; pte != te_list; pte = pte->next) {
			/* if path names match, then return */
			if (strcmp(pte->pathname, entry->pathname) == 0) {
				return (pte);
			}
		}
		return (NULL);
	default:
		break;
	}

	for (pte = te_list->next; pte != te_list; pte = pte->next) {
		/* If the file handles match, then we have a hit */
		if (entry->nfsvers == NFS_VERSION) {
			if (bcmp(&(pte->fh_u.fh), &(entry->fh_u.fh),
				sizeof (fhandle_t)) == 0) {
				switch (entry->optype) {
				case TRANS_OPER_READ:
				case TRANS_OPER_WRITE:
					if (pte->uid ==	entry->uid) {
						return (pte);
					}
					break;
				default:
					return (pte);
				}
			}
		} else {
			if (pte->fh_u.fh3.fh3_length ==
				entry->fh_u.fh3.fh3_length &&
				bcmp(pte->fh_u.fh3.fh3_u.data,
					entry->fh_u.fh3.fh3_u.data,
					pte->fh_u.fh3.fh3_length) == 0)
				switch (entry->optype) {
				case TRANS_OPER_READ:
				case TRANS_OPER_WRITE:
					if (pte->uid ==	entry->uid) {
						return (pte);
					}
					break;
				default:
					return (pte);
				}
		}
	}
	/*
	 * XXX - should compare more of the information to make sure
	 * it is a match.
	 */

	/*
	 * other operation types do not generate an entry for
	 * further analysis
	 */
	switch (entry->optype) {
	case TRANS_OPER_READ:
	case TRANS_OPER_WRITE:
		break;
	default:
		return (NULL);
	}

	insque(entry, te_list);

	return (NULL); /* NULL signifies insertion and no record found */
}

static void
remove_te(struct transentry *pte)
{
	if (pte->next)
		remque(pte);

	if (pte->principal_name) free(pte->principal_name);
	if (pte->pathname) free(pte->pathname);
	if (pte->pnb) freenetbuf(pte->pnb);
	if (pte->netid) free(pte->netid);

	free(pte);
}

/*
 * nfslog_trans_file_free - frees a record
 */
static void
nfslog_trans_file_free(struct nfslog_trans_file *transrec)
{
	if (transrec == NULL)
		return;
	if (transrec->path != NULL) {
		if (debug)
			(void) printf("freeing transpath '%s'\n",
				transrec->path);
		free(transrec->path);
	}
	free(transrec);
}

/*
 * On success returns a pointer to the trans_file that matches
 * 'path', 'output_type' and 'transtolog'.  The reference count for this
 * object is incremented as well.
 * Returns NULL if it is not in the list.
 */
static struct nfslog_trans_file *
nfslog_trans_file_find(
	char *path,
	uint32_t output_type,
	uint32_t transtolog)
{
	struct nfslog_trans_file *tfp;

	for (tfp = trans_file_head; tfp != NULL; tfp = tfp->next) {
		if ((strcmp(path, tfp->path) == 0) &&
		    (output_type == tfp->trans_output_type) &&
		    (transtolog == tfp->trans_to_log)) {
			if (debug)
				(void) printf("Found transfile '%s'\n", path);
			(tfp->refcnt)++;
			return (tfp);
		}
	}
	return (NULL);
}


/*
 * nfslog_close_trans_file - decrements the reference count on
 * this object. On last reference it closes transfile and
 * frees resources
 */
static void
nfslog_close_trans_file(struct nfslog_trans_file *tf)
{
	assert(tf != NULL);
	assert(tf->refcnt > 0);
	if (tf->refcnt > 1) {
		(tf->refcnt)--;
		return;
	}

	if (tf->fp != NULL) {
		(void) fsync(fileno(tf->fp));
		(void) fclose(tf->fp);
	}

	/*
	 * Disconnect from list
	 */
	tf->prev->next = tf->next;
	if (tf->next != NULL)
		tf->next->prev = tf->prev;

	/*
	 * Adjust the head of the list if appropriate
	 */
	if (tf == trans_file_head)
		trans_file_head = tf->next;

	nfslog_trans_file_free(tf);
}

/*
 * nfslog_open_trans_file - open the output trans file and mallocs.
 * The object is then inserted at the beginning of the global
 * transfile list.
 *	Returns 0 for success, error else.
 *
 * *error contains the last error encountered on this object. It can
 * be used to avoid reporting the same error endlessly, by comparing
 * the current error to the last error. It is reset to the current error
 * code on return.
 */
void *
nfslog_open_trans_file(
	char *transpath,
	uint32_t output_type,
	uint32_t transtolog,
	int *error)
{
	int			preverror = *error;
	struct nfslog_trans_file	*transrec;

	transrec = nfslog_trans_file_find(transpath, output_type, transtolog);
	if (transrec != NULL)
		return (transrec);

	if ((transrec = malloc(sizeof (*transrec))) == NULL) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("nfslog_open_trans_file: %s"),
				strerror(*error));
		}
		return (NULL);
	}
	bzero(transrec, sizeof (*transrec));

	if ((transrec->path = strdup(transpath)) == NULL) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("nfslog_open_trans_file: %s"),
				strerror(*error));
		}
		nfslog_trans_file_free(transrec);
		return (NULL);
	}

	if ((transrec->fp = fopen(transpath, "a")) == NULL) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("Cannot open '%s': %s"),
				transpath, strerror(*error));
		}
		nfslog_trans_file_free(transrec);
		return (NULL);
	}

	transrec->te_list_v3_read =
		(struct transentry *)malloc(sizeof (struct transentry));
	transrec->te_list_v3_write =
		(struct transentry *)malloc(sizeof (struct transentry));
	transrec->te_list_v2_read =
		(struct transentry *)malloc(sizeof (struct transentry));
	transrec->te_list_v2_write =
		(struct transentry *)malloc(sizeof (struct transentry));

	if (transrec->te_list_v3_read == NULL ||
		transrec->te_list_v3_write == NULL ||
		transrec->te_list_v2_read == NULL ||
		transrec->te_list_v2_write == NULL) {
		if (transrec->te_list_v3_read)
			free(transrec->te_list_v3_read);
		if (transrec->te_list_v3_write)
			free(transrec->te_list_v3_write);
		if (transrec->te_list_v2_read)
			free(transrec->te_list_v2_read);
		if (transrec->te_list_v2_write)
			free(transrec->te_list_v2_write);
		nfslog_close_trans_file(transrec);
		return (NULL);
	}

	transrec->te_list_v3_read->next =
		transrec->te_list_v3_read->prev = transrec->te_list_v3_read;
	transrec->te_list_v3_write->next =
		transrec->te_list_v3_write->prev = transrec->te_list_v3_write;
	transrec->te_list_v2_read->next =
		transrec->te_list_v2_read->prev = transrec->te_list_v2_read;
	transrec->te_list_v2_write->next =
		transrec->te_list_v2_write->prev = transrec->te_list_v2_write;

	/*
	 * Indicate what transaction types to log
	 */
	transrec->trans_to_log = transtolog;

	/*
	 * Indicate whether to print 'full' or 'basic' version
	 * of the transactions
	 */
	transrec->trans_output_type = output_type;

	/*
	 * Insert at the beginning of the list.
	 */
	transrec->next = trans_file_head;
	if (trans_file_head != NULL)
		trans_file_head->prev = transrec;
	trans_file_head = transrec->prev = transrec;

	transrec->refcnt = 1;

	transrec->lasttrans_timestamp.tv_sec = 0;
	transrec->lasttrans_timestamp.tv_nsec = 0;
	transrec->last_trans_read = time(0);

	if (debug)
		(void) printf("New transfile '%s'\n", transrec->path);

	return (transrec);
}

void
nfslog_process_trans_timeout(
	struct nfslog_trans_file *tf,
	uint32_t force_flush)
{
	struct transentry *pte;
	time_t cur_time = time(0);

	/*
	 * If we have not seen a transaction on this file for
	 * a long time, then we need to flush everything out since
	 * we may not be getting anything else in for awhile.
	 */
	if (difftime(cur_time, tf->last_trans_read) >
		(2 * MAX(TRANS_ENTRY_TIMEOUT, idle_time)))
		force_flush = TRUE;

restart1:
	for (pte = tf->te_list_v3_read->next;
		pte != tf->te_list_v3_read;
		pte = pte->next) {
		if (force_flush == TRUE ||
			(difftime(tf->lasttrans_timestamp.tv_sec,
				pte->lastupdate.tv_sec) >
			MAX(TRANS_ENTRY_TIMEOUT, idle_time))) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
			goto restart1;
		}
	}
restart2:
	for (pte = tf->te_list_v3_write->next;
		pte != tf->te_list_v3_write;
		pte = pte->next) {
		if (force_flush == TRUE ||
			(difftime(tf->lasttrans_timestamp.tv_sec,
				pte->lastupdate.tv_sec) >
			MAX(TRANS_ENTRY_TIMEOUT, idle_time))) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
			goto restart2;
		}
	}
restart3:
	for (pte = tf->te_list_v2_read->next;
		pte != tf->te_list_v2_read;
		pte = pte->next) {
		if (force_flush == TRUE ||
			(difftime(tf->lasttrans_timestamp.tv_sec,
				pte->lastupdate.tv_sec) >
			MAX(TRANS_ENTRY_TIMEOUT, idle_time))) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
			goto restart3;
		}
	}
restart4:
	for (pte = tf->te_list_v2_write->next;
		pte != tf->te_list_v2_write;
		pte = pte->next) {
		if (force_flush == TRUE ||
			(difftime(tf->lasttrans_timestamp.tv_sec,
				pte->lastupdate.tv_sec) >
			MAX(TRANS_ENTRY_TIMEOUT, idle_time))) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
			goto restart4;
		}
	}

	(void) fflush(tf->fp);
}

/*
 * Flushes outstanding transactions to disk, and closes
 * the transaction log.
 */
void
nfslog_close_transactions(void **transcookie)
{
	assert(*transcookie != NULL);
	nfslog_process_trans_timeout(
		(struct nfslog_trans_file *)(*transcookie), TRUE);
	nfslog_close_trans_file((struct nfslog_trans_file *)(*transcookie));
	*transcookie = NULL;
}

static struct transentry *
trans_read(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_nfsreadargs *args = (nfslog_nfsreadargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_rdresult *res = (nfslog_rdresult *)logrec->re_rpc_res;

	if (res->r_status != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname = nfslog_get_path(&args->ra_fhandle,
			NULL, fhpath, "trans_read");
	} else {
		newte->pathname = strdup(path1);
	}

	/* prep the struct for insertion */
	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_READ;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = res->nfslog_rdresult_u.r_ok.rrok_count;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->ra_fhandle));

	if (res->nfslog_rdresult_u.r_ok.rrok_count <
		res->nfslog_rdresult_u.r_ok.filesize) {
		if (pte = insert_te(tf->te_list_v2_read, newte)) {
			/* free this since entry was found (not inserted) */
			remove_te(newte);

			pte->totalbytes +=
				res->nfslog_rdresult_u.r_ok.rrok_count;

			if (pte->lastupdate.tv_sec <=
				logrec->re_header.rh_timestamp.tv_sec)
				pte->lastupdate =
					logrec->re_header.rh_timestamp;

			if (pte->totalbytes <
				res->nfslog_rdresult_u.r_ok.filesize) {
				pte = NULL; /* prevent printing of log entry */
			}
		}
	} else {
		pte = newte; /* print a log record - complete file read */
	}

	return (pte);
}

static struct transentry *
trans_write(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_writeargs *args = (nfslog_writeargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_writeresult *res = (nfslog_writeresult *)logrec->re_rpc_res;

	if (res->wr_status != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname = nfslog_get_path(&args->waargs_fhandle,
			NULL, fhpath, "trans_write");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_WRITE;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = args->waargs_totcount;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->waargs_fhandle));

	if (pte = insert_te(tf->te_list_v2_write, newte)) {
		/*
		 * if the write would have increased the total byte count
		 * over the filesize, then generate a log entry and remove
		 * the write record and insert the new one.
		 */
		if (pte->totalbytes + args->waargs_totcount >
			res->nfslog_writeresult_u.wr_size) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
			(void) insert_te(tf->te_list_v2_write, newte);
			pte = NULL;
		} else {
			/* free this since entry was found (not inserted) */
			remove_te(newte);

			pte->totalbytes += args->waargs_totcount;

			if (pte->lastupdate.tv_sec <=
				logrec->re_header.rh_timestamp.tv_sec) {
				pte->lastupdate =
					logrec->re_header.rh_timestamp;
			}
			pte = NULL; /* prevent printing of log entry */
		}
	}
	return (pte);
}

static struct transentry *
trans_setattr(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_setattrargs *args = (nfslog_setattrargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat *res = (nfsstat *)logrec->re_rpc_res;

	if (*res != NFS_OK)
		return (NULL);

	if (args->saa_sa.sa_size == (uint32_t)-1)
		return (NULL);
	/*
	 * should check the size of the file to see if it
	 * is being truncated below current eof.  if so
	 * a record should be generated.... XXX
	 */
	if (args->saa_sa.sa_size != 0)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname  = nfslog_get_path(&args->saa_fh, NULL,
			fhpath,	"trans_setattr2");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_SETATTR;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->saa_fh));

	if (pte = insert_te(tf->te_list_v2_write, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v2_read, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}

	return (newte);
}

static struct transentry *
trans_create(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_createargs *args = (nfslog_createargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_diropres *res = (nfslog_diropres *)logrec->re_rpc_res;

	if (res->dr_status != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname =
			nfslog_get_path(&args->ca_da.da_fhandle,
				args->ca_da.da_name,
				fhpath, "trans_create2");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_CREATE;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;

	if (args->ca_sa.sa_size == (uint32_t)-1)
		newte->totalbytes = 0;
	else
		newte->totalbytes = args->ca_sa.sa_size;

	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(
		&res->nfslog_diropres_u.dr_ok.drok_fhandle));

	/*
	 * if the file is being truncated on create, we need to flush
	 * any outstanding read/write transactions
	 */
	if (args->ca_sa.sa_size != (uint32_t)-1) {
		if (pte = insert_te(tf->te_list_v2_write, newte)) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
		}
		if (pte = insert_te(tf->te_list_v2_read, newte)) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
		}
	}

	return (newte);
}

static struct transentry *
trans_remove(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_diropargs *args = (nfslog_diropargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat *res = (nfsstat *)logrec->re_rpc_res;

	if (*res != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		char *name = args->da_name;
		fhandle_t *dfh = &args->da_fhandle;
		newte->pathname = nfslog_get_path(dfh, name,
			fhpath, "trans_remove2");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_REMOVE;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->da_fhandle));

	if (pte = insert_te(tf->te_list_v2_write, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v2_read, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v3_write, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v3_read, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}

	return (newte);
}

static struct transentry *
trans_mkdir(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_createargs *args = (nfslog_createargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_diropres *res = (nfslog_diropres *)logrec->re_rpc_res;

	if (res->dr_status != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		nfslog_diropargs *dargs = &args->ca_da;
		char *name = dargs->da_name;
		fhandle_t *dfh = &dargs->da_fhandle;
		newte->pathname = nfslog_get_path(dfh, name,
			fhpath, "trans_mkdir2");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_MKDIR;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->ca_da.da_fhandle));

	return (newte);
}

static struct transentry *
trans_rmdir(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_diropargs *args = (nfslog_diropargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat *res = (nfsstat *)logrec->re_rpc_res;

	if (*res != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		char *name = args->da_name;
		fhandle_t *dfh = &args->da_fhandle;
		newte->pathname = nfslog_get_path(dfh, name,
			fhpath, "trans_rmdir2");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_RMDIR;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->da_fhandle));

	return (newte);
}

static struct transentry *
trans_rename(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1,
	char *path2)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_rnmargs *args = (nfslog_rnmargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat *res = (nfsstat *)logrec->re_rpc_res;
	char *tpath1 = NULL;
	char *tpath2 = NULL;

	if (*res != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		char *from_name, *to_name;
		fhandle_t *from_dfh, *to_dfh;

		from_name = args->rna_from.da_name;
		from_dfh = &args->rna_from.da_fhandle;
		to_name = args->rna_to.da_name;
		to_dfh = &args->rna_to.da_fhandle;

		path1 = tpath1 = nfslog_get_path(from_dfh, from_name,
			fhpath,	"trans_rename from");
		path2 = tpath2 = nfslog_get_path(to_dfh, to_name,
			fhpath, "trans_rename to");
	}

	newte->pathname = path1; /* no need to strdup here */
	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_RENAME;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->rna_from.da_fhandle));

	/* switch path names for the file for renames */
	if (pte = insert_te(tf->te_list_v2_write, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}
	if (pte = insert_te(tf->te_list_v2_read, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}
	if (pte = insert_te(tf->te_list_v3_write, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}
	if (pte = insert_te(tf->te_list_v3_read, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}

	newte->pathname = (char *)malloc(strlen(path1) + strlen(path2) + 3);
	/* check for NULL malloc */
	(void) sprintf(newte->pathname, "%s->%s", path1, path2);

	if (tpath1) {
		free(tpath1);
		free(tpath2);
	}

	return (newte);
}

static struct transentry *
trans_link(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1,
	char *path2)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_linkargs *args = (nfslog_linkargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat *res = (nfsstat *)logrec->re_rpc_res;
	char *tpath1 = NULL;
	char *tpath2 = NULL;

	if (*res != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		fhandle_t *fh = &args->la_from;
		char *name = args->la_to.da_name;
		fhandle_t *dfh = &args->la_to.da_fhandle;

		path1 = tpath1 = nfslog_get_path(fh, NULL,
			fhpath, "trans_link from");
		path2 = tpath2 = nfslog_get_path(dfh, name,
			fhpath, "trans_link to");
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_LINK;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->la_from));

	newte->pathname = (char *)malloc(strlen(path1) + strlen(path2) + 3);
	/* check for NULL malloc */
	(void) sprintf(newte->pathname, "%s->%s", path1, path2);

	if (tpath1) {
		free(tpath1);
		free(tpath2);
	}

	return (newte);
}

static struct transentry *
trans_symlink(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_symlinkargs *args = (nfslog_symlinkargs *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat *res = (nfsstat *)logrec->re_rpc_res;
	char *tpath1 = NULL;

	if (*res != NFS_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		char *name = args->sla_from.da_name;
		fhandle_t *dfh = &args->sla_from.da_fhandle;

		path1 = tpath1 = nfslog_get_path(dfh, name,
			fhpath, "trans_symlink");
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_SYMLINK;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_VERSION;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh = *(NFSLOG_GET_FHANDLE2(&args->sla_from.da_fhandle));

	newte->pathname = (char *)malloc(strlen(path1) +
		strlen(args->sla_tnm) + 3);
	(void) sprintf(newte->pathname, "%s->%s", path1, args->sla_tnm);

	if (tpath1)
		free(tpath1);

	return (newte);
}

static struct transentry *
trans_read3(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_READ3args *args = (nfslog_READ3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_READ3res *res = (nfslog_READ3res *)logrec->re_rpc_res;

	if (res->status != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		fhandle_t *fh = NFSLOG_GET_FHANDLE3(&args->file);
		newte->pathname = nfslog_get_path(fh, NULL,
			fhpath, "trans_read3");
	} else {
		newte->pathname = strdup(path1);
	}

	/* prep the struct for insertion */
	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_READ;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = res->nfslog_READ3res_u.ok.count;
	newte->fh_u.fh3 = args->file;

	if (res->nfslog_READ3res_u.ok.count <
		res->nfslog_READ3res_u.ok.filesize) {
		if (pte = insert_te(tf->te_list_v3_read, newte)) {
			/* free this since entry was found (not inserted) */
			remove_te(newte);

			pte->totalbytes += res->nfslog_READ3res_u.ok.count;

			if (pte->lastupdate.tv_sec <=
				logrec->re_header.rh_timestamp.tv_sec)
				pte->lastupdate =
					logrec->re_header.rh_timestamp;

			if (pte->totalbytes <
				res->nfslog_READ3res_u.ok.filesize) {
				pte = NULL; /* prevent printing of log entry */
			}
		}
	} else {
		pte = newte; /* print a log record - complete file read */
	}

	return (pte);
}

static struct transentry *
trans_write3(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_WRITE3args *args = (nfslog_WRITE3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_WRITE3res *res = (nfslog_WRITE3res *)logrec->re_rpc_res;

	if (res->status != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		fhandle_t *fh = NFSLOG_GET_FHANDLE3(&args->file);
		newte->pathname = nfslog_get_path(fh, NULL,
			fhpath, "trans_write3");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_WRITE;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = res->nfslog_WRITE3res_u.ok.count;
	newte->fh_u.fh3 = args->file;

	if (pte = insert_te(tf->te_list_v3_write, newte)) {
		/*
		 * if the write would have increased the total byte count
		 * over the filesize, then generate a log entry and remove
		 * the write record and insert the new one.
		 */
		if (pte->totalbytes + res->nfslog_WRITE3res_u.ok.count >
			res->nfslog_WRITE3res_u.ok.filesize) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
			(void) insert_te(tf->te_list_v3_write, newte);
			pte = NULL;
		} else {
			/* free this since entry was found (not inserted) */
			remove_te(newte);

			pte->totalbytes += res->nfslog_WRITE3res_u.ok.count;

			if (pte->lastupdate.tv_sec <=
				logrec->re_header.rh_timestamp.tv_sec) {
				pte->lastupdate =
					logrec->re_header.rh_timestamp;
			}
			pte = NULL; /* prevent printing of log entry */
		}
	}
	return (pte);
}

static struct transentry *
trans_setattr3(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_SETATTR3args *args = (nfslog_SETATTR3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat3 *res = (nfsstat3 *)logrec->re_rpc_res;

	if (*res != NFS3_OK)
		return (NULL);

	if (!args->size.set_it)
		return (NULL);
	/*
	 * should check the size of the file to see if it
	 * is being truncated below current eof.  if so
	 * a record should be generated.... XXX
	 */
	if (args->size.size != 0)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		fhandle_t *fh = NFSLOG_GET_FHANDLE3(&args->object);
		newte->pathname = nfslog_get_path(fh, NULL,
			fhpath, "trans_setattr3");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_SETATTR;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->object;

	if (pte = insert_te(tf->te_list_v3_write, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v3_read, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}

	return (newte);
}

static struct transentry *
trans_create3(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_CREATE3args *args = (nfslog_CREATE3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_CREATE3res *res = (nfslog_CREATE3res *)logrec->re_rpc_res;

	if (res->status != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname =
			nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->where.dir),
				args->where.name,
				fhpath, "trans_create3");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_CREATE;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;

	if (!args->how.nfslog_createhow3_u.size.set_it)
		newte->totalbytes = 0;
	else
		newte->totalbytes =
			args->how.nfslog_createhow3_u.size.size;

	newte->fh_u.fh3 = args->where.dir;

	if (args->how.nfslog_createhow3_u.size.set_it) {
		if (pte = insert_te(tf->te_list_v3_write, newte)) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
		}
		if (pte = insert_te(tf->te_list_v3_read, newte)) {
			nfslog_print_trans_logentry(pte, tf);
			remove_te(pte);
		}
	}

	return (newte);
}

static struct transentry *
trans_remove3(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_REMOVE3args *args = (nfslog_REMOVE3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat3 *res = (nfsstat3 *)logrec->re_rpc_res;

	if (*res != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname =
			nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->object.dir),
				args->object.name,
				fhpath, "trans_remove3");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_REMOVE;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->object.dir;

	if (pte = insert_te(tf->te_list_v3_write, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v3_read, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v2_write, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}
	if (pte = insert_te(tf->te_list_v2_read, newte)) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}

	return (newte);
}

static struct transentry *
trans_mkdir3(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_MKDIR3args *args = (nfslog_MKDIR3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_MKDIR3res *res = (nfslog_MKDIR3res *)logrec->re_rpc_res;

	if (res->status != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname =
			nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->where.dir),
				args->where.name,
				fhpath, "trans_mkdir3");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_MKDIR;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->where.dir;

	return (newte);
}

static struct transentry *
trans_rmdir3(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_RMDIR3args *args = (nfslog_RMDIR3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat3 *res = (nfsstat3 *)logrec->re_rpc_res;

	if (*res != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname =
			nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->object.dir),
				args->object.name,
				fhpath, "trans_rmdir3");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_RMDIR;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->object.dir;

	return (newte);
}

static struct transentry *
trans_rename3(
	nfslog_request_record *logrec,
	struct nfslog_trans_file *tf,
	char *fhpath,
	char *path1,
	char *path2)
{
	struct transentry *newte;
	struct transentry *pte = NULL;
	/* LINTED */
	nfslog_RENAME3args *args = (nfslog_RENAME3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat3 *res = (nfsstat3 *)logrec->re_rpc_res;
	char *tpath1 = NULL;
	char *tpath2 = NULL;

	if (*res != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		path1 = tpath1 =
			nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->from.dir),
				args->from.name, fhpath, "trans_rename3 from");
		path2 = tpath2 =
			nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->to.dir),
				args->to.name, fhpath, "trans_rename3 to");
	}

	newte->pathname = path1; /* no need to strdup here */
	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_RENAME;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->from.dir;

	/* switch path names for the file for renames */
	if (pte = insert_te(tf->te_list_v3_write, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}
	if (pte = insert_te(tf->te_list_v3_read, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}
	if (pte = insert_te(tf->te_list_v2_write, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}
	if (pte = insert_te(tf->te_list_v2_read, newte)) {
		free(pte->pathname);
		pte->pathname = strdup(path2);
	}

	newte->pathname = (char *)malloc(strlen(path1) + strlen(path2) + 3);
	/* check for NULL malloc */
	(void) sprintf(newte->pathname, "%s->%s", path1, path2);

	if (tpath1) {
		free(tpath1);
		free(tpath2);
	}

	return (newte);
}

static struct transentry *
trans_mknod3(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_MKNOD3args *args = (nfslog_MKNOD3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_MKNOD3res *res = (nfslog_MKNOD3res *)logrec->re_rpc_res;

	if (res->status != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		newte->pathname =
			nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->where.dir),
				args->where.name,
				fhpath, "trans_mknod3");
	} else {
		newte->pathname = strdup(path1);
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_MKNOD;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;

	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->where.dir;

	return (newte);
}

static struct transentry *
trans_link3(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1,
	char *path2)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_LINK3args *args = (nfslog_LINK3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfsstat3 *res = (nfsstat3 *)logrec->re_rpc_res;

	char *tpath1 = NULL;
	char *tpath2 = NULL;

	if (*res != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (!path1) {
		tpath1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->file),
			NULL, fhpath, "trans_link3 from");
		tpath2 = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->link.dir),
			args->link.name, fhpath, "trans_link3 to");
		path1 = tpath1;
		path2 = tpath2;
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_LINK;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->file;

	newte->pathname = (char *)malloc(strlen(path1) + strlen(path2) + 3);
	/* check for NULL malloc */
	(void) sprintf(newte->pathname, "%s->%s", path1, path2);

	if (tpath1) {
		free(tpath1);
		free(tpath2);
	}

	return (newte);
}

static struct transentry *
trans_symlink3(
	nfslog_request_record *logrec,
	char *fhpath,
	char *path1)
{
	struct transentry *newte;
	/* LINTED */
	nfslog_SYMLINK3args *args = (nfslog_SYMLINK3args *)logrec->re_rpc_arg;
	/* LINTED */
	nfslog_SYMLINK3res *res = (nfslog_SYMLINK3res *)logrec->re_rpc_res;
	char *name;

	if (res->status != NFS3_OK)
		return (NULL);

	if ((newte = create_te()) == NULL)
		return (NULL);

	if (path1) {
		name = strdup(path1);
	} else {
		name = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->where.dir),
			args->where.name, fhpath, "trans_symlink3");
	}

	newte->starttime = logrec->re_header.rh_timestamp;
	newte->lastupdate = logrec->re_header.rh_timestamp;
	newte->optype = TRANS_OPER_SYMLINK;
	newte->datatype = TRANS_DATATYPE_BINARY;
	newte->transoption = TRANS_OPTION_NOACTION;
	newte->pnb = netbufdup(&(logrec->re_ipaddr));
	newte->uid = logrec->re_header.rh_uid;
	newte->nfsvers = NFS_V3;
	newte->netid = strdup(logrec->re_netid);
	if (logrec->re_principal_name)
		newte->principal_name = strdup(logrec->re_principal_name);
	else
		newte->principal_name = NULL;
	newte->totalbytes = 0;
	newte->fh_u.fh3 = args->where.dir;

	newte->pathname = (char *)malloc(strlen(name) +
		strlen(args->symlink_data) + 3);
	/* check for NULL malloc */
	(void) sprintf(newte->pathname, "%s->%s", name, args->symlink_data);

	free(name);

	return (newte);
}

/*
 * nfslog_process_trans_rec - processes the record in the buffer and outputs
 *	to the trans log.
 * Return 0 for success, errno else.
 */
int
nfslog_process_trans_rec(void *transcookie, nfslog_request_record *logrec,
	char *fhpath, char *path1, char *path2)
{
	struct transentry	*pte = NULL;
	struct nfslog_trans_file *tf = (struct nfslog_trans_file *)transcookie;

	/* ignore programs other than nfs */
	if (logrec->re_header.rh_prognum != NFS_PROGRAM)
		return (0);

	/* update the timestamp for use later in the timeout sequences */
	if (tf->lasttrans_timestamp.tv_sec <
		logrec->re_header.rh_timestamp.tv_sec)
		tf->lasttrans_timestamp =
			logrec->re_header.rh_timestamp;

	/* current time of this processing */
	tf->last_trans_read = time(0);

	/* ignore anything that is not a read or write */
	switch (logrec->re_header.rh_version) {
	case NFS_VERSION:
		switch (logrec->re_header.rh_procnum) {
		case RFS_READ:
			if (tf->trans_to_log & TRANSTOLOG_OPER_READ)
				pte = trans_read(logrec, tf, fhpath, path1);
			break;
		case RFS_WRITE:
			if (tf->trans_to_log & TRANSTOLOG_OPER_WRITE)
				pte = trans_write(logrec, tf, fhpath, path1);
			break;
		case RFS_SETATTR:
			if (tf->trans_to_log & TRANSTOLOG_OPER_SETATTR)
				pte = trans_setattr(logrec, tf,
					fhpath, path1);
			break;
		case RFS_REMOVE:
			if (tf->trans_to_log & TRANSTOLOG_OPER_REMOVE)
				pte = trans_remove(logrec, tf,	fhpath, path1);
			break;
		case RFS_MKDIR:
			if (tf->trans_to_log & TRANSTOLOG_OPER_MKDIR)
				pte = trans_mkdir(logrec, fhpath, path1);
			break;
		case RFS_RMDIR:
			if (tf->trans_to_log & TRANSTOLOG_OPER_RMDIR)
				pte = trans_rmdir(logrec, fhpath, path1);
			break;
		case RFS_CREATE:
			if (tf->trans_to_log & TRANSTOLOG_OPER_CREATE)
				pte = trans_create(logrec, tf, fhpath, path1);
			break;
		case RFS_RENAME:
			if (tf->trans_to_log & TRANSTOLOG_OPER_RENAME)
				pte = trans_rename(logrec, tf,
					fhpath, path1, path2);
			break;
		case RFS_LINK:
			if (tf->trans_to_log & TRANSTOLOG_OPER_LINK)
				pte = trans_link(logrec, fhpath, path1, path2);
			break;
		case RFS_SYMLINK:
			if (tf->trans_to_log & TRANSTOLOG_OPER_SYMLINK)
				pte = trans_symlink(logrec, fhpath, path1);
			break;
		default:
			break;
		}
		break;
	case NFS_V3:
		switch (logrec->re_header.rh_procnum) {
		case NFSPROC3_READ:
			if (tf->trans_to_log & TRANSTOLOG_OPER_READ)
				pte = trans_read3(logrec, tf, fhpath, path1);
			break;
		case NFSPROC3_WRITE:
			if (tf->trans_to_log & TRANSTOLOG_OPER_WRITE)
				pte = trans_write3(logrec, tf, fhpath, path1);
			break;
		case NFSPROC3_SETATTR:
			if (tf->trans_to_log & TRANSTOLOG_OPER_SETATTR)
				pte = trans_setattr3(logrec, tf,
					fhpath, path1);
			break;
		case NFSPROC3_REMOVE:
			if (tf->trans_to_log & TRANSTOLOG_OPER_REMOVE)
				pte = trans_remove3(logrec, tf,
					fhpath, path1);
			break;
		case NFSPROC3_MKDIR:
			if (tf->trans_to_log & TRANSTOLOG_OPER_MKDIR)
				pte = trans_mkdir3(logrec, fhpath, path1);
			break;
		case NFSPROC3_RMDIR:
			if (tf->trans_to_log & TRANSTOLOG_OPER_RMDIR)
				pte = trans_rmdir3(logrec, fhpath, path1);
			break;
		case NFSPROC3_CREATE:
			if (tf->trans_to_log & TRANSTOLOG_OPER_CREATE)
				pte = trans_create3(logrec, tf,
					fhpath, path1);
			break;
		case NFSPROC3_RENAME:
			if (tf->trans_to_log & TRANSTOLOG_OPER_RENAME)
				pte = trans_rename3(logrec, tf,
					fhpath, path1, path2);
			break;
		case NFSPROC3_MKNOD:
			if (tf->trans_to_log & TRANSTOLOG_OPER_MKNOD)
				pte = trans_mknod3(logrec, fhpath, path1);
			break;
		case NFSPROC3_LINK:
			if (tf->trans_to_log & TRANSTOLOG_OPER_LINK)
				pte = trans_link3(logrec,
					fhpath, path1, path2);
			break;
		case NFSPROC3_SYMLINK:
			if (tf->trans_to_log & TRANSTOLOG_OPER_SYMLINK)
				pte = trans_symlink3(logrec, fhpath, path1);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (pte != NULL) {
		nfslog_print_trans_logentry(pte, tf);
		remove_te(pte);
	}

	return (0);
}

static void
nfslog_print_trans_logentry(struct transentry *pte,
	struct nfslog_trans_file *tf)
{
	char *remotehost;
	char datatype;
	char transoption;
	char *optype;
	char *prin;
	int prinid;
	char nfs_ident[32];

	remotehost = addrtoname(pte->pnb->buf);

	datatype = (pte->datatype == TRANS_DATATYPE_BINARY ? 'b' : 'a');
	transoption = (pte->transoption == TRANS_OPTION_NOACTION ? '_' : '?');

	if (tf->trans_output_type == TRANSLOG_BASIC) {
		(void) strcpy(nfs_ident, "nfs");
	} else {
		(void) strcpy(nfs_ident,
			(pte->nfsvers == NFS_V3 ? "nfs3-" : "nfs-"));
		(void) strcat(nfs_ident, pte->netid);
	}

	switch (pte->optype) {
	case TRANS_OPER_READ:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"read" : "o");
		break;
	case TRANS_OPER_WRITE:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"write" : "i");
		break;
	case TRANS_OPER_REMOVE:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"remove" : "?");
		break;
	case TRANS_OPER_MKDIR:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"mkdir" : "?");
		break;
	case TRANS_OPER_CREATE:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"create" : "?");
		break;
	case TRANS_OPER_RMDIR:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"rmdir" : "?");
		break;
	case TRANS_OPER_SETATTR:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"setattr" : "?");
		break;
	case TRANS_OPER_RENAME:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"rename" : "?");
		break;
	case TRANS_OPER_MKNOD:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"mknod" : "?");
		break;
	case TRANS_OPER_LINK:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"link" : "?");
		break;
	case TRANS_OPER_SYMLINK:
		optype = (tf->trans_output_type == TRANSLOG_EXTENDED ?
			"symlink" : "?");
		break;
	default:
		optype = "?";
		break;
	}
	if (strcmp(pte->principal_name, "") == 0) {
		prinid = 0;
		prin = "*";
	} else {
		prinid = 1;
		prin = pte->principal_name;
	}
	(void) fprintf(tf->fp,
		"%.24s %d %s %d %s %c %c %s %c %ld %s %d %s\n",
		ctime((time_t *)&pte->starttime.tv_sec),
		pte->lastupdate.tv_sec - pte->starttime.tv_sec,
		remotehost,
		(uint32_t)pte->totalbytes,
		pte->pathname,
		datatype,
		transoption,
		optype,
		'r', /* anonymous == 'a', guest == 'g', real == 'r'), */
		pte->uid,
		nfs_ident,
		/* authenticated - fill in kerb/security? */
		prinid,
		/* authenticated ? authuser : "*" */
		prin);
}
