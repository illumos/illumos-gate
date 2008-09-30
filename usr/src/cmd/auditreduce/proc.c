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
 */


/*
 * Main processor for auditreduce.
 * Mproc() is the entry point for this module. It is the only visible
 * function in this module.
 */

#include <sys/types.h>
#include <locale.h>
#include <bsm/libbsm.h>
#include <bsm/audit.h>
#include "auditr.h"

extern int	write_header();
extern int	token_processing();

static void	asort();
static audit_pcb_t *aget();
static int	get_file();
static int	write_recs();
static int	get_recs();
static int	check_rec();
static void	check_order();
static int	check_header();
static int	get_record();

static char	empty_file_token[] = {
#ifdef _LP64
		AUT_OTHER_FILE64, /* token id */
		0, 0, 0, 0, 0, 0, 0, 0, /* seconds of time */
		0, 0, 0, 0, 0, 0, 0, 0, /* microseconds of time */
#else
		AUT_OTHER_FILE32, /* token id */
		0, 0, 0, 0, /* seconds of time */
		0, 0, 0, 0, /* microseconds of time */
#endif
		0, 0, /* length of path name */
};


/*
 * .func	mproc - main processor.
 * .desc	Mproc controls a single process's actions.
 *	First one record is retreived from each pcb. As they are retreived
 *	they are placed into a linked list sorted with oldest first. Then
 *	the first one from the list is written out and another record
 *	read in to replace it. The new record is placed into the list.
 *	This continues until the list is empty.
 * .call	ret = mproc(pcbr).
 * .arg	pcbr	- ptr to pcb for this process.
 * .ret	0	- no errors in processing.
 * .ret	-1	- errors in processing (message already printed).
 */
int
mproc(pcbr)
register audit_pcb_t *pcbr;
{
	int	i, ret, junk;
	int	nrecs = 0;		/* number of records read from stream */
	int	nprecs = 0;		/* number of records put to stream */
	register audit_pcb_t *pcb;
	audit_pcb_t *aget();
	void	asort();

#if AUDIT_PROC_TRACE
	(void) fprintf(stderr, "mproc: count %d lo %d hi %d\n",
	    pcbr->pcb_count, pcbr->pcb_lo, pcbr->pcb_hi);
#endif

	/*
	 * First load up a record from each input group.
	 */
	for (i = pcbr->pcb_lo; i <= pcbr->pcb_hi; i++) {
		pcb = &(pcbr->pcb_below[i]); /* get next PCB */
		while (pcb->pcb_time < 0) { /* while no active record ... */
			if ((ret = get_file(pcb)) == -1)
				break;		/*  no files - finished PCB */
			if (ret == -2)
				return (-1);	/* quit processing - failed */
			if (get_recs(pcb, &nrecs) == 0)
				asort(pcb);	/* got a rec - put in list */
		}
	}
	/*
	 * Now process all of the records.
	 */
	while ((pcb = aget()) != NULL) {	/* get oldest record */
		if (write_recs(pcbr, pcb, &nprecs))
			return (-1);
		while (pcb->pcb_time < 0) {	/* while we don't have a rec */
			if (pcb->pcb_fpr == NULL) {	/* no active file ... */
				if ((ret = get_file(pcb)) == -1)
					break;	/* no files - finished pcb */
				else if (ret == -2)
					return (-1);	/* quit - failed */
			}
			if (get_recs(pcb, &nrecs) == 0)
				asort(pcb);		/* put record in list */
		}
	}
	/*
	 * For root: write outfile header if no records were encountered.
	 * For non-root: write trailer to pipe and close pipe.
	 */
	if (pcbr->pcb_flags & PF_ROOT) {
		if (nprecs == 0) {
			if (write_header())	/* write header if no records */
				return (-1);
		}
	} else {
		pcb = &(pcbr->pcb_below[0]);	/* any old PCB will do */
		pcb->pcb_rec = empty_file_token;
		if (write_recs(pcbr, pcb, &junk))
			return (-1);
		if (fclose(pcbr->pcb_fpw) == EOF) {
			if (!f_quiet)
				(void) fprintf(stderr,
				    gettext("%s couldn't close pipe.\n"), ar);
		}
	}
	/*
	 * For root process tell how many records were written.
	 */
	if (f_verbose && (pcbr->pcb_flags & PF_ROOT)) {
		(void) fprintf(stderr,
		    gettext("%s %d record(s) total were written out.\n"),
			ar, nprecs);
	}
	return (0);
}


/*
 * Head of linked-list of pcbs - sorted by time - oldest first.
 */
static audit_pcb_t		*pcbls = NULL;

/*
 * .func	asort - audit sort.
 * .desc	Place a pcb in the list sorted by time - oldest first.
 * .call	asort(pcb);
 * .arg	pcb	- ptr to pcb to install in list.
 * .ret	void.
 */
static void
asort(pcb)
register audit_pcb_t *pcb;
{
	register audit_pcb_t *pcbc, *pcbp;
	extern audit_pcb_t *pcbls;	/* ptr to start of list */

	pcb->pcb_next = NULL;
	if (pcbls == NULL) {
		pcbls = pcb;		/* empty list */
		return;
	}
	pcbc = pcbls;			/* current pcb */
	pcbp = pcbls;			/* previous pcb */
	while (pcbc != NULL) {
		if (pcb->pcb_time < pcbc->pcb_time) {
			if (pcbp == pcbc) {
				pcb->pcb_next = pcbls;	/* new -> 1st in list */
				pcbls = pcb;
				return;
			}
			pcbp->pcb_next = pcb;
			pcb->pcb_next = pcbc;		/* new in the inside */
			return;
		}
		pcbp = pcbc;
		pcbc = pcbc->pcb_next;
	}
	pcbp->pcb_next = pcb;				/* new -> last */
}


/*
 * .func	aget - audit get.
 * .desc	Get the first pcb from the list. Pcb is removed from list, too.
 * .call	pcb = aget().
 * .arg	none.
 * .ret	pcb	- ptr to pcb that was the first.
 */
static audit_pcb_t *
aget()
{
	audit_pcb_t *pcbret;
	extern audit_pcb_t *pcbls;	/* ptr to start of list */

	if (pcbls == NULL)
		return (pcbls);		/* empty list */
	pcbret = pcbls;
	pcbls = pcbls->pcb_next;	/* 2nd becomes 1st */
	return (pcbret);
}


/*
 * .func	get_file - get a new file.
 * .desc	Get the next file from the pcb's list. Check the header to see
 *	if the file really is an audit file. If there are no more then
 *	quit. If a file open (fopen) fails because the system file table
 *	is full or the process file table is full then quit processing
 *	altogether.
 * .call	ret = get_file(pcb).
 * .arg	pcb	- pcb holding the fcb's (files).
 * .ret	0	- new file opened for processing.
 * .ret	-1	- no more files - pcb finished.
 * .ret	-2	- fatal error - quit processing.
 */
static int
get_file(pcb)
register audit_pcb_t *pcb;
{
	FILE *fp;
	audit_fcb_t *fcb;

	/*
	 * Process file list until a good one if found or empty.
	 */
	while (pcb->pcb_fpr == NULL) {
		if ((fcb = pcb->pcb_first) == NULL) {
			pcb->pcb_time = -1;
			return (-1);	/* pcb is all done */
		} else {
		/*
		 * If we are reading from files then open the next one.
		 */
			if (!f_stdin) {
				if ((fp = fopen(fcb->fcb_file, "r")) == NULL) {
					if (!f_quiet) {
						(void) sprintf(errbuf, gettext(
						"%s couldn't open:\n  %s"),
						ar, fcb->fcb_file);
						perror(errbuf);
					}
					/*
					 * See if file space is depleted.
					 * If it is then we quit.
					 */
					if (errno == ENFILE || errno == EMFILE)
					{
						return (-2);
					}
					pcb->pcb_first = fcb->fcb_next;
					continue;	/* try another file */
				}
			} else {
				/*
				 * Read from standard input.
				 */
				fp = stdin;
			}
			/*
			 * Check header of audit file.
			 */
			if (check_header(fp, fcb->fcb_name)) {
				if (!f_quiet) {
					(void) fprintf(stderr,
					    "%s %s:\n  %s.\n",
					    ar, error_str, fcb->fcb_file);
				}
				if (fclose(fp) == EOF) {
					if (!f_quiet) {
						(void) fprintf(stderr, gettext(
						"%s couldn't close %s.\n"),
						ar, fcb->fcb_file);
					}
				}
				pcb->pcb_first = fcb->fcb_next;
				continue;		/* try another file */
			}
			/*
			 * Found a good audit file.
			 * Initalize pcb for processing.
			 */
			pcb->pcb_first = fcb->fcb_next;
			pcb->pcb_cur = fcb;
			pcb->pcb_fpr = fp;
			pcb->pcb_nrecs = 0;
			pcb->pcb_nprecs = 0;
			pcb->pcb_otime = -1;
		}
	}
	return (0);
}


/*
 * .func	write_recs - write records.
 * .desc	Write record from a buffer to output stream. Keep an eye out
 *	for the first and last records of the root's output stream.
 * .call	ret = write_recs(pcbr, pcb, nprecs).
 * .arg	pcbr	- ptr to node pcb.
 * .arg	pcb		- ptr to pcb holding the stream.
 * .arg	nprecs	- ptr to the number of put records. Updated here.
 * .ret	0	- no errors detected.
 * .ret	-1	- error in writing. Quit processing.
 */
static int
write_recs(pcbr, pcb, nprecs)
register audit_pcb_t *pcbr, *pcb;
int	*nprecs;
{
	adr_t adr;
	char	id;
	int32_t	size;

	adrm_start(&adr, pcb->pcb_rec);
	(void) adrm_char(&adr, &id, 1);
	(void) adrm_int32(&adr, &size, 1);

	/*
	 * Scan for first record to be written to outfile.
	 * When we find it then write the header and
	 * save the time for the outfile name.
	 */
	if ((*nprecs)++ == 0) {
		if (pcbr->pcb_flags & PF_ROOT) {
			f_start = pcb->pcb_time;	/* save start time */
			if (write_header())
				return (-1);
		}
	}
	f_end = pcb->pcb_time;			/* find last record's time */
	pcb->pcb_time = -1;			/* disable just written rec */

	if ((fwrite(pcb->pcb_rec, sizeof (char), size, pcbr->pcb_fpw)) !=
			size) {
		if (pcbr->pcb_flags & PF_ROOT) {
			(void) sprintf(errbuf, gettext(
				"%s write failed to %s"),
				ar, f_outfile ? f_outfile : gettext("stdout"));
			perror(errbuf);
		} else {
			perror(gettext("auditreduce: write failed to pipe"));
		}
		return (-1);
	}
	free(pcb->pcb_rec);
	return (0);
}

/*
 * .func get_recs - get records.
 * .desc Get records from a stream until one passing the current selection
 *	criteria is found or the stream is emptied.
 * .call	ret = get_recs(pcb, nr).
 * .arg	pcb	- ptr to pcb that holds this stream.
 * .arg	nr	- ptr to number of records read. Updated by this routine.
 * .ret	0	- got a record.
 * .ret	-1	- stream is finished.
 */
static int
get_recs(pcb, nr)
register audit_pcb_t *pcb;
int	*nr;
{
	adr_t adr;
	time_t secs;
	int	tmp;
	int	ret, ret2;
	int	nrecs = 0;	/* count how many records read this call */
	int	getrec = TRUE;
	int	alldone = FALSE;
	char	header_type;
	short	e;
	char	*str;
#if AUDIT_FILE
	static void	get_trace();
#endif

	while (getrec) {
		ret = get_record(pcb->pcb_fpr, &pcb->pcb_rec,
			pcb->pcb_cur->fcb_name);
		if (ret > 0) {
			adrm_start(&adr, pcb->pcb_rec);

			/* get token id */
			(void) adrm_char(&adr, (char *)&header_type, 1);
			/* skip over byte count */
			(void) adrm_int32(&adr, (int32_t *)&tmp, 1);
			/* skip over version # */
			(void) adrm_char(&adr, (char *)&tmp, 1);
			/* skip over event id */
			(void) adrm_short(&adr, (short *)&e, 1);
			/* skip over event id modifier */
			(void) adrm_short(&adr, (short *)&tmp, 1);

			if (header_type == AUT_HEADER32) {
			    int32_t s, m;

			    /* get seconds */
			    (void) adrm_int32(&adr, (int32_t *)&s, 1);
			    /* get microseconds */
			    (void) adrm_int32(&adr, (int32_t *)&m, 1);
			    secs = (time_t)s;
			} else if (header_type == AUT_HEADER32_EX) {
			    int32_t s, m;
			    int32_t t, junk[4];	/* at_type + at_addr[4] */

			    /* skip type and ip address field */
			    (void) adrm_int32(&adr, (int32_t *)&t, 1);
			    (void) adrm_int32(&adr, (int32_t *)&junk[0], t/4);

			    /* get seconds */
			    (void) adrm_int32(&adr, (int32_t *)&s, 1);
			    /* get microseconds */
			    (void) adrm_int32(&adr, (int32_t *)&m, 1);
			    secs = (time_t)s;
			} else if (header_type == AUT_HEADER64) {
			    int64_t s, m;

			    /* get seconds */
			    (void) adrm_int64(&adr, (int64_t *)&s, 1);
			    /* get microseconds */
			    (void) adrm_int64(&adr, (int64_t *)&m, 1);
#if ((!defined(_LP64)) || defined(_SYSCALL32))
			    if (s < (time_t)INT32_MIN ||
				s > (time_t)INT32_MAX)
					secs = 0;
			    else
					secs = (time_t)s;
#else
			    secs = (time_t)s;
#endif
			} else if (header_type == AUT_HEADER64_EX) {
			    int64_t s, m;
			    int32_t t, junk[4];

			    /* skip type and ip address field */
			    (void) adrm_int32(&adr, (int32_t *)&t, 1);
			    (void) adrm_int32(&adr, (int32_t *)&junk[0], t/4);

			    /* get seconds */
			    (void) adrm_int64(&adr, (int64_t *)&s, 1);
			    /* get microseconds */
			    (void) adrm_int64(&adr, (int64_t *)&m, 1);
#if ((!defined(_LP64)) || defined(_SYSCALL32))
			    if (s < (time_t)INT32_MIN ||
				s > (time_t)INT32_MAX)
					secs = 0;
			    else
					secs = (time_t)s;
#else
			    secs = (time_t)s;
#endif
			}
		}

#if AUDIT_REC
		(void) fprintf(stderr, "get_recs: %d ret %d recno %d\n",
			pcb->pcb_procno, ret, pcb->pcb_nrecs + 1);
#endif
		/*
		 * See if entire file is after the time window specified.
		 * Must be check here because the start time of the file name
		 * may be after the first record(s).
		 */
		if (pcb->pcb_nrecs == 0 && (pcb->pcb_flags & PF_FILE)) {
			/*
			 * If the first record read failed then use the time
			 * that was in the filename to judge.
			 */
			if (ret > 0)
				(pcb->pcb_cur)->fcb_start = secs;
			if (!f_all && (m_before <= (pcb->pcb_cur)->fcb_start)) {
				(void) fclose(pcb->pcb_fpr); /* ignore file */
				pcb->pcb_fpr = NULL;
				pcb->pcb_time = -1;
				return (-1);
			} else {
				/* Give belated announcement of file opening. */
				if (f_verbose) {
					(void) fprintf(stderr,
						gettext("%s opened:\n  %s.\n"),
						ar, (pcb->pcb_cur)->fcb_file);
				}
			}
		}
		/* Succesful acquisition of a record.  */
		if (ret > 0) {
			pcb->pcb_time = secs;	/* time of record */
			pcb->pcb_nrecs++;	/* # of read recs from stream */
			nrecs++;		/* # of recs read this call */
			/* Only check record if at bottom of process tree. */
			if (pcb->pcb_flags & PF_FILE) {
				check_order(pcb); /* check time sequence */
				if ((ret2 = check_rec(pcb)) == 0) {
					pcb->pcb_nprecs++;
					getrec = FALSE;
				} else if (ret2 == -2) {
					/* error */
					getrec = FALSE;	/* get no more recs */
					alldone = TRUE;	/* quit this file */
					free(pcb->pcb_rec);
				} else {
					/* -1: record not interesting */
					free(pcb->pcb_rec);
				}
			} else {
				pcb->pcb_nprecs++;
				getrec = FALSE;
			}
		} else {
			/* Error with record read or all done with stream. */
			getrec = FALSE;
			alldone = TRUE;
		}
	}
	if (alldone == TRUE) {
#if AUDIT_FILE
		get_trace(pcb);
#endif
		/* Error in record read. Display messages. */
		if (ret < 0 || ret2 == -2) {
			pcb->pcb_nrecs++;	/* # of read records */
			if (!f_quiet) {
				if (pcb->pcb_flags & PF_FILE) {
					/* Ignore if this is not_terminated. */
					if (!strstr((pcb->pcb_cur)->fcb_file,
							"not_terminated")) {
(void) fprintf(stderr, gettext("%s read error in %s at record %d.\n"), ar,
	(pcb->pcb_cur)->fcb_file, pcb->pcb_nrecs);
					}
				} else {
(void) fprintf(stderr, gettext("%s read error in pipe at record %d.\n"), ar,
	pcb->pcb_nrecs);
				}
			}
		} else {
			/*
			 * Only mark infile for deleting if we have succesfully
			 * processed all of it.
			 */
			if (pcb->pcb_flags & PF_FILE)
				(pcb->pcb_cur)->fcb_flags |= FF_DELETE;
		}
		if (fclose(pcb->pcb_fpr) == EOF) {
			if (!f_quiet) {
				if (pcb->pcb_flags & PF_FILE) {
					str = (pcb->pcb_cur)->fcb_file;
				} else {
					str = "pipe";
				}
				(void) fprintf(stderr,
					gettext("%s couldn't close %s.\n"),
					ar, str);
			}
		}
		pcb->pcb_fpr = NULL;
		pcb->pcb_time = -1;
		*nr += nrecs;
		return (-1);
	}
	*nr += nrecs;
	return (0);
}


#if AUDIT_FILE
/*
 * .func get_trace - get trace.
 * .desc If we are tracing file action (AUDIT_FILE is on) then print out
 *	a message when the file is closed regarding how many records
 *	were handled.
 * .call	get_trace(pcb).
 * .arg	pcb	- ptr to pcb holding file/pipe.
 * .ret	void.
 */
static void
get_trace(pcb)
audit_pcb_t *pcb;
{
	/*
	 * For file give filename, too.
	 */
	if (pcb->pcb_flags & PF_FILE) {
	(void) fprintf(stderr, "%s closed %s: %d records read recs: \
		%d record written.\n", ar, (pcb->pcb_cur)->fcb_file,
		pcb->pcb_nrecs, pcb->pcb_nprecs);
	} else {
		(void) fprintf(stderr, "%s closed pipe: %d records read: \
			%d records written .\n", ar, pcb->pcb_nrecs,
			pcb->pcb_nprecs);
	}
}

#endif

/*
 * .func	check_rec - check a record.
 * .desc	Check a record against the user's selection criteria.
 * .call	ret = check_rec(pcb).
 * .arg	pcb	- ptr to pcb holding the record.
 * .ret	0	- record accepted.
 * .ret	-1	- record rejected - continue processing file.
 * .ret	-2	- record rejected - quit processing file.
 */
static int
check_rec(pcb)
register audit_pcb_t *pcb;
{
	adr_t adr;
	struct timeval tv;
	uint_t	bytes;
	au_emod_t id_modifier;
	char	version;
	au_event_t event_type;
	char	tokenid;
	int	rc;	 /* return code */

	adrm_start(&adr, pcb->pcb_rec);
	(void) adrm_char(&adr, &tokenid, 1);

	/*
	 * checkflags will be my data structure for determining if
	 * a record has met ALL the selection criteria.  Once
	 * checkflags == flags, we have seen all we need to of the
	 * record, and can go to the next one.  If when we finish
	 * processing the record we still have stuff to see,
	 * checkflags != flags, and thus we should return a -1
	 * from this function meaning reject this record.
	 */

	checkflags = 0;

	/* must be header token -- sanity check */
	if (tokenid != AUT_HEADER32 && tokenid != AUT_HEADER64 &&
	    tokenid != AUT_HEADER32_EX && tokenid != AUT_HEADER64_EX) {
#if AUDIT_REC
		(void) fprintf(stderr,
		    "check_rec: %d recno %d no header %d found\n",
		    pcb->pcb_procno, pcb->pcb_nrecs, tokenid);
#endif
		return (-2);
	}

	/*
	 * The header token is:
	 *	attribute id:		char
	 *	byte count:		int
	 *	version #:		char
	 *	event ID:		short
	 *	ID modifier:		short
	 *	seconds (date):		int
	 *	time (microsecs):	int
	 */
	(void) adrm_u_int32(&adr, (uint32_t *)&bytes, 1);
	(void) adrm_char(&adr, &version, 1);
	(void) adrm_u_short(&adr, &event_type, 1);

	/*
	 * Used by s5_IPC_token to set the ipc_type so
	 * s5_IPC_perm_token can test.
	 */
	ipc_type = (char)0;

	if (flags & M_TYPE) {
		checkflags |= M_TYPE;
		if (m_type != event_type)
			return (-1);
	}
	if (flags & M_CLASS) {
		au_event_ent_t *ev = NULL;

		checkflags |= M_CLASS;
		if (cacheauevent(&ev, event_type) <= 0) {
		    (void) fprintf(stderr, gettext(
			"Warning: invalid event no %d in audit trail."),
			event_type);
		    return (-1);
		}
		global_class = ev->ae_class;
		if (!(flags & M_SORF) && !(mask.am_success & global_class))
			return (-1);
	}

	(void) adrm_u_short(&adr, &id_modifier, 1);

	/*
	 * Check record against time criteria.
	 * If the 'A' option was used then no time checking is done.
	 * The 'a' parameter is inclusive and the 'b' exclusive.
	 */
	if (tokenid == AUT_HEADER32) {
	    int32_t secs, msecs;
	    (void) adrm_int32(&adr, (int32_t *)&secs, 1);
	    (void) adrm_int32(&adr, (int32_t *)&msecs, 1);
	    tv.tv_sec = (time_t)secs;
	    tv.tv_usec = (suseconds_t)msecs;
	} else if (tokenid == AUT_HEADER32_EX) {
	    int32_t secs, msecs;
	    int32_t t, junk[5];	/* at_type + at_addr[4] */
	    /* skip type and ip address field */
	    (void) adrm_int32(&adr, (int32_t *)&t, 1);
	    (void) adrm_int32(&adr, (int32_t *)&junk[0], t/4);
	    /* get time */
	    (void) adrm_int32(&adr, (int32_t *)&secs, 1);
	    (void) adrm_int32(&adr, (int32_t *)&msecs, 1);
	    tv.tv_sec = (time_t)secs;
	    tv.tv_usec = (suseconds_t)msecs;
	} else if (tokenid == AUT_HEADER64) {
	    int64_t secs, msecs;
	    (void) adrm_int64(&adr, (int64_t *)&secs, 1);
	    (void) adrm_int64(&adr, (int64_t *)&msecs, 1);
#if ((!defined(_LP64)) || defined(_SYSCALL32))
	    if (secs < (time_t)INT32_MIN ||
		secs > (time_t)INT32_MAX)
			tv.tv_sec = 0;
	    else
			tv.tv_sec = (time_t)secs;
	    if (msecs < (suseconds_t)INT32_MIN ||
		msecs > (suseconds_t)INT32_MAX)
			tv.tv_usec = 0;
	    else
			tv.tv_usec = (suseconds_t)msecs;
#else
	    tv.tv_sec = (time_t)secs;
	    tv.tv_usec = (suseconds_t)msecs;
#endif
	} else if (tokenid == AUT_HEADER64_EX) {
	    int64_t secs, msecs;
	    int32_t t, junk[4];	/* at_type + at_addr[4] */
	    /* skip type and ip address field */
	    (void) adrm_int32(&adr, (int32_t *)&t, 1);
	    (void) adrm_int32(&adr, (int32_t *)&junk[0], t/4);
	    /* get time */
	    (void) adrm_int64(&adr, (int64_t *)&secs, 1);
	    (void) adrm_int64(&adr, (int64_t *)&msecs, 1);
#if ((!defined(_LP64)) || defined(_SYSCALL32))
	    if (secs < (time_t)INT32_MIN ||
		secs > (time_t)INT32_MAX)
			tv.tv_sec = 0;
	    else
			tv.tv_sec = (time_t)secs;
	    if (msecs < (suseconds_t)INT32_MIN ||
		msecs > (suseconds_t)INT32_MAX)
			tv.tv_usec = 0;
	    else
			tv.tv_usec = (suseconds_t)msecs;
#else
	    tv.tv_sec = (time_t)secs;
	    tv.tv_usec = (suseconds_t)msecs;
#endif
	}
	pcb->pcb_otime = pcb->pcb_time;
	if (!f_all) {
		if (m_after > tv.tv_sec)
			return (-1);
		if (m_before <= tv.tv_sec)
			return (-1);
	}

	/* if no selection flags were passed, select everything */
	if (!flags)
		return (0);

	/*
	 * If all information can be found in header,
	 * there is no need to continue processing the tokens.
	 */
	if (flags == checkflags)
		return (0);

	/*
	 * Process tokens until we hit the end of the record
	 */
	while ((uint_t)(adr.adr_now - adr.adr_stream) < bytes) {
		adrm_char(&adr, &tokenid, 1);
		rc = token_processing(&adr, tokenid);

		/* Any Problems? */
		if (rc == -2) {
			(void) fprintf(stderr,
			    gettext("auditreduce: bad token %u, terminating "
			    "file %s\n"), tokenid, (pcb->pcb_cur)->fcb_file);
			return (-2);
		}

		/* Are we finished? */
		if (flags == checkflags)
			return (0);
	}

	/*
	 * So, we haven't seen all that we need to see.  Reject record.
	 */

	return (-1);
}


/*
 * .func check_order - Check temporal sequence.
 * .call check_order(pcb).
 * .arg	 pcb - ptr to audit_pcb_t.
 * .desc	Check to see if the records are out of temporal sequence, ie,
 *	a record has a time stamp older than its predecessor.
 *	Also check to see if the current record is within the bounds of
 *	the file itself.
 *	This routine prints a diagnostic message, unless the QUIET
 *	option was selected.
 * .call	check_order(pcb).
 * .arg	pcb	- ptr to pcb holding the records.
 * .ret	void.
 */
static void
check_order(pcb)
register audit_pcb_t *pcb;
{
	char	cptr1[28], cptr2[28];	/* for error reporting */

	/*
	 * If the record-past is not the oldest then say so.
	 */
	if (pcb->pcb_otime > pcb->pcb_time) {
		if (!f_quiet) {
			(void) memcpy((void *)cptr1,
				(void *)ctime(&pcb->pcb_otime), 26);
			cptr1[24] = ' ';
			(void) memcpy((void *)cptr2,
				(void *)ctime(&pcb->pcb_time), 26);
			cptr2[24] = ' ';
			(void) fprintf(stderr,
	gettext("%s %s had records out of order: %s was followed by %s.\n"),
				ar, (pcb->pcb_cur)->fcb_file, cptr1, cptr2);
		}
	}
}


/*
 * .func	check_header.
 * .desc	Read in and check the header for an audit file.
 *	The header must read-in properly and have the magic #.
 * .call	err = check_header(fp).
 * .arg	fp	- file stream.
 * .ret	0	no problems.
 * .ret	-1	problems.
 */
static int
check_header(fp, fn)
FILE *fp;
char	*fn;
{
	char	id;
	char	*fname;
	short	pathlength;
	adr_t	adr;
	adrf_t	adrf;

	adrf_start(&adrf, &adr, fp);

	if (adrf_char(&adrf, &id, 1)) {
		(void) sprintf(errbuf, gettext("%s is empty"), fn);
		error_str = errbuf;
		return (-1);
	}
	if (!(id == AUT_OTHER_FILE32 || id == AUT_OTHER_FILE64)) {
		(void) sprintf(errbuf, gettext("%s not an audit file "), fn);
		error_str = errbuf;
		return (-1);
	}

	if (id == AUT_OTHER_FILE32) {
	    int32_t secs, msecs;
	    (void) adrf_int32(&adrf, (int32_t *)&secs, 1);
	    (void) adrf_int32(&adrf, (int32_t *)&msecs, 1);
	} else {
	    int64_t secs, msecs;
	    (void) adrf_int64(&adrf, (int64_t *)&secs, 1);
	    (void) adrf_int64(&adrf, (int64_t *)&msecs, 1);
#if ((!defined(_LP64)) || defined(_SYSCALL32))
	    if (secs < (time_t)INT32_MIN ||
		secs > (time_t)INT32_MAX) {
		    error_str = gettext("bad time stamp in file header");
		    return (-1);
	    }
	    if (msecs < (suseconds_t)INT32_MIN ||
		msecs > (suseconds_t)INT32_MAX) {
		    error_str = gettext("bad time stamp in file header");
		    return (-1);
	    }
#endif
	}

	if (adrf_short(&adrf, &pathlength, 1)) {
		error_str = gettext("incomplete file header");
		return (-1);
	}

	if (pathlength != 0) {
		fname = (char *)a_calloc(1, (size_t)pathlength);
		if ((fread(fname, sizeof (char), pathlength, fp)) !=
				pathlength) {
			(void) sprintf(errbuf,
				gettext("error in header/filename read in %s"),
				fn);
			error_str = errbuf;
			return (-1);
		}
		free(fname);
	}
	return (0);
}


/*
 * .func	get_record - get a single record.
 * .desc	Read a single record from stream fp. If the record to be read
 *	is larger than the buffer given to hold it (as determined by
 *	cur_size) then free that buffer and allocate a new and bigger
 *	one, making sure to store its size.
 * .call	ret = get_record(fp, buf, cur_size, flags).
 * .arg	fp	- stream to read from.
 * .arg	buf	- ptr to ptr to buffer to place record in.
 * .arg	cur_size- ptr to the size of the buffer that *buf points to.
 * .arg	flags	- flags from fcb (to get FF_NOTTERM).
 * .ret	+number	- number of chars in the record.
 * .ret	0	- trailer seen - file done.
 * .ret	-1	- read error (error_str know what type).
 */
static int
get_record(fp, buf, fn)
FILE *fp;
char	**buf;
char	*fn;
{
	adr_t	adr;
	adrf_t	adrf;
	int	leadin;
	char	id;
	int	lsize;
	short	ssize;

	/*
	 * Get the token type. It will be either a header or a file
	 * token.
	 */
	(void) adrf_start(&adrf, &adr, fp);
	if (adrf_char(&adrf, &id, 1)) {
		(void) sprintf(errbuf, gettext(
			"record expected but not found in %s"),
			fn);
		error_str = errbuf;
		return (-1);
	}
	switch (id) {
	case AUT_HEADER32:
	case AUT_HEADER32_EX:
	case AUT_HEADER64:
	case AUT_HEADER64_EX:
		/*
		 * The header token is:
		 *	attribute id:		char
		 *	byte count:		int
		 *	version #:		char
		 *	event ID:		short
		 *	ID modifier:		short
		 *	IP address type		int	(_EX only)
		 *	IP address		1/4*int (_EX only)
		 *	seconds (date):		long
		 *	time (microsecs):	long
		 */
		leadin = sizeof (int32_t) + sizeof (char);
		(void) adrf_int32(&adrf, &lsize, 1);
		*buf = (char *)a_calloc(1, (size_t)(lsize + leadin));
		adr_start(&adr, *buf);
		adr_char(&adr, &id, 1);
		adr_int32(&adr, (int32_t *)&lsize, 1);
		if (fread(*buf + leadin, sizeof (char), lsize - leadin, fp) !=
			lsize - leadin) {
			(void) sprintf(errbuf,
				gettext("header token read failure in %s"), fn);
			error_str = errbuf;
			return (-1);
		}
		return (lsize + leadin);
	case AUT_OTHER_FILE32: {
		int32_t secs, msecs;
		leadin =  2 * sizeof (int32_t) +
				sizeof (short) + sizeof (char);
		(void) adrf_int32(&adrf, (int32_t *)&secs, 1);
		(void) adrf_int32(&adrf, (int32_t *)&msecs, 1);
		(void) adrf_short(&adrf, &ssize, 1);
		*buf = (char *)a_calloc(1, (size_t)(ssize + leadin));
		adr_start(&adr, *buf);
		adr_char(&adr, &id, 1);
		adr_int32(&adr, (int32_t *)&secs, 1);
		adr_int32(&adr, (int32_t *)&msecs, 1);
		adr_short(&adr, &ssize, 1);
		if (fread(*buf + leadin, sizeof (char), ssize, fp) != ssize) {
			error_str = gettext("file token read failure");
			return (-1);
		}
		return (0);		/* done! */
	}
	case AUT_OTHER_FILE64: {
		int64_t secs, msecs;
		leadin =  2 * sizeof (int64_t) +
				sizeof (short) + sizeof (char);
		(void) adrf_int64(&adrf, (int64_t *)&secs, 1);
		(void) adrf_int64(&adrf, (int64_t *)&msecs, 1);
		(void) adrf_short(&adrf, &ssize, 1);
		*buf = (char *)a_calloc(1, (size_t)(ssize + leadin));
		adr_start(&adr, *buf);
		adr_char(&adr, &id, 1);
		adr_int64(&adr, (int64_t *)&secs, 1);
		adr_int64(&adr, (int64_t *)&msecs, 1);
		adr_short(&adr, &ssize, 1);
		if (fread(*buf + leadin, sizeof (char), ssize, fp) != ssize) {
			error_str = gettext("file token read failure");
			return (-1);
		}
		return (0);		/* done! */
	}
	default:
		break;
	}
	error_str = gettext("record begins without proper token");
	return (-1);
}
