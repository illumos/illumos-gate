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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * The Secure SunOS audit reduction tool - auditreduce.
 * Document SM0071 is the primary source of information on auditreduce.
 *
 * Composed of 4 source modules:
 * main.c - main driver.
 * option.c - command line option processing.
 * process.c - record/file/process functions.
 * time.c - date/time handling.
 *
 * Main(), write_header(), audit_stats(), and a_calloc()
 * are the only functions visible outside this module.
 */

#include <siginfo.h>
#include <locale.h>
#include <libintl.h>
#include "auditr.h"
#include "auditrd.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

extern void	derive_str(time_t, char *);
extern int	process_options(int, char **);
extern int	mproc(audit_pcb_t *);
extern void	init_tokens(void);	/* shared with praudit */

static int	a_pow(int, int);
static void	calc_procs(void);
static void	chld_handler(int);
static int	close_outfile(void);
static void	c_close(audit_pcb_t *, int);
static void	delete_infiles(void);
static void	gather_pcb(audit_pcb_t *, int, int);
static void	init_options(void);
static int	init_sig(void);
static void	int_handler(int);
static int	mfork(audit_pcb_t *, int, int, int);
static void	mcount(int, int);
static int	open_outfile(void);
static void	p_close(audit_pcb_t *);
static int	rename_outfile(void);
static void	rm_mem(audit_pcb_t *);
static void	rm_outfile(void);
static void	trim_mem(audit_pcb_t *);
static int	write_file_token(time_t);
static int	write_trailer(void);

/*
 * File globals.
 */
static int	max_sproc;	/* maximum number of subprocesses per process */
static int	total_procs;	/* number of processes in the process tree */
static int	total_layers;	/* number of layers in the process tree */

/*
 * .func main - main.
 * .desc The beginning. Main() calls each of the initialization routines
 *	and then allocates the root pcb. Then it calls mfork() to get
 *	the work done.
 * .call	main(argc, argv).
 * .arg	argc	- number of arguments.
 * .arg	argv	- array of pointers to arguments.
 * .ret	0	- via exit() - no errors detected.
 * .ret	1	- via exit() - errors detected (messages printed).
 */
int
main(int argc, char **argv)
{
	int	ret;
	audit_pcb_t *pcb;

	/* Internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	root_pid = getpid();	/* know who is root process for error */
	init_options();		/* initialize options */
	init_tokens();		/* initialize token processing table */
	if (init_sig())		/* initialize signals */
		exit(1);
	if (process_options(argc, argv))
		exit(1);	/* process command line options */
	if (open_outfile())	/* setup root process output stream */
		exit(1);
	calc_procs();		/* see how many subprocesses we need */
	/*
	 * Allocate the root pcb and set it up.
	 */
	pcb = (audit_pcb_t *)a_calloc(1, sizeof (audit_pcb_t));
	pcb->pcb_procno = root_pid;
	pcb->pcb_flags |= PF_ROOT;
	pcb->pcb_fpw = stdout;
	pcb->pcb_time = -1;
	/*
	 * Now start the whole thing rolling.
	 */
	if (mfork(pcb, pcbnum, 0, pcbnum - 1)) {
		/*
		 * Error in processing somewhere. A message is already printed.
		 * Display usage statistics and remove the outfile.
		 */
		if (getpid() == root_pid) {
			audit_stats();
			(void) close_outfile();
			rm_outfile();
		}
		exit(1);
	}
	/*
	 * Clean up afterwards.
	 * Only do outfile cleanup if we are root process.
	 */
	if (getpid() == root_pid) {
		if ((ret = write_trailer()) == 0) { /* write trailer to file */

			ret = close_outfile();	/* close the outfile */
		}
		/*
		 * If there was an error in cleanup then remove outfile.
		 */
		if (ret) {
			rm_outfile();
			exit(1);
		}
		/*
		 * And lastly delete the infiles if the user so wishes.
		 */
		if (f_delete)
			delete_infiles();
	}
	return (0);
/*NOTREACHED*/
}


/*
 * .func mfork - main fork routine.
 * .desc Create a (sub-)tree of processses if needed, or just do the work
 *	if we have few enough groups to process. This is a recursive routine
 *	which stops recursing when the number of files to process is small
 *	enough. Each call to mfork() is responsible for a range of pcbs
 *	from audit_pcbs[]. This range is designated by the lo and hi
 *	arguments (inclusive). If the number of pcbs is small enough
 *	then we have hit a leaf of the tree and mproc() is called to
 *	do the processing. Otherwise we fork some processes and break
 *	the range of pcbs up amongst them.
 * .call	ret = mfork(pcb, nsp, lo, hi).
 * .arg	pcb	- ptr to pcb that is root node of the to-be-created tree.
 * .arg	nsp	- number of sub-processes this tree must process.
 * .arg	lo	- lower-limit of process number range. Index into audit_pcbs.
 * .arg	hi	- higher limit of pcb range. Index into audit_pcbs.
 * .ret	0	- succesful completion.
 * .ret	-1	- error encountered in processing - message already printed.
 */
static int
mfork(audit_pcb_t *pcb, int nsp, int lo, int hi)
{
	int	range, procno, i, tofork, nnsp, nrem;
	int	fildes[2];
	audit_pcb_t *pcbn;

#if AUDIT_PROC_TRACE
	(void) fprintf(stderr, "mfork: nsp %d %d->%d\n", nsp, lo, hi);
#endif

	/*
	 * The range of pcb's to process is small enough now. Do the work.
	 */
	if (nsp <= max_sproc) {
		pcb->pcb_flags |= PF_LEAF;	/* leaf in process tree */
		pcb->pcb_below = audit_pcbs;	/* proc pcbs from audit_pcbs */
		gather_pcb(pcb, lo, hi);
		trim_mem(pcb);			/* trim allocated memory */
		return (mproc(pcb));		/* do the work */
	}
	/*
	 * Too many pcb's for one process - must fork.
	 * Try to balance the tree as it grows and make it short and fat.
	 * The thing to minimize is the number of times a record passes
	 * through a pipe.
	 */
	else {
		/*
		 * Fork less than the maximum number of processes.
		 */
		if (nsp <= max_sproc * (max_sproc - 1)) {
			tofork = nsp / max_sproc;
			if (nsp % max_sproc)
				tofork++;	/* how many to fork */
		}
		/*
		 * Fork the maximum number of processes.
		 */
		else {
			tofork = max_sproc;	/* how many to fork */
		}
		/*
		 * Allocate the nodes below us in the process tree.
		 */
		pcb->pcb_below = (audit_pcb_t *)
			a_calloc(tofork, sizeof (*pcb));
		nnsp = nsp / tofork;	/* # of pcbs per forked process */
		nrem = nsp % tofork;	/* remainder to spread around */
		/*
		 * Loop to fork all of the subs. Open a pipe for each.
		 * If there are any errors in pipes, forks, or getting streams
		 * for the pipes then quit altogether.
		 */
		for (i = 0; i < tofork; i++) {
			pcbn = &pcb->pcb_below[i];
			pcbn->pcb_time = -1;
			if (pipe(fildes)) {
				perror(gettext(
					"auditreduce: couldn't get a pipe"));
				return (-1);
			}
			/*
			 * Convert descriptors to streams.
			 */
			if ((pcbn->pcb_fpr = fdopen(fildes[0], "r")) == NULL) {
				perror(gettext("auditreduce: couldn't get read "
				    "stream for pipe"));
				return (-1);
			}
			if ((pcbn->pcb_fpw = fdopen(fildes[1], "w")) == NULL) {
				perror(gettext("auditreduce: couldn't get "
				    "write stream for pipe"));
				return (-1);
			}
			if ((procno = fork()) == -1) {
				perror(gettext("auditreduce: fork failed"));
				return (-1);
			}
			/*
			 * Calculate the range of pcbs from audit_pcbs [] this
			 * branch of the tree will be responsible for.
			 */
			range = (nrem > 0) ? nnsp + 1 : nnsp;
			/*
			 * Child route.
			 */
			if (procno == 0) {
				pcbn->pcb_procno = getpid();
				c_close(pcb, i); /* close unused streams */
				/*
				 * Continue resolving this branch.
				 */
				return (mfork(pcbn, range, lo, lo + range - 1));
			}
			/* Parent route. */
			else {
				pcbn->pcb_procno = i;
				/* allocate buffer to hold record */
				pcbn->pcb_rec = (char *)a_calloc(1,
				    AUDITBUFSIZE);
				pcbn->pcb_size = AUDITBUFSIZE;
				p_close(pcbn);	/* close unused streams */

				nrem--;
				lo += range;
			}
		}
		/*
		 * Done forking all of the subs.
		 */
		gather_pcb(pcb, 0, tofork - 1);
		trim_mem(pcb);			/* free unused memory */
		return (mproc(pcb));
	}
}


/*
 * .func	trim_mem - trim memory usage.
 * .desc	Free un-needed allocated memory.
 * .call	trim_mem(pcb).
 * .arg	pcb	- ptr to pcb for current process.
 * .ret	void.
 */
static void
trim_mem(audit_pcb_t *pcb)
{
	int	count;
	size_t	size;

	/*
	 * For the root don't free anything. We need to save audit_pcbs[]
	 * in case we are deleting the infiles at the end.
	 */
	if (pcb->pcb_flags & PF_ROOT)
		return;
	/*
	 * For a leaf save its part of audit_pcbs[] and then remove it all.
	 */
	if (pcb->pcb_flags & PF_LEAF) {
		count = pcb->pcb_count;
		size = sizeof (audit_pcb_t);
		/* allocate a new buffer to hold the pcbs */
		pcb->pcb_below = (audit_pcb_t *)a_calloc(count, size);
		/* save this pcb's portion */
		(void) memcpy((void *) pcb->pcb_below,
		    (void *) &audit_pcbs[pcb->pcb_lo], count * size);
		rm_mem(pcb);
		gather_pcb(pcb, 0, count - 1);
	}
		/*
		 * If this is an intermediate node then just remove it all.
		 */
	else {
		rm_mem(pcb);
	}
}


/*
 * .func	rm_mem - remove memory.
 * .desc	Remove unused memory associated with audit_pcbs[]. For each
 *	pcb in audit_pcbs[] free the record buffer and all of
 *	the fcbs. Then free audit_pcbs[].
 * .call	rm_mem(pcbr).
 * .arg	pcbr	- ptr to pcb of current process.
 * .ret	void.
 */
static void
rm_mem(audit_pcb_t *pcbr)
{
	int	i;
	audit_pcb_t *pcb;
	audit_fcb_t *fcb, *fcbn;

	for (i = 0; i < pcbsize; i++) {
		/*
		 * Don't free the record buffer and fcbs for the pcbs this
		 * process is using.
		 */
		if (pcbr->pcb_flags & PF_LEAF) {
			if (pcbr->pcb_lo <= i || i <= pcbr->pcb_hi)
				continue;
		}
		pcb = &audit_pcbs[i];
		free(pcb->pcb_rec);
		for (fcb = pcb->pcb_first; fcb != NULL; /* */) {
			fcbn = fcb->fcb_next;
			free((char *)fcb);
			fcb = fcbn;
		}
	}
	free((char *)audit_pcbs);
}


/*
 * .func	c_close - close unused streams.
 * .desc	This is called for each child process just after being born.
 *	The child closes the read stream for the pipe to its parent.
 *	It also closes the read streams for the other children that
 *	have been born before it. If any closes fail a warning message
 *	is printed, but processing continues.
 * .call	ret = c_close(pcb, i).
 * .arg	pcb	- ptr to the child's parent pcb.
 * .arg	i	- iteration # of child in forking loop.
 * .ret	void.
 */
static void
c_close(audit_pcb_t *pcb, int	i)
{
	int	j;
	audit_pcb_t *pcbt;

	/*
	 * Do all pcbs in parent's group up to and including us
	 */
	for (j = 0; j <= i; j++) {
		pcbt = &pcb->pcb_below[j];
		if (fclose(pcbt->pcb_fpr) == EOF) {
			if (!f_quiet) {
				perror(gettext("auditreduce: initial close "
				    "on pipe failed"));
			}
		}
		/*
		 * Free the buffer allocated to hold incoming records.
		 */
		if (i != j) {
			free(pcbt->pcb_rec);
		}
	}
}


/*
 * .func	p_close - close unused streams for parent.
 * .desc	Called by the parent right after forking a child.
 *	Closes the write stream on the pipe to the child since
 *	we will never use it.
 * .call	p_close(pcbn),
 * .arg	pcbn	- ptr to pcb.
 * .ret	void.
 */
static void
p_close(audit_pcb_t *pcbn)
{
	if (fclose(pcbn->pcb_fpw) == EOF) {
		if (!f_quiet) {
			perror(gettext("auditreduce: close for write "
			    "pipe failed"));
		}
	}
}


/*
 * .func	audit_stats - print statistics.
 * .desc	Print usage statistics for the user if the run fails.
 *	Tells them how many files they had and how many groups this
 *	totalled. Also tell them how many layers and processes the
 *	process tree had.
 * .call	audit_stats().
 * .arg	none.
 * .ret	void.
 */
void
audit_stats(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) != -1)
		(void) fprintf(stderr,
		    gettext("%s The system allows %d files per process.\n"),
		    ar, rl.rlim_cur);
	(void) fprintf(stderr, gettext(
"%s There were %d file(s) %d file group(s) %d process(es) %d layer(s).\n"),
		ar, filenum, pcbnum, total_procs, total_layers);
}


/*
 * .func gather_pcb - gather pcbs.
 * .desc Gather together the range of the sub-processes that we are
 *	responsible for. For a pcb that controls processes this is all
 *	of the sub-processes that it forks. For a pcb that controls
 *	files this is the the range of pcbs from audit_pcbs[].
 * .call gather_pcb(pcb, lo, hi).
 * .arg	pcb	- ptr to pcb.
 * .arg	lo	- lo index into pcb_below.
 * .arg	hi	- hi index into pcb_below.
 * .ret	void.
 */
static void
gather_pcb(audit_pcb_t *pcb, int lo, int hi)
{
	pcb->pcb_lo = lo;
	pcb->pcb_hi = hi;
	pcb->pcb_count = hi - lo + 1;
}


/*
 * .func calc_procs - calculate process parameters.
 * .desc Calculate the current run's paramters regarding how many
 *	processes will have to be forked (maybe none).
 *	5 is subtracted from maxfiles_proc to allow for stdin, stdout,
 *	stderr, and the pipe to a parent process. The outfile
 *	in the root process is assigned to stdout. The unused half of each
 *	pipe is closed, to allow for more connections, but we still
 *	have to have the 5th spot because in order to get the pipe
 *	we need 2 descriptors up front.
 * .call calc_procs().
 * .arg	none.
 * .ret	void.
 */
static void
calc_procs(void)
{
	int	val;
	int	maxfiles_proc;
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
		perror("auditreduce: getrlimit");
		exit(1);
	}

	maxfiles_proc = rl.rlim_cur;

	max_sproc = maxfiles_proc - 5;	/* max subprocesses per process */

	/*
	 * Calculate how many layers the process tree has.
	 */
	total_layers = 1;
	for (/* */; /* */; /* */) {
		val = a_pow(max_sproc, total_layers);
		if (val > pcbnum)
			break;
		total_layers++;
	}
	/*
	 * Count how many processes are in the process tree.
	 */
	mcount(pcbnum, 0);

#if AUDIT_PROC_TRACE
	(void) fprintf(stderr,
	    "pcbnum %d filenum %d mfp %d msp %d ly %d tot %d\n\n",
	    pcbnum, filenum, maxfiles_proc, max_sproc,
	    total_layers, total_procs);
#endif
}


static int
a_pow(int base, int exp)
{
	int	i;
	int	answer;

	if (exp == 0) {
		answer = 1;
	} else {
		answer = base;
		for (i = 0; i < (exp - 1); i++)
			answer *= base;
	}
	return (answer);
}


/*
 * .func mcount - main count.
 * .desc Go through the motions of building the process tree just
 *	to count how many processes there are. Don't really
 *	build anything. Answer is in global var total_procs.
 * .call mcount(nsp, lo).
 * .arg	nsp	- number of subs for this tree branch.
 * .arg	lo	- lo side of range of subs.
 * .ret	void.
 */
static void
mcount(int nsp, int lo)
{
	int	range, i, tofork, nnsp, nrem;

	total_procs++;		/* count another process created */

	if (nsp > max_sproc) {
		if (nsp <= max_sproc * (max_sproc - 1)) {
			tofork = nsp / max_sproc;
			if (nsp % max_sproc)
				tofork++;
		} else {
			tofork = max_sproc;
		}
		nnsp = nsp / tofork;
		nrem = nsp % tofork;
		for (i = 0; i < tofork; i++) {
			range = (nrem > 0) ? nnsp + 1 : nnsp;
			mcount(range, lo);
			nrem--;
			lo += range;
		}
	}
}


/*
 * .func delete_infiles - delete the input files.
 * .desc If the user asked us to (via 'D' flag) then unlink the input files.
 * .call ret = delete_infiles().
 * .arg none.
 * .ret void.
 */
static void
delete_infiles(void)
{
	int	i;
	audit_pcb_t *pcb;
	audit_fcb_t *fcb;

	for (i = 0; i < pcbsize; i++) {
		pcb = &audit_pcbs[i];
		fcb = pcb->pcb_dfirst;
		while (fcb != NULL) {
			/*
			 * Only delete a file if it was succesfully processed.
			 * If there were any read errors or bad records
			 * then don't delete it.
			 * There may still be unprocessed records in it.
			 */
			if (fcb->fcb_flags & FF_DELETE) {
				if (unlink(fcb->fcb_file)) {
					if (f_verbose) {
						(void) sprintf(errbuf, gettext(
						"%s delete on %s failed"),
						ar, fcb->fcb_file);
					}
					perror(errbuf);
				}
			}
			fcb = fcb->fcb_next;
		}
	}
}


/*
 * .func rm_outfile - remove the outfile.
 * .desc Remove the file we are writing the records to. We do this if
 *	processing failed and we are quitting before finishing.
 *	Update - don't actually remove the outfile, but generate
 *	a warning about its possible heathen nature.
 * .call ret = rm_outfile().
 * .arg	none.
 * .ret	void.
 */
static void
rm_outfile(void)
{
#if 0
	if (f_outfile) {
		if (unlink(f_outtemp) == -1) {
			(void) sprintf(errbuf,
				gettext("%s delete on %s failed"),
				ar, f_outtemp);
			perror(errbuf);
		}
	}
#else
	(void) fprintf(stderr,
gettext("%s Warning: Incomplete audit file may have been generated - %s\n"),
		ar,
		(f_outfile == NULL) ? gettext("standard output") : f_outfile);
#endif
}


/*
 * .func	close_outfile - close the outfile.
 * .desc	Close the file we are writing records to.
 * .call	ret = close_outfile().
 * .arg	none.
 * .ret	0	- close was succesful.
 * .ret	-1	- close failed.
 */
static int
close_outfile(void)
{
	if (fclose(stdout) == EOF) {
		(void) sprintf(errbuf, gettext("%s close on %s failed"),
		    ar, f_outfile ? f_outfile : "standard output");
		perror(errbuf);
		return (-1);
	}
	(void) fsync(fileno(stdout));
	return (rename_outfile());
}


/*
 * .func write_header - write audit file header.
 * .desc Write an audit file header to the output stream. The time in the
 *	header is the time of the first record written to the stream. This
 *	routine is called by the process handling the root node of the
 *	process tree just before it writes the first record to the output
 *	stream.
 * .ret	0 - succesful write.
 * .ret -1 - failed write - message printed.
 */
int
write_header(void)
{
	return (write_file_token(f_start));
}


static int
write_file_token(time_t when)
{
	adr_t adr;			/* adr ptr */
	struct timeval tv;		/* time now */
	char	for_adr[16];		/* plenty of room */
#ifdef _LP64
	char	token_id = AUT_OTHER_FILE64;
#else
	char	token_id = AUT_OTHER_FILE32;
#endif
	short	i = 1;
	char	c = '\0';

	tv.tv_sec = when;
	tv.tv_usec = 0;
	adr_start(&adr, for_adr);
	adr_char(&adr, &token_id, 1);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&tv, 2);
#else
	adr_int32(&adr, (int32_t *)&tv, 2);
#endif
	adr_short(&adr, &i, 1);
	adr_char(&adr, &c, 1);

	if (fwrite(for_adr, sizeof (char), adr_count(&adr), stdout) !=
	    adr_count(&adr)) {
		if (when == f_start) {
			(void) sprintf(errbuf,
				gettext("%s error writing header to %s. "),
				ar,
				f_outfile ? f_outfile :
					gettext("standard output"));
		} else {
			(void) sprintf(errbuf,
				gettext("%s error writing trailer to %s. "),
				ar,
				f_outfile ? f_outfile :
					gettext("standard output"));
		}
		perror(errbuf);
		return (-1);
	}
	return (0);
}


/*
 * .func  write_trailer - write audit file trailer.
 * .desc  Write an audit file trailer to the output stream. The finish
 *	time for the trailer is the time of the last record written
 *	to the stream.
 * .ret	0 - succesful write.
 * .ret	-1 - failed write - message printed.
 */
static int
write_trailer(void)
{
	return (write_file_token(f_end));
}


/*
 * .func rename_outfile - rename the outfile.
 * .desc If the user used the -O flag they only gave us the suffix name
 *	for the outfile. We have to add the time stamps to put the filename
 *	in the proper audit file name format. The start time will be the time
 *	of the first record in the file and the end time will be the time of
 *	the last record in the file.
 * .ret	0 - rename succesful.
 * .ret	-1 - rename failed - message printed.
 */
static int
rename_outfile(void)
{
	char	f_newfile[MAXFILELEN];
	char	buf1[15], buf2[15];
	char	*f_file, *f_nfile, *f_time, *f_name;

	if (f_outfile != NULL) {
		/*
		 * Get string representations of start and end times.
		 */
		derive_str(f_start, buf1);
		derive_str(f_end, buf2);

		f_nfile = f_time = f_newfile;	/* working copy */
		f_file = f_name = f_outfile;	/* their version */
		while (*f_file) {
			if (*f_file == '/') {	/* look for filename */
				f_time = f_nfile + 1;
				f_name = f_file + 1;
			}
			*f_nfile++ = *f_file++;	/* make copy of their version */
		}
		*f_time = '\0';
		/* start time goes first */
		(void) strcat(f_newfile, buf1);
		(void) strcat(f_newfile, ".");
		/* then the finish time */
		(void) strcat(f_newfile, buf2);
		(void) strcat(f_newfile, ".");
		/* and the name they gave us */
		(void) strcat(f_newfile, f_name);

#if AUDIT_FILE
		(void) fprintf(stderr, "rename_outfile: <%s> --> <%s>\n",
			f_outfile, f_newfile);
#endif

#if AUDIT_RENAME
		if (rename(f_outtemp, f_newfile) == -1) {
			(void) fprintf(stderr,
			    "%s rename of %s to %s failed.\n",
			    ar, f_outtemp, f_newfile);
			return (-1);
		}
		f_outfile = f_newfile;
#else
		if (rename(f_outtemp, f_outfile) == -1) {
			(void) fprintf(stderr,
			    gettext("%s rename of %s to %s failed.\n"),
			    ar, f_outtemp, f_outfile);
			return (-1);
		}
#endif
	}
	return (0);
}


/*
 * .func open_outfile - open the outfile.
 * .desc Open the outfile specified by the -O option. Assign it to the
 *	the standard output. Get a unique temporary name to use so we
 *	don't clobber an existing file.
 * .ret	0 - no errors detected.
 * .ret	-1 - errors in processing (message already printed).
 */
static int
open_outfile(void)
{
	int	tmpfd = -1;

	if (f_outfile != NULL) {
		f_outtemp = (char *)a_calloc(1, strlen(f_outfile) + 8);
		(void) strcpy(f_outtemp, f_outfile);
		(void) strcat(f_outtemp, "XXXXXX");
		if ((tmpfd = mkstemp(f_outtemp)) == -1) {
			(void) sprintf(errbuf,
			    gettext("%s couldn't create temporary file"), ar);
			perror(errbuf);
			return (-1);
		}
		(void) fflush(stdout);
		if (tmpfd != fileno(stdout)) {
			if ((dup2(tmpfd, fileno(stdout))) == -1) {
				(void) sprintf(errbuf,
				    gettext("%s can't assign %s to the "
				    "standard output"), ar, f_outfile);
				perror(errbuf);
				return (-1);
			}
			(void) close(tmpfd);
		}
	}
	return (0);
}


/*
 * .func init_options - initialize the options.
 * .desc Give initial and/or default values to some options.
 * .call init_options();
 * .arg	none.
 * .ret	void.
 */
static void
init_options(void)
{
	struct timeval tp;
	struct timezone tpz;

	/*
	 * Get current time for general use.
	 */
	if (gettimeofday(&tp, &tpz) == -1)
		perror(gettext("auditreduce: initial getttimeofday failed"));

	time_now = tp.tv_sec;		/* save for general use */
	f_start = 0;			/* first record time default */
	f_end = time_now;		/* last record time default */
	m_after = 0;			/* Jan 1, 1970 00:00:00 */

	/*
	 * Setup initial size of audit_pcbs[].
	 */
	pcbsize = PCB_INITSIZE;		/* initial size of file-holding pcb's */

	audit_pcbs = (audit_pcb_t *)a_calloc(pcbsize, sizeof (audit_pcb_t));

	/* description of 'current' error */
	error_str = gettext("initial error");

}


/*
 * .func a_calloc - audit calloc.
 * .desc Calloc with check for failure. This is called by all of the
 *	places that want memory.
 * .call ptr = a_calloc(nelem, size).
 * .arg	nelem - number of elements to allocate.
 * .arg	size - size of each element.
 * .ret	ptr - ptr to allocated and zeroed memory.
 * .ret	never - if calloc fails then we never return.
 */
void	*
a_calloc(int nelem, size_t size)
{
	void	*ptr;

	if ((ptr = calloc((unsigned)nelem, size)) == NULL) {
		perror(gettext("auditreduce: memory allocation failed"));
		exit(1);
	}
	return (ptr);
}


/*
 * .func init_sig - initial signal catching.
 *
 * .desc
 *	Setup the signal catcher to catch the SIGCHLD signal plus
 *	"environmental" signals -- keyboard plus other externally
 *	generated signals such as out of file space or cpu time.  If a
 *	child exits with either a non-zero exit code or was killed by
 *	a signal to it then we will also exit with a non-zero exit
 *	code. In this way abnormal conditions can be passed up to the
 *	root process and the entire run be halted. Also catch the int
 *	and quit signals. Remove the output file since it is in an
 *	inconsistent state.
 * .call ret = init_sig().
 * .arg none.
 * .ret 0 - no errors detected.
 * .ret -1 - signal failed (message printed).
 */
static int
init_sig(void)
{
	if (signal(SIGCHLD, chld_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGCHLD signal failed"));
		return (-1);
	}

	if (signal(SIGHUP, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGHUP signal failed"));
		return (-1);
	}
	if (signal(SIGINT, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGINT signal failed"));
		return (-1);
	}
	if (signal(SIGQUIT, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGQUIT signal failed"));
		return (-1);
	}
	if (signal(SIGABRT, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGABRT signal failed"));
		return (-1);
	}
	if (signal(SIGTERM, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGTERM signal failed"));
		return (-1);
	}
	if (signal(SIGPWR, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGPWR signal failed"));
		return (-1);
	}
	if (signal(SIGXCPU, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGXCPU signal failed"));
		return (-1);
	}
	if (signal(SIGXFSZ, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGXFSZ signal failed"));
		return (-1);
	}
	if (signal(SIGSEGV, int_handler) == SIG_ERR) {
		perror(gettext("auditreduce: SIGSEGV signal failed"));
		return (-1);
	}

	return (0);
}


/*
 * .func chld_handler - handle child signals.
 * .desc Catch the SIGCHLD signals. Remove the root process
 *	output file because it is in an inconsistent state.
 *	Print a message giving the signal number and/or return code
 *	of the child who caused the signal.
 * .ret	void.
 */
/* ARGSUSED */
void
chld_handler(int sig)
{
	int	pid;
	int	status;

	/*
	 * Get pid and reasons for cause of event.
	 */
	pid = wait(&status);

	if (pid > 0) {
		/*
		 * If child received a signal or exited with a non-zero
		 * exit status then print message and exit
		 */
		if ((WHIBYTE(status) == 0 && WLOBYTE(status) != 0) ||
		    (WHIBYTE(status) != 0 && WLOBYTE(status) == 0)) {
			(void) fprintf(stderr,
			    gettext("%s abnormal child termination - "), ar);

			if (WHIBYTE(status) == 0 && WLOBYTE(status) != 0) {
				psignal(WLOBYTE(status), "signal");
				if (WCOREDUMP(status))
					(void) fprintf(stderr,
					    gettext("core dumped\n"));
			}

			if (WHIBYTE(status) != 0 && WLOBYTE(status) == 0)
				(void) fprintf(stderr, gettext(
					"return code %d\n"),
					WHIBYTE(status));

			/*
			 * Get rid of outfile - it is suspect.
			 */
			if (f_outfile != NULL) {
				(void) close_outfile();
				rm_outfile();
			}
			/*
			 * Give statistical info that may be useful.
			 */
			audit_stats();

			exit(1);
		}
	}
}


/*
 * .func	int_handler - handle quit/int signals.
 * .desc	Catch the keyboard and other environmental signals.
 *		Remove the root process output file because it is in
 *		an inconsistent state.
 * .ret	void.
 */
/* ARGSUSED */
void
int_handler(int sig)
{
	if (getpid() == root_pid) {
		(void) close_outfile();
		rm_outfile();
		exit(1);
	}
	/*
	 * For a child process don't give an error exit or the
	 * parent process will catch it with the chld_handler and
	 * try to erase the outfile again.
	 */
	exit(0);
}
