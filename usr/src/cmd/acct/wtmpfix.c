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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * wtmpfix - adjust wtmpx file and remove date changes.
 *	wtmpfix <wtmpx1 >wtmpx2
 *
 *	Can recover to some extent from wtmpx corruption.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "acctdef.h"
#include <utmpx.h>
#include <time.h>
#include <ctype.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define	DAYEPOCH	(60 * 60 * 24)
#define	UTRSZ		(sizeof (struct futmpx)) /* file record size */

/*
 * The acctsh(8) shell scripts startup(8) and shutacct(8) as well as the
 * runacct script each pass their own specific reason strings in the first
 * argument to acctwtmp(8), to be propagated into ut_line fields.  Additional
 * reasons (RUNLVL_MSG, ..., DOWN_MSG), used by compiled code, are defined in
 * <utmp.h> as preprocessor constants.
 * For simplicity we predefine similar constants for the scripted strings
 * here, as no other compiled code uses those.
 * Moreover, we need a variant of RUNLVL_MSG without the "%c" at the end.
 * We shall use the fact that ut_line[RLVLMSG_LEN] will extract the char
 * in the %c position ('S', '2', ...).
 * Since all of these string constants are '\0' terminated, they can safely
 * be used with strcmp() even when ut_line is not.
 */
#define	RUN_LEVEL_MSG	"run-level "
#define	ACCTG_ON_MSG	"acctg on"
#define	ACCTG_OFF_MSG	"acctg off"
#define	RUNACCT_MSG	"runacct"

#define	RLVLMSG_LEN	(sizeof (RUN_LEVEL_MSG) - 1)

/*
 * Records encountered are classified as one of the following:  corrupted;
 * ok but devoid of interest to acctcon downstream;  ok and interesting;
 * or ok and even redundant enough to latch onto a new alignment whilst
 * recovering from a corruption.
 * The ordering among these four symbolic values is significant.
 */
typedef enum {
	INRANGE_ERR = -1,
	INRANGE_DROP,
	INRANGE_PASS,
	INRANGE_ALIGNED
} inrange_t;

/* input filenames and record numbers, for diagnostics only */
#define	STDIN_NAME	"<stdin>"
static char	*cur_input_name;
static off_t	recin;

static FILE	*Wtmpx, *Temp;

struct	dtab
{
	off_t	d_off1;		/* file offset start */
	off_t	d_off2;		/* file offset stop */
	time_t	d_adj;		/* time adjustment */
	struct dtab *d_ndp;	/* next record */
};

static struct	dtab	*Fdp;	/* list header */
static struct	dtab	*Ldp;	/* list trailer */

static time_t 	lastmonth, nextmonth;

static struct	futmpx	Ut, Ut2;

static int winp(FILE *, struct futmpx *);
static void mkdtab(off_t);
static void setdtab(off_t, struct futmpx *, struct futmpx *);
static void adjust(off_t, struct futmpx *);
static int invalid(char *);
static void scanfile(void);
static inrange_t inrange(void);
static void wcomplain(char *);

int
main(int argc, char **argv)
{
	time_t tloc;
	struct tm *tmp;
	int year;
	int month;
	off_t rectmpin;

	(void) setlocale(LC_ALL, "");
	setbuf(stdout, NULL);

	(void) time(&tloc);
	tmp = localtime(&tloc);
	year = tmp->tm_year;
	month = tmp->tm_mon + 1;
	lastmonth = ((year + 1900 - 1970) * 365 +
	    (month - 1) * 30) * DAYEPOCH;
	nextmonth = ((year + 1900 - 1970) * 365 +
	    (month + 1) * 30) * DAYEPOCH;

	if (argc < 2) {
		argv[argc] = "-";
		argc++;
	}

	/*
	 * Almost all system call failures in this program are unrecoverable
	 * and therefore fatal.  Typical causes might be lack of memory or
	 * of space in a filesystem.  If necessary, the system administrator
	 * can invoke /usr/lib/acct/runacct interactively after making room
	 * to complete the remaining phases of last night's accounting.
	 */
	if ((Temp = tmpfile()) == NULL) {
		perror("Cannot create temporary file");
		return (EXIT_FAILURE);
	}

	while (--argc > 0) {
		argv++;
		if (strcmp(*argv, "-") == 0) {
			Wtmpx = stdin;
			cur_input_name = STDIN_NAME;
		} else if ((Wtmpx = fopen(*argv, "r")) == NULL) {
			(void) fprintf(stderr, "Cannot open %s: %s\n",
			    *argv, strerror(errno));
			return (EXIT_FAILURE);
		} else {
			cur_input_name = *argv;
		}
		/*
		 * Filter records reading from current input stream Wtmpx,
		 * writing to Temp.
		 */
		scanfile();

		if (Wtmpx != stdin)
			(void) fclose(Wtmpx);
	}
	/* flush and rewind Temp for readback */
	if (fflush(Temp) != 0) {
		perror("<temporary file>: fflush");
		return (EXIT_FAILURE);
	}
	if (fseeko(Temp, (off_t)0L, SEEK_SET) != 0) {
		perror("<temporary file>: seek");
		return (EXIT_FAILURE);
	}
	/* second pass: apply time adjustments */
	rectmpin = 0;
	while (winp(Temp, &Ut)) {
		adjust(rectmpin, &Ut);
		rectmpin += UTRSZ;
		if (fwrite(&Ut, UTRSZ, 1, stdout) < 1) {
			perror("<stdout>: fwrite");
			return (EXIT_FAILURE);
		}
	}
	(void) fclose(Temp);
	/*
	 * Detect if we've run out of space (say) and exit unsuccessfully
	 * so that downstream accounting utilities won't start processing an
	 * incomplete tmpwtmp file.
	 */
	if (fflush(stdout) != 0) {
		perror("<stdout>: fflush");
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

static int
winp(FILE *f, struct futmpx *w)
{
	if (fread(w, (size_t)UTRSZ, (size_t)1, f) != 1)
		return (0);
	if ((w->ut_type >= EMPTY) && (w->ut_type <= UTMAXTYPE))
		return (1);
	else {
		(void) fprintf(stderr, "Bad temp file at offset %lld\n",
		    (longlong_t)(ftell(f) - UTRSZ));
		/*
		 * If input was corrupt, neither ut_line nor ut_user can be
		 * relied on to be \0-terminated.  Even fixing the precision
		 * does not entirely guard against this.
		 */
		(void) fprintf(stderr,
		    "ut_line \"%-12.12s\" ut_user \"%-8.8s\" ut_xtime %ld\n",
		    w->ut_line, w->ut_user, (long)w->ut_xtime);
		exit(EXIT_FAILURE);
	}
	/* NOTREACHED */
}

static void
mkdtab(off_t p)
{

	struct dtab *dp;

	dp = Ldp;
	if (dp == NULL) {
		dp = calloc(sizeof (struct dtab), 1);
		if (dp == NULL) {
			(void) fprintf(stderr, "out of memory\n");
			exit(EXIT_FAILURE);
		}
		Fdp = Ldp = dp;
	}
	dp->d_off1 = p;
}

static void
setdtab(off_t p, struct futmpx *w1, struct futmpx *w2)
{
	struct dtab *dp;

	if ((dp = Ldp) == NULL) {
		(void) fprintf(stderr, "no dtab\n");
		exit(EXIT_FAILURE);
	}
	dp->d_off2 = p;
	dp->d_adj = w2->ut_xtime - w1->ut_xtime;
	if ((Ldp = calloc(sizeof (struct dtab), 1)) == NULL) {
		(void) fprintf(stderr, "out of memory\n");
		exit(EXIT_FAILURE);
	}
	Ldp->d_off1 = dp->d_off1;
	dp->d_ndp = Ldp;
}

static void
adjust(off_t p, struct futmpx *w)
{

	off_t pp;
	struct dtab *dp;

	pp = p;

	for (dp = Fdp; dp != NULL; dp = dp->d_ndp) {
		if (dp->d_adj == 0)
			continue;
		if (pp >= dp->d_off1 && pp <= dp->d_off2)
			w->ut_xtime += dp->d_adj;
	}
}

/*
 * invalid() determines whether the name field adheres to the criteria
 * set forth in acctcon1.  If returns VALID if the name is ok, or
 * INVALID if the name violates conventions.
 */

static int
invalid(char *name)
{
	int	i;

	for (i = 0; i < NSZ; i++) {
		if (name[i] == '\0')
			return (VALID);
		if (! (isalnum(name[i]) || (name[i] == '$') ||
		    (name[i] == ' ') || (name[i] == '.') ||
		    (name[i] == '_') || (name[i] == '-'))) {
			return (INVALID);
		}
	}
	return (VALID);
}

/*
 * scanfile:
 * 1)  	reads the current input file
 * 2)   filters for process records in time range of interest and for
 *      other types of records deemed interesting to acctcon downstream
 * 3)   picks up time changes with setdtab() if in multiuser mode, which
 *      will be applied when the temp file is read back
 * 4)   changes bad login names to INVALID
 * 5)   recovers from common cases of wtmpx corruption (loss of record
 *      alignment).
 * All of the static globals are used directly or indirectly.
 *
 * When wtmpfix is asked to process several input files in succession,
 * some state needs to be preserved from one scanfile() invocation to the
 * next.  Aside from the temp file position, we remember whether we were
 * in multi-user mode or not.  Absent evidence to the contrary, we begin
 * processing assuming multi-user mode, because runacct's wtmpx rotation
 * normally gives us a file recently initialized by utmp2wtmp(8) with no
 * older RUN_LVL records surviving.
 */

static void
scanfile()
{
	struct stat Wtstat;
	off_t residue = 0;	/* input file size mod UTRSZ */
	/*
	 * lastok will be the offset of the beginning of the most recent
	 * manifestly plausible and interesting input record in the current
	 * input file, if any.
	 * An invariant at loop entry is -UTRSZ <= lastok <= recin - UTRSZ.
	 */
	off_t lastok = -(off_t)UTRSZ;
	static off_t rectmp;	/* current temp file position */
	static boolean_t multimode = B_TRUE; /* multi-user RUN_LVL in force */
	inrange_t is_ok;	/* caches inrange() result */
	/*
	 * During normal operation, records are of interest and copied to
	 * the output when is_ok >= INRANGE_PASS, ignored and dropped when
	 * is_ok == INRANGE_DROP, and evidence of corruption otherwise.
	 * While we are trying to recover from a corruption and hunting for
	 * records with sufficient redundancy to confirm that we have reached
	 * proper alignment again, we'll want is_ok >= INRANGE_ALIGNED.
	 * The value of want_ok is the minimum inrange() result of current
	 * interest.  It is raised to INRANGE_ALIGNED during ongoing recovery
	 * and dropped back to INRANGE_PASS when we have recovered alignment.
	 */
	inrange_t want_ok = INRANGE_PASS;
	boolean_t recovered = B_FALSE; /* true after a successful recovery */
	int n;

	if (fstat(fileno(Wtmpx), &Wtstat) == -1) {
		(void) fprintf(stderr,
		    "Cannot stat %s (will read sequentially): %s\n",
		    cur_input_name, strerror(errno));
	} else if ((Wtstat.st_mode & S_IFMT) == S_IFREG) {
		residue = Wtstat.st_size % UTRSZ;
	}

	/* if residue != 0, part of the file may be misaligned */
	for (recin = 0;
	    ((n = fread(&Ut, (size_t)UTRSZ, (size_t)1, Wtmpx)) > 0) ||
	    (residue > 0);
	    recin += UTRSZ) {
		if (n == 0) {
			/*
			 * Implying residue > 0 and want_ok == INRANGE_PASS.
			 * It isn't worth telling an I/O error from EOF here.
			 * But one case is worth catching to avoid issuing a
			 * confusing message below.  When the previous record
			 * had been ok, we just drop the current truncated
			 * record and bail out of the loop -- no seeking back.
			 */
			if (lastok == recin - UTRSZ) {
				wcomplain("file ends in mid-record, "
				    "final partial record dropped");
				break;
			} else {
				wcomplain("file ends in mid-record");
				/* handled below like a corrupted record */
				is_ok = INRANGE_ERR;
			}
		} else
			is_ok = inrange();

		/* alignment recovery logic */
		if ((residue > 0) && (is_ok == INRANGE_ERR)) {
			/*
			 * "Let's go back to the last place where we knew
			 * where we were..."
			 * In fact, if the last record had been fine and we
			 * know there's at least one whole record ahead, we
			 * might move forward here  (by residue bytes, less
			 * than one record's worth).  In any case, we align
			 * ourselves to an integral number of records before
			 * the end of the file.
			 */
			wcomplain("suspecting misaligned records, "
			    "repositioning");
			recin = lastok + UTRSZ + residue;
			residue = 0;
			if (fseeko(Wtmpx, recin, SEEK_SET) != 0) {
				(void) fprintf(stderr, "%s: seek: %s\n",
				    cur_input_name, strerror(errno));
				exit(EXIT_FAILURE);
			}
			wcomplain("starting re-scan");
			/*
			 * While want_ok is elevated, only unequivocal records
			 * with inrange() == INRANGE_ALIGNED will be admitted
			 * to latch onto the tentative new alignment.
			 */
			want_ok = INRANGE_ALIGNED;
			/*
			 * Compensate for the loop continuation.  Doing
			 * it this way gets the correct offset reported
			 * in the re-scan message above.
			 */
			recin -= UTRSZ;
			continue;
		}
		/* assert: residue == 0 or is_ok >= INRANGE_DROP here */
		if (is_ok < want_ok)
			/* record of no further interest */
			continue;
		if (want_ok == INRANGE_ALIGNED) {
			wcomplain("now recognizing aligned records again");
			want_ok = INRANGE_PASS;
			recovered = B_TRUE;
		}
		/*
		 * lastok must track recin whenever the current record is
		 * being processed and written out to our temp file, to avoid
		 * reprocessing any bits already done when we readjust our
		 * alignment.
		 */
		lastok = recin;

		/* now we have a good wtmpx record, do more processing */

		if (rectmp == 0 || Ut.ut_type == BOOT_TIME)
			mkdtab(rectmp);
		if (Ut.ut_type == RUN_LVL) {
			/* inrange() already checked the "run-level " part */
			if (Ut.ut_line[RLVLMSG_LEN] == 'S')
				multimode = B_FALSE;
			else if ((Ut.ut_line[RLVLMSG_LEN] == '2') ||
			    (Ut.ut_line[RLVLMSG_LEN] == '3') ||
			    (Ut.ut_line[RLVLMSG_LEN] == '4'))
				multimode = B_TRUE;
		}
		if (invalid(Ut.ut_name) == INVALID) {
			(void) fprintf(stderr,
			    "wtmpfix: logname \"%*.*s\" changed "
			    "to \"INVALID\"\n", OUTPUT_NSZ,
			    OUTPUT_NSZ, Ut.ut_name);
			(void) strncpy(Ut.ut_name, "INVALID", NSZ);
		}
		/*
		 * Special case: OLD_TIME should be immediately followed by
		 * NEW_TIME.
		 * We make no attempt at alignment recovery between these
		 * two: if there's junk at this point in the input, then
		 * a NEW_TIME seen after the junk probably won't be the one
		 * we are looking for.
		 */
		if (Ut.ut_type == OLD_TIME) {
			/*
			 * Make recin refer to the expected NEW_TIME.
			 * Loop continuation will increment it again
			 * for the record we're about to read now.
			 */
			recin += UTRSZ;
			if (!fread(&Ut2, (size_t)UTRSZ, (size_t)1, Wtmpx)) {
				wcomplain("input truncated after OLD_TIME - "
				    "giving up");
				exit(EXIT_FAILURE);
			}
			/*
			 * Rudimentary NEW_TIME sanity check.  Not as thorough
			 * as in inrange(), but then we have redundancy from
			 * context here, since we're just after a plausible
			 * OLD_TIME record.
			 */
			if ((Ut2.ut_type != NEW_TIME) ||
			    (strcmp(Ut2.ut_line, NTIME_MSG) != 0)) {
				wcomplain("NEW_TIME expected but missing "
				    "after OLD_TIME - giving up");
				exit(EXIT_FAILURE);
			}
			lastok = recin;
			if (multimode == B_TRUE)
				setdtab(rectmp, &Ut, &Ut2);
			rectmp += 2 * UTRSZ;
			if ((fwrite(&Ut, UTRSZ, 1, Temp) < 1) ||
			    (fwrite(&Ut2, UTRSZ, 1, Temp) < 1)) {
				perror("<temporary file>: fwrite");
				exit(EXIT_FAILURE);
			}
			continue;
		}
		if (fwrite(&Ut, UTRSZ, 1, Temp) < 1) {
			perror("<temporary file>: fwrite");
			exit(EXIT_FAILURE);
		}
		rectmp += UTRSZ;
	}
	if (want_ok == INRANGE_ALIGNED) {
		wcomplain("EOF reached without recognizing another aligned "
		    "record with certainty. This file may need to be "
		    "repaired by hand.\n");
	} else if (recovered == B_TRUE) {
		/*
		 * There may have been a number of wcomplain() messages
		 * since we reported about the re-scan, so it bears repeating
		 * at the end that not all was well.
		 */
		wcomplain("EOF reached after recovering from corruption "
		    "in the middle of the file.  This file may need to be "
		    "repaired by hand.\n");
	}
}

/*
 * inrange: inspect what we hope to be one wtmpx record.
 * Globals:  Ut, lastmonth, nextmonth;  recin, cur_input_name (diagnostics)
 * Return values:
 * INRANGE_ERR     -- an inconsistency was detected, input file corrupted
 * INRANGE_DROP    -- Ut appears consistent but isn't of interest
 *                    (of process type and outside the time range we want)
 * INRANGE_PASS    -- Ut appears consistent and this record is of interest
 * INRANGE_ALIGNED -- same, and it is also redundant enough to be sure
 *                    that we're correctly aligned on record boundaries
 */
#define	UNEXPECTED_UT_PID \
	(Ut.ut_pid != 0) || \
	(Ut.ut_exit.e_termination != 0) || \
	(Ut.ut_exit.e_exit != 0)

static inrange_t
inrange()
{
	/* pid_t is signed so that fork() can return -1.  Exploit this. */
	if (Ut.ut_pid < 0) {
		wcomplain("negative pid");
		return (INRANGE_ERR);
	}

	/* the legal values for ut_type are enumerated in <utmp.h> */
	switch (Ut.ut_type) {
	case EMPTY:
		if (UNEXPECTED_UT_PID) {
			wcomplain("nonzero pid or status in EMPTY record");
			return (INRANGE_ERR);
		}
		/*
		 * We'd like to have Ut.ut_user[0] == '\0' here, but sadly
		 * this isn't always so, so we can't rely on it.
		 */
		return (INRANGE_DROP);
	case RUN_LVL:
		/* ut_line must have come from the RUNLVL_MSG pattern */
		if (strncmp(Ut.ut_line, RUN_LEVEL_MSG, RLVLMSG_LEN) != 0) {
			wcomplain("RUN_LVL record doesn't say `"
			    RUN_LEVEL_MSG "'");
			return (INRANGE_ERR);
		}
		/*
		 * The ut_pid, termination, and exit status fields have
		 * special meaning in this case, and none of them is
		 * suitable for checking.  And we won't insist on ut_user
		 * to always be an empty string.
		 */
		return (INRANGE_ALIGNED);
	case BOOT_TIME:
		if (UNEXPECTED_UT_PID) {
			wcomplain("nonzero pid or status in BOOT_TIME record");
			return (INRANGE_ERR);
		}
		if (strcmp(Ut.ut_line, BOOT_MSG) != 0) {
			wcomplain("BOOT_TIME record doesn't say `"
			    BOOT_MSG "'");
			return (INRANGE_ERR);
		}
		return (INRANGE_ALIGNED);
	case OLD_TIME:
		if (UNEXPECTED_UT_PID) {
			wcomplain("nonzero pid or status in OLD_TIME record");
			return (INRANGE_ERR);
		}
		if (strcmp(Ut.ut_line, OTIME_MSG) != 0) {
			wcomplain("OLD_TIME record doesn't say `"
			    OTIME_MSG "'");
			return (INRANGE_ERR);
		}
		return (INRANGE_ALIGNED);
	case NEW_TIME:
		/*
		 * We don't actually expect to see any here.  If they follow
		 * an OLD_TIME record as they should, they'll be handled on
		 * the fly in scanfile().  But we might still run into one
		 * if the input is somehow corrupted.
		 */
		if (UNEXPECTED_UT_PID) {
			wcomplain("nonzero pid or status in NEW_TIME record");
			return (INRANGE_ERR);
		}
		if (strcmp(Ut.ut_line, NTIME_MSG) != 0) {
			wcomplain("NEW_TIME record doesn't say `"
			    NTIME_MSG "'");
			return (INRANGE_ERR);
		}
		return (INRANGE_ALIGNED);

	/* the four *_PROCESS ut_types have a lot in common */
	case USER_PROCESS:
		/*
		 * Catch two special cases first: psradm records have no id
		 * and no pid, while root login over FTP may not have a
		 * valid ut_user and may have garbage in ut_id[3].
		 */
		if ((strcmp(Ut.ut_user, "psradm") == 0) &&
		    (Ut.ut_id[0] == '\0') &&
		    (Ut.ut_pid > 0)) {
			if ((Ut.ut_xtime > lastmonth) &&
			    (Ut.ut_xtime < nextmonth)) {
				return (INRANGE_ALIGNED);
			} else {
				return (INRANGE_DROP);
			}
		}
		if ((Ut.ut_user[0] == '\0') &&
		    (strncmp(Ut.ut_id, "ftp", 3) == 0) &&
		    (strncmp(Ut.ut_line, "ftp", 3) == 0)) {
			if ((Ut.ut_xtime > lastmonth) &&
			    (Ut.ut_xtime < nextmonth)) {
				return (INRANGE_ALIGNED);
			} else {
				return (INRANGE_DROP);
			}
		}
		/* FALLTHROUGH */
	case LOGIN_PROCESS:
		if (Ut.ut_user[0] == '\0') {
			wcomplain("missing username in process record");
			return (INRANGE_ERR);
		}
		/* FALLTHROUGH */
	case INIT_PROCESS:
		/*
		 * INIT_PROCESS and DEAD_PROCESS records can come with an
		 * empty ut_user in degenerate cases (e.g. syntax errors
		 * like a comment-only process field in /etc/inittab).
		 * But in an INIT_PROCESS, LOGIN_PROCESS, or USER_PROCESS
		 * record, we expect a respectable ut_pid.
		 */
		if (Ut.ut_pid == 0) {
			wcomplain("null pid in process record");
			return (INRANGE_ERR);
		}
		/* FALLTHROUGH */
	case DEAD_PROCESS:
		/*
		 * DEAD_PROCESS records with a null ut_pid can be produced
		 * by gnome-terminal (normally seen in utmpx only, but they
		 * can leak into wtmpx in rare circumstances).
		 * Unfortunately, ut_id can't be relied on to contain
		 * anything in particular.  (E.g., sshd might leave it
		 * 0-initialized.)  This leaves almost no verifiable
		 * redundancy here beyond the ut_type.
		 * At least we insist on a reasonable timestamp.
		 */
		if (Ut.ut_xtime <= 0) {
			wcomplain("non-positive time in process record");
			return (INRANGE_ERR);
		}
		if ((Ut.ut_xtime > lastmonth) &&
		    (Ut.ut_xtime < nextmonth)) {
			return (INRANGE_PASS);
		} else {
			return (INRANGE_DROP);
		}
	case ACCOUNTING:
		/*
		 * If we recognize one of the three reason strings passed
		 * by the /usr/lib/acct shell scripts to acctwtmp, we
		 * exploit the available redundancy they offer.  But
		 * acctwtmp could have been invoked by custom scripts or
		 * interactively with other reason strings in the first
		 * argument, so anything we don't recognize does not
		 * constitute evidence for corruption.
		 */
		if ((strcmp(Ut.ut_line, RUNACCT_MSG) != 0) &&
		    (strcmp(Ut.ut_line, ACCTG_ON_MSG) != 0) &&
		    (strcmp(Ut.ut_line, ACCTG_OFF_MSG) != 0)) {
			return (INRANGE_DROP);
		}
		return (INRANGE_ALIGNED);
	case DOWN_TIME:
		if (UNEXPECTED_UT_PID) {
			wcomplain("nonzero pid or status in DOWN_TIME record");
			return (INRANGE_ERR);
		}
		if (strcmp(Ut.ut_line, DOWN_MSG) != 0) {
			wcomplain("DOWN_TIME record doesn't say `"
			    DOWN_MSG "'");
			return (INRANGE_ERR);
		}
		return (INRANGE_ALIGNED);
	default:
		wcomplain("ut_type out of range");
		return (INRANGE_ERR);
	}
	/* NOTREACHED */
}

static void
wcomplain(char *msg)
{
	(void) fprintf(stderr, "%s: offset %lld: %s\n", cur_input_name,
	    (longlong_t)recin, msg);
}
