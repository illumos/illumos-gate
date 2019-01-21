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

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include "error.h"

static void errorprint(FILE *place, Eptr errorp, boolean print_all);
static void text(Eptr p, boolean use_all);
static void insert(int place);
static void execvarg(int n_pissed_on, int *r_argc, char ***r_argv);
static void diverterrors(char *name, int dest, Eptr **files, int ix,
    boolean previewed, int nterrors);
static void hackfile(char *name, Eptr **files, int ix, int nerrors);
static int countfiles(Eptr *errors);
static int nopertain(Eptr **files);
static int oktotouch(char *filename);
static boolean preview(int nerrors, Eptr **files, int ix);
static int settotouch(char *name);
static boolean edit(char *name);
static int mustoverwrite(FILE *preciousfile, FILE *tmpfile);
static int mustwrite(char *base, int n, FILE *preciousfile);
static void writetouched(int overwrite);

/*
 *	Iterate through errors
 */
#define	EITERATE(p, fv, i)	for (p = fv[i]; p < fv[i+1]; p++)
#define	ECITERATE(ei, p, lb)	\
	for (ei = lb; p = errors[ei], ei < nerrors; ei++)

#define	FILEITERATE(fi, lb)	for (fi = lb; fi <= nfiles; fi++)
int	touchstatus = Q_YES;

void
findfiles(int nerrors, Eptr *errors, int *r_nfiles, Eptr ***r_files)
{
	int	nfiles;
	Eptr	**files;

	char	*name;
	int	ei;
	int	fi;
	Eptr	errorp;

	nfiles = countfiles(errors);

	files = Calloc(nfiles + 3, sizeof (Eptr*));
	touchedfiles = Calloc(nfiles+3, sizeof (boolean));
	/*
	 *	Now, partition off the error messages
	 *	into those that are synchronization, discarded or
	 *	not specific to any file, and those that were
	 *	nulled or true errors.
	 */
	files[0] = &errors[0];
	ECITERATE(ei, errorp, 0) {
		if (!(NOTSORTABLE(errorp->error_e_class)))
			break;
	}
	/*
	 *	Now, and partition off all error messages
	 *	for a given file.
	 */
	files[1] = &errors[ei];
	touchedfiles[0] = touchedfiles[1] = FALSE;
	name = "\1";
	fi = 1;
	ECITERATE(ei, errorp, ei) {
		if ((errorp->error_e_class == C_NULLED) ||
		    (errorp->error_e_class == C_TRUE)) {
			if (strcmp(errorp->error_text[0], name) != 0) {
				name = errorp->error_text[0];
				touchedfiles[fi] = FALSE;
				files[fi] = &errors[ei];
				fi++;
			}
		}
	}
	files[fi] = &errors[nerrors];
	*r_nfiles = nfiles;
	*r_files = files;
}

static int
countfiles(Eptr *errors)
{
	char	*name;
	int	ei;
	Eptr	errorp;

	int	nfiles;
	nfiles = 0;
	name = "\1";
	ECITERATE(ei, errorp, 0) {
		if (SORTABLE(errorp->error_e_class)) {
			if (strcmp(errorp->error_text[0], name) != 0) {
				nfiles++;
				name = errorp->error_text[0];
			}
		}
	}
	return (nfiles);
}

char	*class_table[] = {
	/* C_UNKNOWN	0	*/	"Unknown",
	/* C_IGNORE	1	*/	"ignore",
	/* C_SYNC	2	*/	"synchronization",
	/* C_DISCARD	3	*/	"discarded",
	/* C_NONSPEC	4	*/	"non specific",
	/* C_THISFILE	5	*/	"specific to this file",
	/* C_NULLED	6	*/	"nulled",
	/* C_TRUE	7	*/	"true",
	/* C_DUPL	8	*/	"duplicated"
};

int	class_count[C_LAST - C_FIRST] = {0};

void
filenames(int nfiles, Eptr **files)
{
	int	fi;
	char	*sep = " ";
	int	someerrors;

	/*
	 *	first, simply dump out errors that
	 *	don't pertain to any file
	 */
	someerrors = nopertain(files);

	if (nfiles) {
		someerrors++;
		(void) fprintf(stdout, terse
			? "%d file%s"
			: "%d file%s contain%s errors",
			nfiles, plural(nfiles), verbform(nfiles));
		if (!terse) {
			FILEITERATE(fi, 1) {
				(void) fprintf(stdout, "%s\"%s\" (%d)",
					sep, (*files[fi])->error_text[0],
					files[fi+1] - files[fi]);
				sep = ", ";
			}
		}
		(void) fprintf(stdout, "\n");
	}
	if (!someerrors)
		(void) fprintf(stdout, "No errors.\n");
}

/*
 *	Dump out errors that don't pertain to any file
 */
static int
nopertain(Eptr **files)
{
	int	type;
	int	someerrors = 0;
	Eptr	*erpp;
	Eptr	errorp;

	if (files[1] - files[0] <= 0)
		return (0);
	for (type = C_UNKNOWN; NOTSORTABLE(type); type++) {
		if (class_count[type] <= 0)
			continue;
		if (type > C_SYNC)
			someerrors++;
		if (terse) {
			(void) fprintf(stdout, "\t%d %s errors NOT PRINTED\n",
				class_count[type], class_table[type]);
		} else {
			(void) fprintf(stdout, "\n\t%d %s errors follow\n",
				class_count[type], class_table[type]);
			EITERATE(erpp, files, 0) {
				errorp = *erpp;
				if (errorp->error_e_class == type) {
					errorprint(stdout, errorp, TRUE);
				}
			}
		}
	}
	return (someerrors);
}

boolean
touchfiles(int nfiles, Eptr **files, int *r_edargc, char ***r_edargv)
{
	char	*name;
	Eptr	errorp;
	int	fi;
	Eptr	*erpp;
	int		ntrueerrors;
	boolean		scribbled;
	int		n_pissed_on;	/* # of file touched */
	int	spread;

	FILEITERATE(fi, 1) {
		name = (*files[fi])->error_text[0];
		spread = files[fi+1] - files[fi];
		(void) fprintf(stdout, terse
			? "\"%s\" has %d error%s, "
			: "\nFile \"%s\" has %d error%s.\n",
			name, spread, plural(spread));
		/*
		 *	First, iterate through all error messages in this file
		 *	to see how many of the error messages really will
		 *	get inserted into the file.
		 */
		ntrueerrors = 0;
		EITERATE(erpp, files, fi) {
			errorp = *erpp;
			if (errorp->error_e_class == C_TRUE)
				ntrueerrors++;
		}
		(void) fprintf(stdout, terse ? "insert %d\n" :
		    "\t%d of these errors can be inserted into the file.\n",
		    ntrueerrors);

		hackfile(name, files, fi, ntrueerrors);
	}
	scribbled = FALSE;
	n_pissed_on = 0;
	FILEITERATE(fi, 1) {
		scribbled |= touchedfiles[fi];
		n_pissed_on++;
	}
	if (scribbled) {
		/*
		 *	Construct an execv argument
		 */
		execvarg(n_pissed_on, r_edargc, r_edargv);
		return (TRUE);
	} else {
		if (!terse)
			(void) fprintf(stdout, "You didn't touch any files.\n");
		return (FALSE);
	}
}

static void
hackfile(char *name, Eptr **files, int ix, int nerrors)
{
	boolean	previewed;
	int	errordest;	/* where errors go */

	if (!oktotouch(name)) {
		previewed = FALSE;
		errordest = TOSTDOUT;
	} else {
		previewed = preview(nerrors, files, ix);
		errordest = settotouch(name);
	}

	if (errordest != TOSTDOUT)
		touchedfiles[ix] = TRUE;

	if (previewed && (errordest == TOSTDOUT))
		return;

	diverterrors(name, errordest, files, ix, previewed, nerrors);

	if (errordest == TOTHEFILE) {
		/*
		 *	overwrite the original file
		 */
		writetouched(1);
	}
}

static boolean
preview(int nerrors, Eptr **files, int ix)
{
	int	back;
	Eptr	*erpp;

	if (nerrors <= 0)
		return (FALSE);
	back = FALSE;
	if (query) {
		switch (inquire(terse
		    ? "Preview? "
		    : "Do you want to preview the errors first? ")) {
		case Q_YES:
		case Q_yes:
			back = TRUE;
			EITERATE(erpp, files, ix) {
				errorprint(stdout, *erpp, TRUE);
			}
			if (!terse)
				(void) fprintf(stdout, "\n");
		default:
			break;
		}
	}
	return (back);
}

static int
settotouch(char *name)
{
	int	dest = TOSTDOUT;

	if (query) {
		switch (touchstatus = inquire(terse
			? "Touch? "
			: "Do you want to touch file \"%s\"? ",
			name)) {
		case Q_NO:
		case Q_no:
			return (dest);
		default:
			break;
		}
	}

	switch (probethisfile(name)) {
	case F_NOTREAD:
		dest = TOSTDOUT;
		(void) fprintf(stdout, terse
			? "\"%s\" unreadable\n"
			: "File \"%s\" is unreadable\n",
			name);
		break;
	case F_NOTWRITE:
		dest = TOSTDOUT;
		(void) fprintf(stdout, terse
			? "\"%s\" unwritable\n"
			: "File \"%s\" is unwritable\n",
			name);
		break;
	case F_NOTEXIST:
		dest = TOSTDOUT;
		(void) fprintf(stdout,
		    terse ? "\"%s\" not found\n" :
			"Can't find file \"%s\" to insert error "
			"messages into.\n",
		    name);
		break;
	default:
		dest = edit(name) ? TOSTDOUT : TOTHEFILE;
		break;
	}
	return (dest);
}

static void
diverterrors(char *name, int dest, Eptr **files, int ix,
    boolean previewed, int nterrors)
{
	int	nerrors;
	Eptr	*erpp;
	Eptr	errorp;

	nerrors = files[ix+1] - files[ix];

	if ((nerrors != nterrors) && (!previewed)) {
		(void) fprintf(stdout, terse
			? "Uninserted errors\n"
			: ">>Uninserted errors for file \"%s\" follow.\n",
			name);
	}

	EITERATE(erpp, files, ix) {
		errorp = *erpp;
		if (errorp->error_e_class != C_TRUE) {
			if (previewed || touchstatus == Q_NO)
				continue;
			errorprint(stdout, errorp, TRUE);
			continue;
		}
		switch (dest) {
		case TOSTDOUT:
			if (previewed || touchstatus == Q_NO)
				continue;
			errorprint(stdout, errorp, TRUE);
			break;
		case TOTHEFILE:
			insert(errorp->error_line);
			text(errorp, FALSE);
			break;
		}
	}
}

static int
oktotouch(char *filename)
{
	extern		char	*suffixlist;
	char	*src;
	char	*pat;
			char	*osrc;

	pat = suffixlist;
	if (pat == 0)
		return (0);
	if (*pat == '*')
		return (1);
	while (*pat++ != '.')
		continue;
	--pat;		/* point to the period */

	for (src = &filename[strlen(filename)], --src;
	    (src > filename) && (*src != '.'); --src)
		continue;
	if (*src != '.')
		return (0);

	for (src++, pat++, osrc = src; *src && *pat; src = osrc, pat++) {
		for (; *src &&			/* not at end of the source */
		    *pat &&			/* not off end of pattern */
		    *pat != '.' &&		/* not off end of sub pattern */
		    *pat != '*' &&		/* not wild card */
		    *src == *pat;		/* and equal... */
		    src++, pat++)
			continue;
		if (*src == 0 && (*pat == 0 || *pat == '.' || *pat == '*'))
			return (1);
		if (*src != 0 && *pat == '*')
			return (1);
		while (*pat && *pat != '.')
			pat++;
		if (! *pat)
			return (0);
	}
	return (0);
}
/*
 *	Construct an execv argument
 *	We need 1 argument for the editor's name
 *	We need 1 argument for the initial search string
 *	We need n_pissed_on arguments for the file names
 *	We need 1 argument that is a null for execv.
 *	The caller fills in the editor's name.
 *	We fill in the initial search string.
 *	We fill in the arguments, and the null.
 */
static void
execvarg(int n_pissed_on, int *r_argc, char ***r_argv)
{
	Eptr	p;
	char	*sep;
	int	fi;

	(*r_argv) = Calloc(n_pissed_on + 3, sizeof (char *));
	(*r_argc) =  n_pissed_on + 2;
	(*r_argv)[1] = "+1;/###/";
	n_pissed_on = 2;
	if (!terse) {
		(void) fprintf(stdout, "You touched file(s):");
		sep = " ";
	}
	FILEITERATE(fi, 1) {
		if (!touchedfiles[fi])
			continue;
		p = *(files[fi]);
		if (!terse) {
			(void) fprintf(stdout, "%s\"%s\"", sep,
			    p->error_text[0]);
			sep = ", ";
		}
		(*r_argv)[n_pissed_on++] = p->error_text[0];
	}
	if (!terse)
		(void) fprintf(stdout, "\n");
	(*r_argv)[n_pissed_on] = 0;
}

FILE	*o_touchedfile;	/* the old file */
FILE	*n_touchedfile;	/* the new file */
char	*o_name;
char	n_name[64];
char	*canon_name = "/tmp/ErrorXXXXXX";
int	o_lineno;
int	n_lineno;
boolean	tempfileopen = FALSE;
/*
 *	open the file; guaranteed to be both readable and writable
 *	Well, if it isn't, then return TRUE if something failed
 */
static boolean
edit(char *name)
{
	o_name = name;
	if ((o_touchedfile = fopen(name, "r")) == NULL) {
		(void) fprintf(stderr,
		    "%s: Can't open file \"%s\" to touch (read).\n",
		    processname, name);
		return (TRUE);
	}
	(void) strcpy(n_name, canon_name);
	(void) mktemp(n_name);
	if ((n_touchedfile = fopen(n_name, "w")) == NULL) {
		(void) fprintf(stderr,
		    "%s: Can't open file \"%s\" to touch (write).\n",
		    processname, name);
		return (TRUE);
	}
	tempfileopen = TRUE;
	n_lineno = 0;
	o_lineno = 0;
	return (FALSE);
}
/*
 *	Position to the line (before, after) the line given by place
 */
char	edbuf[BUFSIZ];

static void
insert(int place)
{
	--place;	/* always insert messages before the offending line */
	for (; o_lineno < place; o_lineno++, n_lineno++) {
		if (fgets(edbuf, BUFSIZ, o_touchedfile) == NULL)
			return;
		(void) fputs(edbuf, n_touchedfile);
	}
}

static void
text(Eptr p, boolean use_all)
{
	int	offset = use_all ? 0 : 2;

	(void) fputs(lang_table[p->error_language].lang_incomment,
	    n_touchedfile);
	(void) fprintf(n_touchedfile, "%d [%s] ",
		p->error_line,
		lang_table[p->error_language].lang_name);
	wordvprint(n_touchedfile, p->error_lgtext-offset, p->error_text+offset);
	(void) fputs(lang_table[p->error_language].lang_outcomment,
	    n_touchedfile);
	n_lineno++;
}

/*
 *	write the touched file to its temporary copy,
 *	then bring the temporary in over the local file
 */
static void
writetouched(int overwrite)
{
	int	nread;
	FILE	*localfile;
	FILE	*tmpfile;
	int	botch;
	int	oktorm;

	botch = 0;
	oktorm = 1;
	while ((nread = fread(edbuf, 1, sizeof (edbuf),
	    o_touchedfile)) != 0) {
		if (nread != fwrite(edbuf, 1, nread, n_touchedfile)) {
			/*
			 *	Catastrophe in temporary area: file system full?
			 */
			botch = 1;
			(void) fprintf(stderr,
			    "%s: write failure: No errors inserted in \"%s\"\n",
			    processname, o_name);
		}
	}
	(void) fclose(n_touchedfile);
	(void) fclose(o_touchedfile);
	/*
	 *	Now, copy the temp file back over the original
	 *	file, thus preserving links, etc
	 */
	if (botch == 0 && overwrite) {
		botch = 0;
		localfile = NULL;
		tmpfile = NULL;
		if ((localfile = fopen(o_name, "w")) == NULL) {
			(void) fprintf(stderr,
				"%s: Can't open file \"%s\" to overwrite.\n",
				processname, o_name);
			botch++;
		}
		if ((tmpfile = fopen(n_name, "r")) == NULL) {
			(void) fprintf(stderr,
			    "%s: Can't open file \"%s\" to read.\n",
			    processname, n_name);
			botch++;
		}
		if (!botch)
			oktorm = mustoverwrite(localfile, tmpfile);
		if (localfile != NULL)
			(void) fclose(localfile);
		if (tmpfile != NULL)
			(void) fclose(tmpfile);
	}
	if (oktorm == 0) {
		(void) fprintf(stderr,
		    "%s: Catastrophe: A copy of \"%s: was saved in \"%s\"\n",
		    processname, o_name, n_name);
		exit(1);
	}
	/*
	 *	Kiss the temp file good bye
	 */
	(void) unlink(n_name);
	tempfileopen = FALSE;
}
/*
 *	return 1 if the tmpfile can be removed after writing it out
 */
static int
mustoverwrite(FILE *preciousfile, FILE *tmpfile)
{
	int	nread;

	while ((nread = fread(edbuf, 1, sizeof (edbuf), tmpfile)) != 0) {
		if (mustwrite(edbuf, nread, preciousfile) == 0)
			return (0);
	}
	return (1);
}
/*
 *	return 0 on catastrophe
 */
static int
mustwrite(char *base, int n, FILE *preciousfile)
{
	int	nwrote;

	if (n <= 0)
		return (1);
	nwrote = fwrite(base, 1, n, preciousfile);
	if (nwrote == n)
		return (1);
	perror(processname);
	switch (inquire(terse
	    ? "Botch overwriting: retry? "
	    : "Botch overwriting the source file: retry? ")) {
	case Q_YES:
	case Q_yes:
		(void) mustwrite(base + nwrote, n - nwrote, preciousfile);
		return (1);
	case Q_NO:
	case Q_no:
		switch (inquire("Are you sure? ")) {
		case Q_YES:
		case Q_yes:
			return (0);
		case Q_NO:
		case Q_no:
			(void) mustwrite(base + nwrote, n - nwrote,
			    preciousfile);
			return (1);
		}
	default:
		return (0);
	}
}

/* ARGSUSED */
void
onintr(int sig)
{
	switch (inquire(terse
	    ? "\nContinue? "
	    : "\nInterrupt: Do you want to continue? ")) {
	case Q_YES:
	case Q_yes:
		(void) signal(SIGINT, onintr);
		return;
	default:
		if (tempfileopen) {
			/*
			 *	Don't overwrite the original file!
			 */
			writetouched(0);
		}
		exit(1);
	}
	/*NOTREACHED*/
}

static void
errorprint(FILE *place, Eptr errorp, boolean print_all)
{
	int	offset = print_all ? 0 : 2;

	if (errorp->error_e_class == C_IGNORE)
		return;
	(void) fprintf(place, "[%s] ",
	    lang_table[errorp->error_language].lang_name);
	wordvprint(place, errorp->error_lgtext-offset,
	    errorp->error_text+offset);
	(void) putc('\n', place);
}

/*PRINTFLIKE1*/
int
inquire(char *format, ...)
{
	char	buffer[128];
	va_list	args;

	if (queryfile == NULL)
		return (0);
	for (;;) {
		do {
			va_start(args, format);
			(void) fflush(stdout);
			(void) vfprintf(stderr, format, args);
			(void) fflush(stderr);
			va_end(args);
		} while (fgets(buffer, 127, queryfile) == NULL);
		switch (buffer[0]) {
		case 'Y':	return (Q_YES);
		case 'y':	return (Q_yes);
		case 'N':	return (Q_NO);
		case 'n':	return (Q_no);
		default:	(void) fprintf(stderr, "Yes or No only!\n");
		}
	}
}

int
probethisfile(char *name)
{
	struct stat statbuf;
	if (stat(name, &statbuf) < 0)
		return (F_NOTEXIST);
	if ((statbuf.st_mode & S_IREAD) == 0)
		return (F_NOTREAD);
	if ((statbuf.st_mode & S_IWRITE) == 0)
		return (F_NOTWRITE);
	return (F_TOUCHIT);
}
