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
 * Copyright 1995-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * module:
 *	debug.c
 *
 * purpose:
 *	utility routines for debugging filesync (tracing, diagnostics,
 *	and error simulation)
 *
 * contents:
 *	showflags	display a word of flags symbolicly
 *	dbg_usage	printout usage info for -D switch
 *	err_usage	printout usage info for -E switch
 *	dbg_set_error	enable an error simulation
 *	dbg_check_error	check for error simulation
 *
 *
 * note:
 *	there are numerous flag words and bit fields in this
 *	program, and it would be horrendous to just print them
 *	out in hex (in debugging output).  These routines use
 *	a "flaglist" data structure to map between bits and
 *	character string names or descriptions.
 *
 *	a flaglist is merely a list of paired bits and name strings.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "filesync.h"
#include "database.h"
#include "debug.h"


/* bits in opt_debug for usage message					*/
static struct flaglist dbgflags[] =
{	DBG_BASE,	"BASE: base include building",
	DBG_RULE,	"RULE: rule tree building",
	DBG_STAT,	"STAT: file stats",
	DBG_ANAL,	"ANAL: difference analysis",
	DBG_RECON,	"RECO: reconciliation list processing",
	DBG_VARS,	"VARS: qualification and expansion",
	DBG_FILES,	"FILE: rule and baseline files",
	DBG_LIST,	"LIST: tree building",
	DBG_EVAL,	"EVAL: tree walking",
	DBG_IGNORE,	"IGNO: ignore list",
	DBG_MISC,	"MISC: everything else",
	0,		0
};

/* bits in opt_debug for dsiplay					*/
struct flaglist dbgmap[] =
{	DBG_BASE,	"BASE",
	DBG_RULE,	"RULE",
	DBG_STAT,	"STAT",
	DBG_ANAL,	"ANAL",
	DBG_RECON,	"RECO",
	DBG_VARS,	"VARS",
	DBG_FILES,	"FILE",
	DBG_LIST,	"LIST",
	DBG_EVAL,	"EVAL",
	DBG_IGNORE,	"IGNO",
	DBG_MISC,	"MISC",
	0,		0
};

/* bits in the rules flag field					*/
struct flaglist rflags[] =
{	R_IGNORE, 	"IGNORE",
	R_PROGRAM,	"PROGRAM",
	R_WILD,		"WILD",
	R_NEW,		"NEW",
	R_BOGUS,	"BOGUS",
	R_RESTRICT,	"RESTRICT",
	0,		0
};

/* bits in the files flag field					*/
struct flaglist fileflags[] =
{	F_NEW, 		"new",
	F_IN_BASELINE,	"base",
	F_IN_SOURCE,	"srce",
	F_IN_DEST,	"dest",
	F_EVALUATE,	"eval",
	F_SPARSE,	"sparse",
	F_REMOVE,	"remove",
	F_CONFLICT,	"conflict",
	F_LISTED,	"listed",
	F_STAT_ERROR,	"statfail",
	0,		0
};

/* bits in the file src/dst difference mask			*/
struct flaglist diffmap[] = {
	D_CREATE,	"create",
	D_DELETE,	"delete",
	D_MTIME,	"modtime",
	D_SIZE,		"size",
	D_UID,		"uid",
	D_GID,		"gid",
	D_PROT,		"modes",
	D_LINKS,	"links",
	D_TYPE,		"type",
	D_FACLS,	"facls",
	D_RENAME_TO,	"rename2",
	D_RENAME_FROM,	"renamed",
	0,		0
};

/* bits in the exit error code mask				*/
struct flaglist errmap[] = {
	ERR_RESOLVABLE,	"resolvable",
	ERR_UNRESOLVED,	"unresolvable",
	ERR_MISSING,	"missing files",
	ERR_PERM,	"permissions",
	ERR_FILES,	"rule/base errors",
	ERR_INVAL,	"invalid arguments",
	ERR_NOBASE,	"bad base dir",
	ERR_OTHER,	"other",
	0,		0
};

/*
 * routine:
 *	showflags
 *
 * purpose:
 *	format flags for printing
 *
 * parameters:
 *	pointer to map
 *	mask to be interpreted \
 *
 * returns:
 *	pointer to a static buffer
 */
char *
showflags(struct flaglist *map, long mask)
{	int i;
	static char outbuf[MAX_NAME];

	outbuf[0] = 0;
	for (i = 0; map[i].fl_mask; i++)
		if (mask & map[i].fl_mask) {
			if (outbuf[0])
				strcat(outbuf, "|");
			strcat(outbuf, map[i].fl_name);
		}

	return (outbuf);
}

/*
 * routines:
 *	dbg_usage, err_usage
 *
 * purpose:
 *	to print out usage messages for the secret debugging flags
 *
 * returns:
 *	void
 */
void
dbg_usage(void)
{	int i;

	fprintf(stderr, "Usage:\tfilesync -Dmask ...\n");
	for (i = 0; dbgflags[i].fl_mask; i++)
		fprintf(stderr, "\t0x%04lx .... %s\n",
			dbgflags[i].fl_mask, dbgflags[i].fl_name);
	fprintf(stderr, "\n");
}

#ifdef	DBG_ERRORS
/*
 * The -E flag is a debugging feature that enables the user to request
 * the simulation of difficult to trigger error conditions in order
 * to test out the error handling code in filesync.  We maintain a
 * registry that specifies a file name and an operation, and an errno
 * to be returned if the specified operation is attempted on the
 * specified file.
 */
void
err_usage(void)
{
	fprintf(stderr, "Usage:\tfilesync -E<errno>,<code>,<filename>\n");
	fprintf(stderr, "\ts ... eval stat source\n");
	fprintf(stderr, "\tS ... eval stat destination\n");
	fprintf(stderr, "\tn ... eval nftw source\n");
	fprintf(stderr, "\tN ... eval nftw destination\n");
	fprintf(stderr, "\tc ... reconcile copy create\n");
	fprintf(stderr, "\to ... reconcile copy open\n");
	fprintf(stderr, "\tr ... reconcile copy read/readlink\n");
	fprintf(stderr, "\tw ... reconcile copy write\n");
	fprintf(stderr, "\tl ... reconcile link/symlink\n");
	fprintf(stderr, "\tu ... reconcile unlink\n");
	fprintf(stderr, "\td ... reconcile mkdir/mknod\n");
	fprintf(stderr, "\tD ... reconcile rmdir\n");
	fprintf(stderr, "\tm ... reconcile rename\n");
	fprintf(stderr, "\tR ... reconcile restat\n");
	fprintf(stderr, "\tp ... reconcile protection (chmod)");
	fprintf(stderr, "\ta ... reconcile access control (setfacl)");
	fprintf(stderr, "\tO ... reconcile ownership (chown)");
	fprintf(stderr, "\tZ ... out of space on target\n");
	fprintf(stderr, "\n");
}

/*
 * this data structure us used to keep track of the error simulations
 * that have been requested.
 */
static struct errsim {
	int Errno;		/* error number to return	*/
	char code;		/* event triggering the error	*/
	char *file;		/* file name triggering error	*/
} errsim[ DBG_MAX_ERR ];

static int num_errs;		/* number of simulated errors	*/


/*
 * routine:
 *	dbg_set_error
 *
 * purpose:
 * 	note that we have been requested to simulate file access errors
 *
 * parameters:
 *	argument string <errno>,<errcode>,<filename>
 *
 * returns:
 *	error mask
 */
int
dbg_set_error(char *arg)
{	char *s;
	char error_type;
	int error_no;

	if (num_errs >= DBG_MAX_ERR) {
		fprintf(stderr, "ERROR: only %d -E specifications allowed\n",
				DBG_MAX_ERR);
		return (ERR_INVAL);
	}

	/* get the error number		*/
	if (!isdigit(arg[0]))
		return (ERR_INVAL);
	error_no = strtol(arg, &s, 0);

	/* get the error condition	*/
	if (*s++ != ',' || !isalpha(*s))
		return (ERR_INVAL);
	error_type = *s;

	/* get the file name		*/
	while (*s && *s != ',') s++;
	if (*s++ != ',' || *s == 0)
		return (ERR_INVAL);

	/* register the error simulation	*/
	errsim[num_errs].Errno = error_no;
	errsim[num_errs].code  = error_type;
	errsim[num_errs].file  = s;

	if (opt_debug & DBG_MISC)
		fprintf(stderr, "MISC: errsim[%d] %c(%s) -> %d\n",
			num_errs, error_type, s, error_no);

	num_errs++;

	return (0);
}

/*
 * routine:
 *	dbg_chk_error
 *
 * purpose:
 *	determine whether or not we have been asked to simulate an
 *	error for a specified file.
 *
 * parameters:
 *	file name
 *
 * returns:
 *	errno (or zero if no error)
 */
int
dbg_chk_error(const char *name, char code)
{	int i;

	for (i = 0; i < num_errs; i++) {
		/* see if this code matches any registered condition	*/
		if (code != errsim[i].code)
			continue;

		/* see if this also matches the file name	*/
		if (!suffix(name, errsim[i].file))
			continue;

		/* we have a winner				*/
		if (opt_debug & DBG_MISC)
			fprintf(stderr, "MISC: trigger %d for file %c(%s)\n",
				errsim[i].Errno, code, name);
		return (errsim[i].Errno);
	}
	return (0);
}

#else	/* ! DBG_ERRORS	*/
void
err_usage(void)
{
	fprintf(stderr, "ERROR: this filesync does not support -E\n");
}

int
dbg_set_error(char *arg)
{
	return (ERR_INVAL);
}

int
dbg_chk_error(const char *name, char code)
{
	return (0);
}
#endif
