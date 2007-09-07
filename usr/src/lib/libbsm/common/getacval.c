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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * get audit control info (replaces getacinfo.c)
 */

#include <secdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>

#define	REALLY_LONG_LINE 8192

#define	FILE_AT_START 0	/* file pointer is at file start or file is closed */
#define	FILE_MIDDLE 1	/* file pointer is not at file start */

#define	LEN 360		/* arbitrary audit control entry length */

#define	SUCCESS 0
#define	EOF_WARN 1
#define	REW_WARN 2
#define	EOF_ERR -1
#define	ERROR   -2
#define	FORMAT_ERR -3
#define	NO_CONTEXT -4

/*
 * libbsm.h has opaque typedef:  typedef struct au_acinfo au_acinfo_t
 */
struct au_acinfo {
	char	*file;
	FILE	*fp;
	int	file_pointer;
	int	once_read;
};

static char	*MINLABEL	= "minfree:";
static char	*DIRLABEL	= "dir:";
static char	*DEFFLGLABEL	= "flags:";
static char	*NAFLGLABEL	= "naflags:";
static char	*lib_label	= "plugin:";

/*
 * get extended line, i.e., interpret trailing "\" and join to make
 * a single line.  Returns NULL on error or EOF, else returns its
 * input pointer.  A line containing only "\" and some blanks is valid.
 *
 * doesn't handle a comment line embedded in a series of continued lines.
 */

static char *
getlongline(char *line, int length, FILE *fp)
{
	int	keepgoing = 1;
	int	partcount = 0;
	char	*l, *b;
	int	end = 0;

	l = line;
	while (keepgoing) {
		if (fgets(l, length, fp) != NULL) {
			partcount++;
			end = strlen(l);
			b = l + end - 2;	/* last char before \n */
			*(b + 1) = '\0';	/* chop the \n */
			keepgoing = 0;
			while (b >= l) {
				if (*b == '\\') {
					keepgoing = 1;
					l = b;
					length -= (end - 1);
					break;
				} else if (*b != ' ')
					break;
				end--;
				b--;
			}
		} else
			keepgoing = 0;
	}
	if (partcount > 0)
		return (line);
	else
		return (NULL);
}

/*
 * input a string of the form   attr: xxxxx{\n}
 * and return xxxxx with leading, internal, and trailing blanks removed
 */

static int
getvalue(char *out_buf, char *line, char *attr_name, int out_len)
{
	int	attr_length, value_length;
	char	*bp, *cp;
	int	retstat = SUCCESS;

	attr_length = (int)strlen(attr_name);
	value_length = (int)strlen(line);

	if (strncmp(line, attr_name, attr_length) == 0) {
		/*
		 * allow zero or more blanks
		 * between colon and rest of line
		 */
		value_length -= attr_length;

		bp = line + attr_length;
		while (*bp == ' ') {
			value_length--;
			attr_length++; /* offset to first non-blank */
			bp++;
		}
		cp = bp;
		while (*bp != '\0') {
			if (*bp == ' ') {
				bp++;
				value_length--;
			} else {
				*cp++ = *bp++;
			}
		}
		*cp = '\0';

		if (value_length < 1) {
			*out_buf = '\0';
			return (retstat);
		}
		if ((retstat == SUCCESS) &&
		    (strlcpy(out_buf, line + attr_length, out_len) >=
		    out_len))
			retstat = FORMAT_ERR;
	} else
		retstat = FORMAT_ERR;

	return (retstat);
}

/*
 * getacval.c  -  get audit control info
 *
 *	_getacdir() - get audit control directories, one at a time
 *	_getacflg() - get audit control default audit flags
 *	_getacmin() - get audit control directory min. fill value
 *	_getacna()  - get audit control non-attrib audit flags
 *	_getacplug() - get audit control remote host and associated data
 *	_openac()  - open the audit control file
 *	_endac()    -  close the audit control file
 */

/*
 * _getacdir() - get audit control directories, one at a time
 *
 * input: len  - size of dir buffer
 *
 * output: dir - directory string
 *
 * returns:	0 - entry read ok
 *		-1 - end of file
 *		-2 - error - can't open audit control file for read
 *		-3 - error - directory entry format error
 *		2 - directory search started from beginning again
 *
 * notes: It is the responsibility of the calling function to
 * 		check the status of the directory entry.
 */

int
_getacdir(au_acinfo_t *context, char *dir, int len)
{
	int	retstat = SUCCESS, gotone = 0;
	char	*entry;

	if (context == NULL)
		return (NO_CONTEXT);

	entry = malloc(REALLY_LONG_LINE);
	if (entry == NULL)
		return (ERROR);

	if ((context->file_pointer != FILE_AT_START) &&
	    (context->once_read == 1)) {
		retstat = REW_WARN;
		_rewindac(context);
	} else {
		context->once_read = 1;
		context->file_pointer = FILE_AT_START;
	}
	if (retstat >= SUCCESS) do {
		if (getlongline(entry, REALLY_LONG_LINE, context->fp) != NULL) {
			if (*entry == 'd') {
				retstat = getvalue(dir, entry, DIRLABEL, len);
				if (retstat == SUCCESS) {
					if (strlen(dir) == 0) {
						retstat = FORMAT_ERR;
					} else {
						gotone = 1;
					}
				}
			}
		} else if ((feof(context->fp)) == 0) {
			retstat = ERROR;
		} else {
			retstat = EOF_ERR;
		}
	} while (gotone == 0 && retstat >= SUCCESS);

	free(entry);
	return (retstat);
}


/*
 * _getacmin() - get audit control directory min. fill value
 *
 * output: min_val - percentage of directory fill allowed
 *
 * returns:	0 - entry read ok
 *		1 - end of file
 *		-2 - error; errno contains error number
 *		-3 - error - directory entry format error
 */

int
_getacmin(au_acinfo_t *context, int *min_val)
{
	int	retstat = SUCCESS, gotone = 0;

	char	entry[LEN];
	char	value[LEN];

	if (context == NULL)
		return (NO_CONTEXT);

	_rewindac(context);

	if (retstat == SUCCESS) do {
		if (getlongline(entry, LEN, context->fp) != NULL) {
			if (*entry == 'm') {
				retstat = getvalue(value, entry, MINLABEL,
				    5);	/* sb 2 digits, allow more */
				if (retstat == SUCCESS) {
					gotone = 1;
					*min_val = (int)strtol(value, NULL, 10);
					if ((*min_val == 0) && (errno != 0))
						retstat = FORMAT_ERR;
				}
			}
		} else if ((feof(context->fp)) == 0)
			retstat = ERROR;
		else
			retstat = EOF_WARN;

	} while (gotone == 0 && retstat == SUCCESS);

	if (context->file_pointer == FILE_AT_START)
		context->file_pointer = FILE_MIDDLE;
	else
		_rewindac(context);

	return (retstat);
}


/*
 * _getacflg() - get audit control flags
 *
 * output: auditstring - character representation of system audit flags
 *
 * returns:	0 - entry read ok
 *		1 - end of file
 *		-2 - error - errno contains error number
 *		-3 - error - directory entry format error
 */

int
_getacflg(au_acinfo_t *context, char *auditstring, int len)
{
	int	retstat = SUCCESS, gotone = 0;
	char	*entry;

	if (context == NULL)
		return (NO_CONTEXT);

	entry = malloc(REALLY_LONG_LINE);
	if (entry == NULL)
		return (ERROR);

	_rewindac(context);

	if (retstat == SUCCESS) do {
		if (getlongline(entry, REALLY_LONG_LINE, context->fp) != NULL) {
			if (*entry == 'f') {
				retstat = getvalue(auditstring, entry,
				    DEFFLGLABEL, len);
				if (retstat == SUCCESS)
					gotone = 1;
			}
		} else if ((feof(context->fp)) == 0) {
			retstat = ERROR;
		} else {
			retstat = EOF_WARN;
		}
	} while (gotone == 0 && retstat == SUCCESS);

	if (context->file_pointer == FILE_AT_START)
		context->file_pointer = FILE_MIDDLE;
	else
		_rewindac(context);

	free(entry);
	return (retstat);
}


/*
 * _getacna() - get audit flags for non-attributable (server) events
 *
 * output: auditstring - character representation of system audit flags
 *
 * returns:	0 - entry read ok
 *		1 - end of file
 *		-2 - error - errno contains error number
 *		-3 - error - directory entry format error
 */

int
_getacna(au_acinfo_t *context, char *auditstring, int len)
{
	int	retstat = SUCCESS, gotone = 0;
	char	*entry;

	entry = malloc(REALLY_LONG_LINE);
	if (entry == NULL)
		return (ERROR);

	_rewindac(context);

	if (retstat == SUCCESS) do {
		if (getlongline(entry, REALLY_LONG_LINE, context->fp) != NULL) {
			if (*entry == 'n') {
				retstat = getvalue(auditstring, entry,
				    NAFLGLABEL, len);
				if (retstat == SUCCESS)
					gotone = 1;
			}
		} else if ((feof(context->fp)) == 0) {
			retstat = ERROR;
		} else {
			retstat = EOF_WARN;
		}
	/* end of if-do */
	} while (gotone == 0 && retstat == SUCCESS);

	if (context->file_pointer == FILE_AT_START)
		context->file_pointer = FILE_MIDDLE;
	else
		_rewindac(context);

	free(entry);
	return (retstat);
}

/*
 * _getacplug() - get plugin parameter line
 *
 * As with _getacdir, the caller is responsible for checking the
 * validity of what's returned.
 *
 * outputs:	keyvalue list (call _kva_free(list_ptr) when you're done with
 *		it.)
 *
 * returns:	SUCCESS - entry read ok
 *		EOF_WARN - end of file
 *		REW_WARN - started over at the start of file
 *		ERROR - error - errno contains error number
 *		FORMAT_ERROR - fat finger failure
 */
#define	MAX_ARG	256

int
_getacplug(au_acinfo_t *context, kva_t **kv_list)
{
	int	retstat = SUCCESS, got_one = 0;
	char	entry[REALLY_LONG_LINE];
	char	value[REALLY_LONG_LINE];

	if (context == NULL)
		return (NO_CONTEXT);

	if (context->file_pointer != FILE_AT_START && context->once_read == 1) {
		retstat = REW_WARN;
		_rewindac(context);
	} else {
		context->once_read = 1;
		context->file_pointer = FILE_AT_START;
	}

	if (retstat == SUCCESS) do {
		if (getlongline(entry, REALLY_LONG_LINE, context->fp) != NULL) {
			if (*entry == 'p') {
				retstat = getvalue(value, entry, lib_label,
				    REALLY_LONG_LINE);
				if (retstat == SUCCESS)
					got_one = 1;
			}
		} else if ((feof(context->fp)) == 0) {
			retstat = ERROR;
		} else {
			retstat = EOF_WARN;
		}
		/* end of if-do */
	} while ((got_one == 0) && (retstat == SUCCESS));

	/* value contains a list of attribute/value pairs */
	if (got_one) {
		*kv_list = _str2kva(value, "=", ";");
		if (*kv_list == NULL)
			retstat = FORMAT_ERR;
	} else {
		retstat = EOF_WARN;
		*kv_list = NULL;
	}
lib_exit:

	return (retstat);
}

/* rewind the audit control file */
void
_rewindac(au_acinfo_t *context)
{
	rewind(context->fp);
	context->file_pointer = FILE_AT_START;
	context->once_read = 0;
}

/*
 * _openac() open either the audit_control file or an alternate.
 * A NULL input means use the real audit_control.
 */

au_acinfo_t *
_openac(char *filepath)
{
	au_acinfo_t	*context;

	if (filepath == NULL)
		filepath = AUDITCONTROLFILE;

	context = malloc(sizeof (au_acinfo_t));
	if (context == NULL)
		return (NULL);

	context->file = strdup(filepath);
	if (filepath == NULL) {
		free(context);
		return (NULL);
	}
	context->fp = fopen(filepath, "rF");
	if (context->fp == NULL) {
		free(context->file);
		free(context);
		return (NULL);
	}
	context->file_pointer = FILE_AT_START;
	context->once_read = 0;
	return (context);
}

/* close the audit control file */
void
_endac(au_acinfo_t *context)
{
	if (context == NULL)
		return;

	if (context->fp != NULL)
		(void) fclose(context->fp);

	free(context->file);
	free(context);
}
