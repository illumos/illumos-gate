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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <stdlib.h>
#include <bsm/devices.h>
#include <bsm/devalloc.h>

char *strtok_r(char *, const char *, char **);

/* externs from getdaent.c */
extern char *trim_white(char *);
extern int pack_white(char *);
extern char *getdadmfield(char *, char *);
extern int getdadmline(char *, int, FILE *);

extern char *_strdup_null(char *);

static struct _dadefbuff {
	FILE		*_dadeff;
			/* pointer into /etc/security/tsol/devalloc_defaults */
	da_defs_t	_interpdadefs;
	char		_interpdadefline[DA_BUFSIZE + 1];
	char		 *_DADEFS;
} *__dadefbuff;

#define	dadeff		(_df->_dadeff)
#define	interpdadefs	(_df->_interpdadefs)
#define	interpdadefline	(_df->_interpdadefline)
#define	DADEFS_FILE	(_df->_DADEFS)

static da_defs_t	*dadef_interpret(char *);
int dadef_matchtype(da_defs_t *, char *);

/*
 * _dadefalloc -
 *	allocates common buffers and structures.
 * 	returns pointer to the new structure, else returns NULL on error.
 */
static struct _dadefbuff *
_dadefalloc(void)
{
	struct _dadefbuff *_df = __dadefbuff;

	if (_df == NULL) {
		_df = (struct _dadefbuff *)calloc((unsigned)1,
		    (unsigned)sizeof (*__dadefbuff));
		if (_df == NULL)
			return (NULL);
		DADEFS_FILE = "/etc/security/tsol/devalloc_defaults";
		__dadefbuff = _df;
	}

	return (__dadefbuff);
}

/*
 * setdadefent -
 *	rewinds devalloc_defaults file to the begining.
 */

void
setdadefent(void)
{
	struct _dadefbuff *_df = _dadefalloc();

	if (_df == NULL)
		return;
	if (dadeff == NULL)
		dadeff = fopen(DADEFS_FILE, "rF");
	else
		rewind(dadeff);
}

/*
 * enddadefent -
 *	closes devalloc_defaults file.
 */

void
enddadefent(void)
{
	struct _dadefbuff *_df = _dadefalloc();

	if (_df == NULL)
		return;
	if (dadeff != NULL) {
		(void) fclose(dadeff);
		dadeff = NULL;
	}
}

void
freedadefent(da_defs_t *da_def)
{
	if (da_def == NULL)
		return;
	_kva_free(da_def->devopts);
	da_def->devopts = NULL;
}

/*
 * getdadefent -
 *	When first called, returns a pointer to the first da_defs_t
 * 	structure in devalloc_defaults; thereafter, it returns a pointer to the
 *	next da_defs_t structure in the file. Thus, successive calls can be
 *	used to search the entire file.
 *	call to getdadefent should be bracketed by setdadefent and enddadefent.
 *	returns NULL on error.
 */
da_defs_t *
getdadefent(void)
{
	char			line1[DA_BUFSIZE + 1];
	da_defs_t		*da_def;
	struct _dadefbuff	*_df = _dadefalloc();

	if ((_df == 0) || (dadeff == NULL))
		return (NULL);

	while (getdadmline(line1, (int)sizeof (line1), dadeff) != 0) {
		if ((da_def = dadef_interpret(line1)) == NULL)
			continue;
		return (da_def);
	}

	return (NULL);
}

/*
 * getdadeftype -
 * 	searches from the beginning of devalloc_defaults for the device
 *	specified by its type.
 *	call to getdadeftype should be bracketed by setdadefent and enddadefent.
 * 	returns pointer to da_defs_t for the device if it is found, else
 *	returns NULL if device not found or in case of error.
 */
da_defs_t *
getdadeftype(char *type)
{
	char			line1[DA_BUFSIZE + 1];
	da_defs_t		*da_def;
	struct _dadefbuff	*_df = _dadefalloc();

	if ((type == NULL) || (_df == NULL) || (dadeff == NULL))
		return (NULL);

	while (getdadmline(line1, (int)sizeof (line1), dadeff) != 0) {
		if (strstr(line1, type) == NULL)
			continue;
		if ((da_def = dadef_interpret(line1)) == NULL)
			continue;
		if (dadef_matchtype(da_def, type))
			return (da_def);
		freedadefent(da_def);
	}

	return (NULL);
}

/*
 * dadef_matchtype -
 *	checks if the specified da_defs_t is for the device type specified.
 *	returns 1 if match found, else, returns 0.
 */
int
dadef_matchtype(da_defs_t *da_def, char *type)
{
	if (da_def->devtype == NULL)
		return (0);

	return ((strcmp(da_def->devtype, type) == 0));
}

/*
 * dadef_interpret -
 *	parses val and initializes pointers in da_defs_t.
 * 	returns pointer to parsed da_defs_t entry, else returns NULL on error.
 */
static da_defs_t  *
dadef_interpret(char *val)
{
	struct _dadefbuff	*_df = _dadefalloc();
	int			i;
	char			*opts;
	kva_t			*kvap;
	kv_t			*kvp;

	if (_df == NULL)
		return (NULL);

	(void) strcpy(interpdadefline, val);
	interpdadefs.devtype = getdadmfield(interpdadefline, KV_TOKEN_DELIMIT);
	opts = getdadmfield(NULL, KV_TOKEN_DELIMIT);
	interpdadefs.devopts = NULL;
	if (interpdadefs.devtype == NULL)
		return (NULL);
	if (opts != NULL)
		interpdadefs.devopts =
		    _str2kva(opts, KV_ASSIGN, KV_DELIMITER);
	/* remove any extraneous whitespace in the options */
	if ((kvap = interpdadefs.devopts) != NULL) {
		for (i = 0, kvp = kvap->data; i < kvap->length; i++, kvp++) {
			(void) pack_white(kvp->key);
			(void) pack_white(kvp->value);
		}
	}

	return (&interpdadefs);
}
