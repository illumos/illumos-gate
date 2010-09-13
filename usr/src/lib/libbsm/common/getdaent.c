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

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <tsol/label.h>
#include <bsm/devices.h>
#include <bsm/devalloc.h>

extern char *_strdup_null(char *);

static struct _dabuff {
	FILE		*_daf;	/* pointer into /etc/security/device_allocate */
	devalloc_t	_interpdevalloc;
	char		_interpdaline[DA_BUFSIZE + 1];
	char		 *_DEVALLOC;
} *__dabuff;

#define	daf	(_da->_daf)
#define	interpdevalloc	(_da->_interpdevalloc)
#define	interpdaline	(_da->_interpdaline)
#define	DEVALLOC_FILE	(_da->_DEVALLOC)
static devalloc_t	*da_interpret(char *);

int da_matchname(devalloc_t *, char *);
int da_matchtype(devalloc_t *, char *);

static int system_labeled = 0;

/*
 * trim_white -
 *	trims off leading and trailing white space from input string.
 * 	The leading white space is skipped by moving the pointer forward.
 * 	The trailing white space is removed by nulling the white space
 *	characters.
 *	returns pointer to non-white string, else returns NULL if input string
 *	is null or if the resulting string has zero length.
 */
char *
trim_white(char *ptr)
{
	char	*tptr;

	if (ptr == NULL)
		return (NULL);
	while (isspace(*ptr))
		ptr++;
	tptr = ptr + strlen(ptr);
	while (tptr != ptr && isspace(tptr[-1]))
		--tptr;
	*tptr = '\0';
	if (*ptr == '\0')
		return (NULL);

	return (ptr);
}

/*
 * pack_white -
 *	trims off multiple occurrences of white space from input string.
 * 	returns the number of spaces retained
 */
int
pack_white(char *ptr)
{
	int	cnt = 0;
	char	*tptr, ch;

	if (ptr == NULL)
		return (0);
	tptr = ptr;
	while (isspace(*tptr))
		tptr++;
	for (;;) {
		while ((ch = *tptr) != '\0' && !isspace(ch)) {
			*ptr++ = ch;
			tptr++;
		}
		while (isspace(*tptr))
			tptr++;
		if (*tptr == '\0')
			break;
		*ptr++ = ' ';
		cnt++;
	}
	*ptr = '\0';

	return (cnt);
}

/*
 * getdadmline -
 *	reads one device_alloc/device_maps line from stream into buff of len
 *	bytes. Continued lines from stream are concatenated into one line in
 *	buff. Comments are removed from buff.
 *	returns the number of characters in buff, else returns 0 if no
 * 	characters are read or an error occurred.
 */
int
getdadmline(char *buff, int len, FILE *stream)
{
	int 	tmpcnt;
	int 	charcnt = 0;
	int 	fileerr = 0;
	int 	contline = 0;
	char 	*cp;
	char 	*ccp;

	do {
		cp = buff;
		*cp = NULL;
		do {
			contline = 0;
			if (fgets(cp, len - charcnt, stream) == NULL) {
				fileerr = 1;
				break;
			}
			ccp = strchr(cp, '\n');
			if (ccp != NULL) {
				if (ccp != cp && ccp[-1] == '\\') {
					ccp--;
					contline = 1;
				}
				else
					contline = 0;
				*ccp = NULL;
			}
			tmpcnt = strlen(cp);
			cp += tmpcnt;
			charcnt += tmpcnt;
		} while ((contline) || (charcnt == 0));
		ccp = strpbrk(buff, "#");
		if (ccp != NULL)
			*ccp = NULL;
		charcnt = strlen(buff);
	} while ((fileerr == 0) && (charcnt == 0));

	if (fileerr && !charcnt)
		return (0);
	else
		return (charcnt);
}

/*
 * _daalloc -
 *	allocates common buffers and structures.
 * 	returns pointer to the new structure, else returns NULL on error.
 */
static struct _dabuff *
_daalloc(void)
{
	struct _dabuff	*_da = __dabuff;

	if (_da == NULL) {
		_da = (struct _dabuff *)calloc((unsigned)1,
		    (unsigned)sizeof (*__dabuff));
		if (_da == NULL)
			return (NULL);
		DEVALLOC_FILE = "/etc/security/device_allocate";
		daf = NULL;
		__dabuff = _da;
		system_labeled = is_system_labeled();
	}

	return (__dabuff);
}

/*
 * getdadmfield -
 *	gets individual fields separated by skip in ptr.
 */
char *
getdadmfield(char *ptr, char *skip)
{
	static char	*tptr = NULL;
	char		*pend;

	/* check for a continuing search */
	if (ptr == NULL)
		ptr = tptr;
	/* check for source end */
	if (ptr == NULL || *ptr == '\0')
		return (NULL);
	/* find terminator */
	pend = strpbrk(ptr, skip);
	/* terminate and set continuation pointer */
	if (pend != NULL) {
		*pend++ = '\0';
		tptr = pend;
	} else
		tptr = NULL;
	/*
	 * trim off any surrounding white space, return what's left
	 */

	return (trim_white(ptr));
}

/*
 * setdaent -
 *	rewinds the device_allocate file to the begining.
 */

void
setdaent(void)
{
	struct _dabuff	*_da = _daalloc();

	if (_da == NULL)
		return;
	if (daf == NULL)
		daf = fopen(DEVALLOC_FILE, "rF");
	else
		rewind(daf);
}

/*
 * enddaent -
 *	closes device_allocate file.
 */

void
enddaent(void)
{
	struct _dabuff	*_da = _daalloc();

	if (_da == NULL)
		return;
	if (daf != NULL) {
		(void) fclose(daf);
		daf = NULL;
	}
}

/*
 * setdafile -
 *	changes the default device_allocate file to the one specified.
 * 	It does not close the previous file. If this is desired, enddaent
 *	should be called prior to setdafile.
 */
void
setdafile(char *file)
{
	struct _dabuff	*_da = _daalloc();

	if (_da == NULL)
		return;
	if (daf != NULL) {
		(void) fclose(daf);
		daf = NULL;
	}
	DEVALLOC_FILE = file;
}

void
freedaent(devalloc_t *dap)
{
	if (dap == NULL)
		return;
	_kva_free(dap->da_devopts);
	dap->da_devopts = NULL;
}

/*
 * getdaon -
 *	checks if device_allocate has string DEVICE_ALLOCATION=ON or
 *	DEVICE_ALLOCATION=OFF string in it.
 *	returns 1 if the string is DEVICE_ALLOCATION=ON, 0 if it is
 *	DEVICE_ALLOCATION=OFF, -1 if neither string present.
 */
int
getdaon()
{
	int		is_on = -1;
	char		line1[DA_BUFSIZE + 1];
	struct _dabuff *_da = _daalloc();

	setdaent();
	if ((_da == NULL) || (daf == NULL)) {
		enddaent();
		return (is_on);
	}
	while (getdadmline(line1, (int)sizeof (line1), daf) != 0) {
		if (strncmp(line1, DA_ON_STR, (strlen(DA_ON_STR) - 1)) == 0) {
			is_on = 1;
			break;
		} else if (strncmp(line1, DA_OFF_STR,
		    (strlen(DA_OFF_STR) - 1)) == 0) {
			is_on = 0;
			break;
		}
	}
	enddaent();

	return (is_on);
}

/*
 * getdaent -
 *	When first called, returns a pointer to the first devalloc_t
 * 	structure in device_allocate; thereafter, it returns a pointer to the
 *	next devalloc_t structure in the file. Thus, successive calls can be
 *	used to search the entire file.
 *	call to getdaent should be bracketed by setdaent and enddaent.
 *	returns NULL on error.
 */
devalloc_t *
getdaent(void)
{
	char		line1[DA_BUFSIZE + 1];
	devalloc_t	*da;
	struct _dabuff	*_da = _daalloc();

	if ((_da == 0) || (daf == NULL))
		return (NULL);

	while (getdadmline(line1, (int)sizeof (line1), daf) != 0) {
		if ((strncmp(line1, DA_ON_STR, (strlen(DA_ON_STR) - 1)) == 0) ||
		    (strncmp(line1, DA_OFF_STR, (strlen(DA_OFF_STR) - 1)) == 0))
			continue;
		if ((da = da_interpret(line1)) == NULL)
			continue;
		return (da);
	}

	return (NULL);
}

/*
 * getdanam
 * 	searches from the beginning of device_allocate for the device specified
 * 	by its name.
 *	call to getdanam should be bracketed by setdaent and enddaent.
 * 	returns pointer to devalloc_t for the device if it is found, else
 *	returns NULL if device not found or in case of error.
 */
devalloc_t *
getdanam(char *name)
{
	char		line[DA_BUFSIZE + 1];
	devalloc_t	*da;
	struct _dabuff	*_da = _daalloc();

	if ((name == NULL) || (_da == 0) || (daf == NULL))
		return (NULL);

	while (getdadmline(line, (int)sizeof (line), daf) != 0) {
		if (strstr(line, name) == NULL)
			continue;
		if ((da = da_interpret(line)) == NULL)
			continue;
		if (da_matchname(da, name)) {
			enddaent();
			return (da);
		}
		freedaent(da);
	}

	return (NULL);
}

/*
 * getdatype -
 * 	searches from the beginning of device_allocate for the device specified
 * 	by its type.
 *	call to getdatype should be bracketed by setdaent and enddaent.
 * 	returns pointer to devalloc_t for the device if it is found, else
 *	returns NULL if device not found or in case of error.
 */
devalloc_t *
getdatype(char *type)
{
	char		line1[DA_BUFSIZE + 1];
	devalloc_t	*da;
	struct _dabuff	*_da = _daalloc();

	if ((type == NULL) || (_da == NULL) || (daf == NULL))
		return (NULL);

	while (getdadmline(line1, (int)sizeof (line1), daf) != 0) {
		if (strstr(line1, type) == NULL)
			continue;
		if ((da = da_interpret(line1)) == NULL)
			continue;
		if (da_matchtype(da, type))
			return (da);
		freedaent(da);
	}

	return (NULL);
}

/*
 * da_matchname -
 *	checks if the specified devalloc_t is for the device specified.
 * 	returns 1 if it is, else returns 0.
 */
int
da_matchname(devalloc_t *dap, char *name)
{
	if (dap->da_devname == NULL)
		return (0);

	return ((strcmp(dap->da_devname, name) == 0));
}

/*
 * da_matchtype -
 *	checks if the specified devalloc_t is for the device type specified.
 *	returns 1 if match found, else, returns 0.
 */
int
da_matchtype(devalloc_t *da, char *type)
{
	if (da->da_devtype == NULL)
		return (0);

	return ((strcmp(da->da_devtype, type) == 0));
}

/*
 * da_match -
 * 	calls da_matchname or da_matchdev as appropriate.
 */
int
da_match(devalloc_t *dap, da_args *dargs)
{
	if (dargs->devinfo->devname)
		return (da_matchname(dap, dargs->devinfo->devname));
	else if (dargs->devinfo->devtype)
		return (da_matchtype(dap, dargs->devinfo->devtype));

	return (0);
}

/*
 * da_interpret -
 *	parses val and initializes pointers in devalloc_t.
 * 	returns pointer to parsed devalloc_t entry, else returns NULL on error.
 */
static devalloc_t  *
da_interpret(char *val)
{
	struct _dabuff	*_da = _daalloc();
	char	*opts;
	int	i;
	kva_t	*kvap;
	kv_t	*kvp;

	if (_da == NULL)
		return (NULL);

	(void) strcpy(interpdaline, val);
	interpdevalloc.da_devname = getdadmfield(interpdaline, KV_DELIMITER);
	interpdevalloc.da_devtype = getdadmfield(NULL, KV_DELIMITER);
	opts = getdadmfield(NULL, KV_DELIMITER);
	(void) getdadmfield(NULL, KV_DELIMITER);	/* reserved field */
	interpdevalloc.da_devauth = getdadmfield(NULL, KV_DELIMITER);
	interpdevalloc.da_devexec = getdadmfield(NULL, KV_DELIMITER);
	interpdevalloc.da_devopts = NULL;
	if (interpdevalloc.da_devname == NULL ||
	    interpdevalloc.da_devtype == NULL)
		return (NULL);
	if ((opts != NULL) &&
	    (strncmp(opts, DA_RESERVED, strlen(DA_RESERVED)) != 0)) {
		interpdevalloc.da_devopts =
		    _str2kva(opts, KV_ASSIGN, KV_TOKEN_DELIMIT);
	}
	/* remove any extraneous whitespace in the options */
	if ((kvap = interpdevalloc.da_devopts) != NULL) {
		for (i = 0, kvp = kvap->data; i < kvap->length; i++, kvp++) {
			(void) pack_white(kvp->key);
			(void) pack_white(kvp->value);
		}
	}

	if (system_labeled) {
		/* if label range is not defined, use the default range. */
		int		i = 0, nlen = 0;
		char		*minstr = NULL, *maxstr = NULL;
		kva_t		*nkvap = NULL;
		kv_t		*ndata = NULL, *odata = NULL;

		if (kvap == NULL) {
			nlen = 2;	/* minlabel, maxlabel */
		} else {
			nlen += kvap->length;
			if ((minstr = kva_match(kvap, DAOPT_MINLABEL)) == NULL)
				nlen++;
			if ((maxstr = kva_match(kvap, DAOPT_MAXLABEL)) == NULL)
				nlen++;
		}
		if ((minstr != NULL) && (maxstr != NULL))
			/*
			 * label range provided; we don't need to construct
			 * default range.
			 */
			goto out;
		nkvap = _new_kva(nlen);
		ndata = nkvap->data;
		if (kvap != NULL) {
			for (i = 0; i < kvap->length; i++) {
				odata = kvap->data;
				ndata[i].key = _strdup_null(odata[i].key);
				ndata[i].value = _strdup_null(odata[i].value);
				nkvap->length++;
			}
		}
		if (minstr == NULL) {
			ndata[i].key = strdup(DAOPT_MINLABEL);
			ndata[i].value = strdup(DA_DEFAULT_MIN);
			nkvap->length++;
			i++;
		}
		if (maxstr == NULL) {
			ndata[i].key = strdup(DAOPT_MAXLABEL);
			ndata[i].value = strdup(DA_DEFAULT_MAX);
			nkvap->length++;
		}
		interpdevalloc.da_devopts = nkvap;
	}

out:
	return (&interpdevalloc);
}
