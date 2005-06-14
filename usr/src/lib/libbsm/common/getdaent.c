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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <bsm/devices.h>

#define	MAXINT 0x7fffffff;
#ifdef SunOS_CMW
extern char	*calloc();
#endif

static struct _dabuff {
	devalloc_t _NULLDA;
	FILE *_daf;	/* pointer into /etc/security/device_allocate */
	devalloc_t _interpdevalloc;
	char _interpline[BUFSIZ + 1];
	char *_DEVALLOC;
} *__dabuff;

#define	NULLDA (_da->_NULLDA)
#define	daf (_da->_daf)
#define	interpdevalloc (_da->_interpdevalloc)
#define	interpline (_da->_interpline)
#define	DEVALLOC (_da->_DEVALLOC)
static devalloc_t  *interpret();
static int matchname();

/*
 * trim_white(ptr) trims off leading and trailing white space from a NULL
 * terminated string pointed to by "ptr". The leading white space is skipped
 * by moving the pointer forward. The trailing white space is removed by
 * nulling the white space characters.  The pointer is returned to the white
 * string. If the resulting string is null in length then a NULL pointer is
 * returned. If "ptr" is NULL then a NULL pointer is returned.
 */
static char	*
trim_white(ptr)
char	*ptr;
{
	register char	*tptr;
	register int	cnt;
	if (ptr == NULL)
		return (NULL);
	while ((*ptr == ' ') || (*ptr == '\t')) {
		ptr++;
	}
	cnt = strlen(ptr);
	if (cnt != 0) {
		tptr = ptr + cnt - 1;
		while ((*tptr == ' ') || (*tptr == '\t')) {
			*tptr = '\0';
			tptr--;
		}
	}
	if (*ptr == NULL)
		return (NULL);
	return (ptr);
}


/*
 * scan string pointed to by pointer "p"
 * find next colin or end of line. Null it and
 * return pointer to next char.
 */
static char	*
daskip(p)
register char	*p;
{
	while (*p && *p != ';' && *p != '\n')
		++p;
	if (*p == '\n')
		*p = '\0';
	else if (*p != '\0')
		*p++ = '\0';
	return (p);
}


/*
 * scan string pointed to by pointer "p"
 * find next colin or end of line. Null it and
 * return pointer to next char.
 */
static char	*
dadskip(p)
register char	*p;
{
	while (*p && *p != ' ' && *p != '\n')
		++p;
	if (*p != '\0')
		*p++ = '\0';
	return (p);
}


/*
 * _daalloc() allocates common buffers and structures used by the device
 * allocate library routines. Then returns a pointer to a structure.  The
 * returned pointer will be null if there is an error condition.
 */
static struct _dabuff *
_daalloc()
{
	register struct _dabuff *_da = __dabuff;

	if (_da == 0) {
		_da = (struct _dabuff *)
		calloc((size_t)1, sizeof (*__dabuff));
		if (_da == 0)
			return (0);
		DEVALLOC = "/etc/security/device_allocate";
		__dabuff = _da;
	}
	return (__dabuff);
}


/*
 * getdaline(buff,len,stream) reads one device allocate line from "stream" into
 * "buff" on "len" bytes.  Continued lines from "stream" are concatinated
 * into one line in "buff". Comments are removed from "buff". The number of
 * characters in "buff" is returned.  If no characters are read or an err or
 * occured then "0" is returned
 */
static int
getdaline(buff, len, stream)
	char *buff;
	int len;
	FILE *stream;
{
	register struct _dabuff *_da = _daalloc();
	char	*cp;
	char	*ccp;
	int	tmpcnt;
	int	charcnt = 0;
	int	fileerr = 0;
	int	contline;
	if (_da == 0)
		return (0);
	do {
		cp = buff;
		*cp = NULL;
		do {
			if (fgets(cp, len - charcnt, stream) == NULL) {
				fileerr = 1;
				break;
			}
			ccp = strpbrk(cp, "\\\n");
			if (ccp != NULL) {
				if (*ccp == '\\')
					contline = 1;
					else
					contline = 0;
				*ccp = NULL;
			}
			tmpcnt = strlen(cp);
			if (tmpcnt != 0) {
				cp += tmpcnt;
				charcnt += tmpcnt;
			}
		} while ((contline) || (charcnt == 0));
		ccp = strpbrk(buff, "#");
		if (ccp != NULL)
			*ccp = NULL;
		charcnt = strlen(buff);
	} while ((fileerr == 0) && (charcnt == 0));
	if (fileerr)
		return (0);
		else
		return (charcnt);
}

char	*
getdafield(ptr)
char	*ptr;
{
	static char	*tptr;
	if (ptr == NULL)
		ptr = tptr;
	if (ptr == NULL)
		return (NULL);
	tptr = daskip(ptr);
	ptr = trim_white(ptr);
	if (ptr == NULL)
		return (NULL);
	if (*ptr == NULL)
		return (NULL);
	return (ptr);
}

char	*
getdadfield(ptr)
char	*ptr;
{
	static char	*tptr;
	if (ptr != NULL) {
		ptr = trim_white(ptr);
	} else {
		ptr = tptr;
	}
	if (ptr == NULL)
		return (NULL);
	tptr = dadskip(ptr);
	if (ptr == NULL)
		return (NULL);
	if (*ptr == NULL)
		return (NULL);
	return (ptr);
}

/*
 * getdadev(dev) searches from the beginning of the file until a logical
 * device matching "dev" is found and returns a pointer to the particular
 * structure in which it was found.  If an EOF or an error is encountered on
 * reading, these functions return a NULL pointer.
 */
#ifdef NOTDEF
devalloc_t *
getdadev(name)
	register char	*name;
{
	register struct _dabuff *_da = _daalloc();
	devalloc_t *da;
	char	line[BUFSIZ + 1];

	if (_da == 0)
		return (0);
	setdaent();
	if (!daf)
		return ((devalloc_t *)NULL);
	while (getdaline(line, sizeof (line), daf) != 0) {
		if ((da = interpret(line)) == NULL)
			continue;
		if (matchdev(&da, name)) {
			enddaent();
			return (da);
		}
	}
	enddaent();
	return ((devalloc_t *)NULL);
}


#endif /* NOTDEF */

/*
 * getdanam(name) searches from the beginning of the file until a audit-name
 * matching "name" is found and returns a pointer to the particular structure
 * in which it was found.  If an EOF or an error is encountered on reading,
 * these functions return a NULL pointer.
 */
devalloc_t *
getdanam(name)
	register char	*name;
{
	register struct _dabuff *_da = _daalloc();
	devalloc_t *da;
	char line[BUFSIZ + 1];

	if (_da == 0)
		return (0);
	setdaent();
	if (!daf)
		return ((devalloc_t *)NULL);
	while (getdaline(line, (int)sizeof (line), daf) != 0) {
		if ((da = interpret(line)) == NULL)
			continue;
		if (matchname(&da, name)) {
			enddaent();
			return (da);
		}
	}
	enddaent();
	return ((devalloc_t *)NULL);
}


/*
 * setdaent() essentially rewinds the device_allocate file to the begining.
 */

void
setdaent()
{
	register struct _dabuff *_da = _daalloc();

	if (_da == 0)
		return;
	if (daf == NULL) {
		daf = fopen(DEVALLOC, "r");
	} else
		rewind(daf);
}


/*
 * enddaent() may be called to close the device_allocate file when processing
 * is complete.
 */

void
enddaent()
{
	register struct _dabuff *_da = _daalloc();

	if (_da == 0)
		return;
	if (daf != NULL) {
		(void) fclose(daf);
		daf = NULL;
	}
}


/*
 * setdafile(name) changes the default device_allocate file to "name" thus
 * allowing alternate device_allocate files to be used.  Note: it does not
 * close the previous file . If this is desired, enddaent should be called
 * prior to it.
 */
void
setdafile(file)
char	*file;
{
	register struct _dabuff *_da = _daalloc();

	if (_da == 0)
		return;
	if (daf != NULL) {
		(void) fclose(daf);
		daf = NULL;
	}
	DEVALLOC = file;
}


/*
 * getdatype(tp) When first called, returns a pointer to the
 * first devalloc_t structure in the file with device-type matching
 * "tp"; thereafter, it returns a pointer to the next devalloc_t
 * structure in the file with device-type matching "tp".
 * Thus successive calls can be used to search the
 * entire file for entries having device-type matching "tp".
 * A null pointer is returned on error.
 */
devalloc_t *
getdatype(tp)
	char	*tp;
{
	register struct _dabuff *_da = _daalloc();
	char line1[BUFSIZ + 1];
	devalloc_t *da;

	if (_da == 0)
		return (0);
	if (daf == NULL && (daf = fopen(DEVALLOC, "r")) == NULL) {
		return (NULL);
	}
	do {
		if (getdaline(line1, (int)sizeof (line1), daf) == 0)
			return (NULL);

		if ((da = interpret(line1)) == NULL)
			return (NULL);
	} while (strcmp(tp, da->da_devtype) != 0);
	return (da);
}


/*
 * getdaent() When first called, returns a pointer to the first devalloc_t
 * structure in the file; thereafter, it returns a pointer to the next
 * devalloc_t structure in the file. Thus successive calls can be used to
 * search the entire file.  A null pointer is returned on error.
 */
devalloc_t *
getdaent()
{
	register struct _dabuff *_da = _daalloc();
	char line1[BUFSIZ + 1];
	devalloc_t *da;

	if (_da == 0)
		return (0);
	if (daf == NULL && (daf = fopen(DEVALLOC, "r")) == NULL) {
		return (NULL);
	}
	if (getdaline(line1, (int)sizeof (line1), daf) == 0)
		return (NULL);

	if ((da = interpret(line1)) == NULL)
		return (NULL);
	return (da);
}


/*
 * matchdev(dap,dev) The dev_list in the structure pointed to by "dap" is
 * searched for string "dev".  If a match occures then a "1" is returned
 * otherwise a "0" is returned.
 */
#ifdef NOTDEF
static
matchdev(dap, dev)
	devalloc_t **dap;
	char	*dev;
{
	register struct _dabuff *_da = _daalloc();
	devalloc_t *da = *dap;
	char tmpdev[BUFSIZ + 1];
	int	charcnt;
	int	tmpcnt;
	char	*cp;
	char	*tcp;
	char	*last;

	charcnt = strlen(dev);
	if (_da == 0)
		return (0);
	if (da->da_devlist == NULL)
		return (0);
	(void) strcpy(tmpdev, da->da_devlist);
	tcp = tmpdev;
	while ((cp = strtok_r(tcp, " ", &last)) != NULL) {
		tcp = NULL;
		tmpcnt = strlen(cp);
		if (tmpcnt != charcnt)
			continue;
		if (strcmp(cp, dev) == 0)
			return (1);
	}
	return (0);
}

#endif /* NOTDEF */
/*
 * matchname(dap,name) The audit-name in the structure pointed to by "dap" is
 * searched for string "name".  If a match occures then a "1" is returned
 * otherwise a "0" is returned.
 */
static int
matchname(dap, name)
	devalloc_t **dap;
	char *name;
{
	register struct _dabuff *_da = _daalloc();
	devalloc_t *da = *dap;

	if (_da == 0)
		return (0);
	if (da->da_devname == NULL)
		return (0);
	if (strlen(da->da_devname) != strlen(name))
		return (0);
	if (strcmp(da->da_devname, name) == 0)
		return (1);
	return (0);
}


/*
 * interpret(val) string "val" is parsed and the pointers in a devalloc_t
 * structure are initialized to point to fields in "val". A pointer to this
 * structure is returned.
 */
static devalloc_t  *
interpret(val)
char	*val;
{
	register struct _dabuff *_da = _daalloc();

	if (_da == 0)
		return (0);
	(void) strcpy(interpline, val);
	interpdevalloc.da_devname = getdafield(interpline);
	interpdevalloc.da_devtype = getdafield((char *)NULL);
	interpdevalloc.da_devmin = getdafield((char *)NULL);
	interpdevalloc.da_devmax = getdafield((char *)NULL);
	interpdevalloc.da_devauth = getdafield((char *)NULL);
	interpdevalloc.da_devexec = getdafield((char *)NULL);

	return (&interpdevalloc);
}
