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
#include <sys/errno.h>

#define	MAXINT 0x7fffffff;

static struct _dmapbuff {
	devmap_t _NULLDM;
	FILE *_dmapf;	/* pointer into /etc/security/device_maps */
	devmap_t _interpdevmap;
	char _interpline[BUFSIZ + 1];
	char *_DEVMAP;
} *__dmapbuff;

#define	NULLDM (_dmap->_NULLDM)
#define	dmapf (_dmap->_dmapf)
#define	interpdevmap (_dmap->_interpdevmap)
#define	interpline (_dmap->_interpline)
#define	DEVMAP (_dmap->_DEVMAP)
static devmap_t  *interpret();
static int matchdev();
static int matchname();
/*
 * trim_white(ptr) trims off leading and trailing white space from a NULL
 * terminated string pointed to by "ptr". The leading white space is skipped
 * by moving the pointer forward. The trailing white space is removed by
 * nulling the white space characters.  The pointer is returned to the white
 * string. If the resulting string is null in length then a NULL pointer is
 * returned. If "ptr" is NULL then a NULL pointer is returned.
 */
static char *
trim_white(char *ptr)
{
	register char  *tptr;
	register int    cnt;
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
static char *
dmapskip(register char *p)
{
	while (*p && *p != ':' && *p != '\n')
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
static char *
dmapdskip(register char *p)
{
	while (*p && *p != ' ' && *p != '\n')
		++p;
	if (*p != '\0')
		*p++ = '\0';
	return (p);
}

/*
 * _dmapalloc() allocates common buffers and structures used by the device
 * maps library routines. Then returns a pointer to a structure.  The
 * returned pointer will be null if there is an error condition.
 */
static struct _dmapbuff *
_dmapalloc(void)
{
	register struct _dmapbuff *_dmap = __dmapbuff;

	if (_dmap == 0) {
		_dmap = (struct _dmapbuff *)
			calloc((unsigned)1, (unsigned)sizeof (*__dmapbuff));
		if (_dmap == 0)
			return (0);
		DEVMAP = "/etc/security/device_maps";
		__dmapbuff = _dmap;
	}
	return (__dmapbuff);
}
/*
 * getdmapline(buff,len,stream) reads one device maps line from "stream" into
 * "buff" on "len" bytes.  Continued lines from "stream" are concatinated
 * into one line in "buff". Comments are removed from "buff". The number of
 * characters in "buff" is returned.  If no characters are read or an error
 * occured then "0" is returned
 */
static int
getdmapline(char *buff, int len, FILE *stream)
{
	register struct _dmapbuff *_dmap = _dmapalloc();
	char *cp;
	char *ccp;
	size_t tmpcnt;
	int charcnt = 0;
	int fileerr = 0;
	int contline;
	if (_dmap == 0)
		return (0);
	do {
		cp = buff;
		*cp = NULL;
		do {
			if ((len - charcnt <= 1) ||
			    (fgets(cp, len - charcnt, stream) == NULL)) {
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
	if (fileerr && !charcnt)
		return (0);
	else
		return (charcnt);
}
char
*getdmapfield(char *ptr)
{
	static	char	*tptr;
	if (ptr == NULL)
		ptr = tptr;
	if (ptr == NULL)
		return (NULL);
	tptr = dmapskip(ptr);
	ptr = trim_white(ptr);
	if (ptr == NULL)
		return (NULL);
	if (*ptr == NULL)
		return (NULL);
	return (ptr);
}
char
*getdmapdfield(char *ptr)
{
	static	char	*tptr;
	if (ptr != NULL) {
		ptr = trim_white(ptr);
	} else {
		ptr = tptr;
	}
	if (ptr == NULL)
		return (NULL);
	tptr = dmapdskip(ptr);
	if (ptr == NULL)
		return (NULL);
	if (*ptr == NULL)
		return (NULL);
	return (ptr);
}
/*
 * getdmapdev(dev) searches from the beginning of the file until a logical
 * device matching "dev" is found and returns a pointer to the particular
 * structure in which it was found.  If an EOF or an error is encountered on
 * reading, these functions return a NULL pointer.
 */
devmap_t *
getdmapdev(register char  *name)
{
	register struct _dmapbuff *_dmap = _dmapalloc();
	devmap_t *dmap;
	char line[BUFSIZ + 1];

	if (_dmap == 0)
		return (0);
	setdmapent();
	if (!dmapf)
		return (NULL);
	while (getdmapline(line, (int)sizeof (line), dmapf) != 0) {
		if ((dmap = interpret(line)) == NULL)
			continue;
		if (matchdev(&dmap, name)) {
			enddmapent();
			return (dmap);
		}
	}
	enddmapent();
	return (NULL);
}
/*
 * getdmapnam(name) searches from the beginning of the file until a audit-name
 * matching "name" is found and returns a pointer to the particular structure
 * in which it was found.  If an EOF or an error is encountered on reading,
 * these functions return a NULL pointer.
 */
devmap_t *
getdmapnam(register char  *name)
{
	register struct _dmapbuff *_dmap = _dmapalloc();
	devmap_t *dmap;
	char line[BUFSIZ + 1];

	if (_dmap == 0)
		return (0);
	setdmapent();
	if (!dmapf)
		return (NULL);
	while (getdmapline(line, (int)sizeof (line), dmapf) != 0) {
		if ((dmap = interpret(line)) == NULL)
			continue;
		if (matchname(&dmap, name)) {
			enddmapent();
			return (dmap);
		}
	}
	enddmapent();
	return (NULL);
}

/*
 * setdmapent() essentially rewinds the device_maps file to the begining.
 */

void
setdmapent(void)
{
	register struct _dmapbuff *_dmap = _dmapalloc();


	if (_dmap == 0)
		return;

	if (dmapf == NULL) {
		dmapf = fopen(DEVMAP, "r");
	} else
		rewind(dmapf);
}


/*
 * enddmapent() may be called to close the device_maps file when processing
 * is complete.
 */

void
enddmapent(void)
{
	register struct _dmapbuff *_dmap = _dmapalloc();

	if (_dmap == 0)
		return;
	if (dmapf != NULL) {
		(void) fclose(dmapf);
		dmapf = NULL;
	}
}


/*
 * setdmapfile(name) changes the default device_maps file to "name" thus
 * allowing alternate device_maps files to be used.  Note: it does not
 * close the previous file . If this is desired, enddmapent should be called
 * prior to it.
 */
void
setdmapfile(char *file)
{
	register struct _dmapbuff *_dmap = _dmapalloc();

	if (_dmap == 0)
		return;
	if (dmapf != NULL) {
		(void) fclose(dmapf);
		dmapf = NULL;
	}
	DEVMAP = file;
}
/*
 * getdmaptype(tp) When first called, returns a pointer to the
 * first devmap_t structure in the file with device-type matching
 * "tp"; thereafter, it returns a pointer to the next devmap_t
 * structure in the file with device-type matching "tp".
 * Thus successive calls can be used to search the
 * entire file for entries having device-type matching "tp".
 * A null pointer is returned on error.
 */
devmap_t *
getdmaptype(char *tp)
{
	register struct _dmapbuff *_dmap = _dmapalloc();
	char line1[BUFSIZ + 1];
	devmap_t *dmap;

	if (_dmap == 0)
		return (0);
	if (dmapf == NULL && (dmapf = fopen(DEVMAP, "r")) == NULL) {
		return (NULL);
	}
	do {
		if (getdmapline(line1, (int)sizeof (line1), dmapf) == 0)
			return (NULL);

		if ((dmap = interpret(line1)) == NULL)
			return (NULL);
	} while (strcmp(tp, dmap->dmap_devtype) != 0);
	return (dmap);
}

/*
 * getdmapent() When first called, returns a pointer to the first devmap_t
 * structure in the file; thereafter, it returns a pointer to the next devmap_t
 * structure in the file. Thus successive calls can be used to search the
 * entire file.  A null pointer is returned on error.
 */
devmap_t *
getdmapent(void)
{
	register struct _dmapbuff *_dmap = _dmapalloc();
	char line1[BUFSIZ + 1];
	devmap_t *dmap;

	if (_dmap == 0)
		return (0);
	if (dmapf == NULL && (dmapf = fopen(DEVMAP, "r")) == NULL) {
		return (NULL);
	}
	if (getdmapline(line1, (int)sizeof (line1), dmapf) == 0)
		return (NULL);

	if ((dmap = interpret(line1)) == NULL)
		return (NULL);
	return (dmap);
}
/*
 * matchdev(dmapp,dev) The dev_list in the structure pointed to by "dmapp" is
 * searched for string "dev".  If a match occures then a "1" is returned
 * otherwise a "0" is returned.
 */
static int
matchdev(devmap_t **dmapp, char *dev)
{
	register struct _dmapbuff *_dmap = _dmapalloc();
	devmap_t *dmap = *dmapp;
	char tmpdev[BUFSIZ + 1];
	int charcnt;
	int tmpcnt;
	char *cp;
	char *tcp;
	char *last;
	charcnt = strlen(dev);
	if (_dmap == 0)
		return (0);
	if (dmap->dmap_devlist == NULL)
		return (0);
	(void) strcpy(tmpdev, dmap->dmap_devlist);
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
/*
 * matchname(dmapp,name) The audit-name in the structure pointed to by "dmapp"
 * is searched for string "name".  If a match occures then a "1" is returned
 * otherwise a "0" is returned.
 */
static int
matchname(devmap_t **dmapp, char *name)
{
	register struct _dmapbuff *_dmap = _dmapalloc();
	devmap_t *dmap = *dmapp;

	if (_dmap == 0)
		return (0);
	if (dmap->dmap_devname == NULL)
		return (0);
	if (strlen(dmap->dmap_devname) != strlen(name))
		return (0);
	if (strcmp(dmap->dmap_devname, name) == 0)
		return (1);
	return (0);
}
/*
 * interpret(val) string "val" is parsed and the pointers in a devmap_t
 * structure are initialized to point to fields in "val". A pointer to this
 * structure is returned.
 */
static devmap_t  *
interpret(char *val)
{
	register struct _dmapbuff *_dmap = _dmapalloc();

	if (_dmap == 0)
		return (0);
	(void) strcpy(interpline, val);
	interpdevmap.dmap_devname = getdmapfield(interpline);
	interpdevmap.dmap_devtype = getdmapfield((char *)NULL);
	interpdevmap.dmap_devlist = getdmapfield((char *)NULL);

	return (&interpdevmap);
}
