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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <devmgmt.h>
#include "libadm.h"
#include <stdlib.h>

#define	LABELSIZ	6
#define	BELL	"\007"

#define	FORMFS_MSG ",\\n\\ \\ or [f] to format %s and place a filesystem on it"
#define	FORMAT_MSG ",\\n\\ \\ or [f] to format the %s"
#define	MAKEFS_MSG ",\\n\\ \\ or [m] to place a filesystem on %s"
#define	EJECT_MSG  ",\\n\\ \\ or [e] to eject the %s"
#define	UNLOAD_MSG ",\\n\\ \\ or [u] to unload/offline the %s"
#define	WLABEL_MSG ",\\n\\ \\ or [w] to write a new label on the %s"
#define	OLABEL_MSG ",\\n\\ \\ or [o] to use the current label anyway"
#define	QUIT_MSG   ",\\n\\ \\ or [q] to quit"

#define	ERR_ACCESS	"\n%s (%s) cannot be accessed.\n"
#define	ERR_FMT		"\nAttempt to format %s failed.\n"
#define	ERR_MKFS	"\nAttempt to place filesystem on %s failed.\n"
#define	ERR_REMOVE	"\nExecution of \"removecmd\"[%s] failed.\n"

static void	elabel(void);
static void	doformat(char *, char *, char *);
static void	labelerr(char *, char *);
static int	ckilabel(char *, int);
static int	insert(char *, char *, int, char *);

static char	*cdevice; 	/* character device name */
static char	*pname; 	/* device presentation name */
static char	*volume; 	/* volume name */
static char	origfsname[LABELSIZ+1];
static char	origvolname[LABELSIZ+1];

/*
 * Return:
 *	0 - okay, label matches
 *	1 - device not accessable
 *	2 - unknown device (devattr failed)
 *	3 - user selected quit
 *	4 - label does not match
 */

/*
 * macros from labelit to behave correctly for tape
 * is a kludge, should use devmgmt
 */
#ifdef RT
#define	IFTAPE(s) ((strncmp(s, "/dev/mt", 7) == 0) || \
(strncmp(s, "mt", 2) == 0))
#define	TAPENAMES "'/dev/mt'"
#else
#define	IFTAPE(s) ((strncmp(s, "/dev/rmt", 8) == 0) || \
(strncmp(s, "rmt", 3) == 0) || (strncmp(s, "/dev/rtp", 8) == 0) || \
(strncmp(s, "rtp", 3) == 0))
#define	TAPENAMES "'/dev/rmt' or '/dev/rtp'"
#endif

int
getvol(char *device, char *label, int options, char *prompt)
{
	return (_getvol(device, label, options, prompt, NULL));
}

int
_getvol(char *device, char *label, int options, char *prompt, char *norewind)
{
	FILE	*tmp;
	char	*advice, *pt;
	int	n, override;

	cdevice = devattr(device, "cdevice");
	if ((cdevice == NULL) || !cdevice[0]) {
		cdevice = devattr(device, "pathname");
		if ((cdevice == NULL) || !cdevice)
			return (2);	/* bad device */
	}

	pname = devattr(device, "desc");
	if (pname == NULL) {
		pname = devattr(device, "alias");
		if (!pname)
			pname = device;
	}

	volume = devattr(device, "volume");

	if (label) {
		(void) strncpy(origfsname, label, LABELSIZ);
		origfsname[LABELSIZ] = '\0';
		if (pt = strchr(origfsname, ',')) {
			*pt = '\0';
		}
		if (pt = strchr(label, ',')) {
			(void) strncpy(origvolname, pt+1, LABELSIZ);
			origvolname[LABELSIZ] = '\0';
		} else
			origvolname[0] = '\0';
	}

	override = 0;
	for (;;) {
		if (!(options & DM_BATCH) && volume) {
			n = insert(device, label, options, prompt);
			if (n < 0)
				override++;
			else if (n)
				return (n);	/* input function failed */
		}

		if ((tmp = fopen(norewind ? norewind : cdevice, "r")) == NULL) {
			/* device was not accessible */
			if (options & DM_BATCH)
				return (1);
			(void) fprintf(stderr, ERR_ACCESS, pname, cdevice);
			if ((options & DM_BATCH) || (volume == NULL))
				return (1);
			/* display advice on how to ready device */
			if (advice = devattr(device, "advice"))
				(void) puttext(stderr, advice, 0, 0);
			continue;
		}
		(void) fclose(tmp);

		/* check label on device */
		if (label) {
			if (options & DM_ELABEL)
				elabel();
			else {
				/* check internal label using /etc/labelit */
				if (ckilabel(label, override)) {
					if ((options & DM_BATCH) ||
					    volume == NULL)
						return (4);
					continue;
				}
			}
		}
		break;
	}
	return (0);
}

static int
ckilabel(char *label, int flag)
{
	FILE	*pp;
	char	*pt, *look, buffer[512];
	char	fsname[LABELSIZ+1], volname[LABELSIZ+1];
	char	*pvolname, *pfsname;
	int	n, c;

	(void) strncpy(fsname, label, LABELSIZ);
	fsname[LABELSIZ] = '\0';
	if (pt = strchr(fsname, ',')) {
		*pt = '\0';
	}
	if (pt = strchr(label, ',')) {
		(void) strncpy(volname, pt+1, LABELSIZ);
		volname[LABELSIZ] = '\0';
	} else
		volname[0] = '\0';

	(void) sprintf(buffer, "/etc/labelit %s", cdevice);
	pp = popen(buffer, "r");
	pt = buffer;
	while ((c = getc(pp)) != EOF)
		*pt++ = (char)c;
	*pt = '\0';
	(void) pclose(pp);

	pt = buffer;
	pfsname = pvolname = NULL;
	look = "Current fsname: ";
	n = (int)strlen(look);
	while (*pt) {
		if (strncmp(pt, look, n) == 0) {
			*pt = '\0';
			pt += strlen(look);
			if (pfsname == NULL) {
				pfsname = pt;
				look = ", Current volname: ";
				n = (int)strlen(look);
			} else if (pvolname == NULL) {
				pvolname = pt;
				look = ", Blocks: ";
				n = (int)strlen(look);
			} else
				break;
		} else
			pt++;
	}

	if (strcmp(fsname, pfsname) || strcmp(volname, pvolname)) {
		/* mismatched label */
		if (flag) {
			(void) sprintf(label, "%s,%s", pfsname, pvolname);
		} else {
			labelerr(pfsname, pvolname);
			return (1);
		}
	}
	return (0);
}

static int
wilabel(char *label)
{
	char	buffer[512];
	char	fsname[LABELSIZ+1];
	char	volname[LABELSIZ+1];
	int	n;

	if (!label || !strlen(origfsname)) {
		if (n = ckstr(fsname, NULL, LABELSIZ, NULL, NULL, NULL,
				"Enter text for fsname label:"))
			return (n);
	} else
		(void) strcpy(fsname, origfsname);
	if (!label || !strlen(origvolname)) {
		if (n = ckstr(volname, NULL, LABELSIZ, NULL, NULL, NULL,
				"Enter text for volume label:"))
			return (n);
	} else
		(void) strcpy(volname, origvolname);

	if (IFTAPE(cdevice)) {
		(void) sprintf(buffer, "/etc/labelit %s \"%s\" \"%s\" -n 1>&2",
			cdevice, fsname, volname);
	} else {
		(void) sprintf(buffer, "/etc/labelit %s \"%s\" \"%s\" 1>&2",
			cdevice, fsname, volname);
	}
	if (system(buffer)) {
		(void) fprintf(stderr, "\nWrite of label to %s failed.", pname);
		return (1);
	}
	if (label)
		(void) sprintf(label, "%s,%s", fsname, volname);
	return (0);
}

static void
elabel(void)
{
}

static int
insert(char *device, char *label, int options, char *prompt)
{
	int	n;
	char	strval[16], prmpt[BUFSIZ];
	char	*pt, *keyword[10];
	char 	*fmtcmd;
	char	*mkfscmd;
	char	*voltxt;
	char	*removecmd;
	char	*dev_type;

	voltxt = (volume ? volume : "volume");

	fmtcmd    = devattr(device, "fmtcmd");
	mkfscmd   = devattr(device, "mkfscmd");
	removecmd = devattr(device, "removecmd");
	dev_type  = devattr(device, "type");

	if (prompt) {
		(void) strcpy(prmpt, prompt);
		for (pt = prmpt; *prompt; ) {
			if ((*prompt == '\\') && (prompt[1] == '%'))
				prompt++;
			else if (*prompt == '%') {
				switch (prompt[1]) {
				    case 'v':
					(void) strcpy(pt, voltxt);
					break;

				    case 'p':
					(void) strcpy(pt, pname);
					break;

				    default:
					*pt = '\0';
					break;
				}
				pt = pt + strlen(pt);
				prompt += 2;
				continue;
			}
			*pt++ = *prompt++;
		}
		*pt = '\0';
	} else {
		(void) sprintf(prmpt, "Insert a %s into %s.", voltxt, pname);
		if (label && (options & DM_ELABEL)) {
			(void) strcat(prmpt, " The following external label ");
			(void) sprintf(prmpt+strlen(prmpt),
				" should appear on the %s:\\n\\t%s",
				voltxt, label);
		}
		if (label && !(options & DM_ELABEL)) {
			(void) sprintf(prmpt+strlen(prmpt),
			"  The %s should be internally labeled as follows:",
				voltxt);
			(void) sprintf(prmpt+strlen(prmpt),
				"\\n\\t%s\\n", label);
		}
	}

	pt = prompt = prmpt + strlen(prmpt);

	n = 0;
	pt += sprintf(pt, "\\nType [go] when ready");
	keyword[n++] = "go";

	if (options & DM_FORMFS) {
		if (fmtcmd && *fmtcmd && mkfscmd && *mkfscmd) {
			pt += sprintf(pt, FORMFS_MSG, voltxt);
			keyword[n++] = "f";
		} else if (fmtcmd && *fmtcmd) {
			pt += sprintf(pt, FORMAT_MSG, voltxt);
			keyword[n++] = "f";
		}
		if (mkfscmd && *mkfscmd) {
			pt += sprintf(pt, MAKEFS_MSG, voltxt);
			keyword[n++] = "m";
		}
	} else if (options & DM_FORMAT) {
		if (fmtcmd && *fmtcmd) {
			pt += sprintf(pt, FORMAT_MSG, voltxt);
			keyword[n++] = "f";
		}
	}
	if (options & DM_WLABEL) {
		pt += sprintf(pt, WLABEL_MSG, voltxt);
		keyword[n++] = "w";
	}
	if (options & DM_OLABEL) {
		pt += sprintf(pt, OLABEL_MSG);
		keyword[n++] = "o";
	}
	if (removecmd && *removecmd && dev_type && *dev_type) {
		if (strcmp(dev_type, "diskette") == 0) {
			pt += sprintf(pt, EJECT_MSG, voltxt);
			keyword[n++] = "e";
		} else {
			pt += sprintf(pt, UNLOAD_MSG, voltxt);
			keyword[n++] = "u";
		}
	}
	keyword[n] = NULL;
	if (ckquit)
		pt += sprintf(pt, QUIT_MSG);
	*pt++ = ':';
	*pt = '\0';

	pt = prmpt;
	(void) fprintf(stderr, BELL);
	for (;;) {
		if (n = ckkeywd(strval, keyword, NULL, NULL, NULL, pt))
			return (n);

		pt = prompt; /* next prompt is only partial */
		if (*strval == 'f') {
			if (options & DM_FORMFS)
				doformat(voltxt, fmtcmd, mkfscmd);
			else
				doformat(voltxt, fmtcmd, NULL);
			continue;
		} else if (*strval == 'm') {
			doformat(voltxt, NULL, mkfscmd);
			continue;
		} else if (*strval == 'e' || *strval == 'u') {
			(void) doremovecmd(device, 1);
			continue;
		} else if (*strval == 'w') {
			(void) wilabel(label);
			continue;
		} else if (*strval == 'o')
			return (-1);
		break;
	}
	return (0);
}

static void
doformat(char *voltxt, char *fmtcmd, char *mkfscmd)
{
	char	buffer[512];

	if (fmtcmd && *fmtcmd) {
		(void) fprintf(stderr, "\t[%s]\n", fmtcmd);
		(void) sprintf(buffer, "(%s) 1>&2", fmtcmd);
		if (system(buffer)) {
			(void) fprintf(stderr, ERR_FMT, voltxt);
			return;
		}
	}
	if (mkfscmd && *mkfscmd) {
		(void) fprintf(stderr, "\t[%s]\n", mkfscmd);
		(void) sprintf(buffer, "(%s) 1>&2", mkfscmd);
		if (system(buffer)) {
			(void) fprintf(stderr, ERR_MKFS, voltxt);
			return;
		}
	}
}

void
doremovecmd(char *device, int echo)
{
	char 	*removecmd;
	char	buffer[512];

	if (device && *device) {
		removecmd = devattr(device, "removecmd");
		if (removecmd && *removecmd) {
			if (echo)
				(void) fprintf(stderr, "\t[%s]\n", removecmd);
			(void) sprintf(buffer, "(%s) 1>&2", removecmd);
			if (system(buffer)) {
				if (echo)
					(void) fprintf(stderr, ERR_REMOVE,
					removecmd);
				return;
			}
		}
	}
}

static void
labelerr(char *fsname, char *volname)
{
	(void) fprintf(stderr, "\nLabel incorrect.\n");
	if (volume)
		(void) fprintf(stderr,
			"The internal label on the inserted %s is\n", volume);
	else
		(void) fprintf(stderr, "The internal label for %s is", pname);
	(void) fprintf(stderr, "\t%s,%s\n", fsname, volname);
}
