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
 * Copyright 1992-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * scan /dev directory for mountable objects and construct device_allocate
 * file for allocate....
 *
 * devices are:
 *	tape (cartridge)
 *		/dev/rst*
 *		/dev/nrst*
 *		/dev/rmt/...
 *	audio
 *		/dev/audio
 *		/dev/audioctl
 *		/dev/sound/...
 *	floppy
 *		/dev/diskette
 *		/dev/fd*
 *		/dev/rdiskette
 *		/dev/rfd*
 *	CD
 *		/dev/sr*
 *		/dev/nsr*
 *		/dev/dsk/c?t?d0s?
 *		/dev/rdsk/c?t?d0s?
 */

#include <sys/types.h>	/* for stat(2), etc. */
#include <sys/stat.h>
#include <dirent.h>	/* for readdir(3), etc. */
#include <unistd.h>	/* for readlink(2) */
#include <string.h>	/* for strcpy(3), etc. */
#include <strings.h>	/* for bcopy(3C), etc. */
#include <stdio.h>	/* for perror(3) */
#include <stdlib.h>	/* for atoi(3) */
#include <locale.h>
#include <libintl.h>
#include <auth_attr.h>
#include <auth_list.h>
#include "allocate.h"   /* for SECLIB */

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

#define	DELTA	5	/* array size delta when full */

/* "/dev/rst...", "/dev/nrst...", "/dev/rmt/..." */
struct tape {
	char	*name;
	char	*device;
	int	number;
} *tape;
#define	DFLT_NTAPE  10		/* size of initial array */
#define	SIZE_OF_RST  3		/* |rmt| */
#define	SIZE_OF_NRST 4		/* |nrmt| */
#define	SIZE_OF_TMP  4		/* |/tmp| */
#define	SIZE_OF_RMT  8		/* |/dev/rmt| */

/* "/dev/audio", "/dev/audioctl", "/dev/sound/..." */
struct audio {
	char	*name;
	char	*device;
	int	number;
} *audio;
#define	DFLT_NAUDIO   10	/* size of initial array */
#define	SIZE_OF_SOUND 10	/* |/dev/sound| */

/* "/dev/sr", "/dev/nsr", "/dev/dsk/c?t?d0s?", "/dev/rdsk/c?t?d0s?" */
struct cd {
	char	*name;
	char	*device;
	int	id;
	int	controller;
	int	number;
} *cd;
#define	DFLT_NCD    10		/* size of initial array */
#define	SIZE_OF_SR   2		/* |sr| */
#define	SIZE_OF_RSR  3		/* |rsr| */
#define	SIZE_OF_DSK  8		/* |/dev/dsk| */
#define	SIZE_OF_RDSK 9		/* |/dev/rdsk| */


/* "/dev/fd0*", "/dev/rfd0*", "/dev/fd1*", "/dev/rfd1*" */
struct fp {
	char *name;
	char *device;
	int number;
} *fp;
#define	DFLT_NFP    10		/* size of initial array */
#define	SIZE_OF_FD0  3		/* |fd0| */
#define	SIZE_OF_RFD0 4		/* |rfd0| */

static void dotape();
static void doaudio();
static void dofloppy();
static void docd();
static void initmem();
static int  expandmem(int, void **, int);
static void no_memory(void);

void
main()
{
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	initmem();		/* initialize memory */

	dotape();		/* do tape */

	doaudio();		/* do audio */

	dofloppy();		/* do floppy */

	docd();			/* do cd */
}

static void
dotape()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int	i, j, n;
	char	*nm;		/* name/device of special device */
	char	linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int	sz;		/* size of symlink value */
	char	*cp;		/* pointer into string */
	int	ntape;		/* max array size */

	ntape = DFLT_NTAPE;

	/*
	 * look for rst* and nrst*
	 */

	if ((dirp = opendir("/dev")) == NULL) {
		perror(gettext("open /dev failure"));
		exit(1);
	}

	i = 0;
	while (dep = readdir(dirp)) {
		/* ignore if neither rst* nor nrst* */
		if (strncmp(dep->d_name, "rst", SIZE_OF_RST) &&
		    strncmp(dep->d_name, "nrst", SIZE_OF_NRST))
			continue;

		/* if array full, then expand it */
		if (i == ntape) {
			/* will exit(1) if insufficient memory */
			ntape = expandmem(i, (void **)&tape,
					sizeof (struct tape));
		}

		/* save name (/dev + / + d_name + \0) */
		nm = (char *)malloc(SIZE_OF_TMP + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/");
		(void) strcat(nm, dep->d_name);
		tape[i].name = nm;

		/* ignore if not symbolic link (note i not incremented) */
		if (lstat(tape[i].name, &stat) < 0) {
			perror("stat(2) failed ");
			exit(1);
		}
		if ((stat.st_mode & S_IFMT) != S_IFLNK)
			continue;

		/* get name from symbolic link */
		if ((sz = readlink(tape[i].name, linkvalue,
				sizeof (linkvalue))) < 0)
			continue;
		nm = (char *)malloc(sz + 1);
		if (nm == NULL)
			no_memory();
		(void) strncpy(nm, linkvalue, sz);
		nm[sz] = '\0';
		tape[i].device = nm;

		/* get device number */
		cp = strrchr(tape[i].device, '/');
		cp++;				/* advance to device # */
		(void) sscanf(cp, "%d", &tape[i].number);

		i++;
	}

	(void) closedir(dirp);

	/*
	 * scan /dev/rmt and add entry to table
	 */

	if ((dirp = opendir("/dev/rmt")) == NULL) {
		perror(gettext("open /dev failure"));
		exit(1);
	}

	while (dep = readdir(dirp)) {
		/* skip . .. etc... */
		if (strncmp(dep->d_name, ".", 1) == NULL)
			continue;

		/* if array full, then expand it */
		if (i == ntape) {
			/* will exit(1) if insufficient memory */
			ntape = expandmem(i, (void **)&tape,
					sizeof (struct tape));
		}

		/* save name (/dev/rmt + / + d_name + \0) */
		nm = (char *)malloc(SIZE_OF_RMT + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/rmt/");
		(void) strcat(nm, dep->d_name);
		tape[i].name = nm;

		/* save device name (rmt/ + d_name + \0) */
		nm = (char *)malloc(SIZE_OF_TMP + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "rmt/");
		(void) strcat(nm, dep->d_name);
		tape[i].device = nm;

		(void) sscanf(dep->d_name, "%d", &tape[i].number);

		i++;
	}
	n = i;

	(void) closedir(dirp);

	/* remove duplicate entries */
	for (i = 0; i < n - 1; i++) {
		for (j = i + 1; j < n; j++) {
			if (strcmp(tape[i].device, tape[j].device))
				continue;
			tape[j].number = -1;
		}
	}

	/* print out device_allocate entries for tape devices */
	for (i = 0; i < 8; i++) {
		for (j = 0; j < n; j++) {
			if (tape[j].number == i) {
				(void) printf(
					"st%d;st;reserved;reserved;%s;",
					i, DEFAULT_DEV_ALLOC_AUTH);
				(void) printf("%s%s\n", SECLIB, "/st_clean");
				break;
			}
		}
	}
}

static void
doaudio()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int	i, j, n;
	char	*nm;		/* name/device of special device */
	char	linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int	sz;		/* size of symlink value */
	char	*cp;		/* pointer into string */
	int	naudio;		/* max array size */

	naudio = DFLT_NAUDIO;

	if ((dirp = opendir("/dev")) == NULL) {
		perror(gettext("open /dev failure"));
		exit(1);
	}

	i = 0;
	while (dep = readdir(dirp)) {
		if (strcmp(dep->d_name, "audio") &&
		    strcmp(dep->d_name, "audioctl"))
			continue;

		/* if array full, then expand it */
		if (i == naudio) {
			/* will exit(1) if insufficient memory */
			naudio = expandmem(i, (void **)&audio,
					sizeof (struct audio));
		}

		/* save name (/dev + 1 + d_name + \0) */
		nm = (char *)malloc(SIZE_OF_TMP + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/");
		(void) strcat(nm, dep->d_name);
		audio[i].name = nm;

		/* ignore if not symbolic link (note i not incremented) */
		if (lstat(audio[i].name, &stat) < 0) {
			perror(gettext("stat(2) failed "));
			exit(1);
		}
		if ((stat.st_mode & S_IFMT) != S_IFLNK)
			continue;

		/* get name from symbolic link */
		if ((sz = readlink(audio[i].name, linkvalue,
				sizeof (linkvalue))) < 0)
			continue;
		nm = (char *)malloc(sz + 1);
		if (nm == NULL)
			no_memory();
		(void) strncpy(nm, linkvalue, sz);
		nm[sz] = '\0';
		audio[i].device = nm;

		cp = strrchr(audio[i].device, '/');
		cp++;				/* advance to device # */
		(void) sscanf(cp, "%d", &audio[i].number);

		i++;
	}

	(void) closedir(dirp);

	if ((dirp = opendir("/dev/sound")) == NULL) {
		goto skip;
	}

	while (dep = readdir(dirp)) {
		/* skip . .. etc... */
		if (strncmp(dep->d_name, ".", 1) == NULL)
			continue;

		/* if array full, then expand it */
		if (i == naudio) {
			/* will exit(1) if insufficient memory */
			naudio = expandmem(i, (void **)&audio,
					sizeof (struct audio));
		}

		/* save name (/dev/sound + / + d_name + \0) */
		nm = (char *)malloc(SIZE_OF_SOUND + 1 +
		    strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/sound/");
		(void) strcat(nm, dep->d_name);
		audio[i].name = nm;

		nm = (char *)malloc(SIZE_OF_SOUND + 1 +
		    strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/sound/");
		(void) strcat(nm, dep->d_name);
		audio[i].device = nm;

		(void) sscanf(dep->d_name, "%d", &audio[i].number);

		i++;
	}

	(void) closedir(dirp);

skip:
	n = i;

	/* remove duplicate entries */
	for (i = 0; i < n - 1; i++) {
		for (j = i + 1; j < n; j++) {
			if (strcmp(audio[i].device, audio[j].device))
				continue;
			audio[j].number = -1;
		}
	}

	/* print out device_allocate entries for tape devices */
	for (i = 0; i < 8; i++) {
		for (j = 0; j < n; j++) {
			if (audio[j].number == i) {
				(void) printf("audio;audio;");
				(void) printf("reserved;reserved;%s;",
				    DEFAULT_DEV_ALLOC_AUTH);
				(void) printf("%s%s\n", SECLIB, "/audio_clean");
				break;
			}
		}
	}
}

static void
dofloppy()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int i, j, n;
	char *nm;		/* name/device of special device */
	char linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int sz;			/* size of symlink value */
	char *cp;		/* pointer into string */
	int nfp;		/* max array size */

	nfp = DFLT_NFP;

	/*
	 * look for fd* and rfd*
	 */

	if ((dirp = opendir("/dev")) == NULL) {
		perror(gettext("open /dev failure"));
		exit(1);
	}

	i = 0;
	while (dep = readdir(dirp)) {
		/* ignore if neither rst* nor nrst* */
		if (strncmp(dep->d_name, "fd0", SIZE_OF_FD0) &&
		    strncmp(dep->d_name, "rfd0", SIZE_OF_RFD0) &&
		    strncmp(dep->d_name, "fd1", SIZE_OF_FD0) &&
		    strncmp(dep->d_name, "rfd0", SIZE_OF_RFD0))
			continue;

		/* if array full, then expand it */
		if (i == nfp) {
			/* will exit(1) if insufficient memory */
			nfp = expandmem(i, (void **)&fp, sizeof (struct fp));
		}

		/* save name (/dev + 1 + d_name + \0) */
		nm = (char *)malloc(SIZE_OF_TMP + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/");
		(void) strcat(nm, dep->d_name);
		fp[i].name = nm;

		/* ignore if not symbolic link (note i not incremented) */
		if (lstat(fp[i].name, &stat) < 0) {
			perror(gettext("stat(2) failed "));
			exit(1);
		}
		if ((stat.st_mode&S_IFMT) != S_IFLNK)
			continue;

		/* get name from symbolic link */
		if ((sz = readlink(fp[i].name, linkvalue,
		    sizeof (linkvalue))) < 0)
			continue;
		nm = (char *)malloc(sz+1);
		if (nm == NULL)
			no_memory();
		(void) strncpy(nm, linkvalue, sz);
		nm[sz] = '\0';
		fp[i].device = nm;

		/* get device number */
		cp = strchr(fp[i].name, 'd');
		cp++;				/* advance to device # */
		cp = strchr(cp, 'd');
		cp++;				/* advance to device # */
		(void) sscanf(cp, "%d", &fp[i].number);

		i++;
	}

	(void) closedir(dirp);

	n = i;

	/* print out device_allocate entries for tape devices */
	for (i = 0; i < 8; i++) {
	    for (j = 0; j < n; j++) {
		if (fp[j].number == i) {
		    (void) printf("fd%d;fd;reserved;reserved;%s;",
			i, DEFAULT_DEV_ALLOC_AUTH);
		    (void) printf("/etc/security/lib/fd_clean\n");
		    break;
		}
	    }
	}
}

static void
docd()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int	i, j, n;
	char	*nm;		/* name/device of special device */
	char	linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int	sz;		/* size of symlink value */
	char	*cp;		/* pointer into string */
	int	id;		/* disk id */
	int	ctrl;		/* disk controller */
	int	ncd;		/* max array size */

	ncd = DFLT_NCD;

	/*
	 * look for sr* and rsr*
	 */

	if ((dirp = opendir("/dev")) == NULL) {
		perror(gettext("open /dev failure"));
		exit(1);
	}

	i = 0;
	while (dep = readdir(dirp)) {
		/* ignore if neither sr* nor rsr* */
		if (strncmp(dep->d_name, "sr", SIZE_OF_SR) &&
		    strncmp(dep->d_name, "rsr", SIZE_OF_RSR))
			continue;

		/* if array full, then expand it */
		if (i == ncd) {
			/* will exit(1) if insufficient memory */
			ncd = expandmem(i, (void **)&cd, sizeof (struct cd));
		}

		/* save name (/dev + / + d_name + \0) */
		nm = (char *)malloc(SIZE_OF_TMP + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/");
		(void) strcat(nm, dep->d_name);
		cd[i].name = nm;

		/* save id # */
		if (dep->d_name[0] == 'r')
			(void) sscanf(dep->d_name, "rsr%d", &cd[i].id);
		else
			(void) sscanf(dep->d_name, "sr%d", &cd[i].id);

		/* ignore if not symbolic link (note i not incremented) */
		if (lstat(cd[i].name, &stat) < 0) {
			perror(gettext("stat(2) failed "));
			exit(1);
		}
		if ((stat.st_mode & S_IFMT) != S_IFLNK)
			continue;

		/* get name from symbolic link */
		if ((sz = readlink(cd[i].name, linkvalue, sizeof (linkvalue))) <
		    0)
			continue;
		nm = (char *)malloc(sz + 1);
		if (nm == NULL)
			no_memory();
		(void) strncpy(nm, linkvalue, sz);
		nm[sz] = '\0';
		cd[i].device = nm;

		cp = strrchr(cd[i].device, '/');
		cp++;				/* advance to device # */
		(void) sscanf(cp, "c%dt%d", &cd[i].controller, &cd[i].number);

		i++;
	}
	n = i;

	(void) closedir(dirp);

	/*
	 * scan /dev/dsk for cd devices
	 */

	if ((dirp = opendir("/dev/dsk")) == NULL) {
		perror("gettext(open /dev/dsk failure)");
		exit(1);
	}

	while (dep = readdir(dirp)) {
		/* skip . .. etc... */
		if (strncmp(dep->d_name, ".", 1) == NULL)
			continue;

		/* get device # (disk #) */
		if (sscanf(dep->d_name, "c%dt%d", &ctrl, &id) <= 0)
			continue;

		/* see if this is one of the cd special devices */
		for (j = 0; j < n; j++) {
			if (cd[j].number == id && cd[j].controller == ctrl)
				goto found;
		}
		continue;

		/* add new entry to table (/dev/dsk + / + d_name + \0) */
found:
		/* if array full, then expand it */
		if (i == ncd) {
			/* will exit(1) if insufficient memory */
			ncd = expandmem(i, (void **)&cd, sizeof (struct cd));
		}

		nm = (char *)malloc(SIZE_OF_DSK + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/dsk/");
		(void) strcat(nm, dep->d_name);
		cd[i].name = nm;

		cd[i].id = cd[j].id;

		cd[i].device = "";

		cd[i].number = id;

		i++;
	}

	(void) closedir(dirp);

	/*
	 * scan /dev/rdsk for cd devices
	 */

	if ((dirp = opendir("/dev/rdsk")) == NULL) {
		perror(gettext("open /dev/dsk failure"));
		exit(1);
	}

	while (dep = readdir(dirp)) {
		/* skip . .. etc... */
		if (strncmp(dep->d_name, ".", 1) == NULL)
			continue;

		/* get device # (disk #) */
		if (sscanf(dep->d_name, "c%dt%d", &ctrl, &id) != 2)
			continue;

		/* see if this is one of the cd special devices */
		for (j = 0; j < n; j++) {
			if (cd[j].number == id && cd[j].controller == ctrl)
				goto found1;
		}
		continue;

		/* add new entry to table (/dev/rdsk + / + d_name + \0) */
found1:
		/* if array full, then expand it */
		if (i == ncd) {
			/* will exit(1) if insufficient memory */
			ncd = expandmem(i, (void **)&cd, sizeof (struct cd));
		}

		nm = (char *)malloc(SIZE_OF_RDSK + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/rdsk/");
		(void) strcat(nm, dep->d_name);
		cd[i].name = nm;

		cd[i].id = cd[j].id;

		cd[i].device = "";

		cd[i].number = id;

		cd[i].controller = ctrl;

		i++;
	}

	(void) closedir(dirp);

	n = i;

	/* print out device_maps entries for tape devices */
	for (i = 0; i < 8; i++) {
		for (j = 0; j < n; j++) {
			if (cd[j].id == i) {
				(void) printf(
					"sr%d;sr;reserved;reserved;%s;",
					i, DEFAULT_DEV_ALLOC_AUTH);
				(void) printf("%s%s\n", SECLIB, "/sr_clean");
				break;
			}
		}
	}
}

/* set default array sizes */
static void
initmem()
{
	tape  = (struct tape *)calloc(DFLT_NTAPE, sizeof (struct tape));
	audio = (struct audio *)calloc(DFLT_NAUDIO, sizeof (struct audio));
	cd    = (struct cd *)calloc(DFLT_NCD, sizeof (struct cd));
	fp    = (struct fp *)calloc(DFLT_NFP, sizeof (struct fp));

	if (tape == NULL || audio == NULL || cd == NULL || fp == NULL)
		no_memory();
}

/* note n will be # elments in array (and could be 0) */
static int
expandmem(int n, void **array, int size)
{
	void *old = *array;
	void *new;

	/* get new array space (n + DELTA) */
	new = (void *)calloc(n + DELTA,  size);

	if (new == NULL) {
		perror("memory allocation failed");
		exit(1);
	}

	/* copy old array into new space */
	bcopy(old, new, n * size);

	/* now release old arrary */
	free(old);

	*array = new;

	return (n + DELTA);
}

static void
no_memory(void)
{
	(void) fprintf(stderr, "%s: %s\n", "mkdevalloc",
	    gettext("out of memory"));
	exit(1);
	/* NOT REACHED */
}
