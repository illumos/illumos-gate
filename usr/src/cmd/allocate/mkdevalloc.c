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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>	/* for stat(2), etc. */
#include <sys/stat.h>
#include <dirent.h>	/* for readdir(3), etc. */
#include <unistd.h>	/* for readlink(2) */
#include <stropts.h>
#include <string.h>	/* for strcpy(3), etc. */
#include <strings.h>	/* for bcopy(3C), etc. */
#include <stdio.h>	/* for perror(3) */
#include <stdlib.h>	/* for atoi(3) */
#include <sys/dkio.h>
#include <locale.h>
#include <libintl.h>
#include <libdevinfo.h>
#include <secdb.h>
#include <deflt.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <bsm/devices.h>
#include <bsm/devalloc.h>
#include <tsol/label.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

#define	MKDEVALLOC	"mkdevalloc"
#define	MKDEVMAPS	"mkdevmaps"

#define	DELTA	5	/* array size delta when full */
#define	SECLIB	"/etc/security/lib"

/* "/dev/rst...", "/dev/nrst...", "/dev/rmt/..." */
struct tape {
	char	*name;
	char	*device;
	int	number;
} *tape;
#define	DFLT_NTAPE  10		/* size of initial array */
#define	SIZE_OF_RST  3		/* |rmt| */
#define	SIZE_OF_NRST 4		/* |nrmt| */
#define	SIZE_OF_TMP 4		/* |/tmp| */
#define	SIZE_OF_RMT  8		/* |/dev/rmt| */
#define	TAPE_CLEAN    SECLIB"/st_clean"

/* "/dev/audio", "/dev/audioctl", "/dev/sound/..." */
struct audio {
	char	*name;
	char	*device;
	int	number;
} *audio;
#define	DFLT_NAUDIO   10	/* size of initial array */
#define	SIZE_OF_SOUND 10	/* |/dev/sound| */
#define	AUDIO_CLEAN   SECLIB"/audio_clean"

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
#define	CD_CLEAN    SECLIB"/sr_clean"

/* "/dev/sr", "/dev/nsr", "/dev/dsk/c?t?d0s?", "/dev/rdsk/c?t?d0s?" */
struct rmdisk {
	char	*name;
	char	*device;
	int	id;
	int	controller;
	int	number;
} *rmdisk, *rmdisk_r;
#define	DFLT_RMDISK	10	/* size of initial array */

/* "/dev/fd0*", "/dev/rfd0*", "/dev/fd1*", "/dev/rfd1*" */
struct fp {
	char *name;
	char *device;
	int number;
} *fp;
#define	DFLT_NFP    10		/* size of initial array */
#define	SIZE_OF_FD0  3		/* |fd0| */
#define	SIZE_OF_RFD0 4		/* |rfd0| */
#define	FLOPPY_CLEAN SECLIB"/fd_clean"

static void dotape();
static void doaudio();
static void dofloppy();
static int docd();
static void dormdisk(int);
static void initmem();
static int  expandmem(int, void **, int);
static void no_memory(void);

int		system_labeled = 0;
int		do_devalloc = 0;
int		do_devmaps = 0;
int		do_files = 0;
devlist_t	devlist;

int
main(int argc, char **argv)
{
	int		cd_count = 0;
	char		*progname;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;
	if (strcmp(progname, MKDEVALLOC) == 0)
		do_devalloc = 1;
	else if (strcmp(progname, MKDEVMAPS) == 0)
		do_devmaps = 1;
	else
		exit(1);

	system_labeled = is_system_labeled();

	if (!system_labeled) {
		/*
		 * is_system_labeled() will return false in case we are
		 * starting before the first reboot after Trusted Extensions
		 * is enabled.  Check the setting in /etc/system to see if
		 * TX is enabled (even if not yet booted).
		 */
		if (defopen("/etc/system") == 0) {
			if (defread("set sys_labeling=1") != NULL)
				system_labeled = 1;

			/* close defaults file */
			(void) defopen(NULL);
		}
	}

#ifdef DEBUG
	/* test hook: see also devfsadm.c and allocate.c */
	if (!system_labeled) {
		struct stat	tx_stat;

		system_labeled = is_system_labeled_debug(&tx_stat);
		if (system_labeled) {
			fprintf(stderr, "/ALLOCATE_FORCE_LABEL is set,\n"
			    "forcing system label on for testing...\n");
		}
	}
#endif

	if (system_labeled && do_devalloc && (argc == 2) &&
	    (strcmp(argv[1], DA_IS_LABELED) == 0)) {
		/*
		 * write device entries to device_allocate and device_maps.
		 * default is to print them on stdout.
		 */
		do_files = 1;
	}

	initmem();		/* initialize memory */
	dotape();
	doaudio();
	dofloppy();
	cd_count = docd();
	if (system_labeled)
		dormdisk(cd_count);

	return (0);
}

static void
dotape()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int	i, j;
	char	*nm;		/* name/device of special device */
	char	linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int	sz;		/* size of symlink value */
	char	*cp;		/* pointer into string */
	int	ntape;		/* max array size */
	int	tape_count;
	int	first = 0;
	char	*dname, *dtype, *dclean;
	da_args	dargs;
	deventry_t *entry;

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
		if (strncmp(dep->d_name, ".", 1) == 0)
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
	tape_count = i;

	(void) closedir(dirp);

	/* remove duplicate entries */
	for (i = 0; i < tape_count - 1; i++) {
		for (j = i + 1; j < tape_count; j++) {
			if (strcmp(tape[i].device, tape[j].device))
				continue;
			tape[j].number = -1;
		}
	}

	if (system_labeled) {
		dname = DA_TAPE_NAME;
		dtype = DA_TAPE_TYPE;
		dclean = DA_DEFAULT_TAPE_CLEAN;
	} else {
		dname = "st";
		dtype = "st";
		dclean = TAPE_CLEAN;
	}
	for (i = 0; i < 8; i++) {
		for (j = 0; j < tape_count; j++) {
			if (tape[j].number != i)
				continue;
			if (do_files) {
				(void) da_add_list(&devlist, tape[j].name, i,
				    DA_TAPE);
			} else if (do_devalloc) {
				/* print device_allocate for tape devices */
				if (system_labeled) {
					(void) printf("%s%d%s\\\n",
					    dname, i, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_TAPE_TYPE, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DEFAULT_DEV_ALLOC_AUTH,
					    KV_DELIMITER);
					(void) printf("\t%s\n\n", dclean);
				} else {
					(void) printf(
					    "st%d;st;reserved;reserved;%s;",
					    i, DEFAULT_DEV_ALLOC_AUTH);
					(void) printf("%s%s\n", SECLIB,
					    "/st_clean");
				}
				break;
			} else if (do_devmaps) {
				/* print device_maps for tape devices */
				if (first) {
					(void) printf(" ");
				} else {
					if (system_labeled) {
						(void) printf("%s%d%s\\\n",
						    dname, i, KV_TOKEN_DELIMIT);
						(void) printf("\t%s%s\\\n",
						    dtype, KV_TOKEN_DELIMIT);
						(void) printf("\t");
					} else {
						(void) printf("st%d:\\\n", i);
						(void) printf("\trmt:\\\n");
						(void) printf("\t");
					}
						first++;
				}
				(void) printf("%s", tape[j].name);
			}
		}
		if (do_devmaps && first) {
			(void) printf("\n\n");
			first = 0;
		}
	}
	if (do_files && tape_count) {
		dargs.rootdir = NULL;
		dargs.devnames = NULL;
		dargs.optflag = DA_ADD;
		for (entry = devlist.tape; entry != NULL; entry = entry->next) {
			dargs.devinfo = &(entry->devinfo);
			(void) da_update_device(&dargs);
		}
	}
}

static void
doaudio()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int	i, j;
	char	*nm;		/* name/device of special device */
	char	linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int	sz;		/* size of symlink value */
	char	*cp;		/* pointer into string */
	int	naudio;		/* max array size */
	int	audio_count = 0;
	int	len, slen;
	int	first = 0;
	char	dname[128];
	char	*dclean;
	da_args	dargs;
	deventry_t *entry;

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
		if (strncmp(dep->d_name, ".", 1) == 0)
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
	audio_count = i;

	/* remove duplicate entries */
	for (i = 0; i < audio_count - 1; i++) {
		for (j = i + 1; j < audio_count; j++) {
			if (strcmp(audio[i].device, audio[j].device))
				continue;
			audio[j].number = -1;
		}
	}

	/* print out device_allocate entries for audio devices */
	(void) strcpy(dname, DA_AUDIO_NAME);
	slen = strlen(DA_AUDIO_NAME);
	len = sizeof (dname) - slen;
	dclean = system_labeled ? DA_DEFAULT_AUDIO_CLEAN : AUDIO_CLEAN;
	for (i = 0; i < 8; i++) {
		for (j = 0; j < audio_count; j++) {
			if (audio[j].number != i)
				continue;
			if (system_labeled)
				(void) snprintf(dname+slen, len, "%d", i);
			if (do_files) {
				(void) da_add_list(&devlist, audio[j].name,
				    i, DA_AUDIO);
			} else if (do_devalloc) {
				/* print device_allocate for audio devices */
				if (system_labeled) {
					(void) printf("%s%s\\\n",
					    dname, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_AUDIO_TYPE, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DEFAULT_DEV_ALLOC_AUTH,
					    KV_DELIMITER);
					(void) printf("\t%s\n\n", dclean);
				} else {
					(void) printf("audio;audio;");
					(void) printf("reserved;reserved;%s;",
					    DEFAULT_DEV_ALLOC_AUTH);
					(void) printf("%s%s\n", SECLIB,
					    "/audio_clean");
				}
				break;
			} else if (do_devmaps) {
				/* print device_maps for audio devices */
				if (first) {
					(void) printf(" ");
				} else {
					if (system_labeled) {
						(void) printf("%s%s\\\n",
						    dname, KV_TOKEN_DELIMIT);
						(void) printf("\t%s%s\\\n",
						    DA_AUDIO_TYPE,
						    KV_TOKEN_DELIMIT);
						(void) printf("\t");
					} else {
						(void) printf("audio:\\\n");
						(void) printf("\taudio:\\\n");
						(void) printf("\t");
					}
					first++;
				}
				(void) printf("%s", audio[j].name);
			}
		}
		if (do_devmaps && first) {
			(void) printf("\n\n");
			first = 0;
		}
	}
	if (do_files && audio_count) {
		dargs.rootdir = NULL;
		dargs.devnames = NULL;
		dargs.optflag = DA_ADD;
		for (entry = devlist.audio; entry != NULL;
		    entry = entry->next) {
			dargs.devinfo = &(entry->devinfo);
			(void) da_update_device(&dargs);
		}
	}
}

static void
dofloppy()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int i, j;
	char *nm;		/* name/device of special device */
	char linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int sz;			/* size of symlink value */
	char *cp;		/* pointer into string */
	int nfp;		/* max array size */
	int floppy_count = 0;
	int first = 0;
	char *dname, *dclean;
	da_args dargs;
	deventry_t *entry;

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

	floppy_count = i;

	/* print out device_allocate entries for floppy devices */
	if (system_labeled) {
		dname = DA_FLOPPY_NAME;
		dclean = DA_DEFAULT_DISK_CLEAN;
	} else {
		dname = "fd";
		dclean = FLOPPY_CLEAN;
	}
	for (i = 0; i < 8; i++) {
		for (j = 0; j < floppy_count; j++) {
			if (fp[j].number != i)
				continue;
			if (do_files) {
				(void) da_add_list(&devlist, fp[j].name, i,
				    DA_FLOPPY);
			} else if (do_devalloc) {
				/* print device_allocate for floppy devices */
				if (system_labeled) {
					(void) printf("%s%d%s\\\n",
					    dname, i, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_FLOPPY_TYPE, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DEFAULT_DEV_ALLOC_AUTH,
					    KV_DELIMITER);
					(void) printf("\t%s\n\n", dclean);
				} else {
					(void) printf(
					    "fd%d;fd;reserved;reserved;%s;",
					    i, DEFAULT_DEV_ALLOC_AUTH);
					(void) printf("%s%s\n", SECLIB,
					    "/fd_clean");
				}
				break;
			} else if (do_devmaps) {
				/* print device_maps for floppy devices */
				if (first) {
					(void) printf(" ");
				} else {
					if (system_labeled) {
						(void) printf("%s%d%s\\\n",
						    dname, i, KV_TOKEN_DELIMIT);
						(void) printf("\t%s%s\\\n",
						    DA_FLOPPY_TYPE,
						    KV_TOKEN_DELIMIT);
						(void) printf("\t");
					} else {
						(void) printf("fd%d:\\\n", i);
						(void) printf("\tfd:\\\n");
						(void) printf("\t");
					}
					if (i == 0) {
						(void) printf("/dev/diskette ");
						(void) printf(
						    "/dev/rdiskette ");
					}
					first++;
				}
				(void) printf("%s", fp[j].name);
			}
		}
		if (do_devmaps && first) {
			(void) printf("\n\n");
			first = 0;
		}
	}
	if (do_files && floppy_count) {
		dargs.rootdir = NULL;
		dargs.devnames = NULL;
		dargs.optflag = DA_ADD;
		for (entry = devlist.floppy; entry != NULL;
		    entry = entry->next) {
			dargs.devinfo = &(entry->devinfo);
			(void) da_update_device(&dargs);
		}
	}
}

static int
docd()
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int	i, j;
	char	*nm;		/* name/device of special device */
	char	linkvalue[2048];	/* symlink value */
	struct stat stat;	/* determine if it's a symlink */
	int	sz;		/* size of symlink value */
	char	*cp;		/* pointer into string */
	int	id;		/* disk id */
	int	ctrl;		/* disk controller */
	int	ncd;		/* max array size */
	int	cd_count = 0;
	int	first = 0;
	char	*dname, *dclean;
	da_args	dargs;
	deventry_t *entry;

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
		cd[i].id = cd[i].number;

		i++;
	}
	cd_count = i;

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
		if (strncmp(dep->d_name, ".", 1) == 0)
			continue;

		/* get device # (disk #) */
		if (sscanf(dep->d_name, "c%dt%d", &ctrl, &id) != 2)
			continue;

		/* see if this is one of the cd special devices */
		for (j = 0; j < cd_count; j++) {
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
		if (strncmp(dep->d_name, ".", 1) == 0)
			continue;

		/* get device # (disk #) */
		if (sscanf(dep->d_name, "c%dt%d", &ctrl, &id) != 2)
			continue;

		/* see if this is one of the cd special devices */
		for (j = 0; j < cd_count; j++) {
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

	cd_count = i;

	if (system_labeled) {
		dname = DA_CD_NAME;
		dclean = DA_DEFAULT_DISK_CLEAN;
	} else {
		dname = "sr";
		dclean = CD_CLEAN;
	}
	for (i = 0; i < 8; i++) {
		for (j = 0; j < cd_count; j++) {
			if (cd[j].id != i)
				continue;
			if (do_files) {
				(void) da_add_list(&devlist, cd[j].name, i,
				    DA_CD);
			} else if (do_devalloc) {
				/* print device_allocate for cd devices */
				if (system_labeled) {
					(void) printf("%s%d%s\\\n",
					    dname, i, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_CD_TYPE, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DA_RESERVED, KV_DELIMITER);
					(void) printf("\t%s%s\\\n",
					    DEFAULT_DEV_ALLOC_AUTH,
					    KV_DELIMITER);
					(void) printf("\t%s\n\n", dclean);
				} else {
					(void) printf(
					    "sr%d;sr;reserved;reserved;%s;",
					    i, DEFAULT_DEV_ALLOC_AUTH);
					(void) printf("%s%s\n", SECLIB,
					    "/sr_clean");
				}
				break;
			} else if (do_devmaps) {
				/* print device_maps for cd devices */
				if (first) {
					(void) printf(" ");
				} else {
					if (system_labeled) {
						(void) printf("%s%d%s\\\n",
						    dname, i, KV_TOKEN_DELIMIT);
						(void) printf("\t%s%s\\\n",
						    DA_CD_TYPE,
						    KV_TOKEN_DELIMIT);
						(void) printf("\t");
					} else {
						(void) printf("sr%d:\\\n", i);
						(void) printf("\tsr:\\\n");
						(void) printf("\t");
					}
					first++;
				}
				(void) printf("%s", cd[j].name);
			}
		}
		if (do_devmaps && first) {
			(void) printf("\n\n");
			first = 0;
		}
	}
	if (do_files && cd_count) {
		dargs.rootdir = NULL;
		dargs.devnames = NULL;
		dargs.optflag = DA_ADD;
		for (entry = devlist.cd; entry != NULL; entry = entry->next) {
			dargs.devinfo = &(entry->devinfo);
			(void) da_update_device(&dargs);
		}
	}

	return (cd_count);
}

static void
dormdisk(int cd_count)
{
	DIR *dirp;
	struct dirent *dep;	/* directory entry pointer */
	int	i, j;
	char	*nm;		/* name/device of special device */
	int	id;		/* disk id */
	int	ctrl;		/* disk controller */
	int	nrmdisk;	/* max array size */
	int	fd = -1;
	int	rmdisk_count;
	int	first = 0;
	int	is_cd;
	int	checked;
	int	removable;
	char	path[MAXPATHLEN];
	da_args	dargs;
	deventry_t *entry;

	nrmdisk = DFLT_RMDISK;
	i = rmdisk_count = 0;

	/*
	 * scan /dev/dsk for rmdisk devices
	 */
	if ((dirp = opendir("/dev/dsk")) == NULL) {
		perror("gettext(open /dev/dsk failure)");
		exit(1);
	}

	while (dep = readdir(dirp)) {
		is_cd = 0;
		checked = 0;
		removable = 0;
		/* skip . .. etc... */
		if (strncmp(dep->d_name, ".", 1) == 0)
			continue;

		/* get device # (disk #) */
		if (sscanf(dep->d_name, "c%dt%d", &ctrl, &id) != 2)
			continue;

		/* see if we've already examined this device */
		for (j = 0; j < i; j++) {
			if (id == rmdisk[j].id &&
			    ctrl == rmdisk[j].controller &&
			    (strcmp(dep->d_name, rmdisk[j].name) == 0)) {
				checked = 1;
				break;
			}
			if (id == rmdisk[j].id && ctrl != rmdisk[j].controller)
				/*
				 * c2t0d0s0 is a different rmdisk than c3t0d0s0.
				 */
				id = rmdisk[j].id + 1;
		}
		if (checked)
			continue;

		/* ignore if this is a cd */
		for (j = 0; j < cd_count; j++) {
			if (id == cd[j].id && ctrl == cd[j].controller) {
				is_cd = 1;
				break;
			}
		}
		if (is_cd)
			continue;

		/* see if device is removable */
		(void) snprintf(path, sizeof (path), "%s%s", "/dev/rdsk/",
		    dep->d_name);
		if ((fd = open(path, O_RDONLY | O_NONBLOCK)) < 0)
			continue;
		(void) ioctl(fd, DKIOCREMOVABLE, &removable);
		(void) close(fd);
		if (removable == 0)
			continue;

		/*
		 * add new entry to table (/dev/dsk + / + d_name + \0)
		 * if array full, then expand it
		 */
		if (i == nrmdisk) {
			/* will exit(1) if insufficient memory */
			nrmdisk = expandmem(i, (void **)&rmdisk,
			    sizeof (struct rmdisk));
			/* When we expand rmdisk, need to expand rmdisk_r */
			(void) expandmem(i, (void **)&rmdisk_r,
			    sizeof (struct rmdisk));
		}
		nm = (char *)malloc(SIZE_OF_DSK + 1 + strlen(dep->d_name) + 1);
		if (nm == NULL)
			no_memory();
		(void) strcpy(nm, "/dev/dsk/");
		(void) strcat(nm, dep->d_name);
		rmdisk[i].name = nm;
		rmdisk[i].id = id;
		rmdisk[i].controller = ctrl;
		rmdisk[i].device = "";
		rmdisk[i].number = id;
		rmdisk_r[i].name = strdup(path);
		i++;
	}

	rmdisk_count = i;
	(void) closedir(dirp);

	for (i = 0, j = rmdisk_count; i < rmdisk_count; i++, j++) {
		if (j == nrmdisk) {
			/* will exit(1) if insufficient memory */
			nrmdisk = expandmem(j, (void **)&rmdisk,
			    sizeof (struct rmdisk));
		}
		rmdisk[j].name = rmdisk_r[i].name;
		rmdisk[j].id = rmdisk[i].id;
		rmdisk[j].controller = rmdisk[i].controller;
		rmdisk[j].device = rmdisk[i].device;
		rmdisk[j].number = rmdisk[i].number;
	}
	rmdisk_count = j;

	for (i = 0; i < 8; i++) {
		for (j = 0; j < rmdisk_count; j++) {
			if (rmdisk[j].id != i)
				continue;
			if (do_files) {
				(void) da_add_list(&devlist, rmdisk[j].name, i,
				    DA_RMDISK);
			} else if (do_devalloc) {
				/* print device_allocate for rmdisk devices */
				(void) printf("%s%d%s\\\n",
				    DA_RMDISK_NAME, i, KV_DELIMITER);
				(void) printf("\t%s%s\\\n",
				    DA_RMDISK_TYPE, KV_DELIMITER);
				(void) printf("\t%s%s\\\n",
				    DA_RESERVED, KV_DELIMITER);
				(void) printf("\t%s%s\\\n",
				    DA_RESERVED, KV_DELIMITER);
				(void) printf("\t%s%s\\\n",
				    DEFAULT_DEV_ALLOC_AUTH, KV_DELIMITER);
				(void) printf("\t%s\n", DA_DEFAULT_DISK_CLEAN);
				break;
			} else if (do_devmaps) {
				/* print device_maps for rmdisk devices */
				if (first) {
					(void) printf(" ");
				} else {
					(void) printf("%s%d%s\\\n",
					    DA_RMDISK_NAME, i,
					    KV_TOKEN_DELIMIT);
					(void) printf("\t%s%s\\\n",
					    DA_RMDISK_TYPE, KV_TOKEN_DELIMIT);
					(void) printf("\t");
					first++;
				}
				(void) printf("%s", rmdisk[j].name);
			}
		}
		if (do_devmaps && first) {
			(void) printf("\n\n");
			first = 0;
		}
	}
	if (do_files && rmdisk_count) {
		dargs.rootdir = NULL;
		dargs.devnames = NULL;
		dargs.optflag = DA_ADD;
		for (entry = devlist.rmdisk; entry != NULL;
		    entry = entry->next) {
			dargs.devinfo = &(entry->devinfo);
			(void) da_update_device(&dargs);
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
	if (system_labeled) {
		rmdisk = (struct rmdisk *)calloc(DFLT_RMDISK,
		    sizeof (struct rmdisk));
		if (rmdisk == NULL)
			no_memory();
		rmdisk_r = (struct rmdisk *)calloc(DFLT_RMDISK,
		    sizeof (struct rmdisk));
		if (rmdisk_r == NULL)
			no_memory();
	}

	if (tape == NULL || audio == NULL || cd == NULL || fp == NULL)
		no_memory();

	devlist.audio = devlist.cd = devlist.floppy = devlist.rmdisk =
	    devlist.tape = NULL;
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
