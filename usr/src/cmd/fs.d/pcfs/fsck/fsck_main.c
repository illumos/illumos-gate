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
 * Copyright (c) 1999,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright 2024 MNX Cloud, Inc.
 */

/*
 * fsck_pcfs -- main routines.
 */

#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/fcntl.h>
#include <sys/dktp/fdisk.h>
#include "getresponse.h"
#include "pcfs_common.h"
#include "fsck_pcfs.h"
#include "pcfs_bpb.h"

size_t bpsec = MINBPS;
int32_t BytesPerCluster;
int32_t TotalClusters;
int32_t LastCluster;
off64_t	FirstClusterOffset;
off64_t	PartitionOffset;
bpb_t	TheBIOSParameterBlock;

/*
 * {Output,Input}Image are the file names where we should write the
 * checked fs image and from which we should read the initial fs.
 * The image capability is designed for debugging purposes.
 */
static char	*OutputImage = NULL;
static char	*InputImage = NULL;
static int	WritableOnly = 0; /* -o w, check writable fs' only */
static int	Mflag = 0;	  /* -m, sanity check if fs is mountable */
static int	Preen = 0;	  /* -o p, preen; non-interactive */
/*
 * By default be quick; skip verify reads.
 * If the user wants more exhaustive checking,
 * they should run with the -o v option.
 */
static int	Quick = 1;

int	ReadOnly = 0;
int	IsFAT32 = 0;
int	Verbose = 0;

bool	AlwaysYes = false; /* -y or -Y, assume a yes answer to all questions */
bool	AlwaysNo = false; /* -n or -N, assume a no answer to all questions */

extern	ClusterContents	TheRootDir;

/*
 * Function definitions
 */

static void
passOne(int fd)
{
	if (!Quick)
		findBadClusters(fd);
	scanAndFixMetadata(fd);
}

static void
writeBackChanges(int fd)
{
	writeFATMods(fd);
	if (!IsFAT32)
		writeRootDirMods(fd);
	writeClusterMods(fd);
}

static void
tryOpen(int *fd, char *openMe, int oflag, int exitOnFailure)
{
	int saveError;

	if ((*fd = open(openMe, oflag)) < 0) {
		if (exitOnFailure == RETURN_ON_OPEN_FAILURE)
			return;
		saveError = errno;
		mountSanityCheckFails();
		(void) fprintf(stderr, "%s: ", openMe);
		(void) fprintf(stderr, strerror(saveError));
		(void) fprintf(stderr, "\n");
		exit(1);
	}
}

static void
doOpen(int *inFD, int *outFD, char *name, char *outName)
{
	if (ReadOnly) {
		tryOpen(inFD, name, O_RDONLY, EXIT_ON_OPEN_FAILURE);
		*outFD = -1;
	} else {
		tryOpen(inFD, name, O_RDWR, RETURN_ON_OPEN_FAILURE);
		if (*inFD < 0) {
			if (errno != EACCES || WritableOnly) {
				int saveError = errno;
				mountSanityCheckFails();
				(void) fprintf(stderr,
				    gettext("%s: "), name);
				(void) fprintf(stderr, strerror(saveError));
				(void) fprintf(stderr, "\n");
				exit(2);
			} else {
				tryOpen(inFD, name, O_RDONLY,
				    EXIT_ON_OPEN_FAILURE);
				AlwaysYes = false;
				AlwaysNo = true;
				ReadOnly = 1;
				*outFD = -1;
			}
		} else {
			*outFD = *inFD;
		}
	}

	if (outName != NULL) {
		tryOpen(outFD, outName, (O_RDWR | O_CREAT),
		    EXIT_ON_OPEN_FAILURE);
	}

	(void) printf("** %s %s\n", name,
	    ReadOnly ? gettext("(NO WRITE)") : "");
}

static void
openFS(char *special, int *inFD, int *outFD)
{
	struct stat dinfo;
	char *actualDisk = NULL;
	char *suffix = NULL;
	int rv;

	if (Verbose)
		(void) fprintf(stderr, gettext("Opening file system.\n"));

	if (InputImage == NULL) {
		actualDisk = stat_actual_disk(special, &dinfo, &suffix);
		/*
		 *  Destination exists, now find more about it.
		 */
		if (!(S_ISCHR(dinfo.st_mode))) {
			mountSanityCheckFails();
			(void) fprintf(stderr,
			    gettext("\n%s: device name must be a "
			    "character special device.\n"), actualDisk);
			exit(2);
		}
	} else {
		actualDisk = InputImage;
	}
	doOpen(inFD, outFD, actualDisk, OutputImage);
	rv = get_media_sector_size(*inFD, &bpsec);
	if (rv != 0) {
		(void) fprintf(stderr,
		    gettext("error detecting device sector size: %s\n"),
		    strerror(rv));
		exit(2);
	}
	if (!is_sector_size_valid(bpsec)) {
		(void) fprintf(stderr,
		    gettext("unsupported sector size: %zu\n"), bpsec);
		exit(2);
	}

	if (suffix) {
		if ((PartitionOffset =
		    findPartitionOffset(*inFD, bpsec, suffix)) < 0) {
			mountSanityCheckFails();
			(void) fprintf(stderr,
			    gettext("Unable to find logical drive %s\n"),
			    suffix);
			exit(2);
		} else if (Verbose) {
			(void) fprintf(stderr,
			    gettext("Partition starts at offset %lld\n"),
			    PartitionOffset);
		}
	} else {
		PartitionOffset = 0;
	}
}

void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("pcfs Usage: fsck -F pcfs [-o v|p|w] special-file\n"));
	exit(1);
}

static
char *LegalOpts[] = {
#define	VFLAG 0
	"v",
#define	PFLAG 1
	"p",
#define	WFLAG 2
	"w",
#define	DFLAG 3
	"d",
#define	IFLAG 4
	"i",
#define	OFLAG 5
	"o",
	NULL
};

static void
parseSubOptions(char *optsstr)
{
	char *value;
	int c;

	while (*optsstr != '\0') {
		switch (c = getsubopt(&optsstr, LegalOpts, &value)) {
		case VFLAG:
			Quick = 0;
			break;
		case PFLAG:
			Preen++;
			break;
		case WFLAG:
			WritableOnly++;
			break;
		case DFLAG:
			Verbose++;
			break;
		case IFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				InputImage = value;
			}
			break;
		case OFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				OutputImage = value;
			}
			break;
		default:
			bad_arg(value);
			break;
		}
	}
}

static void
sanityCheckOpts(void)
{
	if (WritableOnly && ReadOnly) {
		(void) fprintf(stderr,
		    gettext("-w option may not be used with the -n "
		    "or -m options\n"));
		exit(4);
	}
}

static void
confirmMountable(char *special, int fd)
{
	char *printName;
	int okayToMount = 1;

	printName = InputImage ? InputImage : special;

	if (!IsFAT32) {
		/* make sure we can at least read the root directory */
		getRootDirectory(fd);
		if (TheRootDir.bytes == NULL)
			okayToMount = 0;
	} else {
		/* check the bit designed into FAT32 for this purpose */
		okayToMount = checkFAT32CleanBit(fd);
	}
	if (okayToMount) {
		(void) fprintf(stderr,
		    gettext("pcfs fsck: sanity check: %s okay\n"), printName);
		exit(0);
	} else {
		(void) fprintf(stderr,
		    gettext("pcfs fsck: sanity check: %s needs checking\n"),
		    printName);
		exit(32);
	}
}

void
mountSanityCheckFails(void)
{
	if (Mflag) {
		(void) fprintf(stderr,
		    gettext("pcfs fsck: sanity check failed: "));
	}
}

/*
 * preenBail
 *	Routine that other routines can call if they would go into a
 *	state where they need user input.  They can send an optional
 *	message string to be printed before the exit.  Caller should
 *	send a NULL string if they don't have an exit message.
 */
void
preenBail(char *outString)
{
	/*
	 *  If we are running in the 'preen' mode, we got here because
	 *  we reached a situation that would require user intervention.
	 *  We have no choice but to bail at this point.
	 */
	if (Preen) {
		if (outString)
			(void) printf("%s", outString);
		(void) printf(gettext("FILE SYSTEM FIX REQUIRES USER "
		    "INTERVENTION; RUN fsck MANUALLY.\n"));
		exit(36);
	}
}

int
main(int argc, char *argv[])
{
	char *string;
	int  ifd, ofd;
	int  c;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	if (init_yes() < 0)
		errx(2, gettext(ERR_MSG_INIT_YES), strerror(errno));

	if (argc < 2)
		usage();

	while ((c = getopt(argc, argv, "F:VYNynmo:")) != EOF) {
		switch (c) {
		case 'F':
			string = optarg;
			if (strcmp(string, "pcfs") != 0)
				usage();
			break;
		case 'V': {
				char	*opt_text;
				int	opt_count;

				(void) printf(gettext("fsck -F pcfs "));
				for (opt_count = 1; opt_count < argc;
				    opt_count++) {
					opt_text = argv[opt_count];
					if (opt_text)
						(void) printf(" %s ",
						    opt_text);
				}
				(void) printf("\n");
				fini_yes();
				exit(0);
			}
			break;
		case 'N':
		case 'n':
			AlwaysYes = false;
			AlwaysNo = true;
			ReadOnly = 1;
			break;
		case 'Y':
		case 'y':
			AlwaysYes = true;
			AlwaysNo = false;
			break;
		case 'm':
			Mflag++;
			ReadOnly = 1;
			break;
		case 'o':
			string = optarg;
			parseSubOptions(string);
			break;
		}
	}

	sanityCheckOpts();
	if (InputImage == NULL && (optind < 0 || optind >= argc))
		usage();

	openFS(argv[optind], &ifd, &ofd);
	readBPB(ifd);

	/*
	 * -m mountable fs check.  This call will not return.
	 */
	if (Mflag)
		confirmMountable(argv[optind], ifd);

	/*
	 *  Pass 1: Find any bad clusters and adjust the FAT and directory
	 *	entries accordingly
	 */
	passOne(ifd);

	/*
	 *  XXX - future passes?
	 *	Ideas:
	 *	    Data relocation for bad clusters with partial read success?
	 *	    Syncing backup FAT copies with main copy?
	 *	    Syncing backup root sector for FAT32?
	 */

	/*
	 *  No problems if we made it this far.
	 */
	printSummary(stdout);
	writeBackChanges(ofd);
	fini_yes();
	return (0);
}
