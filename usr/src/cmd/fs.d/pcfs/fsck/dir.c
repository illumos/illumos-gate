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

/*
 * fsck_pcfs -- routines for manipulating directories.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libintl.h>
#include <ctype.h>
#include <time.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_label.h>
#include "pcfs_common.h"
#include "fsck_pcfs.h"

extern	int32_t	HiddenClusterCount;
extern	int32_t	FileClusterCount;
extern	int32_t	DirClusterCount;
extern	int32_t	HiddenFileCount;
extern	int32_t	LastCluster;
extern	int32_t	FileCount;
extern	int32_t	BadCount;
extern	int32_t	DirCount;
extern	int32_t	FATSize;
extern	off64_t	PartitionOffset;
extern	bpb_t	TheBIOSParameterBlock;
extern	int	ReadOnly;
extern	int	IsFAT32;
extern	int	Verbose;

static uchar_t *CHKsList = NULL;

ClusterContents	TheRootDir;
int32_t	RootDirSize;
int	RootDirModified;
int	OkayToRelink = 1;

/*
 * We have a bunch of routines for handling CHK names.  A CHK name is
 * simply a file name of the form "FILEnnnn.CHK", where the n's are the
 * digits in the numbers from 1 to 9999.  There are always four digits
 * used, leading zeros are added as necessary.
 *
 * We use CHK names to link orphaned cluster chains back into the file
 * system's root directory under an auspicious name so that the user
 * may be able to recover some of their data.
 *
 * We use these routines to ensure CHK names we use don't conflict
 * with any already present in the file system.
 */
static int
hasCHKName(struct pcdir *dp)
{
	return (dp->pcd_filename[CHKNAME_F] == 'F' &&
	    dp->pcd_filename[CHKNAME_I] == 'I' &&
	    dp->pcd_filename[CHKNAME_L] == 'L' &&
	    dp->pcd_filename[CHKNAME_E] == 'E' &&
	    isdigit(dp->pcd_filename[CHKNAME_THOUSANDS]) &&
	    isdigit(dp->pcd_filename[CHKNAME_HUNDREDS]) &&
	    isdigit(dp->pcd_filename[CHKNAME_TENS]) &&
	    isdigit(dp->pcd_filename[CHKNAME_ONES]) &&
	    dp->pcd_ext[CHKNAME_C] == 'C' &&
	    dp->pcd_ext[CHKNAME_H] == 'H' &&
	    dp->pcd_ext[CHKNAME_K] == 'K');
}

void
addEntryToCHKList(int chkNumber)
{
	/* silent failure on bogus value */
	if (chkNumber < 0 || chkNumber > MAXCHKVAL)
		return;
	CHKsList[chkNumber / NBBY] |= (1 << (chkNumber % NBBY));
}

static void
addToCHKList(struct pcdir *dp)
{
	int chknum;

	chknum = 1000 * (dp->pcd_filename[CHKNAME_THOUSANDS] - '0');
	chknum += 100 * (dp->pcd_filename[CHKNAME_HUNDREDS] - '0');
	chknum += 10 * (dp->pcd_filename[CHKNAME_TENS] - '0');
	chknum += (dp->pcd_filename[CHKNAME_ONES] - '0');
	addEntryToCHKList(chknum);
}

static int
inUseCHKName(int chkNumber)
{
	return (CHKsList[chkNumber / NBBY] & (1 << (chkNumber % NBBY)));
}

static void
appendToPath(struct pcdir *dp, char *thePath, int *theLen)
{
	int i = 0;

	/*
	 * Sometimes caller doesn't care about keeping track of the path
	 */
	if (thePath == NULL)
		return;

	/*
	 *  Prepend /
	 */
	if (*theLen < MAXPATHLEN)
		*(thePath + (*theLen)++) = '/';
	/*
	 *  Print out the file name part, but only up to the first
	 *  space.
	 */
	while (*theLen < MAXPATHLEN && i < PCFNAMESIZE) {
		/*
		 *  When we start seeing spaces we assume that's the
		 *  end of the interesting characters in the name.
		 */
		if ((dp->pcd_filename[i] == ' ') ||
		    !(pc_validchar(dp->pcd_filename[i])))
			break;
		*(thePath + (*theLen)++) = dp->pcd_filename[i++];
	}
	/*
	 *  Leave now, if we don't have an extension (or room for one)
	 */
	if ((dp->pcd_ext[i] == ' ') || ((*theLen) >= MAXPATHLEN) ||
	    (!(pc_validchar(dp->pcd_ext[i]))))
		return;
	/*
	 *  Tack on the extension
	 */
	*(thePath + (*theLen)++) = '.';
	i = 0;
	while ((*theLen < MAXPATHLEN) && (i < PCFEXTSIZE)) {
		if ((dp->pcd_ext[i] == ' ') || !(pc_validchar(dp->pcd_ext[i])))
			break;
		*(thePath + (*theLen)++) = dp->pcd_ext[i++];
	}
}

static void
printName(FILE *outDest, struct pcdir *dp)
{
	int i;
	for (i = 0; i < PCFNAMESIZE; i++) {
		if ((dp->pcd_filename[i] == ' ') ||
		    !(pc_validchar(dp->pcd_filename[i])))
			break;
		(void) fprintf(outDest, "%c", dp->pcd_filename[i]);
	}
	(void) fprintf(outDest, ".");
	for (i = 0; i < PCFEXTSIZE; i++) {
		if (!(pc_validchar(dp->pcd_ext[i])))
			break;
		(void) fprintf(outDest, "%c", dp->pcd_ext[i]);
	}
}

/*
 *  sanityCheckSize
 *	Make sure the size in the directory entry matches what is
 *	actually allocated.  If there is a mismatch, orphan all
 *	the allocated clusters.  Returns SIZE_MATCHED if everything matches
 *	up, TRUNCATED to indicate truncation was necessary.
 */
static int
sanityCheckSize(int fd, struct pcdir *dp, int32_t actualClusterCount,
    int isDir, int32_t startCluster, struct nameinfo *fullPathName,
    struct pcdir **orphanEntry)
{
	uint32_t sizeFromDir;
	int32_t ignorei = 0;
	int64_t bpc;

	bpc = TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector;
	sizeFromDir = extractSize(dp);
	if (isDir) {
		if (sizeFromDir == 0)
			return (SIZE_MATCHED);
	} else {
		if ((sizeFromDir > ((actualClusterCount - 1) * bpc)) &&
		    (sizeFromDir <= (actualClusterCount * bpc)))
			return (SIZE_MATCHED);
	}
	if (fullPathName != NULL) {
		fullPathName->references++;
		(void) fprintf(stderr, "%s\n", fullPathName->fullName);
	}
	squirrelPath(fullPathName, startCluster);
	(void) fprintf(stderr,
	    gettext("Truncating chain due to incorrect size "
	    "in directory.  Size from directory = %u bytes,\n"), sizeFromDir);
	if (actualClusterCount == 0) {
		(void) fprintf(stderr,
		    gettext("Zero bytes are allocated to the file.\n"));
	} else {
		(void) fprintf(stderr,
		    gettext("Allocated size in range %llu - %llu bytes.\n"),
		    ((actualClusterCount - 1) * bpc) + 1,
		    (actualClusterCount * bpc));
	}
	/*
	 * Use splitChain() to make an orphan that is the entire allocation
	 * chain.
	 */
	splitChain(fd, dp, startCluster, orphanEntry, &ignorei);
	return (TRUNCATED);
}

static int
noteUsage(int fd, int32_t startAt, struct pcdir *dp, struct pcdir *lp,
    int32_t longEntryStartCluster, int isHidden, int isDir,
    struct nameinfo *fullPathName)
{
	struct pcdir *orphanEntry;
	int32_t chain = startAt;
	int32_t count = 0;
	int savePathNextIteration = 0;
	int haveBad = 0;
	ClusterInfo *tmpl = NULL;

	while ((chain >= FIRST_CLUSTER) && (chain <= LastCluster)) {
		if ((markInUse(fd, chain, dp, lp, longEntryStartCluster,
		    isHidden ? HIDDEN : VISIBLE, &tmpl))
			!= CLINFO_NEWLY_ALLOCED)
			break;
		count++;
		if (savePathNextIteration == 1) {
			savePathNextIteration = 0;
			if (fullPathName != NULL)
				fullPathName->references++;
			squirrelPath(fullPathName, chain);
		}
		if (isMarkedBad(chain)) {
			haveBad = 1;
			savePathNextIteration = 1;
		}
		if (isHidden)
			HiddenClusterCount++;
		else if (isDir)
			DirClusterCount++;
		else
			FileClusterCount++;
		chain = nextInChain(chain);
	}
	/*
	 * Do a sanity check on the file size in the directory entry.
	 * This may create an orphaned cluster chain.
	 */
	if (sanityCheckSize(fd, dp, count, isDir, startAt,
	    fullPathName, &orphanEntry) == TRUNCATED) {
		/*
		 * The pre-existing directory entry has been truncated,
		 * so the chain associated with it no longer has any
		 * bad clusters.  Instead, the new orphan has them.
		 */
		if (haveBad > 0) {
			truncChainWithBadCluster(fd, orphanEntry, startAt);
		}
		haveBad = 0;
	}
	return (haveBad);
}

static void
storeInfoAboutEntry(int fd, struct pcdir *dp, struct pcdir *ldp, int depth,
    int32_t longEntryStartCluster, char *fullPath, int *fullLen)
{
	struct nameinfo *pathCopy;
	int32_t start;
	int haveBad;
	int hidden = (dp->pcd_attr & PCA_HIDDEN || dp->pcd_attr & PCA_SYSTEM);
	int dir = (dp->pcd_attr & PCA_DIR);
	int i;

	if (hidden)
		HiddenFileCount++;
	else if (dir)
		DirCount++;
	else
		FileCount++;
	appendToPath(dp, fullPath, fullLen);

	/*
	 * Make a copy of the name at this point.  We may want it to
	 * note the original source of an orphaned cluster.
	 */
	if ((pathCopy =
	    (struct nameinfo *)malloc(sizeof (struct nameinfo))) != NULL) {
		if ((pathCopy->fullName =
		    (char *)malloc(*fullLen + 1)) != NULL) {
			pathCopy->references = 0;
			(void) strncpy(pathCopy->fullName, fullPath, *fullLen);
			pathCopy->fullName[*fullLen] = '\0';
		} else {
			free(pathCopy);
			pathCopy = NULL;
		}
	}
	if (Verbose) {
		for (i = 0; i < depth; i++)
			(void) fprintf(stderr, "  ");
		if (hidden)
			(void) fprintf(stderr, "[");
		else if (dir)
			(void) fprintf(stderr, "|_");
		else
			(void) fprintf(stderr, gettext("(%06d) "), FileCount);
		printName(stderr, dp);
		if (hidden)
			(void) fprintf(stderr, "]");
		(void) fprintf(stderr,
		    gettext(", %u bytes, start cluster %d"),
		    extractSize(dp), extractStartCluster(dp));
		(void) fprintf(stderr, "\n");
	}
	start = extractStartCluster(dp);
	haveBad = noteUsage(fd, start, dp, ldp, longEntryStartCluster,
	    hidden, dir, pathCopy);
	if (haveBad > 0) {
		if (dir && pathCopy->fullName != NULL) {
			(void) fprintf(stderr,
			    gettext("Adjusting for bad allocation units in "
			    "the meta-data of:\n  "));
			(void) fprintf(stderr, pathCopy->fullName);
			(void) fprintf(stderr, "\n");
		}
		truncChainWithBadCluster(fd, dp, start);
	}
	if ((pathCopy != NULL) && (pathCopy->references == 0)) {
		free(pathCopy->fullName);
		free(pathCopy);
	}
}

static void
storeInfoAboutLabel(struct pcdir *dp)
{
	/*
	 * XXX eventually depth should be passed to this routine just
	 * as it is with storeInfoAboutEntry().  If it isn't zero, then
	 * we've got a bogus directory entry.
	 */
	if (Verbose) {
		(void) fprintf(stderr, gettext("** "));
		printName(stderr, dp);
		(void) fprintf(stderr, gettext(" **\n"));
	}
}

static void
searchChecks(struct pcdir *dp, int operation, char matchRequired,
    struct pcdir **found)
{
	/*
	 *  We support these searching operations:
	 *
	 *  PCFS_FIND_ATTR
	 *	look for the first file with a certain attribute
	 *	(e.g, find all hidden files)
	 *  PCFS_FIND_STATUS
	 *	look for the first file with a certain status
	 *	(e.g., the file has been marked deleted; making
	 *	its directory entry reusable)
	 *  PCFS_FIND_CHKS
	 *	look for all files with short names of the form
	 *	FILENNNN.CHK.  These are the file names we give
	 *	to chains of orphaned clusters we relink into the
	 *	file system.  This find facility allows us to seek
	 *	out all existing files of this naming form so that
	 *	we may create unique file names for new orphans.
	 */
	if (operation == PCFS_FIND_ATTR && dp->pcd_attr == matchRequired) {
		*found = dp;
	} else if (operation == PCFS_FIND_STATUS &&
	    dp->pcd_filename[0] == matchRequired) {
		*found = dp;
	} else if (operation == PCFS_FIND_CHKS && hasCHKName(dp)) {
		addToCHKList(dp);
	}
}

static void
catalogEntry(int fd, struct pcdir *dp, struct pcdir *longdp,
    int32_t currentCluster, int depth, char *recordPath, int *pathLen)
{
	if (dp->pcd_attr & PCA_LABEL) {
		storeInfoAboutLabel(dp);
	} else {
		storeInfoAboutEntry(fd, dp, longdp, depth, currentCluster,
		    recordPath, pathLen);
	}
}

/*
 * visitNodes()
 *
 * This is the main workhouse routine for traversing pcfs metadata.
 * There isn't a lot to the metadata.  Basically there is a root
 * directory somewhere (either in its own special place outside the
 * data area or in a data cluster).  The root directory (and all other
 * directories) are filled with a number of fixed size entries.  An
 * entry has the filename and extension, the file's attributes, the
 * file's size, and the starting data cluster of the storage allocated
 * to the file.  To determine which clusters are assigned to the file,
 * you start at the starting cluster entry in the FAT, and follow the
 * chain of entries in the FAT.
 *
 *	Arguments are:
 *	fd
 *		descriptor for accessing the raw file system data
 *	currentCluster
 *		original caller supplies the initial starting cluster,
 *		subsequent recursive calls are made with updated
 *		cluster numbers for the sub-directories.
 *	dirData
 *		pointer to the directory data bytes
 *	dirDataLen
 *		size of the whole buffer of data bytes (usually it is
 *		the size of a cluster, but the root directory on
 *		FAT12/16 is not necessarily the same size as a cluster).
 *	depth
 *		original caller should set it to zero (assuming they are
 *		starting from the root directory).  This number is used to
 *		change the indentation of file names presented as debug info.
 *	descend
 *		boolean indicates if we should descend into subdirectories.
 *	operation
 *		what, if any, matching should be performed.
 *		The PCFS_TRAVERSE_ALL operation is a depth first traversal
 *		of all nodes in the metadata tree, that tracks all the
 *		clusters in use (according to the meta-data, at least)
 *	matchRequired
 *		value to be matched (if any)
 *	found
 *		output parameter
 *		used to return pointer to a directory entry that matches
 *		the search requirement
 *		original caller should pass in a pointer to a NULL pointer.
 *	lastDirCluster
 *		output parameter
 *		if no match found, last cluster num of starting directory
 *	dirEnd
 *		output parameter
 *		if no match found, return parameter stores pointer to where
 *		new directory entry could be appended to existing directory
 *	recordPath
 *		output parameter
 *		as files are discovered, and directories traversed, this
 *		buffer is used to store the current full path name.
 *	pathLen
 *		output parameter
 *		this is in the integer length of the current full path name.
 */
static void
visitNodes(int fd, int32_t currentCluster, ClusterContents *dirData,
    int32_t dirDataLen, int depth, int descend, int operation,
    char matchRequired,  struct pcdir **found, int32_t *lastDirCluster,
    struct pcdir **dirEnd, char *recordPath, int *pathLen)
{
	struct pcdir *longdp = NULL;
	struct pcdir *dp;
	int32_t longStart;
	int withinLongName = 0;
	int saveLen = *pathLen;

	dp = dirData->dirp;

	/*
	 *  A directory entry where the first character of the name is
	 *  PCD_UNUSED indicates the end of the directory.
	 */
	while ((uchar_t *)dp < dirData->bytes + dirDataLen &&
	    dp->pcd_filename[0] != PCD_UNUSED) {
		/*
		 *  Handle the special case find operations.
		 */
		searchChecks(dp, operation, matchRequired, found);
		if (*found)
			break;
		/*
		 * Are we looking at part of a long file name entry?
		 * If so, we may need to note the start of the name.
		 * We don't do any further processing of long file
		 * name entries.
		 *
		 * We also skip deleted entries and the '.' and '..'
		 * entries.
		 */
		if ((dp->pcd_attr & PCDL_LFN_BITS) == PCDL_LFN_BITS) {
			if (!withinLongName) {
				withinLongName++;
				longStart = currentCluster;
				longdp = dp;
			}
			dp++;
			continue;
		} else if ((dp->pcd_filename[0] == PCD_ERASED) ||
		    (dp->pcd_filename[0] == '.')) {
			/*
			 * XXX - if we were within a long name, then
			 * its existence is bogus, because it is not
			 * attached to any real file.
			 */
			withinLongName = 0;
			dp++;
			continue;
		}
		withinLongName = 0;
		if (operation == PCFS_TRAVERSE_ALL)
			catalogEntry(fd, dp, longdp, longStart, depth,
			    recordPath, pathLen);
		longdp = NULL;
		longStart = 0;
		if (dp->pcd_attr & PCA_DIR && descend == PCFS_VISIT_SUBDIRS) {
			traverseDir(fd, extractStartCluster(dp), depth + 1,
			    descend, operation, matchRequired, found,
			    lastDirCluster, dirEnd, recordPath, pathLen);
			if (*found)
				break;
		}
		dp++;
		*pathLen = saveLen;
	}
	if (*found)
		return;
	if ((uchar_t *)dp < dirData->bytes + dirDataLen) {
		/*
		 * We reached the end of directory before the end of
		 * our provided data (a cluster).  That means this cluster
		 * is the last one in this directory's chain.  It also
		 * means we've just looked at the last directory entry.
		 */
		*lastDirCluster = currentCluster;
		*dirEnd = dp;
		return;
	}
	/*
	 * If there is more to the directory we'll go get it otherwise we
	 * are done traversing this directory.
	 */
	if ((currentCluster == FAKE_ROOTDIR_CLUST) ||
	    (lastInFAT(currentCluster))) {
		*lastDirCluster = currentCluster;
		return;
	} else {
		traverseDir(fd, nextInChain(currentCluster),
		    depth, descend, operation, matchRequired,
		    found, lastDirCluster, dirEnd, recordPath, pathLen);
		*pathLen = saveLen;
	}
}

/*
 *  traverseFromRoot()
 *	For use with 12 and 16 bit FATs that have a root directory outside
 *	of the file system.  This is a general purpose routine that
 *	can be used simply to visit all of the nodes in the metadata or
 *	to find the first instance of something, e.g., the first directory
 *	entry where the file is marked deleted.
 *
 *	Inputs are described in the commentary for visitNodes() above.
 */
void
traverseFromRoot(int fd, int depth, int descend, int operation,
    char matchRequired,  struct pcdir **found, int32_t *lastDirCluster,
    struct pcdir **dirEnd, char *recordPath, int *pathLen)
{
	visitNodes(fd, FAKE_ROOTDIR_CLUST, &TheRootDir, RootDirSize, depth,
	    descend, operation, matchRequired, found, lastDirCluster, dirEnd,
	    recordPath, pathLen);
}

/*
 *  traverseDir()
 *	For use with all FATs outside of the initial root directory on
 *	12 and 16 bit FAT file systems.  This is a general purpose routine
 *	that can be used simply to visit all of the nodes in the metadata or
 *	to find the first instance of something, e.g., the first directory
 *	entry where the file is marked deleted.
 *
 *	Unique Input is:
 *	startAt
 *		starting cluster of the directory
 *
 *	This is the cluster that is the first one in this directory.
 *	We read it right away, so we can provide it as data to visitNodes().
 *	Note that we cache this cluster as we read it, because it is
 *	metadata and we cache all metadata.  By doing so, we can
 *	keep pointers to directory entries for quickly moving around and
 *	fixing up any problems we find.  Of course if we get a big
 *	filesystem with a huge amount of metadata we may be hosed, as
 *	we'll likely run out of memory.
 *
 *	I believe in the future this will have to be addressed.  It
 *	may be possible to do more of the processing of problems
 *	within directories as they are cached, so that when memory
 *	runs short we can free cached directories we are already
 *	finished visiting.
 *
 *	The remainder of inputs are described in visitNodes() comments.
 */
void
traverseDir(int fd, int32_t startAt, int depth, int descend, int operation,
    char matchRequired,  struct pcdir **found, int32_t *lastDirCluster,
    struct pcdir **dirEnd, char *recordPath, int *pathLen)
{
	ClusterContents dirdata;
	int32_t dirdatasize = 0;

	if (startAt < FIRST_CLUSTER || startAt > LastCluster)
		return;

	if (readCluster(fd, startAt, &(dirdata.bytes), &dirdatasize,
	    RDCLUST_DO_CACHE) != RDCLUST_GOOD) {
		(void) fprintf(stderr,
		    gettext("Unable to get more directory entries!\n"));
		return;
	}

	if (operation == PCFS_TRAVERSE_ALL) {
		if (Verbose)
			(void) fprintf(stderr,
			    gettext("Directory traversal enters "
			    "allocation unit %d.\n"), startAt);
	}
	visitNodes(fd, startAt, &dirdata, dirdatasize, depth, descend,
	    operation, matchRequired, found, lastDirCluster, dirEnd,
	    recordPath, pathLen);
}

void
createCHKNameList(int fd)
{
	struct pcdir *ignorep1, *ignorep2;
	int32_t ignore32;
	char *ignorecp = NULL;
	char ignore = '\0';
	int ignoreint = 0;

	ignorep1 = ignorep2 = NULL;
	if (!OkayToRelink || CHKsList != NULL)
		return;

	/*
	 *  Allocate an array to keep a bit map of the integer
	 *  values used in CHK names.
	 */
	if ((CHKsList =
	    (uchar_t *)calloc(1, idivceil(MAXCHKVAL, NBBY))) == NULL) {
		OkayToRelink = 0;
		return;
	}

	/*
	 *  Search the root directory for all the files with names of
	 *  the form FILEXXXX.CHK.  The root directory is an area
	 *  outside of the file space on FAT12 and FAT16 file systems.
	 *  On FAT32 file systems, the root directory is in a file
	 *  area cluster just like any other directory.
	 */
	if (!IsFAT32) {
		traverseFromRoot(fd, 0, PCFS_NO_SUBDIRS, PCFS_FIND_CHKS,
		    ignore, &ignorep1, &ignore32, &ignorep2, ignorecp,
		    &ignoreint);
	} else {
		DirCount++;
		traverseDir(fd, TheBIOSParameterBlock.bpb32.root_dir_clust,
		    0, PCFS_NO_SUBDIRS, PCFS_FIND_CHKS, ignore,
		    &ignorep1, &ignore32, &ignorep2, ignorecp, &ignoreint);
	}
}


char *
nextAvailableCHKName(int *chosen)
{
	static char nameBuf[PCFNAMESIZE];
	int i;

	if (!OkayToRelink)
		return (NULL);

	nameBuf[CHKNAME_F] = 'F';
	nameBuf[CHKNAME_I] = 'I';
	nameBuf[CHKNAME_L] = 'L';
	nameBuf[CHKNAME_E] = 'E';

	for (i = 1; i <= MAXCHKVAL; i++) {
		if (!inUseCHKName(i))
			break;
	}
	if (i <= MAXCHKVAL) {
		nameBuf[CHKNAME_THOUSANDS] = '0' + (i / 1000);
		nameBuf[CHKNAME_HUNDREDS] = '0' + ((i % 1000) / 100);
		nameBuf[CHKNAME_TENS] = '0' + ((i % 100) / 10);
		nameBuf[CHKNAME_ONES] = '0' + (i % 10);
		*chosen = i;
		return (nameBuf);
	} else {
		(void) fprintf(stderr,
		    gettext("Sorry, no names available for "
		    "relinking orphan chains!\n"));
		OkayToRelink = 0;
		return (NULL);
	}
}

uint32_t
extractSize(struct pcdir *dp)
{
	uint32_t returnMe;

	read_32_bits((uchar_t *)&(dp->pcd_size), &returnMe);
	return (returnMe);
}

int32_t
extractStartCluster(struct pcdir *dp)
{
	uint32_t lo, hi;

	if (IsFAT32) {
		read_16_bits((uchar_t *)&(dp->un.pcd_scluster_hi), &hi);
		read_16_bits((uchar_t *)&(dp->pcd_scluster_lo), &lo);
		return ((int32_t)((hi << 16) | lo));
	} else {
		read_16_bits((uchar_t *)&(dp->pcd_scluster_lo), &lo);
		return ((int32_t)lo);
	}
}

static struct pcdir *
findAvailableRootDirEntSlot(int fd, int32_t *clusterWithSlot)
{
	struct pcdir *deletedEntry = NULL;
	struct pcdir *appendPoint = NULL;
	char *ignorecp = NULL;
	int ignore = 0;

	*clusterWithSlot = 0;

	/*
	 *  First off, try to find an erased entry in the root
	 *  directory.  The root directory is an area outside of the
	 *  file space on FAT12 and FAT16 file systems.  On FAT32 file
	 *  systems, the root directory is in a file area cluster just
	 *  like any other directory.
	 */
	if (!IsFAT32) {
		traverseFromRoot(fd, 0, PCFS_NO_SUBDIRS, PCFS_FIND_STATUS,
		    PCD_ERASED, &deletedEntry, clusterWithSlot,
		    &appendPoint, ignorecp, &ignore);
	} else {
		DirCount++;
		traverseDir(fd, TheBIOSParameterBlock.bpb32.root_dir_clust,
		    0, PCFS_NO_SUBDIRS, PCFS_FIND_STATUS, PCD_ERASED,
		    &deletedEntry, clusterWithSlot, &appendPoint, ignorecp,
		    &ignore);
	}
	/*
	 *  If we found a deleted file in the directory we'll overwrite
	 *  that entry.
	 */
	if (deletedEntry)
		return (deletedEntry);
	/*
	 *  If there is room at the end of the existing directory, we
	 *  should place the new entry there.
	 */
	if (appendPoint)
		return (appendPoint);
	/*
	 *  XXX need to grow the directory
	 */
	return (NULL);
}

static void
insertDirEnt(struct pcdir *slot, struct pcdir *entry, int32_t clusterWithSlot)
{
	(void) memcpy(slot, entry, sizeof (struct pcdir));
	markClusterModified(clusterWithSlot);
}

/*
 *  Convert current UNIX time into a PCFS timestamp (which is in local time).
 *
 *  Since the "seconds" field of that is only accurate to 2sec precision,
 *  we allow for the optional (used only for creation times on FAT) "msec"
 *  parameter that takes the fractional part.
 */
static void
getNow(struct pctime *pctp, uchar_t *msec)
{
	time_t		now;
	struct tm	tm;
	ushort_t	tim, dat;

	/*
	 * Disable daylight savings corrections - Solaris PCFS doesn't
	 * support such conversions yet. Save timestamps in local time.
	 */
	daylight = 0;

	(void) time(&now);
	(void) localtime_r(&now, &tm);

	dat = (tm.tm_year - 80) << YEARSHIFT;
	dat |= tm.tm_mon << MONSHIFT;
	dat |= tm.tm_mday << DAYSHIFT;
	tim = tm.tm_hour << HOURSHIFT;
	tim |= tm.tm_min << MINSHIFT;
	tim |= (tm.tm_sec / 2) << SECSHIFT;

	/*
	 * Sanity check. If we overflow the PCFS timestamp range
	 * we set the time to 01/01/1980, 00:00:00
	 */
	if (dat < 80 || dat > 227)
		dat = tim = 0;

	pctp->pct_date = LE_16(dat);
	pctp->pct_time = LE_16(tim);
	if (msec)
		*msec = (tm.tm_sec & 1) ? 100 : 0;
}

/*
 *  FAT file systems store the following time information in a directory
 *  entry:
 *		timestamp		member of "struct pcdir"
 * ======================================================================
 *		creation time		pcd_crtime.pct_time
 *		creation date		pcd_crtime.pct_date
 *		last access date	pcd_ladate
 *		last modify time	pcd_mtime.pct_time
 *		last modify date	pcd_mtime.pct_date
 *
 *  No access time is kept.
 */
static void
updateDirEnt_CreatTime(struct pcdir *dp)
{
	getNow(&dp->pcd_crtime, &dp->pcd_crtime_msec);
	markClusterModified(findImpactedCluster(dp));
}

static void
updateDirEnt_ModTimes(struct pcdir *dp)
{
	timestruc_t	ts;

	getNow(&dp->pcd_mtime, NULL);
	dp->pcd_ladate = dp->pcd_mtime.pct_date;
	dp->pcd_attr |= PCA_ARCH;
	markClusterModified(findImpactedCluster(dp));
}

struct pcdir *
addRootDirEnt(int fd, struct pcdir *new)
{
	struct pcdir *added;
	int32_t inCluster;

	if ((added = findAvailableRootDirEntSlot(fd, &inCluster)) != NULL) {
		insertDirEnt(added, new, inCluster);
		return (added);
	}
	return (NULL);
}

/*
 *  FAT12 and FAT16 have a root directory outside the normal file space,
 *  so we have separate routines for finding and reading the root directory.
 */
static off64_t
seekRootDirectory(int fd)
{
	off64_t seekto;

	/*
	 *  The RootDir immediately follows the FATs, which in
	 *  turn immediately follow the reserved sectors.
	 */
	seekto = (off64_t)TheBIOSParameterBlock.bpb.resv_sectors *
		    TheBIOSParameterBlock.bpb.bytes_per_sector +
		    (off64_t)FATSize * TheBIOSParameterBlock.bpb.num_fats +
		    (off64_t)PartitionOffset;
	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Seeking root directory @%lld.\n"), seekto);
	return (lseek64(fd, seekto, SEEK_SET));
}

void
getRootDirectory(int fd)
{
	ssize_t bytesRead;

	if (TheRootDir.bytes != NULL)
		return;
	else if ((TheRootDir.bytes = (uchar_t *)malloc(RootDirSize)) == NULL) {
		mountSanityCheckFails();
		perror(gettext("No memory for a copy of the root directory"));
		(void) close(fd);
		exit(8);
	}

	if (seekRootDirectory(fd) < 0) {
		mountSanityCheckFails();
		perror(gettext("Cannot seek to RootDir"));
		(void) close(fd);
		exit(8);
	}

	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Reading root directory.\n"));
	if ((bytesRead = read(fd, TheRootDir.bytes, RootDirSize)) !=
	    RootDirSize) {
		mountSanityCheckFails();
		if (bytesRead < 0) {
			perror(gettext("Cannot read a RootDir"));
		} else {
			(void) fprintf(stderr,
			    gettext("Short read of RootDir\n"));
		}
		(void) close(fd);
		exit(8);
	}
	if (Verbose) {
		(void) fprintf(stderr,
		    gettext("Dump of root dir's first 256 bytes.\n"));
		header_for_dump();
		dump_bytes(TheRootDir.bytes, 256);
	}
}

void
writeRootDirMods(int fd)
{
	ssize_t bytesWritten;

	if (!TheRootDir.bytes) {
		(void) fprintf(stderr,
		    gettext("Internal error: No Root directory to write\n"));
		(void) close(fd);
		exit(12);
	}
	if (!RootDirModified) {
		if (Verbose) {
			(void) fprintf(stderr,
			    gettext("No root directory changes need to "
			    "be written.\n"));
		}
		return;
	}
	if (ReadOnly)
		return;
	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Writing root directory.\n"));
	if (seekRootDirectory(fd) < 0) {
		perror(gettext("Cannot write the RootDir (seek failed)"));
		(void) close(fd);
		exit(12);
	}
	if ((bytesWritten = write(fd, TheRootDir.bytes, RootDirSize)) !=
	    RootDirSize) {
		if (bytesWritten < 0) {
			perror(gettext("Cannot write the RootDir"));
		} else {
			(void) fprintf(stderr,
			    gettext("Short write of root directory\n"));
		}
		(void) close(fd);
		exit(12);
	}
	RootDirModified = 0;
}

struct pcdir *
newDirEnt(struct pcdir *copyme)
{
	struct pcdir *ndp;

	if ((ndp = (struct pcdir *)calloc(1, sizeof (struct pcdir))) == NULL) {
		(void) fprintf(stderr, gettext("Out of memory to create a "
		    "new directory entry!\n"));
		return (ndp);
	}
	if (copyme)
		(void) memcpy(ndp, copyme, sizeof (struct pcdir));
	ndp->pcd_ext[CHKNAME_C] = 'C';
	ndp->pcd_ext[CHKNAME_H] = 'H';
	ndp->pcd_ext[CHKNAME_K] = 'K';
	updateDirEnt_CreatTime(ndp);
	updateDirEnt_ModTimes(ndp);
	return (ndp);
}

void
updateDirEnt_Size(struct pcdir *dp, uint32_t newSize)
{
	uchar_t *p = (uchar_t *)&(dp->pcd_size);
	store_32_bits(&p, newSize);
	markClusterModified(findImpactedCluster(dp));
}

void
updateDirEnt_Start(struct pcdir *dp, int32_t newStart)
{
	uchar_t *p = (uchar_t *)&(dp->pcd_scluster_lo);
	store_16_bits(&p, newStart & 0xffff);
	if (IsFAT32) {
		p = (uchar_t *)&(dp->un.pcd_scluster_hi);
		store_16_bits(&p, newStart >> 16);
	}
	markClusterModified(findImpactedCluster(dp));
}

void
updateDirEnt_Name(struct pcdir *dp, char *newName)
{
	int i;

	for (i = 0; i < PCFNAMESIZE; i++) {
		if (*newName)
			dp->pcd_filename[i] = *newName++;
		else
			dp->pcd_filename[i] = ' ';
	}
	markClusterModified(findImpactedCluster(dp));
}
