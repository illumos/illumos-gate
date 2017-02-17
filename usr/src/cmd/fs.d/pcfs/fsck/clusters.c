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
 * Copyright (c) 1999,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fsck_pcfs -- routines for manipulating clusters.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libintl.h>
#include <errno.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_label.h>
#include "pcfs_common.h"
#include "fsck_pcfs.h"

extern	ClusterContents	TheRootDir;
extern	off64_t		FirstClusterOffset;
extern	off64_t		PartitionOffset;
extern	int32_t		BytesPerCluster;
extern	int32_t		TotalClusters;
extern	int32_t		LastCluster;
extern	int32_t		RootDirSize;
extern	int32_t		FATSize;
extern	bpb_t		TheBIOSParameterBlock;
extern	short		FATEntrySize;
extern	int		RootDirModified;
extern	int		OkayToRelink;
extern	int		ReadOnly;
extern	int		IsFAT32;
extern	int		Verbose;

static	struct pcdir	BlankPCDIR;
static	CachedCluster	*ClusterCache;
static	ClusterInfo	**InUse;
static	int32_t		ReservedClusterCount;
static	int32_t		AllocedClusterCount;
static	int32_t		FreeClusterCount;
static	int32_t		BadClusterCount;

/*
 * Internal statistics
 */
static	int32_t		CachedClusterCount;

int32_t	HiddenClusterCount;
int32_t	FileClusterCount;
int32_t	DirClusterCount;
int32_t	HiddenFileCount;
int32_t	FileCount;
int32_t	DirCount;

static int32_t orphanSizeLookup(int32_t clusterNum);

static void
freeNameInfo(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;
	if (InUse[clusterNum - FIRST_CLUSTER]->path != NULL) {
		if (InUse[clusterNum - FIRST_CLUSTER]->path->references > 1) {
			InUse[clusterNum - FIRST_CLUSTER]->path->references--;
		} else {
			free(InUse[clusterNum - FIRST_CLUSTER]->path->fullName);
			free(InUse[clusterNum - FIRST_CLUSTER]->path);
		}
		InUse[clusterNum - FIRST_CLUSTER]->path = NULL;
	}
}

static void
printOrphanPath(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;
	if (InUse[clusterNum - FIRST_CLUSTER]->path != NULL) {
		(void) printf(gettext("\nOrphaned allocation units originally "
		    "allocated to:\n"));
		(void) printf("%s\n",
		    InUse[clusterNum - FIRST_CLUSTER]->path->fullName);
		freeNameInfo(clusterNum);
	} else {
		(void) printf(gettext("\nOrphaned allocation units originally "
		    "allocated to an unknown file or directory:\n"));
		(void) printf(gettext("Orphaned chain begins with allocation "
		    "unit %d.\n"), clusterNum);
	}
}

static void
printOrphanSize(int32_t clusterNum)
{
	int32_t size = orphanSizeLookup(clusterNum);

	if (size > 0) {
		(void) printf(gettext("%d bytes in the orphaned chain of "
		    "allocation units.\n"), size);
		if (Verbose) {
			(void) printf(gettext("[Starting at allocation "
			    "unit %d]\n"), clusterNum);
		}
	}
}

static void
printOrphanInfo(int32_t clusterNum)
{
	printOrphanPath(clusterNum);
	printOrphanSize(clusterNum);
}

static int
askAboutFreeing(int32_t clusterNum)
{
	/*
	 * If it is not OkayToRelink, we haven't already printed the size
	 * of the orphaned chain.
	 */
	if (!OkayToRelink)
		printOrphanInfo(clusterNum);
	/*
	 *  If we are in preen mode, preenBail won't return.
	 */
	preenBail("Need user confirmation to free orphaned chain.\n");

	(void) printf(
	    gettext("Free the allocation units in the orphaned chain ? "
	    "(y/n) "));
	return (yes());
}

static int
askAboutRelink(int32_t clusterNum)
{
	/*
	 * Display the size of the chain for the user to consider.
	 */
	printOrphanInfo(clusterNum);
	/*
	 *  If we are in preen mode, preenBail won't return.
	 */
	preenBail("Need user confirmation to re-link orphaned chain.\n");

	(void) printf(gettext("Re-link orphaned chain into file system ? "
	    "(y/n) "));

	return (yes());
}

static int
isHidden(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (0);

	if (InUse[clusterNum - FIRST_CLUSTER] == NULL)
		return (0);

	return (InUse[clusterNum - FIRST_CLUSTER]->flags & CLINFO_HIDDEN);
}

static int
isInUse(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (0);

	return ((InUse[clusterNum - FIRST_CLUSTER] != NULL) &&
		(InUse[clusterNum - FIRST_CLUSTER]->dirent != NULL));
}

/*
 *  Caller's may request that we cache the data from a readCluster.
 *  The xxxClusterxxxCachexxx routines handle looking for cached data
 *  or initially caching the data.
 *
 *  XXX - facilitate releasing cached data for low memory situations.
 */
static CachedCluster *
findClusterCacheEntry(int32_t clusterNum)
{
	CachedCluster *loop = ClusterCache;

	while (loop != NULL) {
		if (loop->clusterNum == clusterNum)
			return (loop);
		loop = loop->next;
	}
	return (NULL);
}

static uchar_t *
findClusterDataInTheCache(int32_t clusterNum)
{
	CachedCluster *loop = ClusterCache;

	while (loop) {
		if (loop->clusterNum == clusterNum)
			return (loop->clusterData.bytes);
		loop = loop->next;
	}
	return (NULL);
}

static uchar_t *
addToCache(int32_t clusterNum, uchar_t *buf, int32_t *datasize)
{
	CachedCluster *new;
	uchar_t *cp;

	if ((new = (CachedCluster *)malloc(sizeof (CachedCluster))) == NULL) {
		perror(gettext("No memory for cached cluster info"));
		return (buf);
	}
	new->clusterNum = clusterNum;
	new->modified = 0;

	if ((cp = (uchar_t *)calloc(1, BytesPerCluster)) == NULL) {
		perror(gettext("No memory for cached copy of cluster"));
		free(new);
		return (buf);
	}
	(void) memcpy(cp, buf, *datasize);
	new->clusterData.bytes = cp;

	if (Verbose) {
		(void) fprintf(stderr,
		    gettext("Allocation unit %d cached.\n"), clusterNum);
	}
	if (ClusterCache == NULL) {
		ClusterCache = new;
		new->next = NULL;
	} else if (new->clusterNum < ClusterCache->clusterNum) {
		new->next = ClusterCache;
		ClusterCache = new;
	} else {
		CachedCluster *loop = ClusterCache;
		CachedCluster *trailer = NULL;

		while (loop && new->clusterNum > loop->clusterNum) {
			trailer = loop;
			loop = loop->next;
		}
		trailer->next = new;
		if (loop) {
			new->next = loop;
		} else {
			new->next = NULL;
		}
	}
	CachedClusterCount++;
	return (new->clusterData.bytes);
}

static int
seekCluster(int fd, int32_t clusterNum)
{
	off64_t seekto;
	int saveError;

	seekto = FirstClusterOffset +
	    ((off64_t)clusterNum - FIRST_CLUSTER) * BytesPerCluster;
	if (lseek64(fd, seekto, SEEK_SET) != seekto) {
		saveError = errno;
		(void) fprintf(stderr,
		    gettext("Seek to Allocation unit #%d failed: "),
		    clusterNum);
		(void) fprintf(stderr, strerror(saveError));
		(void) fprintf(stderr, "\n");
		return (0);
	}
	return (1);
}

/*
 *  getcluster
 *	Get cluster bytes off the disk.  We always read those bytes into
 *	the same static buffer.  If the caller wants its own copy of the
 *	data it'll have to make its own copy.  We'll return all the data
 *	read, even if it's short of a full cluster.  This is for future use
 *	when we might want to relocate any salvagable data from bad clusters.
 */
static int
getCluster(int fd, int32_t clusterNum, uchar_t **data, int32_t *datasize)
{
	static uchar_t *clusterBuffer = NULL;
	int saveError;
	int try;

	*datasize = 0;
	*data = NULL;

	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (RDCLUST_BADINPUT);

	if (clusterBuffer == NULL &&
	    (clusterBuffer = (uchar_t *)malloc(BytesPerCluster)) == NULL) {
		perror(gettext("No memory for a cluster data buffer"));
		return (RDCLUST_MEMERR);
	}

	for (try = 0; try < RDCLUST_MAX_RETRY; try++) {
		if (!seekCluster(fd, clusterNum))
			return (RDCLUST_FAIL);
		if ((*datasize = read(fd, clusterBuffer, BytesPerCluster)) ==
		    BytesPerCluster) {
			*data = clusterBuffer;
			return (RDCLUST_GOOD);
		}
	}
	if (*datasize >= 0) {
		*data = clusterBuffer;
		(void) fprintf(stderr,
		    gettext("Short read of allocation unit #%d\n"), clusterNum);
	} else {
		saveError = errno;
		(void) fprintf(stderr, "Allocation unit %d:", clusterNum);
		(void) fprintf(stderr, strerror(saveError));
		(void) fprintf(stderr, "\n");
	}
	return (RDCLUST_FAIL);
}

static void
writeCachedCluster(int fd, CachedCluster *clustInfo)
{
	ssize_t bytesWritten;

	if (ReadOnly)
		return;

	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Allocation unit %d modified.\n"),
		    clustInfo->clusterNum);

	if (seekCluster(fd, clustInfo->clusterNum) == NULL)
		return;

	if ((bytesWritten = write(fd, clustInfo->clusterData.bytes,
	    BytesPerCluster)) != BytesPerCluster) {
		if (bytesWritten < 0) {
			perror(gettext("Failed to write modified "
			    "allocation unit"));
		} else {
			(void) fprintf(stderr,
			    gettext("Short write of allocation unit %d\n"),
			    clustInfo->clusterNum);
		}
		(void) close(fd);
		exit(13);
	}
}

/*
 * It's cheaper to allocate a lot at a time; malloc overhead pushes
 * you over the brink much more quickly if you don't.
 * This numbers seems to be a fair trade-off between reduced malloc overhead
 * and additional overhead by over-allocating.
 */

#define	CHUNKSIZE	1024

static ClusterInfo *pool;

static ClusterInfo *
newClusterInfo(void)
{

	ClusterInfo *ret;

	if (pool == NULL) {
		int i;

		pool = (ClusterInfo *)malloc(sizeof (ClusterInfo) * CHUNKSIZE);

		if (pool == NULL) {
			perror(
			    gettext("Out of memory for cluster information"));
			exit(9);
		}

		for (i = 0; i < CHUNKSIZE - 1; i++)
			pool[i].nextfree = &pool[i+1];

		pool[CHUNKSIZE-1].nextfree = NULL;
	}
	ret = pool;
	pool = pool->nextfree;

	memset(ret, 0, sizeof (*ret));

	return (ret);
}

/* Should be called with verified arguments */

static ClusterInfo *
cloneClusterInfo(int32_t clusterNum)
{
	ClusterInfo *cl = InUse[clusterNum - FIRST_CLUSTER];

	if (cl->refcnt > 1) {
		ClusterInfo *newCl = newClusterInfo();
		cl->refcnt--;
		*newCl = *cl;
		newCl->refcnt = 1;
		if (newCl->path)
			newCl->path->references++;
		InUse[clusterNum - FIRST_CLUSTER] = newCl;
	}
	return (InUse[clusterNum - FIRST_CLUSTER]);
}

static void
updateFlags(int32_t clusterNum, int newflags)
{
	ClusterInfo *cl = InUse[clusterNum - FIRST_CLUSTER];

	if (cl->flags != newflags && cl->refcnt > 1)
		cl = cloneClusterInfo(clusterNum);

	cl->flags = newflags;
}

static void
freeClusterInfo(ClusterInfo *old)
{
	if (--old->refcnt <= 0) {
		if (old->path && --old->path->references <= 0) {
			free(old->path->fullName);
			free(old->path);
		}
		old->nextfree = pool;
		pool = old;
	}
}

/*
 * Allocate entries in our sparse array of cluster information.
 * Returns non-zero if the structure already has been allocated
 * (for those keeping score at home).
 *
 * The template parameter, if non-NULL, is used to facilitate sharing
 * the ClusterInfo nodes for the clusters belonging to the same file.
 * The first call to allocInUse for a new file should have *template
 * set to 0; on return, *template then points to the newly allocated
 * ClusterInfo.  Second and further calls keep the same value
 * in *template and that ClusterInfo ndoe is then used for all
 * entries in the file.  Code that modifies the ClusterInfo nodes
 * should take care proper sharing semantics are maintained (i.e.,
 * copy-on-write using cloneClusterInfo())
 *
 * The ClusterInfo used in the template is guaranted to be in use in
 * at least one other cluster as we never return a value if we didn't
 * set it first.  So we can overwrite it without the possibility of a leak.
 */
static int
allocInUse(int32_t clusterNum, ClusterInfo **template)
{
	ClusterInfo *newCl;

	if (InUse[clusterNum - FIRST_CLUSTER] != NULL)
		return (CLINFO_PREVIOUSLY_ALLOCED);

	if (template != NULL && *template != NULL)
		newCl = *template;
	else {
		newCl = newClusterInfo();
		if (template)
			*template = newCl;
	}

	InUse[clusterNum - FIRST_CLUSTER] = newCl;
	newCl->refcnt++;

	return (CLINFO_NEWLY_ALLOCED);
}

static void
markFree(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;

	if (InUse[clusterNum - FIRST_CLUSTER]) {
		if (InUse[clusterNum - FIRST_CLUSTER]->saved)
			free(InUse[clusterNum - FIRST_CLUSTER]->saved);
		freeClusterInfo(InUse[clusterNum - FIRST_CLUSTER]);
		InUse[clusterNum - FIRST_CLUSTER] = NULL;
	}
}

static void
markOrphan(int fd, int32_t clusterNum, struct pcdir *dp)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;

	(void) markInUse(fd, clusterNum, dp, NULL, 0, VISIBLE, NULL);
	if (InUse[clusterNum - FIRST_CLUSTER] != NULL)
		updateFlags(clusterNum,
		    InUse[clusterNum - FIRST_CLUSTER]->flags | CLINFO_ORPHAN);
}

static void
markBad(int32_t clusterNum, uchar_t *recovered, int32_t recoveredLen)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;

	(void) allocInUse(clusterNum, NULL);

	if (recoveredLen) {
		(void) cloneClusterInfo(clusterNum);
		InUse[clusterNum - FIRST_CLUSTER]->saved = recovered;
	}
	updateFlags(clusterNum,
	    InUse[clusterNum - FIRST_CLUSTER]->flags | CLINFO_BAD);

	BadClusterCount++;
	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Allocation unit %d marked bad.\n"), clusterNum);
}

static void
clearOrphan(int32_t c)
{
	/* silent failure for bogus clusters */
	if (c < FIRST_CLUSTER || c > LastCluster)
		return;
	if (InUse[c - FIRST_CLUSTER] != NULL)
		updateFlags(c,
		    InUse[c - FIRST_CLUSTER]->flags & ~CLINFO_ORPHAN);
}

static void
clearInUse(int32_t c)
{
	ClusterInfo **clp;

	/* silent failure for bogus clusters */
	if (c < FIRST_CLUSTER || c > LastCluster)
		return;

	clp = &InUse[c - FIRST_CLUSTER];
	if (*clp != NULL) {
		freeClusterInfo(*clp);
		*clp = NULL;
	}
}

static void
clearAllClusters_InUse()
{
	int32_t cc;
	for (cc = FIRST_CLUSTER; cc < LastCluster; cc++) {
		clearInUse(cc);
	}
}

static void
makeUseTable(void)
{
	if (InUse != NULL) {
		clearAllClusters_InUse();
		return;
	}
	if ((InUse = (ClusterInfo **)
	    calloc(TotalClusters, sizeof (ClusterInfo *))) == NULL) {
		perror(gettext("No memory for internal table"));
		exit(9);
	}
}

static void
countClusters(void)
{
	int32_t c;

	BadClusterCount = HiddenClusterCount =
	    AllocedClusterCount = FreeClusterCount = 0;

	for (c = FIRST_CLUSTER; c < LastCluster; c++) {
		if (badInFAT(c)) {
			BadClusterCount++;
		} else if (isMarkedBad(c)) {
			/*
			 * This catches the bad sectors found
			 * during thorough verify that have never been
			 * allocated to a file.  Without this check, we
			 * count these guys as free.
			 */
			BadClusterCount++;
			markBadInFAT(c);
		} else if (isHidden(c)) {
			HiddenClusterCount++;
		} else if (isInUse(c)) {
			AllocedClusterCount++;
		} else {
			FreeClusterCount++;
		}
	}
}

/*
 * summarizeFAT
 *	Mark orphans without directory entries as allocated.
 *	XXX - these chains should be reclaimed!
 *	XXX - merge this routine with countClusters (same loop, duh.)
 */
static void
summarizeFAT(int fd)
{
	int32_t c;
	ClusterInfo *tmpl = NULL;

	for (c = FIRST_CLUSTER; c < LastCluster; c++) {
		if (!freeInFAT(c) && !badInFAT(c) && !reservedInFAT(c) &&
		    !isInUse(c)) {
			(void) markInUse(fd, c, &BlankPCDIR, NULL, 0, VISIBLE,
				&tmpl);
		}
	}
}

static void
getReadyToSearch(int fd)
{
	getFAT(fd);
	if (!IsFAT32)
		getRootDirectory(fd);
}


static char PathName[MAXPATHLEN];

static void
summarize(int fd, int includeFAT)
{
	struct pcdir *ignorep1, *ignorep2 = NULL;
	int32_t ignore32;
	char ignore;
	int pathlen;

	ReservedClusterCount = 0;
	AllocedClusterCount = 0;
	HiddenClusterCount = 0;
	FileClusterCount = 0;
	FreeClusterCount = 0;
	DirClusterCount = 0;
	BadClusterCount = 0;
	HiddenFileCount = 0;
	FileCount = 0;
	DirCount = 0;
	ignorep1 = ignorep2 = NULL;
	ignore = '\0';

	PathName[0] = '\0';
	pathlen = 0;

	getReadyToSearch(fd);
	/*
	 *  Traverse the full meta-data tree to talley what clusters
	 * are in use.  The root directory is an area outside of the
	 * file space on FAT12 and FAT16 file systems.  On FAT32 file
	 * systems, the root directory is in a file area cluster just
	 * like any other directory.
	 */
	if (!IsFAT32) {
		traverseFromRoot(fd, 0, PCFS_VISIT_SUBDIRS, PCFS_TRAVERSE_ALL,
		    ignore, &ignorep1, &ignore32, &ignorep2, PathName,
		    &pathlen);
	} else {
		DirCount++;
		traverseDir(fd, TheBIOSParameterBlock.bpb32.root_dir_clust,
		    0, PCFS_VISIT_SUBDIRS, PCFS_TRAVERSE_ALL, ignore,
		    &ignorep1, &ignore32, &ignorep2, PathName, &pathlen);
	}

	if (includeFAT)
		summarizeFAT(fd);
	countClusters();
}

int
isMarkedBad(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (0);

	if (InUse[clusterNum - FIRST_CLUSTER] == NULL)
		return (0);

	return (InUse[clusterNum - FIRST_CLUSTER]->flags & CLINFO_BAD);
}

static int
isMarkedOrphan(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (0);

	if (InUse[clusterNum - FIRST_CLUSTER] == NULL)
		return (0);

	return (InUse[clusterNum - FIRST_CLUSTER]->flags & CLINFO_ORPHAN);
}

static void
orphanChain(int fd, int32_t c, struct pcdir *ndp)
{
	ClusterInfo *tmpl = NULL;

	/* silent failure for bogus clusters */
	if (c < FIRST_CLUSTER || c > LastCluster)
		return;
	clearInUse(c);
	markOrphan(fd, c, ndp);
	c = nextInChain(c);
	while (c != 0) {
		clearInUse(c);
		clearOrphan(c);
		(void) markInUse(fd, c, ndp, NULL, 0, VISIBLE, &tmpl);
		c = nextInChain(c);
	}
}

static int32_t
findAFreeCluster(int32_t startAt)
{
	int32_t look = startAt;

	for (;;) {
		if (freeInFAT(look)) {
			break;
		}
		if (look == LastCluster)
			look = FIRST_CLUSTER;
		else
			look++;
		if (look == startAt)
			break;
	}
	if (look != startAt)
		return (look);
	else
		return (0);
}

static void
setEndOfDirectory(struct pcdir *dp)
{
	dp->pcd_filename[0] = PCD_UNUSED;
}

static void
emergencyEndOfDirectory(int fd, int32_t secondToLast)
{
	ClusterContents dirdata;
	int32_t dirdatasize = 0;

	if (readCluster(fd, secondToLast, &(dirdata.bytes), &dirdatasize,
	    RDCLUST_DO_CACHE) != RDCLUST_GOOD) {
		(void) fprintf(stderr,
		    gettext("Unable to read allocation unit %d.\n"),
		    secondToLast);
		(void) fprintf(stderr,
		    gettext("Cannot allocate a new allocation unit to hold an"
		    " end-of-directory marker.\nCannot access allocation unit"
		    " to overwrite existing directory entry with\nthe marker."
		    "  Needed directory truncation has failed.  Giving up.\n"));
		(void) close(fd);
		exit(11);
	}
	setEndOfDirectory(dirdata.dirp);
	markClusterModified(secondToLast);
}

static void
makeNewEndOfDirectory(struct pcdir *entry, int32_t secondToLast,
    int32_t newCluster, ClusterContents *newData)
{
	setEndOfDirectory(newData->dirp);
	markClusterModified(newCluster);
	/*
	 *  There are two scenarios.  One is that we truncated the
	 *  directory in the very beginning.  The other is that we
	 *  truncated it in the middle or at the end.  In the first
	 *  scenario, the secondToLast argument is not a valid cluster
	 *  (it's zero), and so we actually need to change the start
	 *  cluster for the directory to this new start cluster.  In
	 *  the second scenario, the secondToLast cluster we received
	 *  as an argument needs to be pointed at the new end of
	 *  directory.
	 */
	if (secondToLast == 0) {
		updateDirEnt_Start(entry, newCluster);
	} else {
		writeFATEntry(secondToLast, newCluster);
	}
	markLastInFAT(newCluster);
}

static void
createNewEndOfDirectory(int fd, struct pcdir *entry, int32_t secondToLast)
{
	ClusterContents dirdata;
	int32_t dirdatasize = 0;
	int32_t freeCluster;

	if (((freeCluster = findAFreeCluster(secondToLast)) != 0)) {
		if (readCluster(fd, freeCluster, &(dirdata.bytes),
		    &dirdatasize, RDCLUST_DO_CACHE) == RDCLUST_GOOD) {
			if (Verbose) {
				(void) fprintf(stderr,
				    gettext("Grabbed allocation unit #%d "
				    "for truncated\ndirectory's new end "
				    "of directory.\n"), freeCluster);
			}
			makeNewEndOfDirectory(entry, secondToLast,
			    freeCluster, &dirdata);
			return;
		}
	}
	if (secondToLast == 0) {
		if (freeCluster == 0) {
			(void) fprintf(stderr, gettext("File system full.\n"));
		} else {
			(void) fprintf(stderr,
			    gettext("Unable to read allocation unit %d.\n"),
			    freeCluster);
		}
		(void) fprintf(stderr,
		    gettext("Cannot allocate a new allocation unit to hold "
		    "an end-of-directory marker.\nNo existing directory "
		    "entries can be overwritten with the marker,\n"
		    "the only unit allocated to the directory is "
		    "inaccessible.\nNeeded directory truncation has failed.  "
		    "Giving up.\n"));
		(void) close(fd);
		exit(11);
	}
	emergencyEndOfDirectory(fd, secondToLast);
}

/*
 * truncAtCluster
 *	Given a directory entry and a cluster number, search through
 *	the cluster chain for the entry and make the cluster previous
 *	to the given cluster in the chain the last cluster in the file.
 *	The number of orphaned bytes is returned.  For a chain that's
 *	a directory we need to do some special handling, since we'll be
 *	getting rid of the end of directory notice by truncating.
 */
static int64_t
truncAtCluster(int fd, struct pcdir *entry, int32_t cluster)
{
	uint32_t oldSize, newSize;
	int32_t prev, count, follow;
	int dir = (entry->pcd_attr & PCA_DIR);

	prev = 0; count = 0;
	follow = extractStartCluster(entry);
	while (follow != cluster && follow >= FIRST_CLUSTER &&
	    follow <= LastCluster) {
		prev = follow;
		count++;
		follow = nextInChain(follow);
	}
	if (follow != cluster) {
		/*
		 *  We didn't find the cluster they wanted to trunc at
		 *  anywhere in the entry's chain.  So we'll leave the
		 *  entry alone, and return a negative value so they
		 *  can know something is wrong.
		 */
		return (-1);
	}
	if (Verbose) {
		(void) fprintf(stderr,
		    gettext("Chain truncation at unit #%d\n"), cluster);
	}
	if (!dir) {
		oldSize = extractSize(entry);
		newSize = count *
		    TheBIOSParameterBlock.bpb.sectors_per_cluster *
		    TheBIOSParameterBlock.bpb.bytes_per_sector;
		if (newSize == 0)
			updateDirEnt_Start(entry, 0);
	} else {
		newSize = 0;
	}
	updateDirEnt_Size(entry, newSize);
	if (dir) {
		createNewEndOfDirectory(fd, entry, prev);
	} else if (prev != 0) {
		markLastInFAT(prev);
	}
	if (dir) {
		/*
		 * We don't really know what the size of a directory is
		 * but it is important for us to know if this truncation
		 * results in an orphan with any size.  The value we
		 * return from this routine for a normal file is the
		 * number of bytes left in the chain.  For a directory
		 * we can't be exact, and the caller doesn't really
		 * expect us to be.  For a directory the caller only
		 * cares if there are zero bytes left or more than
		 * zero bytes left.  We'll return 1 to indicate
		 * more than zero.
		 */
		if ((follow = nextInChain(follow)) != 0)
			return (1);
		else
			return (0);
	}
	/*
	 * newSize should always be smaller than the old one, since
	 * we are decreasing the number of clusters allocated to the file.
	 */
	return ((int64_t)oldSize - (int64_t)newSize);
}

static struct pcdir *
updateOrphanedChainMetadata(int fd, struct pcdir *dp, int32_t endCluster,
    int isBad)
{
	struct pcdir *ndp = NULL;
	int64_t remainder;
	char *newName = NULL;
	int chosenName;
	int dir = (dp->pcd_attr & PCA_DIR);

	/*
	 *  If the truncation fails, (which ought not to happen),
	 *  there's no need to go any further, we just return
	 *  a null value for the new directory entry pointer.
	 */
	remainder = truncAtCluster(fd, dp, endCluster);
	if (remainder < 0)
		return (ndp);
	if (!dir && isBad) {
		/*
		 *  Subtract out the bad cluster from the remaining size
		 *  We always assume the cluster being deleted from the
		 *  file is full size, but that might not be the case
		 *  for the last cluster of the file, so that is why
		 *  we check for negative remainder value.
		 */
		remainder -= TheBIOSParameterBlock.bpb.sectors_per_cluster *
		    TheBIOSParameterBlock.bpb.bytes_per_sector;
		if (remainder < 0)
			remainder = 0;
	}
	/*
	 * Build a new directory entry for the rest of the chain.
	 * Later, if the user okays it, we'll link this entry into the
	 * root directory.  The new entry will start out as a
	 * copy of the truncated entry.
	 */
	if ((remainder != 0) &&
	    ((newName = nextAvailableCHKName(&chosenName)) != NULL) &&
	    ((ndp = newDirEnt(dp)) != NULL)) {
		if (Verbose) {
			if (dir)
				(void) fprintf(stderr,
				    gettext("Orphaned directory chain.\n"));
			else
				(void) fprintf(stderr,
				    gettext("Orphaned chain, %u bytes.\n"),
				    (uint32_t)remainder);
		}
		if (!dir)
			updateDirEnt_Size(ndp, (uint32_t)remainder);
		if (isBad)
			updateDirEnt_Start(ndp, nextInChain(endCluster));
		else
			updateDirEnt_Start(ndp, endCluster);
		updateDirEnt_Name(ndp, newName);
		addEntryToCHKList(chosenName);
	}
	return (ndp);
}

/*
 *  splitChain()
 *
 *	split a cluster allocation chain into two cluster chains
 *	around a given cluster (problemCluster).  This results in two
 *	separate directory entries; the original (dp), and one we hope
 *	to create and return a pointer to to the caller (*newdp).
 *	This second entry is the orphan chain, and it may end up in
 *	the root directory as a FILEnnnn.CHK file.  We also return the
 *	starting cluster of the orphan chain to the caller (*orphanStart).
 */
void
splitChain(int fd, struct pcdir *dp, int32_t problemCluster,
    struct pcdir **newdp, int32_t *orphanStart)
{
	struct pcdir *ndp = NULL;
	int isBad = isMarkedBad(problemCluster);

	ndp = updateOrphanedChainMetadata(fd, dp, problemCluster, isBad);
	*newdp = ndp;
	clearInUse(problemCluster);
	if (isBad) {
		clearOrphan(problemCluster);
		*orphanStart = nextInChain(problemCluster);
		orphanChain(fd, *orphanStart, ndp);
		markBadInFAT(problemCluster);
	} else {
		*orphanStart = problemCluster;
		orphanChain(fd, problemCluster, ndp);
	}
}

/*
 *  freeOrphan
 *
 *  User has requested that an orphaned cluster chain be freed back
 *  into the file area.
 */
static void
freeOrphan(int32_t c)
{
	int32_t n;

	/*
	 * Free the directory entry we explicitly created for
	 * the orphaned clusters.
	 */
	if (InUse[c - FIRST_CLUSTER]->dirent != NULL)
		free(InUse[c - FIRST_CLUSTER]->dirent);
	/*
	 * Then mark the clusters themselves as available.
	 */
	do {
		n = nextInChain(c);
		markFreeInFAT(c);
		markFree(c);
		c = n;
	} while (c != 0);
}

/*
 *  Rewrite the InUse field for a cluster chain.  Can be used on a partial
 *  chain if provided with a stopAtCluster.
 */
static void
redoInUse(int fd, int32_t c, struct pcdir *ndp, int32_t stopAtCluster)
{
	while (c && c != stopAtCluster) {
		clearInUse(c);
		(void) markInUse(fd, c, ndp, NULL, 0, VISIBLE, NULL);
		c = nextInChain(c);
	}
}

static struct pcdir *
orphanDirEntLookup(int32_t clusterNum)
{
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (NULL);

	if (isInUse(clusterNum)) {
		return (InUse[clusterNum - FIRST_CLUSTER]->dirent);
	} else {
		return (NULL);
	}
}

static int32_t
orphanSizeLookup(int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (-1);

	if (isInUse(clusterNum)) {
		return (extractSize(InUse[clusterNum - FIRST_CLUSTER]->dirent));
	} else {
		return (-1);
	}
}

/*
 *  linkOrphan
 *
 *  User has requested that an orphaned cluster chain be brought back
 *  into the file system.  So we have to make a new directory entry
 *  in the root directory and point it at the cluster chain.
 */
static void
linkOrphan(int fd, int32_t start)
{
	struct pcdir *newEnt = NULL;
	struct pcdir *dp;

	if ((dp = orphanDirEntLookup(start)) != NULL) {
		newEnt = addRootDirEnt(fd, dp);
	} else {
		(void) printf(gettext("Re-link of orphaned chain failed."
		    "  Allocation units will remain orphaned.\n"));
	}
	/*
	 *  A cluster isn't really InUse() unless it is referenced,
	 *  so if newEnt is NULL here, we are in effect using markInUse()
	 *  to note that the cluster is NOT in use.
	 */
	redoInUse(fd, start, newEnt, 0);
}

/*
 *  relinkCreatedOrphans
 *
 *  While marking clusters as bad, we can create orphan cluster
 *  chains.  Since we were the ones doing the marking, we were able to
 *  keep track of the orphans we created.  Now we want to go through
 *  all those chains and either get them back into the file system or
 *  free them depending on the user's input.
 */
static void
relinkCreatedOrphans(int fd)
{
	int32_t c;

	for (c = FIRST_CLUSTER; c < LastCluster; c++) {
		if (isMarkedOrphan(c)) {
			if (OkayToRelink && askAboutRelink(c)) {
				linkOrphan(fd, c);
			} else if (askAboutFreeing(c)) {
				freeOrphan(c);
			}
			clearOrphan(c);
		}
	}
}

/*
 *  relinkFATOrphans
 *
 *  We want to find orphans not represented in the meta-data.
 *  These are chains marked in the FAT as being in use but
 *  not referenced anywhere by any directory entries.
 *  We'll go through the whole FAT and mark the first cluster
 *  in any such chain as an orphan.  Then we can just use
 *  the relinkCreatedOrphans routine to get them back into the
 *  file system or free'ed depending on the user's input.
 */
static void
relinkFATOrphans(int fd)
{
	struct pcdir *ndp = NULL;
	int32_t cc, c, n;
	int32_t bpc, newSize;
	char *newName;
	int chosenName;

	for (c = FIRST_CLUSTER; c < LastCluster; c++) {
		if (freeInFAT(c) || badInFAT(c) ||
		    reservedInFAT(c) || isInUse(c))
			continue;
		cc = 1;
		n = c;
		while (n = nextInChain(n))
			cc++;
		bpc = TheBIOSParameterBlock.bpb.sectors_per_cluster *
		    TheBIOSParameterBlock.bpb.bytes_per_sector;
		newSize = cc * bpc;
		if (((newName = nextAvailableCHKName(&chosenName)) != NULL) &&
		    ((ndp = newDirEnt(NULL)) != NULL)) {
			updateDirEnt_Size(ndp, newSize);
			updateDirEnt_Start(ndp, c);
			updateDirEnt_Name(ndp, newName);
			addEntryToCHKList(chosenName);
		}
		orphanChain(fd, c, ndp);
	}
	relinkCreatedOrphans(fd);
}

static void
relinkOrphans(int fd)
{
	relinkCreatedOrphans(fd);
	relinkFATOrphans(fd);
}

static void
checkForFATLoop(int32_t clusterNum)
{
	int32_t prev = clusterNum;
	int32_t follow;

	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;

	follow = nextInChain(clusterNum);
	while (follow != clusterNum && follow >= FIRST_CLUSTER &&
	    follow <= LastCluster) {
		prev = follow;
		follow = nextInChain(follow);
	}
	if (follow == clusterNum) {
		/*
		 * We found a loop.  Eradicate it by changing
		 * the last cluster in the loop to be last
		 * in the chain instead instead of pointing
		 * back to the first cluster.
		 */
		markLastInFAT(prev);
	}
}

static void
sharedChainError(int fd, int32_t clusterNum, struct pcdir *badEntry)
{
	/*
	 * If we have shared clusters, it is either because the
	 * cluster somehow got assigned to multiple files and/or
	 * because of a loop in the cluster chain.  In either
	 * case we want to truncate the offending file at the
	 * cluster of contention.  Then, we will want to run
	 * through the remainder of the chain. If we find ourselves
	 * back at the top, we will know there is a loop in the
	 * FAT we need to remove.
	 */
	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Truncating chain due to duplicate allocation of "
		    "unit %d.\n"), clusterNum);
	/*
	 * Note that we don't orphan anything here, because the duplicate
	 * part of the chain may be part of another valid chain.
	 */
	(void) truncAtCluster(fd, badEntry, clusterNum);
	checkForFATLoop(clusterNum);
}

void
truncChainWithBadCluster(int fd, struct pcdir *dp, int32_t startCluster)
{
	struct pcdir *orphanEntry;
	int32_t orphanStartCluster;
	int32_t c = startCluster;

	while (c != 0) {
		if (isMarkedBad(c)) {
			/*
			 *  splitChain() truncates the current guy and
			 *  then makes an orphan chain out of the remaining
			 *  clusters.  When we come back from the split
			 *  we'll want to continue looking for bad clusters
			 *  in the orphan chain.
			 */
			splitChain(fd, dp, c,
			    &orphanEntry, &orphanStartCluster);
			/*
			 *  There is a chance that we weren't able or weren't
			 *  required to make a directory entry for the
			 *  remaining clusters.  In that case we won't go
			 *  on, because we couldn't make any more splits
			 *  anyway.
			 */
			if (orphanEntry == NULL)
				break;
			c = orphanStartCluster;
			dp = orphanEntry;
			continue;
		}
		c = nextInChain(c);
	}
}

int32_t
nextInChain(int32_t currentCluster)
{
	int32_t nextCluster;

	/* silent failure for bogus clusters */
	if (currentCluster < FIRST_CLUSTER || currentCluster > LastCluster)
		return (0);

	/*
	 * Look up FAT entry of next link in cluster chain,
	 * if this one is the last one return 0 as the next link.
	 */
	nextCluster = readFATEntry(currentCluster);
	if (nextCluster < FIRST_CLUSTER || nextCluster > LastCluster)
		return (0);

	return (nextCluster);
}

/*
 * findImpactedCluster
 *
 *	Called when someone modifies what they believe might be a cached
 *	cluster entry, but when	they only have a directory entry pointer
 *	and not the cluster number.  We have to go dig up what cluster
 *	they are modifying.
 */
int32_t
findImpactedCluster(struct pcdir *modified)
{
	CachedCluster *loop;
	/*
	 * Check to see if it's in the root directory first
	 */
	if (!IsFAT32 && ((uchar_t *)modified >= TheRootDir.bytes) &&
	    ((uchar_t *)modified < TheRootDir.bytes + RootDirSize))
		return (FAKE_ROOTDIR_CLUST);

	loop = ClusterCache;
	while (loop) {
		if (((uchar_t *)modified >= loop->clusterData.bytes) &&
		    ((uchar_t *)modified <
		    (loop->clusterData.bytes + BytesPerCluster))) {
			return (loop->clusterNum);
		}
		loop = loop->next;
	}
	/*
	 *  Guess it wasn't cached after all...
	 */
	return (0);
}

void
writeClusterMods(int fd)
{
	CachedCluster *loop = ClusterCache;

	while (loop) {
		if (loop->modified)
			writeCachedCluster(fd, loop);
		loop = loop->next;
	}
}

void
squirrelPath(struct nameinfo *pathInfo, int32_t clusterNum)
{
	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;
	if (InUse[clusterNum - FIRST_CLUSTER] == NULL)
		return;
	InUse[clusterNum - FIRST_CLUSTER]->path = pathInfo;
}

int
markInUse(int fd, int32_t clusterNum, struct pcdir *referencer, struct
    pcdir *longRef, int32_t longStartCluster, int isHiddenFile,
    ClusterInfo **template)
{
	int alreadyMarked;
	ClusterInfo *cl;

	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return (CLINFO_NEWLY_ALLOCED);

	alreadyMarked = allocInUse(clusterNum, template);
	if ((alreadyMarked == CLINFO_PREVIOUSLY_ALLOCED) &&
	    (isInUse(clusterNum))) {
		sharedChainError(fd, clusterNum, referencer);
		return (CLINFO_PREVIOUSLY_ALLOCED);
	}
	cl = InUse[clusterNum - FIRST_CLUSTER];
	/*
	 * If Cl is newly allocated (refcnt <= 1) we must fill in the fields.
	 * If Cl has different fields, we must clone it.
	 */

	if (cl->refcnt <= 1 || cl->dirent != referencer ||
	    cl->longent != longRef ||
	    cl->longEntStartClust != longStartCluster) {
		if (cl->refcnt > 1)
			cl = cloneClusterInfo(clusterNum);
		cl->dirent = referencer;
		cl->longent = longRef;
		cl->longEntStartClust = longStartCluster;
		if (isHiddenFile)
			cl->flags |= CLINFO_HIDDEN;

		/*
		 * Return cl as the template to use for other clusters in
		 * this file
		 */
		if (template)
			*template = cl;
	}
	return (CLINFO_NEWLY_ALLOCED);
}

void
markClusterModified(int32_t clusterNum)
{
	CachedCluster *c;

	if (clusterNum == FAKE_ROOTDIR_CLUST) {
		RootDirModified = 1;
		return;
	}

	/* silent failure for bogus clusters */
	if (clusterNum < FIRST_CLUSTER || clusterNum > LastCluster)
		return;

	if (c = findClusterCacheEntry(clusterNum)) {
		c->modified = 1;
	} else {
		(void) fprintf(stderr,
		    gettext("Unexpected internal error: "
		    "Missing cache entry [%d]\n"), clusterNum);
		exit(10);
	}
}

/*
 *  readCluster
 *	caller wants to read cluster clusterNum.  We should return
 *	a pointer to the read data in "data", and fill in the number
 *	of bytes read in "datasize".  If shouldCache is non-zero
 *	we should allocate cache space to the cluster, otherwise we
 *	just return a pointer to a buffer we re-use whenever cacheing
 *	is not requested.
 */
int
readCluster(int fd, int32_t clusterNum, uchar_t **data, int32_t *datasize,
    int shouldCache)
{
	uchar_t *newBuf;
	int rv;

	*data = NULL;
	if ((*data = findClusterDataInTheCache(clusterNum)) != NULL) {
		*datasize = BytesPerCluster;
		return (RDCLUST_GOOD);
	}

	rv = getCluster(fd, clusterNum, &newBuf, datasize);
	if (rv != RDCLUST_GOOD)
		return (rv);

	/*
	 * Caller requested we NOT cache the data from this read.
	 * So, we just return a pointer to the common data buffer.
	 */
	if (shouldCache == 0) {
		*data = newBuf;
		return (rv);
	}

	/*
	 * Caller requested we cache the data from this read.
	 * So, if we have some data, add it to the cache by
	 * copying it out of the common buffer into new storage.
	 */
	if (*datasize > 0)
		*data = addToCache(clusterNum, newBuf, datasize);
	return (rv);
}

void
findBadClusters(int fd)
{
	int32_t clusterCount;
	int32_t datasize;
	uchar_t *data;

	BadClusterCount = 0;
	makeUseTable();
	(void) printf(gettext("** Scanning allocation units\n"));
	for (clusterCount = FIRST_CLUSTER;
	    clusterCount < LastCluster; clusterCount++) {
		if (readCluster(fd, clusterCount,
		    &data, &datasize, RDCLUST_DONT_CACHE) < 0) {
			if (Verbose)
			    (void) fprintf(stderr,
				gettext("\nUnreadable allocation unit %d.\n"),
				clusterCount);
			markBad(clusterCount, data, datasize);
		}
		/*
		 *  Progress meter, display a '.' for every 1000 clusters
		 *  processed.  We don't want to display this when
		 *  we are in verbose mode; verbose mode progress is
		 *  shown by displaying each file name as it is found.
		 */
		if (!Verbose && clusterCount % 1000 == 0)
			(void) printf(".");
	}
	(void) printf(gettext("..done\n"));
}

void
scanAndFixMetadata(int fd)
{
	/*
	 * First we initialize a few things.
	 */
	makeUseTable();
	getReadyToSearch(fd);
	createCHKNameList(fd);

	/*
	 * Make initial scan, taking into account any effect that
	 * the bad clusters we may have already discovered have
	 * on meta-data.  We may break up some cluster chains
	 * during this period.  The relinkCreatedOrphans() call
	 * will then give the user the chance to recover stuff
	 * we've created.
	 */
	(void) printf(gettext("** Scanning file system meta-data\n"));
	summarize(fd, NO_FAT_IN_SUMMARY);
	if (Verbose)
		printSummary(stderr);
	(void) printf(gettext("** Correcting any meta-data discrepancies\n"));
	relinkCreatedOrphans(fd);

	/*
	 * Clear our usage table and go back over everything, this
	 * time including looking for clusters floating free in the FAT.
	 * This may include clusters the user chose to free during the
	 * relink phase.
	 */
	makeUseTable();
	summarize(fd, INCLUDE_FAT_IN_SUMMARY);
	relinkOrphans(fd);
}

void
printSummary(FILE *outDest)
{
	(void) fprintf(outDest,
	    gettext("%llu bytes.\n"),
	    (uint64_t)
	    TotalClusters * TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector);
	(void) fprintf(outDest,
	    gettext("%llu bytes in bad sectors.\n"),
	    (uint64_t)
	    BadClusterCount * TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector);
	(void) fprintf(outDest,
	    gettext("%llu bytes in %d directories.\n"),
	    (uint64_t)
	    DirClusterCount * TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector, DirCount);
	if (HiddenClusterCount) {
		(void) fprintf(outDest,
		    gettext("%llu bytes in %d hidden files.\n"),
		    (uint64_t)HiddenClusterCount *
		    TheBIOSParameterBlock.bpb.sectors_per_cluster *
		    TheBIOSParameterBlock.bpb.bytes_per_sector,
		    HiddenFileCount);
	}
	(void) fprintf(outDest,
	    gettext("%llu bytes in %d files.\n"),
	    (uint64_t)
	    FileClusterCount * TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector, FileCount);
	(void) fprintf(outDest,
	    gettext("%llu bytes free.\n"), (uint64_t)FreeClusterCount *
	    TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector);
	(void) fprintf(outDest,
	    gettext("%d bytes per allocation unit.\n"),
	    TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector);
	(void) fprintf(outDest,
	    gettext("%d total allocation units.\n"), TotalClusters);
	if (ReservedClusterCount)
	    (void) fprintf(outDest, gettext("%d reserved allocation units.\n"),
		ReservedClusterCount);
	(void) fprintf(outDest,
	    gettext("%d available allocation units.\n"), FreeClusterCount);
}
