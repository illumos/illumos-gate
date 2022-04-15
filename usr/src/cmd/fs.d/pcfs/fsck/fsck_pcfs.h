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
 * Copyright 2024 MNX Cloud, Inc.
 */

#ifndef _FSCK_PCFS_H
#define	_FSCK_PCFS_H

/*
 * Structures used by the pcfs file system checker.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 *  The root directory of FAT12/16 file systems doesn't sit in
 *  a cluster.
 */
#define	FAKE_ROOTDIR_CLUST	-1

/*
 *  The first available cluster number for a FAT fs is always the same, 2.
 */
#define	FIRST_CLUSTER		2

#define	RETURN_ON_OPEN_FAILURE	0
#define	EXIT_ON_OPEN_FAILURE	1

#define	NO_FAT_IN_SUMMARY	0
#define	INCLUDE_FAT_IN_SUMMARY	1

#define	RDCLUST_DONT_CACHE	0
#define	RDCLUST_DO_CACHE	1

/*
 *  Return values for sanityCheckSize()
 */
#define	SIZE_MATCHED	0
#define	TRUNCATED	1

#define	RDCLUST_MAX_RETRY 3
#define	RDCLUST_GOOD 0
#define	RDCLUST_FAIL -1
#define	RDCLUST_MEMERR -2
#define	RDCLUST_BADINPUT -3

typedef union clustDataTypes {
    struct pcdir	*dirp;
    uchar_t		*bytes;
} ClusterContents;

struct cached {
    int32_t	clusterNum;
    ClusterContents clusterData;
    short	modified;
    struct cached *next;
};

typedef struct cached CachedCluster;

struct nameinfo {
	char *fullName;
	int references;
};

/*
 * This structure is shared between all structures belonging to
 * a single file.  The refcnt is a 24 bit integer, that should be
 * sufficient for 4GB files, even when someone uses 256 byte clusters
 * (4K is the typical cluster size, 512 bytes is probably the minimum)
 * The inefficiency of using a bit field is compensated by the memory
 * savings and prevented paging on large filesystems.
 */
struct clinfo {
	struct pcdir	*dirent;
	union {
	    struct clinfo	*_nextfree;
	    struct pcdir	*_longent;
	}		_unionelem;
	int32_t		longEntStartClust;
	int		refcnt:24;
	uint_t		flags:8;
	uchar_t		*saved;
	struct nameinfo	*path;
};

/*
 * #define dirent conflicts with other dirent uses, so we used the
 * second element instead of the first one one as union for the free
 * list
 */
#define	longent		_unionelem._longent
#define	nextfree	_unionelem._nextfree

typedef struct clinfo ClusterInfo;

/*
 *  Return values for allocInUse
 */
#define	CLINFO_PREVIOUSLY_ALLOCED	1
#define	CLINFO_NEWLY_ALLOCED		0

#define	CLINFO_BAD	0x1
#define	CLINFO_ORPHAN	0x2
#define	CLINFO_HIDDEN	0x4

/*
 *	Traversal operations for wandering the file system metadata
 */
#define	PCFS_NO_SUBDIRS		0
#define	PCFS_VISIT_SUBDIRS	1

#define	PCFS_TRAVERSE_ALL	1	/* visit all nodes */
#define	PCFS_FIND_ATTR		2	/* search for matching attribute */
#define	PCFS_FIND_STATUS	3	/* search for same status */
#define	PCFS_FIND_CHKS		4	/* find FILENNNN.CHK files */

/*
 *  Booleans for markInUse, whether or not file is marked hidden.
 */
#define	VISIBLE 0
#define	HIDDEN  1

/*
 * Indices for various parts of the FILEnnnn.CHK name
 */
#define	CHKNAME_F	0
#define	CHKNAME_I	1
#define	CHKNAME_L	2
#define	CHKNAME_E	3
#define	CHKNAME_THOUSANDS	4
#define	CHKNAME_HUNDREDS	5
#define	CHKNAME_TENS	6
#define	CHKNAME_ONES	7
#define	CHKNAME_C	0
#define	CHKNAME_H	1
#define	CHKNAME_K	2

/*
 *  Largest value that will fit into our lost+found naming scheme of
 *  FILEnnnn.CHK.
 */
#define	MAXCHKVAL	9999

extern size_t bpsec;
extern bool AlwaysYes;	/* assume a yes answer to all questions */
extern bool AlwaysNo;	/* assume a no answer to all questions */

/*
 * Function prototypes
 */
extern struct pcdir *addRootDirEnt(int fd, struct pcdir *copyme);
extern struct pcdir *newDirEnt(struct pcdir *copyme);
extern int32_t extractStartCluster(struct pcdir *dp);
extern int32_t findImpactedCluster(struct pcdir *modified);
extern int32_t readFATEntry(int32_t currentCluster);
extern uint32_t extractSize(struct pcdir *dp);
extern int32_t nextInChain(int32_t currentCluster);
extern char *nextAvailableCHKName(int *chosen);
extern void truncChainWithBadCluster(int fd, struct pcdir *dp,
    int32_t startCluster);
extern void mountSanityCheckFails(void);
extern void markClusterModified(int32_t clusterNum);
extern void scanAndFixMetadata(int fd);
extern void updateDirEnt_Start(struct pcdir *dp, int32_t newStart);
extern void addEntryToCHKList(int chkNumber);
extern void createCHKNameList(int fd);
extern void updateDirEnt_Name(struct pcdir *dp, char *newName);
extern void updateDirEnt_Size(struct pcdir *dp, uint32_t newSize);
extern void getRootDirectory(int fd);
extern void writeClusterMods(int fd);
extern void writeRootDirMods(int fd);
extern void traverseFromRoot(int fd, int depth, int descend, int operation,
    char matchRequired,  struct pcdir **found, int32_t *lastDirCluster,
    struct pcdir **dirEnd, char *recordPath, int *pathLen);
extern void findBadClusters(int fd);
extern void markFreeInFAT(int32_t clusterNum);
extern void markLastInFAT(int32_t clusterNum);
extern void writeFATEntry(int32_t currentCluster, int32_t value);
extern void markBadInFAT(int32_t clusterNum);
extern void printSummary(FILE *outDest);
extern void squirrelPath(struct nameinfo *pathInfo, int32_t clusterNum);
extern void usingCHKName(void *nameCookie);
extern void writeFATMods(int fd);
extern void traverseDir(int fd, int32_t startAt, int depth, int descend,
    int operation, char matchRequired,  struct pcdir **found,
    int32_t *lastDirCluster, struct pcdir **dirEnd, char *recordPath,
    int *pathLen);
extern void splitChain(int fd, struct pcdir *dp, int32_t problemCluster,
    struct pcdir **newdp, int32_t *orphanStart);
extern void preenBail(char *outString);
extern void readBPB(int fd);
extern void getFAT(int fd);
extern int checkFAT32CleanBit(int fd);
extern int reservedInFAT(int32_t clusterNum);
extern int isMarkedBad(int32_t clusterNum);
extern int readCluster(int fd, int32_t clusterNum, uchar_t **data,
    int32_t *datasize, int shouldCache);
extern int freeInFAT(int32_t clusterNum);
extern int lastInFAT(int32_t clusterNum);
extern int markInUse(int fd, int32_t clusterNum, struct pcdir *referencer,
    struct pcdir *longRef, int32_t longStartCluster, int isHidden,
    ClusterInfo **template);
extern int badInFAT(int32_t clusterNum);

#ifdef __cplusplus
}
#endif

#endif /* _FSCK_PCFS_H */
