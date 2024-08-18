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
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 MNX Cloud, Inc.
 */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * libfstyp module for pcfs
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <errno.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_label.h>
#include <sys/fs/pc_dir.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/dkio.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/mnttab.h>
#include <locale.h>
#include <libfstyp_module.h>

#define	PC_LABEL_SIZE 11

/* for the <sys/fs/pc_dir.h> PCDL_IS_LFN macro */
int	enable_long_filenames = 1;

struct fstyp_fat16_bs {
	uint8_t		f_drvnum;
	uint8_t		f_reserved1;
	uint8_t		f_bootsig;
	uint8_t		f_volid[4];
	uint8_t		f_label[11];
	uint8_t		f_typestring[8];
};

struct fstyp_fat32_bs {
	uint32_t	f_fatlength;
	uint16_t	f_flags;
	uint8_t		f_major;
	uint8_t		f_minor;
	uint32_t	f_rootcluster;
	uint16_t	f_infosector;
	uint16_t	f_backupboot;
	uint8_t		f_reserved2[12];
	uint8_t		f_drvnum;
	uint8_t		f_reserved1;
	uint8_t		f_bootsig;
	uint8_t		f_volid[4];
	uint8_t		f_label[11];
	uint8_t		f_typestring[8];
};

typedef struct fstyp_pcfs {
	int		fd;
	off_t		offset;
	nvlist_t	*attr;
	struct bootsec	bs;
	struct fstyp_fat16_bs bs16;
	struct fstyp_fat32_bs bs32;
	ushort_t	bps;
	int		fattype;
	char		volume_label[PC_LABEL_SIZE + 1];

	/* parameters derived or calculated per FAT spec */
	ulong_t		FATSz;
	ulong_t		TotSec;
	ulong_t		RootDirSectors;
	ulong_t		FirstDataSector;
	ulong_t		DataSec;
	ulong_t		CountOfClusters;
} fstyp_pcfs_t;


/* We should eventually make the structs "packed" so these won't be needed */
#define	PC_BPSEC(h)	ltohs((h)->bs.bps[0])
#define	PC_RESSEC(h)	ltohs((h)->bs.res_sec[0])
#define	PC_NROOTENT(h)	ltohs((h)->bs.rdirents[0])
#define	PC_NSEC(h)	ltohs((h)->bs.numsect[0])
#define	PC_DRVNUM(h)	(FSTYP_IS_32(h) ? (h)->bs32.f_drvnum : \
			    (h)->bs16.f_drvnum)
#define	PC_VOLID(a)	(FSTYP_IS_32(h) ? ltohi((h)->bs32.f_volid[0]) : \
			    ltohi((h)->bs16.f_volid[0]))
#define	PC_LABEL_ADDR(a) (FSTYP_IS_32(h) ? \
			    &((h)->bs32.f_label[0]) : &((h)->bs16.f_label[0]))

#define	FSTYP_IS_32(h)	((h)->fattype == 32)

#define	FSTYP_MAX_CLUSTER_SIZE	(64 * 1024)	/* though officially 32K */
#define	FSTYP_MAX_DIR_SIZE	(65536 * 32)

static int	read_bootsec(fstyp_pcfs_t *h);
static int	valid_media(fstyp_pcfs_t *h);
static int	well_formed(fstyp_pcfs_t *h);
static void	calculate_parameters(fstyp_pcfs_t *h);
static void	determine_fattype(fstyp_pcfs_t *h);
static void	get_label(fstyp_pcfs_t *h);
static void	get_label_16(fstyp_pcfs_t *h);
static void	get_label_32(fstyp_pcfs_t *h);
static int	next_cluster_32(fstyp_pcfs_t *h, int n);
static boolean_t dir_find_label(fstyp_pcfs_t *h, struct pcdir *d, int nent);
static int	is_pcfs(fstyp_pcfs_t *h);
static int	dumpfs(fstyp_pcfs_t *h, FILE *fout, FILE *ferr);
static int	get_attr(fstyp_pcfs_t *h);

int	fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle);
void	fstyp_mod_fini(fstyp_mod_handle_t handle);
int	fstyp_mod_ident(fstyp_mod_handle_t handle);
int	fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp);
int	fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr);

int
fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle)
{
	struct fstyp_pcfs *h;

	if ((h = calloc(1, sizeof (struct fstyp_pcfs))) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	h->fd = fd;
	h->offset = offset;

	*handle = (fstyp_mod_handle_t)h;
	return (0);
}

void
fstyp_mod_fini(fstyp_mod_handle_t handle)
{
	struct fstyp_pcfs *h = (struct fstyp_pcfs *)handle;

	if (h->attr == NULL) {
		nvlist_free(h->attr);
		h->attr = NULL;
	}
	free(h);
}

int
fstyp_mod_ident(fstyp_mod_handle_t handle)
{
	struct fstyp_pcfs *h = (struct fstyp_pcfs *)handle;

	return (is_pcfs(h));
}

int
fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp)
{
	struct fstyp_pcfs *h = (struct fstyp_pcfs *)handle;
	int error;

	if (h->attr == NULL) {
		if (nvlist_alloc(&h->attr, NV_UNIQUE_NAME_TYPE, 0)) {
			return (FSTYP_ERR_NOMEM);
		}
		if ((error = get_attr(h)) != 0) {
			nvlist_free(h->attr);
			h->attr = NULL;
			return (error);
		}
	}

	*attrp = h->attr;
	return (0);
}

int
fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr)
{
	struct fstyp_pcfs *h = (struct fstyp_pcfs *)handle;

	return (dumpfs(h, fout, ferr));
}


/*
 * Read in boot sector. Convert into host endianness where possible.
 */
static int
read_bootsec(fstyp_pcfs_t *h)
{
	struct dk_minfo dkminfo;
	char  *buf;
	size_t size = PC_SECSIZE;

	if (ioctl(h->fd, DKIOCGMEDIAINFO, &dkminfo) != -1) {
		if (dkminfo.dki_lbsize != 0)
			size = dkminfo.dki_lbsize;
	}

	buf = malloc(size);
	if (buf == NULL)
		return (FSTYP_ERR_NOMEM);

	(void) lseek(h->fd, h->offset, SEEK_SET);
	if (read(h->fd, buf, size) != (ssize_t)size) {
		free(buf);
		return (FSTYP_ERR_IO);
	}

	bcopy(buf, &h->bs, sizeof (h->bs));
	bcopy(buf + sizeof (struct bootsec), &h->bs16, sizeof (h->bs16));
	bcopy(buf + sizeof (struct bootsec), &h->bs32, sizeof (h->bs32));
	free(buf);

	h->bs.fatsec = ltohs(h->bs.fatsec);
	h->bs.spt = ltohs(h->bs.spt);
	h->bs.nhead = ltohs(h->bs.nhead);
	h->bs.hiddensec = ltohi(h->bs.hiddensec);
	h->bs.totalsec = ltohi(h->bs.totalsec);

	h->bs32.f_fatlength = ltohi(h->bs32.f_fatlength);
	h->bs32.f_flags = ltohs(h->bs32.f_flags);
	h->bs32.f_rootcluster = ltohi(h->bs32.f_rootcluster);
	h->bs32.f_infosector = ltohs(h->bs32.f_infosector);
	h->bs32.f_backupboot = ltohs(h->bs32.f_backupboot);

	h->bps = PC_BPSEC(h);

	return (0);
}

static int
valid_media(fstyp_pcfs_t *h)
{
	switch (h->bs.mediadesriptor) {
	case MD_FIXED:
	case SS8SPT:
	case DS8SPT:
	case SS9SPT:
	case DS9SPT:
	case DS18SPT:
	case DS9_15SPT:
		return (1);
	default:
		return (0);
	}
}

static int
well_formed(fstyp_pcfs_t *h)
{
	int fatmatch;

	if (h->bs16.f_bootsig == 0x29) {
		fatmatch = ((h->bs16.f_typestring[0] == 'F' &&
		    h->bs16.f_typestring[1] == 'A' &&
		    h->bs16.f_typestring[2] == 'T') &&
		    (h->bs.fatsec > 0) &&
		    ((PC_NSEC(h) == 0 && h->bs.totalsec > 0) ||
		    PC_NSEC(h) > 0));
	} else if (h->bs32.f_bootsig == 0x29) {
		fatmatch = ((h->bs32.f_typestring[0] == 'F' &&
		    h->bs32.f_typestring[1] == 'A' &&
		    h->bs32.f_typestring[2] == 'T') &&
		    (h->bs.fatsec == 0 && h->bs32.f_fatlength > 0) &&
		    ((PC_NSEC(h) == 0 && h->bs.totalsec > 0) ||
		    PC_NSEC(h) > 0));
	} else {
		fatmatch = (PC_NSEC(h) > 0 && h->bs.fatsec > 0);
	}

	return (fatmatch && h->bps > 0 && h->bps % 512 == 0 &&
	    h->bs.spcl > 0 && PC_RESSEC(h) >= 1 && h->bs.nfat > 0);
}

static void
calculate_parameters(fstyp_pcfs_t *h)
{
	if (PC_NSEC(h) != 0) {
		h->TotSec = PC_NSEC(h);
	} else {
		h->TotSec = h->bs.totalsec;
	}
	if (h->bs.fatsec != 0) {
		h->FATSz = h->bs.fatsec;
	} else {
		h->FATSz = h->bs32.f_fatlength;
	}
	if ((h->bps == 0) || (h->bs.spcl == 0)) {
		return;
	}
	h->RootDirSectors =
	    ((PC_NROOTENT(h) * 32) + (h->bps - 1)) / h->bps;
	h->FirstDataSector =
	    PC_RESSEC(h) + h->bs.nfat * h->FATSz + h->RootDirSectors;
	h->DataSec = h->TotSec - h->FirstDataSector;
	h->CountOfClusters = h->DataSec / h->bs.spcl;
}

static void
determine_fattype(fstyp_pcfs_t *h)
{
	if (h->CountOfClusters == 0) {
		h->fattype = 0;
		return;
	}

	if (h->CountOfClusters < 4085) {
		h->fattype = 12;
	} else if (h->CountOfClusters < 65525) {
		h->fattype = 16;
	} else {
		h->fattype = 32;
	}
}

static void
get_label(fstyp_pcfs_t *h)
{
	/*
	 * Use label from the boot sector by default.
	 * Can overwrite later with the one from root directory.
	 */
	(void) memcpy(h->volume_label, PC_LABEL_ADDR(h), PC_LABEL_SIZE);
	h->volume_label[PC_LABEL_SIZE] = '\0';

	if (h->fattype == 0) {
		return;
	} else if (FSTYP_IS_32(h)) {
		get_label_32(h);
	} else {
		get_label_16(h);
	}
}

/*
 * Get volume label from the root directory entry.
 * In FAT12/16 the root directory is of fixed size.
 * It immediately follows the FATs
 */
static void
get_label_16(fstyp_pcfs_t *h)
{
	ulong_t	FirstRootDirSecNum;
	int	secsize;
	off_t	offset;
	uint8_t	buf[PC_SECSIZE * 4];
	int	i;
	int	nent, resid;

	if ((secsize = h->bps) > sizeof (buf)) {
		return;
	}

	FirstRootDirSecNum = PC_RESSEC(h) + h->bs.nfat * h->bs.fatsec;
	offset = h->offset + FirstRootDirSecNum * secsize;
	resid = PC_NROOTENT(h);

	for (i = 0; i < h->RootDirSectors; i++) {
		(void) lseek(h->fd, offset, SEEK_SET);
		if (read(h->fd, buf, secsize) != secsize) {
			return;
		}

		nent = secsize / sizeof (struct pcdir);
		if (nent > resid) {
			nent = resid;
		}
		if (dir_find_label(h, (struct pcdir *)buf, nent)) {
			return;
		}

		resid -= nent;
		offset += PC_SECSIZE;
	}
}

/*
 * Get volume label from the root directory entry.
 * In FAT32 root is a usual directory, a cluster chain.
 * It starts at BPB_RootClus.
 */
static void
get_label_32(fstyp_pcfs_t *h)
{
	off_t	offset;
	int	clustersize;
	int	n;
	ulong_t	FirstSectorofCluster;
	uint8_t	*buf;
	int	nent;
	int	cnt = 0;

	clustersize = h->bs.spcl * h->bps;
	if ((clustersize == 0) || (clustersize > FSTYP_MAX_CLUSTER_SIZE) ||
	    ((buf = calloc(1, clustersize)) == NULL)) {
		return;
	}

	for (n = h->bs32.f_rootcluster; n != 0; n = next_cluster_32(h, n)) {
		FirstSectorofCluster =
		    (n - 2) * h->bs.spcl + h->FirstDataSector;
		offset = h->offset + FirstSectorofCluster * h->bps;
		(void) lseek(h->fd, offset, SEEK_SET);
		if (read(h->fd, buf, clustersize) != clustersize) {
			break;
		}

		nent = clustersize / sizeof (struct pcdir);
		if (dir_find_label(h, (struct pcdir *)buf, nent)) {
			break;
		}

		if (++cnt > FSTYP_MAX_DIR_SIZE / clustersize) {
			break;
		}
	}

	free(buf);
}

/*
 * Get a FAT entry pointing to the next file cluster
 */
int
next_cluster_32(fstyp_pcfs_t *h, int n)
{
	uint8_t	buf[PC_SECSIZE];
	ulong_t	ThisFATSecNum;
	ulong_t	ThisFATEntOffset;
	off_t	offset;
	uint32_t val;
	int	next = 0;

	ThisFATSecNum = PC_RESSEC(h) + (n * 4) / h->bps;
	ThisFATEntOffset = (n * 4) % h->bps;
	offset = h->offset + ThisFATSecNum * h->bps;

	(void) lseek(h->fd, offset, SEEK_SET);
	if (read(h->fd, buf, sizeof (buf)) == sizeof (buf)) {
		val = buf[ThisFATEntOffset] & 0x0fffffff;
		next = ltohi(val);
	}

	return (next);
}

/*
 * Given an array of pcdir structs, find one containing volume label.
 */
static boolean_t
dir_find_label(fstyp_pcfs_t *h, struct pcdir *d, int nent)
{
	int	i;

	for (i = 0; i < nent; i++, d++) {
		if (PCDL_IS_LFN(d))
			continue;
		if ((d->pcd_filename[0] != PCD_UNUSED) &&
		    (d->pcd_filename[0] != PCD_ERASED) &&
		    ((d->pcd_attr & (PCA_LABEL | PCA_DIR)) == PCA_LABEL) &&
		    (d->un.pcd_scluster_hi == 0) &&
		    (d->pcd_scluster_lo == 0)) {
			(void) memcpy(h->volume_label, d->pcd_filename,
			    PC_LABEL_SIZE);
			h->volume_label[PC_LABEL_SIZE] = '\0';
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static int
is_pcfs(fstyp_pcfs_t *h)
{
	int	error;

	if ((error = read_bootsec(h)) != 0) {
		return (error);
	}
	if (!valid_media(h)) {
		return (FSTYP_ERR_NO_MATCH);
	}
	if (!well_formed(h)) {
		return (FSTYP_ERR_NO_MATCH);
	}

	calculate_parameters(h);
	determine_fattype(h);
	get_label(h);

	return (0);
}

static int
dumpfs(fstyp_pcfs_t *h, FILE *fout, FILE *ferr __unused)
{
	/*
	 * If fat type was not detected, then the other data is
	 * likely bogus.
	 */
	if (h->fattype == 0)
		return (FSTYP_ERR_NO_MATCH);

	(void) fprintf(fout, "Filesystem type: FAT%d\n", h->fattype);
	(void) fprintf(fout,
	    "Bytes Per Sector  %d\t\tSectors Per Cluster    %d\n",
	    h->bps, h->bs.spcl);
	(void) fprintf(fout,
	    "Reserved Sectors  %d\t\tNumber of FATs         %d\n",
	    (unsigned short)PC_RESSEC(h), h->bs.nfat);
	(void) fprintf(fout,
	    "Root Dir Entries  %d\t\tNumber of Sectors      %d\n",
	    (unsigned short)PC_NROOTENT(h), h->TotSec);
	(void) fprintf(fout,
	    "Sectors Per FAT   %d\t\tSectors Per Track      %d\n",
	    h->FATSz, h->bs.spt);
	(void) fprintf(fout,
	    "Number of Heads   %d\t\tNumber Hidden Sectors  %d\n",
	    h->bs.nhead, h->bs.hiddensec);
	(void) fprintf(fout, "Volume ID: 0x%x\n", PC_VOLID(h));
	(void) fprintf(fout, "Volume Label: %s\n", h->volume_label);
	(void) fprintf(fout, "Drive Number: 0x%x\n", PC_DRVNUM(h));
	(void) fprintf(fout, "Media Type: 0x%x   ", h->bs.mediadesriptor);

	switch (h->bs.mediadesriptor) {
	case MD_FIXED:
		(void) fprintf(fout, "\"Fixed\" Disk\n");
		break;
	case SS8SPT:
		(void) fprintf(fout, "Single Sided, 8 Sectors Per Track\n");
		break;
	case DS8SPT:
		(void) fprintf(fout, "Double Sided, 8 Sectors Per Track\n");
		break;
	case SS9SPT:
		(void) fprintf(fout, "Single Sided, 9 Sectors Per Track\n");
		break;
	case DS9SPT:
		(void) fprintf(fout, "Double Sided, 9 Sectors Per Track\n");
		break;
	case DS18SPT:
		(void) fprintf(fout, "Double Sided, 18 Sectors Per Track\n");
		break;
	case DS9_15SPT:
		(void) fprintf(fout, "Double Sided, 9-15 Sectors Per Track\n");
		break;
	default:
		(void) fprintf(fout, "Unknown Media Type\n");
	}

	return (0);
}

#define	ADD_STRING(h, name, value) \
	if (nvlist_add_string(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

#define	ADD_UINT32(h, name, value) \
	if (nvlist_add_uint32(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

#define	ADD_UINT64(h, name, value) \
	if (nvlist_add_uint64(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

#define	ADD_BOOL(h, name, value) \
	if (nvlist_add_boolean_value(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

static int
get_attr(fstyp_pcfs_t *h)
{
	char	s[64];

	ADD_UINT32(h, "bytes_per_sector", h->bps);
	ADD_UINT32(h, "sectors_per_cluster", h->bs.spcl);
	ADD_UINT32(h, "reserved_sectors", PC_RESSEC(h));
	ADD_UINT32(h, "fats", h->bs.nfat);
	ADD_UINT32(h, "root_entry_count", PC_NROOTENT(h));
	ADD_UINT32(h, "total_sectors_16", PC_NSEC(h));
	ADD_UINT32(h, "media", h->bs.mediadesriptor);
	ADD_UINT32(h, "fat_size_16", h->bs.fatsec);
	ADD_UINT32(h, "sectors_per_track", h->bs.spt);
	ADD_UINT32(h, "heads", h->bs.nhead);
	ADD_UINT32(h, "hidden_sectors", h->bs.hiddensec);
	ADD_UINT32(h, "total_sectors_32", h->bs.totalsec);
	ADD_UINT32(h, "drive_number", PC_DRVNUM(h));
	ADD_UINT32(h, "volume_id", PC_VOLID(h));
	ADD_STRING(h, "volume_label", h->volume_label);
	if (FSTYP_IS_32(h)) {
		ADD_UINT32(h, "fat_size_32", h->bs32.f_fatlength);
	}
	ADD_UINT32(h, "total_sectors", h->TotSec);
	ADD_UINT32(h, "fat_size", h->FATSz);
	ADD_UINT32(h, "count_of_clusters", h->CountOfClusters);
	ADD_UINT32(h, "fat_entry_size", h->fattype);

	ADD_BOOL(h, "gen_clean", B_TRUE);
	if (PC_VOLID(a) != 0) {
		(void) snprintf(s, sizeof (s), "%08x", PC_VOLID(a));
		ADD_STRING(h, "gen_guid", s);
	}
	(void) snprintf(s, sizeof (s), "%d", h->fattype);
	ADD_STRING(h, "gen_version", s);
	ADD_STRING(h, "gen_volume_label", h->volume_label);

	return (0);
}
