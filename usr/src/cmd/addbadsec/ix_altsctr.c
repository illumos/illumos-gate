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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * copyright (c) 1990, 1991 UNIX System Laboratories, Inc.
 * copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T
 * All rights reserved.
 */

/*
 * Copyrighted as an unpublished work.
 * (c) Copyright INTERACTIVE Systems Corporation 1986, 1988, 1990
 * All rights reserved.
 */

#include <sys/types.h>
#include <ctype.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/vtoc.h>
#include <sys/param.h>
#include <sys/dkio.h>
#include <sys/dktp/altsctr.h>
#include <sys/dktp/fdisk.h>
#include "badsec.h"

#define	FAILURE	0
#define	SUCCESS	1

#define	CMD_READ	0
#define	CMD_WRITE	1

struct	badsec_lst *badsl_chain;
int	badsl_chain_cnt;
struct	badsec_lst *gbadsl_chain;
int	gbadsl_chain_cnt;

extern struct dk_geom	dkg;
extern int	alts_fd;

struct	alts_mempart alts_part = { 0, NULL, 0 };
struct	alts_mempart *ap = &alts_part;	/* pointer to incore alts tables */

static void read_altsctr(struct extpartition *part, int badok);
static void chk_badsec(void);
static void init_altsctr(void);
void wr_altsctr(void);
static void get_badsec(void);
static int count_badsec(void);
static void gen_alts_ent(void);
static void assign_altsctr(void);
static void expand_map(void);
static void compress_map(void);
static int altsmap_getbit(blkaddr_t badsec);
static blkaddr_t altsmap_alloc(blkaddr_t srt_ind, blkaddr_t end_ind,
	int cnt, int dir);
static void ent_sort(struct alts_ent buf[], int cnt);
static void ent_compress(struct alts_ent buf[], int cnt);
static int  ent_merge(
	struct alts_ent buf[],
	struct alts_ent list1[],
	int    lcnt1,
	struct alts_ent list2[],
	int    lcnt2);
static int  ent_bsearch(struct alts_ent buf[], int cnt, struct alts_ent *key);
static int  chk_bad_altsctr(blkaddr_t badsec);
int	print_altsec(struct extpartition *part);
int	get_altsctr(int);
static void print_altsctr(void);
static int  absdsk_io(int fd, uint_t srtsec, char *bufp, uint_t len,
	int ioflag);

/*
 * updatebadsec () -- update bad sector/track mapping tables
 */
int
updatebadsec(struct extpartition *part, int init_flag)
{
	if (init_flag)
		ap->ap_flag |= ALTS_ADDPART;
	get_badsec();
	read_altsctr(part, 1);
	ent_sort(ap->ap_gbadp, ap->ap_gbadcnt);
	ent_compress(ap->ap_gbadp, ap->ap_gbadcnt);
	gen_alts_ent();
	compress_map();
	return (SUCCESS);
}

/*
 * read_altsctr( ptr to alternate sector partition )
 *		-- read the alternate sector partition tables
 */
static void
read_altsctr(struct extpartition *part, int badok)
{
	if (ap->ap_tblp == NULL) {
/*	    allocate buffer for the alts partition table (sector size)	*/
	    ap->ap_tbl_secsiz = byte_to_secsiz(ALTS_PARTTBL_SIZE, NBPSCTR);
	    ap->ap_tblp = (struct alts_parttbl *)malloc(ap->ap_tbl_secsiz);
	    if (ap->ap_tblp == NULL) {
		(void) fprintf(stderr,
			"Unable to malloc alternate partition table.\n");
		exit(50);
	    }

/*	    allocate buffer for the alts partition map (sector size)	*/
/*	    buffers include the disk image bit map 			*/
/*	    and the incore transformed char map				*/

	    if ((ap->ap_memmapp = (uchar_t *)malloc(part->p_size)) == NULL) {
		(void) fprintf(stderr,
			"Unable to malloc incore alternate partition map.\n");
		exit(51);
	    }
	    ap->ap_tblp->alts_map_len = (part->p_size + 8 - 1) / 8;
	    ap->ap_map_secsiz = byte_to_secsiz(ap->ap_tblp->alts_map_len,
		NBPSCTR);
	    ap->ap_map_sectot = ap->ap_map_secsiz / NBPSCTR;
	    if ((ap->ap_mapp = (uchar_t *)malloc(ap->ap_map_secsiz)) == NULL) {
		(void) fprintf(stderr,
		    "Unable to malloc alternate partition map.\n");
		exit(52);
	    }
/*	    clear the buffers to zero					*/
	    (void) memset(ap->ap_memmapp, 0, part->p_size);
	    (void) memset(ap->ap_mapp, 0, ap->ap_map_secsiz);
	    ap->part = *part;		/* struct copy			*/

/*
 *	    if add alternate partition flag is set, then install the partition
 *	    otherwise read the alts partition info from disk
 *	    if failed, then assume the first installation
 */
	    if (ap->ap_flag & ALTS_ADDPART) {
		(void) fprintf(stderr,
		    "WARNING: Manually initializing alternate table.\n");
		init_altsctr();
	    } else {
	    	if (get_altsctr(badok) == SUCCESS)
		    chk_badsec();
	    	else
		    init_altsctr();
	    }
	}
}


/*
 *	checking duplicate bad sectors or bad sectors in ALTSCTR partition
 */
static void
chk_badsec(void)
{
	blkaddr_t	badsec;
	blkaddr_t	altsp_srtsec = ap->part.p_start;
	blkaddr_t	altsp_endsec = ap->part.p_start + ap->part.p_size - 1;
	int	cnt;
	int	status;

	for (cnt = 0; cnt < ap->ap_gbadcnt; cnt++) {
	    badsec = (ap->ap_gbadp)[cnt].bad_start;

	    /* if bad sector is within the ATLSCTR partition */
	    if ((badsec >= altsp_srtsec) && (badsec <= altsp_endsec)) {
		if ((ap->ap_memmapp)[badsec - altsp_srtsec] != ALTS_BAD) {
		    if ((badsec >= altsp_srtsec) && (badsec <= (altsp_srtsec +
			ap->ap_tbl_secsiz / NBPSCTR - 1))) {
		    	(void) fprintf(stderr,
			    "Alternate partition information table is bad.\n");
		    	exit(53);
	    	    }
		    if ((badsec >= altsp_srtsec+ap->ap_tblp->alts_map_base) &&
			(badsec <= (altsp_srtsec + ap->ap_tblp->alts_map_base +
			ap->ap_map_sectot - 1))) {
		    	(void) fprintf(stderr,
			    "Alternate partition map is bad.\n");
		    	exit(54);
	    	    }
		    if ((badsec >= altsp_srtsec+ap->ap_tblp->alts_ent_base) &&
			(badsec <= (altsp_srtsec + ap->ap_tblp->alts_ent_base +
			ap->ap_ent_secsiz / NBPSCTR - 1))) {
		    	(void) fprintf(stderr,
			    "Alternate partition entry table is bad.\n");
		    	exit(55);
	    	    }
		    (ap->ap_memmapp)[badsec - altsp_srtsec] = ALTS_BAD;
		    (ap->ap_gbadp)[cnt].bad_start = (uint32_t)ALTS_ENT_EMPTY;
		} else {
		    status = chk_bad_altsctr(badsec);
		    (ap->ap_gbadp)[cnt].bad_start = (uint32_t)ALTS_ENT_EMPTY;
		}
	    } else {
/*
 *		binary search for bad sector in the alts entry table
 */
		status = ent_bsearch(ap->ap_entp, ap->ap_tblp->alts_ent_used,
					&((ap->ap_gbadp)[cnt]));
/*
 *		if the bad sector had already been remapped(found in alts_entry)
 *		then ignore the bad sector
 */
		if (status != -1) {
		    (ap->ap_gbadp)[cnt].bad_start = (uint32_t)ALTS_ENT_EMPTY;
		}
	    }
	}
	
}

/*
 *	initialize the alternate partition tables
 */
static void
init_altsctr(void)
{
	blkaddr_t	badsec;
	blkaddr_t	altsp_srtsec = ap->part.p_start;
	blkaddr_t	altsp_endsec = ap->part.p_start + ap->part.p_size - 1;
	int	cnt;

	ap->ap_entp = NULL;
	ap->ap_ent_secsiz = 0;
	ap->ap_tblp->alts_sanity = ALTS_SANITY;
	ap->ap_tblp->alts_version = ALTS_VERSION1;
	ap->ap_tblp->alts_map_len = (ap->part.p_size + 8 - 1) / 8;
	ap->ap_tblp->alts_ent_used = 0;
	ap->ap_tblp->alts_ent_base = 0;
	ap->ap_tblp->alts_ent_end  = 0;
	ap->ap_tblp->alts_resv_base = ap->part.p_size - 1;
	for (cnt = 0; cnt < 5; cnt++)
	    ap->ap_tblp->alts_pad[cnt] = 0;

	for (cnt = 0; cnt < ap->ap_gbadcnt; cnt++) {
	    badsec = (ap->ap_gbadp)[cnt].bad_start;
	    if ((badsec >= altsp_srtsec) && (badsec <= altsp_endsec)) {
		if (badsec == altsp_srtsec) {
		    (void) fprintf(stderr,
			"First sector of alternate partition is bad.\n");
		    exit(56);
	    	}
		(ap->ap_memmapp)[badsec - altsp_srtsec] = ALTS_BAD;
		(ap->ap_gbadp)[cnt].bad_start = (uint32_t)ALTS_ENT_EMPTY;
	    }
	}

/*	allocate the alts_map on disk skipping possible bad sectors	*/
	ap->ap_tblp->alts_map_base =
		altsmap_alloc(ap->ap_tbl_secsiz / NBPSCTR,
			ap->part.p_size, ap->ap_map_sectot, ALTS_MAP_UP);
	if (ap->ap_tblp->alts_map_base == 0) {
	    perror("Unable to allocate alternate map on disk: ");
	    exit(57);
	}

}


/*
 * 	read the alternate partition tables from disk
 */
int
get_altsctr(badok)
int badok;
{
/*	get alts partition table info					*/
	if (absdsk_io(alts_fd, 0, (char *)ap->ap_tblp,
			ap->ap_tbl_secsiz, CMD_READ) == FAILURE) {
	    if (badok)
		return(FAILURE);
	    perror("Unable to read alternate sector partition: ");
	    exit(58);
	}
	if (ap->ap_tblp->alts_sanity != ALTS_SANITY) {
	    if (badok)
		return(FAILURE);
	    (void) fprintf(stderr, "Bad alternate sector magic number.\n");
	    exit(69);
	}

/*	get the alts map						*/
	if (absdsk_io(alts_fd, ap->ap_tblp->alts_map_base,
		(char *)ap->ap_mapp, ap->ap_map_secsiz, CMD_READ) == FAILURE) {
	    if (badok)
		return(FAILURE);
	    perror("Unable to read alternate sector partition map: ");
	    exit(59);
	}

/*	transform the disk image bit-map to incore char map		*/
	expand_map();

	if (ap->ap_tblp->alts_ent_used == 0) {
	    ap->ap_entp = NULL;
	    ap->ap_ent_secsiz = 0;
	} else {
	    ap->ap_ent_secsiz = byte_to_secsiz(
			(ap->ap_tblp->alts_ent_used*ALTS_ENT_SIZE),NBPSCTR);
	    if ((ap->ap_entp =
		(struct alts_ent *)malloc(ap->ap_ent_secsiz)) == NULL) {
		if (badok)
		    return(FAILURE);
		(void) fprintf(stderr,
		    "Unable to malloc alternate sector entry table.\n");
		exit(60);
	    }

	    if (absdsk_io(alts_fd, ap->ap_tblp->alts_ent_base,
	    	(char *)ap->ap_entp, ap->ap_ent_secsiz,
		CMD_READ) ==FAILURE){
		if (badok)
		    return(FAILURE);
		perror("Unable to read alternate sector entry table: ");
		exit(61);
	    }
	}
	return(SUCCESS);
}


/*
 *	update the new alternate partition tables on disk
 */
void
wr_altsctr(void)
{
	if (ap->ap_tblp == NULL)
		return;
	if (absdsk_io(alts_fd, 0, (char *)ap->ap_tblp,
		ap->ap_tbl_secsiz, CMD_WRITE) == FAILURE) {
	    perror("Unable to write alternate sector partition: ");
	    exit(62);
	}

	if (absdsk_io(alts_fd, ap->ap_tblp->alts_map_base,
		(char *)ap->ap_mapp, ap->ap_map_secsiz, CMD_WRITE) == FAILURE) {
	    perror("Unable to write alternate sector partition map: ");
	    exit(63);
	}

	if (ap->ap_tblp->alts_ent_used != 0) {
	    if (absdsk_io(alts_fd, ap->ap_tblp->alts_ent_base,
	    			(char *)ap->ap_entp, ap->ap_ent_secsiz,
				CMD_WRITE) == FAILURE) {
		perror("Unable to write alternate sector entry table: ");
		exit(64);
	    }
	}
}


/*
 *	get a list of bad sector
 */
static void
get_badsec(void)
{
	int	cnt;
	struct	badsec_lst *blc_p;
	blkaddr_t	curbad;
	blkaddr_t	maxsec = (blkaddr_t)dkg.dkg_nhead *
					dkg.dkg_ncyl * dkg.dkg_nsect;
	struct	alts_ent *growbadp;
	int	i;

	cnt = count_badsec();
	if (!cnt) {
	    ap->ap_gbadp = NULL;
	    ap->ap_gbadcnt = 0;
	} else {
	    ap->ap_gbadp = (struct alts_ent *)malloc(cnt*ALTS_ENT_SIZE);
	    (void) memset(ap->ap_gbadp,0,cnt*ALTS_ENT_SIZE);

	    for (growbadp = ap->ap_gbadp, cnt=0, blc_p=badsl_chain;
		blc_p; blc_p=blc_p->bl_nxt) {
		for (i=0; i<blc_p->bl_cnt; i++) {
		    curbad = blc_p->bl_sec[i];
		    if (curbad < (blkaddr_t)dkg.dkg_nsect) {
		    	(void) fprintf(stderr,
			    "Ignoring bad sector %ld which is in first"
			    " track of the drive.\n", curbad);
		    	continue;
		    }
		    if (curbad >= maxsec) {
		    	(void) fprintf(stderr,
			    "Ignoring bad sector %ld which is past"
			    " the end of the drive.\n", curbad);
		    	continue;
		    }
		    growbadp[cnt].bad_start = curbad;
		    growbadp[cnt].bad_end = curbad;
		    cnt++;
		}
	    }
	}
	ap->ap_gbadcnt = cnt;
}

/*
 *	count number of bad sector on list
 *	merging the bad sector list from surface analysis and the
 *	one given through the command line
 */
static int
count_badsec(void)
{

	struct badsec_lst *blc_p;

	if (!badsl_chain)
		badsl_chain = gbadsl_chain;
	else {
		for (blc_p = badsl_chain; blc_p->bl_nxt; blc_p = blc_p->bl_nxt)
			;
		blc_p->bl_nxt = gbadsl_chain;
	}

	badsl_chain_cnt += gbadsl_chain_cnt;
	return(badsl_chain_cnt);
}


/*
 *	generate alternate entry table by merging the existing and
 *	the new entry list.
 */
static void
gen_alts_ent(void)
{
	uint_t	ent_used;
	struct	alts_ent *entp;

	if (ap->ap_gbadcnt == 0)
	    return;

	ent_used = ap->ap_tblp->alts_ent_used + ap->ap_gbadcnt;
	ap->ap_ent_secsiz = byte_to_secsiz(ent_used*ALTS_ENT_SIZE,NBPSCTR);
	entp=(struct alts_ent *) malloc (ap->ap_ent_secsiz);
	ent_used = ent_merge(entp, ap->ap_entp, ap->ap_tblp->alts_ent_used,
			     ap->ap_gbadp, ap->ap_gbadcnt);
	if (ap->ap_entp)
	    free(ap->ap_entp);
	if (ap->ap_gbadp)
	    free(ap->ap_gbadp);
	ap->ap_entp = entp;
	ap->ap_ent_secsiz = byte_to_secsiz(ent_used*ALTS_ENT_SIZE, NBPSCTR);
	ap->ap_tblp->alts_ent_used = ent_used;
	ap->ap_gbadp = NULL;
	ap->ap_gbadcnt = 0;

/*	assign alternate sectors to the bad sectors			*/
	assign_altsctr();

/*	allocate the alts_entry on disk skipping possible bad sectors	*/
	ap->ap_tblp->alts_ent_base =
		altsmap_alloc(ap->ap_tblp->alts_map_base + ap->ap_map_sectot,
			ap->part.p_size,
			ap->ap_ent_secsiz / NBPSCTR, ALTS_MAP_UP);
	if (ap->ap_tblp->alts_ent_base == 0) {
	    perror("Unable to allocate alternate entry table on disk: ");
	    exit(65);
	}

	ap->ap_tblp->alts_ent_end = ap->ap_tblp->alts_ent_base +
			(ap->ap_ent_secsiz / NBPSCTR) - 1;
}


/*
 *	assign alternate sectors for bad sector mapping
 */
static void
assign_altsctr(void)
{
	uint_t	i;
	uint_t	j;
	blkaddr_t	alts_ind;
	uint_t	cluster;

	for (i = 0; i < ap->ap_tblp->alts_ent_used; i++) {
	    if ((ap->ap_entp)[i].bad_start == (uint32_t)ALTS_ENT_EMPTY)
		continue;
	    if ((ap->ap_entp)[i].good_start != 0)
		continue;
	    cluster = (ap->ap_entp)[i].bad_end-(ap->ap_entp)[i].bad_start +1;
	    alts_ind =
		altsmap_alloc(ap->part.p_size-1, ap->ap_tblp->alts_map_base +
			ap->ap_map_sectot - 1, cluster, ALTS_MAP_DOWN);
	    if (alts_ind == 0) {
	    	(void) fprintf(stderr,
		    "Unable to allocate alternates for bad starting"
		    " sector %u.\n", (ap->ap_entp)[i].bad_start);
	    	exit(65);
	    }
	    alts_ind = alts_ind - cluster + 1;
	    (ap->ap_entp)[i].good_start = alts_ind + ap->part.p_start;
	    for (j = 0; j < cluster; j++) {
		(ap->ap_memmapp)[alts_ind+j] = ALTS_BAD;		
	    }

	}

}

/*
 *	transform the disk image alts bit map to incore char map
 */
static void
expand_map(void)
{
	int 	i;

	for (i = 0; i < ap->part.p_size; i++) {
	    (ap->ap_memmapp)[i] = altsmap_getbit(i);
	}
}

/*
 *	transform the incore alts char map to the disk image bit map
 */
static void
compress_map(void)
{

	int 	i;
	int	bytesz;
	char	mask = 0;
	int	maplen = 0;

	for (i = 0, bytesz = 7; i < ap->part.p_size; i++) {
	    mask |= ((ap->ap_memmapp)[i] << bytesz--);
	    if (bytesz < 0) {
		(ap->ap_mapp)[maplen++] = mask;
		bytesz = 7;
		mask = 0;
	    }
	}
/*
 *	if partition size != multiple number of bytes
 *	then record the last partial byte
 */
	if (bytesz != 7)
	    (ap->ap_mapp)[maplen] = mask;

}

/*
 *	given a bad sector number, search in the alts bit map
 *	and identify the sector as good or bad
 */
static int
altsmap_getbit(blkaddr_t badsec)
{
	uint_t	slot = badsec / 8;
	uint_t	field = badsec % 8;
	uchar_t	mask;

	mask = ALTS_BAD<<7;
	mask >>= field;
	if ((ap->ap_mapp)[slot] & mask)
	     return(ALTS_BAD);
	return(ALTS_GOOD);
}


/*
 *	allocate a range of sectors from the alternate partition
 */
static blkaddr_t
altsmap_alloc(blkaddr_t srt_ind, blkaddr_t end_ind, int cnt, int dir)
{
	blkaddr_t	i;
	blkaddr_t	total;
	blkaddr_t	first_ind;

	for (i = srt_ind, first_ind = srt_ind, total = 0;
	    i != end_ind; i += dir) {
	    if ((ap->ap_memmapp)[i] == ALTS_BAD) {
		total = 0;
		first_ind = i + dir;
		continue;
	    }
	    total++;
	    if (total == cnt)
		return(first_ind);

	}
	return(0);
}



/*
 * 	bubble sort the entry table into ascending order
 */
static void
ent_sort(struct alts_ent buf[], int cnt)
{
struct	alts_ent temp;
int	flag;
int	i, j;

	for (i = 0; i < cnt-1; i++) {
	    temp = buf[cnt-1];
	    flag = 1;

	    for (j = cnt-1; j > i; j--) {
		if (buf[j-1].bad_start < temp.bad_start) {
		    buf[j] = temp;
		    temp = buf[j-1];
		} else {
		    buf[j] = buf[j-1];
		    flag = 0;
		}
	    }
	    buf[i] = temp;
	    if (flag) break;
	}

}


/*
 *	compress all the contiguous bad sectors into a single entry
 *	in the entry table. The entry table must be sorted into ascending
 *	before the compression.
 */
static void
ent_compress(struct alts_ent buf[], int cnt)
{
int	keyp;
int	movp;
int	i;

	for (i = 0; i < cnt; i++) {
	    if (buf[i].bad_start == (uint32_t)ALTS_ENT_EMPTY)
		continue;
	    for (keyp = i, movp = i+1; movp < cnt; movp++) {
		if (buf[movp].bad_start == (uint32_t)ALTS_ENT_EMPTY)
			continue;
		if (buf[keyp].bad_end+1 != buf[movp].bad_start)
		    break;
		buf[keyp].bad_end++;
		buf[movp].bad_start = (uint32_t)ALTS_ENT_EMPTY;
	    }
	    if (movp == cnt) break;
	}
}


/*
 *	merging two entry tables into a single table. In addition,
 *	all empty slots in the entry table will be removed.
 */
static int
ent_merge(
	struct alts_ent buf[],
	struct alts_ent list1[],
	int    lcnt1,
	struct alts_ent list2[],
	int    lcnt2)
{
	int	i;
	int	j1, j2;

	for (i = 0, j1 = 0, j2 = 0; j1 < lcnt1 && j2 < lcnt2; ) {
	    if (list1[j1].bad_start == (uint32_t)ALTS_ENT_EMPTY) {
		j1++;
		continue;
	    }
	    if (list2[j2].bad_start == (uint32_t)ALTS_ENT_EMPTY) {
		j2++;
		continue;
	    }
	    if (list1[j1].bad_start < list2[j2].bad_start)
		buf[i++] = list1[j1++];
	    else
		buf[i++] = list2[j2++];
	}
	for (; j1 < lcnt1; j1++) {
	    if (list1[j1].bad_start == (uint32_t)ALTS_ENT_EMPTY)
		continue;
	    buf[i++] = list1[j1];
	}
	for (; j2 < lcnt2; j2++) {
	    if (list2[j2].bad_start == (uint32_t)ALTS_ENT_EMPTY)
		continue;
	    buf[i++] = list2[j2];
	}
	return (i);
}


/*
 *	binary search for bad sector in the alternate entry table
 */
static int
ent_bsearch(struct alts_ent buf[], int cnt, struct alts_ent *key)
{
	int	i;
	int	ind;
	int	interval;
	int	mystatus = -1;

	if (!cnt)
		return(mystatus);

	for (i = 1; i <= cnt; i <<= 1)
	    ind = i;

	for (interval = ind; interval; ) {
/*
	    printf("ind= %d, intv= %d; ",ind, interval);
*/
	    if ((key->bad_start >= buf[ind-1].bad_start) &&
		(key->bad_start <= buf[ind-1].bad_end)) {
		return(mystatus = ind-1);
	    } else {
		interval >>= 1;
		if (!interval) break;
		if (key->bad_start < buf[ind-1].bad_start) {
		    ind = ind - interval;
		} else {
 /* 		    if key is larger than the last element then break	*/
		    if (ind == cnt) break;	
		    if ((ind+interval) <= cnt)
		    	ind += interval;
		}
	    }
	}
	return(mystatus);
}

/*
 *	check for bad sector in assigned alternate sectors
 */
static int
chk_bad_altsctr(blkaddr_t badsec)
{
	int	i;
	blkaddr_t	numsec;
	int	cnt = ap->ap_tblp->alts_ent_used;
/*
 *	blkaddr_t intv[3];
 */

	for (i = 0; i < cnt; i++) {
	    numsec = (ap->ap_entp)[i].bad_end - (ap->ap_entp)[i].bad_start;
	    if ((badsec >= (ap->ap_entp)[i].good_start) &&
		(badsec <= ((ap->ap_entp)[i].good_start + numsec))) {
		(void) fprintf(stderr, "Bad sector %ld is an assigned"
		    " alternate sector.\n", badsec);
		exit(66);
/*
 *		if (!numsec) {
 *		    (ap->ap_entp)[i].good_start = 0;
 *		    return (FAILURE);
 *		}
 *		intv[0] = badsec - (ap->ap_entp)[i].good_start;
 *		intv[1] = 1;
 *		intv[2] = (ap->ap_entp)[i].good_start + numsec - badsec;
 */
	    }
	}
	/* the bad sector has already been identified as bad */
	return(SUCCESS);
}


/*
 * print_altsec () -- print alternate sector information
 */
int
print_altsec(struct extpartition *part)
{
	ap->ap_tblp = NULL;
	ap->ap_flag &= ~ALTS_ADDPART;
	read_altsctr(part, 0);
	print_altsctr();
	return(SUCCESS);
}

static void
print_altsctr(void)
{
	int	i;
	int	totalloc;
	int	avail;

/*	find # of available alternate sectors				*/
	for (i=0, totalloc=0; i<ap->part.p_size; i++) {
	    if ((ap->ap_memmapp)[i])
		totalloc++;
	}
/*
 *	available = size of partition - allocated sectors/bad sectors
 *		    - partition table - partition map
 *		    - entry table
 */
	avail = ap->part.p_size - totalloc;
	avail = avail - (ap->ap_tbl_secsiz/NBPSCTR)
		- ap->ap_map_sectot;
	avail = avail-(ap->ap_tblp->alts_ent_end -ap->ap_tblp->alts_ent_base+1);
	if (avail < 0) avail = 0;

	(void) printf("\nALTERNATE SECTOR/TRACK MAPPING TABLE:\n");
	(void) printf("\nBad Sector Start\tAlternate Sector Start\t\tCount\n");

	for (i=0; i<ap->ap_tblp->alts_ent_used; i++) {
	     (void) printf("\t%u\t     ->\t\t%u\t\t\t   %u\n",
		(ap->ap_entp)[i].bad_start,
		(ap->ap_entp)[i].good_start,
		((ap->ap_entp)[i].bad_end - (ap->ap_entp)[i].bad_start + 1));
	}
	(void) printf("\n      %d alternate sector(s) left for allocation.\n",
	    avail);

}

static int
absdsk_io(int fd, uint_t srtsec, char *bufp, uint_t len, int ioflag)
{
	int	rc;

	if (llseek (fd, (offset_t)srtsec * NBPSCTR, SEEK_SET) == -1)
		return(FAILURE);
	switch (ioflag)
	{
	case CMD_READ:
		rc = read (fd, bufp, len);
		break;
	case CMD_WRITE:
		rc = write (fd, bufp, len);
		break;
	default:
		break;
	}
	if (rc == -1)
		return(FAILURE);
	return(SUCCESS);
}
