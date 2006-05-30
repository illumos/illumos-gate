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

#ifndef _SYS_MD_MDDB_H
#define	_SYS_MD_MDDB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/buf.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if 0 /* DRP FOR DEBUGGING */
#define	MDDB_FAKE
#endif

/* Private flags */
#define	MD_PRV_GOTIT		0x0001	/* Been snarfed */
#define	MD_PRV_DELETE		0x0002	/* Record pending to be deleted */
#define	MD_PRV_COMMIT		0x0004	/* Record pending to be commited */
#define	MD_PRV_CLEANUP		0x0008	/* Record pending to be cleaned up */
#define	MD_PRV_CONVD		0x0010  /* Record has been converted (32->64) */
#define	MD_PRV_PENDDEL		(MD_PRV_GOTIT | MD_PRV_DELETE)
#define	MD_PRV_PENDCOM		(MD_PRV_GOTIT | MD_PRV_COMMIT)
#define	MD_PRV_PENDCLEAN	(MD_PRV_GOTIT | MD_PRV_CLEANUP)


#define	MDDB_E_INVALID	(-1)	/* an invalid argument was passed */
#define	MDDB_E_EXISTS	(-2)	/* doing an operation a 2nd time which can */
				/*	only be done once */
#define	MDDB_E_MASTER	(-3)	/* problem occurred accessing mastor block */
				/*	returned from NEW_DEV	*/
#define	MDDB_E_TOOSMALL	(-4)	/* device is not large enough */
#define	MDDB_E_NORECORD	(-5)	/* record does not exits */
				/*
				 *	returned from:	mddb_getnextrec
				 *			mddb_getrecsize
				 *			mddb_commitrec
				 *			mddb_commitrecs
				 *			mddb_deleterec
				 */
#define	MDDB_E_NOSPACE	(-6)	/* no space to create record */
#define	MDDB_E_NOTNOW	(-7)	/* do not presently have enough resources */
				/*	to perform requested operation */
#define	MDDB_E_NODB	(-8)	/* no database exist */
#define	MDDB_E_NOTOWNER (-9)	/* have not been told to grab this set */
#define	MDDB_E_STALE	(-10)	/* database is stale */
#define	MDDB_E_TOOFEW	(-11)	/* not enough replicas available */
#define	MDDB_E_TAGDATA	(-12)	/* tagged data detected */
#define	MDDB_E_ACCOK	(-13)	/* 50/50 mode */
#define	MDDB_E_NTAGDATA	(-14)	/* tagop try, no tag data */
#define	MDDB_E_ACCNOTOK	(-15)	/* accop try, no accept possible */
#define	MDDB_E_NOLOCBLK	(-16)	/* No valid locators found */
#define	MDDB_E_NOLOCNMS	(-17)	/* No valid locator name information */
#define	MDDB_E_NODIRBLK	(-18)	/* No directory blocks found */
#define	MDDB_E_NOTAGREC	(-19)	/* No tag record blocks found */
#define	MDDB_E_NOTAG	(-20)	/* No matching tag record found */
#define	MDDB_E_NODEVID	(-21)	/* No device id found */

#define	MDDB_MINBLKS		16	/* enough for a few metadevices */
#define	MDDB_MAXBLKS		8192	/* size of free bit map (must be / 8) */
#define	MDDB_MN_MINBLKS		32768	/* Multinode metadb minimum size */
					/* 16MB */
#define	MDDB_MN_MAXBLKS		524288	/* size of free bit map (must be / 8) */
					/* 256MB */

#define	MDDB_C_STALE		0x0001
#define	MDDB_C_TOOFEW		0x0002
#define	MDDB_C_NOTOWNER		0x0004
#define	MDDB_C_SET_MN_STALE	0x0008	/* Set MN set to stale */
#define	MDDB_C_IMPORT		0x0010

/*
 * Defines used to set/reset new master flag in set structure.
 * Used during reconfig cycle to determine quickly if there is
 * new master for the set.
 */
#define	MDDB_NM_SET		0x0001
#define	MDDB_NM_RESET		0x0002
#define	MDDB_NM_GET		0x0004

/* Definitions of flag in Locator Block Device ID data area - mddb_did_info */
#define	MDDB_DID_EXISTS		0x0001	/* Device ID exists */
#define	MDDB_DID_VALID		0x0002	/* Device ID valid on current system */
#define	MDDB_DID_UPDATED	0x0004  /* locator/sidelocator info updated */

/* Definitions of flag in Locator Block - mddb_lb */
#define	MDDB_DEVID_STYLE	0x0001	/* Locator Block in Device ID format */
#define	MDDB_MNSET		0x0002  /* MDDB is for a multi-node set */


#define	MDDB_MAX_PATCH	25		/* number of locations that */
					/*	can be patched in etc/system */

/*
 * Set struct used by all parts of the driver, to store anchor pointers.
 *
 * Lock associated with field in this structure:
 *
 * Some of fields are accessible by both the single threaded ioctl thread
 * and internal threads such as resync, hotsparing...etc.  In this case
 * additional protection is needed.  For example, s_db is protected by
 * s_dbmx additionally and s_un, s_ui are protected by md_unit_array_rw.lock
 * s_nm, s_nmid, s_did_nm and s_did_nmid and s_dtp are protected by nm_lock
 * Rest of other fileds are protected by md_mx.  Two fields s_un_next and
 * s_un_avail are introduced by the friendly name project and are ONLY
 * accessible via a single threaded ioctl thread which already is protected
 * by the ioctl lock and there is no need to add extra protection to them.
 * However, in the future if they become accessible by other internal threads
 * then an additional protection such as md_mx lock is highly recommended.
 *
 */
typedef struct md_set {
	uint_t		s_status;	/* set status */
	void		**s_ui;		/* set unit incore anchor */
	void		**s_un;		/* set unit anchor */
	void		*s_hsp;		/* set Hot Spare Pool anchor */
	void		*s_hs;		/* set Hot Spare anchor */
	void		*s_db;		/* set MDDB anchor */
	kmutex_t	s_dbmx;		/* set MDDB mutex */
	void		*s_nm;		/* set namespace anchor */
	mddb_recid_t	s_nmid;		/* set namespace anchor record */
	void		*s_did_nm;	/* set device id namespace anchor */
	mddb_recid_t	s_did_nmid;	/* set device id namespace anchor rec */
	void		*s_dtp;		/* set data tag rec */
	int		s_am_i_master;	/* incore master flag for this node */
	md_mn_nodeid_t	s_nodeid;	/* nodeid of this node - for MN sets */
	uint_t		s_rcnt;		/* incore resync count for set */
	unit_t		s_un_next;	/* s_un scan starts here */
	unit_t		s_un_avail;	/* number of avail slots */
} md_set_t;


#define	MDDB_MAGIC_MB	0x6d646d62	/* magic number for master blocks */
#define	MDDB_MAGIC_DB	0x6d646462	/* magic number for directory blocks */
#define	MDDB_MAGIC_RB	0x6d647262	/* magic number for record blocks */
#define	MDDB_MAGIC_LB	0x6d646c62	/* magic number for locator blocks */
#define	MDDB_MAGIC_LN	0x6d646c6e	/* magic number for locator names */
#define	MDDB_MAGIC_DT	0x6d646474	/* magic number for data tag */
#define	MDDB_MAGIC_DI	0x6d646469	/* magic number for device ID block */
#define	MDDB_MAGIC_DU	0x6d646475	/* magic num for dummy mb */
#define	MDDB_MAGIC_DE	0x6d646465	/* magic num for mb devid */

#define	MDDB_GLOBAL_XOR 1234567890

#define	MDDB_REV_MAJOR  (uint_t)0xff00
#define	MDDB_REV_MINOR  (uint_t)0x00ff

/*
 * MDDB_REV_MNMB:
 * If a MN diskset, master block revision is set to MDDB_REV_MNMB.
 * Even though the master block structure is no different
 * for a MN set, setting the revision field to a different
 * number keeps any pre-MN_diskset code from accessing
 * this diskset.  It also allows for an early determination
 * of a MN diskset when reading in from disk so that the
 * proper size locator block and locator names structure
 * can be read in thus saving time on diskset startup.
 * Since no change in master block structure, the MDDB_REV_MINOR
 * portion of the revision was incremented.
 *
 * MDDB_REV_MNLB:
 * If a MN diskset, the locator block structure is a different size in
 * order to accomodate up to MD_MNMAXSIDES nodes in a diskset
 * with any nodeid (sideno) allowed.
 * The revision is set to MDDB_REV_MNLB which is a change of the
 * MDDB_REV_MAJOR portion of the revision.
 *
 * MDDB_REV_MNLN:
 * If a MN diskset, the locator names is a different size in
 * order to accomodate up to MD_MNMAXSIDES nodes in a diskset
 * with any nodeid (sideno) allowed.
 * The revision is set to MDDB_REV_MNLN which is a change of the
 * MDDB_REV_MAJOR portion of the revision.
 *
 * The record blocks have two binary properties.  A record block can
 * represent either a 32 or 64 bit unit.  A record block can also represent
 * a traditionally named unit or a friendly named unit.  Thus, there are
 * minor revisions of record block.
 *
 *		Traditional		Friendly
 *		Name			Name
 *		-----------		--------
 * 32 bit	MDDB_REV_RB		MDDB_REV_RBFN
 * 64 bit	MDDB_REV_RB64		MDDB_REV_RB64FN
 */

#define	MDDB_REV_MB	(uint_t)0x0201
#define	MDDB_REV_MNMB	(uint_t)0x0202
#define	MDDB_REV_DB	(uint_t)0x0201
#define	MDDB_REV_LB	(uint_t)0x0500
#define	MDDB_REV_MNLB	(uint_t)0x0600
#define	MDDB_REV_LN	(uint_t)0x0100
#define	MDDB_REV_MNLN	(uint_t)0x0300
#define	MDDB_REV_RB	(uint_t)0x0200
#define	MDDB_REV_RB64	(uint_t)0x0201
#define	MDDB_REV_RBFN	(uint_t)0x0202
#define	MDDB_REV_RB64FN	(uint_t)0x0203
#define	MDDB_REV_DT	(uint_t)0x0100
#define	MDDB_REV_DI	(uint_t)0x0100

/*
 * Transfer record block friendly name status to unit/hs structure.
 */
#define	MDDB_NOTE_FN(rbv, unv)	switch (rbv) { \
				case MDDB_REV_RB: \
				case MDDB_REV_RB64: \
					unv &= ~MD_FN_META_DEV; \
					break; \
				case MDDB_REV_RBFN: \
				case MDDB_REV_RB64FN: \
					unv |= MD_FN_META_DEV; \
					break;	\
				}

#define	MDDB_BSIZE	(uint_t)DEV_BSIZE
#define	MDDB_PREFIXCNT	10
#define	MDDB_DRVNMCNT   10

typedef int	mddb_block_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct md_mnname_suffix {
	md_name_suffix	mn_ln_suffix;
	uint_t		mn_ln_sideno;
} md_mnname_suffix_t;

typedef	struct mddb_ln {
	int			ln_magic;
	uint_t			ln_revision;
	uint_t			ln_checksum;
	struct timeval32	ln_timestamp;
	md_name_prefix		ln_prefixes[MDDB_PREFIXCNT];
	/* Don't change array sizes without changing RNDUP_BLKCNT */
	md_name_suffix		ln_suffixes[MD_MAXSIDES][MDDB_NLB];
} mddb_ln_t;

/*
 * Locator name structure for MN diskset.  Same as for traditional
 * and local diskset except that more sides are supported and the
 * side number can be any number since the side number is stored
 * in the ln_mnsuffixes structure instead of being used as an index
 * into that array.  This means that the whole array may need to be
 * searched in order to find the correct information given a side number.
 */
typedef	struct mddb_mnln {
	int			ln_magic;
	uint_t			ln_revision;
	uint_t			ln_checksum;
	struct timeval32	ln_timestamp;
	md_name_prefix		ln_prefixes[MDDB_PREFIXCNT];
	/* Don't change array sizes without changing MDDB_MNLNCNT */
	md_mnname_suffix_t	ln_mnsuffixes[MD_MNMAXSIDES][MDDB_NLB];
} mddb_mnln_t;

#define	RNDUP_BLKCNT(sz, delta)	(((sz) - \
				    ((delta) * \
				    ((MD_MAXSIDES  - 1) * MDDB_NLB)) + \
				    MDDB_BSIZE - 1) / MDDB_BSIZE)
#define	MDDB_LNCNT		RNDUP_BLKCNT(sizeof (mddb_ln_t), 0)
#define	MDDB_LOCAL_LNCNT	RNDUP_BLKCNT(sizeof (mddb_ln_t), \
				    sizeof (md_name_suffix))

#define	MDDB_MNLNCNT		((sizeof (mddb_mnln_t) + (MDDB_BSIZE - 1)) \
				    / MDDB_BSIZE)

typedef struct mddb_dt {
	uint_t		dt_mag;
	uint_t		dt_rev;
	uint_t		dt_cks;
	mddb_dtag_t	dt_dtag;
} mddb_dt_t;

#define	MDDB_DT_BYTES	(roundup(sizeof (mddb_dt_t), MDDB_BSIZE))
#define	MDDB_DT_BLOCKS	(btodb(MDDB_DT_BYTES))

typedef union identifier {
	char			serial[MDDB_SN_LEN];
	struct timeval32	createtime;
} identifier_t;

typedef struct mddb_locator {
	dev32_t		l_dev;
	daddr32_t	l_blkno;
	int		l_flags;
} mddb_locator_t;

typedef struct mddb_sidelocator {
	uchar_t		l_drvnm_index;
	minor_t		l_mnum;
} mddb_sidelocator_t;

typedef struct mddb_mnsidelocator {
	uchar_t		mnl_drvnm_index;
	minor_t		mnl_mnum;
	uint_t		mnl_sideno;
} mddb_mnsidelocator_t;

typedef struct mddb_drvnm {
	uchar_t		dn_len;
	char		dn_data[MD_MAXDRVNM];
} mddb_drvnm_t;

/*
 * Locator Block Device ID Information
 * Several device id's may share one disk block in an effort to
 * conserve used replica space.
 */
typedef struct mddb_did_info {
	uint_t		info_flags;	/* MDDB Device ID flags */
	uint_t		info_firstblk;	/* Device ID Start Block */
	uint_t		info_blkcnt;	/* Device ID Block Count */
	uint_t		info_offset;	/* Device ID offset w/i Block */
	uint_t		info_length;	/* Device ID Length */
	uint_t		info_checksum;	/* Device ID Checksum */
	char		info_minor_name[32]; /* Minor name of lb dev */
} mddb_did_info_t;

typedef struct mddb_did_blk {
	int		blk_magic;	/* used for verification */
	uint_t		blk_revision;	/* used for verification */
	int		blk_checksum;	/* used for verification */
	uint_t		blk_commitcnt;	/* matches LB's commitcnt */
	mddb_did_info_t	blk_info[MDDB_NLB];
} mddb_did_blk_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#define	MDDB_DID_BYTES	(roundup(sizeof (mddb_did_blk_t), MDDB_BSIZE))
#define	MDDB_DID_BLOCKS	(btodb(MDDB_DID_BYTES))

/*
 * Device ID Disk Blocks.
 * Incore linked list of disk blocks containing device IDs.
 * The list is built when reading in the mddb_did_blk structure and
 * when reading in the actual disk blocks containing device ids.
 * This list is used to easily write out all disk blocks containing
 * device ids.
 */
typedef struct mddb_did_db {
	uint_t		db_firstblk;	/* Disk Block's logical addr */
	uint_t		db_blkcnt;	/* Contig Disk Block Count */
	caddr_t		db_ptr;		/* Ptr to incore Block(s) */
	struct mddb_did_db	*db_next;	/* Ptr to next in list */
} mddb_did_db_t;

/*
 * Device ID Free List.
 * Incore linked list of free space in disk blocks containing device IDs.
 * Used to manage placement of device IDs in disk blocks.
 * All disk blocks on free list are also in linked list of disk block
 * containing device IDs (mddb_did_db_t).
 */
typedef struct mddb_did_free {
	uint_t			free_blk;	/* Disk Block's logical addr */
	uint_t			free_offset;	/* offset of free space */
	uint_t			free_length;	/* length of free space */
	struct mddb_did_free	*free_next;	/* Ptr to next in list */
} mddb_did_free_t;

/*
 * Device ID Incore Area
 *    Contains pointer to Device ID Disk Block list and
 *         Device ID Free List.
 *    Also contains incore array of pointers to device IDs.  Pointers
 *    point into the device ID Disk Block list and are used as a
 *    shortcut to find incore device IDs.
 */
typedef struct mddb_did_ic {
	mddb_did_blk_t	*did_ic_blkp;
	mddb_did_db_t	*did_ic_dbp;
	mddb_did_free_t	*did_ic_freep;
	ddi_devid_t	did_ic_devid[MDDB_NLB]; /* Ptr to device IDs */
} mddb_did_ic_t;

/*
 * Locator Block (LB):
 *	- Are fixed size, but the size is different
 *		for local/shared set db replicas.
 *	- All LB's start at logical block 0.
 * 	- After a replica quorum is found, there is
 *	  is only one incore copy of the LB.
 *	- LB's are only written when replicas are added, deleted, or errored.
 *	- LB's provide information about other replica's and their state.
 */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct mddb_lb {
	int			lb_magic;	/* used for verification */
	uint_t			lb_revision;	/* used for verification */
	int			lb_checksum;	/* used for verification */
	uint_t			lb_commitcnt;	/* IMPORTANT */
	struct timeval32	lb_timestamp;	/* informative only */
	int			lb_loccnt;	/* used for verification */
	identifier_t		lb_ident;	/* used for verification */
	uint_t			lb_flags;	/* flags describing LB */
	uint_t			lb_spare[8];	/* Spare/Pad */
	mddb_block_t		lb_didfirstblk;	/* Devid Array Start Block */
	mddb_block_t		lb_didblkcnt;	/* Devid Array Number Blocks */
	mddb_block_t		lb_dtfirstblk;	/* Data Tag Start Block */
	mddb_block_t		lb_dtblkcnt;	/* Data Tag Number Block(s) */
	struct timeval32	lb_inittime;	/* creation of database */
	set_t			lb_setno;	/* used for verification */
	mddb_block_t		lb_blkcnt;	/* used for verification */
	mddb_block_t		lb_lnfirstblk;
	mddb_block_t		lb_lnblkcnt;
	mddb_block_t		lb_dbfirstblk;
	mddb_drvnm_t		lb_drvnm[MDDB_DRVNMCNT];
	mddb_locator_t		lb_locators[MDDB_NLB];
	/* Don't change array sizes without changing RNDUP_BLKCNT */
	mddb_sidelocator_t	lb_sidelocators[MD_MAXSIDES][MDDB_NLB];
} mddb_lb_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * Locator block structure for MN diskset.  Same as for traditional
 * and local diskset except that more sides are supported and the
 * side number can be any number since the side number is stored
 * in the lb_mnsidelocators structure instead of being used as an index
 * into that array.  This means that the whole array may need to be
 * searched in order to find the correct information given a side number.
 */
typedef struct mddb_mnlb {
	int			lb_magic;	/* used for verification */
	uint_t			lb_revision;	/* used for verification */
	int			lb_checksum;	/* used for verification */
	uint_t			lb_commitcnt;	/* IMPORTANT */
	struct timeval32	lb_timestamp;	/* informative only */
	int			lb_loccnt;	/* used for verification */
	identifier_t		lb_ident;	/* used for verification */
	uint_t			lb_flags;	/* flags describing LB */
	uint_t			lb_spare[8];	/* Spare/Pad */
	mddb_block_t		lb_didfirstblk;	/* Devid Array Start Block */
	mddb_block_t		lb_didblkcnt;	/* Devid Array Number Blocks */
	mddb_block_t		lb_dtfirstblk;	/* Data Tag Start Block */
	mddb_block_t		lb_dtblkcnt;	/* Data Tag Number Block(s) */
	struct timeval32	lb_inittime;	/* creation of database */
	set_t			lb_setno;	/* used for verification */
	mddb_block_t		lb_blkcnt;	/* used for verification */
	mddb_block_t		lb_lnfirstblk;
	mddb_block_t		lb_lnblkcnt;
	mddb_block_t		lb_dbfirstblk;
	mddb_drvnm_t		lb_drvnm[MDDB_DRVNMCNT];
	mddb_locator_t		lb_locators[MDDB_NLB];
	/* Don't change array sizes without changing MDDB_MNLBCNT */
	mddb_mnsidelocator_t	lb_mnsidelocators[MD_MNMAXSIDES][MDDB_NLB];
} mddb_mnlb_t;


#define	MDDB_LBCNT		RNDUP_BLKCNT(sizeof (mddb_lb_t), 0)
#define	MDDB_LOCAL_LBCNT	RNDUP_BLKCNT(sizeof (mddb_lb_t), \
				    sizeof (mddb_sidelocator_t))

#define	MDDB_MNLBCNT		((sizeof (mddb_mnlb_t) + (MDDB_BSIZE - 1)) \
				    / MDDB_BSIZE)

typedef struct mddb_map {
	daddr32_t		m_consecutive;
	daddr32_t		m_firstblk;
} mddb_map_t;

/*
 * Master block(s) (MB)
 * 	- Are written by userland; Never by the driver!
 *	- Each replica has there own master blocks,
 *		the master block(s) are not shared.
 *	- MB's are not in the logical block address space of the database.
 *	- MB's are a fixed size record (MDDB_BSIZE)
 *	- MB's provide the logical to physical block translation,
 *		for their replica.
 */
typedef	struct mddb_mb {
	int			mb_magic;	/* used for verification */
	uint_t			mb_revision;	/* used for verification */
	uint_t			mb_checksum;	/* used for verification */
#ifdef _LP64
	uint32_t		mb_next;	/* incore to next mb */
#else
	struct mddb_mb		*mb_next;	/* incore to next mb */
#endif	/* _LP64 */
	daddr32_t		mb_nextblk;	/* block # for next mb */
	md_timeval32_t		mb_timestamp;	/* timestamp */
	daddr32_t		mb_blkcnt;	/* size of blkmap */
	daddr32_t		mb_blkno;	/* physical loc. for this MB */
	set_t			mb_setno;	/* used for verification */
	struct timeval32	mb_setcreatetime; /* set creation timestamp */
	int			spares[7];
	mddb_map_t		mb_blkmap;	/* logical->physical blk map */
	int			mb_devid_magic;	/* verify devid in mb */
	short			mb_devid_len;	/* len of following devid */
	char			mb_devid[1];	/* devid byte array */
} mddb_mb_t;

/*
 * In-core version of mddb_mb. It is known that the mddb_mb is 512 bytes on
 * disk, really, and so this structure is 512 + sizeof(struct mddb_mb_ic *)
 */
#define	MDDB_IC_BSIZE	(MDDB_BSIZE + sizeof (struct mddb_mb_ic *))
typedef struct mddb_mb_ic {
	struct mddb_mb_ic 	*mbi_next;
	struct mddb_mb		mbi_mddb_mb;
} mddb_mb_ic_t;


/*
 * there can be no address in record block. The checksum must
 * stay the same where ever the record is in memory. Many
 * things depend on this. Also the timestamp is the time the the
 * record was committed not the time it was written to a particular
 * device.
 *
 * Old definition of mddb_rb, for 32-bit apps and libraries
 */
typedef struct mddb_rb {
	uint_t			rb_magic;
	uint_t			rb_revision;
	uint_t			rb_checksum;
	uint_t			rb_checksum_fiddle;
	uint_t			rb_private;
	void			*rb_userdata;
	uint_t			rb_commitcnt;
	uint_t			rb_spare[1];
	struct timeval32	rb_timestamp;
	int			rb_data[1];
} mddb_rb_t;

/* This is, and always will be, the on-disk version of mddb_rb */
typedef struct mddb_rb32 {
	uint_t			rb_magic;
	uint_t			rb_revision;
	uint_t			rb_checksum;
	uint_t			rb_checksum_fiddle;
	uint_t			rb_private;
	uint32_t		rb_userdata;
	uint_t			rb_commitcnt;
	uint_t			rb_spare[1];
	struct timeval32	rb_timestamp;
	int			rb_data[1];
} mddb_rb32_t;

/*
 * directory entries
 */
typedef struct mddb_optinfo {
	int		o_li;
	int		o_flags;
} mddb_optinfo_t;

/* Old definition of mddb_de, for 32-bit apps and libraries */
typedef struct mddb_de {
	struct mddb_de	*de_next;
	mddb_rb_t	*de_rb;
	mddb_recid_t	de_recid;
	mddb_type_t	de_type1;
	uint_t		de_type2;
	uint_t		de_reqsize;
	uint_t		de_recsize;
	mddb_block_t	de_blkcount;
	uint_t		de_flags;
	mddb_optinfo_t	de_optinfo[2];
	mddb_block_t	de_blks[1];
} mddb_de_t;

/*
 * In core version of mddb_de, includes pointer for mddb_rb32_t user data
 * mddb_rb32_t is used incore
 */
typedef struct mddb_de_ic {
	void			*de_rb_userdata;
	void			*de_rb_userdata_ic;
	uint_t			de_owner_nodeid;
	struct mddb_de_ic	*de_next;
	mddb_rb32_t		*de_rb;
	mddb_recid_t		de_recid;
	mddb_type_t		de_type1;
	uint_t			de_type2;
	size_t			de_reqsize;
	size_t			de_icreqsize;
	size_t			de_recsize;
	uint_t			de_blkcount;
	uint_t			de_flags;
	mddb_optinfo_t		de_optinfo[2];
	mddb_block_t		de_blks[1];
} mddb_de_ic_t;

typedef struct mddb_db {
	uint_t			db_magic;
	uint_t			db_revision;
	uint_t			db_checksum;
	mddb_block_t		db_blknum;
	struct mddb_db		*db_next;
	mddb_block_t		db_nextblk;
	struct timeval32	db_timestamp;
	uint_t			db_recsum;
#ifdef _KERNEL
	mddb_de_ic_t		*db_firstentry;
#else
	mddb_de_t		*db_firstentry;
#endif
} mddb_db_t;

/*
 * This is, and always will be, the on-disk version of mddb_de
 * When mddb_de32 is read in it is converted into mddb_de_ic
 */
typedef struct mddb_de32 {
	uint32_t	de32_next;
	uint32_t	de32_rb;
	mddb_recid_t	de32_recid;
	mddb_type_t	de32_type1;
	uint_t		de32_type2;
	uint_t		de32_reqsize;
	uint_t		de32_recsize;
	mddb_block_t	de32_blkcount;
	uint_t		de32_flags;
	mddb_optinfo_t	de32_optinfo[2];
	mddb_block_t	de32_blks[1];
} mddb_de32_t;

/*
 * This is, and always will be, the on-disk version of mddb_db
 * When mddb_db32 is read in it is converted into mddb_db
 * To minimize impact on mddb format mddb_db fileds remain intact
 */
typedef struct mddb_db32 {
	uint_t			db32_magic;
	uint_t			db32_revision;
	uint_t			db32_checksum;
	mddb_block_t		db32_blknum;
	uint32_t		db32_next;
	mddb_block_t		db32_nextblk;
	struct timeval32	db32_timestamp;
	uint_t			db32_recsum;
	uint32_t		db32_firstentry;
} mddb_db32_t;

#define	de32tode(from, to) \
	{ \
	int i; \
	to->de_rb_userdata = NULL; \
	to->de_owner_nodeid = MD_MN_INVALID_NID; \
	to->de_next = (struct mddb_de_ic *)(uintptr_t)from->de32_next; \
	to->de_rb = (mddb_rb32_t *)(uintptr_t)from->de32_rb; \
	to->de_recid =  from->de32_recid; \
	to->de_type1 =  from->de32_type1; \
	to->de_type2 =  from->de32_type2; \
	to->de_reqsize =  from->de32_reqsize; \
	to->de_recsize =  from->de32_recsize; \
	to->de_blkcount =  from->de32_blkcount; \
	to->de_flags =  from->de32_flags; \
	to->de_optinfo[0] =  from->de32_optinfo[0]; \
	to->de_optinfo[1] =  from->de32_optinfo[1]; \
	for (i = 0; i < from->de32_blkcount; i++) \
		to->de_blks[i] = from->de32_blks[i]; \
	}

#define	detode32(from, to) \
	{ \
	int i; \
	to->de32_next = (uint32_t)(uintptr_t)from->de_next; \
	to->de32_rb = (uint32_t)(uintptr_t)from->de_rb; \
	to->de32_recid =  from->de_recid; \
	to->de32_type1 =  from->de_type1; \
	to->de32_type2 =  from->de_type2; \
	to->de32_reqsize =  from->de_reqsize; \
	to->de32_recsize =  from->de_recsize; \
	to->de32_blkcount =  from->de_blkcount; \
	to->de32_flags =  from->de_flags; \
	to->de32_optinfo[0] =  from->de_optinfo[0]; \
	to->de32_optinfo[1] =  from->de_optinfo[1]; \
	for (i = 0; i < from->de_blkcount; i++) \
		to->de32_blks[i] = from->de_blks[i]; \
	}

#define	db32todb(from, to) \
	to->db_magic = from->db32_magic; \
	to->db_revision = from->db32_revision; \
	to->db_checksum = from->db32_checksum; \
	to->db_blknum = from->db32_blknum; \
	to->db_next = (struct mddb_db *)(uintptr_t)from->db32_next; \
	to->db_nextblk = from->db32_nextblk; \
	to->db_timestamp = from->db32_timestamp; \
	to->db_recsum = from->db32_recsum; \
	to->db_firstentry = (mddb_de_ic_t *)(uintptr_t)from->db32_firstentry;

#define	dbtodb32(from, to) \
	to->db32_magic = from->db_magic; \
	to->db32_revision = from->db_revision; \
	to->db32_checksum = from->db_checksum; \
	to->db32_blknum = from->db_blknum; \
	to->db32_next = (uint32_t)(uintptr_t)from->db_next; \
	to->db32_nextblk = from->db_nextblk; \
	to->db32_timestamp = from->db_timestamp; \
	to->db32_recsum = from->db_recsum; \
	to->db32_firstentry = (uint32_t)(uintptr_t)from->db_firstentry;

/*
 * information about a replica of the data base
 */
typedef struct mddb_ri {
	struct mddb_ri		*ri_next;
	uint_t			ri_flags;
	uint_t			ri_commitcnt;
	int			ri_transplant;
	md_dev64_t		ri_dev;
	daddr32_t		ri_blkno;
	char			ri_driver[16];
	mddb_mb_ic_t		*ri_mbip;
	mddb_lb_t		*ri_lbp;
	mddb_dt_t		*ri_dtp;
	mddb_did_ic_t		*ri_did_icp;
	ddi_devid_t		ri_devid;
	ddi_devid_t		ri_old_devid;
	char			ri_minor_name[MDDB_MINOR_NAME_MAX];
	char			ri_devname[MAXPATHLEN];
} mddb_ri_t;

typedef struct mddb_bf {
	struct mddb_bf	*bf_next;
	mddb_locator_t	*bf_locator;
	buf_t		bf_buf;
} mddb_bf_t;

/*
 * Information for sets of databases (which include replicas)
 */
#define	MDDB_BITSRECID	31
#define	MDDB_SETSHIFT	(MDDB_BITSRECID - MD_BITSSET)
#define	MDDB_SETMASK	(MD_SETMASK << MDDB_SETSHIFT)
#define	MDDB_RECIDMASK	((1 << MDDB_SETSHIFT) - 1)

#define	DBSET(id)	(((id) & MDDB_SETMASK) >> MDDB_SETSHIFT)
#define	DBID(id)	((id) & MDDB_RECIDMASK)
#define	MAKERECID(s, i)	((((s) << MDDB_SETSHIFT) & MDDB_SETMASK) | \
			((i) & MDDB_RECIDMASK))

#define	MDDB_PARSE_LOCBLK	0x00000001
#define	MDDB_PARSE_LOCNM	0x00000002
#define	MDDB_PARSE_OPTRECS	0x00000004
#define	MDDB_PARSE_MASK		0x0000000F


#define	MDDB_BLOCK_PARSE	0x00000001	/* Block sending parse msgs */
#define	MDDB_UNBLOCK_PARSE	0x00000002	/* Unblock sending parse msgs */

/*
 * We need to keep s_ident and s_inittime 32 bit.  They are used in mddb_lb
 */
typedef struct mddb_set {
	uint_t		s_setno;		/* set number */
	uint_t		s_sideno;		/* side number */
	identifier_t	s_ident;		/* set identifier */
	char		*s_setname;		/* set name */
	mddb_mb_ic_t	**s_mbiarray;		/* master blocks array */
	mddb_db_t	*s_dbp;			/* directory block */
	mddb_lb_t	*s_lbp;			/* locator block */
						/* May be cast to mddb_mnlb_t */
						/* if accessing sidenames in */
						/* MN diskset */
	mddb_ln_t	*s_lnp;			/* locator names block */
						/* May be cast to mddb_mnln_t */
						/* if accessing sidenames in */
						/* MN diskset */
	mddb_dtag_lst_t	*s_dtlp;		/* List of data tags found */
	mddb_did_ic_t	*s_did_icp;		/* Device ID incore area */
	mddb_ri_t	*s_rip;			/* replicas incore list */
	int		s_freeblkcnt;		/* visable for test code */
	int		s_totalblkcnt;		/* visable for test code */
	int		s_mn_parseflags;	/* mddb parse flags for MNset */
	int		s_mn_parseflags_sending; /* parse flgs sent to slaves */
	uchar_t		*s_freebitmap;		/* free blocks bitmap */
	uint_t		s_freebitmapsize;	/* size of bitmap */
	struct timeval32	s_inittime;	/* timestamp set created */
	mddb_recid_t	s_zombie;		/* zombie record - createrec */
	int		s_staledeletes;		/* number of stale deleterec */
	int		s_optcmtcnt;		/* Following are opt. record */
	int		s_opthavelck;		/*   bookkeeping records ... */
	int		s_optwantlck;
	kcondvar_t	s_optwantlck_cv;
	int		s_optwaiterr;
	int		s_opthungerr;
	kcondvar_t	s_opthungerr_cv;
	int		s_opthavequeuinglck;
	int		s_optwantqueuinglck;
	kcondvar_t	s_optqueuing_cv;
	ulong_t		s_bufmisses;
	mddb_bf_t	*s_freebufhead;
	int		s_bufwakeup;
	kcondvar_t	s_buf_cv;
	size_t		s_databuffer_size;
	void		*s_databuffer;
	int		s_singlelockgotten;
	int		s_singlelockwanted;
	kcondvar_t	s_single_thread_cv;
	md_hi_arr_t	s_med;
} mddb_set_t;

#ifndef MDDB_FAKE
#ifdef _KERNEL
/* md_mddb.c */
extern uint_t			mddb_lb_did_convert(mddb_set_t *,
				    uint_t, uint_t *);
extern void			mddb_locatorblock2splitname(mddb_ln_t *,
				    int, side_t, md_splitname *);
extern int			mddb_configure(mddb_cfgcmd_t,
				    struct mddb_config *);
extern mddb_recid_t		mddb_getnextrec(mddb_recid_t,
				    mddb_type_t, uint_t);
extern int			mddb_getoptloc(mddb_optloc_t *);
extern void			*mddb_getrecaddr(mddb_recid_t);
extern void			*mddb_getrecaddr_resize(mddb_recid_t, size_t,
				    off_t);
extern int			mddb_getrecprivate(mddb_recid_t);
extern void			mddb_setrecprivate(mddb_recid_t, uint_t);
extern mddb_de_ic_t		*mddb_getrecdep(mddb_recid_t);
extern mddb_type_t		mddb_getrectype1(mddb_recid_t);
extern int			mddb_getrectype2(mddb_recid_t);
extern int			mddb_getrecsize(mddb_recid_t);
extern int			mddb_commitrec(mddb_recid_t);
extern int			mddb_commitrecs(mddb_recid_t *);
extern int			mddb_deleterec(mddb_recid_t);
extern mddb_recstatus_t		mddb_getrecstatus(mddb_recid_t);
extern mddb_recid_t		mddb_createrec(size_t usersize,
				    mddb_type_t type, uint_t type2,
				    md_create_rec_option_t option, set_t setno);
extern void			mddb_init(void);
extern void			mddb_unload(void);
extern void			mddb_unload_set(set_t setno);
extern mddb_recid_t		mddb_makerecid(set_t setno, mddb_recid_t id);
extern set_t			mddb_getsetnum(mddb_recid_t id);
extern char			*mddb_getsetname(set_t setno);
extern side_t			mddb_getsidenum(set_t setno);
extern int			mddb_ownset(set_t setno);
extern int			getmed_ioctl(mddb_med_parm_t *medpp, int mode);
extern int			setmed_ioctl(mddb_med_parm_t *medpp, int mode);
extern int			updmed_ioctl(mddb_med_upd_parm_t *medpp,
				    int mode);
extern int			take_set(mddb_config_t *cp, int mode);
extern int			release_set(mddb_config_t *cp, int mode);
extern int			gettag_ioctl(mddb_dtag_get_parm_t *dtgpp,
				    int mode);
extern int			usetag_ioctl(mddb_dtag_use_parm_t *dtupp,
				    int mode);
extern int			accept_ioctl(mddb_accept_parm_t *medpp,
				    int mode);
extern int			md_update_locator_namespace(set_t setno,
				    side_t side, char *dname, char *pname,
				    md_dev64_t devt);
extern int			mddb_validate_lb(set_t setno, int *rmaxsz);
extern int			mddb_getinvlb_devid(set_t setno, int count,
				    int size, char **ctdptr);
extern int			md_update_minor(set_t, side_t, mdkey_t);
extern int			md_update_nm_rr_did_ioctl(mddb_config_t *cp);
extern int			md_update_top_device_minor(set_t, side_t,
				    md_dev64_t);
#ifdef DEBUG
extern void			mddb_check(void);
#endif /* DEBUG */
#endif /* _KERNEL */

#else

caddr_t mddb_fakeit;

#define	md_lb_did_convert(a, b, c)	(0)
#define	mddb_configure(a, b)	(0)
#define	mddb_getnextrec(a, b, c)		((mddb_recid_t)0)
#define	mddb_getrecaddr(a)	(mddb_fakeit)
#define	mddb_getrecprivate(a)	(0)
#define	mddb_setrecprivate(a, b) (0)
#define	mddb_getrectype1(a)	(0)
#define	mddb_getrectype2(a)	(0)
#define	mddb_getrecsize(a)	(0)
#define	mddb_commitrec(a)	(0)
#define	mddb_commitrecs(a)	(0)
#define	mddb_deleterec(a)	(0)
#define	mddb_getrecstatus(a)	(MDDB_OK)
#define	mddb_createrec(s, a, b)	(0xffff & (int)(mddb_fakeit = \
					(caddr_t)kmem_zalloc(s, KM_SLEEP)))
#define	mddb_unload()		(0)

#endif

#define	MDDB_NOSLEEP	1
#define	MDDB_SLEEPOK	0

#define	MDDB_NOOLDOK	0x1
#define	MDDB_MUSTEXIST	0x2
#define	MDDB_NOINIT	0x4
#define	MDDB_MULTINODE	0x8
#define	MDDB_MN_STALE	0x10	/* MN set is stale */

/* Flags passed to selectreplicas - not a bit mask */
#define	MDDB_SCANALL		1
#define	MDDB_RETRYSCAN		0
#define	MDDB_SCANALLSYNC	2	/* During reconfig, sync up incore */
					/* and ondisk mddb by writing incore */
					/* values to disk.  Don't write */
					/* change log records. */

/* Flags passed to writestart and writecopy */
#define	MDDB_WRITECOPY_ALL	1	/* Write all incore mddb to disk */
#define	MDDB_WRITECOPY_SYNC	2	/* Write incore mddb to disk except */
					/* 	- change log records */
					/*	- optimized resync records */


#define	MDDB_PROBE	1
#define	MDDB_NOPROBE	0


/*
 * MN diskset definitions used to determine if a slave can write
 * directly to the mddb.  ONLY_MASTER only allows the master node
 * to write to the mddb.  ANY_NODE allows any node to write
 * to the mddb.
 */
#define	MDDB_WR_ONLY_MASTER	0
#define	MDDB_WR_ANY_NODE	1

#define	MDDB_L_LOCKED	0x0001	/* this record is locked */
#define	MDDB_L_WANTED	0x0002

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_MDDB_H */
