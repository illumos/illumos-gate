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
 */

#ifndef	_SYS_FS_UDF_VOLUME_H
#define	_SYS_FS_UDF_VOLUME_H

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	UDF_102	0x66
#define	UDF_150	0x96
#define	UDF_200	0xC8

/* fid_idlen include compression id */
#define	FID_LEN(fid)	(((sizeof (struct file_id) +	\
		SWAP_16((fid)->fid_iulen) + (fid)->fid_idlen - 2) + 3) & ~3)

/*
 * #define	ID_LEN(fid)	\
 *		(((SWAP_16((fid)->fid_iulen) + (fid)->fid_idlen - 2) + 3) & ~3)
 */

#define	F_LEN		(sizeof (struct file_id) - 2)

#define	UDF_DOMAIN_NAME		"*OSTA UDF Compliant\0\0\0\0"
#define	UDF_LV_INFO		"*UDF LV Info\0\0\0\0\0\0\0\0\0\0\0\0"
#define	UDF_FREEEASPACE		"*UDF FreeEASpace\0\0\0\0\0\0\0\0"
#define	UDF_FREEAEASPACE	"*UDF FreeAppEASpace\0\0\0\0"
#define	UDF_CGMS_INFO		"*UDF DVD CGMS Info\0\0\0\0"
#define	UDF_OS2_EA		"*UDF OS/2 EA\0\0\0\0\0\0\0\0\0\0\0"
#define	UDF_OS2_EA_LEN		"*UDF OS/2 EALength\0\0\0\0\0\0"
#define	UDF_MAC_VOLINFO		"*UDF Mac VolumeInfo\0\0\0\0"
#define	UDF_MAC_UNIQID		"*UDF Mac UniqueIDTable\0"
#define	UDF_MAC_RESFRK		"*UDF Mac ResourceFork\0\0"
#define	UDF_VIRT_PART		"*UDF Virtual Partition\0"
#define	UDF_SPAR_PART		"*UDF Sparable Partition"
#define	UDF_VAT			"*UDF Virtual Alloc Tbl\0"
#define	UDF_SPAR_TBL		"*UDF Sparing Table\0\0\0\0\0"


#if defined(_BIG_ENDIAN)
#define	SWAP_16(a)	(((ushort_t)((a) & 0xff) << 8) | \
					((ushort_t)((a) & 0xff00) >> 8))
#define	SWAP_32(a)	((((a) & 0xff) << 24) |	\
				(((a) & 0xff00) << 8) |	\
				(((a) & 0xff0000) >> 8) |	\
				(((a) & 0xff000000) >> 24))
#define	SWAP_64(a)	((((a) & 0xffULL) << 56)	| \
				(((a) & 0xff00ULL) << 40) | \
				(((a) & 0xff0000ULL) << 24) | \
				(((a) & 0xff000000ULL) << 8) | \
				(((a) & 0xff00000000ULL) >> 8) | \
				(((a) & 0xff0000000000ULL) >> 24) | \
				(((a) & 0xff000000000000ULL) >> 40) | \
				(((a) & 0xff00000000000000ULL) >> 56))

#define	GET_32(a)	((uint32_t)(*((uint8_t *)a)) | \
				(((uint32_t)(*(((uint8_t *)a) + 1))) << 8) | \
				(((uint32_t)(*(((uint8_t *)a) + 2))) << 16) | \
				(((uint32_t)(*(((uint8_t *)a) + 3))) << 24))
#else
#define	SWAP_16(a)	(a)
#define	SWAP_32(a)	(a)
#define	SWAP_64(a)	(a)

#define	GET_32(a)	(*((uint32_t *)a))
#endif	/* _BIG_ENDIAN */


#define	BCD2HEX_16(a)	(((a) & 0xf) + \
			(((ushort_t)((a) & 0xf0) >> 4) * 10) + \
			(((ushort_t)((a) & 0xf00) >> 8) * 100) + \
			(((ushort_t)((a) & 0xf000) >> 12) * 1000))

#define	HEX2BCD_16(a)	((((ushort_t)a) % 10) | \
			(((ushort_t)((ushort_t)(a) / 10) % 10) << 4) | \
			(((ushort_t)((ushort_t)(a) / 100) % 10) << 8) | \
			(((ushort_t)((ushort_t)(a) / 1000) % 10) << 12))

#define	ANCHOR_VOL_DESC_LOC	(256)
#define	ANCHOR_VOL_DESC_LEN	0x200



/* Basic data structures */


typedef char dstring_t;


/*
 * recorded at the start of the descriptor
 * used to distinguish between different
 * descriptors
 */
struct tag {
	uint16_t	tag_id;		/* 00 Tag Identifier */
	uint16_t	tag_desc_ver;	/* 02 Descriptor Version */
	uint8_t		tag_cksum;	/* 04 Tag Checksum */
	uint8_t		tag_res;	/* 05 Reserved */
	uint16_t	tag_sno;	/* 06 Tag Serial Number */
	uint16_t	tag_crc;	/* 08 Descriptor CRC */
	uint16_t	tag_crc_len;	/* 0A Descriptor CRC length */
	uint32_t	tag_loc;	/* 0C Tag Location */
};
typedef struct tag tag_t;

/*
 * descriptor tag id values
 */

#define	UD_PRI_VOL_DESC		0x0001
#define	UD_ANCH_VOL_DESC	0x0002
#define	UD_VOL_DESC_PTR		0x0003
#define	UD_IMPL_USE_DESC	0x0004
#define	UD_PART_DESC		0x0005
#define	UD_LOG_VOL_DESC		0x0006
#define	UD_UNALL_SPA_DESC	0x0007
#define	UD_TERM_DESC		0x0008
#define	UD_LOG_VOL_INT		0x0009

#define	UD_FILE_SET_DESC	0x0100
#define	UD_FILE_ID_DESC		0x0101
#define	UD_ALLOC_EXT_DESC	0x0102
#define	UD_INDIRECT_ENT		0x0103
#define	UD_TERMINAL_ENT		0x0104
#define	UD_FILE_ENTRY		0x0105
#define	UD_EXT_ATTR_HDR		0x0106
#define	UD_UNALL_SPA_ENT	0x0107
#define	UD_SPA_BMAP_DESC	0x0108
#define	UD_PART_INT_DESC	0x0109
#define	UD_EXT_FILE_ENT		0x010A




/*
 * Character set's allowed in descriptor fields
 * shall be specified
 */
struct charspec {
	uint8_t		cs_type;	/* 00 Character Set Type */
	char		cs_info[63];	/* 01 Character Set Information */
};
typedef struct charspec charspec_t;

#define	CS_TYPE0	0x00
#define	CS_TYPE1	0x01
#define	CS_TYPE2	0x02
#define	CS_TYPE3	0x03
#define	CS_TYPE4	0x04
#define	CS_TYPE5	0x05
#define	CS_TYPE6	0x06
#define	CS_TYPE7	0x07
#define	CS_TYPE8	0x08



/*
 * Entity Identification
 */
struct regid {
	uint8_t		reg_flags;	/* 00 Flags */
	char		reg_id[23];	/* 01 Identifier */
	char		reg_ids[8];	/* 18 Identifier Suffix */
};
typedef struct regid regid_t;

#define	EI_FLAG_DIRTY		0x00
#define	EI_FLAG_PROT		0x01

struct lb_addr {
	/* uint32_t	lba_number;	00 Logical Block Number */
	/* uint8_t	lba_prn[2];	04 Partition Reference Number */
	char		lba_aaa[6];
};
typedef	struct lb_addr lb_addr_t;
#define	lba_number(x)(((x)->lba_aaa[0]) | \
			((x)->lba_aaa[1] << 8) | \
			((x)->lba_aaa[2] << 16) | \
			((x)->lba_aaa[3] << 24))

#define	lba_prn(x)	((x)->lba_aaa[4] | ((x)->lba_aaa[5] << 8))


/*
 * Extend Descriptor
 */
struct extent_ad {
	uint32_t	ext_len;	/* 00 Extent Length */
	uint32_t	ext_loc;	/* 04 Extent Location */
};
typedef struct extent_ad extent_ad_t;

/*
 * Short Allocation Descriptor
 */
struct short_ad {
	uint32_t	sad_ext_len;	/* 00 Extent Length */
	uint32_t	sad_ext_loc;	/* 04 extent Position */
};
typedef struct short_ad short_ad_t;

/*
 * Long Allocation Descriptor
 */
struct long_ad {
	uint32_t	lad_ext_len;	/* 00 Extent Length */
	uint32_t	lad_ext_loc;	/* 04 Extent Location */
	uint16_t	lad_ext_prn;	/* 08 Extent part ref no */
	/* lb_addr_t	lad_ext_loc;	 04 Extent Location */
	char		lad_iu[6];	/* 0A Implementation Use */
};
typedef struct long_ad long_ad_t;




/*
 * Format to record date and time
 * If zero date & time is not specified
 */
struct tstamp {
	uint16_t	ts_tzone;	/* 00 Type and Time Zone */
	uint16_t	ts_year;	/* 02 Year */
	uint8_t		ts_month;	/* 04 Month */
	uint8_t		ts_day;		/* 05 Day */
	uint8_t		ts_hour;	/* 06 Hour */
	uint8_t		ts_min;		/* 07 Minute */
	uint8_t		ts_sec;		/* 08 Second */
	uint8_t		ts_csec;	/* 09 Centi-seconds */
	uint8_t		ts_husec;	/* 0A Hundreds of Micro sec's */
	uint8_t		ts_usec;	/* 0B Micro-seconds */
};
typedef struct tstamp tstamp_t;


/*
 * ts_tzone
 */
#define	TMODE		0xF000
#define	TSIGN		0x0800
#define	TOFFSET		0x07FF
#define	TINVALID	(TSIGN|TOFFSET)


/*
 * Format of the ICB tag which specifies
 * most of the infomation of the file
 */
struct icb_tag {
	uint32_t	itag_prnde;	/* 00 Prior Recorded No of Dir Entry */
	uint16_t	itag_strategy;	/* 04 Strategy Type */
	uint16_t	itag_param;	/* 06 Strategy parameter */
	uint16_t	itag_max_ent;	/* 08 Maximum No of Entries */
	uint8_t		itag_rsvd;	/* 0A Reserved */
	uint8_t		itag_ftype;	/* 0B File Type */
	/* lb_addr_t	itag_lb_addr;	0C parent ICB Location */
	uint32_t	itag_lb_loc;	/* 0C */
	uint16_t	itag_lb_prn;	/* 10 */
	uint16_t	itag_flags;	/* 12 Flags */
};
typedef struct icb_tag icb_tag_t;

/*
 * Different strategy types for the file
 * For DVD_ROM we use onlt type4
 */
#define	STRAT_TYPE1		0x0001
#define	STRAT_TYPE2		0x0002
#define	STRAT_TYPE3		0x0003
#define	STRAT_TYPE4		0x0004
#define	STRAT_TYPE4096		0x1000

/*
 * File types
 */
#define	FTYPE_UNALL_SPACE	0x01
#define	FTYPE_PART_INTEG	0x02
#define	FTYPE_INDIRECT		0x03
#define	FTYPE_DIRECTORY		0x04
#define	FTYPE_FILE		0x05
#define	FTYPE_BLOCK_DEV		0x06
#define	FTYPE_CHAR_DEV		0x07
#define	FTYPE_EAR		0x08
#define	FTYPE_FIFO		0x09
#define	FTYPE_C_ISSOCK		0x0A
#define	FTYPE_T_ENTRY		0x0B
#define	FTYPE_SYMLINK		0x0C

/*
 * Flags
 */
#define	ICB_FLAG_SHORT_AD	0x0000
#define	ICB_FLAG_LONG_AD	0x0001
#define	ICB_FLAG_EXT_AD		0x0002
#define	ICB_FLAG_ONE_AD		0x0003
#define	ICB_FLAG_SORTED		0x0008
#define	ICB_FLAG_NON_RELOC	0x0010
#define	ICB_FLAG_ARCHIVE	0x0020
#define	ICB_FLAG_SETUID		0x0040
#define	ICB_FLAG_SETGID		0x0080
#define	ICB_FLAG_STICKY		0x0100
#define	ICB_FLAG_CONTIG		0x0200
#define	ICB_FLAG_SYSTEM		0x0400
#define	ICB_FLAG_TRNSFRMED	0x0800
#define	ICB_FLAG_MVERS		0x1000




/* Volume recognition descriptors */




/*
 * Primary volume descriptor identifis the
 * volume and certain attributes of the volume
 */
struct pri_vol_desc {
	tag_t		pvd_tag;	/* 00 Descriptor Tag */
	uint32_t	pvd_vdsn;	/* 10 Volume Descriptor Seq Num */
	uint32_t	pvd_pvdn;	/* 14 Primary Vol Desc Num */
	dstring_t	pvd_vol_id[32];	/* 18 Volume Identifier */
	uint16_t	pvd_vsn;	/* 38 Volume Sequence Num */
	uint16_t	pvd_mvsn;	/* 3A Max Volume Sequence Num */
	uint16_t	pvd_il;		/* 3C Interchange Level */
	uint16_t	pvd_mil;	/* 3E Max Interchange Level */
	uint32_t	pvd_csl;	/* 40 Character Set List */
	uint32_t	pvd_mcsl;	/* 44 Max Character Set List */
	dstring_t	pvd_vsi[128];	/* 48 Volume Set Identifier */
	charspec_t	pvd_desc_cs;	/* C8 Descriptor Character Set */
	charspec_t	pvd_exp_cs;	/* 108 Explanatory Char Set */
	extent_ad_t	pvd_vol_abs;	/* 148 Volume Abstract */
	extent_ad_t	pvd_vcn;	/* 150 Volume Copyright Notice */
	regid_t		pvd_appl_id;	/* 158 Application Identifier */
	tstamp_t	pvd_time;	/* 178 Recording Data & Time */
	regid_t		pvd_ii;		/* 184 Implementation Identifier */
	char		pvd_iu[64];	/* 1A4 Implementation Use */
	uint32_t	pvd_pvdsl;	/* 1E4 Pred Vol Desc Seq Loc */
	uint16_t	pvd_flags;	/* 1E8 Flags */
	uint8_t		pvd_res[22];	/* 1EA Reserved */
};




/*
 * Anchor Volume Descriptor Pointer specifies
 * the extent of Main & Reserve volume descriptor
 */
struct anch_vol_desc_ptr {
	tag_t		avd_tag;	/* 00 Descriptor Tag */
	extent_ad_t	avd_main_vdse;	/* 10 Main Vol Desc Seq Extent */
	extent_ad_t	avd_res_vdse;	/* 18 Reserve Vol Desc Seq Ext */
	char		avd_res[480];	/* 20 Reserved */
};
typedef struct anch_vol_desc_ptr anch_vol_desc_ptr_t;




/*
 * Volume Descriptor Pointer
 */
struct vol_desc_ptr {
	tag_t		vdp_tag;	/* 00 Descriptor Tag */
	uint32_t	vdp_vdsn;	/* 10 Volume Descriptor Seq Num */
	extent_ad_t	vdp_nvdse;	/* 14 Next Vol Desc Seq Extent */
	uint8_t		vdp_res[484];	/* 1A Reserved */
};
typedef struct vol_desc_ptr vol_desc_ptr_t;




/*
 * Implementation Use Volume Descriptor
 * This is taken from udf1.02/1.50 documents
 * the fields after iuvd_ii are defined only
 * for the udf domain
 */
struct iuvd_desc {
	tag_t		iuvd_tag;	/* 00 Descriptor Tag */
	uint32_t	iuvd_vdsn;	/* 10 Volume Desc Seq Num */
	regid_t		iuvd_ii;	/* 14 Domain Identifier */
	charspec_t	iuvd_cset;	/* 34 LVI Charset */
	dstring_t	iuvd_lvi[128];	/* 74 Logical Vol Identifier */
	dstring_t	iuvd_ifo1[36];	/* F4 LV Info1 */
	dstring_t	iuvd_ifo2[36];	/* 118 LV Info2 */
	dstring_t	iuvd_ifo3[36];	/* 13C LV Info3 */
	regid_t		iuvd_iid;	/* 160 Implementation ID */
	uint8_t		iuvd_iu[128];	/* 180 Implementation Use */
};
typedef struct iuvd_desc iuvd_desc_t;





/*
 * Partition Descriptor
 * specifies the size and location of the partition
 */
struct part_desc {
	tag_t		pd_tag;		/* 00 Descriptor Tag */
	uint32_t	pd_vdsn;	/* 10 Volume Desc Seq Num */
	uint16_t	pd_pflags;	/* 14 Partition Flags */
	uint16_t	pd_pnum;	/* 16 partition Number */
	regid_t		pd_pcontents;	/* 18 Partition Contents */
	uint8_t		pd_pc_use[128];	/* 38 Partition Contents Use */
	uint32_t	pd_acc_type;	/* B8 Access Type */
	uint32_t	pd_part_start;	/* BC Part Start Location */
	uint32_t	pd_part_length;	/* C0 partition Length */
	regid_t		pd_ii;		/* C4 Implementation Identifier */
	uint8_t		pd_iu[128];	/* E4 Implementation Use */
	uint8_t		pd_res[156];	/* 164 Reserved */
};
typedef struct part_desc part_desc_t;


/*
 * pd_acc_type
 */
#define	PART_ACC_RO	0x01
#define	PART_ACC_WO	0x02
#define	PART_ACC_RW	0x03
#define	PART_ACC_OW	0x04


/*
 * Partition Header Descriptor
 * Overloads pd_pc_use
 */
struct phdr_desc {
	struct short_ad	phdr_ust;		/* Unallocated Space Table */
	struct short_ad	phdr_usb;		/* Unallocated Space Bitmap */
	struct short_ad	phdr_it;		/* Partition Integrity Table */
	struct short_ad	phdr_fst;		/* Freed Space Table */
	struct short_ad	phdr_fsb;		/* Freed Space Bitmap */
};
typedef struct phdr_desc phdr_desc_t;






/*
 * Logical Volume Descriptor
 */
struct log_vol_desc {
	tag_t		lvd_tag;	/* 00 Descriptor Tag */
	uint32_t	lvd_vdsn;	/* 10 Volume Desc Seq Num */
	charspec_t	lvd_desc_cs;	/* 14 Descriptor Char Set */
	dstring_t	lvd_lvid[128];	/* 54 Logical Vol Identifier */
	uint32_t	lvd_log_bsize;	/* D4 Logical Block Size */
	regid_t		lvd_dom_id;	/* D8 Domain Identifier */
	long_ad_t	lvd_lvcu;	/* F8 Logical Vol Contents Use */
	uint32_t	lvd_mtbl_len;	/* 108 Map Table Length */
	uint32_t	lvd_num_pmaps;	/* 10C Number of Partition Maps */
	regid_t		lvd_ii;		/* 110 Implementation Identifier */
	uint8_t		lvd_iu[128];	/* 130 Implementation Use */
	extent_ad_t	lvd_int_seq_ext; /* 1B0 Integrity Sequence Extent */
	uint8_t		lvd_pmaps[72];	/* 1B8 Partition Maps */
};
typedef struct log_vol_desc log_vol_desc_t;





/*
 * Unallocated Space Descriptor
 * Contains information about the space
 * that does not belong to any of the
 * partition
 */
struct unall_spc_desc {
	tag_t		ua_tag;		/* 00 Descriptor Tag */
	uint32_t	ua_vdsn;	/* 10 Volume Desc Seq Num */
	uint32_t	ua_nad;		/* 14 Number of Allocation Desc */
	uint8_t		ua_al_dsc[488];	/* 18 Allocation Desc */
};
typedef struct unall_spc_desc unall_spc_desc_t;




/*
 * Terminating Descriptor
 * this will be the last in a Volume Descriptor Sequence
 */
struct term_desc {
	tag_t		td_tag;		/* 00 Descriptor Tag */
	uint8_t		td_res[496];	/* 10 Reserved */
};
typedef struct term_desc term_desc_t;


/*
 * Logical Volume Header Descriptor
 * This will be overlaid on lvid_lvcu
 * and will contain the maximum value of
 * unique id on the media
 */
struct log_vol_hdr_desc {
	uint64_t	lvhd_uniqid;	/* 00 Unique Id */
	uint8_t		lvhd_pad[24];	/* 08 reserved */
};
typedef struct log_vol_hdr_desc log_vol_hdr_desc_t;

/*
 * Logical Volume Integrity Sequence
 * This will contain the integrity of the
 * file system
 */
struct log_vol_int_desc {
	tag_t		lvid_tag;	/* 00 Descriptor Tag */
	tstamp_t	lvid_tstamp;	/* 10 Recording Date and Time */
	uint32_t	lvid_int_type;	/* 1C Integrity Type */
	extent_ad_t	lvid_nie;	/* 20 Next Integrity Extent */
	/* uint8_t	lvid_lvcu[32]; */
	log_vol_hdr_desc_t lvid_lvcu;	/* 28 Logical Volume Contents Use */
	uint32_t	lvid_npart;	/* 48 Number of Partitions */
	uint32_t	lvid_liu;	/* 4C Length of Implementation Use */
	uint32_t	lvid_fst[2];	/* 50 Free Space Table */
					/* Size Table */
					/* Implementation Use */
};
typedef struct log_vol_int_desc log_vol_int_desc_t;

#define	lvid_uniqid	lvid_lvcu.lvhd_uniqid


#define	LOG_VOL_OPEN_INT	0x00
#define	LOG_VOL_CLOSE_INT	0x01


/*
 * Logical Volume integrity Implementation Use
 * This is defined in udf spec
 */
struct lvid_iu {
	regid_t		lvidiu_regid;	/* 00 Implementation ID */
	uint32_t	lvidiu_nfiles;	/* 20 Number of Files */
	uint32_t	lvidiu_ndirs;	/* 24 Number of Directories */
	uint16_t	lvidiu_mread;	/* 28 Minimum UDF read revision */
	uint16_t	lvidiu_mwrite;	/* 2A Minimum UDF write revision */
	uint16_t	lvidiu_maxwr;	/* 2C Maximum UDF write revision */
};







/*
 * File Set Descriptor
 * This will point to the root directory.
 */
struct file_set_desc {
	tag_t		fsd_tag;	/* 00 Descriptor Tag */
	tstamp_t	fsd_time;	/* 10 Recording Date and Time */
	uint16_t	fsd_ilevel;	/* 1C Interchange Level */
	uint16_t	fsd_mi_level;	/* 1E Max Interchange Level */
	uint32_t	fsd_cs_list;	/* 20 Character Set List */
	uint32_t	fsd_mcs_list;	/* 24 Max Character Set List */
	uint32_t	fsd_fs_no;	/* 28 File Set Number */
	uint32_t	fsd_fsd_no;	/* 2C File Set Desc Number */
	charspec_t	fsd_lvidcs;	/* 30 Log Vol Id Char Set */
	char		fsd_lvid[128];	/* 70 Log Vol Identifier */
	charspec_t	fsd_fscs;	/* F0 File Set Character Set */
	char		fsd_fsi[32];	/* 130 File Set Identifier */
	char		fsd_cfi[32];	/* 150 Copyright File Identifier */
	char		fsd_afi[32];	/* 170 Abstract File identifier */
	long_ad_t	fsd_root_icb;	/* 190 Root Directory ICB */
	regid_t		fsd_did;	/* 1A0 Domain Identifier */
	long_ad_t	fsd_next;	/* 1C0 Next Extent */
	uint8_t		fsd_res[48];	/* 1D0 Reserved */
};
typedef struct file_set_desc file_set_desc_t;







/*
 * File Identifier Descriptor
 * Directory entries
 */
struct file_id {
	tag_t		fid_tag;	/* 00 Descriptor Tag */
	uint16_t	fid_ver;	/* 10 File Version Number */
	uint8_t		fid_flags;	/* 12 File characteristics */
	uint8_t		fid_idlen;	/* 13 Length File Identifier */
	long_ad_t	fid_icb;	/* 14 ICB */
	uint16_t	fid_iulen;	/* 24 Length of Implmentation use */
	uint8_t		fid_spec[2];	/* iulen for iu name and padding */
};
typedef struct file_id file_id_t;

#define	FID_EXIST	0x01
#define	FID_DIR		0x02
#define	FID_DELETED	0x04
#define	FID_PARENT	0x08







/*
 * Allocation Extent Descriptor
 */
struct alloc_ext_desc {
	tag_t		aed_tag;	/* 00 Descriptor Tag */
	uint32_t	aed_rev_ael;	/* 10 Previous Alloc Extent Location */
	uint32_t	aed_len_aed;	/* 14 Length of Allocation Desc */
};
typedef struct alloc_ext_desc alloc_ext_desc_t;





/*
 * Indirect Entry
 * used to specify the address of another ICB
 */
struct indirect_entry {
	tag_t		ie_tag;		/* 00 Descriptor Tag */
	icb_tag_t	ie_icb_tag;	/* 10 ICB tag */
	long_ad_t	ie_indirecticb;	/* 24 Indirect ICB */
};
typedef struct indirect_entry indirect_entry_t;




/*
 * Terminal Entry
 */
struct term_entry {
	tag_t		te_tag;		/* 00 Descriptor Tag */
	icb_tag_t	te_icb_tag;	/* 10 ICB tag */
};
typedef struct term_entry term_entry_t;




/*
 * File entry describes the
 * file attributes and location it is recorded on the media
 */
struct file_entry {
	tag_t		fe_tag;		/* 00 Descriptor Tag */
	icb_tag_t	fe_icb_tag;	/* 10 ICB tag */
	uint32_t	fe_uid;		/* 24 Uid */
	uint32_t	fe_gid;		/* 28 Gid */
	uint32_t	fe_perms;	/* 2C Permissions */
	uint16_t	fe_lcount;	/* 30 File Link Count */
	uint8_t		fe_rec_for;	/* 32 Record Format */
	uint8_t		fe_rec_dis;	/* 33 Record Display Attributes */
	uint32_t	fe_rec_len;	/* 34 Record Length */
	uint64_t	fe_info_len;	/* 38 Information Length */
	uint64_t	fe_lbr;		/* 40 Logical Blocks recorded */
	tstamp_t	fe_acc_time;	/* 48 Access Data and Time */
	tstamp_t	fe_mod_time;	/* 54 Modification Data and Time */
	tstamp_t	fe_attr_time;	/* 60 Attribute Data and Time */
	uint32_t	fe_ckpoint;	/* 6C Checkpoint */
	long_ad_t	fe_ea_icb;	/* 70 Extended Attr ICB */
	regid_t		fe_impl_id;	/* 80 Implementation Identifier */
	uint64_t	fe_uniq_id;	/* A0 Unique Id */
	uint32_t	fe_len_ear;	/* A8 Length of Extended Attr */
	uint32_t	fe_len_adesc;	/* AC Length of Alloc Desc */
	char		fe_spec[336];	/* B0 used for EA and AD's */
};
typedef struct file_entry file_entry_t;





/*
 * Extended Attribute Header
 */
struct ext_attr_hdr {
	tag_t		eah_tag;	/* 00 Descriptor Tag */
	uint32_t	eah_ial;	/* 10 Implementation Attr Location */
	uint32_t	eah_aal;	/* 14 Application Attr Location */
};
typedef struct ext_attr_hdr ext_attr_hdr_t;







/*
 * Unallocated Space Entry
 */
struct unall_space_ent {
	tag_t		use_tag;	/* 00 Descriptor Tag */
	icb_tag_t	use_icb_tag;	/* 10 ICB tag */
	uint32_t	use_len_ad;	/* 24 Lenght of Allocation desc */
	uint8_t		use_ad[484];	/* 28 Allocation Descriptors */
};
typedef struct unall_space_ent unall_space_ent_t;





/*
 * Space Bitmap Descriptor
 */
struct space_bmap_desc {
	tag_t		sbd_tag;	/* 00 Descriptor Tag */
	uint32_t	sbd_nbits;	/* 10 Number of Bits */
	uint32_t	sbd_nbytes;	/* 14 Number of Bytes */
	uint8_t		sbd_bmap[500];	/* 18 Bitmap */
};
typedef struct space_bmap_desc space_bmap_desc_t;





/*
 * Partition Integrity entry
 */
struct part_int_desc {
	tag_t		pid_tag;	/* 00 Descriptor Tag */
	icb_tag_t	pid_idb_tag;	/* 10 ICB tag */
	tstamp_t	pid_rtime;	/* 24 Recording Data and Time */
	uint8_t		pid_integ;	/* 30 Integrity type */
	uint8_t		pid_res[175];	/* 31 Reserved */
	regid_t		pid_ii;		/* E0 Implementation Identifier */
	uint8_t		pid_iu[256];	/* 100 Implementation Use */
};
typedef struct part_int_desc part_int_desc_t;


#define	PART_OPEN_INT		0x00
#define	PART_CLOSE_INT		0x01
#define	PART_STABLE_INT		0x02




struct attr_hdr {
	uint32_t	ahdr_atype;	/* Attribute Type */
	uint8_t		ahdr_astype;	/* Attribute Subtype */
	uint8_t		ahdr_res[3];	/* Reserved */
	uint32_t	ahdr_length;	/* Attribute Length */
	uint8_t		ahdr_data[4];	/* Attribute Data */
};

/*
 * We will support and use the
 * following Extended Attributes
 * we will ignore others while reading
 * and will preserve then when updating
 * the EAR's
 * In all the EA's we allocate the last member
 * as 4 bytes. This is a sort of hack
 * since the structure has to be
 * properly alined to 4 bytes.
 */

struct dev_spec_ear {
	uint32_t	ds_atype;	/* 00 Attribute Type */
	uint8_t		ds_astype;	/* 04 Attribute Subtype */
	uint8_t		ds_res[3];	/* 05 Reserved */
	uint32_t	ds_attr_len;	/* 08 Attrbute Length */
	uint32_t	ds_iu_len;	/* 0C Impl Use Length */
	uint32_t	ds_major_id;	/* 10 Major Device ID */
	uint32_t	ds_minor_id;	/* 14 Minor Device ID */
	uint8_t		ds_iu[4];	/* 18 Implementation Use */
};


struct ftimes_ear {
	uint32_t	ft_atype;	/* 00 Attribute Type */
	uint8_t		ft_astype;	/* 04 Attribute Subtype */
	uint8_t		ft_res[3];	/* 05 Reserved */
	uint32_t	ft_attr_len;	/* 08 Attrbute Length */
	uint32_t	ft_data_len;	/* 0C Data Length */
	uint32_t	ft_exist;	/* 10 File Time Existence */
	uint8_t		ft_ft[4];	/* 14 File Times */
};

/* ft_exit */
#define	FT_EXIST	0x0
#define	FT_DELETE	0x2
#define	FT_FEDT		0x3
#define	FT_BACKUP	0x5

struct iu_ea {
	uint32_t	iuea_atype;	/* 00 Attribute Type */
	uint8_t		iuea_astype;	/* 04 Attribute Subtype */
	uint8_t		iuea_res[3];	/* 05 Reserved */
	uint32_t	iuea_attr_len;	/* 08 Attrbute Length */
	uint32_t	iuea_iu_len;	/* 0C Implementation Use Length */
	regid_t		iuea_ii;		/* 10 Implementation ID */
	uint8_t		iuea_iu[4];	/* 30 Impl Use */
};


/*
 * CGMS & FREE_SPACE will be
 * over laid on iu_iu field
 */

struct copy_mgt_info {
	uint16_t	cgms_cksum;	/* Header Checksum */
	uint8_t		cgms_info;	/* CGMS Information */
	uint8_t		cgms_dstype;	/* Data Structure Type */
	uint32_t	cgms_psi;	/* Protection System Info */
};

#define	COPY_PROTECTED	0x80

struct FREE_SPACE {
	uint16_t	fs_cksum;	/* Header Checksum */
	uint8_t		fs_freesp[2];	/* Free EA space */
};




struct nsr_desc {
	uint8_t		nsr_str_type;
	uint8_t		nsr_id[5];
	uint8_t		nsr_ver;
	uint8_t		nsr_res;
	uint8_t		nsr_data[2040];
};



/*
 * Partition Map
 */
struct pmap_hdr {
	uint8_t		maph_type;	/* Partition Map Type */
	uint8_t		maph_length;	/* Partition Map Length */
};

#define	MAP_TYPE1	1
#define	MAP_TYPE2	2

#define	MAP_TYPE1_LEN	6
#define	MAP_TYPE2_LEN	64

struct pmap_typ1 {
	uint8_t		map1_type;	/* Map type == 1 */
	uint8_t		map1_length;	/* Map length == 6 */
	uint16_t	map1_vsn;	/* Volume Sequence Number */
	uint16_t	map1_pn;	/* Partition Number */
};


/*
 * Only two types of type2 maps
 * are supported they are
 * *UDF Virtual Partition
 * *UDF Sparable Partition
 * For vpm fields till map2_pn
 * are valid and the entire structure is
 * valid for spm
 */
struct pmap_typ2 {
	uint8_t		map2_type;	/* 00 Map type == 2 */
	uint8_t		map2_length;	/* 01 Map length == 64 */
	uint16_t	map2_pad1;	/* 02 Reserved */
	regid_t		map2_pti;	/* 04 Entiry ID */
	uint16_t	map2_vsn;	/* 24 Volume Sequence Number */
	uint16_t	map2_pn;	/* 26 Partition Number */
	uint16_t	map2_pl;	/* 28 Packet Length == 32 */
	uint8_t		map2_nst;	/* 2A Number of sparing tables */
	uint8_t		map2_pad2;	/* 2B Reserved */
	uint32_t	map2_sest;	/* 2C Size of each sparing table */
	uint32_t	map2_st[4];	/* 30 sparing Tables */
};


struct stbl_entry {
	uint32_t	sent_ol;	/* Original Location */
	uint32_t	sent_ml;	/* Mapped Location */
};

typedef struct stbl_entry stbl_entry_t;

struct stbl {
	tag_t		stbl_tag;	/* 00 Tag */
	regid_t		stbl_si;	/* 10 Sparing Identifier */
	uint16_t	stbl_len;	/* 30 Reallocation Table Len */
	uint16_t	stbl_res1;	/* 32 Reserved */
	uint32_t	stbl_seqno;	/* 34 Sequence Number */
	stbl_entry_t	stbl_entry;	/* 38 Sparing Table Entries */
};

struct path_comp {
	uint8_t		pc_type;	/* Component Type */
	uint8_t		pc_len;		/* Length of Component ID */
	uint16_t	pc_ver;		/* Component File Version Number */
	uint8_t		pc_id[4];	/* Component ID */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UDF_VOLUME_H */
