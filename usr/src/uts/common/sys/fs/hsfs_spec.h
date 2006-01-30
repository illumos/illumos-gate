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

#ifndef	_SYS_FS_HSFS_SPEC_H
#define	_SYS_FS_HSFS_SPEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * High Sierra filesystem specification
 */

#include <sys/types.h>
#include <sys/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/* routines required for date parsing */
extern void	hs_parse_dirdate(uchar_t *, struct timeval *);
extern void	hs_parse_longdate(uchar_t *, struct timeval *);

#endif	/* _KERNEL */


/* macros to parse binary integers */
#define	ZERO(x)		(uint_t)(((uchar_t *)(x))[0])
#define	ONE(x)		(uint_t)(((uchar_t *)(x))[1])
#define	TWO(x)		(uint_t)(((uchar_t *)(x))[2])
#define	THREE(x)	(uint_t)(((uchar_t *)(x))[3])

#define	MSB_INT(x) \
	((((((ZERO(x) << 8) | ONE(x)) << 8) | TWO(x)) << 8) | THREE(x))
#define	LSB_INT(x) \
	((((((THREE(x) << 8) | TWO(x)) << 8) | ONE(x)) << 8) | ZERO(x))
#define	MSB_SHORT(x)	((ZERO(x) << 8) | ONE(x))
#define	LSB_SHORT(x)	((ONE(x) << 8) | ZERO(x))

#if defined(__i386) || defined(__amd64)
#define	BOTH_SHORT(x)	(short)*((short *)x)
#define	BOTH_INT(x)	(int)*((int *)x)
#elif defined(__sparc)
/*
 * SPARC machines requires that integer must
 * be in a full word boundary.	CD-ROM data aligns
 * to even word boundary only.	Because of this mismatch,
 * we have to move integer data from CD-ROM to memory one
 * byte at a time.  LSB data starts first. We therefore
 * use this to do byte by byte copying.
 */
#define	BOTH_SHORT(x)	LSB_SHORT(x)
#define	BOTH_INT(x)	LSB_INT(x)
#endif

/*
 * The following describes actual on-disk structures.
 * To achieve portability, all structures are #defines
 * rather than a structure definition.	Macros are provided
 * to get either the data or address of individual fields.
 */

/* Overall High Sierra disk structure */
#define	HS_SECTOR_SIZE	2048		/* bytes per logical sector */
#define	HS_SECTOR_SHIFT	11		/* sector<->byte shift count */
#define	HS_SEC_PER_PAGE	(PAGESIZE/HS_SECTOR_SIZE)	/* sectors per page */
#define	HS_SYSAREA_SEC	0		/* 1st sector of system area */
#define	HS_VOLDESC_SEC	16		/* 1st sector of volume descriptors */
#define	HS_MAXFILEOFF 4294967295U	/* Max file offset (4Gb - 1). */
#define	MAXHSOFFSET (HS_SECTOR_SIZE - 1)
#define	MAXHSMASK   (~MAXHSOFFSET)

/* Standard File Structure Volume Descriptor */

enum hs_voldesc_type {
	VD_BOOT = 0, VD_SFS = 1, VD_CCFS = 2, VD_UNSPEC = 3, VD_EOV = 255
};
#define	HSV_ID_STRING	"CDROM"		/* HSV_std_id field */
#define	HSV_ID_STRLEN	5		/* HSV_std_id field length */
#define	HSV_ID_VER	1		/* HSV_std_ver field */
#define	HSV_FILE_STRUCT_ID_VER	1	/* HSV_file_struct_ver field */
#define	HSV_SYS_ID_STRLEN	32	/* HSV_sys_id field length */
#define	HSV_VOL_ID_STRLEN	32	/* HSV_vol_id field length */
#define	HSV_VOL_SET_ID_STRLEN	128	/* HSV_vol_set_id field length */
#define	HSV_PUB_ID_STRLEN	128	/* HSV_pub_id field length */
#define	HSV_PREP_ID_STRLEN	128	/* HSV_prep_id field length */
#define	HSV_APPL_ID_STRLEN	128	/* HSV_appl_id field length */
#define	HSV_COPYR_ID_STRLEN	32	/* HSV_copyr_id field length */
#define	HSV_ABSTR_ID_STRLEN	32	/* HSV_abstr_id field length */
#define	HSV_DATE_LEN		16	/* HSV date filed length */

/* macros to get the address of each field */
#define	HSV_desc_lbn(x)		(&((uchar_t *)x)[0])
#define	HSV_desc_type(x)	(&((uchar_t *)x)[8])
#define	HSV_std_id(x)		(&((uchar_t *)x)[9])
#define	HSV_std_ver(x)		(&((uchar_t *)x)[14])
#define	HSV_sys_id(x)		(&((uchar_t *)x)[16])
#define	HSV_vol_id(x)		(&((uchar_t *)x)[48])
#define	HSV_vol_size(x)		(&((uchar_t *)x)[88])
#define	HSV_set_size(x)		(&((uchar_t *)x)[128])
#define	HSV_set_seq(x)		(&((uchar_t *)x)[132])
#define	HSV_blk_size(x)		(&((uchar_t *)x)[136])
#define	HSV_ptbl_size(x)	(&((uchar_t *)x)[140])
#define	HSV_ptbl_man_ls(x)	(&((uchar_t *)x)[148])
#define	HSV_ptbl_opt_ls1(x)	(&((uchar_t *)x)[152])
#define	HSV_ptbl_opt_ls2(x)	(&((uchar_t *)x)[156])
#define	HSV_ptbl_opt_ls3(x)	(&((uchar_t *)x)[160])
#define	HSV_ptbl_man_ms(x)	(&((uchar_t *)x)[164])
#define	HSV_ptbl_opt_ms1(x)	(&((uchar_t *)x)[168])
#define	HSV_ptbl_opt_ms2(x)	(&((uchar_t *)x)[172])
#define	HSV_ptbl_opt_ms3(x)	(&((uchar_t *)x)[176])
#define	HSV_root_dir(x)		(&((uchar_t *)x)[180])
#define	HSV_vol_set_id(x)	(&((uchar_t *)x)[214])
#define	HSV_pub_id(x)		(&((uchar_t *)x)[342])
#define	HSV_prep_id(x)		(&((uchar_t *)x)[470])
#define	HSV_appl_id(x)		(&((uchar_t *)x)[598])
#define	HSV_copyr_id(x)		(&((uchar_t *)x)[726])
#define	HSV_abstr_id(x)		(&((uchar_t *)x)[758])
#define	HSV_cre_date(x)		(&((uchar_t *)x)[790])
#define	HSV_mod_date(x)		(&((uchar_t *)x)[806])
#define	HSV_exp_date(x)		(&((uchar_t *)x)[822])
#define	HSV_eff_date(x)		(&((uchar_t *)x)[838])
#define	HSV_file_struct_ver(x)	(&((uchar_t *)x)[854])

/* macros to get the values of each field (strings are returned as ptrs) */
#define	HSV_DESC_LBN(x)		BOTH_INT(HSV_desc_lbn(x))
#define	HSV_DESC_TYPE(x)	((enum hs_voldesc_type)*(HSV_desc_type(x)))
#define	HSV_STD_ID(x)		HSV_std_id(x)
#define	HSV_STD_VER(x)		*(HSV_std_ver(x))
#define	HSV_SYS_ID(x)		HSV_sys_id(x)
#define	HSV_VOL_ID(x)		HSV_vol_id(x)
#define	HSV_VOL_SIZE(x)		BOTH_INT(HSV_vol_size(x))
#define	HSV_SET_SIZE(x)		BOTH_SHORT(HSV_set_size(x))
#define	HSV_SET_SEQ(x)		BOTH_SHORT(HSV_set_seq(x))
#define	HSV_BLK_SIZE(x)		BOTH_SHORT(HSV_blk_size(x))
#define	HSV_PTBL_SIZE(x)	BOTH_INT(HSV_ptbl_size(x))
#define	HSV_PTBL_MAN_LS(x)	LSB_INT(HSV_ptbl_man_ls(x))
#define	HSV_PTBL_OPT_LS1(x)	LSB_INT(HSV_ptbl_opt_ls1(x))
#define	HSV_PTBL_OPT_LS2(x)	LSB_INT(HSV_ptbl_opt_ls2(x))
#define	HSV_PTBL_OPT_LS3(x)	LSB_INT(HSV_ptbl_opt_ls3(x))
#define	HSV_PTBL_MAN_MS(x)	MSB_INT(HSV_ptbl_man_ms(x))
#define	HSV_PTBL_OPT_MS1(x)	MSB_INT(HSV_ptbl_opt_ms1(x))
#define	HSV_PTBL_OPT_MS2(x)	MSB_INT(HSV_ptbl_opt_ms2(x))
#define	HSV_PTBL_OPT_MS3(x)	MSB_INT(HSV_ptbl_opt_ms3(x))
#define	HSV_ROOT_DIR(x)		HSV_root_dir(x)
#define	HSV_VOL_SET_ID(x)	HSV_vol_set_id(x)
#define	HSV_PUB_ID(x)		HSV_pub_id(x)
#define	HSV_PREP_ID(x)		HSV_prep_id(x)
#define	HSV_APPL_ID(x)		HSV_appl_id(x)
#define	HSV_COPYR_ID(x)		HSV_copyr_id(x)
#define	HSV_ABSTR_ID(x)		HSV_abstr_id(x)
#define	HSV_CRE_DATE(x)		HSV_cre_date(x)
#define	HSV_MOD_DATE(x)		HSV_mod_date(x)
#define	HSV_EXP_DATE(x)		HSV_exp_date(x)
#define	HSV_EFF_DATE(x)		HSV_eff_date(x)
#define	HSV_FILE_STRUCT_VER(x)	*(HSV_file_struct_ver(x))

/* Standard File Structure Volume Descriptor date fields */
#define	HSV_DATE_2DIG(x)	((((x)[0] - '0') * 10) + \
					((x)[1] - '0'))
#define	HSV_DATE_4DIG(x)	((((x)[0] - '0') * 1000) + \
					(((x)[1] - '0') * 100) + \
					(((x)[2] - '0') * 10) +	\
						((x)[3] - '0'))
#define	HSV_DATE_YEAR(x)	HSV_DATE_4DIG(&((uchar_t *)x)[0])
#define	HSV_DATE_MONTH(x)	HSV_DATE_2DIG(&((uchar_t *)x)[4])
#define	HSV_DATE_DAY(x)		HSV_DATE_2DIG(&((uchar_t *)x)[6])
#define	HSV_DATE_HOUR(x)	HSV_DATE_2DIG(&((uchar_t *)x)[8])
#define	HSV_DATE_MIN(x)		HSV_DATE_2DIG(&((uchar_t *)x)[10])
#define	HSV_DATE_SEC(x)		HSV_DATE_2DIG(&((uchar_t *)x)[12])
#define	HSV_DATE_HSEC(x)	HSV_DATE_2DIG(&((uchar_t *)x)[14])
#define	HSV_DATE_GMTOFF(x)	(((char *)x)[16])


/* Path table enry */
/* fix size of path table entry */
#define	HPE_FPESIZE		8
/* macros to get the address of each field */
#define	HPE_ext_lbn(x)		(&((uchar_t *)x)[0])
#define	HPE_xar_len(x)		(&((uchar_t *)x)[4])
#define	HPE_name_len(x)		(&((uchar_t *)x)[5])
#define	HPE_parent_no(x)	(&((uchar_t *)x)[6])
#define	HPE_name(x)		(&((uchar_t *)x)[8])

/* macros to get the values of each field */
#if defined(__sparc)
#define	HPE_EXT_LBN(x)		(MSB_INT(HPE_ext_lbn(x)))
#else
#define	HPE_EXT_LBN(x)		*(int *)(HPE_ext_lbn(x))
#endif
#define	HPE_XAR_LEN(x)		*(HPE_xar_len(x))
#define	HPE_NAME_LEN(x)		*(HPE_name_len(x))
#define	HPE_PARENT_NO(x)	*(short *)(HPE_parent_no(x))
#define	HPE_NAME(x)		HPE_name(x)

/* root record */
#define	HDE_ROOT_DIR_REC_SIZE	34	/* size of root directory record */
#define	HDE_FDESIZE		33	/* fixed size for hsfs directory area */
#define	HDE_FUSIZE		12	/* fixed size for unix area */
					/* max size of a name */
#define	HDE_MAX_NAME_LEN	(255 - HDE_FDESIZE - HDE_FUSIZE)

/* Directory Entry (Directory Record) */

#define	UNIX_TO_HDE_DATE(t, p)	parse_unixdate((t), (p))

/* macros to get the address of each field */
#define	HDE_dir_len(x)		(&((uchar_t *)x)[0])
#define	HDE_xar_len(x)		(&((uchar_t *)x)[1])
#define	HDE_ext_lbn(x)		(&((uchar_t *)x)[2])
#define	HDE_ext_size(x)		(&((uchar_t *)x)[10])
#define	HDE_cdate(x)		(&((uchar_t *)x)[18])
#define	HDE_flags(x)		(&((uchar_t *)x)[24])
#define	HDE_reserved(x)		(&((uchar_t *)x)[25])
#define	HDE_intrlv_size(x)	(&((uchar_t *)x)[26])
#define	HDE_intrlv_skip(x)	(&((uchar_t *)x)[27])
#define	HDE_vol_set(x)		(&((uchar_t *)x)[28])
#define	HDE_name_len(x)		(&((uchar_t *)x)[32])
#define	HDE_name(x)		(&((uchar_t *)x)[33])

/* **UNIX extension*** */
#define	HDE_mode(x)		(&((uchar_t *)x)[0])
#define	HDE_uid(x)		(&((uchar_t *)x)[4])
#define	HDE_gid(x)		(&((uchar_t *)x)[8])

/* macros to get the values of each field (strings are returned as ptrs) */
#define	HDE_DIR_LEN(x)		*(HDE_dir_len(x))
#define	HDE_XAR_LEN(x)		*(HDE_xar_len(x))
#define	HDE_EXT_LBN(x)		BOTH_INT(HDE_ext_lbn(x))
#define	HDE_EXT_SIZE(x)		BOTH_INT(HDE_ext_size(x))
#define	HDE_CDATE(x)		HDE_cdate(x)
#define	HDE_FLAGS(x)		*(HDE_flags(x))
#define	HDE_RESERVED(x)		*(HDE_reserved(x))
#define	HDE_INTRLV_SIZE(x)	*(HDE_intrlv_size(x))
#define	HDE_INTRLV_SKIP(x)	*(HDE_intrlv_skip(x))
#define	HDE_VOL_SET(x)		BOTH_SHORT(HDE_vol_set(x))
#define	HDE_NAME_LEN(x)		*(HDE_name_len(x))
#define	HDE_NAME(x)		HDE_name(x)

/* **UNIX EXTENSION**** */
#define	HDE_MODE(x)		*(HDE_mode(x))
#define	HDE_UID(x)		*(HDE_uid(x))
#define	HDE_GID(x)		*(HDE_gid(x))

/* mask bits for HDE_FLAGS */
#define	HDE_EXISTENCE		0x01	/* zero if file exists */
#define	HDE_DIRECTORY		0x02	/* zero if file is not a directory */
#define	HDE_ASSOCIATED		0x04	/* zero if file is not Associated */
#define	HDE_RECORD		0x08	/* zero if no record attributes */
#define	HDE_PROTECTION		0x10	/* zero if no protection attributes */
#define	HDE_UNUSED_FLAGS	0x60
#define	HDE_LAST_EXTENT		0x80	/* zero if last extent in file */
#define	HDE_PROHIBITED	(HDE_DIRECTORY | HDE_RECORD | \
				HDE_LAST_EXTENT | HDE_UNUSED_FLAGS)

/* Directory Record date fields */
#define	HDE_DATE_YEAR(x)	(((uchar_t *)x)[0] + 1900)
#define	HDE_DATE_MONTH(x)	(((uchar_t *)x)[1])
#define	HDE_DATE_DAY(x)		(((uchar_t *)x)[2])
#define	HDE_DATE_HOUR(x)	(((uchar_t *)x)[3])
#define	HDE_DATE_MIN(x)		(((uchar_t *)x)[4])
#define	HDE_DATE_SEC(x)		(((uchar_t *)x)[5])
#define	HDE_DATE_GMTOFF(x)	(((char *)x)[6])


/* tests for Interchange Levels 1 & 2 file types */
#define	HDE_REGULAR_FILE(x)	(((x) & HDE_PROHIBITED) == 0)
#define	HDE_REGULAR_DIR(x)	(((x) & HDE_PROHIBITED) == HDE_DIRECTORY)

#define	HS_DIR_NAMELEN		31	/* max length of a directory name */
#define	HS_FILE_NAMELEN		31	/* max length of a filename */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_HSFS_SPEC_H */
