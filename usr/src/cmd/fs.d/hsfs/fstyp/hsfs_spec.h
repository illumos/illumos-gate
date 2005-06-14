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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * High Sierra filesystem specification
 * Copyright (c) 1989 by Sun Microsystem, Inc.
 */

#ifndef	_HSFS_SPEC_H_
#define	_HSFS_SPEC_H_

#include <sys/isa_defs.h>	/* for ENDIAN defines */

/* routines required for date parsing */
extern void	hs_parse_dirdate();	/* parse date in directory */
extern void	hs_parse_longdate();	/* parse date in volume id */

/* macros to parse binary integers */
#define ZERO(x)         (u_int) (((u_char *)(x))[0])
#define ONE(x)          (u_int) (((u_char *)(x))[1])
#define TWO(x)          (u_int) (((u_char *)(x))[2])
#define THREE(x)        (u_int) (((u_char *)(x))[3])

#define MSB_INT(x) \
        ((((((ZERO(x) << 8) | ONE(x)) << 8) | TWO(x)) << 8) | THREE(x))
#define LSB_INT(x) \
        ((((((THREE(x) << 8) | TWO(x)) << 8) | ONE(x)) << 8) | ZERO(x))
#define MSB_SHORT(x)    ((ZERO(x) << 8) | ONE(x))
#define LSB_SHORT(x)    ((ONE(x) << 8) | ZERO(x))

#if defined(_LITTLE_ENDIAN)
#define BOTH_SHORT(x)   (short) *((short *)x)
#define BOTH_INT(x)     (int) *((int *)x)
#endif
 
/*
 * The following describes actual on-disk structures.
 * To achieve portability, all structures are #defines
 * rather than a structure definition.  Macros are provided
 * to get either the data or address of individual fields.
 */

/* Overall High Sierra disk structure */
#define HS_SECTOR_SIZE	2048		/* bytes per logical sector */
#define HS_SECTOR_SHIFT	11		/* sector<->byte shift count */
#define HS_SEC_PER_PAGE	(PAGESIZE/HS_SECTOR_SIZE)	/* sectors per page */
#define HS_SYSAREA_SEC	0		/* 1st sector of system area */
#define HS_VOLDESC_SEC	16		/* 1st sector of volume descriptors */
#define MAXHSOFFSET (HS_SECTOR_SIZE - 1)
#define MAXHSMASK   (~MAXHSOFFSET)

/* Standard File Structure Volume Descriptor */

enum hs_voldesc_type {
	VD_BOOT=0, VD_SFS=1, VD_CCFS=2, VD_UNSPEC=3, VD_EOV=255
};
#define HSV_ID_STRING	"CDROM"		/* HSV_std_id field */
#define HSV_ID_STRLEN	5		/* HSV_std_id field length */
#define HSV_ID_VER	1		/* HSV_std_ver field */
#define HSV_FILE_STRUCT_ID_VER	1	/* HSV_file_struct_ver field */
#define HSV_SYS_ID_STRLEN	32	/* HSV_sys_id field length */
#define HSV_VOL_ID_STRLEN	32	/* HSV_vol_id field length */
#define HSV_VOL_SET_ID_STRLEN	128	/* HSV_vol_set_id field length */
#define HSV_PUB_ID_STRLEN	128	/* HSV_pub_id field length */
#define HSV_PREP_ID_STRLEN	128	/* HSV_prep_id field length */
#define HSV_APPL_ID_STRLEN	128	/* HSV_appl_id field length */
#define HSV_COPYR_ID_STRLEN	32	/* HSV_copyr_id field length */
#define HSV_ABSTR_ID_STRLEN	32	/* HSV_abstr_id field length */
#define HSV_DATE_LEN		16	/* HSV date filed length */

/* macros to get the address of each field */
#define HSV_desc_lbn(x)		(&((u_char *)x)[0])
#define HSV_desc_type(x)	(&((u_char *)x)[8])
#define HSV_std_id(x)		(&((u_char *)x)[9])
#define HSV_std_ver(x)		(&((u_char *)x)[14])
#define HSV_sys_id(x)		(&((u_char *)x)[16])
#define HSV_vol_id(x)		(&((u_char *)x)[48])
#define HSV_vol_size(x)		(&((u_char *)x)[88])
#define HSV_set_size(x)		(&((u_char *)x)[128])
#define HSV_set_seq(x)		(&((u_char *)x)[132])
#define HSV_blk_size(x)		(&((u_char *)x)[136])
#define HSV_ptbl_size(x)	(&((u_char *)x)[140])
#define HSV_ptbl_man_ls(x)	(&((u_char *)x)[148])
#define HSV_ptbl_opt_ls1(x)	(&((u_char *)x)[152])
#define HSV_ptbl_opt_ls2(x)	(&((u_char *)x)[156])
#define HSV_ptbl_opt_ls3(x)	(&((u_char *)x)[160])
#define HSV_ptbl_man_ms(x)	(&((u_char *)x)[164])
#define HSV_ptbl_opt_ms1(x)	(&((u_char *)x)[168])
#define HSV_ptbl_opt_ms2(x)	(&((u_char *)x)[172])
#define HSV_ptbl_opt_ms3(x)	(&((u_char *)x)[176])
#define HSV_root_dir(x)		(&((u_char *)x)[180])
#define HSV_vol_set_id(x)	(&((u_char *)x)[214])
#define HSV_pub_id(x)		(&((u_char *)x)[342])
#define HSV_prep_id(x)		(&((u_char *)x)[470])
#define HSV_appl_id(x)		(&((u_char *)x)[598])
#define HSV_copyr_id(x)		(&((u_char *)x)[726])
#define HSV_abstr_id(x)		(&((u_char *)x)[758])
#define HSV_cre_date(x)		(&((u_char *)x)[790])
#define HSV_mod_date(x)		(&((u_char *)x)[806])
#define HSV_exp_date(x)		(&((u_char *)x)[822])
#define HSV_eff_date(x)		(&((u_char *)x)[838])
#define HSV_file_struct_ver(x)	(&((u_char *)x)[854])

/* macros to get the values of each field (strings are returned as ptrs) */
#define HSV_DESC_LBN(x)		BOTH_INT(HSV_desc_lbn(x))
#define HSV_DESC_TYPE(x)	((enum hs_voldesc_type)*(HSV_desc_type(x)))
#define HSV_STD_ID(x)		HSV_std_id(x)
#define HSV_STD_VER(x)		*(HSV_std_ver(x))
#define HSV_SYS_ID(x)		HSV_sys_id(x)
#define HSV_VOL_ID(x)		HSV_vol_id(x)
#define HSV_VOL_SIZE(x)		BOTH_INT(HSV_vol_size(x))
#define HSV_SET_SIZE(x)		BOTH_SHORT(HSV_set_size(x))
#define HSV_SET_SEQ(x)		BOTH_SHORT(HSV_set_seq(x))
#define HSV_BLK_SIZE(x)		BOTH_SHORT(HSV_blk_size(x))
#define HSV_PTBL_SIZE(x)	BOTH_INT(HSV_ptbl_size(x))
#define HSV_PTBL_MAN_LS(x)	LSB_INT(HSV_ptbl_man_ls(x))
#define HSV_PTBL_OPT_LS1(x)	LSB_INT(HSV_ptbl_opt_ls1(x))
#define HSV_PTBL_OPT_LS2(x)	LSB_INT(HSV_ptbl_opt_ls2(x))
#define HSV_PTBL_OPT_LS3(x)	LSB_INT(HSV_ptbl_opt_ls3(x))
#define HSV_PTBL_MAN_MS(x)	MSB_INT(HSV_ptbl_man_ms(x))
#define HSV_PTBL_OPT_MS1(x)	MSB_INT(HSV_ptbl_opt_ms1(x))
#define HSV_PTBL_OPT_MS2(x)	MSB_INT(HSV_ptbl_opt_ms2(x))
#define HSV_PTBL_OPT_MS3(x)	MSB_INT(HSV_ptbl_opt_ms3(x))
#define HSV_ROOT_DIR(x)		HSV_root_dir(x)
#define HSV_VOL_SET_ID(x)	HSV_vol_set_id(x)
#define HSV_PUB_ID(x)		HSV_pub_id(x)
#define HSV_PREP_ID(x)		HSV_prep_id(x)
#define HSV_APPL_ID(x)		HSV_appl_id(x)
#define HSV_COPYR_ID(x)		HSV_copyr_id(x)
#define HSV_ABSTR_ID(x)		HSV_abstr_id(x)
#define HSV_CRE_DATE(x)		HSV_cre_date(x)
#define HSV_MOD_DATE(x)		HSV_mod_date(x)
#define HSV_EXP_DATE(x)		HSV_exp_date(x)
#define HSV_EFF_DATE(x)		HSV_eff_date(x)
#define HSV_FILE_STRUCT_VER(x)	*(HSV_file_struct_ver(x))

/* Standard File Structure Volume Descriptor date fields */
#define HSV_DATE_2DIG(x)	( (((x)[0] - '0') * 10) +		\
				   ((x)[1] - '0') )
#define HSV_DATE_4DIG(x)	( (((x)[0] - '0') * 1000) +		\
				  (((x)[1] - '0') * 100) +		\
				  (((x)[2] - '0') * 10) +		\
				   ((x)[3] - '0') )
#define HSV_DATE_YEAR(x)	HSV_DATE_4DIG(&((u_char *)x)[0])
#define HSV_DATE_MONTH(x)	HSV_DATE_2DIG(&((u_char *)x)[4])
#define HSV_DATE_DAY(x)		HSV_DATE_2DIG(&((u_char *)x)[6])
#define HSV_DATE_HOUR(x)	HSV_DATE_2DIG(&((u_char *)x)[8])
#define HSV_DATE_MIN(x)		HSV_DATE_2DIG(&((u_char *)x)[10])
#define HSV_DATE_SEC(x)		HSV_DATE_2DIG(&((u_char *)x)[12])
#define HSV_DATE_HSEC(x)	HSV_DATE_2DIG(&((u_char *)x)[14])

/* Path table enry */
/* fix size of path table entry */
#define HPE_FPESIZE		8
/* macros to get the address of each field */
#define HPE_ext_lbn(x)		(&((u_char *)x)[0])
#define HPE_xar_len(x)		(&((u_char *)x)[4])
#define HPE_name_len(x)		(&((u_char *)x)[5])
#define HPE_parent_no(x)	(&((u_char *)x)[6])
#define HPE_name(x)		(&((u_char *)x)[8])

/* macros to get the values of each field */
#if sun4
#define HPE_EXT_LBN(x)		(MSB_INT(HPE_ext_lbn(x)))
#else
#define HPE_EXT_LBN(x)		*(int *)(HPE_ext_lbn(x))
#endif
#define HPE_XAR_LEN(x)		*(HPE_xar_len(x))
#define HPE_NAME_LEN(x)		*(HPE_name_len(x))
#define HPE_PARENT_NO(x)	*(short *)(HPE_parent_no(x))
#define HPE_NAME(x)		HPE_name(x)

/* root record */
#define HDE_ROOT_DIR_REC_SIZE	34	/* size of root directory record */
#define HDE_FDESIZE		33	/* fixed size for hsfs directory area */
#define HDE_FUSIZE		12	/* fixed size for unix areaa */
					/* max size of a name */
#define HDE_MAX_NAME_LEN	(255 - HDE_FDESIZE - HDE_FUSIZE)

/* Directory Entry (Directory Record) */

#define UNIX_TO_HDE_DATE(t,p)	parse_unixdate(t, p)	/* return val at p */

/* macros to get the address of each field */
#define HDE_dir_len(x)		(&((u_char *)x)[0])
#define HDE_xar_len(x)		(&((u_char *)x)[1])
#define HDE_ext_lbn(x)		(&((u_char *)x)[2])
#define HDE_ext_size(x)		(&((u_char *)x)[10])
#define HDE_cdate(x)		(&((u_char *)x)[18])
#define HDE_flags(x)		(&((u_char *)x)[24])
#define HDE_reserved(x)		(&((u_char *)x)[25])
#define HDE_intrlv_size(x)	(&((u_char *)x)[26])
#define HDE_intrlv_skip(x)	(&((u_char *)x)[27])
#define HDE_vol_set(x)		(&((u_char *)x)[28])
#define HDE_name_len(x)		(&((u_char *)x)[32])
#define HDE_name(x)		(&((u_char *)x)[33])

/***UNIX extension****/
#define HDE_mode(x)		(&((u_char *)x)[0])
#define HDE_uid(x)		(&((u_char *)x)[4])
#define HDE_gid(x)		(&((u_char *)x)[8])

/* macros to get the values of each field (strings are returned as ptrs) */
#define HDE_DIR_LEN(x)		*(HDE_dir_len(x))
#define HDE_XAR_LEN(x)		*(HDE_xar_len(x))
#define HDE_EXT_LBN(x)		BOTH_INT(HDE_ext_lbn(x))
#define HDE_EXT_SIZE(x)		BOTH_INT(HDE_ext_size(x))
#define HDE_CDATE(x)		HDE_cdate(x)
#define HDE_FLAGS(x)		*(HDE_flags(x))
#define HDE_RESERVED(x)		*(HDE_reserved(x))
#define HDE_INTRLV_SIZE(x)	*(HDE_intrlv_size(x))
#define HDE_INTRLV_SKIP(x)	*(HDE_intrlv_skip(x))
#define HDE_VOL_SET(x)		BOTH_SHORT(HDE_vol_set(x))
#define HDE_NAME_LEN(x)		*(HDE_name_len(x))
#define HDE_NAME(x)		HDE_name(x)

/***UNIX EXTENSION*****/
#define HDE_MODE(x)		*(HDE_mode(x))
#define HDE_UID(x)		*(HDE_uid(x))
#define HDE_GID(x)		*(HDE_gid(x))

/* mask bits for HDE_FLAGS */
#define HDE_EXISTENCE		0x01	/* zero if file exists */
#define HDE_DIRECTORY		0x02	/* zero if file is not a directory */
#define HDE_ASSOCIATED		0x04	/* zero if file is not Associated */
#define HDE_RECORD		0x08	/* zero if no record attributes */
#define HDE_PROTECTION		0x10	/* zero if no protection attributes */
#define HDE_UNUSED_FLAGS	0x60
#define HDE_LAST_EXTENT		0x80	/* zero if last extent in file */
#define HDE_PROHIBITED	(HDE_DIRECTORY | HDE_ASSOCIATED | HDE_RECORD | \
			 HDE_LAST_EXTENT | HDE_UNUSED_FLAGS)

/* Directory Record date fields */
#define HDE_DATE_YEAR(x)	(((u_char *)x)[0] + 1900)
#define HDE_DATE_MONTH(x)	(((u_char *)x)[1])
#define HDE_DATE_DAY(x)		(((u_char *)x)[2])
#define HDE_DATE_HOUR(x)	(((u_char *)x)[3])
#define HDE_DATE_MIN(x)		(((u_char *)x)[4])
#define HDE_DATE_SEC(x)		(((u_char *)x)[5])

/* tests for Interchange Levels 1 & 2 file types */
#define HDE_REGULAR_FILE(x)	(((x) & HDE_PROHIBITED) == 0)
#define HDE_REGULAR_DIR(x)	(((x) & HDE_PROHIBITED) == HDE_DIRECTORY)

#define HS_DIR_NAMELEN		31	/* max length of a directory name */
#define HS_FILE_NAMELEN		31	/* max length of a filename */

#endif	/*!_HSFS_SPEC_H_*/
