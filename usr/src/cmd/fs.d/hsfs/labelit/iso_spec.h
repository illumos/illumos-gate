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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ISO 9660 filesystem specification
 */

#ifndef	_ISO_SPEC_H_
#define	_ISO_SPEC_H_

#include <sys/isa_defs.h>

/* routines required for date parsing */
extern struct timeval	iso_parse_dirdate();	/* parse date in directory */
extern struct timeval	iso__parse_longdate();	/* parse date in volume id */

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

#if defined(sparc)
/*
 * Sparc machines requires that integer must
 * be in a full word boundary.	CD-ROM data aligns
 * to even word boundary only.	Because of this mismatch,
 * we have to move integer data from CD-ROM to memory one
 * byte at a time.  LSB data starts first. We therefore
 * use this to do byte by byte copying.
 */
#define BOTH_SHORT(x)   LSB_SHORT(x)
#define BOTH_INT(x)     LSB_INT(x)

#elif defined(_LITTLE_ENDIAN)
#define BOTH_SHORT(x)   (short) *((short *)x)
#define BOTH_INT(x)     (int) *((int *)x)

#elif defined(_BIG_ENDIAN)
#define BOTH_SHORT(x)   (short) *((short *)x + 1)
#define BOTH_INT(x)     (int) *((int *)x + 1)
#else
#error One of _BIG_ENDIAN and _LITTLE_ENDIAN must be defined
#endif

/*
 * conversions to/from little endian format
 */
#if defined(_LITTLE_ENDIAN)
/* little endian machines */
#define ltohs(S)                (S)
#define ltohl(L)                (L)
#define htols(S)                (S)
#define htoll(L)                (L)
#else
/* big endian machines */
#define ltohs(S)        LSB_SHORT((char *) (S))
#define ltohl(L)        LSB_INT((char *) (L))
#define htols(S)        LSB_SHORT((char *) (S))
#define htoll(L)        LSB_INT((char *) (L))
#endif
 
/*
 * The following describes actual on-disk structures.
 * To achieve portability, all structures are #defines
 * rather than a structure definition.  Macros are provided
 * to get either the data or address of individual fields.
 */

/* Overall High Sierra disk structure */
#define ISO_SECTOR_SIZE	2048		/* bytes per logical sector */
#define ISO_SECTOR_SHIFT	11		/* sector<->byte shift count */
#define ISO_SEC_PER_PAGE	(PAGESIZE/HS_SECTOR_SIZE)	/* sectors per page */
#define ISO_SYSAREA_SEC	0		/* 1st sector of system area */
#define ISO_VOLDESC_SEC	16		/* 1st sector of volume descriptors */
#define MAXISOOFFSET (ISO_SECTOR_SIZE - 1)
#define MAXISOMASK   (~MAXISOOFFSET)


/* Standard File Structure Volume Descriptor */

enum iso_voldesc_type {
	ISO_VD_BOOT=0, ISO_VD_PVD=1, ISO_VD_SVD=2, ISO_VD_VPD=3, 
	ISO_VD_UNIX=4, /* UNIX extension */
	ISO_VD_EOV=255
};
#define ISO_ID_STRING	"CD001"		/* ISO_std_id field */
#define ISO_ID_STRLEN	5		/* ISO_std_id field length */
#define ISO_ID_VER	1		/* ISO_std_ver field */
#define ISO_FILE_STRUCT_ID_VER	1	/* ISO_file structure version  field */
#define ISO_DATE_TO_UNIX(x)	iso_parse_longdate(x)	/* returns a timeval */
#define ISO_SYS_ID_STRLEN	32
#define ISO_VOL_ID_STRLEN	32
#define ISO_VOL_SET_ID_STRLEN	128
#define ISO_PUB_ID_STRLEN	128
#define ISO_PREP_ID_STRLEN	128
#define ISO_APPL_ID_STRLEN	128
#define ISO_COPYR_ID_STRLEN	37
#define ISO_ABSTR_ID_STRLEN	37
#define ISO_DATE_LEN		17



/* macros to get the address of each field */
#define ISO_desc_type(x)	(&((u_char *)x)[0])
#define ISO_std_id(x)		(&((u_char *)x)[1])
#define ISO_std_ver(x)		(&((u_char *)x)[6])
#define ISO_sys_id(x)		(&((u_char *)x)[8])
#define ISO_vol_id(x)		(&((u_char *)x)[40])
#define ISO_vol_size(x)		(&((u_char *)x)[80])
#define ISO_set_size(x)		(&((u_char *)x)[120])
#define ISO_set_seq(x)		(&((u_char *)x)[124])
#define ISO_blk_size(x)		(&((u_char *)x)[128])
#define ISO_ptbl_size(x)	(&((u_char *)x)[132])
#define ISO_ptbl_man_ls(x)	(&((u_char *)x)[140])
#define ISO_ptbl_opt_ls1(x)	(&((u_char *)x)[144])
#define ISO_ptbl_man_ms(x)	(&((u_char *)x)[148])
#define ISO_ptbl_opt_ms1(x)	(&((u_char *)x)[152])
#define ISO_root_dir(x)		(&((u_char *)x)[156])
#define ISO_vol_set_id(x)	(&((u_char *)x)[190])
#define ISO_pub_id(x)		(&((u_char *)x)[318])
#define ISO_prep_id(x)		(&((u_char *)x)[446])
#define ISO_appl_id(x)		(&((u_char *)x)[574])
#define ISO_copyr_id(x)		(&((u_char *)x)[702])
#define ISO_abstr_id(x)		(&((u_char *)x)[739])
#define ISO_bibli_id(x)		(&((u_char *)x)[776])
#define ISO_cre_date(x)		(&((u_char *)x)[813])
#define ISO_mod_date(x)		(&((u_char *)x)[830])
#define ISO_exp_date(x)		(&((u_char *)x)[847])
#define ISO_eff_date(x)		(&((u_char *)x)[864])
#define ISO_file_struct_ver(x)	(&((u_char *)x)[881])

/* macros to get the values of each field (strings are returned as ptrs) */
#define ISO_DESC_TYPE(x)	((enum hs_voldesc_type)*(ISO_desc_type(x)))
#define ISO_STD_ID(x)		ISO_std_id(x)
#define ISO_STD_VER(x)		*(ISO_std_ver(x))
#define ISO_SYS_ID(x)		ISO_sys_id(x)
#define ISO_VOL_ID(x)		ISO_vol_id(x)
#define ISO_VOL_SIZE(x)		BOTH_INT(ISO_vol_size(x))
#define ISO_SET_SIZE(x)		BOTH_SHORT(ISO_set_size(x))
#define ISO_SET_SEQ(x)		BOTH_SHORT(ISO_set_seq(x))
#define ISO_BLK_SIZE(x)		BOTH_SHORT(ISO_blk_size(x))
#define ISO_PTBL_SIZE(x)	BOTH_INT(ISO_ptbl_size(x))
#define ISO_PTBL_MAN_LS(x)	LSB_INT(ISO_ptbl_man_ls(x))
#define ISO_PTBL_OPT_LS1(x)	LSB_INT(ISO_ptbl_opt_ls1(x))
#define ISO_PTBL_MAN_MS(x)	MSB_INT(ISO_ptbl_man_ms(x))
#define ISO_PTBL_OPT_MS1(x)	MSB_INT(ISO_ptbl_opt_ms1(x))
#define ISO_ROOT_DIR(x)		ISO_root_dir(x)
#define ISO_VOL_SET_ID(x)	ISO_vol_set_id(x)
#define ISO_PUB_ID(x)		ISO_pub_id(x)
#define ISO_PREP_ID(x)		ISO_prep_id(x)
#define ISO_APPL_ID(x)		ISO_appl_id(x)
#define ISO_COPYR_ID(x)		ISO_copyr_id(x)
#define ISO_ABSTR_ID(x)		ISO_abstr_id(x)
#define ISO_BIBLI_ID(x)		ISO_bibli_id(x)
#define ISO_CRE_DATE(x)		ISO_DATE_TO_UNIX(HSV_cre_date(x))
#define ISO_MOD_DATE(x)		ISO_DATE_TO_UNIX(HSV_mod_date(x))
#define ISO_EXP_DATE(x)		ISO_DATE_TO_UNIX(HSV_exp_date(x))
#define ISO_EFF_DATE(x)		ISO_DATE_TO_UNIX(HSV_eff_date(x))
#define ISO_FILE_STRUCT_VER(x)	*(ISO_file_struct_ver(x))

/* Standard File Structure Volume Descriptor date fields */
#define ISO_DATE_2DIG(x)	( (((x)[0] - '0') * 10) +		\
				   ((x)[1] - '0') )
#define ISO_DATE_4DIG(x)	( (((x)[0] - '0') * 1000) +		\
				  (((x)[1] - '0') * 100) +		\
				  (((x)[2] - '0') * 10) +		\
				   ((x)[3] - '0') )
#define ISO_DATE_YEAR(x)	ISO_DATE_4DIG(&((u_char *)x)[0])
#define ISO_DATE_MONTH(x)	ISO_DATE_2DIG(&((u_char *)x)[4])
#define ISO_DATE_DAY(x)		ISO_DATE_2DIG(&((u_char *)x)[6])
#define ISO_DATE_HOUR(x)	ISO_DATE_2DIG(&((u_char *)x)[8])
#define ISO_DATE_MIN(x)		ISO_DATE_2DIG(&((u_char *)x)[10])
#define ISO_DATE_SEC(x)		ISO_DATE_2DIG(&((u_char *)x)[12])
#define ISO_DATE_HSEC(x)	ISO_DATE_2DIG(&((u_char *)x)[14])



/* Directory Entry (Directory Record) */
#define IDE_ROOT_DIR_REC_SIZE   34      /* size of root directory record */
#define IDE_FDESIZE             33      /* fixed size for hsfs directory area */
                                        /* max size of a name */
#define IDE_MAX_NAME_LEN        (255 - IDE_FDESIZE)


#define IDE_DATE_TO_UNIX(x)	iso_parse_dirdate(x)	/* returns a timeval */

/* macros to get the address of each field */
#define IDE_dir_len(x)		(&((u_char *)x)[0])
#define IDE_xar_len(x)		(&((u_char *)x)[1])
#define IDE_ext_lbn(x)		(&((u_char *)x)[2])
#define IDE_ext_size(x)		(&((u_char *)x)[10])
#define IDE_cdate(x)		(&((u_char *)x)[18])
#define IDE_flags(x)		(&((u_char *)x)[25])
#define IDE_intrlv_size(x)	(&((u_char *)x)[26])
#define IDE_intrlv_skip(x)	(&((u_char *)x)[27])
#define IDE_vol_set(x)		(&((u_char *)x)[28])
#define IDE_name_len(x)		(&((u_char *)x)[32])
#define IDE_name(x)		(&((u_char *)x)[33])

/* macros to get the values of each field (strings are returned as ptrs) */
#define IDE_DIR_LEN(x)		*(IDE_dir_len(x))
#define IDE_XAR_LEN(x)		*(IDE_xar_len(x))
#define IDE_EXT_LBN(x)		BOTH_INT(IDE_ext_lbn(x))
#define IDE_EXT_SIZE(x)		BOTH_INT(IDE_ext_size(x))
#define IDE_CDATE(x)		IDE_DATE_TO_UNIX(HDE_cdate(x))
#define IDE_FLAGS(x)		*(IDE_flags(x))
#define IDE_INTRLV_SIZE(x)	*(IDE_intrlv_size(x))
#define IDE_INTRLV_SKIP(x)	*(IDE_intrlv_skip(x))
#define IDE_VOL_SET(x)		BOTH_SHORT(IDE_vol_set(x))
#define IDE_NAME_LEN(x)		*(IDE_name_len(x))
#define IDE_NAME(x)		IDE_name(x)

/* mask bits for IDE_FLAGS */
#define IDE_EXISTENCE		0x01	/* zero if file exists */
#define IDE_DIRECTORY		0x02	/* zero if file is not a directory */
#define IDE_ASSOCIATED		0x04	/* zero if file is not Associated */
#define IDE_RECORD		0x08	/* zero if no record attributes */
#define IDE_PROTECTION		0x10	/* zero if no protection attributes */
#define IDE_UNUSED_FLAGS	0x60
#define IDE_LAST_EXTENT		0x80	/* zero if last extent in file */
#define IDE_PROHIBITED	(IDE_DIRECTORY | HDE_ASSOCIATED | HDE_RECORD | \
			 IDE_LAST_EXTENT | IDE_UNUSED_FLAGS)

/* Directory Record date fields */
#define IDE_DATE_YEAR(x)	(((u_char *)x)[0] + 1900)
#define IDE_DATE_MONTH(x)	(((u_char *)x)[1])
#define IDE_DATE_DAY(x)		(((u_char *)x)[2])
#define IDE_DATE_HOUR(x)	(((u_char *)x)[3])
#define IDE_DATE_MIN(x)		(((u_char *)x)[4])
#define IDE_DATE_SEC(x)		(((u_char *)x)[5])

/* tests for Interchange Levels 1 & 2 file types */
#define IDE_REGULAR_FILE(x)	(((x) & IDE_PROHIBITED) == 0)
#define IDE_REGULAR_DIR(x)	(((x) & IDE_PROHIBITED) == IDE_DIRECTORY)

#define ISO_DIR_NAMELEN		31	/* max length of a directory name */
#define ISO_FILE_NAMELEN		31	/* max length of a filename */

/* Path table enry */
/* fix size of path table entry */
#define IPE_FPESIZE             8
/* macros to get the address of each field */
#define IPE_name_len(x)         (&((u_char *)x)[0])
#define IPE_xar_len(x)          (&((u_char *)x)[1])
#define IPE_ext_lbn(x)          (&((u_char *)x)[2])
#define IPE_parent_no(x)        (&((u_char *)x)[6])
#define IPE_name(x)             (&((u_char *)x)[8])
 
/* macros to get the values of each field */
#define IPE_EXT_LBN(x)          (MSB_INT(IPE_ext_lbn(x)))
#define IPE_XAR_LEN(x)          *(IPE_xar_len(x))
#define IPE_NAME_LEN(x)         *(IPE_name_len(x))
#define IPE_PARENT_NO(x)        *(short *)(IPE_parent_no(x))
#define IPE_NAME(x)             IPE_name(x)

/* cdrom UNIX extension */
/* UNIX Volume Descriptor */
#define ISO_UNIX_ID_STRING	"UNIXCD01"	/* ISO_UNIX_std_id field */
#define ISO_UNIX_ID_STRLEN	8		/* ISO_UNIX_std_id length */
#define	ISO_UNIX_FEATURE_SYMLNK	0x01		/* CD-ROM supports symbolic links */
#define	ISO_UNIX_FEATURE_LONGFN	0x02		/* CD-ROM supports long BSD file names */

#define ISO_UNIX_feature(x)	(&((u_char *)x)[7])
#define ISO_UNIX_root_dir(x)	(&((u_char *)x)[1395])
#define ISO_UNIX_signature(x)	(&((u_char *)x)[2040])

#define ISO_UNIX_FEATURE(x)	*(ISO_UNIX_feature(x)) 
#define ISO_UNIX_ROOT_DIR(x)	ISO_UNIX_root_dir(x)
#define ISO_UNIX_SIGNATURE(x)	ISO_UNIX_signature(x)

/* UNIX extension to path table entry */
/* fix size of path table entry */
#define IPE_UNIX_FPESIZE             20

#define IPE_UNIX_mode(x)        (&((u_char *)x)[0])
#define IPE_UNIX_uid(x)         (&((u_char *)x)[4])
#define IPE_UNIX_gid(x)         (&((u_char *)x)[8])

/* macros to get the values of each field */
#define IPE_UNIX_MODE(x)        (MSB_INT(IPE_UNIX_mode(x)))
#define IPE_UNIX_UID(x)         (MSB_INT(IPE_UNIX_uid(x)))
#define IPE_UNIX_GID(x)         (MSB_INT(IPE_UNIX_gid(x)))

/* UNIX extension to directory entry */
#define	IDE_UNIX_SIG_UX	"UX"		/* UNIX extension signature */
#define	IDE_UNIX_SIG_TI	"TI"		/* UNIX extension signature for time */
#define IDE_UNIX_USE_ID_VER 1           /* UNIX extension sys use id */
#define IDE_UNIX_UX_LEN	36		/* length of UX */
#define IDE_UNIX_TI_LEN	40		/* length of TI */

#define IDE_UNIX_signature(x)        (&((u_char *)x)[0])
#define IDE_UNIX_ext_len(x)        (&((u_char *)x)[2])
#define IDE_UNIX_use_id(x)        (&((u_char *)x)[3])
#define IDE_UNIX_mode(x)        (&((u_char *)x)[4])
#define IDE_UNIX_nlink(x)        (&((u_char *)x)[12])
#define IDE_UNIX_uid(x)        (&((u_char *)x)[20])
#define IDE_UNIX_gid(x)        (&((u_char *)x)[28])


#define IDE_UNIX_cre_date(x)	(&((u_char *)x)[4])
#define IDE_UNIX_mod_date(x)	(&((u_char *)x)[11])
#define IDE_UNIX_exp_date(x)	(&((u_char *)x)[18])
#define IDE_UNIX_eff_date(x)	(&((u_char *)x)[25])
#define IDE_UNIX_acc_date(x)	(&((u_char *)x)[32])
#define IDE_UNIX_reserved(x)	(&((u_char *)x)[39])

#define IDE_UNIX_SIGNATURE(x)	IDE_UNIX_signature(x)
#define IDE_UNIX_EXT_LEN(x)	*(IDE_UNIX_ext_len(x))
#define IDE_UNIX_USE_ID(x)	*(IDE_UNIX_use_id(x))
#define IDE_UNIX_MODE(x)	BOTH_INT(IDE_UNIX_mode(x))
#define IDE_UNIX_NLINK(x)	BOTH_INT(IDE_UNIX_nlink(x))
#define IDE_UNIX_UID(x)		BOTH_INT(IDE_UNIX_uid(x))
#define IDE_UNIX_GID(x)		BOTH_INT(IDE_UNIX_gid(x))

#define IDE_UNIX_CRE_DATE(x)	IDE_UNIX_cre_date(x)
#define IDE_UNIX_MOD_DATE(x)	IDE_UNIX_mod_date(x)
#define IDE_UNIX_EXP_DATE(x)	IDE_UNIX_exp_date(x)
#define IDE_UNIX_EFF_DATE(x)	IDE_UNIX_eff_date(x)
#define IDE_UNIX_ACC_DATE(x)	IDE_UNIX_acc_date(x)
#define IDE_UNIX_RESERVED(x)	*(IDE_UNIX_reserved(x))

/* root record */
/* size of root directory record */
#define IDE_UNIX_ROOT_DIR_REC_SIZE   34+IDE_UNIX_UX_LEN      
#define IDE_UNIX_MAX_NAME_LEN   IDE_MAX_NAME_LEN - IDE_UNIX_UX_LEN

#endif	/*!_ISO_SPEC_H_*/
