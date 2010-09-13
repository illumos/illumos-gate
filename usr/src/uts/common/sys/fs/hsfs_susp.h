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
 * ISO 9660 RRIP extension filesystem specifications
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_HSFS_SUSP_H
#define	_SYS_FS_HSFS_SUSP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DEBUGGING_ALL	0
#define	DEBUGGING	0
#define	DPRINTF		if (DEBUGGING) printf
#define	DPRINTF_ALL	if (DEBUGGING_ALL) printf

/*
 * 	return values from SUA parsing
 */
#define	SUA_NULL_POINTER	-1
#define	END_OF_SUA_PARSING	-2
#define	END_OF_SUA		-3
#define	GET_CONTINUATION	-4
#define	SUA_ENOMEM		-5
#define	SUA_EINVAL		-6
#define	RELOC_DIR		-7	/* actually for rrip */

/*
 * For dealing with implemented bits...
 *    These here expect the fsp and a bit as an agument
 */
#define	SET_IMPL_BIT(fsp, y)	((fsp->hsfs_ext_impl)  |= (0x01L) << (y))
#define	UNSET_IMPL_BIT(fsp, y)	((fsp->hsfs_ext_impl)  &= ~((0x01L) << (y)))
#define	IS_IMPL_BIT_SET(fsp, y)	((fsp->hsfs_ext_impl)  & ((0x01L) << (y)))

#define	HAVE_SUSP		0	/* have a SUSP */
#define	HAVE_PROHIBITED		1	/* prohibited file/dir type in fs */

/*
 * For dealing with implemented bits...
 *    These here expect just the fsp->hsfs_ext_impl
 */
#define	SET_SUSP_BIT(fsp)	(SET_IMPL_BIT((fsp), HAVE_SUSP))
#define	UNSET_SUSP_BIT(fsp)	(UNSET_IMPL_BIT((fsp), HAVE_SUSP))
#define	IS_SUSP_IMPLEMENTED(fsp) (IS_IMPL_BIT_SET(fsp, 0) ? 1 : 0)

#define	SUSP_VERSION	1

/*
 * SUSP signagure definitions
 */
#define	SUSP_SP		"SP"
#define	SUSP_CE		"CE"
#define	SUSP_PD		"PD"
#define	SUSP_ER		"ER"
#define	SUSP_ST		"ST"

/*
 * 	Generic System Use Field (SUF) Macros and declarations
 */

#define	SUF_SIG_LEN	2			/* length of signatures */
#define	SUF_MIN_LEN	4			/* minimum length of a */
						/* 	signature field */

#define	SUF_LEN(x)	*(SUF_len(x))		/* SUF length */
#define	SUF_len(x)	(&((uchar_t *)x)[2])	/* SUF length */

#define	SUF_VER(x)	*(SUF_ver(x))		/* SUF version */
#define	SUF_ver(x)	(&((uchar_t *)x)[3])	/* SUF version */

/*
 * Extension Reference Macros
 */

#define	ER_ID_LEN(x)	*(ER_id_len(x))	/* Extension ref id length */
#define	ER_id_len(x)	(&((uchar_t *)x)[4])	/* Extension ref id length */


#define	ER_DES_LEN(x)	*(ER_des_len(x))	/* Extension ref description */
						/* 	length */
#define	ER_des_len(x)	(&((uchar_t *)x)[5])	/* Extension ref description */
						/* 	length */

#define	ER_SRC_LEN(x)	*(ER_src_len(x))	/* Extension ref source */
						/* 	description length */

#define	ER_src_len(x)	(&((uchar_t *)x)[6])	/* Extension ref source */
						/* description length */


#define	ER_EXT_VER(x)	*(ER_ext_ver(x))	/* Extension ref description */
						/*  length */
#define	ER_ext_ver(x)	(&((uchar_t *)x)[7])	/* Extension ref description */
						/* length */

#define	ER_EXT_ID_LOC	8			/* location where the ER id */
						/* string begins */

#define	ER_ext_id(x)	(&((uchar_t *)x)[ER_EXT_ID_LOC])
						/* extension id string */

#define	ER_ext_des(x)	(&((uchar_t *)x)[ER_EXT_ID_LOC + ER_ID_LEN(x)])
						/* ext. description string */

#define	ER_ext_src(x)	(&((uchar_t *)x)[ER_EXT_ID_LOC + ER_ID_LEN(x) + \
					ER_DES_LEN(x)])
						/* ext. source string */


/*
 * Continuation Area Macros
 */
#define	CE_BLK_LOC(x)	BOTH_INT(CE_blk_loc(x))	/* cont. starting block */
#define	CE_blk_loc(x)	(&((uchar_t *)x)[4])	/* cont. starting block */

#define	CE_OFFSET(x)	BOTH_INT(CE_offset(x))	/* cont. offset */
#define	CE_offset(x)	(&((uchar_t *)x)[12])	/* cont. offset */

#define	CE_CONT_LEN(x)	BOTH_INT(CE_cont_len(x))	/* continuation len */
#define	CE_cont_len(x)	(&((uchar_t *)x)[20])	/* continuation len */


/*
 * Sharing Protocol (SP) Macros
 */
#define	SP_CHK_BYTE_1(x)	*(SP_chk_byte_1(x))	/* check bytes */
#define	SP_chk_byte_1(x)	(&((uchar_t *)x)[4])	/* check bytes */

#define	SP_CHK_BYTE_2(x)	*(SP_chk_byte_2(x))	/* check bytes */
#define	SP_chk_byte_2(x)	(&((uchar_t *)x)[5])	/* check bytes */

#define	SUSP_CHECK_BYTE_1	(uchar_t)0xBE		/* check for 0xBE */
#define	SUSP_CHECK_BYTE_2	(uchar_t)0xEF		/* check for 0xEF */

#define	CHECK_BYTES_OK(x)	((SP_CHK_BYTE_1(x) == SUSP_CHECK_BYTE_1) && \
				(SP_CHK_BYTE_2(x) == SUSP_CHECK_BYTE_2))

#define	SP_SUA_OFFSET(x)	*(SP_sua_offset(x))	/* SUA bytes to skip */
#define	SP_sua_offset(x)	(&((uchar_t *)x)[6])	/* SUA bytes to skip */



/*
 * Forward declarations
 */

#ifdef _KERNEL

extern uchar_t *share_protocol();
extern uchar_t *share_ext_ref();
extern uchar_t *share_continue();
extern uchar_t *share_padding();
extern uchar_t *share_stop();

#endif

/*
 * Extension signature structure, to corrolate the handler functions
 * with the signatures
 */
struct extension_signature_struct {
	char	*ext_signature;		/* extension signature */
	uchar_t	*(*sig_handler)();	/* extension handler function */
};

typedef	struct extension_signature_struct	ext_signature_t;


/*
 * Extension name structure, to corrolate the extensions with their own
 * 	signature tables.
 */
struct extension_name_struct {
	char  		*extension_name;	/* ER field identifier */
	ushort_t	ext_version;		/* version # of extensions */
	ext_signature_t	*signature_table;	/* pointer to signature */
						/*   table for appropriate */
						/*   extension */
};

typedef	struct extension_name_struct extension_name_t;

/*
 * Extern declaration for all supported extensions
 */
struct	cont_info_struct	{
	uint_t	cont_lbn;	/* location  of cont */
	uint_t	cont_offset;	/* offset into cont */
	uint_t	cont_len;	/* len of cont */
};

typedef struct cont_info_struct	cont_info_t;

/*
 * Structure for passing arguments to sig_handler()'s.  Since there are
 * so many sig_handler()'s, it would be slower to pass multiple
 * arguments to all of them. It would also ease maintainance
 */
struct sig_args_struct {
	uchar_t			*dirp;		/* pointer to ISO dir entry */
	uchar_t			*name_p;	/* dir entry name */
	int			*name_len_p;	/* dir entry name length */
	short			flags;		/* misc flags */
	ulong_t			name_flags;		/* misc flags */
	uchar_t			*SUF_ptr;	/* pointer to current SUF */
	struct hs_direntry	*hdp;		/* directory entry  */
	struct hsfs		*fsp;		/* file system  */
	cont_info_t		*cont_info_p;	/* continuation area */
};

typedef struct sig_args_struct	sig_args_t;


/*
 * Extern declaration for all supported extensions
 */

#ifdef _KERNEL

extern ext_signature_t		rrip_signature_table[];
extern ext_signature_t		susp_signature_table[];
extern extension_name_t		extension_name_table[];

extern ext_signature_t		*susp_sp;

extern int parse_sua(uchar_t *, int *name_len_p, int *, uchar_t *, uint_t,
	struct hs_direntry *,	struct hsfs *,	uchar_t	*, int search_num);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_HSFS_SUSP_H */
