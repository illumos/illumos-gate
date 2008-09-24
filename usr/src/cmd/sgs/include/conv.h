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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CONV_H
#define	_CONV_H

/*
 * Global include file for conversion library.
 */

#include <stdlib.h>
#include <libelf.h>
#include <dlfcn.h>
#include <libld.h>
#include <sgs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Configuration features available - maintained here (instead of debug.h)
 * to save libconv from having to include debug.h which results in numerous
 * "declared but not used or defined" lint errors.
 */
#define	CONF_EDLIBPATH	0x000100	/* ELF default library path */
#define	CONF_ESLIBPATH	0x000200	/* ELF secure library path */
#define	CONF_ADLIBPATH	0x000400	/* AOUT default library path */
#define	CONF_ASLIBPATH	0x000800	/* AOUT secure library path */
#define	CONF_DIRCFG	0x001000	/* directory configuration available */
#define	CONF_OBJALT	0x002000	/* object alternatives available */
#define	CONF_MEMRESV	0x004000	/* memory reservation required */
#define	CONF_ENVS	0x008000	/* environment variables available */
#define	CONF_FLTR	0x010000	/* filter information available */
#define	CONF_FEATMSK	0xffff00

/*
 * Buffer types:
 *
 * Many of the routines in this module require the user to supply a
 * buffer into which the desired strings may be written. These are
 * all arrays of characters, and might be defined as simple arrays
 * of char. The problem with that approach is that when such an array
 * is passed to a function, the C language considers it to have the
 * type (char *), without any regard to its length. Not all of our
 * buffers have the same length, and we want to ensure that the compiler
 * will refuse to compile code that passes the wrong type of buffer to
 * a given routine. The solution is to define the buffers as unions
 * that contain the needed array, and then to pass the given union
 * by address. The compiler will catch attempts to pass the wrong type
 * of pointer, and the size of a structure/union is implicit in its type.
 *
 * A nice side effect of this approach is that we can use a union with
 * multiple buffers to handle the cases where a given routine needs
 * more than one type of buffer. The end result is a single buffer large
 * enough to handle any of the subcases, but no larger.
 */

/*
 * Size of buffer used by conv_invalid_val():
 *
 * Various values that can't be matched to a symbolic definition are converted
 * to a numeric string.
 *
 * The buffer size reflects the maximum number of digits needed to
 * display an integer as text, plus a trailing null, and with room for
 * a leading "0x" if hexidecimal display is selected.
 */
#define	CONV32_INV_BUFSIZE	12
typedef union {
	char			buf[CONV32_INV_BUFSIZE];
} Conv32_inv_buf_t;

#define	CONV64_INV_BUFSIZE	22
typedef union {
	char			buf[CONV64_INV_BUFSIZE];
} Conv64_inv_buf_t;



/* conv_ehdr_flags() */
#define	CONV_EHDR_FLAGS_BASE_BUFSIZE	69
#define	CONV32_EHDR_FLAGS_BUFSIZE	\
	(CONV_EHDR_FLAGS_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_EHDR_FLAGS_BUFSIZE];
} Conv32_ehdr_flags_buf_t;

#define	CONV64_EHDR_FLAGS_BUFSIZE	\
	(CONV_EHDR_FLAGS_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_EHDR_FLAGS_BUFSIZE];
} Conv64_ehdr_flags_buf_t;


/* conv_reject_desc() */
typedef union {
	Conv32_inv_buf_t	inv_buf;
	Conv32_ehdr_flags_buf_t	flags_buf;
} Conv32_reject_desc_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	Conv64_ehdr_flags_buf_t	flags_buf;
} Conv64_reject_desc_buf_t;


/*
 * conv_cap_val_hw1()
 *
 * This size is based on the maximum number of hardware capabilities
 * that exist.  See common/elfcap.
 */
#define	CONV_CAP_VAL_HW1_BUFSIZE	195

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CAP_VAL_HW1_BUFSIZE];
} Conv32_cap_val_hw1_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CAP_VAL_HW1_BUFSIZE];
} Conv64_cap_val_hw1_buf_t;


/*
 * conv_cap_val_sf1()
 *
 * This size is based on the maximum number of software capabilities
 * that exist.  See common/elfcap.
 */
#define	CONV_CAP_VAL_SF1_BUFSIZE	45

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CAP_VAL_SF1_BUFSIZE];
} Conv32_cap_val_sf1_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CAP_VAL_SF1_BUFSIZE];
} Conv64_cap_val_sf1_buf_t;



/* conv_cap_val_buf() */
typedef union {
	Conv32_inv_buf_t		inv_buf;
	Conv32_cap_val_hw1_buf_t	cap_val_hw1_buf;
	Conv32_cap_val_sf1_buf_t	cap_val_sf1_buf;
} Conv32_cap_val_buf_t;

typedef union {
	Conv64_inv_buf_t		inv_buf;
	Conv64_cap_val_hw1_buf_t	cap_val_hw1_buf;
	Conv64_cap_val_sf1_buf_t	cap_val_sf1_buf;
} Conv64_cap_val_buf_t;


/* conv_config_feat() */
#define	CONV_CONFIG_FEAT_BUFSIZE	194

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CONFIG_FEAT_BUFSIZE];
} Conv32_config_feat_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CONFIG_FEAT_BUFSIZE];
} Conv64_config_feat_buf_t;


/* conv_config_obj() */
#define	CONV_CONFIG_OBJ_BUFSIZE		154

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CONFIG_OBJ_BUFSIZE];
} Conv32_config_obj_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CONFIG_OBJ_BUFSIZE];
} Conv64_config_obj_buf_t;


/* conv_dl_mode() */
#define	CONV_DL_MODE_BUFSIZE		122

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_DL_MODE_BUFSIZE];
} Conv32_dl_mode_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_DL_MODE_BUFSIZE];
} Conv64_dl_mode_buf_t;


/* conv_dl_flag() */
#define	CONV_DL_FLAG_BUFSIZE		175

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_DL_FLAG_BUFSIZE];
} Conv32_dl_flag_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_DL_FLAG_BUFSIZE];
} Conv64_dl_flag_buf_t;


/* conv_grphdl_flags() */
#define	CONV_GRPHDL_FLAGS_BUFSIZE	82

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_GRPHDL_FLAGS_BUFSIZE];
} Conv32_grphdl_flags_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_GRPHDL_FLAGS_BUFSIZE];
} Conv64_grphdl_flags_buf_t;


/* conv_grpdesc_flags() */
#define	CONV_GRPDESC_FLAGS_BUFSIZE	92

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_GRPDESC_FLAGS_BUFSIZE];
} Conv32_grpdesc_flags_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_GRPDESC_FLAGS_BUFSIZE];
} Conv64_grpdesc_flags_buf_t;


/* conv_seg_flags() */
#define	CONV_SEG_FLAGS_BUFSIZE		186

typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_SEG_FLAGS_BUFSIZE];
} Conv32_seg_flags_buf_t;

typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_SEG_FLAGS_BUFSIZE];
} Conv64_seg_flags_buf_t;


/* conv_dyn_posflag1() */
#define	CONV_DYN_POSFLAG1_BASE_BUFSIZE	23
#define	CONV32_DYN_POSFLAG1_BUFSIZE	\
	(CONV_DYN_POSFLAG1_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_DYN_POSFLAG1_BUFSIZE];
} Conv32_dyn_posflag1_buf_t;

#define	CONV64_DYN_POSFLAG1_BUFSIZE	\
	(CONV_DYN_POSFLAG1_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_DYN_POSFLAG1_BUFSIZE];
} Conv64_dyn_posflag1_buf_t;


/* conv_dyn_flag() */
#define	CONV_DYN_FLAG_BASE_BUFSIZE	48
#define	CONV32_DYN_FLAG_BUFSIZE	\
	(CONV_DYN_FLAG_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_DYN_FLAG_BUFSIZE];
} Conv32_dyn_flag_buf_t;

#define	CONV64_DYN_FLAG_BUFSIZE	\
	(CONV_DYN_FLAG_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_DYN_FLAG_BUFSIZE];
} Conv64_dyn_flag_buf_t;


/* conv_dyn_flag1() */
#define	CONV_DYN_FLAG1_BASE_BUFSIZE	265
#define	CONV32_DYN_FLAG1_BUFSIZE	\
	(CONV_DYN_FLAG1_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_DYN_FLAG1_BUFSIZE];
} Conv32_dyn_flag1_buf_t;

#define	CONV64_DYN_FLAG1_BUFSIZE	\
	(CONV_DYN_FLAG1_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_DYN_FLAG1_BUFSIZE];
} Conv64_dyn_flag1_buf_t;


/* conv_dyn_feature1() */
#define	CONV_DYN_FEATURE1_BASE_BUFSIZE	20
#define	CONV32_DYN_FEATURE1_BUFSIZE	\
	(CONV_DYN_FEATURE1_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_DYN_FEATURE1_BUFSIZE];
} Conv32_dyn_feature1_buf_t;

#define	CONV64_DYN_FEATURE1_BUFSIZE	\
	(CONV_DYN_FEATURE1_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_DYN_FEATURE1_BUFSIZE];
} Conv64_dyn_feature1_buf_t;


/* conv_bnd_type() */
#define	CONV_BND_TYPE_BASE_BUFSIZE	29
#define	CONV32_BND_TYPE_BUFSIZE	\
	(CONV_BND_TYPE_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_BND_TYPE_BUFSIZE];
} Conv32_bnd_type_buf_t;

#define	CONV64_BND_TYPE_BUFSIZE	\
	(CONV_BND_TYPE_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_BND_TYPE_BUFSIZE];
} Conv64_bnd_type_buf_t;


/* conv_bnd_obj() */
#define	CONV_BND_OBJ_BASE_BUFSIZE	38
#define	CONV32_BND_OBJ_BUFSIZE	\
	(CONV_BND_OBJ_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_BND_OBJ_BUFSIZE];
} Conv32_bnd_obj_buf_t;

#define	CONV64_BND_OBJ_BUFSIZE	\
	(CONV_BND_OBJ_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_BND_OBJ_BUFSIZE];
} Conv64_bnd_obj_buf_t;


/* conv_phdr_flags() */
#define	CONV_PHDR_FLAGS_BASE_BUFSIZE	35
#define	CONV32_PHDR_FLAGS_BUFSIZE	\
	(CONV_PHDR_FLAGS_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_PHDR_FLAGS_BUFSIZE];
} Conv32_phdr_flags_buf_t;

#define	CONV64_PHDR_FLAGS_BUFSIZE	\
	(CONV_PHDR_FLAGS_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_PHDR_FLAGS_BUFSIZE];
} Conv64_phdr_flags_buf_t;


/* conv_sec_flags() */
#define	CONV_SEC_FLAGS_BASE_BUFSIZE	168
#define	CONV32_SEC_FLAGS_BUFSIZE	\
	(CONV_SEC_FLAGS_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_SEC_FLAGS_BUFSIZE];
} Conv32_sec_flags_buf_t;

#define	CONV64_SEC_FLAGS_BUFSIZE	\
	(CONV_SEC_FLAGS_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_SEC_FLAGS_BUFSIZE];
} Conv64_sec_flags_buf_t;


/* conv_dwarf_ehe() */
#define	CONV_DWARF_EHE_BUFSIZE		33
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_DWARF_EHE_BUFSIZE];
} Conv32_dwarf_ehe_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_DWARF_EHE_BUFSIZE];
} Conv64_dwarf_ehe_buf_t;


/* conv_syminfo_flags() */
#define	CONV_SYMINFO_FLAGS_BASE_BUFSIZE	36
#define	CONV32_SYMINFO_FLAGS_BUFSIZE	\
	(CONV_SYMINFO_FLAGS_BASE_BUFSIZE + CONV32_INV_BUFSIZE)
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV32_SYMINFO_FLAGS_BUFSIZE];
} Conv32_syminfo_flags_buf_t;

#define	CONV64_SYMINFO_FLAGS_BUFSIZE	\
	(CONV_SYMINFO_FLAGS_BASE_BUFSIZE + CONV64_INV_BUFSIZE)
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV64_SYMINFO_FLAGS_BUFSIZE];
} Conv64_syminfo_flags_buf_t;


/* conv_cnote_pr_flags() */
#define	CONV_CNOTE_PR_FLAGS_BUFSIZE	244
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_PR_FLAGS_BUFSIZE];
} Conv32_cnote_pr_flags_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_PR_FLAGS_BUFSIZE];
} Conv64_cnote_pr_flags_buf_t;


/* conv_cnote_old_pr_flags() */
#define	CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE	164
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE];
} Conv32_cnote_old_pr_flags_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE];
} Conv64_cnote_old_pr_flags_buf_t;


/* conv_cnote_proc_flag() */
#define	CONV_CNOTE_PROC_FLAG_BUFSIZE	29
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_PROC_FLAG_BUFSIZE];
} Conv32_cnote_proc_flag_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_PROC_FLAG_BUFSIZE];
} Conv64_cnote_proc_flag_buf_t;


/* conv_cnote_sigset() */
#define	CONV_CNOTE_SIGSET_BUFSIZE	629
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SIGSET_BUFSIZE];
} Conv32_cnote_sigset_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SIGSET_BUFSIZE];
} Conv64_cnote_sigset_buf_t;


/* conv_cnote_fltset() */
#define	CONV_CNOTE_FLTSET_BUFSIZE	501
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_FLTSET_BUFSIZE];
} Conv32_cnote_fltset_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_FLTSET_BUFSIZE];
} Conv64_cnote_fltset_buf_t;


/* conv_cnote_sysset() */
#define	CONV_CNOTE_SYSSET_BUFSIZE	3212
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SYSSET_BUFSIZE];
} Conv32_cnote_sysset_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SYSSET_BUFSIZE];
} Conv64_cnote_sysset_buf_t;


/* conv_cnote_sa_flags() */
#define	CONV_CNOTE_SA_FLAGS_BUFSIZE	99
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SA_FLAGS_BUFSIZE];
} Conv32_cnote_sa_flags_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SA_FLAGS_BUFSIZE];
} Conv64_cnote_sa_flags_buf_t;


/* conv_cnote_ss_flags() */
#define	CONV_CNOTE_SS_FLAGS_BUFSIZE	38
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SS_FLAGS_BUFSIZE];
} Conv32_cnote_ss_flags_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_SS_FLAGS_BUFSIZE];
} Conv64_cnote_ss_flags_buf_t;


/* conv_cnote_cc_content() */
#define	CONV_CNOTE_CC_CONTENT_BUFSIZE	87
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_CC_CONTENT_BUFSIZE];
} Conv32_cnote_cc_content_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_CC_CONTENT_BUFSIZE];
} Conv64_cnote_cc_content_buf_t;


/* conv_cnote_auxv_af() */
#define	CONV_CNOTE_AUXV_AF_BUFSIZE	63
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_AUXV_AF_BUFSIZE];
} Conv32_cnote_auxv_af_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_CNOTE_AUXV_AF_BUFSIZE];
} Conv64_cnote_auxv_af_buf_t;


/* conv_ver_flags() */
#define	CONV_VER_FLAGS_BUFSIZE	31
typedef union {
	Conv32_inv_buf_t	inv_buf;
	char			buf[CONV_VER_FLAGS_BUFSIZE];
} Conv32_ver_flags_buf_t;
typedef union {
	Conv64_inv_buf_t	inv_buf;
	char			buf[CONV_VER_FLAGS_BUFSIZE];
} Conv64_ver_flags_buf_t;



/*
 * Generic names for class specific buffer types above
 */
#if	defined(_ELF64)
#define	CONV_INV_BUFSIZE		CONV64_INV_BUFSIZE
#define	CONV_EHDR_FLAGS_BUFSIZE		CONV64_EHDR_FLAGS_BUFSIZE
#define	CONV_DYN_POSFLAG1_BUFSIZE	CONV64_DYN_POSFLAG1_BUFSIZE
#define	CONV_DYN_FLAG_BUFSIZE		CONV64_DYN_FLAG_BUFSIZE
#define	CONV_DYN_FLAG1_BUFSIZE		CONV64_DYN_FLAG1_BUFSIZE
#define	CONV_DYN_FEATURE1_BUFSIZE	CONV64_DYN_FEATURE1_BUFSIZE
#define	CONV_BND_TYPE_BUFSIZE		CONV64_BND_TYPE_BUFSIZE
#define	CONV_BND_OBJ_BUFSIZE		CONV64_BND_OBJ_BUFSIZE
#define	CONV_PHDR_FLAGS_BUFSIZE		CONV64_PHDR_FLAGS_BUFSIZE
#define	CONV_SEC_FLAGS_BUFSIZE		CONV64_SEC_FLAGS_BUFSIZE
#define	CONV_SYMINFO_FLAGS_BUFSIZE	CONV64_SYMINFO_FLAGS_BUFSIZE

#define	Conv_inv_buf_t			Conv64_inv_buf_t
#define	Conv_ehdr_flags_buf_t		Conv64_ehdr_flags_buf_t
#define	Conv_reject_desc_buf_t		Conv64_reject_desc_buf_t
#define	Conv_cap_val_hw1_buf_t		Conv64_cap_val_hw1_buf_t
#define	Conv_cap_val_sf1_buf_t		Conv64_cap_val_sf1_buf_t
#define	Conv_cap_val_buf_t		Conv64_cap_val_buf_t
#define	Conv_config_feat_buf_t		Conv64_config_feat_buf_t
#define	Conv_config_obj_buf_t		Conv64_config_obj_buf_t
#define	Conv_dl_mode_buf_t		Conv64_dl_mode_buf_t
#define	Conv_dl_flag_buf_t		Conv64_dl_flag_buf_t
#define	Conv_grphdl_flags_buf_t		Conv64_grphdl_flags_buf_t
#define	Conv_grpdesc_flags_buf_t	Conv64_grpdesc_flags_buf_t
#define	Conv_seg_flags_buf_t		Conv64_seg_flags_buf_t
#define	Conv_dyn_posflag1_buf_t		Conv64_dyn_posflag1_buf_t
#define	Conv_dyn_flag_buf_t		Conv64_dyn_flag_buf_t
#define	Conv_dyn_flag1_buf_t		Conv64_dyn_flag1_buf_t
#define	Conv_dyn_feature1_buf_t		Conv64_dyn_feature1_buf_t
#define	Conv_bnd_type_buf_t		Conv64_bnd_type_buf_t
#define	Conv_bnd_obj_buf_t		Conv64_bnd_obj_buf_t
#define	Conv_phdr_flags_buf_t		Conv64_phdr_flags_buf_t
#define	Conv_sec_flags_buf_t		Conv64_sec_flags_buf_t
#define	Conv_dwarf_ehe_buf_t		Conv64_dwarf_ehe_buf_t
#define	Conv_syminfo_flags_buf_t	Conv64_syminfo_flags_buf_t
#define	Conv_cnote_pr_flags_buf_t	Conv64_cnote_pr_flags_buf_t
#define	Conv_cnote_old_pr_flags_buf_t	Conv64_cnote_old_pr_flags_buf_t
#define	Conv_cnote_proc_flag_buf_t	Conv64_cnote_proc_flag_buf_t
#define	Conv_cnote_sigset_buf_t		Conv64_cnote_sigset_buf_t
#define	Conv_cnote_fltset_buf_t		Conv64_cnote_fltset_buf_t
#define	Conv_cnote_sysset_buf_t		Conv64_cnote_sysset_buf_t
#define	Conv_cnote_sa_flags_buf_t	Conv64_cnote_sa_flags_buf_t
#define	Conv_cnote_ss_flags_buf_t	Conv64_cnote_ss_flags_buf_t
#define	Conv_cnote_cc_content_buf_t	Conv64_cnote_cc_content_buf_t
#define	Conv_cnote_auxv_af_buf_t	Conv64_cnote_auxv_af_buf_t
#define	Conv_ver_flags_buf_t		Conv64_ver_flags_buf_t
#else
#define	CONV_INV_BUFSIZE		CONV32_INV_BUFSIZE
#define	CONV_EHDR_FLAGS_BUFSIZE		CONV32_EHDR_FLAGS_BUFSIZE
#define	CONV_DYN_POSFLAG1_BUFSIZE	CONV32_DYN_POSFLAG1_BUFSIZE
#define	CONV_DYN_FLAG_BUFSIZE		CONV32_DYN_FLAG_BUFSIZE
#define	CONV_DYN_FLAG1_BUFSIZE		CONV32_DYN_FLAG1_BUFSIZE
#define	CONV_DYN_FEATURE1_BUFSIZE	CONV32_DYN_FEATURE1_BUFSIZE
#define	CONV_BND_TYPE_BUFSIZE		CONV32_BND_TYPE_BUFSIZE
#define	CONV_BND_OBJ_BUFSIZE		CONV32_BND_OBJ_BUFSIZE
#define	CONV_PHDR_FLAGS_BUFSIZE		CONV32_PHDR_FLAGS_BUFSIZE
#define	CONV_SEC_FLAGS_BUFSIZE		CONV32_SEC_FLAGS_BUFSIZE
#define	CONV_SYMINFO_FLAGS_BUFSIZE	CONV32_SYMINFO_FLAGS_BUFSIZE

#define	Conv_inv_buf_t			Conv32_inv_buf_t
#define	Conv_ehdr_flags_buf_t		Conv32_ehdr_flags_buf_t
#define	Conv_reject_desc_buf_t		Conv32_reject_desc_buf_t
#define	Conv_cap_val_hw1_buf_t		Conv32_cap_val_hw1_buf_t
#define	Conv_cap_val_sf1_buf_t		Conv32_cap_val_sf1_buf_t
#define	Conv_cap_val_buf_t		Conv32_cap_val_buf_t
#define	Conv_config_feat_buf_t		Conv32_config_feat_buf_t
#define	Conv_config_obj_buf_t		Conv32_config_obj_buf_t
#define	Conv_dl_mode_buf_t		Conv32_dl_mode_buf_t
#define	Conv_dl_flag_buf_t		Conv32_dl_flag_buf_t
#define	Conv_grphdl_flags_buf_t		Conv32_grphdl_flags_buf_t
#define	Conv_grpdesc_flags_buf_t	Conv32_grpdesc_flags_buf_t
#define	Conv_seg_flags_buf_t		Conv32_seg_flags_buf_t
#define	Conv_dyn_posflag1_buf_t		Conv32_dyn_posflag1_buf_t
#define	Conv_dyn_flag_buf_t		Conv32_dyn_flag_buf_t
#define	Conv_dyn_flag1_buf_t		Conv32_dyn_flag1_buf_t
#define	Conv_dyn_feature1_buf_t		Conv32_dyn_feature1_buf_t
#define	Conv_bnd_type_buf_t		Conv32_bnd_type_buf_t
#define	Conv_bnd_obj_buf_t		Conv32_bnd_obj_buf_t
#define	Conv_phdr_flags_buf_t		Conv32_phdr_flags_buf_t
#define	Conv_sec_flags_buf_t		Conv32_sec_flags_buf_t
#define	Conv_dwarf_ehe_buf_t		Conv32_dwarf_ehe_buf_t
#define	Conv_syminfo_flags_buf_t	Conv32_syminfo_flags_buf_t
#define	Conv_cnote_pr_flags_buf_t	Conv32_cnote_pr_flags_buf_t
#define	Conv_cnote_old_pr_flags_buf_t	Conv32_cnote_old_pr_flags_buf_t
#define	Conv_cnote_proc_flag_buf_t	Conv32_cnote_proc_flag_buf_t
#define	Conv_cnote_sigset_buf_t		Conv32_cnote_sigset_buf_t
#define	Conv_cnote_fltset_buf_t		Conv32_cnote_fltset_buf_t
#define	Conv_cnote_sysset_buf_t		Conv32_cnote_sysset_buf_t
#define	Conv_cnote_sa_flags_buf_t	Conv32_cnote_sa_flags_buf_t
#define	Conv_cnote_ss_flags_buf_t	Conv32_cnote_ss_flags_buf_t
#define	Conv_cnote_cc_content_buf_t	Conv32_cnote_cc_content_buf_t
#define	Conv_cnote_auxv_af_buf_t	Conv32_cnote_auxv_af_buf_t
#define	Conv_ver_flags_buf_t		Conv32_ver_flags_buf_t
#endif




/*
 * Many conversion routines accept a fmt_flags argument of this type
 * to allow the caller to modify the output. There are two parts to
 * this value:
 *
 *	(1) Format requests (decimal vs hex, etc...)
 *	(2) The low order bits specified by CONV_MASK_FMT_ALT
 *		and retrieved by CONV_TYPE_FMT_ALT are integer
 *		values that specify that an alternate set of
 *		strings should be used. This is necessary because
 *		different utilities evolved to use different strings,
 *		and there are backward compatability guarantees in
 *		place that prevent changing them.
 *
 * These values are designed such that a caller can always supply a
 * simple 0 in order to receive "default" behavior.
 */
typedef int Conv_fmt_flags_t;

/*
 * The bottom 8 bits of Conv_fmt_flags_t are used to encode
 * alternative strings.
 *
 * If a given conversion routine does not support alternative strings
 * for a given CONV_FMT_ALT type, it silently ignores the request and
 * supplies the default set. This means that a utility like dump(1) is
 * free to specify its special type in every conversion routine call,
 * without regard to whether it has any special meaning for that particular
 * routine. It will receive its special strings if there are any, and
 * the defaults otherwise.
 */
#define	CONV_MASK_FMT_ALT		0xff
#define	CONV_TYPE_FMT_ALT(fmt_flags)	(fmt_flags & CONV_MASK_FMT_ALT)

#define	CONV_FMT_ALT_DEFAULT	0	/* "Standard" strings */
#define	CONV_FMT_ALT_DUMP	1	/* Style of strings used by dump(1) */
#define	CONV_FMT_ALT_FILE	2	/* Style of strings used by file(1) */
#define	CONV_FMT_ALT_CRLE	3	/* Style of strings used by crle(1) */
#define	CONV_FMT_ALT_FULLNAME	4	/* Strings should be full #define */
					/* 	(e.g. STB_LOCAL, not LOCL) */

/*
 * Flags that alter standard formatting for conversion routines.
 * These bits start after the range occupied by CONV_MASK_FMT_ALT.
 */
#define	CONV_FMT_DECIMAL	0x0100	/* conv_invalid_val() should print */
					/*    integer print as decimal */
					/*    (default is hex) */
#define	CONV_FMT_SPACE		0x0200	/* conv_invalid_val() should append */
					/*    a space after the number.  */
#define	CONV_FMT_NOBKT		0x0400	/* conv_expn_field() should omit */
					/*    prefix and suffix strings */


/*
 * The expansion of bit-field data items is driven from a value descriptor and
 * the conv_expn_field() routine.
 */
typedef struct {
	Xword		v_val;		/* expansion value */
	const char	*v_msg;		/* associated message string */
} Val_desc;

/*
 * conv_expn_field() is willing to supply default strings for the
 * prefix, separator, and suffix arguments, if they are passed as NULL.
 * The caller needs to know how much room to allow for these items.
 * These values supply those sizes.
 */
#define	CONV_EXPN_FIELD_DEF_PREFIX_SIZE	2	/* Default is "[ " */
#define	CONV_EXPN_FIELD_DEF_SEP_SIZE	1	/* Default is " " */
#define	CONV_EXPN_FIELD_DEF_SUFFIX_SIZE	2	/* Default is " ]" */

/*
 * conv_expn_field() requires a large number of inputs, many of which
 * can be NULL to accept default behavior. An argument of the following
 * type is used to supply them.
 */
typedef struct {
	char *buf;		/* Buffer to receive generated string */
	size_t bufsize;		/* sizeof(buf) */
	const Val_desc *vdp;	/* Array of value descriptors, giving the */
				/*	possible bit values, and their */
				/*	corresponding strings. Note that the */
				/*	final element must contain only NULL */
				/*	values. This terminates the list. */
	const char **lead_str;	/* NULL, or array of pointers to strings to */
				/*	be output at the head of the list. */
				/*	Last entry must be NULL. */
	Xword oflags;		/* Bits for which output strings are desired */
	Xword rflags;		/* Bits for which a numeric value should be */
				/*	output if vdp does not provide str. */
				/*	Must be a proper subset of oflags */
	const char *prefix;	/* NULL, or string to prefix output with */
				/*	If NULL, "[ " is used. */
	const char *sep;	/* NULL, or string to separate output items */
				/*	with. If NULL, " " is used. */
	const char *suffix;	/* NULL, or string to suffix output with */
				/*	If NULL, " ]" is used. */
} CONV_EXPN_FIELD_ARG;


/*
 * Callback function for conv_str_to_c_literal(). A user supplied function
 * of this type is called by conv_str_to_c_literal() in order to dispatch
 * the translated output characters.
 *
 *	buf - Pointer to output text
 *	n - # of characters to output
 *	uvalue - User value argument to conv_str_to_c_literal(),
 *		passed through without interpretation.
 */
typedef	void		Conv_str_to_c_literal_func_t(const void *ptr,
			    size_t size, void *uvalue);

/*
 * Define all generic interfaces.
 */
extern	uchar_t		conv_check_native(char **, char **);
extern	const char	*conv_config_feat(int, Conv_config_feat_buf_t *);
extern	const char	*conv_config_obj(ushort_t, Conv_config_obj_buf_t *);
extern	const char	*conv_config_upm(const char *, const char *,
			    const char *, size_t);
extern	const char	*conv_cnote_auxv_af(Word, Conv_fmt_flags_t,
			    Conv_cnote_auxv_af_buf_t *);
extern	const char	*conv_cnote_auxv_type(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_cc_content(Lword, Conv_fmt_flags_t,
			    Conv_cnote_cc_content_buf_t *);
extern	const char	*conv_cnote_errno(int, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_fault(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_fltset(uint32_t *, int,
			    Conv_fmt_flags_t, Conv_cnote_fltset_buf_t *);
extern	const char	*conv_cnote_old_pr_flags(int, Conv_fmt_flags_t,
			    Conv_cnote_old_pr_flags_buf_t *);
extern	const char	*conv_cnote_pr_dmodel(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_pr_flags(int, Conv_fmt_flags_t,
			    Conv_cnote_pr_flags_buf_t *);
extern	const char	*conv_cnote_proc_flag(int, Conv_fmt_flags_t,
			    Conv_cnote_proc_flag_buf_t *);
extern	const char	*conv_cnote_pr_regname(Half, int, Conv_fmt_flags_t,
			    Conv_inv_buf_t *inv_buf);
extern	const char	*conv_cnote_pr_stype(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_pr_what(short, short, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_pr_why(short, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_priv(int, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_psetid(int, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_sa_flags(int, Conv_fmt_flags_t,
			    Conv_cnote_sa_flags_buf_t *);
extern	const char	*conv_cnote_signal(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_si_code(Half, int, int, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_sigset(uint32_t *, int,
			    Conv_fmt_flags_t, Conv_cnote_sigset_buf_t *);
extern	const char	*conv_cnote_ss_flags(int, Conv_fmt_flags_t,
			    Conv_cnote_ss_flags_buf_t *);
extern	const char	*conv_cnote_syscall(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cnote_sysset(uint32_t *, int,
			    Conv_fmt_flags_t, Conv_cnote_sysset_buf_t *);
extern	const char	*conv_cnote_type(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_def_tag(Symref, Conv_inv_buf_t *);
extern	const char	*conv_demangle_name(const char *);
extern	const char	*conv_dl_flag(int, Conv_fmt_flags_t,
			    Conv_dl_flag_buf_t *);
extern	const char	*conv_dl_mode(int, int, Conv_dl_mode_buf_t *);
extern	const char	*conv_dwarf_ehe(uint_t, Conv_dwarf_ehe_buf_t *);
extern	const char	*conv_elfdata_type(Elf_Type, Conv_inv_buf_t *);
extern	const char	*conv_grphdl_flags(uint_t, Conv_grphdl_flags_buf_t *);
extern	const char	*conv_grpdesc_flags(uint_t, Conv_grpdesc_flags_buf_t *);
extern	Isa_desc	*conv_isalist(void);
extern	const char	*conv_lddstub(int);
extern	const char	*conv_seg_flags(Half, Conv_seg_flags_buf_t *);
extern	int		conv_sys_eclass();
extern	void		conv_str_to_c_literal(const char *buf, size_t n,
			    Conv_str_to_c_literal_func_t *cb_func,
			    void *uvalue);
extern	Uts_desc	*conv_uts(void);
extern	const char	*conv_ver_flags(Half, Conv_fmt_flags_t,
			    Conv_ver_flags_buf_t *);
extern	const char	*conv_ver_index(Versym, int, Conv_inv_buf_t *);


/*
 * Define all class specific routines.
 */
#if	defined(_ELF64)
#define	conv_bnd_obj		conv64_bnd_obj
#define	conv_bnd_type		conv64_bnd_type
#define	conv_cap_tag		conv64_cap_tag
#define	conv_cap_val		conv64_cap_val
#define	conv_cap_val_hw1	conv64_cap_val_hw1
#define	conv_cap_val_sf1	conv64_cap_val_sf1
#define	conv_dyn_feature1	conv64_dyn_feature1
#define	conv_dyn_flag1		conv64_dyn_flag1
#define	conv_dyn_flag		conv64_dyn_flag
#define	conv_dyn_posflag1	conv64_dyn_posflag1
#define	conv_dyn_tag		conv64_dyn_tag
#define	conv_ehdr_class		conv64_ehdr_class
#define	conv_ehdr_data		conv64_ehdr_data
#define	conv_ehdr_flags		conv64_ehdr_flags
#define	conv_ehdr_mach		conv64_ehdr_mach
#define	conv_ehdr_osabi		conv64_ehdr_osabi
#define	conv_ehdr_type		conv64_ehdr_type
#define	conv_ehdr_vers		conv64_ehdr_vers
#define	conv_expn_field		conv64_expn_field
#define	conv_invalid_val	conv64_invalid_val
#define	conv_phdr_flags		conv64_phdr_flags
#define	conv_phdr_type		conv64_phdr_type
#define	conv_reject_desc	conv64_reject_desc
#define	conv_reloc_type		conv64_reloc_type
#define	conv_reloc_type_static	conv64_reloc_type_static
#define	conv_reloc_386_type	conv64_reloc_386_type
#define	conv_reloc_amd64_type	conv64_reloc_amd64_type
#define	conv_reloc_SPARC_type	conv64_reloc_SPARC_type
#define	conv_sec_flags		conv64_sec_flags
#define	conv_sec_linkinfo	conv64_sec_linkinfo
#define	conv_sec_type		conv64_sec_type
#define	conv_sym_info_bind	conv64_sym_info_bind
#define	conv_sym_info_type	conv64_sym_info_type
#define	conv_sym_shndx		conv64_sym_shndx
#define	conv_sym_other		conv64_sym_other
#define	conv_sym_other_vis	conv64_sym_other_vis
#define	conv_sym_value		conv64_sym_value
#define	conv_sym_SPARC_value	conv64_sym_SPARC_value
#define	conv_syminfo_flags	conv64_syminfo_flags
#else
#define	conv_bnd_obj		conv32_bnd_obj
#define	conv_bnd_type		conv32_bnd_type
#define	conv_cap_tag		conv32_cap_tag
#define	conv_cap_val		conv32_cap_val
#define	conv_cap_val_hw1	conv32_cap_val_hw1
#define	conv_cap_val_sf1	conv32_cap_val_sf1
#define	conv_dyn_feature1	conv32_dyn_feature1
#define	conv_dyn_flag1		conv32_dyn_flag1
#define	conv_dyn_flag		conv32_dyn_flag
#define	conv_dyn_posflag1	conv32_dyn_posflag1
#define	conv_dyn_tag		conv32_dyn_tag
#define	conv_ehdr_class		conv32_ehdr_class
#define	conv_ehdr_data		conv32_ehdr_data
#define	conv_ehdr_flags		conv32_ehdr_flags
#define	conv_ehdr_mach		conv32_ehdr_mach
#define	conv_ehdr_osabi		conv32_ehdr_osabi
#define	conv_ehdr_type		conv32_ehdr_type
#define	conv_ehdr_vers		conv32_ehdr_vers
#define	conv_expn_field		conv32_expn_field
#define	conv_invalid_val	conv32_invalid_val
#define	conv_phdr_flags		conv32_phdr_flags
#define	conv_phdr_type		conv32_phdr_type
#define	conv_reject_desc	conv32_reject_desc
#define	conv_reloc_type		conv32_reloc_type
#define	conv_reloc_type_static	conv32_reloc_type_static
#define	conv_reloc_386_type	conv32_reloc_386_type
#define	conv_reloc_amd64_type	conv32_reloc_amd64_type
#define	conv_reloc_SPARC_type	conv32_reloc_SPARC_type
#define	conv_sec_flags		conv32_sec_flags
#define	conv_sec_linkinfo	conv32_sec_linkinfo
#define	conv_sec_type		conv32_sec_type
#define	conv_sym_info_bind	conv32_sym_info_bind
#define	conv_sym_info_type	conv32_sym_info_type
#define	conv_sym_shndx		conv32_sym_shndx
#define	conv_sym_other		conv32_sym_other
#define	conv_sym_other_vis	conv32_sym_other_vis
#define	conv_sym_value		conv32_sym_value
#define	conv_sym_SPARC_value	conv32_sym_SPARC_value
#define	conv_syminfo_flags	conv32_syminfo_flags
#endif

extern	const char	*conv_bnd_obj(uint_t, Conv_bnd_obj_buf_t *);
extern	const char	*conv_bnd_type(uint_t, Conv_bnd_type_buf_t *);
extern	const char	*conv_cap_tag(Xword, Conv_inv_buf_t *);
extern	const char	*conv_cap_val(Xword, Xword, Half, Conv_cap_val_buf_t *);
extern	const char	*conv_cap_val_hw1(Xword, Half, Conv_fmt_flags_t,
			    Conv_cap_val_hw1_buf_t *);
extern	const char	*conv_cap_val_sf1(Xword, Half, Conv_fmt_flags_t,
			    Conv_cap_val_sf1_buf_t *);
extern	const char	*conv_dyn_flag1(Xword, Conv_fmt_flags_t,
			    Conv_dyn_flag1_buf_t *);
extern	const char	*conv_dyn_flag(Xword, Conv_fmt_flags_t,
			    Conv_dyn_flag_buf_t *);
extern	const char	*conv_dyn_posflag1(Xword, Conv_fmt_flags_t,
			    Conv_dyn_posflag1_buf_t *);
extern	const char	*conv_dyn_tag(Xword, Half, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_dyn_feature1(Xword, Conv_fmt_flags_t,
			    Conv_dyn_feature1_buf_t *);
extern	const char	*conv_ehdr_class(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_ehdr_data(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_ehdr_flags(Half, Word, Conv_fmt_flags_t,
			    Conv_ehdr_flags_buf_t *);
extern	const char	*conv_ehdr_mach(Half, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_ehdr_osabi(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_ehdr_type(Half, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_ehdr_vers(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	int		conv_expn_field(CONV_EXPN_FIELD_ARG *,
			    Conv_fmt_flags_t);
extern	const char	*conv_invalid_val(Conv_inv_buf_t *, Xword,
			    Conv_fmt_flags_t);
extern	const char	*conv_phdr_flags(Word, Conv_fmt_flags_t fmt_flags,
			    Conv_phdr_flags_buf_t *);
extern	const char	*conv_phdr_type(Half, Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_reject_desc(Rej_desc *, Conv_reject_desc_buf_t *,
			    Half mach);
extern	const char	*conv_reloc_type(Half, Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_reloc_type_static(Half, Word, Conv_fmt_flags_t);
extern	const char	*conv_reloc_386_type(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_reloc_amd64_type(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_reloc_SPARC_type(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sec_flags(Xword, Conv_fmt_flags_t,
			    Conv_sec_flags_buf_t *);
extern	const char	*conv_sec_linkinfo(Word, Xword, Conv_inv_buf_t *);
extern	const char	*conv_sec_type(Half, Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sym_info_bind(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sym_info_type(Half, uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sym_shndx(Half, Conv_inv_buf_t *);
extern	const char	*conv_sym_other(uchar_t, Conv_inv_buf_t *);
extern	const char	*conv_sym_other_vis(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sym_value(Half, uchar_t, Addr, Conv_inv_buf_t *);
extern	const char	*conv_sym_SPARC_value(Addr, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_syminfo_flags(Xword, Conv_fmt_flags_t,
			    Conv_syminfo_flags_buf_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _CONV_H */
