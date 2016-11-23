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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 * Copyright 2016 RackTop Systems.
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
#include <sgsmsg.h>

#ifndef	NATIVE_BUILD
#include <sys/secflags.h>
#endif

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
 * Valid flags for conv_strproc_extract_value().
 */
#define	CONV_SPEXV_F_NOTRIM	0x0001	/* Do not trim whitespace around '=' */
#define	CONV_SPEXV_F_UCASE	0x0002	/* Convert value to uppercase */
#define	CONV_SPEXV_F_NULLOK	0x0004	 /* Empty ("") value is OK */

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
 *
 * The 32-bit version of this requires 12 characters, and the 64-bit version
 * needs 22. By using the larger value for both, we can have a single
 * definition, which is necessary for code that is ELFCLASS independent. A
 * nice side benefit is that it lets us dispense with a large number of 32/64
 * buffer size definitions that build off CONV_INV_BUFSIZE, and the macros
 * that would then be needed.
 */
#define	CONV_INV_BUFSIZE		22
typedef union {
	char				buf[CONV_INV_BUFSIZE];
} Conv_inv_buf_t;

/* conv_ehdr_flags() */
#define	CONV_EHDR_FLAGS_BUFSIZE		91
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_EHDR_FLAGS_BUFSIZE];
} Conv_ehdr_flags_buf_t;

/* conv_reject_desc() */
typedef union {
	Conv_inv_buf_t			inv_buf;
	Conv_ehdr_flags_buf_t		flags_buf;
} Conv_reject_desc_buf_t;

/*
 * conv_la_bind()
 */
#define	CONV_LA_BIND_BUFSIZE		56
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_LA_BIND_BUFSIZE];
} Conv_la_bind_buf_t;

/*
 * conv_la_search()
 */
#define	CONV_LA_SEARCH_BUFSIZE		111
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_LA_SEARCH_BUFSIZE];
} Conv_la_search_buf_t;

/*
 * conv_la_symbind()
 */
#define	CONV_LA_SYMBIND_BUFSIZE		113
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_LA_SYMBIND_BUFSIZE];
} Conv_la_symbind_buf_t;

/*
 * conv_cap_val_hw/sf()
 *
 * These sizes are based on the maximum number of capabilities that exist.
 * See common/elfcap.
 */
#define	CONV_CAP_VAL_HW1_BUFSIZE	195
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CAP_VAL_HW1_BUFSIZE];
} Conv_cap_val_hw1_buf_t;

#define	CONV_CAP_VAL_HW2_BUFSIZE	CONV_INV_BUFSIZE	/* for now */
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CAP_VAL_HW2_BUFSIZE];
} Conv_cap_val_hw2_buf_t;

#define	CONV_CAP_VAL_SF1_BUFSIZE	45
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CAP_VAL_SF1_BUFSIZE];
} Conv_cap_val_sf1_buf_t;

/* conv_cap_val_buf() */
typedef union {
	Conv_inv_buf_t			inv_buf;
	Conv_cap_val_hw1_buf_t		cap_val_hw1_buf;
	Conv_cap_val_sf1_buf_t		cap_val_sf1_buf;
	Conv_cap_val_hw2_buf_t		cap_val_hw2_buf;
} Conv_cap_val_buf_t;

/* conv_config_feat() */
#define	CONV_CONFIG_FEAT_BUFSIZE	204
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CONFIG_FEAT_BUFSIZE];
} Conv_config_feat_buf_t;

/* conv_config_obj() */
#define	CONV_CONFIG_OBJ_BUFSIZE		164
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CONFIG_OBJ_BUFSIZE];
} Conv_config_obj_buf_t;

/* conv_dl_mode() */
#define	CONV_DL_MODE_BUFSIZE		132
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_DL_MODE_BUFSIZE];
} Conv_dl_mode_buf_t;

/* conv_dl_flag() */
#define	CONV_DL_FLAG_BUFSIZE		185
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_DL_FLAG_BUFSIZE];
} Conv_dl_flag_buf_t;

/* conv_grphdl_flags() */
#define	CONV_GRPHDL_FLAGS_BUFSIZE	78
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_GRPHDL_FLAGS_BUFSIZE];
} Conv_grphdl_flags_buf_t;

/* conv_grpdesc_flags() */
#define	CONV_GRPDESC_FLAGS_BUFSIZE	91
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_GRPDESC_FLAGS_BUFSIZE];
} Conv_grpdesc_flags_buf_t;

/* conv_seg_flags() */
#define	CONV_SEG_FLAGS_BUFSIZE		241
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_SEG_FLAGS_BUFSIZE];
} Conv_seg_flags_buf_t;

/* conv_dyn_posflag1() */
#define	CONV_DYN_POSFLAG1_BUFSIZE	72
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_DYN_POSFLAG1_BUFSIZE];
} Conv_dyn_posflag1_buf_t;

/* conv_dyn_flag() */
#define	CONV_DYN_FLAG_BUFSIZE		85
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_DYN_FLAG_BUFSIZE];
} Conv_dyn_flag_buf_t;

/* conv_dyn_flag1() */
#define	CONV_DYN_FLAG1_BUFSIZE		361
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_DYN_FLAG1_BUFSIZE];
} Conv_dyn_flag1_buf_t;

/* conv_dyn_feature1() */
#define	CONV_DYN_FEATURE1_BUFSIZE	54
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_DYN_FEATURE1_BUFSIZE];
} Conv_dyn_feature1_buf_t;

/* conv_bnd_type() */
#define	CONV_BND_TYPE_BUFSIZE		51
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_BND_TYPE_BUFSIZE];
} Conv_bnd_type_buf_t;

/* conv_bnd_obj() */
#define	CONV_BND_OBJ_BUFSIZE		60
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_BND_OBJ_BUFSIZE];
} Conv_bnd_obj_buf_t;

/* conv_phdr_flags() */
#define	CONV_PHDR_FLAGS_BUFSIZE		244
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_PHDR_FLAGS_BUFSIZE];
} Conv_phdr_flags_buf_t;

/* conv_sec_flags() */
#define	CONV_SEC_FLAGS_BUFSIZE		190
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_SEC_FLAGS_BUFSIZE];
} Conv_sec_flags_buf_t;

/* conv_dwarf_ehe() */
#define	CONV_DWARF_EHE_BUFSIZE		43
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_DWARF_EHE_BUFSIZE];
} Conv_dwarf_ehe_buf_t;

/* conv_syminfo_flags() */
#define	CONV_SYMINFO_FLAGS_BUFSIZE	230
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_SYMINFO_FLAGS_BUFSIZE];
} Conv_syminfo_flags_buf_t;

/* conv_cnote_pr_flags() */
#define	CONV_CNOTE_PR_FLAGS_BUFSIZE	254
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_PR_FLAGS_BUFSIZE];
} Conv_cnote_pr_flags_buf_t;

/* conv_cnote_old_pr_flags() */
#define	CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE	174
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE];
} Conv_cnote_old_pr_flags_buf_t;

/* conv_cnote_proc_flag() */
#define	CONV_CNOTE_PROC_FLAG_BUFSIZE	39
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_PROC_FLAG_BUFSIZE];
} Conv_cnote_proc_flag_buf_t;

#ifndef	NATIVE_BUILD
/* conv_prsecflags() */
#define	CONV_PRSECFLAGS_BUFSIZE		57
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_PRSECFLAGS_BUFSIZE];
} Conv_secflags_buf_t;
#endif

/* conv_cnote_sigset() */
#define	CONV_CNOTE_SIGSET_BUFSIZE	639
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_SIGSET_BUFSIZE];
} Conv_cnote_sigset_buf_t;

/* conv_cnote_fltset() */
#define	CONV_CNOTE_FLTSET_BUFSIZE	511
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_FLTSET_BUFSIZE];
} Conv_cnote_fltset_buf_t;

/* conv_cnote_sysset() */
#define	CONV_CNOTE_SYSSET_BUFSIZE	3195
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_SYSSET_BUFSIZE];
} Conv_cnote_sysset_buf_t;

/* conv_cnote_sa_flags() */
#define	CONV_CNOTE_SA_FLAGS_BUFSIZE	109
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_SA_FLAGS_BUFSIZE];
} Conv_cnote_sa_flags_buf_t;

/* conv_cnote_ss_flags() */
#define	CONV_CNOTE_SS_FLAGS_BUFSIZE	48
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_SS_FLAGS_BUFSIZE];
} Conv_cnote_ss_flags_buf_t;

/* conv_cnote_cc_content() */
#define	CONV_CNOTE_CC_CONTENT_BUFSIZE	97
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_CC_CONTENT_BUFSIZE];
} Conv_cnote_cc_content_buf_t;

/* conv_cnote_auxv_af() */
#define	CONV_CNOTE_AUXV_AF_BUFSIZE	73
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_CNOTE_AUXV_AF_BUFSIZE];
} Conv_cnote_auxv_af_buf_t;

/* conv_ver_flags() */
#define	CONV_VER_FLAGS_BUFSIZE		41
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_VER_FLAGS_BUFSIZE];
} Conv_ver_flags_buf_t;

/* conv_ent_flags() */
#define	CONV_ENT_FLAGS_BUFSIZE		69
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_ENT_FLAGS_BUFSIZE];
} Conv_ent_flags_buf_t;

/* conv_ent_files_flags() */
#define	CONV_ENT_FILES_FLAGS_BUFSIZE	89
typedef union {
	Conv_inv_buf_t			inv_buf;
	char				buf[CONV_ENT_FILES_FLAGS_BUFSIZE];
} Conv_ent_files_flags_buf_t;

/*
 * conv_time()
 *
 * This size is based on the maximum "hour.min.sec.fraction: " time that
 * would be expected of ld().
 */
#define	CONV_TIME_BUFSIZE		18
typedef union {
	char				buf[CONV_TIME_BUFSIZE];
} Conv_time_buf_t;

/*
 * Many conversion routines accept a fmt_flags argument of this type
 * to allow the caller to modify the output. There are two parts to
 * this value:
 *
 *	(1) Format requests (decimal vs hex, etc...)
 *	(2) The low order bits specified by CONV_MASK_FMT_ALT
 *		and retrieved by CONV_TYPE_FMT_ALT are integer
 *		values that specify that an alternate set of
 *		strings should be used.
 *
 * The fmt_flags value is designed such that a caller can always
 * supply a 0 in order to receive default behavior.
 */
typedef int Conv_fmt_flags_t;

/*
 * Type used to represent ELF constants within libconv. This relies on
 * the fact that there are no ELF constants that need more than 32-bits,
 * nor are there any signed values.
 */
typedef uint32_t Conv_elfvalue_t;

/*
 * Most conversion routines are able to provide strings in one of
 * several alternative styles. The bottom 8 bits of Conv_fmt_flags_t
 * are used to specify which strings should be used for a given call
 * to a conversion routine:
 *
 *   DEFAULT
 *	The default string style used by a given conversion routine is
 *	an independent choice made by that routine. Different routines
 *	make different choices, based largely on historical usage and
 *	the perceived common case. It may be an alias for one of the
 *	specific styles listed below, or it may be unique.
 *
 *   DUMP
 *	Style of strings used by dump(1).
 *
 *   FILE
 *	Style of strings used by file(1).
 *
 *   CRLE
 *	Style of strings used by crle(1).
 *
 *   CF
 *	Canonical Form: The string is exactly the same as the name
 *	of the #define macro that defines it in the public header files.
 *	(e.g. STB_LOCAL, not LOCL, LOCAL, LOC, or any other variation).
 *
 *   CFNP
 *	No Prefix Canonical Form: The same strings supplied by CF,
 *	but without their standard prefix. (e.g. LOCAL, instead of STT_LOCAL).
 *
 *   NF
 *	Natural Form: The form of the strings that might typically be entered
 *	via a keyboard by an interactive user. These are usually the strings
 *	from CFNP, converted to lowercase, although in some cases they may
 *	take some other "natural" form. In command completion applications,
 *	lowercase strings appear less formal, and are easier on the eye.
 *
 * Every routine is required to have a default style. The others are optional,
 * and may not be provided if not needed. If a given conversion routine does
 * not support alternative strings for a given CONV_FMT_ALT type, it silently
 * ignores the request and supplies the default set. This means that a utility
 * like dump(1) is free to specify a style like DUMP to every conversion
 * routine. It will receive its special strings if there are any, and
 * the defaults otherwise.
 */
#define	CONV_MASK_FMT_ALT		0xff
#define	CONV_TYPE_FMT_ALT(fmt_flags)	(fmt_flags & CONV_MASK_FMT_ALT)

#define	CONV_FMT_ALT_DEFAULT	0	/* "Standard" strings */
#define	CONV_FMT_ALT_DUMP	1	/* dump(1) */
#define	CONV_FMT_ALT_FILE	2	/* file(1) */
#define	CONV_FMT_ALT_CRLE	3	/* crle(1) */
#define	CONV_FMT_ALT_CF		4	/* Canonical Form */
#define	CONV_FMT_ALT_CFNP	5	/* No Prefix Canonical Form */
#define	CONV_FMT_ALT_NF		6	/* Natural Form */

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
 * A Val_desc structure is used to associate an ELF constant and
 * the message code (Msg) for the string that corresponds to it.
 *
 * Val_desc2 adds v_osabi and v_mach fields to Val_desc, which allows
 * for non-generic mappings that apply only to a specific OSABI/machine.
 * Setting v_osabi to 0 (ELFOSABI_NONE) specifies that any OSABI matches.
 * Similarly, setting v_mach to 0 (EM_MACH) matches any machine. Hence,
 * setting v_osabi and v_mach to 0 in a Val_desc2 results in a generic item,
 * and is equivalent to simply using a Val_desc.
 *
 * These structs are used in two different contexts:
 *
 * 1)	To expand bit-field data items, using conv_expn_field() to
 *	process a NULL terminated array of Val_desc, or conv_expn_field2()
 *	to process a null terminated array of Val_desc2.
 *
 * 2)	To represent sparse ranges of non-bitfield values, referenced via
 *	conv_ds_vd_t or conv_ds_vd2_t descriptors, as described below.
 */
typedef struct {
	Conv_elfvalue_t	v_val;		/* expansion value */
	Msg		v_msg;		/* associated message string code */
} Val_desc;
typedef struct {
	Conv_elfvalue_t	v_val;		/* expansion value */
	uchar_t		v_osabi;	/* OSABI to which entry applies */
	Half		v_mach;		/* Machine to which entry applies */
	Msg		v_msg;		/* associated message string code */
} Val_desc2;

/*
 * The conv_ds_XXX_t structs are used to pull together the information used
 * to map non-bitfield values to strings. They are a variant family, sharing
 * the same initial fields, with a generic "header" definition that can be
 * used to read those common fields and determine which subcase is being
 * seen. We do this instead of using a single struct containing a type code
 * and a union in order to allow for static compile-time initialization.
 *
 * conv_ds_t is the base type, containing the initial fields common to all
 * the variants. Variables of type conv_ds_t are never instantiated. This
 * type exists only to provide a common pointer type that can reference
 * any of the variants safely. In C++, it would be a virtual base class.
 * The fields common to all the variants are:
 *
 *	ds_type: Identifies the variant
 *	ds_baseval/ds_topval: The lower and upper bound of the range
 *		of values represented by this conv_ds_XXX_t descriptor.
 *
 * There are three different variants:
 *    conv_ds_msg_t (ds_type == CONV_DS_MSGARR)
 *	This structure references an array of message codes corresponding
 *	to consecutive ELF values. The first item in the array is the Msg
 *	code for the value given by ds_baseval. Consecutive strings follow
 *	in consecutive order. The final item corresponds to the value given
 *	by ds_topval. Zero (0) Msg values can be used to represent missing
 *	values. Entries with a 0 are quietly ignored.
 *
 *    conv_ds_vd_t (ds_type == CONV_DS_VD)
 *	This structure employs a NULL terminated array of Val_desc structs.
 *	Each Val_desc supplies a mapping from a value in the range
 *	(ds_baseval <= value <= ds_topval). The values described need not
 *	be consecutive, and can be sparse. ds_baseval does not need to
 *	correspond to the first item, and ds_topval need not correspond to
 *	the final item.
 *
 *    conv_ds_vd2_t (ds_type == CONV_DS_VD2)
 *	This structure employs a NULL terminated array of Val_desc2 structs,
 *	rather than Val_desc, adding the ability to specify OSABI and machine
 *	as part of the value/string mapping. It is otherwise the same thing
 *	as CONV_DS_VD.
 */
typedef enum {
	CONV_DS_MSGARR = 0,		/* Array of Msg */
	CONV_DS_VD = 1,			/* Null terminated array of Val_desc */
	CONV_DS_VD2 = 2,		/* Null terminated array of Val_desc2 */
} conv_ds_type_t;

#define	CONV_DS_COMMON_FIELDS \
	conv_ds_type_t	ds_type;   	/* Type of data structure used */ \
	uint32_t	ds_baseval;	/* Value of first item */	\
	uint32_t	ds_topval	/* Value of last item */

typedef struct {		/* Virtual base type --- do not instantiate */
	CONV_DS_COMMON_FIELDS;
} conv_ds_t;
typedef struct {
	CONV_DS_COMMON_FIELDS;
	const Msg		*ds_msg;
} conv_ds_msg_t;
typedef struct {
	CONV_DS_COMMON_FIELDS;
	const Val_desc		*ds_vd;
} conv_ds_vd_t;
typedef struct {
	CONV_DS_COMMON_FIELDS;
	const Val_desc2		*ds_vd2;
} conv_ds_vd2_t;

/*
 * The initialization of conv_ds_msg_t can be completely derived from
 * its base value and the array of Msg codes. CONV_DS_MSG_INIT() is used
 * to do that.
 */
#define	CONV_DS_MSG_INIT(_baseval, _arr) \
	CONV_DS_MSGARR, _baseval, \
	_baseval + (sizeof (_arr) / sizeof (_arr[0])) - 1, _arr

/*
 * Null terminated arrays of pointers to conv_ds_XXX_t structs are processed
 * by conv_map_ds() to convert ELF constants to their symbolic names, and by
 * conv_iter_ds() to iterate over all the available value/name combinations.
 *
 * These pointers are formed by casting the address of the specific
 * variant types (described above) to generic base type pointer.
 * CONV_DS_ADDR() is a convenience macro to take the address of
 * one of these variants and turn it into a generic pointer.
 */
#define	CONV_DS_ADDR(_item) ((conv_ds_t *)&(_item))

/*
 * Type used by libconv to represent osabi values passed to iteration
 * functions. The type in the ELF header is uchar_t. However, every possible
 * value 0-255 has a valid meaning, leaving us no extra value to assign
 * to mean "ALL". Using Half for osabi leaves us the top byte to use for
 * out of bound values.
 *
 * Non-iteration functions, and any code that does not need to use
 * CONV_OSABI_ALL, should use uchar_t for osabi.
 */
typedef Half conv_iter_osabi_t;

/*
 * Many of the iteration functions accept an osabi or mach argument,
 * used to specify the type of object being processed. The following
 * values can be used to specify a wildcard that matches any item. Their
 * values are carefully chosen to ensure that they cannot be interpreted
 * as an otherwise valid osabi or machine.
 */
#define	CONV_OSABI_ALL	1024	/* Larger than can be represented by uchar_t */
#define	CONV_MACH_ALL	EM_NUM	/* Never a valid machine type */

/*
 * We compare Val_Desc2 descriptors with a specified osabi and machine
 * to determine whether to use it or not. This macro encapsulates that logic.
 *
 * We consider an osabi to match when any of the following things hold:
 *
 * -	The descriptor osabi is ELFOSABI_NONE.
 * -	The supplied osabi and the descriptor osabi match
 * -	The supplied osabi is ELFOSABI_NONE, and the descriptor osabi is
 *	ELFOSABI_SOLARIS. Many operating systems, Solaris included,
 *	produce or have produced ELFOSABI_NONE native objects, if only
 *	because OSABI ranges are not an original ELF feature. We
 *	give our own objects the home field advantage.
 * -	Iteration Only: An osabi value of CONV_OSABI_ALL is specified.
 *
 * We consider a machine to match when any of the following things hold:
 *
 * -	The descriptor mach is EM_NONE.
 * -	The supplied mach and the descriptor mach match
 * -	Iteration Only: A mach value of CONV_MACH_ALL is specified.
 *
 * The special extra _ALL case for iteration is handled by defining a separate
 * macro with the extra CONV_xxx_ALL tests.
 */
#define	CONV_VD2_SKIP_OSABI(_osabi, _vdp) \
	((_vdp->v_osabi != ELFOSABI_NONE) && (_vdp->v_osabi != osabi) && \
	((_osabi != ELFOSABI_NONE) || (_vdp->v_osabi != ELFOSABI_SOLARIS)))

#define	CONV_VD2_SKIP_MACH(_mach, _vdp) \
	((_vdp->v_mach != EM_NONE) && (_vdp->v_mach != _mach))

#define	CONV_VD2_SKIP(_osabi, _mach, _vdp) \
	(CONV_VD2_SKIP_OSABI(_osabi, _vdp) || CONV_VD2_SKIP_MACH(_mach, _vdp))

#define	CONV_ITER_VD2_SKIP(_osabi, _mach, _vdp)			      \
	((CONV_VD2_SKIP_OSABI(_osabi, _vdp) && (_osabi != CONV_OSABI_ALL)) || \
	(CONV_VD2_SKIP_MACH(_mach, _vdp) && (_mach != CONV_MACH_ALL)))


/*
 * Possible return values from iteration functions.
 */
typedef enum {
	CONV_ITER_DONE,		/* Stop: No more iterations are desired */
	CONV_ITER_CONT		/* Continue with following iterations */
} conv_iter_ret_t;

/*
 * Prototype for caller supplied callback function to iteration functions.
 */
typedef conv_iter_ret_t (* conv_iter_cb_t)(const char *str,
    Conv_elfvalue_t value, void *uvalue);

/*
 * User value block employed by conv_iter_strtol()
 */
typedef struct {
	const char	*csl_str;	/* String to search for */
	size_t		csl_strlen;	/* # chars in csl_str to examine */
	int		csl_found;	/* Init to 0, set to 1 if item found */
	Conv_elfvalue_t	csl_value;	/* If csl_found, resulting value */
} conv_strtol_uvalue_t;

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
 * Generic miscellaneous interfaces
 */
extern	uchar_t		conv_check_native(char **, char **);
extern	const char	*conv_lddstub(int);
extern	int		conv_strproc_isspace(int);
extern	char		*conv_strproc_trim(char *);
extern	Boolean		conv_strproc_extract_value(char *, size_t, int,
			    const char **);
extern	int		conv_sys_eclass(void);
extern	int		conv_translate_c_esc(char **);

/*
 * Generic core formatting and iteration functionality
 */
extern	conv_iter_ret_t	_conv_iter_ds(conv_iter_osabi_t, Half,
			    const conv_ds_t **, conv_iter_cb_t, void *,
			    const char *);
extern	conv_iter_ret_t	_conv_iter_ds_msg(const conv_ds_msg_t *,
			    conv_iter_cb_t, void *, const char *);
extern	conv_iter_ret_t	_conv_iter_vd(const Val_desc *, conv_iter_cb_t,
			    void *, const char *);
extern	conv_iter_ret_t	_conv_iter_vd2(conv_iter_osabi_t, Half,
			    const Val_desc2 *, conv_iter_cb_t, void *,
			    const char *);
extern	int		conv_iter_strtol_init(const char *,
			    conv_strtol_uvalue_t *);
extern	conv_iter_ret_t	conv_iter_strtol(const char *, Conv_elfvalue_t, void *);
extern	const char	*_conv_map_ds(uchar_t, Half, Conv_elfvalue_t,
			    const conv_ds_t **, Conv_fmt_flags_t,
			    Conv_inv_buf_t *, const char *);


/*
 * Generic formatting interfaces.
 */
extern	const char	*conv_bnd_obj(uint_t, Conv_bnd_obj_buf_t *);
extern	const char	*conv_bnd_type(uint_t, Conv_bnd_type_buf_t *);
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
#ifndef	NATIVE_BUILD
extern	const char	*conv_prsecflags(secflagset_t, Conv_fmt_flags_t,
			    Conv_secflags_buf_t *);
#endif
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
extern	const char	*conv_cnote_fileflags(uint32_t, Conv_fmt_flags_t,
			    char *, size_t);
extern	const char	*conv_cnote_filemode(uint32_t, Conv_fmt_flags_t,
			    char *, size_t);
extern	const char	*conv_cnote_type(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_def_tag(Symref, Conv_inv_buf_t *);
extern	const char	*conv_demangle_name(const char *);
extern	const char	*conv_dl_flag(int, Conv_fmt_flags_t,
			    Conv_dl_flag_buf_t *);
extern	const char	*conv_dl_info(int);
extern	const char	*conv_dl_mode(int, int, Conv_dl_mode_buf_t *);
extern	const char	*conv_dwarf_cfa(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_dwarf_ehe(uint_t, Conv_dwarf_ehe_buf_t *);
extern	const char	*conv_dwarf_regname(Half, Word, Conv_fmt_flags_t,
			    int *, Conv_inv_buf_t *);
extern	const char	*conv_ehdr_abivers(uchar_t, Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
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
extern	const char	*conv_ehdr_type(uchar_t, Half, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_ehdr_vers(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_elfdata_type(Elf_Type, Conv_inv_buf_t *);
extern	const char	*conv_ent_flags(ec_flags_t, Conv_ent_flags_buf_t *);
extern	const char	*conv_ent_files_flags(Word,  Conv_fmt_flags_t fmt_flags,
			    Conv_ent_files_flags_buf_t *);
extern	const char	*conv_la_activity(uint_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_la_bind(uint_t, Conv_la_bind_buf_t *);
extern	const char	*conv_la_search(uint_t, Conv_la_search_buf_t *);
extern	const char	*conv_la_symbind(uint_t, Conv_la_symbind_buf_t *);
extern	const char	*conv_grphdl_flags(uint_t, Conv_grphdl_flags_buf_t *);
extern	const char	*conv_grpdesc_flags(uint_t, Conv_grpdesc_flags_buf_t *);
extern	Isa_desc	*conv_isalist(void);
extern	const char	*conv_mapfile_version(Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_phdr_flags(uchar_t, Word, Conv_fmt_flags_t,
			    Conv_phdr_flags_buf_t *);
extern	const char	*conv_phdr_type(uchar_t, Half, Word, Conv_fmt_flags_t,
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
extern	const char	*conv_sec_type(uchar_t, Half, Word, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_seg_flags(sg_flags_t, Conv_seg_flags_buf_t *);
extern	void		conv_str_to_c_literal(const char *buf, size_t n,
			    Conv_str_to_c_literal_func_t *cb_func,
			    void *uvalue);
extern	const char	*conv_sym_info_bind(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sym_info_type(Half, uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sym_shndx(uchar_t, Half, Half, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_sym_other(uchar_t, Conv_inv_buf_t *);
extern	const char	*conv_sym_other_vis(uchar_t, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_syminfo_boundto(Half, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_syminfo_flags(Half, Conv_fmt_flags_t,
			    Conv_syminfo_flags_buf_t *);
extern	const char	*conv_time(struct timeval *, struct timeval *,
			    Conv_time_buf_t *);
extern	Uts_desc	*conv_uts(void);
extern	const char	*conv_ver_flags(Half, Conv_fmt_flags_t,
			    Conv_ver_flags_buf_t *);
extern	const char	*conv_ver_index(Versym, int, Conv_inv_buf_t *);


/*
 * Generic iteration interfaces.
 */
extern	conv_iter_ret_t	conv_iter_cap_tags(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_cap_val_hw1(Half, Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_cap_val_hw2(Half, Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_cap_val_sf1(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);

extern	conv_iter_ret_t	conv_iter_dyn_feature1(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_dyn_flag(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_dyn_flag1(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_dyn_posflag1(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_dyn_tag(conv_iter_osabi_t, Half,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);

extern	conv_iter_ret_t	conv_iter_ehdr_abivers(conv_iter_osabi_t,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_ehdr_class(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_ehdr_data(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_ehdr_eident(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_ehdr_flags(Half, Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_ehdr_mach(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_ehdr_osabi(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);
extern	conv_iter_ret_t	conv_iter_ehdr_type(conv_iter_osabi_t, Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_ehdr_vers(Conv_fmt_flags_t, conv_iter_cb_t,
			    void *);

extern	conv_iter_ret_t	conv_iter_phdr_flags(conv_iter_osabi_t,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_phdr_type(conv_iter_osabi_t, Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);

extern	conv_iter_ret_t	conv_iter_sec_flags(conv_iter_osabi_t, Half,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_sec_symtab(conv_iter_osabi_t,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_sec_type(conv_iter_osabi_t, Half,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);

extern	conv_iter_ret_t	conv_iter_sym_info_bind(Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_sym_other_vis(Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_sym_shndx(conv_iter_osabi_t, Half,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_sym_info_type(Half, Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);

extern	conv_iter_ret_t	conv_iter_syminfo_boundto(Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);
extern	conv_iter_ret_t	conv_iter_syminfo_flags(Conv_fmt_flags_t,
			    conv_iter_cb_t, void *);

/*
 * Define all class specific routines.
 */
#if	defined(_ELF64)
#define	conv_cap_tag		conv64_cap_tag
#define	conv_cap_val		conv64_cap_val
#define	conv_cap_val_hw1	conv64_cap_val_hw1
#define	conv_cap_val_hw2	conv64_cap_val_hw2
#define	conv_cap_val_sf1	conv64_cap_val_sf1
#define	conv_dyn_feature1	conv64_dyn_feature1
#define	conv_dyn_flag1		conv64_dyn_flag1
#define	conv_dyn_flag		conv64_dyn_flag
#define	conv_dyn_posflag1	conv64_dyn_posflag1
#define	conv_dyn_tag		conv64_dyn_tag
#define	_conv_expn_field	_conv64_expn_field
#define	_conv_expn_field2	_conv64_expn_field2
#define	conv_invalid_val	conv64_invalid_val
#define	conv_sec_flags		conv64_sec_flags
#define	conv_sec_linkinfo	conv64_sec_linkinfo
#define	conv_sym_value		conv64_sym_value
#define	conv_sym_SPARC_value	conv64_sym_SPARC_value
#else
#define	conv_cap_tag		conv32_cap_tag
#define	conv_cap_val		conv32_cap_val
#define	conv_cap_val_hw1	conv32_cap_val_hw1
#define	conv_cap_val_hw2	conv32_cap_val_hw2
#define	conv_cap_val_sf1	conv32_cap_val_sf1
#define	conv_dyn_feature1	conv32_dyn_feature1
#define	conv_dyn_flag1		conv32_dyn_flag1
#define	conv_dyn_flag		conv32_dyn_flag
#define	conv_dyn_posflag1	conv32_dyn_posflag1
#define	conv_dyn_tag		conv32_dyn_tag
#define	_conv_expn_field	_conv32_expn_field
#define	_conv_expn_field2	_conv32_expn_field2
#define	conv_invalid_val	conv32_invalid_val
#define	conv_sec_flags		conv32_sec_flags
#define	conv_sec_linkinfo	conv32_sec_linkinfo
#define	conv_sym_value		conv32_sym_value
#define	conv_sym_SPARC_value	conv32_sym_SPARC_value
#endif

/*
 * ELFCLASS-specific core formatting functionality
 */
extern	int		_conv_expn_field(CONV_EXPN_FIELD_ARG *,
			    const Val_desc *, Conv_fmt_flags_t, const char *);
extern	int		_conv_expn_field2(CONV_EXPN_FIELD_ARG *, uchar_t,
			    Half, const Val_desc2 *, Conv_fmt_flags_t,
			    const char *);
extern	const char	*conv_invalid_val(Conv_inv_buf_t *, Xword,
			    Conv_fmt_flags_t);

/*
 * ELFCLASS-specific formatting interfaces.
 */
extern	const char	*conv_cap_tag(Xword, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_cap_val(Xword, Xword, Half, Conv_fmt_flags_t,
			    Conv_cap_val_buf_t *);
extern	const char	*conv_cap_val_hw1(Xword, Half, Conv_fmt_flags_t,
			    Conv_cap_val_hw1_buf_t *);
extern	const char	*conv_cap_val_hw2(Xword, Half, Conv_fmt_flags_t,
			    Conv_cap_val_hw2_buf_t *);
extern	const char	*conv_cap_val_sf1(Xword, Half, Conv_fmt_flags_t,
			    Conv_cap_val_sf1_buf_t *);
extern	const char	*conv_dyn_flag1(Xword, Conv_fmt_flags_t,
			    Conv_dyn_flag1_buf_t *);
extern	const char	*conv_dyn_flag(Xword, Conv_fmt_flags_t,
			    Conv_dyn_flag_buf_t *);
extern	const char	*conv_dyn_posflag1(Xword, Conv_fmt_flags_t,
			    Conv_dyn_posflag1_buf_t *);
extern	const char	*conv_dyn_tag(Xword, uchar_t, Half, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);
extern	const char	*conv_dyn_feature1(Xword, Conv_fmt_flags_t,
			    Conv_dyn_feature1_buf_t *);
extern	const char	*conv_sec_flags(uchar_t osabi, Half mach, Xword,
			    Conv_fmt_flags_t, Conv_sec_flags_buf_t *);
extern	const char	*conv_sec_linkinfo(Word, Xword, Conv_inv_buf_t *);
extern	const char	*conv_sym_value(Half, uchar_t, Addr, Conv_inv_buf_t *);
extern	const char	*conv_sym_SPARC_value(Addr, Conv_fmt_flags_t,
			    Conv_inv_buf_t *);

/*
 * Define macros for _conv_XXX() routines that accept local_sgs_msg as the
 * final argument. The macros hide that argument from the caller's view and
 * supply the SGS message array for the file from which the macro is used
 * in its place. This trick is used to allow these functions to access the
 * message strings from any source file they are called from.
 */
#define	conv_expn_field(_arg, _vdp, _fmt_flags) \
    _conv_expn_field(_arg, _vdp, _fmt_flags, MSG_SGS_LOCAL_ARRAY)

#define	conv_expn_field2(_arg, _osabi, _mach, _vdp, _fmt_flags) \
    _conv_expn_field2(_arg, _osabi, _mach, _vdp, _fmt_flags, \
    MSG_SGS_LOCAL_ARRAY)

#define	conv_iter_ds(_osabi, _mach, _dsp, _func, _uvalue) \
    _conv_iter_ds(_osabi, _mach, _dsp, _func, _uvalue, MSG_SGS_LOCAL_ARRAY)

#define	conv_iter_vd(_vdp, _func, _uvalue)	\
    _conv_iter_vd(_vdp, _func, _uvalue, MSG_SGS_LOCAL_ARRAY)

#define	conv_iter_vd2(_osabi, _mach, _vdp, _func, _uvalue)		\
    _conv_iter_vd2(_osabi, _mach, _vdp, _func, _uvalue, MSG_SGS_LOCAL_ARRAY)

#define	conv_map_ds(_osabi, _mach, _value, _dsp, _fmt_flags, _inv_buf) \
    _conv_map_ds(_osabi, _mach, _value, _dsp, _fmt_flags, _inv_buf, \
    MSG_SGS_LOCAL_ARRAY)


#ifdef	__cplusplus
}
#endif

#endif /* _CONV_H */
