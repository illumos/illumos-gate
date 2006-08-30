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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CONV_H
#define	_CONV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global include file for conversion library.
 */

#include <stdlib.h>
#include <libelf.h>
#include <dlfcn.h>
#include <libld.h>
#include <sgs.h>
#include <machdep.h>

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
 * Various values that can't be matched to a symbolic definition are converted
 * to a numeric string.  Each function that may require this fallback maintains
 * its own static string buffer, as many conversion routines may be called for
 * one final diagnostic.  See conv_invalid_val().
 *
 * The string size reflects the largest possible decimal number plus a trailing
 * null.  Typically however, values are hex with a leading "0x".
 */
#if	defined(_ELF64)
#define	CONV_INV_STRSIZE	22
#else
#define	CONV_INV_STRSIZE	12
#endif

/*
 * Flags that alter standard formatting for conversion routines.
 */
#define	CONV_FMT_DECIMAL	0x01	/* conv_invalid_val() should print */
					/*    integer print as decimal */
					/*    (default is hex) */
#define	CONV_FMT_SPACE		0x02	/* conv_invalid_val() should append */
					/*    a space after the number.  */
#define	CONV_FMT_ALTDUMP	0x04	/* Output strings using the versions */
					/*    used by the dump program. */
#define	CONV_FMT_ALTFILE	0x08	/* Output strings in the form used */
					/*    by the file(1) command */
#define	CONV_FMT_ALTCRLE	0x10	/* Output strings in the form used */
					/*    by the crle(1) command */

/*
 * Mask of CONV_FMT bits that reflect a desire to use alternate strings.
 */
#define	CONV_FMTALTMASK (CONV_FMT_ALTDUMP|CONV_FMT_ALTFILE)

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
 * Define all generic interfaces.
 */
extern	uchar_t		conv_check_native(char **, char **);
extern	const char	*conv_config_feat(int);
extern	const char	*conv_config_obj(ushort_t);
extern	const char	*conv_config_upm(const char *, const char *,
			    const char *, size_t);
extern	const char	*conv_def_tag(Symref);
extern	const char	*conv_demangle_name(const char *);
extern	const char	*conv_dl_flag(int, int);
extern	const char	*conv_dl_mode(int, int);
extern	const char	*conv_dwarf_ehe(uint_t);
extern	const char	*conv_elfdata_type(Elf_Type);
extern	const char	*conv_grphdl_flags(uint_t);
extern	Isa_desc	*conv_isalist(void);
extern	const char	*conv_lddstub(int);
extern	const char	*conv_seg_flags(Half);
extern	int		conv_sys_eclass();
extern	Uts_desc	*conv_uts(void);
extern	const char	*conv_ver_flags(Half);

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
#define	conv_ehdr_type		conv64_ehdr_type
#define	conv_ehdr_vers		conv64_ehdr_vers
#define	conv_expn_field		conv64_expn_field
#define	conv_invalid_val	conv64_invalid_val
#define	conv_phdr_flags		conv64_phdr_flags
#define	conv_phdr_type		conv64_phdr_type
#define	conv_reject_desc	conv64_reject_desc
#define	conv_reloc_type		conv64_reloc_type
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
#define	conv_sym_value		conv64_sym_value
#define	conv_sym_SPARC_value	conv64_sym_SPARC_value
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
#define	conv_ehdr_type		conv32_ehdr_type
#define	conv_ehdr_vers		conv32_ehdr_vers
#define	conv_expn_field		conv32_expn_field
#define	conv_invalid_val	conv32_invalid_val
#define	conv_phdr_flags		conv32_phdr_flags
#define	conv_phdr_type		conv32_phdr_type
#define	conv_reject_desc	conv32_reject_desc
#define	conv_reloc_type		conv32_reloc_type
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
#define	conv_sym_value		conv32_sym_value
#define	conv_sym_SPARC_value	conv32_sym_SPARC_value
#endif

extern	const char	*conv_bnd_obj(uint_t);
extern	const char	*conv_bnd_type(uint_t);
extern	const char	*conv_cap_tag(Xword);
extern	const char	*conv_cap_val(Xword, Xword, Half);
extern	const char	*conv_cap_val_hw1(Xword, Half);
extern	const char	*conv_cap_val_sf1(Xword, Half);
extern	const char	*conv_dyn_flag1(Xword);
extern	const char	*conv_dyn_flag(Xword, int);
extern	const char	*conv_dyn_posflag1(Xword, int);
extern	const char	*conv_dyn_tag(Xword, Half, int);
extern	const char	*conv_dyn_feature1(Xword, int);
extern	const char	*conv_ehdr_class(uchar_t, int);
extern	const char	*conv_ehdr_data(uchar_t, int);
extern	const char	*conv_ehdr_flags(Half, Word);
extern	const char	*conv_ehdr_mach(Half, int);
extern	const char	*conv_ehdr_type(Half, int);
extern	const char	*conv_ehdr_vers(Word, int);
extern	int		conv_expn_field(CONV_EXPN_FIELD_ARG *);
extern	const char	*conv_invalid_val(char *, size_t, Xword, int);
extern	const char	*conv_phdr_flags(Word);
extern	const char	*conv_phdr_type(Half, Word);
extern	const char	*conv_reject_desc(Rej_desc *);
extern	const char	*conv_reloc_type(Half, Word, int);
extern	const char	*conv_reloc_386_type(Word, int);
extern	const char	*conv_reloc_amd64_type(Word, int);
extern	const char	*conv_reloc_SPARC_type(Word, int);
extern	const char	*conv_sec_flags(Xword);
extern	const char	*conv_sec_linkinfo(Word, Xword);
extern	const char	*conv_sec_type(Half, Word, int);
extern	const char	*conv_sym_info_bind(uchar_t, int);
extern	const char	*conv_sym_info_type(Half, uchar_t, int);
extern	const char	*conv_sym_shndx(Half);
extern	const char	*conv_sym_other(uchar_t);
extern	const char	*conv_sym_value(Half, uchar_t, Addr);
extern	const char	*conv_sym_SPARC_value(Addr, int);

#ifdef	__cplusplus
}
#endif

#endif /* _CONV_H */
