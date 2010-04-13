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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_RELOC_DOT_H
#define	_RELOC_DOT_H

#if defined(_KERNEL)
#include <sys/bootconf.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#else
#include <rtld.h>
#include <conv.h>
#endif /* _KERNEL */

#include "reloc_defs.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Global include file for relocation common code.
 */

/*
 * In user land, redefine the relocation table and relocation engine to be
 * class/machine specific if necessary.  This allows multiple engines to
 * reside within a single instance of libld.
 */
#if	!defined(_KERNEL)

#if defined(DO_RELOC_LIBLD)
#undef DO_RELOC_LIBLD
#endif

#if	defined(DO_RELOC_LIBLD_X86)

#define	DO_RELOC_LIBLD
#if	defined(_ELF64)
#define	do_reloc_ld		do64_reloc_ld_x86
#define	reloc_table		reloc64_table_x86
#else
#define	do_reloc_ld		do32_reloc_ld_x86
#define	reloc_table		reloc32_table_x86
#endif

#elif	defined(DO_RELOC_LIBLD_SPARC)

#define	DO_RELOC_LIBLD
#if	defined(_ELF64)
#define	do_reloc_ld		do64_reloc_ld_sparc
#define	reloc_table		reloc64_table_sparc
#else
#define	do_reloc_ld		do32_reloc_ld_sparc
#define	reloc_table		reloc32_table_sparc
#endif

#else				/* rtld */

#if	defined(_ELF64)
#define	do_reloc_rtld		do64_reloc_rtld
#define	reloc_table		reloc64_table
#else
#define	do_reloc_rtld		do32_reloc_rtld
#define	reloc_table		reloc32_table
#endif

#endif

#endif	/* !_KERNEL */

/*
 * Relocation table and macros for testing relocation table flags.
 */
extern	const Rel_entry	reloc_table[];

#define	IS_PLT(X)		RELTAB_IS_PLT(X, reloc_table)
#define	IS_GOT_RELATIVE(X)	RELTAB_IS_GOT_RELATIVE(X, reloc_table)
#define	IS_GOT_PC(X)		RELTAB_IS_GOT_PC(X, reloc_table)
#define	IS_GOTPCREL(X)		RELTAB_IS_GOTPCREL(X, reloc_table)
#define	IS_GOT_BASED(X)		RELTAB_IS_GOT_BASED(X, reloc_table)
#define	IS_GOT_OPINS(X)		RELTAB_IS_GOT_OPINS(X, reloc_table)
#define	IS_GOT_REQUIRED(X)	RELTAB_IS_GOT_REQUIRED(X, reloc_table)
#define	IS_PC_RELATIVE(X)	RELTAB_IS_PC_RELATIVE(X, reloc_table)
#define	IS_ADD_RELATIVE(X)	RELTAB_IS_ADD_RELATIVE(X, reloc_table)
#define	IS_REGISTER(X)		RELTAB_IS_REGISTER(X, reloc_table)
#define	IS_NOTSUP(X)		RELTAB_IS_NOTSUP(X, reloc_table)
#define	IS_SEG_RELATIVE(X)	RELTAB_IS_SEG_RELATIVE(X, reloc_table)
#define	IS_EXTOFFSET(X)		RELTAB_IS_EXTOFFSET(X, reloc_table)
#define	IS_SEC_RELATIVE(X)	RELTAB_IS_SEC_RELATIVE(X, reloc_table)
#define	IS_TLS_INS(X)		RELTAB_IS_TLS_INS(X, reloc_table)
#define	IS_TLS_GD(X)		RELTAB_IS_TLS_GD(X, reloc_table)
#define	IS_TLS_LD(X)		RELTAB_IS_TLS_LD(X, reloc_table)
#define	IS_TLS_IE(X)		RELTAB_IS_TLS_IE(X, reloc_table)
#define	IS_TLS_LE(X)		RELTAB_IS_TLS_LE(X, reloc_table)
#define	IS_LOCALBND(X)		RELTAB_IS_LOCALBND(X, reloc_table)
#define	IS_SIZE(X)		RELTAB_IS_SIZE(X, reloc_table)

/*
 * Relocation engine.
 *
 * The do_reloc() code is used in three different places: The kernel,
 * the link-editor, and the runtime linker. All three convey the same
 * basic information with the first 5 arguments:
 *
 * 1)	Relocation type. The kernel and runtime linker pass this as
 *	an integer value, while the link-editor passes it as a Rel_desc
 *	descriptor. The relocation engine only looks at the rel_rtype
 *	field of this descriptor, and does not examine the other fields,
 *	which are explicitly allowed to contain garbage.
 * 2)	Address of offset
 * 3)	Address of value
 * 4)	Name of symbol associated with the relocation, used if it is
 *	necessary to report an error. The kernel and runtime linker pass
 *	directly as a string pointer. The link-editor passes the address
 *	of a rel_desc_sname_func_t function, which can be called by do_reloc(),
 *	passing it the Rel_desc pointer (argument 1, above), to obtain the
 *	string pointer.
 * 5)	String giving the source file for the relocation.
 *
 * In addition:
 *	- The linker and rtld want a link map pointer argument
 *	- The linker wants to pass a byte swap argument that tells
 *		the relocation engine that the data it is relocating
 *		has the opposite byte order of the system running the
 *		linker.
 *	- The linker is a cross-linker, meaning that it can examine
 *		relocation records for target hosts other than that of
 *		the currently running system. This means that multiple
 *		versions of the relocation code must be able to reside
 *		in a single program, without namespace clashes.
 *
 * To ensure that there is never any confusion about which version is
 * being linked to, we give each variant a different name, even though
 * each one is generated from the same source code.
 *
 *	do_reloc_krtld()
 *	The kernel version is provided if the _KERNEL macro is defined.
 *
 *	do_reloc_ld()
 *	The ld version is provided if the DO_RELOC_LIBLD_ macro is defined.
 *
 *	do_reloc_rtld()
 *	The rtld version is provided if neither _KERNEL or DO_RELOC_LIBLD
 *	are defined.
 *
 * Implementations of do_reloc() should use these same macros to
 * conditionalize any code not used by all three versions.
 */
#if defined(_KERNEL)
extern	int	do_reloc_krtld(uchar_t, uchar_t *, Xword *, const char *,
		    const char *);
#elif defined(DO_RELOC_LIBLD)
extern	int	do_reloc_ld(Rel_desc *, uchar_t *, Xword *,
		    rel_desc_sname_func_t, const char *, int, void *);
#else
extern	int	do_reloc_rtld(uchar_t, uchar_t *, Xword *, const char *,
		    const char *, void *);
#endif

#if defined(_KERNEL)
/*
 * These are macro's that are only needed for krtld.  Many of these are already
 * defined in the sgs/include files referenced by ld and rtld
 */
#define	S_MASK(n)	((1l << (n)) - 1l)
#define	S_INRANGE(v, n)	(((-(1l << (n)) - 1l) < (v)) && ((v) < (1l << (n))))

/*
 * Message strings used by doreloc().
 */
#define	MSG_STR_UNKNOWN		"(unknown)"

#define	MSG_REL_PREGEN		"relocation error: %s: "
#define	MSG_REL_PREFIL		"relocation error: file %s: "
#define	MSG_REL_FILE		"file %s: "
#define	MSG_REL_SYM		"symbol %s: "
#define	MSG_REL_VALUE		"value 0x%llx "
#define	MSG_REL_LOSEBITS	"loses %d bits at "

#define	MSG_REL_UNIMPL		"unimplemented relocation type: %d"
#define	MSG_REL_UNSUPSZ		"offset size (%d bytes) is not supported"
#define	MSG_REL_NONALIGN	"offset 0x%llx is non-aligned"
#define	MSG_REL_UNNOBITS	"unsupported number of bits: %d"
#define	MSG_REL_OFFSET		"offset 0x%llx"
#define	MSG_REL_NOFIT		"value 0x%llx does not fit"

/*
 * Provide a macro to select the appropriate conversion routine for this
 * architecture.
 */
#if defined(__amd64)

extern const char	*conv_reloc_amd64_type(Word);
#define	CONV_RELOC_TYPE	conv_reloc_amd64_type

#elif defined(__i386)

extern const char	*conv_reloc_386_type(Word);
#define	CONV_RELOC_TYPE	conv_reloc_386_type

#elif defined(__sparc)

extern const char	*conv_reloc_SPARC_type(Word);
#define	CONV_RELOC_TYPE	conv_reloc_SPARC_type

#else
#error platform not defined!
#endif


/*
 * Note:  dlerror() only keeps track of a single error string, and therefore
 * must have errors reported through a single eprintf() call.  The kernel's
 * _kobj_printf is somewhat more limited, and must receive messages with only
 * one argument to the format string.  The following macros account for these
 * differences, as krtld and rtld share the same do_reloc() source.
 */
#define	REL_ERR_UNIMPL(lml, file, sym, rtype) \
	_kobj_printf(ops, MSG_REL_PREFIL, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_UNIMPL, (int)(rtype))

#define	REL_ERR_UNSUPSZ(lml, file, sym, rtype, size) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_UNSUPSZ, (int)(size))

#define	REL_ERR_NONALIGN(lml, file, sym, rtype, off) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_NONALIGN, EC_OFF((off)))

#define	REL_ERR_UNNOBITS(lml, file, sym, rtype, nbits) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_UNNOBITS, (nbits))

#define	REL_ERR_LOSEBITS(lml, file, sym, rtype, uvalue, nbits, off) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_VALUE, EC_XWORD((uvalue))); \
	_kobj_printf(ops, MSG_REL_LOSEBITS, (int)(nbits)); \
	_kobj_printf(ops, MSG_REL_OFFSET, EC_NATPTR((off)))

#define	REL_ERR_NOFIT(lml, file, sym, rtype, uvalue) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_NOFIT, EC_XWORD((uvalue)))


#else	/* !_KERNEL */

extern	const char *demangle(const char *);

#define	REL_ERR_UNIMPL(lml, file, sym, rtype) \
	(eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_UNIMPL), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), (int)(rtype)))

#define	REL_ERR_UNSUPSZ(lml, file, sym, rtype, size) \
	(eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_UNSUPSZ), \
	    conv_reloc_type_static(M_MACH, (rtype), 0), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), (int)(size)))

#define	REL_ERR_NONALIGN(lml, file, sym, rtype, off) \
	(eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_NONALIGN), \
	    conv_reloc_type_static(M_MACH, (rtype), 0), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), EC_OFF((off))))

#define	REL_ERR_UNNOBITS(lml, file, sym, rtype, nbits) \
	(eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_UNNOBITS), \
	    conv_reloc_type_static(M_MACH, (rtype), 0), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), (nbits)))

#define	REL_ERR_LOSEBITS(lml, file, sym, rtype, uvalue, nbits, off) \
	(eprintf(lml, ERR_FATAL,  MSG_INTL(MSG_REL_LOSEBITS), \
	    conv_reloc_type_static(M_MACH, (rtype), 0), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), \
	    EC_XWORD((uvalue)), (nbits), EC_NATPTR((off))))

#define	REL_ERR_NOFIT(lml, file, sym, rtype, uvalue) \
	(eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_NOFIT), \
	    conv_reloc_type_static(M_MACH, (rtype), 0), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), \
	    EC_XWORD((uvalue))))

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _RELOC_DOT_H */
