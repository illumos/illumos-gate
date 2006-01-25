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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RELOC_DOT_H
#define	_RELOC_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(_KERNEL)
#include <sys/machelf.h>
#include <sys/bootconf.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#else
#include <machdep.h>
#include <conv.h>
#endif /* _KERNEL */

#include <relmach.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Global include file for relocation common code.
 *
 * Flags for reloc_entry->re_flags
 */
#define	FLG_RE_NOTREL		0x00000000
#define	FLG_RE_GOTADD		0x00000001	/* create a GOT entry */
#define	FLG_RE_GOTREL		0x00000002	/* GOT based */
#define	FLG_RE_GOTPC		0x00000004	/* GOT - P */
#define	FLG_RE_GOTOPINS		0x00000008	/* GOTOP instruction */
#define	FLG_RE_PCREL		0x00000010
#define	FLG_RE_PLTREL		0x00000020
#define	FLG_RE_VERIFY		0x00000040	/* verify value fits */
#define	FLG_RE_UNALIGN		0x00000080	/* offset is not aligned */
#define	FLG_RE_WDISP16		0x00000100	/* funky sparc DISP16 rel */
#define	FLG_RE_SIGN		0x00000200	/* value is signed */
#define	FLG_RE_ADDRELATIVE	0x00000400	/* RELATIVE relocation */
						/* required for non-fixed */
						/* objects */
#define	FLG_RE_EXTOFFSET	0x00000800	/* extra offset required */
#define	FLG_RE_REGISTER		0x00001000	/* relocation initializes */
						/*    a REGISTER by OLO10 */
#define	FLG_RE_NOTSUP		0x00010000	/* relocation not supported */

#define	FLG_RE_SEGREL		0x00040000	/* segment relative */
#define	FLG_RE_SECREL		0x00080000	/* section relative */
#define	FLG_RE_TLSINS		0x00100000	/* TLS instructino rel */
#define	FLG_RE_TLSGD		0x00200000	/* TLS GD relocation */
#define	FLG_RE_TLSLD		0x00400000	/* TLS LD relocation */
#define	FLG_RE_TLSIE		0x00800000	/* TLS IE relocation */
#define	FLG_RE_TLSLE		0x01000000	/* TLS LE relocation */
#define	FLG_RE_LOCLBND		0x02000000	/* relocation must bind */
						/*    locally */

/*
 * Macros for testing relocation table flags
 */
extern	const Rel_entry		reloc_table[];

#define	IS_PLT(X)		((reloc_table[(X)].re_flags & \
					FLG_RE_PLTREL) != 0)
#define	IS_GOT_RELATIVE(X)	((reloc_table[(X)].re_flags & \
					FLG_RE_GOTADD) != 0)
#define	IS_GOT_PC(X)		((reloc_table[(X)].re_flags & \
					FLG_RE_GOTPC) != 0)
#define	IS_GOTPCREL(X)		((reloc_table[(X)].re_flags & \
					(FLG_RE_GOTPC | FLG_RE_GOTADD)) == \
					(FLG_RE_GOTPC | FLG_RE_GOTADD))
#define	IS_GOT_BASED(X)		((reloc_table[(X)].re_flags & \
					FLG_RE_GOTREL) != 0)
#define	IS_GOT_INS(X)		((reloc_table[(X)].re_flags & \
					FLG_RE_GOTOPINS) != 0)
#define	IS_GOT_REQUIRED(X)	((reloc_table[(X)].re_flags & \
					(FLG_RE_GOTADD | FLG_RE_GOTREL | \
					FLG_RE_GOTPC | FLG_RE_GOTOPINS)) != 0)
#define	IS_PC_RELATIVE(X)	((reloc_table[(X)].re_flags & \
					FLG_RE_PCREL) != 0)
#define	IS_ADD_RELATIVE(X)	((reloc_table[(X)].re_flags & \
					FLG_RE_ADDRELATIVE) != 0)
#define	IS_REGISTER(X)		((reloc_table[(X)].re_flags & \
					FLG_RE_REGISTER) != 0)
#define	IS_FORMOFF(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_FRMOFF) != 0)
#define	IS_NOTSUP(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_NOTSUP) != 0)
#define	IS_SEG_RELATIVE(X)	((reloc_table[(X)].re_flags &\
					FLG_RE_SEGREL) != 0)
#define	IS_EXTOFFSET(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_EXTOFFSET) != 0)
#define	IS_SEC_RELATIVE(X)	((reloc_table[(X)].re_flags &\
					FLG_RE_SECREL) != 0)
#define	IS_TLS_INS(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_TLSINS) != 0)
#define	IS_TLS_GD(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_TLSGD) != 0)
#define	IS_TLS_LD(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_TLSLD) != 0)
#define	IS_TLS_IE(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_TLSIE) != 0)
#define	IS_TLS_LE(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_TLSLE) != 0)
#define	IS_TLS(X)		((reloc_table[(X)].re_flags &\
					(FLG_RE_TLSINS|FLG_RE_TLSGD| \
					FLG_RE_TLSLD|FLG_RE_TLSIE| \
					FLG_RE_TLSLE)) != 0)
#define	IS_LOCALBND(X)		((reloc_table[(X)].re_flags &\
					FLG_RE_LOCLBND) != 0)

/*
 * Functions.
 */
extern	int	do_reloc(uchar_t, uchar_t *, Xword *, const char *,
		    const char *);

/*
 * Provide a macro to select the appropriate convension routine for this
 * architecture.
 */
#if defined(__amd64)
#define	CONV_RELOC_TYPE		conv_reloc_amd64_type_str
#elif defined(__i386)
#define	CONV_RELOC_TYPE		conv_reloc_386_type_str
#elif defined(__sparc)
#define	CONV_RELOC_TYPE		conv_reloc_SPARC_type_str
#else
#error platform not defined!
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

extern const char	 *conv_reloc_386_type_str(uint_t);
extern const char	 *conv_reloc_amd64_type_str(uint_t);
extern const char	 *conv_reloc_SPARC_type_str(uint_t);

/*
 * Note:  Related to bug 4128755, dlerror() only keeps track of a single error
 * string, and therefore must have errors reported through a single eprintf()
 * call.  The kernel's _kobj_printf is somewhat more limited, and must receive
 * messages with only one arguement to the format string.  The following macros
 * are to straighted all this out because krtld and rtld share do_reloc().
 */
#define	REL_ERR_UNIMPL(file, sym, rtype) \
	_kobj_printf(ops, MSG_REL_PREFIL, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_UNIMPL, (int)(rtype))

#define	REL_ERR_UNSUPSZ(file, sym, rtype, size) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_UNSUPSZ, (int)(size))

#define	REL_ERR_NONALIGN(file, sym, rtype, off) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_NONALIGN, EC_OFF((off)))

#define	REL_ERR_UNNOBITS(file, sym, rtype, nbits) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_UNNOBITS, (nbits))

#define	REL_ERR_LOSEBITS(file, sym, rtype, uvalue, nbits, off) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_VALUE, EC_XWORD((uvalue))); \
	_kobj_printf(ops, MSG_REL_LOSEBITS, (int)(nbits)); \
	_kobj_printf(ops, MSG_REL_OFFSET, EC_ADDR((off)))

#define	REL_ERR_NOFIT(file, sym, rtype, uvalue) \
	_kobj_printf(ops, MSG_REL_PREGEN, CONV_RELOC_TYPE((rtype))); \
	_kobj_printf(ops, MSG_REL_FILE, (file)); \
	_kobj_printf(ops, MSG_REL_SYM, ((sym) ? (sym) : MSG_STR_UNKNOWN)); \
	_kobj_printf(ops, MSG_REL_NOFIT, EC_XWORD((uvalue)))


#else	/* !_KERNEL */

extern	const char *demangle(const char *);

#define	REL_ERR_UNIMPL(file, sym, rtype) \
	(eprintf(ERR_FATAL, MSG_INTL(MSG_REL_UNIMPL), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), (int)(rtype)))

#define	REL_ERR_UNSUPSZ(file, sym, rtype, size) \
	(eprintf(ERR_FATAL, MSG_INTL(MSG_REL_UNSUPSZ), \
	    CONV_RELOC_TYPE((rtype)), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), (int)(size)))

#define	REL_ERR_NONALIGN(file, sym, rtype, off) \
	(eprintf(ERR_FATAL, MSG_INTL(MSG_REL_NONALIGN), \
	    CONV_RELOC_TYPE((rtype)), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), EC_OFF((off))))

#define	REL_ERR_UNNOBITS(file, sym, rtype, nbits) \
	(eprintf(ERR_FATAL, MSG_INTL(MSG_REL_UNNOBITS), \
	    CONV_RELOC_TYPE((rtype)), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), (nbits)))

#define	REL_ERR_LOSEBITS(file, sym, rtype, uvalue, nbits, off) \
	(eprintf(ERR_FATAL,  MSG_INTL(MSG_REL_LOSEBITS), \
	    CONV_RELOC_TYPE((rtype)), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), \
	    EC_XWORD((uvalue)), (nbits), EC_ADDR((off))))

#define	REL_ERR_NOFIT(file, sym, rtype, uvalue) \
	(eprintf(ERR_FATAL, MSG_INTL(MSG_REL_NOFIT), \
	    CONV_RELOC_TYPE((rtype)), (file), \
	    ((sym) ? demangle(sym) : MSG_INTL(MSG_STR_UNKNOWN)), \
	    EC_XWORD((uvalue))))

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _RELOC_DOT_H */
