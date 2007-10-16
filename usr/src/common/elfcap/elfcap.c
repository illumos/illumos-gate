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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * String conversion routine for hardware capabilities types.
 */
#include	<strings.h>
#include	<stdio.h>
#include	<ctype.h>
#include	<limits.h>
#include	<sys/machelf.h>
#include	<sys/elf.h>
#include	<sys/auxv_SPARC.h>
#include	<sys/auxv_386.h>
#include	<elfcap.h>

/*
 * Define separators for val2str processing.
 */
static const Fmt_desc format[] = {
	{" ",	1 },
	{"  ",	2 },
	{" | ",	3 }
};

/*
 * Define all known capabilities as both lower and upper case strings.  This
 * duplication is necessary, rather than have one string and use something
 * like toupper(), as a client such as ld.so.1 doesn't need the overhead of
 * dragging in the internationalization support of toupper().  The Intel 3DNow
 * flags are a slightly odd convention too.
 *
 * Define all known software capabilities.
 */
#ifdef	CAP_UPPERCASE
static const char Sf1_fpknwn[] =	"FPKNWN";
static const char Sf1_fpused[] =	"FPUSED";
#elif	CAP_LOWERCASE
static const char Sf1_fpknwn[] =	"fpknwn";
static const char Sf1_fpused[] =	"fpused";
#else
#error	"Software Capabilities - what case do you want?"
#endif

/*
 * Order the software capabilities to match their numeric value.  See SF1_SUNW_
 * values in sys/elf.h.
 */
static const Cap_desc sf1[] = {
	{ SF1_SUNW_FPKNWN,	Sf1_fpknwn,	(sizeof (Sf1_fpknwn) - 1) },
	{ SF1_SUNW_FPUSED,	Sf1_fpused,	(sizeof (Sf1_fpused) - 1) }
};
static const uint_t sf1_num = sizeof (sf1) / sizeof (Cap_desc);

/*
 * Define all known SPARC hardware capabilities.
 */
#ifdef	CAP_UPPERCASE
static const char Hw1_s_mul32[] =	"MUL32";
static const char Hw1_s_div32[] =	"DIV32";
static const char Hw1_s_fsmuld[] =	"FSMULD";
static const char Hw1_s_v8plus[] =	"V8PLUS";
static const char Hw1_s_popc[] =	"POPC";
static const char Hw1_s_vis[] =		"VIS";
static const char Hw1_s_vis2[] =	"VIS2";
static const char Hw1_s_asi_blk_init[] =	"ASI_BLK_INIT";
static const char Hw1_s_fmaf[] = 	"FMAF";
static const char Hw1_s_reserved1[] = 	"RESERVED1";
static const char Hw1_s_reserved2[] = 	"RESERVED2";
static const char Hw1_s_reserved3[] = 	"RESERVED3";
static const char Hw1_s_reserved4[] = 	"RESERVED4";
static const char Hw1_s_reserved5[] = 	"RESERVED5";
static const char Hw1_s_fjfmau[] = 	"FJFMAU";
static const char Hw1_s_ima[] = 	"IMA";
#elif	CAP_LOWERCASE
static const char Hw1_s_mul32[] =	"mul32";
static const char Hw1_s_div32[] =	"div32";
static const char Hw1_s_fsmuld[] =	"fsmuld";
static const char Hw1_s_v8plus[] =	"v8plus";
static const char Hw1_s_popc[] =	"popc";
static const char Hw1_s_vis[] =		"vis";
static const char Hw1_s_vis2[] =	"vis2";
static const char Hw1_s_asi_blk_init[] =	"asi_blk_init";
static const char Hw1_s_fmaf[] =	"fmaf";
static const char Hw1_s_reserved1[] = 	"reserved1";
static const char Hw1_s_reserved2[] = 	"reserved2";
static const char Hw1_s_reserved3[] = 	"reserved3";
static const char Hw1_s_reserved4[] = 	"reserved4";
static const char Hw1_s_reserved5[] = 	"reserved5";
static const char Hw1_s_fjfmau[] =	"fjfmau";
static const char Hw1_s_ima[] =		"ima";

#else
#error	"Hardware Capabilities (sparc) - what case do you want?"
#endif

/*
 * Order the SPARC hardware capabilities to match their numeric value.  See
 * AV_SPARC_ values in sys/auxv_SPARC.h.
 */
static const Cap_desc hw1_s[] = {
	{ AV_SPARC_MUL32,	Hw1_s_mul32,	sizeof (Hw1_s_mul32) - 1 },
	{ AV_SPARC_DIV32,	Hw1_s_div32,	sizeof (Hw1_s_div32) - 1 },
	{ AV_SPARC_FSMULD,	Hw1_s_fsmuld,	sizeof (Hw1_s_fsmuld) - 1 },
	{ AV_SPARC_V8PLUS,	Hw1_s_v8plus,	sizeof (Hw1_s_v8plus) - 1 },
	{ AV_SPARC_POPC,	Hw1_s_popc,	sizeof (Hw1_s_popc) - 1 },
	{ AV_SPARC_VIS,		Hw1_s_vis,	sizeof (Hw1_s_vis) - 1 },
	{ AV_SPARC_VIS2,	Hw1_s_vis2,	sizeof (Hw1_s_vis2) - 1 },
	{ AV_SPARC_ASI_BLK_INIT,	Hw1_s_asi_blk_init,
		sizeof (Hw1_s_asi_blk_init) - 1 },
	{ AV_SPARC_FMAF,	Hw1_s_fmaf,	sizeof (Hw1_s_fmaf) - 1 },
	{ 0,	Hw1_s_reserved1,	sizeof (Hw1_s_reserved1) - 1 },
	{ 0,	Hw1_s_reserved2,	sizeof (Hw1_s_reserved2) - 1 },
	{ 0,	Hw1_s_reserved3,	sizeof (Hw1_s_reserved3) - 1 },
	{ 0,	Hw1_s_reserved4,	sizeof (Hw1_s_reserved4) - 1 },
	{ 0,	Hw1_s_reserved5,	sizeof (Hw1_s_reserved5) - 1 },
	{ AV_SPARC_FJFMAU,	Hw1_s_fjfmau,	sizeof (Hw1_s_fjfmau) - 1 },
	{ AV_SPARC_IMA,		Hw1_s_ima,	sizeof (Hw1_s_ima) - 1 }
};
static const uint_t hw1_s_num = sizeof (hw1_s) / sizeof (Cap_desc);

/*
 * Define all known Intel hardware capabilities.
 */
#ifdef	CAP_UPPERCASE
static const char Hw1_i_fpu[] =		"FPU";
static const char Hw1_i_tsc[] =		"TSC";
static const char Hw1_i_cx8[] =		"CX8";
static const char Hw1_i_sep[] =		"SEP";
static const char Hw1_i_amd_sysc[] =	"AMD_SYSC";
static const char Hw1_i_cmov[] =	"CMOV";
static const char Hw1_i_mmx[] =		"MMX";
static const char Hw1_i_amd_mmx[] =	"AMD_MMX";
static const char Hw1_i_amd_3dnow[] =	"AMD_3DNow";
static const char Hw1_i_amd_3dnowx[] =	"AMD_3DNowx";
static const char Hw1_i_fxsr[] =	"FXSR";
static const char Hw1_i_sse[] =		"SSE";
static const char Hw1_i_sse2[] =	"SSE2";
static const char Hw1_i_pause[] =	"PAUSE";
static const char Hw1_i_sse3[] =	"SSE3";
static const char Hw1_i_mon[] =		"MON";
static const char Hw1_i_cx16[] =	"CX16";
static const char Hw1_i_ahf[] =		"AHF";
static const char Hw1_i_tscp[] =	"TSCP";
static const char Hw1_i_amd_sse4a[] =	"AMD_SSE4A";
static const char Hw1_i_popcnt[] =	"POPCNT";
static const char Hw1_i_amd_lzcnt[] =	"AMD_LZCNT";
static const char Hw1_i_ssse3[] =	"SSSE3";
static const char Hw1_i_sse4_1[] =	"SSE4.1";
static const char Hw1_i_sse4_2[] =	"SSE4.2";
#elif	CAP_LOWERCASE
static const char Hw1_i_fpu[] =		"fpu";
static const char Hw1_i_tsc[] =		"tsc";
static const char Hw1_i_cx8[] =		"cx8";
static const char Hw1_i_sep[] =		"sep";
static const char Hw1_i_amd_sysc[] =	"amd_sysc";
static const char Hw1_i_cmov[] =	"cmov";
static const char Hw1_i_mmx[] =		"mmx";
static const char Hw1_i_amd_mmx[] =	"amd_mmx";
static const char Hw1_i_amd_3dnow[] =	"amd_3dnow";
static const char Hw1_i_amd_3dnowx[] =	"amd_3dnowx";
static const char Hw1_i_fxsr[] =	"fxsr";
static const char Hw1_i_sse[] =		"sse";
static const char Hw1_i_sse2[] =	"sse2";
static const char Hw1_i_pause[] =	"pause";
static const char Hw1_i_sse3[] =	"sse3";
static const char Hw1_i_mon[] =		"mon";
static const char Hw1_i_cx16[] =	"cx16";
static const char Hw1_i_ahf[] =		"ahf";
static const char Hw1_i_tscp[] = 	"tscp";
static const char Hw1_i_amd_sse4a[] = 	"amd_sse4a";
static const char Hw1_i_popcnt[] = 	"popcnt";
static const char Hw1_i_amd_lzcnt[] = 	"amd_lzcnt";
static const char Hw1_i_ssse3[] =	"ssse3";
static const char Hw1_i_sse4_1[] =	"sse4.1";
static const char Hw1_i_sse4_2[] =	"sse4.2";
#else
#error	"Hardware Capabilities (intel) - what case do you want?"
#endif

/*
 * Order the Intel hardware capabilities to match their numeric value.  See
 * AV_386_ values in sys/auxv_386.h.
 */
static const Cap_desc hw1_i[] = {
	{ AV_386_FPU,		Hw1_i_fpu,	sizeof (Hw1_i_fpu) - 1 },
	{ AV_386_TSC,		Hw1_i_tsc,	sizeof (Hw1_i_tsc) - 1 },
	{ AV_386_CX8,		Hw1_i_cx8,	sizeof (Hw1_i_cx8) - 1 },
	{ AV_386_SEP,		Hw1_i_sep,	sizeof (Hw1_i_sep) - 1 },
	{ AV_386_AMD_SYSC,	Hw1_i_amd_sysc,	sizeof (Hw1_i_amd_sysc) - 1 },
	{ AV_386_CMOV,		Hw1_i_cmov,	sizeof (Hw1_i_cmov) - 1 },
	{ AV_386_MMX,		Hw1_i_mmx,	sizeof (Hw1_i_mmx) - 1 },
	{ AV_386_AMD_MMX,	Hw1_i_amd_mmx,	sizeof (Hw1_i_amd_mmx) - 1 },
	{ AV_386_AMD_3DNow,	Hw1_i_amd_3dnow,
						sizeof (Hw1_i_amd_3dnow) - 1 },
	{ AV_386_AMD_3DNowx,	Hw1_i_amd_3dnowx,
						sizeof (Hw1_i_amd_3dnowx) - 1 },
	{ AV_386_FXSR,		Hw1_i_fxsr,	sizeof (Hw1_i_fxsr) - 1 },
	{ AV_386_SSE,		Hw1_i_sse,	sizeof (Hw1_i_sse) - 1 },
	{ AV_386_SSE2,		Hw1_i_sse2,	sizeof (Hw1_i_sse2) - 1 },
	{ AV_386_PAUSE,		Hw1_i_pause,	sizeof (Hw1_i_pause) - 1 },
	{ AV_386_SSE3,		Hw1_i_sse3,	sizeof (Hw1_i_sse3) - 1 },
	{ AV_386_MON,		Hw1_i_mon,	sizeof (Hw1_i_mon) - 1 },
	{ AV_386_CX16,		Hw1_i_cx16,	sizeof (Hw1_i_cx16) - 1 },
	{ AV_386_AHF,		Hw1_i_ahf,	sizeof (Hw1_i_ahf) - 1 },
	{ AV_386_TSCP,		Hw1_i_tscp,	sizeof (Hw1_i_tscp) - 1 },
	{ AV_386_AMD_SSE4A,	Hw1_i_amd_sse4a,
						sizeof (Hw1_i_amd_sse4a) - 1 },
	{ AV_386_POPCNT,	Hw1_i_popcnt,	sizeof (Hw1_i_popcnt) - 1 },
	{ AV_386_AMD_LZCNT,	Hw1_i_amd_lzcnt,
						sizeof (Hw1_i_amd_lzcnt) - 1 },
	{ AV_386_SSSE3,		Hw1_i_ssse3,	sizeof (Hw1_i_ssse3) - 1 },
	{ AV_386_SSE4_1,	Hw1_i_sse4_1,	sizeof (Hw1_i_sse4_1) - 1 },
	{ AV_386_SSE4_2,	Hw1_i_sse4_2,	sizeof (Hw1_i_sse4_2) - 1 }
};
static const uint_t hw1_i_num = sizeof (hw1_i) / sizeof (Cap_desc);

/*
 * Concatenate a token to the string buffer.  This can be a capabilities token
 * or a separator token.
 */
static int
token(char **ostr, size_t *olen, const char *nstr, size_t nlen)
{
	if (*olen < nlen)
		return (CAP_ERR_BUFOVFL);

	(void) strcat(*ostr, nstr);
	*ostr += nlen;
	*olen -= nlen;

	return (0);
}

/*
 * Expand a capabilities value into the strings defined in the associated
 * capabilities descriptor.
 */
static int
expand(uint64_t val, const Cap_desc *cdp, uint_t cnum, char *str, size_t slen,
    int fmt)
{
	uint_t	cnt, mask;
	int	follow = 0, err;

	if (val == 0)
		return (0);

	for (cnt = WORD_BIT, mask = 0x80000000; cnt; cnt--,
	    (mask = mask >> 1)) {
		if ((val & mask) && (cnt <= cnum) && cdp[cnt - 1].c_val) {
			if (follow++ && ((err = token(&str, &slen,
			    format[fmt].f_str, format[fmt].f_len)) != 0))
				return (err);

			if ((err = token(&str, &slen, cdp[cnt - 1].c_str,
			    cdp[cnt - 1].c_len)) != 0)
				return (err);

			val = val & ~mask;
		}
	}

	/*
	 * If there are any unknown bits remaining display the numeric value.
	 */
	if (val) {
		if (follow && ((err = token(&str, &slen, format[fmt].f_str,
		    format[fmt].f_len)) != 0))
			return (err);

		(void) snprintf(str, slen, "0x%llx", val);
	}
	return (0);
}

/*
 * Expand a CA_SUNW_HW_1 value.
 */
int
hwcap_1_val2str(uint64_t val, char *str, size_t len, int fmt, ushort_t mach)
{
	/*
	 * Initialize the string buffer, and validate the format request.
	 */
	*str = '\0';
	if (fmt > CAP_MAX_TYPE)
		return (CAP_ERR_INVFMT);

	if ((mach == EM_386) || (mach == EM_IA_64) || (mach == EM_AMD64))
		return (expand(val, &hw1_i[0], hw1_i_num, str, len, fmt));

	if ((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9))
		return (expand(val, &hw1_s[0], hw1_s_num, str, len, fmt));

	return (CAP_ERR_UNKMACH);
}

/*
 * Expand a CA_SUNW_SF_1 value.  Note, that at present these capabilities are
 * common across all platforms.  The use of "mach" is therefore redundant, but
 * is retained for compatibility with the interface of hwcap_1_val2str(), and
 * possible future expansion.
 */
int
/* ARGSUSED4 */
sfcap_1_val2str(uint64_t val, char *str, size_t len, int fmt, ushort_t mach)
{
	/*
	 * Initialize the string buffer, and validate the format request.
	 */
	*str = '\0';
	if (fmt > CAP_MAX_TYPE)
		return (CAP_ERR_INVFMT);

	return (expand(val, &sf1[0], sf1_num, str, len, fmt));
}

/*
 * Determine capability type from the capability tag.
 */
int
cap_val2str(uint64_t tag, uint64_t val, char *str, size_t len, int fmt,
    ushort_t mach)
{
	if (tag == CA_SUNW_HW_1)
		return (hwcap_1_val2str(val, str, len, fmt, mach));
	if (tag == CA_SUNW_SF_1)
		return (sfcap_1_val2str(val, str, len, fmt, mach));

	return (CAP_ERR_UNKTAG);
}

/*
 * Determine a capabilities value from a capabilities string.
 */
static uint64_t
value(const char *str, const Cap_desc *cdp, uint_t cnum)
{
	uint_t	num;

	for (num = 0; num < cnum; num++) {
		if (strcmp(str, cdp[num].c_str) == 0)
			return (cdp[num].c_val);
	}
	return (0);
}

uint64_t
sfcap_1_str2val(const char *str, ushort_t mach)
{
	return (value(str, &sf1[0], sf1_num));
}

uint64_t
hwcap_1_str2val(const char *str, ushort_t mach)
{
	if ((mach == EM_386) || (mach == EM_IA_64) || (mach == EM_AMD64))
		return (value(str, &hw1_i[0], hw1_i_num));

	if ((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9))
		return (value(str, &hw1_s[0], hw1_s_num));

	return (0);
}
