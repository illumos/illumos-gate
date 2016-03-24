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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Format String Decoder
 *
 * This file provides the core engine for converting strings of format
 * characters into formatted output.  The various format dcmds invoke the
 * mdb_fmt_print() function below with a target, address space identifier,
 * address, count, and format character, and it reads the required data from
 * the target and prints the formatted output to stdout.  Since nearly two
 * thirds of the format characters can be expressed as simple printf format
 * strings, we implement the engine using the lookup table below.  Each entry
 * provides either a pointer to a printf format string or a pointer to a
 * function to perform special processing.  For the printf case, the
 * corresponding data size in bytes is also supplied.  The printf processing
 * code handles 1, 2, 4, and 8-byte reads into an unsigned integer container
 * of the given size, and then simply calls mdb_iob_printf with the integer
 * and format string. This handles all printf cases, except when unsigned
 * promotion of an integer type in the varargs list does not perform the
 * conversion we require to get the proper result.  With the current set of
 * format characters, this case only occurs twice: we need a 4-byte float
 * to get promoted to 8-byte double for the 'f' format so it can be
 * correctly formatted by %f, and we need a 1-byte int8_t to get promoted
 * with sign extension to a 4-byte int32_t for the 'v' format so it can be
 * correctly formatted by %d.  We provide explicit functions to handle these
 * cases, as well as to handle special format characters such as 'i', etc.
 * We also provide a cmd_formats() dcmd function below which prints a table
 * of the output formats and their sizes.  Format characters that provide
 * custom functions provide their help description string explicitly.  All
 * the printf formats have their help strings generated automatically by
 * our printf "unparser" mdb_iob_format2str().
 */

#include <mdb/mdb_types.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb.h>

#define	FUNCP(p)	((void *)(p))	/* Cast to f_ptr type */
#define	SZ_NONE		((size_t)-1L)	/* Format does not change dot */

typedef mdb_tgt_addr_t mdb_fmt_func_f(mdb_tgt_t *,
    mdb_tgt_as_t, mdb_tgt_addr_t, size_t);

/*
 * There are several 'special' characters that are handled outside of
 * mdb_fmt_print().  These are characters that write (vwWZ) and characters that
 * match (lLM).  We include them here so that ::formats can display an
 * appropriate message, but they are handled specially by write_arglist() and
 * match_arglist() in mdb_cmds.c.
 */
#define	FMT_NONE	0x0	/* Format character is not supported */
#define	FMT_FUNC	0x1	/* f_ptr is a mdb_fmt_func_f to call */
#define	FMT_PRINTF	0x2	/* f_ptr is a const char * format string */
#define	FMT_MATCH	0x4	/* Match command (not supported here) */
#define	FMT_WRITE	0x8	/* Command writes to address space */

#define	FMT_TYPE(x)	((x) & 0x7) /* Excludes modifying flags (FMT_WRITE) */

typedef struct mdb_fmt_desc {
	int f_type;		/* Type of format (see above) */
	void *f_ptr;		/* Data pointer (see above) */
	const char *f_help;	/* Additional help string */
	size_t f_size;		/* Size of type in bytes, or SZ_NONE */
	boolean_t f_float;	/* Is this a floating point type */
} mdb_fmt_desc_t;

static const char help_plus[] = "increment dot by the count";
static const char help_minus[] = "decrement dot by the count";
static const char help_escchr[] = "character using C character notation";
static const char help_swapint[] = "swap bytes and shorts";
static const char help_dotinstr[] = "address and disassembled instruction";
static const char help_instr[] = "disassembled instruction";
static const char help_escstr[] = "string using C string notation";
static const char help_time32[] = "decoded time32_t";
static const char help_carat[] = "decrement dot by increment * count";
static const char help_dot[] = "dot as symbol+offset";
#ifndef _KMDB
static const char help_f[] = "float";
#endif
static const char help_swapshort[] = "swap bytes";
static const char help_nl[] = "newline";
static const char help_ws[] = "whitespace";
static const char help_rawstr[] = "raw string";
static const char help_tab[] = "horizontal tab";
static const char help_sdbyte[] = "decimal signed int";
static const char help_time64[] = "decoded time64_t";
static const char help_binary[] = "binary unsigned long long";
static const char help_hex64[] = "hexadecimal long long";
static const char help_match32[] = "int";
static const char help_match64[] = "long long";
static const char help_match16[] = "short";
static const char help_uintptr[] = "hexadecimal uintptr_t";

/*ARGSUSED*/
static mdb_tgt_addr_t
fmt_dot(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	uint_t oflags = mdb_iob_getflags(mdb.m_out) & MDB_IOB_INDENT;
	char buf[24];

	mdb_iob_clrflags(mdb.m_out, oflags);

	if (mdb.m_flags & MDB_FL_PSYM) {
		while (cnt-- != 0)
			mdb_iob_printf(mdb.m_out, "%-#16lla%16T", addr);
	} else {
		(void) mdb_iob_snprintf(buf, sizeof (buf),
		    "%#llx:", (u_longlong_t)addr);
		while (cnt-- != 0)
			mdb_iob_printf(mdb.m_out, "%-16s%16T", buf);
	}

	mdb_iob_setflags(mdb.m_out, oflags);
	mdb_nv_set_value(mdb.m_rvalue, addr);
	return (addr);
}

#ifndef _KMDB
static mdb_tgt_addr_t
fmt_float(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	float f;
	/*
	 * We need to handle float as a special case because we need it to be
	 * promoted to a double by virtue of appearing as a parameter, and all
	 * our generic format handling below is based on integer types.
	 */
	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &f, sizeof (f), addr) != sizeof (f)) {
			warn("failed to read data from target");
			break;
		}
		mdb_iob_printf(mdb.m_out, "%e", f);
		addr += sizeof (f);
	}
	return (addr);
}
#endif

/*ARGSUSED*/
static mdb_tgt_addr_t
fmt_plus(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	return (addr + cnt);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
fmt_minus(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	return (addr - cnt);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
fmt_carat(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	return (addr - (mdb.m_incr * cnt));
}

/*ARGSUSED*/
static mdb_tgt_addr_t
fmt_nl(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	while (cnt-- != 0)
		mdb_iob_nl(mdb.m_out);

	return (addr);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
fmt_ws(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	mdb_iob_ws(mdb.m_out, cnt);
	return (addr);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
fmt_tab(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	size_t ts = mdb_iob_gettabstop(mdb.m_out);

	mdb_iob_tabstop(mdb.m_out, cnt);
	mdb_iob_tab(mdb.m_out);
	mdb_iob_tabstop(mdb.m_out, ts);

	return (addr);
}

static mdb_tgt_addr_t
fmt_rawstr(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	uint_t oflags = mdb_iob_getflags(mdb.m_out) & MDB_IOB_INDENT;
	char buf[BUFSIZ];
	ssize_t nbytes;

	mdb_iob_clrflags(mdb.m_out, oflags);

	for (; cnt-- != 0; addr++) {
		do {
			nbytes = mdb_tgt_readstr(t, as, buf, BUFSIZ, addr);
			if (nbytes > 0) {
				mdb_iob_puts(mdb.m_out, buf);
				addr += MIN(nbytes, BUFSIZ - 1);
			} else if (nbytes < 0) {
				warn("failed to read data from target");
				goto out;
			}
		} while (nbytes == BUFSIZ);

		if (cnt != 0)
			mdb_iob_puts(mdb.m_out, "\\0");
	}
out:
	mdb_iob_setflags(mdb.m_out, oflags);
	return (addr);
}

static mdb_tgt_addr_t
fmt_escstr(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	uint_t oflags = mdb_iob_getflags(mdb.m_out) & MDB_IOB_INDENT;
	char buf[BUFSIZ];
	ssize_t nbytes;
	char *s;

	mdb_iob_clrflags(mdb.m_out, oflags);

	for (; cnt-- != 0; addr++) {
		do {
			nbytes = mdb_tgt_readstr(t, as, buf, BUFSIZ, addr);
			if (nbytes > 0) {
				s = strchr2esc(buf, strlen(buf));
				mdb_iob_puts(mdb.m_out, s);
				strfree(s);
				addr += MIN(nbytes, BUFSIZ - 1);
			} else if (nbytes < 0) {
				warn("failed to read data from target");
				goto out;
			}
		} while (nbytes == BUFSIZ);

		if (cnt != 0)
			mdb_iob_puts(mdb.m_out, "\\0");
	}
out:
	mdb_iob_setflags(mdb.m_out, oflags);
	return (addr);
}

static mdb_tgt_addr_t
fmt_escchr(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	char *(*convert)(const char *, size_t);
	ssize_t nbytes;
	char *buf, *s;

	if (mdb.m_flags & MDB_FL_ADB)
		convert = &strchr2adb;
	else
		convert = &strchr2esc;

	buf = mdb_alloc(cnt + 1, UM_SLEEP);
	buf[cnt] = 0;

	if ((nbytes = mdb_tgt_aread(t, as, buf, cnt, addr)) > 0) {
		s = convert(buf, nbytes);
		mdb_iob_puts(mdb.m_out, s);
		strfree(s);
		addr += nbytes;
	}

	mdb_free(buf, cnt + 1);
	return (addr);
}

static mdb_tgt_addr_t
fmt_swapshort(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	ushort_t x;

	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &x, sizeof (x), addr) == sizeof (x)) {
			x = (x << 8) | (x >> 8);
			mdb_iob_printf(mdb.m_out, "%-8x", x);
			mdb_nv_set_value(mdb.m_rvalue, x);
			addr += sizeof (x);
		} else {
			warn("failed to read data from target");
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
fmt_swapint(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	uint_t x;

	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &x, sizeof (x), addr) == sizeof (x)) {
			x = ((x << 24) | ((x << 8) & 0xff0000) |
			    ((x >> 8) & 0xff00) | ((x >> 24) & 0xff));
			mdb_iob_printf(mdb.m_out, "%-16x", x);
			mdb_nv_set_value(mdb.m_rvalue, x);
			addr += sizeof (x);
		} else {
			warn("failed to read data from target");
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
fmt_time32(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	int32_t x;

	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &x, sizeof (x), addr) == sizeof (x)) {
			mdb_iob_printf(mdb.m_out, "%-24Y", (time_t)x);
			mdb_nv_set_value(mdb.m_rvalue, x);
			addr += sizeof (x);
		} else {
			warn("failed to read data from target");
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
fmt_time64(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	int64_t x;

	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &x, sizeof (x), addr) == sizeof (x)) {
			if ((time_t)x == x)
				mdb_iob_printf(mdb.m_out, "%-24Y", (time_t)x);
			else
				mdb_iob_printf(mdb.m_out, "%-24llR", x);

			mdb_nv_set_value(mdb.m_rvalue, x);
			addr += sizeof (x);
		} else {
			warn("failed to read data from target");
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
fmt_sdbyte(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	int8_t x;

	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &x, sizeof (x), addr) == sizeof (x)) {
			mdb_iob_printf(mdb.m_out, "%-8d", (int32_t)x);
			mdb_nv_set_value(mdb.m_rvalue, (uint8_t)x);
			addr += sizeof (x);
		} else {
			warn("failed to read data from target");
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
fmt_instr(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	char buf[BUFSIZ];
	uintptr_t naddr;

	while (cnt-- != 0) {
		naddr = mdb_dis_ins2str(mdb.m_disasm, t, as,
		    buf, sizeof (buf), addr);
		if (naddr == addr)
			return (addr); /* If we didn't move, we failed */
		mdb_iob_printf(mdb.m_out, "%s\n", buf);
		addr = naddr;
	}
	return (addr);
}

static mdb_tgt_addr_t
fmt_dotinstr(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	uint_t oflags = mdb_iob_getflags(mdb.m_out) & MDB_IOB_INDENT;

	char buf[BUFSIZ];
	uintptr_t naddr;
	uint32_t i;

	for (mdb_iob_clrflags(mdb.m_out, oflags); cnt-- != 0; addr = naddr) {
		if (mdb_tgt_aread(t, as, &i, sizeof (i), addr) != sizeof (i)) {
			warn("failed to read data from target");
			break; /* Fail if we can't read instruction */
		}
		naddr = mdb_dis_ins2str(mdb.m_disasm, t, as,
		    buf, sizeof (buf), addr);
		if (naddr == addr)
			break; /* Fail if we didn't advance */
		mdb_iob_printf(mdb.m_out, "%lx %x: %s\n", (long)addr, i, buf);
	}

	mdb_iob_setflags(mdb.m_out, oflags);
	return (addr);
}

static mdb_tgt_addr_t
fmt_binary(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	uint64_t x;

	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &x, sizeof (x), addr) == sizeof (x)) {
			mdb_iob_printf(mdb.m_out, "%-64s",
			    numtostr(x, 2, NTOS_UNSIGNED));
			mdb_nv_set_value(mdb.m_rvalue, x);
			addr += sizeof (x);
		} else {
			warn("failed to read data from target");
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
fmt_hex64(mdb_tgt_t *t, mdb_tgt_as_t as, mdb_tgt_addr_t addr, size_t cnt)
{
	const char *fmts[] = { "%-16llx", "%-17llx" };
	const uint64_t mask = 0xf000000000000000ull;
	uint64_t x;

	while (cnt-- != 0) {
		if (mdb_tgt_aread(t, as, &x, sizeof (x), addr) == sizeof (x)) {
			mdb_iob_printf(mdb.m_out, fmts[(x & mask) != 0], x);
			mdb_nv_set_value(mdb.m_rvalue, x);
			addr += sizeof (x);
		} else {
			warn("failed to read data from target");
			break;
		}
	}
	return (addr);
}

static const mdb_fmt_desc_t fmttab[] = {
	{ FMT_NONE, NULL, NULL, 0 },				/* 0 = NUL */
	{ FMT_NONE, NULL, NULL, 0 },				/* 1 = SOH */
	{ FMT_NONE, NULL, NULL, 0 },				/* 2 = STX */
	{ FMT_NONE, NULL, NULL, 0 },				/* 3 = ETX */
	{ FMT_NONE, NULL, NULL, 0 },				/* 4 = EOT */
	{ FMT_NONE, NULL, NULL, 0 },				/* 5 = ENQ */
	{ FMT_NONE, NULL, NULL, 0 },				/* 6 = ACK */
	{ FMT_NONE, NULL, NULL, 0 },				/* 7 = BEL */
	{ FMT_NONE, NULL, NULL, 0 },				/* 8 = BS */
	{ FMT_NONE, NULL, NULL, 0 },				/* 9 = \t */
	{ FMT_NONE, NULL, NULL, 0 },				/* 10 = \n */
	{ FMT_NONE, NULL, NULL, 0 },				/* 11 = VT */
	{ FMT_NONE, NULL, NULL, 0 },				/* 12 = FF */
	{ FMT_NONE, NULL, NULL, 0 },				/* 13 = \r */
	{ FMT_NONE, NULL, NULL, 0 },				/* 14 = SO */
	{ FMT_NONE, NULL, NULL, 0 },				/* 15 = SI */
	{ FMT_NONE, NULL, NULL, 0 },				/* 16 = DLE */
	{ FMT_NONE, NULL, NULL, 0 },				/* 17 = DC1 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 18 = DC2 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 19 = DC3 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 20 = DC4 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 21 = NAK */
	{ FMT_NONE, NULL, NULL, 0 },				/* 22 = EYC */
	{ FMT_NONE, NULL, NULL, 0 },				/* 23 = ETB */
	{ FMT_NONE, NULL, NULL, 0 },				/* 24 = CAN */
	{ FMT_NONE, NULL, NULL, 0 },				/* 25 = EM */
	{ FMT_NONE, NULL, NULL, 0 },				/* 26 = SUB */
	{ FMT_NONE, NULL, NULL, 0 },				/* 27 = ESC */
	{ FMT_NONE, NULL, NULL, 0 },				/* 28 = FS */
	{ FMT_NONE, NULL, NULL, 0 },				/* 29 = GS */
	{ FMT_NONE, NULL, NULL, 0 },				/* 30 = RS */
	{ FMT_NONE, NULL, NULL, 0 },				/* 31 = US */
	{ FMT_NONE, NULL, NULL, 0 },				/* 32 = SPACE */
	{ FMT_NONE, NULL, NULL, 0 },				/* 33 = ! */
	{ FMT_NONE, NULL, NULL, 0 },				/* 34 = " */
	{ FMT_NONE, NULL, NULL, 0 },				/* 35 = # */
	{ FMT_NONE, NULL, NULL, 0 },				/* 36 = $ */
	{ FMT_NONE, NULL, NULL, 0 },				/* 37 = % */
	{ FMT_NONE, NULL, NULL, 0 },				/* 38 = & */
	{ FMT_NONE, NULL, NULL, 0 },				/* 39 = ' */
	{ FMT_NONE, NULL, NULL, 0 },				/* 40 = ( */
	{ FMT_NONE, NULL, NULL, 0 },				/* 41 = ) */
	{ FMT_NONE, NULL, NULL, 0 },				/* 42 = * */
	{ FMT_FUNC, FUNCP(fmt_plus), help_plus, 0 },		/* 43 = + */
	{ FMT_NONE, NULL, NULL, 0 },				/* 44 = , */
	{ FMT_FUNC, FUNCP(fmt_minus), help_minus, 0 },		/* 45 = - */
	{ FMT_NONE, NULL, NULL, 0 },				/* 46 = . */
	{ FMT_NONE, NULL, NULL, 0 },				/* 47 = / */
	{ FMT_NONE, NULL, NULL, 0 },				/* 48 = 0 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 49 = 1 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 50 = 2 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 51 = 3 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 52 = 4 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 53 = 5 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 54 = 6 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 55 = 7 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 56 = 8 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 57 = 9 */
	{ FMT_NONE, NULL, NULL, 0 },				/* 58 = : */
	{ FMT_NONE, NULL, NULL, 0 },				/* 59 = ; */
	{ FMT_NONE, NULL, NULL, 0 },				/* 60 = < */
	{ FMT_NONE, NULL, NULL, 0 },				/* 61 = = */
	{ FMT_NONE, NULL, NULL, 0 },				/* 62 = > */
	{ FMT_NONE, NULL, NULL, 0 },				/* 63 = ? */
	{ FMT_NONE, NULL, NULL, 0 },				/* 64 = @ */
	{ FMT_NONE, NULL, NULL, 0 },				/* 65 = A */
	{ FMT_PRINTF, "%-8x", NULL, 1 },			/* 66 = B */
	{ FMT_FUNC, FUNCP(fmt_escchr), help_escchr, 1 },	/* 67 = C */
	{ FMT_PRINTF, "%-16d", NULL, 4 },			/* 68 = D */
	{ FMT_PRINTF, "%-16llu", NULL, 8 },			/* 69 = E */
#ifdef _KMDB
	{ FMT_NONE, NULL, NULL, 0 },				/* 70 = F */
#else
	{ FMT_PRINTF, "%g", NULL, sizeof (double), B_TRUE },	/* 70 = F */
#endif
	{ FMT_PRINTF, "%-16llo", NULL, 8 },			/* 71 = G */
	{ FMT_FUNC, FUNCP(fmt_swapint), help_swapint, 4 },	/* 72 = H */
	{ FMT_FUNC, FUNCP(fmt_dotinstr), help_dotinstr, 0 },	/* 73 = I */
	{ FMT_FUNC, FUNCP(fmt_hex64), help_hex64, 8 },		/* 74 = J */
#ifdef _LP64
	{ FMT_FUNC, FUNCP(fmt_hex64), help_uintptr, 8 },	/* 75 = K (J) */
#else
	{ FMT_PRINTF, "%-16x", help_uintptr, 4 },		/* 75 = K (X) */
#endif
	{ FMT_MATCH, NULL, help_match32, 4 },			/* 76 = L */
	{ FMT_MATCH, NULL, help_match64, 8 },			/* 77 = M */
	{ FMT_FUNC, FUNCP(fmt_nl), help_nl, SZ_NONE },		/* 78 = N */
	{ FMT_PRINTF, "%-#16o", NULL, 4 },			/* 79 = O */
	{ FMT_PRINTF, "%-16a", NULL, sizeof (uintptr_t) },	/* 80 = P */
	{ FMT_PRINTF, "%-#16q", NULL, 4 },			/* 81 = Q */
	{ FMT_FUNC, FUNCP(fmt_binary), help_binary, 8 },	/* 82 = R */
	{ FMT_FUNC, FUNCP(fmt_escstr), help_escstr, 0 },	/* 83 = S */
	{ FMT_FUNC, FUNCP(fmt_tab), help_tab, SZ_NONE },	/* 84 = T */
	{ FMT_PRINTF, "%-16u", NULL, 4 },			/* 85 = U */
	{ FMT_PRINTF, "%-8u", NULL, 1 },			/* 86 = V */
	{ FMT_PRINTF|FMT_WRITE, "%-16r", NULL, 4 },		/* 87 = W */
	{ FMT_PRINTF, "%-16x", NULL, 4 },			/* 88 = X */
	{ FMT_FUNC, FUNCP(fmt_time32), help_time32, 4 },	/* 89 = Y */
	{ FMT_FUNC|FMT_WRITE, FUNCP(fmt_hex64), help_hex64, 8 }, /* 90 = Z */
	{ FMT_NONE, NULL, NULL, 0 },				/* 91 = [ */
	{ FMT_NONE, NULL, NULL, 0 },				/* 92 = \ */
	{ FMT_NONE, NULL, NULL, 0 },				/* 93 = ] */
	{ FMT_FUNC, FUNCP(fmt_carat), help_carat, 0 },		/* 94 = ^ */
	{ FMT_NONE, NULL, NULL, 0 },				/* 95 = _ */
	{ FMT_NONE, NULL, NULL, 0 },				/* 96 = ` */
	{ FMT_FUNC, FUNCP(fmt_dot), help_dot, SZ_NONE },	/* 97 = a */
	{ FMT_PRINTF, "%-#8o", NULL, 1 },			/* 98 = b */
	{ FMT_PRINTF, "%c", NULL, 1 },				/* 99 = c */
	{ FMT_PRINTF, "%-8hd", NULL, 2 },			/* 100 = d */
	{ FMT_PRINTF, "%-16lld", NULL, 8 },			/* 101 = e */
#ifdef _KMDB
	{ FMT_NONE, NULL, NULL, 0 },				/* 102 = f */
#else
	{ FMT_FUNC, FUNCP(fmt_float), help_f, sizeof (float),
	    B_TRUE },						/* 102 = f */
#endif
	{ FMT_PRINTF, "%-16llq", NULL, 8 },			/* 103 = g */
	{ FMT_FUNC, FUNCP(fmt_swapshort), help_swapshort, 2 },	/* 104 = h */
	{ FMT_FUNC, FUNCP(fmt_instr), help_instr, 0 },		/* 105 = i */
	{ FMT_NONE, NULL, NULL, 0 },				/* 106 = j */
	{ FMT_NONE, NULL, NULL, 0 },				/* 107 = k */
	{ FMT_MATCH, NULL, help_match16, 2 },			/* 108 = l */
	{ FMT_NONE, NULL, NULL, 0 },				/* 109 = m */
	{ FMT_FUNC, FUNCP(fmt_nl), help_nl, SZ_NONE },		/* 110 = n */
	{ FMT_PRINTF, "%-#8ho", NULL, 2 },			/* 111 = o */
	{ FMT_PRINTF, "%-16a", NULL, sizeof (uintptr_t) },	/* 112 = p */
	{ FMT_PRINTF, "%-#8hq", NULL, 2 },			/* 113 = q */
	{ FMT_FUNC, FUNCP(fmt_ws), help_ws, SZ_NONE },		/* 114 = r */
	{ FMT_FUNC, FUNCP(fmt_rawstr), help_rawstr, 0 },	/* 115 = s */
	{ FMT_FUNC, FUNCP(fmt_tab), help_tab, SZ_NONE },	/* 116 = t */
	{ FMT_PRINTF, "%-8hu", NULL, 2 },			/* 117 = u */
	{ FMT_FUNC|FMT_WRITE, FUNCP(fmt_sdbyte), help_sdbyte, 1 }, /* 118 = v */
	{ FMT_PRINTF|FMT_WRITE, "%-8hr", NULL, 2 },		/* 119 = w */
	{ FMT_PRINTF, "%-8hx", NULL, 2 },			/* 120 = x */
	{ FMT_FUNC, FUNCP(fmt_time64), help_time64, 8 },	/* 121 = y */
	{ FMT_NONE, NULL, NULL, 0 },				/* 122 = z */
};

mdb_tgt_addr_t
mdb_fmt_print(mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr, size_t cnt, char fmt)
{
	const mdb_fmt_desc_t *fp = &fmttab[fmt];
	mdb_fmt_func_f *funcp;
	uintmax_t rvalue;
	void *buf;

	union {
		uint64_t i8;
		uint32_t i4;
		uint16_t i2;
		uint8_t i1;
		double d;
	} u;

	if (fmt < 0 || fmt > (sizeof (fmttab) / sizeof (fmttab[0]))) {
		warn("invalid format character -- '%c'\n", fmt);
		return (addr);
	}

	switch (FMT_TYPE(fp->f_type)) {
	case FMT_FUNC:
		funcp = (mdb_fmt_func_f *)fp->f_ptr;
		addr = funcp(t, as, addr, cnt);
		break;

	case FMT_PRINTF:
		switch (fp->f_size) {
		case 1:
			buf = &u.i1;
			break;
		case 2:
			buf = &u.i2;
			break;
		case 4:
			buf = &u.i4;
			break;
		case 8:
			buf = &u.i8;
			break;
		default:
			fail("format %c is defined using illegal size\n", fmt);
		}

		if (fp->f_float == B_TRUE) {
			if (fp->f_size != 8) {
				fail("format %c is using illegal fp size\n",
				    fmt);
			}

			buf = &u.d;
		}

		while (cnt-- != 0) {
			if (mdb_tgt_aread(t, as, buf, fp->f_size, addr) !=
			    fp->f_size) {
				warn("failed to read data from target");
				return (addr);
			}

			switch (fp->f_size) {
			case 1:
				mdb_iob_printf(mdb.m_out, fp->f_ptr, u.i1);
				rvalue = u.i1;
				break;
			case 2:
				mdb_iob_printf(mdb.m_out, fp->f_ptr, u.i2);
				rvalue = u.i2;
				break;
			case 4:
				mdb_iob_printf(mdb.m_out, fp->f_ptr, u.i4);
				rvalue = u.i4;
				break;
			case 8:
				if (fp->f_float) {
					mdb_iob_printf(mdb.m_out, fp->f_ptr,
					    u.d);
				} else {
					mdb_iob_printf(mdb.m_out, fp->f_ptr,
					    u.i8);
				}
				rvalue = u.i8;
				break;
			}

			mdb_nv_set_value(mdb.m_rvalue, rvalue);
			addr += fp->f_size;
		}
		break;

	default:
		warn("invalid format character -- '%c'\n", fmt);
	}

	return (addr);
}

/*ARGSUSED*/
int
cmd_formats(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const mdb_fmt_desc_t *fp = &fmttab[0];
	int i;
	const char *write;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	for (i = 0; i < (sizeof (fmttab) / sizeof (fmttab[0])); i++, fp++) {
		if (fp->f_type == FMT_NONE)
			continue;

		write = (fp->f_type & FMT_WRITE) ? "write " : "";

		if (fp->f_type & FMT_FUNC)
			mdb_printf("%c - %s%s", i, write, fp->f_help);
		else if (fp->f_type & FMT_MATCH)
			mdb_printf("%c - match %s", i, fp->f_help);
		else if (fp->f_help != NULL)
			mdb_printf("%c - %s%s", i, write, fp->f_help);
		else
			mdb_printf("%c - %s%s", i, write,
			    mdb_iob_format2str(fp->f_ptr));

		switch (fp->f_size) {
		case SZ_NONE:
			mdb_printf("\n");
			break;
		case 0:
			mdb_printf(" (variable size)\n");
			break;
		case 1:
			mdb_printf(" (1 byte)\n");
			break;
		default:
			mdb_printf(" (%lu bytes)\n", fp->f_size);
		}
	}

	return (DCMD_OK);
}
