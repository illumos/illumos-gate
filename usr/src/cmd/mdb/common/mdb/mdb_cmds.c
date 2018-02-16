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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2018 Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 * Copyright (c) 2015, 2017 by Delphix. All rights reserved.
 */

#include <sys/elf.h>
#include <sys/elf_SPARC.h>

#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <alloca.h>
#include <libctf.h>
#include <ctype.h>

#include <mdb/mdb_string.h>
#include <mdb/mdb_argvec.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_fmt.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_help.h>
#include <mdb/mdb_disasm.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_evset.h>
#include <mdb/mdb_print.h>
#include <mdb/mdb_nm.h>
#include <mdb/mdb_set.h>
#include <mdb/mdb_demangle.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_whatis.h>
#include <mdb/mdb_whatis_impl.h>
#include <mdb/mdb_macalias.h>
#include <mdb/mdb_tab.h>
#include <mdb/mdb_typedef.h>
#ifdef _KMDB
#include <kmdb/kmdb_kdi.h>
#endif
#include <mdb/mdb.h>

#ifdef __sparc
#define	SETHI_MASK	0xc1c00000
#define	SETHI_VALUE	0x01000000

#define	IS_SETHI(machcode)	(((machcode) & SETHI_MASK) == SETHI_VALUE)

#define	OP(machcode)	((machcode) >> 30)
#define	OP3(machcode)	(((machcode) >> 19) & 0x3f)
#define	RD(machcode)	(((machcode) >> 25) & 0x1f)
#define	RS1(machcode)	(((machcode) >> 14) & 0x1f)
#define	I(machcode)	(((machcode) >> 13) & 0x01)

#define	IMM13(machcode)	((machcode) & 0x1fff)
#define	IMM22(machcode)	((machcode) & 0x3fffff)

#define	OP_ARITH_MEM_MASK	0x2
#define	OP_ARITH		0x2
#define	OP_MEM			0x3

#define	OP3_CC_MASK		0x10
#define	OP3_COMPLEX_MASK	0x20

#define	OP3_ADD			0x00
#define	OP3_OR			0x02
#define	OP3_XOR			0x03

#ifndef	R_O7
#define	R_O7	0xf
#endif
#endif /* __sparc */

static mdb_tgt_addr_t
write_uint8(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t ull, uint_t rdback)
{
	uint8_t o, n = (uint8_t)ull;

	if (rdback && mdb_tgt_aread(mdb.m_target, as, &o, sizeof (o),
	    addr) == -1)
		return (addr);

	if (mdb_tgt_awrite(mdb.m_target, as, &n, sizeof (n), addr) == -1)
		return (addr);

	if (rdback) {
		if (mdb_tgt_aread(mdb.m_target, as, &n, sizeof (n), addr) == -1)
			return (addr);

		mdb_iob_printf(mdb.m_out, "%-#*lla%16T%-#8x=%8T0x%x\n",
		    mdb_iob_getmargin(mdb.m_out), addr, o, n);
	}

	return (addr + sizeof (n));
}

static mdb_tgt_addr_t
write_uint16(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t ull, uint_t rdback)
{
	uint16_t o, n = (uint16_t)ull;

	if (rdback && mdb_tgt_aread(mdb.m_target, as, &o, sizeof (o),
	    addr) == -1)
		return (addr);

	if (mdb_tgt_awrite(mdb.m_target, as, &n, sizeof (n), addr) == -1)
		return (addr);

	if (rdback) {
		if (mdb_tgt_aread(mdb.m_target, as, &n, sizeof (n), addr) == -1)
			return (addr);

		mdb_iob_printf(mdb.m_out, "%-#*lla%16T%-#8hx=%8T0x%hx\n",
		    mdb_iob_getmargin(mdb.m_out), addr, o, n);
	}

	return (addr + sizeof (n));
}

static mdb_tgt_addr_t
write_uint32(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t ull, uint_t rdback)
{
	uint32_t o, n = (uint32_t)ull;

	if (rdback && mdb_tgt_aread(mdb.m_target, as, &o, sizeof (o),
	    addr) == -1)
		return (addr);

	if (mdb_tgt_awrite(mdb.m_target, as, &n, sizeof (n), addr) == -1)
		return (addr);

	if (rdback) {
		if (mdb_tgt_aread(mdb.m_target, as, &n, sizeof (n), addr) == -1)
			return (addr);

		mdb_iob_printf(mdb.m_out, "%-#*lla%16T%-#16x=%8T0x%x\n",
		    mdb_iob_getmargin(mdb.m_out), addr, o, n);
	}

	return (addr + sizeof (n));
}

static mdb_tgt_addr_t
write_uint64(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t n, uint_t rdback)
{
	uint64_t o;

	if (rdback && mdb_tgt_aread(mdb.m_target, as, &o, sizeof (o),
	    addr) == -1)
		return (addr);

	if (mdb_tgt_awrite(mdb.m_target, as, &n, sizeof (n), addr) == -1)
		return (addr);

	if (rdback) {
		if (mdb_tgt_aread(mdb.m_target, as, &n, sizeof (n), addr) == -1)
			return (addr);

		mdb_iob_printf(mdb.m_out, "%-#*lla%16T%-#24llx=%8T0x%llx\n",
		    mdb_iob_getmargin(mdb.m_out), addr, o, n);
	}

	return (addr + sizeof (n));
}

/*
 * Writes to objects of size 1, 2, 4, or 8 bytes. The function
 * doesn't care if the object is a number or not (e.g. it could
 * be a byte array, or a struct) as long as the size of the write
 * is one of the aforementioned ones.
 */
static mdb_tgt_addr_t
write_var_uint(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t val, size_t size,
    uint_t rdback)
{
	if (size < sizeof (uint64_t)) {
		uint64_t max_num = 1ULL << (size * NBBY);

		if (val >= max_num) {
			uint64_t write_len = 0;

			/* count bytes needed for val */
			while (val != 0) {
				write_len++;
				val >>= NBBY;
			}

			mdb_warn("value too big for the length of the write: "
			    "supplied %llu bytes but maximum is %llu bytes\n",
			    (u_longlong_t)write_len, (u_longlong_t)size);
			return (addr);
		}
	}

	switch (size) {
	case 1:
		return (write_uint8(as, addr, val, rdback));
	case 2:
		return (write_uint16(as, addr, val, rdback));
	case 4:
		return (write_uint32(as, addr, val, rdback));
	case 8:
		return (write_uint64(as, addr, val, rdback));
	default:
		mdb_warn("writes of size %u are not supported\n ", size);
		return (addr);
	}
}

static mdb_tgt_addr_t
write_ctf_uint(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t n, uint_t rdback)
{
	mdb_ctf_id_t mid;
	size_t size;
	ssize_t type_size;
	int kind;

	if (mdb_ctf_lookup_by_addr(addr, &mid) != 0) {
		mdb_warn("no CTF data found at this address\n");
		return (addr);
	}

	kind = mdb_ctf_type_kind(mid);
	if (kind == CTF_ERR) {
		mdb_warn("CTF data found but type kind could not be read");
		return (addr);
	}

	if (kind == CTF_K_TYPEDEF) {
		mdb_ctf_id_t temp_id;
		if (mdb_ctf_type_resolve(mid, &temp_id) != 0) {
			mdb_warn("failed to resolve type");
			return (addr);
		}
		kind = mdb_ctf_type_kind(temp_id);
	}

	if (kind != CTF_K_INTEGER && kind != CTF_K_POINTER &&
	    kind != CTF_K_ENUM) {
		mdb_warn("CTF type should be integer, pointer, or enum\n");
		return (addr);
	}

	type_size = mdb_ctf_type_size(mid);
	if (type_size < 0) {
		mdb_warn("CTF data found but size could not be read");
		return (addr);
	}
	size = type_size;

	return (write_var_uint(as, addr, n, size, rdback));
}

static int
write_arglist(mdb_tgt_as_t as, mdb_tgt_addr_t addr,
    int argc, const mdb_arg_t *argv)
{
	mdb_tgt_addr_t (*write_value)(mdb_tgt_as_t, mdb_tgt_addr_t,
	    uint64_t, uint_t);
	mdb_tgt_addr_t naddr;
	uintmax_t value;
	int rdback = mdb.m_flags & MDB_FL_READBACK;
	size_t i;

	if (argc == 1) {
		mdb_warn("expected value to write following %c\n",
		    argv->a_un.a_char);
		return (DCMD_ERR);
	}

	switch (argv->a_un.a_char) {
	case 'v':
		write_value = write_uint8;
		break;
	case 'w':
		write_value = write_uint16;
		break;
	case 'z':
		write_value = write_ctf_uint;
		break;
	case 'W':
		write_value = write_uint32;
		break;
	case 'Z':
		write_value = write_uint64;
		break;
	}

	for (argv++, i = 1; i < argc; i++, argv++) {
		if (argv->a_type == MDB_TYPE_CHAR) {
			mdb_warn("expected immediate value instead of '%c'\n",
			    argv->a_un.a_char);
			return (DCMD_ERR);
		}

		if (argv->a_type == MDB_TYPE_STRING) {
			if (mdb_eval(argv->a_un.a_str) == -1) {
				mdb_warn("failed to write \"%s\"",
				    argv->a_un.a_str);
				return (DCMD_ERR);
			}
			value = mdb_nv_get_value(mdb.m_dot);
		} else
			value = argv->a_un.a_val;

		mdb_nv_set_value(mdb.m_dot, addr);

		if ((naddr = write_value(as, addr, value, rdback)) == addr) {
			mdb_warn("failed to write %llr at address 0x%llx",
			    value, addr);
			mdb.m_incr = 0;
			return (DCMD_ERR);
		}

		mdb.m_incr = naddr - addr;
		addr = naddr;
	}

	return (DCMD_OK);
}

static mdb_tgt_addr_t
match_uint16(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t v64, uint64_t m64)
{
	uint16_t x, val = (uint16_t)v64, mask = (uint16_t)m64;

	for (; mdb_tgt_aread(mdb.m_target, as, &x,
	    sizeof (x), addr) == sizeof (x); addr += sizeof (x)) {

		if ((x & mask) == val) {
			mdb_iob_printf(mdb.m_out, "%lla\n", addr);
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
match_uint32(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t v64, uint64_t m64)
{
	uint32_t x, val = (uint32_t)v64, mask = (uint32_t)m64;

	for (; mdb_tgt_aread(mdb.m_target, as, &x,
	    sizeof (x), addr) == sizeof (x); addr += sizeof (x)) {

		if ((x & mask) == val) {
			mdb_iob_printf(mdb.m_out, "%lla\n", addr);
			break;
		}
	}
	return (addr);
}

static mdb_tgt_addr_t
match_uint64(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint64_t val, uint64_t mask)
{
	uint64_t x;

	for (; mdb_tgt_aread(mdb.m_target, as, &x,
	    sizeof (x), addr) == sizeof (x); addr += sizeof (x)) {

		if ((x & mask) == val) {
			mdb_iob_printf(mdb.m_out, "%lla\n", addr);
			break;
		}
	}
	return (addr);
}

static int
match_arglist(mdb_tgt_as_t as, uint_t flags, mdb_tgt_addr_t addr,
    int argc, const mdb_arg_t *argv)
{
	mdb_tgt_addr_t (*match_value)(mdb_tgt_as_t, mdb_tgt_addr_t,
	    uint64_t, uint64_t);

	uint64_t args[2] = { 0, -1ULL }; /* [ value, mask ] */
	size_t i;

	if (argc < 2) {
		mdb_warn("expected value following %c\n", argv->a_un.a_char);
		return (DCMD_ERR);
	}

	if (argc > 3) {
		mdb_warn("only value and mask may follow %c\n",
		    argv->a_un.a_char);
		return (DCMD_ERR);
	}

	switch (argv->a_un.a_char) {
	case 'l':
		match_value = match_uint16;
		break;
	case 'L':
		match_value = match_uint32;
		break;
	case 'M':
		match_value = match_uint64;
		break;
	}

	for (argv++, i = 1; i < argc; i++, argv++) {
		if (argv->a_type == MDB_TYPE_CHAR) {
			mdb_warn("expected immediate value instead of '%c'\n",
			    argv->a_un.a_char);
			return (DCMD_ERR);
		}

		if (argv->a_type == MDB_TYPE_STRING) {
			if (mdb_eval(argv->a_un.a_str) == -1) {
				mdb_warn("failed to evaluate \"%s\"",
				    argv->a_un.a_str);
				return (DCMD_ERR);
			}
			args[i - 1] = mdb_nv_get_value(mdb.m_dot);
		} else
			args[i - 1] = argv->a_un.a_val;
	}

	addr = match_value(as, addr, args[0], args[1]);
	mdb_nv_set_value(mdb.m_dot, addr);

	/*
	 * In adb(1), the match operators ignore any repeat count that has
	 * been applied to them.  We emulate this undocumented property
	 * by returning DCMD_ABORT if our input is not a pipeline.
	 */
	return ((flags & DCMD_PIPE) ? DCMD_OK : DCMD_ABORT);
}

static int
argncmp(int argc, const mdb_arg_t *argv, const char *s)
{
	for (; *s != '\0'; s++, argc--, argv++) {
		if (argc == 0 || argv->a_type != MDB_TYPE_CHAR)
			return (FALSE);
		if (argv->a_un.a_char != *s)
			return (FALSE);
	}
	return (TRUE);
}

static int
print_arglist(mdb_tgt_as_t as, mdb_tgt_addr_t addr, uint_t flags,
    int argc, const mdb_arg_t *argv)
{
	char buf[MDB_TGT_SYM_NAMLEN];
	mdb_tgt_addr_t oaddr = addr;
	mdb_tgt_addr_t naddr;
	GElf_Sym sym;
	size_t i, n;

	if (DCMD_HDRSPEC(flags) && (flags & DCMD_PIPE_OUT) == 0) {
		const char *fmt;
		int is_dis;
		/*
		 * This is nasty, but necessary for precise adb compatibility.
		 * Detect disassembly format by looking for "ai" or "ia":
		 */
		if (argncmp(argc, argv, "ai")) {
			fmt = "%-#*lla\n";
			is_dis = TRUE;
		} else if (argncmp(argc, argv, "ia")) {
			fmt = "%-#*lla";
			is_dis = TRUE;
		} else {
			fmt = "%-#*lla%16T";
			is_dis = FALSE;
		}

		/*
		 * If symbolic decoding is on, disassembly is off, and the
		 * address exactly matches a symbol, print the symbol name:
		 */
		if ((mdb.m_flags & MDB_FL_PSYM) && !is_dis &&
		    (as == MDB_TGT_AS_VIRT || as == MDB_TGT_AS_FILE) &&
		    mdb_tgt_lookup_by_addr(mdb.m_target, (uintptr_t)addr,
		    MDB_TGT_SYM_EXACT, buf, sizeof (buf), &sym, NULL) == 0)
			mdb_iob_printf(mdb.m_out, "%s:\n", buf);

		/*
		 * If this is a virtual address, cast it so that it reflects
		 * only the valid component of the address.
		 */
		if (as == MDB_TGT_AS_VIRT)
			addr = (uintptr_t)addr;

		mdb_iob_printf(mdb.m_out, fmt,
		    (uint_t)mdb_iob_getmargin(mdb.m_out), addr);
	}

	if (argc == 0) {
		/*
		 * Yes, for you trivia buffs: if you use a format verb and give
		 * no format string, you get: X^"= "i ... note that in adb the
		 * the '=' verb once had 'z' as its default, but then 'z' was
		 * deleted (it was once an alias for 'i') and so =\n now calls
		 * scanform("z") and produces a 'bad modifier' message.
		 */
		static const mdb_arg_t def_argv[] = {
			{ MDB_TYPE_CHAR, MDB_INIT_CHAR('X') },
			{ MDB_TYPE_CHAR, MDB_INIT_CHAR('^') },
			{ MDB_TYPE_STRING, MDB_INIT_STRING("= ") },
			{ MDB_TYPE_CHAR, MDB_INIT_CHAR('i') }
		};

		argc = sizeof (def_argv) / sizeof (mdb_arg_t);
		argv = def_argv;
	}

	mdb_iob_setflags(mdb.m_out, MDB_IOB_INDENT);

	for (i = 0, n = 1; i < argc; i++, argv++) {
		switch (argv->a_type) {
		case MDB_TYPE_CHAR:
			naddr = mdb_fmt_print(mdb.m_target, as, addr, n,
			    argv->a_un.a_char);
			mdb.m_incr = naddr - addr;
			addr = naddr;
			n = 1;
			break;

		case MDB_TYPE_IMMEDIATE:
			n = argv->a_un.a_val;
			break;

		case MDB_TYPE_STRING:
			mdb_iob_puts(mdb.m_out, argv->a_un.a_str);
			n = 1;
			break;
		}
	}

	mdb.m_incr = addr - oaddr;
	mdb_iob_clrflags(mdb.m_out, MDB_IOB_INDENT);
	return (DCMD_OK);
}

static int
print_common(mdb_tgt_as_t as, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_addr_t addr = mdb_nv_get_value(mdb.m_dot);

	if (argc != 0 && argv->a_type == MDB_TYPE_CHAR) {
		if (strchr("vwzWZ", argv->a_un.a_char))
			return (write_arglist(as, addr, argc, argv));
		if (strchr("lLM", argv->a_un.a_char))
			return (match_arglist(as, flags, addr, argc, argv));
	}

	return (print_arglist(as, addr, flags, argc, argv));
}

/*ARGSUSED*/
static int
cmd_print_core(uintptr_t x, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (print_common(MDB_TGT_AS_VIRT, flags, argc, argv));
}

#ifndef _KMDB
/*ARGSUSED*/
static int
cmd_print_object(uintptr_t x, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (print_common(MDB_TGT_AS_FILE, flags, argc, argv));
}
#endif

/*ARGSUSED*/
static int
cmd_print_phys(uintptr_t x, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (print_common(MDB_TGT_AS_PHYS, flags, argc, argv));
}

/*ARGSUSED*/
static int
cmd_print_value(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintmax_t ndot, dot = mdb_get_dot();
	const char *tgt_argv[1];
	mdb_tgt_t *t;
	size_t i, n;

	if (argc == 0) {
		mdb_warn("expected one or more format characters "
		    "following '='\n");
		return (DCMD_ERR);
	}

	tgt_argv[0] = (const char *)&dot;
	t = mdb_tgt_create(mdb_value_tgt_create, 0, 1, tgt_argv);
	mdb_iob_setflags(mdb.m_out, MDB_IOB_INDENT);

	for (i = 0, n = 1; i < argc; i++, argv++) {
		switch (argv->a_type) {
		case MDB_TYPE_CHAR:
			ndot = mdb_fmt_print(t, MDB_TGT_AS_VIRT,
			    dot, n, argv->a_un.a_char);
			if (argv->a_un.a_char == '+' ||
			    argv->a_un.a_char == '-')
				dot = ndot;
			n = 1;
			break;

		case MDB_TYPE_IMMEDIATE:
			n = argv->a_un.a_val;
			break;

		case MDB_TYPE_STRING:
			mdb_iob_puts(mdb.m_out, argv->a_un.a_str);
			n = 1;
			break;
		}
	}

	mdb_iob_clrflags(mdb.m_out, MDB_IOB_INDENT);
	mdb_nv_set_value(mdb.m_dot, dot);
	mdb.m_incr = 0;

	mdb_tgt_destroy(t);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_assign_variable(uintptr_t addr, uint_t flags,
    int argc, const mdb_arg_t *argv)
{
	uintmax_t dot = mdb_nv_get_value(mdb.m_dot);
	const char *p;
	mdb_var_t *v;

	if (argc == 2) {
		if (argv->a_type != MDB_TYPE_CHAR) {
			mdb_warn("improper arguments following '>' operator\n");
			return (DCMD_ERR);
		}

		switch (argv->a_un.a_char) {
		case 'c':
			addr = *((uchar_t *)&addr);
			break;
		case 's':
			addr = *((ushort_t *)&addr);
			break;
		case 'i':
			addr = *((uint_t *)&addr);
			break;
		case 'l':
			addr = *((ulong_t *)&addr);
			break;
		default:
			mdb_warn("%c is not a valid // modifier\n",
			    argv->a_un.a_char);
			return (DCMD_ERR);
		}

		dot = addr;
		argv++;
		argc--;
	}

	if (argc != 1 || argv->a_type != MDB_TYPE_STRING) {
		mdb_warn("expected single variable name following '>'\n");
		return (DCMD_ERR);
	}

	if (strlen(argv->a_un.a_str) >= (size_t)MDB_NV_NAMELEN) {
		mdb_warn("variable names may not exceed %d characters\n",
		    MDB_NV_NAMELEN - 1);
		return (DCMD_ERR);
	}

	if ((p = strbadid(argv->a_un.a_str)) != NULL) {
		mdb_warn("'%c' may not be used in a variable name\n", *p);
		return (DCMD_ERR);
	}

	if ((v = mdb_nv_lookup(&mdb.m_nv, argv->a_un.a_str)) == NULL)
		(void) mdb_nv_insert(&mdb.m_nv, argv->a_un.a_str, NULL, dot, 0);
	else
		mdb_nv_set_value(v, dot);

	mdb.m_incr = 0;
	return (DCMD_OK);
}

static int
print_soutype(const char *sou, uintptr_t addr, uint_t flags)
{
	static const char *prefixes[] = { "struct ", "union " };
	size_t namesz = 7 + strlen(sou) + 1;
	char *name = mdb_alloc(namesz, UM_SLEEP | UM_GC);
	mdb_ctf_id_t id;
	int i;

	for (i = 0; i < 2; i++) {
		(void) mdb_snprintf(name, namesz, "%s%s", prefixes[i], sou);

		if (mdb_ctf_lookup_by_name(name, &id) == 0) {
			mdb_arg_t v;
			int rv;

			v.a_type = MDB_TYPE_STRING;
			v.a_un.a_str = name;

			rv = mdb_call_dcmd("print", addr, flags, 1, &v);
			return (rv);
		}
	}

	return (DCMD_ERR);
}

static int
print_type(const char *name, uintptr_t addr, uint_t flags)
{
	mdb_ctf_id_t id;
	char *sname;
	size_t snamesz;
	int rv;

	if (!(flags & DCMD_ADDRSPEC)) {
		addr = mdb_get_dot();
		flags |= DCMD_ADDRSPEC;
	}

	if ((rv = print_soutype(name, addr, flags)) != DCMD_ERR)
		return (rv);

	snamesz = strlen(name) + 3;
	sname = mdb_zalloc(snamesz, UM_SLEEP | UM_GC);
	(void) mdb_snprintf(sname, snamesz, "%s_t", name);

	if (mdb_ctf_lookup_by_name(sname, &id) == 0) {
		mdb_arg_t v;
		int rv;

		v.a_type = MDB_TYPE_STRING;
		v.a_un.a_str = sname;

		rv = mdb_call_dcmd("print", addr, flags, 1, &v);
		return (rv);
	}

	sname[snamesz - 2] = 's';
	rv = print_soutype(sname, addr, flags);
	return (rv);
}

static int
exec_alias(const char *fname, uintptr_t addr, uint_t flags)
{
	const char *alias;
	int rv;

	if ((alias = mdb_macalias_lookup(fname)) == NULL)
		return (DCMD_ERR);

	if (flags & DCMD_ADDRSPEC) {
		size_t sz = sizeof (uintptr_t) * 2 + strlen(alias) + 1;
		char *addralias = mdb_alloc(sz, UM_SLEEP | UM_GC);
		(void) mdb_snprintf(addralias, sz, "%p%s", addr, alias);
		rv = mdb_eval(addralias);
	} else {
		rv = mdb_eval(alias);
	}

	return (rv == -1 ? DCMD_ABORT : DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_src_file(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *fname;
	mdb_io_t *fio;
	int rv;

	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	fname = argv->a_un.a_str;

	if (flags & DCMD_PIPE_OUT) {
		mdb_warn("macro files cannot be used as input to a pipeline\n");
		return (DCMD_ABORT);
	}

	if ((fio = mdb_fdio_create_path(mdb.m_ipath, fname,
	    O_RDONLY, 0)) != NULL) {
		mdb_frame_t *fp = mdb.m_frame;
		int err;

		mdb_iob_stack_push(&fp->f_istk, mdb.m_in, yylineno);
		mdb.m_in = mdb_iob_create(fio, MDB_IOB_RDONLY);
		err = mdb_run();

		ASSERT(fp == mdb.m_frame);
		mdb.m_in = mdb_iob_stack_pop(&fp->f_istk);
		yylineno = mdb_iob_lineno(mdb.m_in);

		if (err == MDB_ERR_PAGER && mdb.m_fmark != fp)
			longjmp(fp->f_pcb, err);

		if (err == MDB_ERR_QUIT || err == MDB_ERR_ABORT ||
		    err == MDB_ERR_SIGINT || err == MDB_ERR_OUTPUT)
			longjmp(fp->f_pcb, err);

		return (DCMD_OK);
	}

	if ((rv = exec_alias(fname, addr, flags)) != DCMD_ERR ||
	    (rv = print_type(fname, addr, flags)) != DCMD_ERR)
		return (rv);

	mdb_warn("failed to open %s (see ::help '$<')\n", fname);
	return (DCMD_ABORT);
}

static int
cmd_exec_file(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *fname;
	mdb_io_t *fio;
	int rv;

	/*
	 * The syntax [expr[,count]]$< with no trailing macro file name is
	 * magic in that if count is zero, this command won't be called and
	 * the expression is thus a no-op.  If count is non-zero, we get
	 * invoked with argc == 0, and this means abort the current macro.
	 * If our debugger stack depth is greater than one, we may be using
	 * $< from within a previous $<<, so in that case we set m_in to
	 * NULL to force this entire frame to be popped.
	 */
	if (argc == 0) {
		if (mdb_iob_stack_size(&mdb.m_frame->f_istk) != 0) {
			mdb_iob_destroy(mdb.m_in);
			mdb.m_in = mdb_iob_stack_pop(&mdb.m_frame->f_istk);
		} else if (mdb.m_depth > 1) {
			mdb_iob_destroy(mdb.m_in);
			mdb.m_in = NULL;
		} else
			mdb_warn("input stack is empty\n");
		return (DCMD_OK);
	}

	if ((flags & (DCMD_PIPE | DCMD_PIPE_OUT)) || mdb.m_depth == 1)
		return (cmd_src_file(addr, flags, argc, argv));

	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	fname = argv->a_un.a_str;

	if ((fio = mdb_fdio_create_path(mdb.m_ipath, fname,
	    O_RDONLY, 0)) != NULL) {
		mdb_iob_destroy(mdb.m_in);
		mdb.m_in = mdb_iob_create(fio, MDB_IOB_RDONLY);
		return (DCMD_OK);
	}

	if ((rv = exec_alias(fname, addr, flags)) != DCMD_ERR ||
	    (rv = print_type(fname, addr, flags)) != DCMD_ERR)
		return (rv);

	mdb_warn("failed to open %s (see ::help '$<')\n", fname);
	return (DCMD_ABORT);
}

#ifndef _KMDB
/*ARGSUSED*/
static int
cmd_cat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status = DCMD_OK;
	char buf[BUFSIZ];
	mdb_iob_t *iob;
	mdb_io_t *fio;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	for (; argc-- != 0; argv++) {
		if (argv->a_type != MDB_TYPE_STRING) {
			mdb_warn("expected string argument\n");
			status = DCMD_ERR;
			continue;
		}

		if ((fio = mdb_fdio_create_path(NULL,
		    argv->a_un.a_str, O_RDONLY, 0)) == NULL) {
			mdb_warn("failed to open %s", argv->a_un.a_str);
			status = DCMD_ERR;
			continue;
		}

		iob = mdb_iob_create(fio, MDB_IOB_RDONLY);

		while (!(mdb_iob_getflags(iob) & (MDB_IOB_EOF | MDB_IOB_ERR))) {
			ssize_t len = mdb_iob_read(iob, buf, sizeof (buf));
			if (len > 0) {
				if (mdb_iob_write(mdb.m_out, buf, len) < 0) {
					if (errno != EPIPE)
						mdb_warn("write failed");
					status = DCMD_ERR;
					break;
				}
			}
		}

		if (mdb_iob_err(iob))
			mdb_warn("error while reading %s", mdb_iob_name(iob));

		mdb_iob_destroy(iob);
	}

	return (status);
}
#endif

/*ARGSUSED*/
static int
cmd_grep(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (mdb_eval(argv->a_un.a_str) == -1)
		return (DCMD_ABORT);

	if (mdb_get_dot() != 0)
		mdb_printf("%lr\n", addr);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_map(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (mdb_eval(argv->a_un.a_str) == -1)
		return (DCMD_ABORT);

	mdb_printf("%llr\n", mdb_get_dot());
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_notsup(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_warn("command is not supported by current target\n");
	return (DCMD_ERR);
}

/*ARGSUSED*/
static int
cmd_quit(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
#ifdef _KMDB
	uint_t opt_u = FALSE;

	if (mdb_getopts(argc, argv,
	    'u', MDB_OPT_SETBITS, TRUE, &opt_u, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_u) {
		if (mdb.m_flags & MDB_FL_NOUNLOAD) {
			warn("%s\n", mdb_strerror(EMDB_KNOUNLOAD));
			return (DCMD_ERR);
		}

		kmdb_kdi_set_unload_request();
	}
#endif

	longjmp(mdb.m_frame->f_pcb, MDB_ERR_QUIT);
	/*NOTREACHED*/
	return (DCMD_ERR);
}

#ifdef _KMDB
static void
quit_help(void)
{
	mdb_printf(
	    "-u    unload the debugger (if not loaded at boot)\n");
}
#endif

/*ARGSUSED*/
static int
cmd_vars(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_nz = FALSE, opt_tag = FALSE, opt_prt = FALSE;
	mdb_var_t *v;

	if (mdb_getopts(argc, argv,
	    'n', MDB_OPT_SETBITS, TRUE, &opt_nz,
	    'p', MDB_OPT_SETBITS, TRUE, &opt_prt,
	    't', MDB_OPT_SETBITS, TRUE, &opt_tag, NULL) != argc)
		return (DCMD_USAGE);

	mdb_nv_rewind(&mdb.m_nv);

	while ((v = mdb_nv_advance(&mdb.m_nv)) != NULL) {
		if ((opt_tag == FALSE || (v->v_flags & MDB_NV_TAGGED)) &&
		    (opt_nz == FALSE || mdb_nv_get_value(v) != 0)) {
			if (opt_prt) {
				mdb_printf("%#llr>%s\n",
				    mdb_nv_get_value(v), mdb_nv_get_name(v));
			} else {
				mdb_printf("%s = %llr\n",
				    mdb_nv_get_name(v), mdb_nv_get_value(v));
			}
		}
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_nzvars(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintmax_t value;
	mdb_var_t *v;

	if (argc != 0)
		return (DCMD_USAGE);

	mdb_nv_rewind(&mdb.m_nv);

	while ((v = mdb_nv_advance(&mdb.m_nv)) != NULL) {
		if ((value = mdb_nv_get_value(v)) != 0)
			mdb_printf("%s = %llr\n", mdb_nv_get_name(v), value);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_radix(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if (flags & DCMD_ADDRSPEC) {
		if (addr < 2 || addr > 16) {
			mdb_warn("expected radix from 2 to 16\n");
			return (DCMD_ERR);
		}
		mdb.m_radix = (int)addr;
	}

	mdb_iob_printf(mdb.m_out, "radix = %d base ten\n", mdb.m_radix);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_symdist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if (flags & DCMD_ADDRSPEC)
		mdb.m_symdist = addr;

	mdb_printf("symbol matching distance = %lr (%s)\n",
	    mdb.m_symdist, mdb.m_symdist ? "absolute mode" : "smart mode");

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_pgwidth(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if (flags & DCMD_ADDRSPEC)
		mdb_iob_resize(mdb.m_out, mdb.m_out->iob_rows, addr);

	mdb_printf("output page width = %lu\n", mdb.m_out->iob_cols);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_reopen(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_tgt_setflags(mdb.m_target, MDB_TGT_F_RDWR) == -1) {
		mdb_warn("failed to re-open target for writing");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
print_xdata(void *ignored, const char *name, const char *desc, size_t nbytes)
{
	mdb_printf("%-24s - %s (%lu bytes)\n", name, desc, (ulong_t)nbytes);
	return (0);
}

/*ARGSUSED*/
static int
cmd_xdata(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0 || (flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	(void) mdb_tgt_xdata_iter(mdb.m_target, print_xdata, NULL);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_unset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_var_t *v;
	size_t i;

	for (i = 0; i < argc; i++) {
		if (argv[i].a_type != MDB_TYPE_STRING) {
			mdb_warn("bad option: arg %lu is not a string\n",
			    (ulong_t)i + 1);
			return (DCMD_USAGE);
		}
	}

	for (i = 0; i < argc; i++, argv++) {
		if ((v = mdb_nv_lookup(&mdb.m_nv, argv->a_un.a_str)) == NULL)
			mdb_warn("variable '%s' not defined\n",
			    argv->a_un.a_str);
		else
			mdb_nv_remove(&mdb.m_nv, v);
	}

	return (DCMD_OK);
}

#ifndef _KMDB
/*ARGSUSED*/
static int
cmd_log(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_e = FALSE, opt_d = FALSE;
	const char *filename = NULL;
	int i;

	i = mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &opt_d,
	    'e', MDB_OPT_SETBITS, TRUE, &opt_e, NULL);

	if ((i != argc && i != argc - 1) || (opt_d && opt_e) ||
	    (i != argc && argv[i].a_type != MDB_TYPE_STRING) ||
	    (i != argc && opt_d == TRUE) || (flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb.m_depth != 1) {
		mdb_warn("log may not be manipulated in this context\n");
		return (DCMD_ABORT);
	}

	if (i != argc)
		filename = argv[i].a_un.a_str;

	/*
	 * If no arguments were specified, print the log file name (if any)
	 * and report whether the log is enabled or disabled.
	 */
	if (argc == 0) {
		if (mdb.m_log) {
			mdb_printf("%s: logging to \"%s\" is currently %s\n",
			    mdb.m_pname, IOP_NAME(mdb.m_log),
			    mdb.m_flags & MDB_FL_LOG ?  "enabled" : "disabled");
		} else
			mdb_printf("%s: no log is active\n", mdb.m_pname);
		return (DCMD_OK);
	}

	/*
	 * If the -d option was specified, pop the log i/o object off the
	 * i/o stack of stdin, stdout, and stderr.
	 */
	if (opt_d) {
		if (mdb.m_flags & MDB_FL_LOG) {
			(void) mdb_iob_pop_io(mdb.m_in);
			(void) mdb_iob_pop_io(mdb.m_out);
			(void) mdb_iob_pop_io(mdb.m_err);
			mdb.m_flags &= ~MDB_FL_LOG;
		} else
			mdb_warn("logging is already disabled\n");
		return (DCMD_OK);
	}

	/*
	 * The -e option is the default: (re-)enable logging by pushing
	 * the log i/o object on to stdin, stdout, and stderr.  If we have
	 * a previous log file, we need to pop it and close it.  If we have
	 * no new log file, push the previous one back on.
	 */
	if (filename != NULL) {
		if (mdb.m_log != NULL) {
			if (mdb.m_flags & MDB_FL_LOG) {
				(void) mdb_iob_pop_io(mdb.m_in);
				(void) mdb_iob_pop_io(mdb.m_out);
				(void) mdb_iob_pop_io(mdb.m_err);
				mdb.m_flags &= ~MDB_FL_LOG;
			}
			mdb_io_rele(mdb.m_log);
		}

		mdb.m_log = mdb_fdio_create_path(NULL, filename,
		    O_CREAT | O_APPEND | O_WRONLY, 0666);

		if (mdb.m_log == NULL) {
			mdb_warn("failed to open %s", filename);
			return (DCMD_ERR);
		}
	}

	if (mdb.m_log != NULL) {
		mdb_iob_push_io(mdb.m_in, mdb_logio_create(mdb.m_log));
		mdb_iob_push_io(mdb.m_out, mdb_logio_create(mdb.m_log));
		mdb_iob_push_io(mdb.m_err, mdb_logio_create(mdb.m_log));

		mdb_printf("%s: logging to \"%s\"\n", mdb.m_pname, filename);
		mdb.m_log = mdb_io_hold(mdb.m_log);
		mdb.m_flags |= MDB_FL_LOG;

		return (DCMD_OK);
	}

	mdb_warn("no log file has been selected\n");
	return (DCMD_ERR);
}

static int
cmd_old_log(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc == 0) {
		mdb_arg_t arg = { MDB_TYPE_STRING, MDB_INIT_STRING("-d") };
		return (cmd_log(addr, flags, 1, &arg));
	}

	return (cmd_log(addr, flags, argc, argv));
}
#endif

/*ARGSUSED*/
static int
cmd_load(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i, mode = MDB_MOD_LOCAL;

	i = mdb_getopts(argc, argv,
#ifdef _KMDB
	    'd', MDB_OPT_SETBITS, MDB_MOD_DEFER, &mode,
#endif
	    'f', MDB_OPT_SETBITS, MDB_MOD_FORCE, &mode,
	    'g', MDB_OPT_SETBITS, MDB_MOD_GLOBAL, &mode,
	    's', MDB_OPT_SETBITS, MDB_MOD_SILENT, &mode,
	    NULL);

	argc -= i;
	argv += i;

	if ((flags & DCMD_ADDRSPEC) || argc != 1 ||
	    argv->a_type != MDB_TYPE_STRING ||
	    strchr("+-", argv->a_un.a_str[0]) != NULL)
		return (DCMD_USAGE);

	if (mdb_module_load(argv->a_un.a_str, mode) < 0)
		return (DCMD_ERR);

	return (DCMD_OK);
}

static void
load_help(void)
{
	mdb_printf(
#ifdef _KMDB
	    "-d    defer load until next continue\n"
#endif
	    "-s    load module silently\n");
}

/*ARGSUSED*/
static int
cmd_unload(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int mode = 0;
	int i;

	i = mdb_getopts(argc, argv,
#ifdef _KMDB
	    'd', MDB_OPT_SETBITS, MDB_MOD_DEFER, &mode,
#endif
	    NULL);

	argc -= i;
	argv += i;

	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (mdb_module_unload(argv->a_un.a_str, mode) == -1) {
		mdb_warn("failed to unload %s", argv->a_un.a_str);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

#ifdef _KMDB
static void
unload_help(void)
{
	mdb_printf(
	    "-d    defer unload until next continue\n");
}
#endif

static int
cmd_dbmode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc > 1 || (argc != 0 && (flags & DCMD_ADDRSPEC)))
		return (DCMD_USAGE);

	if (argc != 0) {
		if (argv->a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);
		if ((addr = mdb_dstr2mode(argv->a_un.a_str)) != MDB_DBG_HELP)
			mdb_dmode(addr);
	} else if (flags & DCMD_ADDRSPEC)
		mdb_dmode(addr);

	mdb_printf("debugging mode = 0x%04x\n", mdb.m_debug);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_version(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
#ifdef DEBUG
	mdb_printf("\r%s (DEBUG)\n", mdb_conf_version());
#else
	mdb_printf("\r%s\n", mdb_conf_version());
#endif
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_algol(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (mdb.m_flags & MDB_FL_ADB)
		mdb_printf("No algol 68 here\n");
	else
		mdb_printf("No adb here\n");
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_obey(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (mdb.m_flags & MDB_FL_ADB)
		mdb_printf("CHAPTER 1\n");
	else
		mdb_printf("No Language H here\n");
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
print_global(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	uintptr_t value;

	if (mdb_tgt_vread((mdb_tgt_t *)data, &value, sizeof (value),
	    (uintptr_t)sym->st_value) == sizeof (value))
		mdb_printf("%s(%llr):\t%lr\n", name, sym->st_value, value);
	else
		mdb_printf("%s(%llr):\t?\n", name, sym->st_value);

	return (0);
}

/*ARGSUSED*/
static int
cmd_globals(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	(void) mdb_tgt_symbol_iter(mdb.m_target, MDB_TGT_OBJ_EVERY,
	    MDB_TGT_SYMTAB, MDB_TGT_BIND_GLOBAL | MDB_TGT_TYPE_OBJECT |
	    MDB_TGT_TYPE_FUNC, print_global, mdb.m_target);

	return (0);
}

/*ARGSUSED*/
static int
cmd_eval(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (mdb_eval(argv->a_un.a_str) == -1)
		return (DCMD_ABORT);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
print_file(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	int i = *((int *)data);

	mdb_printf("%d\t%s\n", i++, name);
	*((int *)data) = i;
	return (0);
}

/*ARGSUSED*/
static int
cmd_files(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i = 1;
	const char *obj = MDB_TGT_OBJ_EVERY;

	if ((flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc == 1) {
		if (argv->a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		obj = argv->a_un.a_str;
	}

	(void) mdb_tgt_symbol_iter(mdb.m_target, obj, MDB_TGT_SYMTAB,
	    MDB_TGT_BIND_ANY | MDB_TGT_TYPE_FILE, print_file, &i);

	return (DCMD_OK);
}

static const char *
map_name(const mdb_map_t *map, const char *name)
{
	if (map->map_flags & MDB_TGT_MAP_HEAP)
		return ("[ heap ]");
	if (name != NULL && name[0] != 0)
		return (name);

	if (map->map_flags & MDB_TGT_MAP_SHMEM)
		return ("[ shmem ]");
	if (map->map_flags & MDB_TGT_MAP_STACK)
		return ("[ stack ]");
	if (map->map_flags & MDB_TGT_MAP_ANON)
		return ("[ anon ]");
	if (map->map_name != NULL)
		return (map->map_name);
	return ("[ unknown ]");
}

/*ARGSUSED*/
static int
print_map(void *ignored, const mdb_map_t *map, const char *name)
{
	name = map_name(map, name);

	mdb_printf("%?p %?p %?lx %s\n", map->map_base,
	    map->map_base + map->map_size, map->map_size, name);
	return (0);
}

static int
cmd_mappings(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const mdb_map_t *m;

	if (argc > 1 || (argc != 0 && (flags & DCMD_ADDRSPEC)))
		return (DCMD_USAGE);

	mdb_printf("%<u>%?s %?s %?s %s%</u>\n",
	    "BASE", "LIMIT", "SIZE", "NAME");

	if (flags & DCMD_ADDRSPEC) {
		if ((m = mdb_tgt_addr_to_map(mdb.m_target, addr)) == NULL)
			mdb_warn("failed to obtain mapping");
		else
			(void) print_map(NULL, m, NULL);

	} else if (argc != 0) {
		if (argv->a_type == MDB_TYPE_STRING)
			m = mdb_tgt_name_to_map(mdb.m_target, argv->a_un.a_str);
		else
			m = mdb_tgt_addr_to_map(mdb.m_target, argv->a_un.a_val);

		if (m == NULL)
			mdb_warn("failed to obtain mapping");
		else
			(void) print_map(NULL, m, NULL);

	} else if (mdb_tgt_mapping_iter(mdb.m_target, print_map, NULL) == -1)
		mdb_warn("failed to iterate over mappings");

	return (DCMD_OK);
}

static int
whatis_map_callback(void *wp, const mdb_map_t *map, const char *name)
{
	mdb_whatis_t *w = wp;
	uintptr_t cur;

	name = map_name(map, name);

	while (mdb_whatis_match(w, map->map_base, map->map_size, &cur))
		mdb_whatis_report_address(w, cur, "in %s [%p,%p)\n",
		    name, map->map_base, map->map_base + map->map_size);

	return (0);
}

/*ARGSUSED*/
int
whatis_run_mappings(mdb_whatis_t *w, void *ignored)
{
	(void) mdb_tgt_mapping_iter(mdb.m_target, whatis_map_callback, w);
	return (0);
}

/*ARGSUSED*/
static int
objects_printversion(void *ignored, const mdb_map_t *map, const char *name)
{
	ctf_file_t *ctfp;
	const char *version;

	ctfp = mdb_tgt_name_to_ctf(mdb.m_target, name);
	if (ctfp == NULL || (version = ctf_label_topmost(ctfp)) == NULL)
		version = "Unknown";

	mdb_printf("%-28s %s\n", name, version);
	return (0);
}

/*ARGSUSED*/
static int
cmd_objects(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;
	mdb_tgt_map_f *cb;

	if ((flags & DCMD_ADDRSPEC) || mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_v) {
		cb = objects_printversion;
		mdb_printf("%<u>%-28s %s%</u>\n", "NAME", "VERSION");
	} else {
		cb = print_map;
		mdb_printf("%<u>%?s %?s %?s %s%</u>\n",
		    "BASE", "LIMIT", "SIZE", "NAME");
	}

	if (mdb_tgt_object_iter(mdb.m_target, cb, NULL) == -1) {
		mdb_warn("failed to iterate over objects");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
showrev_addversion(void *vers_nv, const mdb_map_t *ignored, const char *object)
{
	ctf_file_t *ctfp;
	const char *version = NULL;
	char *objname;

	objname = mdb_alloc(strlen(object) + 1, UM_SLEEP | UM_GC);
	(void) strcpy(objname, object);

	if ((ctfp = mdb_tgt_name_to_ctf(mdb.m_target, objname)) != NULL)
		version = ctf_label_topmost(ctfp);

	/*
	 * Not all objects have CTF and label data, so set version to "Unknown".
	 */
	if (version == NULL)
		version = "Unknown";

	(void) mdb_nv_insert(vers_nv, version, NULL, (uintptr_t)objname,
	    MDB_NV_OVERLOAD);

	return (0);
}

static int
showrev_ispatch(const char *s)
{
	if (s == NULL)
		return (0);

	if (*s == 'T')
		s++; /* skip T for T-patch */

	for (; *s != '\0'; s++) {
		if ((*s < '0' || *s > '9') && *s != '-')
			return (0);
	}

	return (1);
}

/*ARGSUSED*/
static int
showrev_printobject(mdb_var_t *v, void *ignored)
{
	mdb_printf("%s ", MDB_NV_COOKIE(v));
	return (0);
}

static int
showrev_printversion(mdb_var_t *v, void *showall)
{
	const char *version = mdb_nv_get_name(v);
	int patch;

	patch = showrev_ispatch(version);
	if (patch || (uintptr_t)showall) {
		mdb_printf("%s: %s  Objects: ",
		    (patch ? "Patch" : "Version"), version);
		(void) mdb_inc_indent(2);

		mdb_nv_defn_iter(v, showrev_printobject, NULL);

		(void) mdb_dec_indent(2);
		mdb_printf("\n");
	}

	return (0);
}

/*
 * Display version information for each object in the system.
 * Print information about patches only, unless showall is TRUE.
 */
static int
showrev_objectversions(int showall)
{
	mdb_nv_t vers_nv;

	(void) mdb_nv_create(&vers_nv, UM_SLEEP | UM_GC);
	if (mdb_tgt_object_iter(mdb.m_target, showrev_addversion,
	    &vers_nv) == -1) {
		mdb_warn("failed to iterate over objects");
		return (DCMD_ERR);
	}

	mdb_nv_sort_iter(&vers_nv, showrev_printversion,
	    (void *)(uintptr_t)showall, UM_SLEEP | UM_GC);
	return (DCMD_OK);
}

/*
 * Display information similar to what showrev(1M) displays when invoked
 * with no arguments.
 */
static int
showrev_sysinfo(void)
{
	const char *s;
	int rc;
	struct utsname u;

	if ((rc = mdb_tgt_uname(mdb.m_target, &u)) != -1) {
		mdb_printf("Hostname: %s\n", u.nodename);
		mdb_printf("Release: %s\n", u.release);
		mdb_printf("Kernel architecture: %s\n", u.machine);
	}

	/*
	 * Match the order of the showrev(1M) output and put "Application
	 * architecture" before "Kernel version"
	 */
	if ((s = mdb_tgt_isa(mdb.m_target)) != NULL)
		mdb_printf("Application architecture: %s\n", s);

	if (rc != -1)
		mdb_printf("Kernel version: %s %s %s %s\n",
		    u.sysname, u.release, u.machine, u.version);

	if ((s = mdb_tgt_platform(mdb.m_target)) != NULL)
		mdb_printf("Platform: %s\n", s);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_showrev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_p = FALSE, opt_v = FALSE;

	if ((flags & DCMD_ADDRSPEC) || mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, TRUE, &opt_p,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_p || opt_v)
		return (showrev_objectversions(opt_v));
	else
		return (showrev_sysinfo());
}

#ifdef __sparc
static void
findsym_output(uintptr_t *symlist, uintptr_t value, uintptr_t location)
{
	uintptr_t	*symbolp;

	for (symbolp = symlist; *symbolp; symbolp++)
		if (value == *symbolp)
			mdb_printf("found %a at %a\n", value, location);
}

/*ARGSUSED*/
static int
findsym_cb(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	uint32_t	*text;
	int		len;
	int		i;
	int		j;
	uint8_t		rd;
	uintptr_t	value;
	int32_t		imm13;
	uint8_t		op;
	uint8_t		op3;
	uintptr_t	*symlist = data;
	size_t		size = sym->st_size;

	/*
	 * if the size of the symbol is 0, then this symbol must be for an
	 * alternate entry point or just some global label. We will,
	 * therefore, get back to the text that follows this symbol in
	 * some other symbol
	 */
	if (size == 0)
		return (0);

	if (sym->st_shndx == SHN_UNDEF)
		return (0);

	text = alloca(size);

	if (mdb_vread(text, size, sym->st_value) == -1) {
		mdb_warn("failed to read text for %s", name);
		return (0);
	}

	len = size / 4;
	for (i = 0; i < len; i++) {
		if (!IS_SETHI(text[i]))
			continue;

		rd = RD(text[i]);
		value = IMM22(text[i]) << 10;

		/*
		 * see if we already have a match with just the sethi
		 */
		findsym_output(symlist, value, sym->st_value + i * 4);

		/*
		 * search from the sethi on until we hit a relevant instr
		 */
		for (j = i + 1; j < len; j++) {
			if ((op = OP(text[j])) & OP_ARITH_MEM_MASK) {
				op3 = OP3(text[j]);

				if (RS1(text[j]) != rd)
					goto instr_end;

				/*
				 * This is a simple tool; we only deal
				 * with operations which take immediates
				 */
				if (I(text[j]) == 0)
					goto instr_end;

				/*
				 * sign extend the immediate value
				 */
				imm13 = IMM13(text[j]);
				imm13 <<= 19;
				imm13 >>= 19;

				if (op == OP_ARITH) {
					/* arithmetic operations */
					if (op3 & OP3_COMPLEX_MASK)
						goto instr_end;

					switch (op3 & ~OP3_CC_MASK) {
					case OP3_OR:
						value |= imm13;
						break;
					case OP3_ADD:
						value += imm13;
						break;
					case OP3_XOR:
						value ^= imm13;
						break;
					default:
						goto instr_end;
					}
				} else {
					/* loads and stores */
					/* op3 == OP_MEM */

					value += imm13;
				}

				findsym_output(symlist, value,
				    sym->st_value + j * 4);
instr_end:
				/*
				 * if we're clobbering rd, break
				 */
				if (RD(text[j]) == rd)
					break;
			} else if (IS_SETHI(text[j])) {
				if (RD(text[j]) == rd)
					break;
			} else if (OP(text[j]) == 1) {
				/*
				 * see if a call clobbers an %o or %g
				 */
				if (rd <= R_O7)
					break;
			}
		}
	}

	return (0);
}

static int
cmd_findsym(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t *symlist;
	uint_t optg = FALSE;
	uint_t type;
	int len, i;

	i = mdb_getopts(argc, argv, 'g', MDB_OPT_SETBITS, TRUE, &optg, NULL);

	argc -= i;
	argv += i;

	len = argc + ((flags & DCMD_ADDRSPEC) ? 1 : 0) + 1;

	if (len <= 1)
		return (DCMD_USAGE);

	/*
	 * Set up a NULL-terminated symbol list, and then iterate over the
	 * symbol table, scanning each function for references to these symbols.
	 */
	symlist = mdb_alloc(len * sizeof (uintptr_t), UM_SLEEP | UM_GC);
	len = 0;

	for (i = 0; i < argc; i++, argv++) {
		const char *str = argv->a_un.a_str;
		uintptr_t value;
		GElf_Sym sym;

		if (argv->a_type == MDB_TYPE_STRING) {
			if (strchr("+-", str[0]) != NULL)
				return (DCMD_USAGE);
			else if (str[0] >= '0' && str[0] <= '9')
				value = mdb_strtoull(str);
			else if (mdb_lookup_by_name(str, &sym) != 0) {
				mdb_warn("symbol '%s' not found", str);
				return (DCMD_USAGE);
			} else
				value = sym.st_value;
		} else
			value = argv[i].a_un.a_val;

		if (value != NULL)
			symlist[len++] = value;
	}

	if (flags & DCMD_ADDRSPEC)
		symlist[len++] = addr;

	symlist[len] = NULL;

	if (optg)
		type = MDB_TGT_BIND_GLOBAL | MDB_TGT_TYPE_FUNC;
	else
		type = MDB_TGT_BIND_ANY | MDB_TGT_TYPE_FUNC;

	if (mdb_tgt_symbol_iter(mdb.m_target, MDB_TGT_OBJ_EVERY,
	    MDB_TGT_SYMTAB, type, findsym_cb, symlist) == -1) {
		mdb_warn("failed to iterate over symbol table");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}
#endif /* __sparc */

static int
dis_str2addr(const char *s, uintptr_t *addr)
{
	GElf_Sym sym;

	if (s[0] >= '0' && s[0] <= '9') {
		*addr = (uintptr_t)mdb_strtoull(s);
		return (0);
	}

	if (mdb_tgt_lookup_by_name(mdb.m_target,
	    MDB_TGT_OBJ_EVERY, s, &sym, NULL) == -1) {
		mdb_warn("symbol '%s' not found\n", s);
		return (-1);
	}

	*addr = (uintptr_t)sym.st_value;
	return (0);
}

static int
cmd_dis(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *tgt = mdb.m_target;
	mdb_disasm_t *dis = mdb.m_disasm;

	uintptr_t oaddr, naddr;
	mdb_tgt_as_t as;
	mdb_tgt_status_t st;
	char buf[BUFSIZ];
	GElf_Sym sym;
	int i;

	uint_t opt_f = FALSE;		/* File-mode off by default */
	uint_t opt_w = FALSE;		/* Window mode off by default */
	uint_t opt_a = FALSE;		/* Raw-address mode off by default */
	uint_t opt_b = FALSE;		/* Address & symbols off by default */
	uintptr_t n = -1UL;		/* Length of window in instructions */
	uintptr_t eaddr = 0;		/* Ending address; 0 if limited by n */

	i = mdb_getopts(argc, argv,
	    'f', MDB_OPT_SETBITS, TRUE, &opt_f,
	    'w', MDB_OPT_SETBITS, TRUE, &opt_w,
	    'a', MDB_OPT_SETBITS, TRUE, &opt_a,
	    'b', MDB_OPT_SETBITS, TRUE, &opt_b,
	    'n', MDB_OPT_UINTPTR, &n, NULL);

	/*
	 * Disgusting argument post-processing ... basically the idea is to get
	 * the target address into addr, which we do by using the specified
	 * expression value, looking up a string as a symbol name, or by
	 * using the address specified as dot.
	 */
	if (i != argc) {
		if (argc != 0 && (argc - i) == 1) {
			if (argv[i].a_type == MDB_TYPE_STRING) {
				if (argv[i].a_un.a_str[0] == '-')
					return (DCMD_USAGE);

				if (dis_str2addr(argv[i].a_un.a_str, &addr))
					return (DCMD_ERR);
			} else
				addr = argv[i].a_un.a_val;
		} else
			return (DCMD_USAGE);
	}

	/*
	 * If we're not in window mode yet, and some type of arguments were
	 * specified, see if the address corresponds nicely to a function.
	 * If not, turn on window mode; otherwise disassemble the function.
	 */
	if (opt_w == FALSE && (argc != i || (flags & DCMD_ADDRSPEC))) {
		if (mdb_tgt_lookup_by_addr(tgt, addr,
		    MDB_TGT_SYM_EXACT, buf, sizeof (buf), &sym, NULL) == 0 &&
		    GELF_ST_TYPE(sym.st_info) == STT_FUNC) {
			/*
			 * If the symbol has a size then set our end address to
			 * be the end of the function symbol we just located.
			 */
			if (sym.st_size != 0)
				eaddr = addr + (uintptr_t)sym.st_size;
		} else
			opt_w = TRUE;
	}

	/*
	 * Window-mode doesn't make sense in a loop.
	 */
	if (flags & DCMD_LOOP)
		opt_w = FALSE;

	/*
	 * If -n was explicit, limit output to n instructions;
	 * otherwise set n to some reasonable default
	 */
	if (n != -1UL)
		eaddr = 0;
	else
		n = 10;

	/*
	 * If the state is IDLE (i.e. no address space), turn on -f.
	 */
	if (mdb_tgt_status(tgt, &st) == 0 && st.st_state == MDB_TGT_IDLE)
		opt_f = TRUE;

	if (opt_f)
		as = MDB_TGT_AS_FILE;
	else
		as = MDB_TGT_AS_VIRT;

	if (opt_w == FALSE) {
		n++;
		while ((eaddr == 0 && n-- != 0) || (addr < eaddr)) {
			naddr = mdb_dis_ins2str(dis, tgt, as,
			    buf, sizeof (buf), addr);
			if (naddr == addr)
				return (DCMD_ERR);
			if (opt_a)
				mdb_printf("%-#32p%8T%s\n", addr, buf);
			else if (opt_b)
				mdb_printf("%-#?p  %-#32a%8T%s\n",
				    addr, addr, buf);
			else
				mdb_printf("%-#32a%8T%s\n", addr, buf);
			addr = naddr;
		}

	} else {
#ifdef __sparc
		if (addr & 0x3) {
			mdb_warn("address is not properly aligned\n");
			return (DCMD_ERR);
		}
#endif

		for (oaddr = mdb_dis_previns(dis, tgt, as, addr, n);
		    oaddr < addr; oaddr = naddr) {
			naddr = mdb_dis_ins2str(dis, tgt, as,
			    buf, sizeof (buf), oaddr);
			if (naddr == oaddr)
				return (DCMD_ERR);
			if (opt_a)
				mdb_printf("%-#32p%8T%s\n", oaddr, buf);
			else if (opt_b)
				mdb_printf("%-#?p  %-#32a%8T%s\n",
				    oaddr, oaddr, buf);
			else
				mdb_printf("%-#32a%8T%s\n", oaddr, buf);
		}

		if ((naddr = mdb_dis_ins2str(dis, tgt, as,
		    buf, sizeof (buf), addr)) == addr)
			return (DCMD_ERR);

		mdb_printf("%<b>");
		mdb_flush();
		if (opt_a)
			mdb_printf("%-#32p%8T%s%", addr, buf);
		else if (opt_b)
			mdb_printf("%-#?p  %-#32a%8T%s", addr, addr, buf);
		else
			mdb_printf("%-#32a%8T%s%", addr, buf);
		mdb_printf("%</b>\n");

		for (addr = naddr; n-- != 0; addr = naddr) {
			naddr = mdb_dis_ins2str(dis, tgt, as,
			    buf, sizeof (buf), addr);
			if (naddr == addr)
				return (DCMD_ERR);
			if (opt_a)
				mdb_printf("%-#32p%8T%s\n", addr, buf);
			else if (opt_b)
				mdb_printf("%-#?p  %-#32a%8T%s\n",
				    addr, addr, buf);
			else
				mdb_printf("%-#32a%8T%s\n", addr, buf);
		}
	}

	mdb_set_dot(addr);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
walk_step(uintptr_t addr, const void *data, void *private)
{
	mdb_printf("%#lr\n", addr);
	return (WALK_NEXT);
}

static int
cmd_walk(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;

	if (argc < 1 || argc > 2 || argv[0].a_type != MDB_TYPE_STRING ||
	    argv[argc - 1].a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (argc > 1) {
		const char *name = argv[1].a_un.a_str;
		mdb_var_t *v = mdb_nv_lookup(&mdb.m_nv, name);
		const char *p;

		if (v != NULL && (v->v_flags & MDB_NV_RDONLY) != 0) {
			mdb_warn("variable %s is read-only\n", name);
			return (DCMD_ABORT);
		}

		if (v == NULL && (p = strbadid(name)) != NULL) {
			mdb_warn("'%c' may not be used in a variable "
			    "name\n", *p);
			return (DCMD_ABORT);
		}

		if (v == NULL && (v = mdb_nv_insert(&mdb.m_nv,
		    name, NULL, 0, 0)) == NULL)
			return (DCMD_ERR);

		/*
		 * If there already exists a vcb for this variable, we may be
		 * calling ::walk in a loop.  We only create a vcb for this
		 * variable on the first invocation.
		 */
		if (mdb_vcb_find(v, mdb.m_frame) == NULL)
			mdb_vcb_insert(mdb_vcb_create(v), mdb.m_frame);
	}

	if (flags & DCMD_ADDRSPEC)
		status = mdb_pwalk(argv->a_un.a_str, walk_step, NULL, addr);
	else
		status = mdb_walk(argv->a_un.a_str, walk_step, NULL);

	if (status == -1) {
		mdb_warn("failed to perform walk");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
cmd_walk_tab(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (argc > 1)
		return (1);

	if (argc == 1) {
		ASSERT(argv[0].a_type == MDB_TYPE_STRING);
		return (mdb_tab_complete_walker(mcp, argv[0].a_un.a_str));
	}

	if (argc == 0 && flags & DCMD_TAB_SPACE)
		return (mdb_tab_complete_walker(mcp, NULL));

	return (1);
}

static ssize_t
mdb_partial_xread(void *buf, size_t nbytes, uintptr_t addr, void *arg)
{
	ssize_t (*fp)(mdb_tgt_t *, const void *, size_t, uintptr_t) =
	    (ssize_t (*)(mdb_tgt_t *, const void *, size_t, uintptr_t))arg;

	return (fp(mdb.m_target, buf, nbytes, addr));
}

/* ARGSUSED3 */
static ssize_t
mdb_partial_pread(void *buf, size_t nbytes, physaddr_t addr, void *arg)
{
	return (mdb_tgt_pread(mdb.m_target, buf, nbytes, addr));
}


static int
cmd_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t dflags =
	    MDB_DUMP_ALIGN | MDB_DUMP_NEWDOT | MDB_DUMP_ASCII | MDB_DUMP_HEADER;
	uint_t phys = FALSE;
	uint_t file = FALSE;
	uintptr_t group = 4;
	uintptr_t length = 0;
	uintptr_t width = 1;
	mdb_tgt_status_t st;
	int error;

	if (mdb_getopts(argc, argv,
	    'e', MDB_OPT_SETBITS, MDB_DUMP_ENDIAN, &dflags,
	    'f', MDB_OPT_SETBITS, TRUE, &file,
	    'g', MDB_OPT_UINTPTR, &group,
	    'l', MDB_OPT_UINTPTR, &length,
	    'p', MDB_OPT_SETBITS, TRUE, &phys,
	    'q', MDB_OPT_CLRBITS, MDB_DUMP_ASCII, &dflags,
	    'r', MDB_OPT_SETBITS, MDB_DUMP_RELATIVE, &dflags,
	    's', MDB_OPT_SETBITS, MDB_DUMP_SQUISH, &dflags,
	    't', MDB_OPT_SETBITS, MDB_DUMP_TRIM, &dflags,
	    'u', MDB_OPT_CLRBITS, MDB_DUMP_ALIGN, &dflags,
	    'v', MDB_OPT_SETBITS, MDB_DUMP_PEDANT, &dflags,
	    'w', MDB_OPT_UINTPTR, &width, NULL) != argc)
		return (DCMD_USAGE);

	if ((phys && file) ||
	    (width == 0) || (width > 0x10) ||
	    (group == 0) || (group > 0x100) ||
	    (mdb.m_dcount > 1 && length > 0))
		return (DCMD_USAGE);
	if (length == 0)
		length = mdb.m_dcount;

	/*
	 * If neither -f nor -p were specified and the state is IDLE (i.e. no
	 * address space), turn on -p.  This is so we can read large files.
	 */
	if (phys == FALSE && file == FALSE && mdb_tgt_status(mdb.m_target,
	    &st) == 0 && st.st_state == MDB_TGT_IDLE)
		phys = TRUE;

	dflags |= MDB_DUMP_GROUP(group) | MDB_DUMP_WIDTH(width);
	if (phys)
		error = mdb_dump64(mdb_get_dot(), length, dflags,
		    mdb_partial_pread, NULL);
	else if (file)
		error = mdb_dumpptr(addr, length, dflags,
		    mdb_partial_xread, (void *)mdb_tgt_fread);
	else
		error = mdb_dumpptr(addr, length, dflags,
		    mdb_partial_xread, (void *)mdb_tgt_vread);

	return (((flags & DCMD_LOOP) || (error == -1)) ? DCMD_ABORT : DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_echo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	for (; argc-- != 0; argv++) {
		if (argv->a_type == MDB_TYPE_STRING)
			mdb_printf("%s ", argv->a_un.a_str);
		else
			mdb_printf("%llr ", argv->a_un.a_val);
	}

	mdb_printf("\n");
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_head(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t cnt = 10;
	const char *c;
	mdb_pipe_t p;

	if (!flags & DCMD_PIPE)
		return (DCMD_USAGE);

	if (argc == 1 || argc == 2) {
		const char *num;

		if (argc == 1) {
			if (argv[0].a_type != MDB_TYPE_STRING ||
			    *argv[0].a_un.a_str != '-')
				return (DCMD_USAGE);

			num = argv[0].a_un.a_str + 1;

		} else {
			if (argv[0].a_type != MDB_TYPE_STRING ||
			    strcmp(argv[0].a_un.a_str, "-n") != 0)
				return (DCMD_USAGE);

			num = argv[1].a_un.a_str;
		}

		for (cnt = 0, c = num; *c != '\0' && isdigit(*c); c++)
			cnt = cnt * 10 + (*c - '0');

		if (*c != '\0')
			return (DCMD_USAGE);

	} else if (argc != 0) {
		return (DCMD_USAGE);
	}

	mdb_get_pipe(&p);

	if (p.pipe_data == NULL)
		return (DCMD_OK);
	p.pipe_len = MIN(p.pipe_len, cnt);

	if (flags & DCMD_PIPE_OUT) {
		mdb_set_pipe(&p);
	} else {
		while (p.pipe_len-- > 0)
			mdb_printf("%lx\n", *p.pipe_data++);
	}

	return (DCMD_OK);
}

static void
head_help(void)
{
	mdb_printf(
	    "-n num\n or\n"
	    "-num   pass only the first `num' elements in the pipe.\n"
	    "\n%<b>Note:%</b> `num' is a decimal number.\n");
}

static int
cmd_typeset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int add_tag = 0, del_tag = 0;
	const char *p;
	mdb_var_t *v;

	if (argc == 0)
		return (cmd_vars(addr, flags, argc, argv));

	if (argv->a_type == MDB_TYPE_STRING && (argv->a_un.a_str[0] == '-' ||
	    argv->a_un.a_str[0] == '+')) {
		if (argv->a_un.a_str[1] != 't')
			return (DCMD_USAGE);
		if (argv->a_un.a_str[0] == '-')
			add_tag++;
		else
			del_tag++;
		argc--;
		argv++;
	}

	if (!(flags & DCMD_ADDRSPEC))
		addr = 0; /* set variables to zero unless explicit addr given */

	for (; argc-- != 0; argv++) {
		if (argv->a_type != MDB_TYPE_STRING)
			continue;

		if (argv->a_un.a_str[0] == '-' || argv->a_un.a_str[0] == '+') {
			mdb_warn("ignored bad option -- %s\n",
			    argv->a_un.a_str);
			continue;
		}

		if ((p = strbadid(argv->a_un.a_str)) != NULL) {
			mdb_warn("'%c' may not be used in a variable "
			    "name\n", *p);
			return (DCMD_ERR);
		}

		if ((v = mdb_nv_lookup(&mdb.m_nv, argv->a_un.a_str)) == NULL) {
			v = mdb_nv_insert(&mdb.m_nv, argv->a_un.a_str,
			    NULL, addr, 0);
		} else if (flags & DCMD_ADDRSPEC)
			mdb_nv_set_value(v, addr);

		if (v != NULL) {
			if (add_tag)
				v->v_flags |= MDB_NV_TAGGED;
			if (del_tag)
				v->v_flags &= ~MDB_NV_TAGGED;
		}
	}

	return (DCMD_OK);
}

#ifndef _KMDB
/*ARGSUSED*/
static int
cmd_context(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_tgt_setcontext(mdb.m_target, (void *)addr) == 0)
		return (DCMD_OK);

	return (DCMD_ERR);
}
#endif

/*ARGSUSED*/
static int
cmd_prompt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *p = "";

	if (argc != 0) {
		if (argc > 1 || argv->a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);
		p = argv->a_un.a_str;
	}

	(void) mdb_set_prompt(p);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_term(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_printf("%s\n", mdb.m_termtype);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_vtop(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	physaddr_t pa;
	mdb_tgt_as_t as = MDB_TGT_AS_VIRT;

	if (mdb_getopts(argc, argv, 'a', MDB_OPT_UINTPTR, (uintptr_t *)&as,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_tgt_vtop(mdb.m_target, as, addr, &pa) == -1) {
		mdb_warn("failed to get physical mapping");
		return (DCMD_ERR);
	}

	if (flags & DCMD_PIPE_OUT)
		mdb_printf("%llr\n", pa);
	else
		mdb_printf("virtual %lr mapped to physical %llr\n", addr, pa);
	return (DCMD_OK);
}

#define	EVENTS_OPT_A	0x1	/* ::events -a (show all events) */
#define	EVENTS_OPT_V	0x2	/* ::events -v (verbose display) */

static const char *
event_action(const mdb_tgt_spec_desc_t *sp)
{
	if (!(sp->spec_flags & MDB_TGT_SPEC_HIDDEN) && sp->spec_data != NULL)
		return (sp->spec_data);

	return ("-");
}

static void
print_evsep(void)
{
	static const char dash20[] = "--------------------";
	mdb_printf("----- - -- -- -- %s%s --%s\n", dash20, dash20, dash20);
}

/*ARGSUSED*/
static int
print_event(mdb_tgt_t *t, void *private, int vid, void *data)
{
	uint_t opts = (uint_t)(uintptr_t)private;
	mdb_tgt_spec_desc_t sp;
	char s1[41], s2[22];
	const char *s2str;
	int visible;

	(void) mdb_tgt_vespec_info(t, vid, &sp, s1, sizeof (s1));
	visible = !(sp.spec_flags & (MDB_TGT_SPEC_HIDDEN|MDB_TGT_SPEC_DELETED));

	if ((opts & EVENTS_OPT_A) || visible) {
		int encoding = (!(sp.spec_flags & MDB_TGT_SPEC_DISABLED)) |
		    (!(sp.spec_flags & MDB_TGT_SPEC_MATCHED) << 1);

		char ldelim = "<<(["[encoding];
		char rdelim = ">>)]"[encoding];

		char state = "0-+*!"[sp.spec_state];

		char tflag = "T "[!(sp.spec_flags & MDB_TGT_SPEC_STICKY)];
		char aflag = "d "[!(sp.spec_flags & MDB_TGT_SPEC_AUTODIS)];

		if (sp.spec_flags & MDB_TGT_SPEC_TEMPORARY)
			tflag = 't'; /* TEMP takes precedence over STICKY */
		if (sp.spec_flags & MDB_TGT_SPEC_AUTODEL)
			aflag = 'D'; /* AUTODEL takes precedence over AUTODIS */
		if (sp.spec_flags & MDB_TGT_SPEC_AUTOSTOP)
			aflag = 's'; /* AUTOSTOP takes precedence over both */

		if (opts & EVENTS_OPT_V) {
			if (sp.spec_state == MDB_TGT_SPEC_IDLE ||
			    sp.spec_state == MDB_TGT_SPEC_ERROR)
				s2str = mdb_strerror(sp.spec_errno);
			else
				s2str = "-";
		} else
			s2str = event_action(&sp);

		if (mdb_snprintf(s2, sizeof (s2), "%s", s2str) >= sizeof (s2))
			(void) strabbr(s2, sizeof (s2));

		if (vid > -10 && vid < 10)
			mdb_printf("%c%2d %c", ldelim, vid, rdelim);
		else
			mdb_printf("%c%3d%c", ldelim, vid, rdelim);

		mdb_printf(" %c %c%c %2u %2u %-40s %-21s\n",
		    state, tflag, aflag, sp.spec_hits, sp.spec_limit, s1, s2);

		if (opts & EVENTS_OPT_V) {
			mdb_printf("%-17s%s\n", "", event_action(&sp));
			print_evsep();
		}
	}

	return (0);
}

/*ARGSUSED*/
static int
cmd_events(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opts = 0;

	if ((flags & DCMD_ADDRSPEC) || mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, EVENTS_OPT_A, &opts,
	    'v', MDB_OPT_SETBITS, EVENTS_OPT_V, &opts, NULL) != argc)
		return (DCMD_USAGE);


	if (opts & EVENTS_OPT_V) {
		mdb_printf("   ID S TA HT LM %-40s %-21s\n%-17s%s\n",
		    "Description", "Status", "", "Action");
	} else {
		mdb_printf("   ID S TA HT LM %-40s %-21s\n",
		    "Description", "Action");
	}

	print_evsep();
	return (mdb_tgt_vespec_iter(mdb.m_target, print_event,
	    (void *)(uintptr_t)opts));
}

static int
tgt_status(const mdb_tgt_status_t *tsp)
{
	const char *format;
	char buf[BUFSIZ];

	if (tsp->st_flags & MDB_TGT_BUSY)
		return (DCMD_OK);

	if (tsp->st_pc != 0) {
		if (mdb_dis_ins2str(mdb.m_disasm, mdb.m_target, MDB_TGT_AS_VIRT,
		    buf, sizeof (buf), tsp->st_pc) != tsp->st_pc)
			format = "target stopped at:\n%-#16a%8T%s\n";
		else
			format = "target stopped at %a:\n";
		mdb_warn(format, tsp->st_pc, buf);
	}

	switch (tsp->st_state) {
	case MDB_TGT_IDLE:
		mdb_warn("target is idle\n");
		break;
	case MDB_TGT_RUNNING:
		if (tsp->st_flags & MDB_TGT_DSTOP)
			mdb_warn("target is running, stop directive pending\n");
		else
			mdb_warn("target is running\n");
		break;
	case MDB_TGT_STOPPED:
		if (tsp->st_pc == 0)
			mdb_warn("target is stopped\n");
		break;
	case MDB_TGT_UNDEAD:
		mdb_warn("target has terminated\n");
		break;
	case MDB_TGT_DEAD:
		mdb_warn("target is a core dump\n");
		break;
	case MDB_TGT_LOST:
		mdb_warn("target is no longer under debugger control\n");
		break;
	}

	mdb_set_dot(tsp->st_pc);
	return (DCMD_OK);
}

/*
 * mdb continue/step commands take an optional signal argument, but the
 * corresponding kmdb versions don't.
 */
#ifdef _KMDB
#define	CONT_MAXARGS	0	/* no optional SIG argument */
#else
#define	CONT_MAXARGS	1
#endif

/*ARGSUSED*/
static int
cmd_cont_common(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int (*t_cont)(mdb_tgt_t *, mdb_tgt_status_t *), const char *name)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_status_t st;
	int sig = 0;

	if ((flags & DCMD_ADDRSPEC) || argc > CONT_MAXARGS)
		return (DCMD_USAGE);

	if (argc > 0) {
		if (argv->a_type == MDB_TYPE_STRING) {
			if (proc_str2sig(argv->a_un.a_str, &sig) == -1) {
				mdb_warn("invalid signal name -- %s\n",
				    argv->a_un.a_str);
				return (DCMD_USAGE);
			}
		} else
			sig = (int)(intmax_t)argv->a_un.a_val;
	}

	(void) mdb_tgt_status(t, &st);

	if (st.st_state == MDB_TGT_IDLE && mdb_tgt_run(t, 0, NULL) == -1) {
		if (errno != EMDB_TGT)
			mdb_warn("failed to create new target");
		return (DCMD_ERR);
	}

	if (sig != 0 && mdb_tgt_signal(t, sig) == -1) {
		mdb_warn("failed to post signal %d", sig);
		return (DCMD_ERR);
	}

	if (st.st_state == MDB_TGT_IDLE && t_cont == &mdb_tgt_step) {
		(void) mdb_tgt_status(t, &st);
		return (tgt_status(&st));
	}

	if (t_cont(t, &st) == -1) {
		if (errno != EMDB_TGT)
			mdb_warn("failed to %s target", name);
		return (DCMD_ERR);
	}

	return (tgt_status(&st));
}

static int
cmd_step(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int (*func)(mdb_tgt_t *, mdb_tgt_status_t *) = &mdb_tgt_step;
	const char *name = "single-step";

	if (argc > 0 && argv->a_type == MDB_TYPE_STRING) {
		if (strcmp(argv->a_un.a_str, "out") == 0) {
			func = &mdb_tgt_step_out;
			name = "step (out)";
			argv++;
			argc--;
		} else if (strcmp(argv->a_un.a_str, "over") == 0) {
			func = &mdb_tgt_next;
			name = "step (over)";
			argv++;
			argc--;
		}
	}

	return (cmd_cont_common(addr, flags, argc, argv, func, name));
}

static int
cmd_step_out(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (cmd_cont_common(addr, flags, argc, argv,
	    &mdb_tgt_step_out, "step (out)"));
}

static int
cmd_next(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (cmd_cont_common(addr, flags, argc, argv,
	    &mdb_tgt_next, "step (over)"));
}

static int
cmd_cont(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (cmd_cont_common(addr, flags, argc, argv,
	    &mdb_tgt_continue, "continue"));
}

#ifndef _KMDB
/*ARGSUSED*/
static int
cmd_run(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_tgt_run(mdb.m_target, argc, argv) == -1) {
		if (errno != EMDB_TGT)
			mdb_warn("failed to create new target");
		return (DCMD_ERR);
	}
	return (cmd_cont(NULL, 0, 0, NULL));
}
#endif

/*
 * To simplify the implementation of :d, :z, and ::delete, we use the sp
 * parameter to store the criteria for what to delete.  If spec_base is set,
 * we delete vespecs with a matching address.  If spec_id is set, we delete
 * vespecs with a matching id.  Otherwise, we delete all vespecs.  We bump
 * sp->spec_size so the caller can tell how many vespecs were deleted.
 */
static int
ve_delete(mdb_tgt_t *t, mdb_tgt_spec_desc_t *sp, int vid, void *data)
{
	mdb_tgt_spec_desc_t spec;
	int status = -1;

	if (vid < 0)
		return (0); /* skip over target implementation events */

	if (sp->spec_base != NULL) {
		(void) mdb_tgt_vespec_info(t, vid, &spec, NULL, 0);
		if (sp->spec_base - spec.spec_base < spec.spec_size)
			status = mdb_tgt_vespec_delete(t, vid);
	} else if (sp->spec_id == 0) {
		(void) mdb_tgt_vespec_info(t, vid, &spec, NULL, 0);
		if (!(spec.spec_flags & MDB_TGT_SPEC_STICKY))
			status = mdb_tgt_vespec_delete(t, vid);
	} else if (sp->spec_id == vid)
		status = mdb_tgt_vespec_delete(t, vid);

	if (status == 0) {
		if (data != NULL)
			strfree(data);
		sp->spec_size++;
	}

	return (0);
}

static int
ve_delete_spec(mdb_tgt_spec_desc_t *sp)
{
	(void) mdb_tgt_vespec_iter(mdb.m_target,
	    (mdb_tgt_vespec_f *)ve_delete, sp);

	if (sp->spec_size == 0) {
		if (sp->spec_id != 0 || sp->spec_base != NULL)
			mdb_warn("no traced events matched description\n");
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_zapall(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_spec_desc_t spec;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	bzero(&spec, sizeof (spec));
	return (ve_delete_spec(&spec));
}

static int
cmd_delete(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_spec_desc_t spec;

	if (((flags & DCMD_ADDRSPEC) && argc > 0) || argc > 1)
		return (DCMD_USAGE);

	bzero(&spec, sizeof (spec));

	if (flags & DCMD_ADDRSPEC)
		spec.spec_base = addr;
	else if (argc == 0)
		spec.spec_base = mdb_get_dot();
	else if (argv->a_type == MDB_TYPE_STRING &&
	    strcmp(argv->a_un.a_str, "all") != 0)
		spec.spec_id = (int)(intmax_t)mdb_strtonum(argv->a_un.a_str,
		    10);
	else if (argv->a_type == MDB_TYPE_IMMEDIATE)
		spec.spec_id = (int)(intmax_t)argv->a_un.a_val;

	return (ve_delete_spec(&spec));
}

static int
cmd_write(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_as_t as;
	int rdback = mdb.m_flags & MDB_FL_READBACK;
	mdb_tgt_addr_t naddr;
	size_t forced_size = 0;
	boolean_t opt_p, opt_o, opt_l;
	uint64_t val = 0;
	int i;

	opt_p = opt_o = opt_l = B_FALSE;

	i = mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, B_TRUE, &opt_p,
	    'o', MDB_OPT_SETBITS, B_TRUE, &opt_o,
	    'l', MDB_OPT_UINTPTR_SET, &opt_l, (uintptr_t *)&forced_size, NULL);

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (opt_p && opt_o) {
		mdb_warn("-o and -p are incompatible\n");
		return (DCMD_USAGE);
	}

	argc -= i;
	argv += i;

	if (argc == 0)
		return (DCMD_USAGE);

	switch (argv[0].a_type) {
	case MDB_TYPE_STRING:
		val = mdb_strtoull(argv[0].a_un.a_str);
		break;
	case MDB_TYPE_IMMEDIATE:
		val = argv[0].a_un.a_val;
		break;
	default:
		return (DCMD_USAGE);
	}

	if (opt_p)
		as = MDB_TGT_AS_PHYS;
	else if (opt_o)
		as = MDB_TGT_AS_FILE;
	else
		as = MDB_TGT_AS_VIRT;

	if (opt_l)
		naddr = write_var_uint(as, addr, val, forced_size, rdback);
	else
		naddr = write_ctf_uint(as, addr, val, rdback);

	if (addr == naddr) {
		mdb_warn("failed to write %llr at address %#llx", val, addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
write_help(void)
{
	mdb_printf(
	    "-l length  force a write with the specified length in bytes\n"
	    "-o         write data to the object file location specified\n"
	    "-p         write data to the physical address specified\n"
	    "\n"
	    "Attempts to write the given value to the address provided.\n"
	    "If -l is not specified, the address must be the position of a\n"
	    "symbol that is either of integer, pointer, or enum type. The\n"
	    "type and the size of the symbol are inferred by the CTF found\n"
	    "in the provided address. The length of the write is guaranteed\n"
	    "to be the inferred size of the symbol.\n"
	    "\n"
	    "If no CTF data exists, or the address provided is not a symbol\n"
	    "of integer or pointer type, then the write fails. At that point\n"
	    "the user can force the write by using the '-l' option and\n"
	    "specifying its length.\n"
	    "\n"
	    "Note that forced writes with a length that are bigger than\n"
	    "the size of the biggest data pointer supported are not allowed."
	    "\n");
}

static void
srcexec_file_help(void)
{
	mdb_printf(
"The library of macros delivered with previous versions of Solaris have been\n"
"superseded by the dcmds and walkers provided by MDB.  See ::help for\n"
"commands that can be used to list the available dcmds and walkers.\n"
"\n"
"Aliases have been created for several of the more popular macros.  To see\n"
"the list of aliased macros, as well as their native MDB equivalents,\n"
"type $M.\n");

#ifdef _KMDB
	mdb_printf(
"When invoked, the $< and $<< dcmds will consult the macro alias list.  If an\n"
"alias cannot be found, an attempt will be made to locate a data type whose\n"
"name corresponds to the requested macro.  If such a type can be found, it\n"
"will be displayed using the ::print dcmd.\n");
#else
	mdb_printf(
"When invoked, the $< and $<< dcmds will first attempt to locate a macro with\n"
"the indicated name.  If no macro can be found, and if no alias exists for\n"
"this macro, an attempt will be made to locate a data type whose name\n"
"corresponds to the requested macro.  If such a type can be found, it will be\n"
"displayed using the ::print dcmd.\n");
#endif
}

static void
events_help(void)
{
	mdb_printf("Options:\n"
	    "-a       show all events, including internal debugger events\n"
	    "-v       show verbose display, including inactivity reason\n"
	    "\nOutput Columns:\n"
	    "ID       decimal event specifier id number:\n"
	    "    [ ]  event tracing is enabled\n"
	    "    ( )  event tracing is disabled\n"
	    "    < >  target is currently stopped on this type of event\n\n"
	    "S        event specifier state:\n"
	    "     -   event specifier is idle (not applicable yet)\n"
	    "     +   event specifier is active\n"
	    "     *   event specifier is armed (target program running)\n"
	    "     !   error occurred while attempting to arm event\n\n"
	    "TA       event specifier flags:\n"
	    "     t   event specifier is temporary (delete at next stop)\n"
	    "     T   event specifier is sticky (::delete all has no effect)\n"
	    "     d   event specifier will be disabled when HT = LM\n"
	    "     D   event specifier will be deleted when HT = LM\n"
	    "     s   target will automatically stop when HT = LM\n\n"
	    "HT       hit count (number of times event has occurred)\n"
	    "LM       hit limit (limit for autostop, disable, delete)\n");
}

static void
dump_help(void)
{
	mdb_printf(
	    "-e    adjust for endianness\n"
	    "      (assumes 4-byte words; use -g to change word size)\n"
#ifdef _KMDB
	    "-f    no effect\n"
#else
	    "-f    dump from object file\n"
#endif
	    "-g n  display bytes in groups of n\n"
	    "      (default is 4; n must be a power of 2, divide line width)\n"
	    "-l n  display n bytes\n"
	    "      (default is 1; rounded up to multiple of line width)\n"
	    "-p    dump from physical memory\n"
	    "-q    don't print ASCII\n"
	    "-r    use relative numbering (automatically sets -u)\n"
	    "-s    elide repeated lines\n"
	    "-t    only read from and display contents of specified addresses\n"
	    "      (default is to read and print entire lines)\n"
	    "-u    un-align output\n"
	    "      (default is to align output at paragraph boundary)\n"
	    "-w n  display n 16-byte paragraphs per line\n"
	    "      (default is 1, maximum is 16)\n");
}

/*
 * Table of built-in dcmds associated with the root 'mdb' module.  Future
 * expansion of this program should be done here, or through the external
 * loadable module interface.
 */
const mdb_dcmd_t mdb_dcmd_builtins[] = {

	/*
	 * dcmds common to both mdb and kmdb
	 */
	{ ">", "variable-name", "assign variable", cmd_assign_variable },
	{ "/", "fmt-list", "format data from virtual as", cmd_print_core },
	{ "\\", "fmt-list", "format data from physical as", cmd_print_phys },
	{ "@", "fmt-list", "format data from physical as", cmd_print_phys },
	{ "=", "fmt-list", "format immediate value", cmd_print_value },
	{ "$<", "macro-name", "replace input with macro",
	    cmd_exec_file, srcexec_file_help },
	{ "$<<", "macro-name", "source macro",
	    cmd_src_file, srcexec_file_help},
	{ "$%", NULL, NULL, cmd_quit },
	{ "$?", NULL, "print status and registers", cmd_notsup },
	{ "$a", NULL, NULL, cmd_algol },
	{ "$b", "[-av]", "list traced software events",
	    cmd_events, events_help },
	{ "$c", "?[cnt]", "print stack backtrace", cmd_notsup },
	{ "$C", "?[cnt]", "print stack backtrace", cmd_notsup },
	{ "$d", NULL, "get/set default output radix", cmd_radix },
	{ "$D", "?[mode,...]", NULL, cmd_dbmode },
	{ "$e", NULL, "print listing of global symbols", cmd_globals },
	{ "$f", NULL, "print listing of source files", cmd_files },
	{ "$m", "?[name]", "print address space mappings", cmd_mappings },
	{ "$M", NULL, "list macro aliases", cmd_macalias_list },
	{ "$P", "[prompt]", "set debugger prompt string", cmd_prompt },
	{ "$q", NULL, "quit debugger", cmd_quit },
	{ "$Q", NULL, "quit debugger", cmd_quit },
	{ "$r", NULL, "print general-purpose registers", cmd_notsup },
	{ "$s", NULL, "get/set symbol matching distance", cmd_symdist },
	{ "$v", NULL, "print non-zero variables", cmd_nzvars },
	{ "$V", "[mode]", "get/set disassembly mode", cmd_dismode },
	{ "$w", NULL, "get/set output page width", cmd_pgwidth },
	{ "$W", NULL, "re-open target in write mode", cmd_reopen },
	{ ":a", ":[cmd...]", "set read access watchpoint", cmd_oldwpr },
	{ ":b", ":[cmd...]", "breakpoint at the specified address", cmd_oldbp },
	{ ":d", "?[id|all]", "delete traced software events", cmd_delete },
	{ ":p", ":[cmd...]", "set execute access watchpoint", cmd_oldwpx },
	{ ":S", NULL, NULL, cmd_step },
	{ ":w", ":[cmd...]", "set write access watchpoint", cmd_oldwpw },
	{ ":z", NULL, "delete all traced software events", cmd_zapall },
	{ "array", ":[type count] [variable]", "print each array element's "
	    "address", cmd_array },
	{ "bp", "?[+/-dDestT] [-c cmd] [-n count] sym ...", "breakpoint at the "
	    "specified addresses or symbols", cmd_bp, bp_help },
	{ "dcmds", NULL, "list available debugger commands", cmd_dcmds },
	{ "delete", "?[id|all]", "delete traced software events", cmd_delete },
	{ "dis", "?[-abfw] [-n cnt] [addr]", "disassemble near addr", cmd_dis },
	{ "disasms", NULL, "list available disassemblers", cmd_disasms },
	{ "dismode", "[mode]", "get/set disassembly mode", cmd_dismode },
	{ "dmods", "[-l] [mod]", "list loaded debugger modules", cmd_dmods },
	{ "dump", "?[-eqrstu] [-f|-p] [-g bytes] [-l bytes] [-w paragraphs]",
	    "dump memory from specified address", cmd_dump, dump_help },
	{ "echo", "args ...", "echo arguments", cmd_echo },
	{ "enum", "?[-ex] enum [name]", "print an enumeration", cmd_enum,
	    enum_help },
	{ "eval", "command", "evaluate the specified command", cmd_eval },
	{ "events", "[-av]", "list traced software events",
	    cmd_events, events_help },
	{ "evset", "?[+/-dDestT] [-c cmd] [-n count] id ...",
	    "set software event specifier attributes", cmd_evset, evset_help },
	{ "files", "[object]", "print listing of source files", cmd_files },
#ifdef __sparc
	{ "findsym", "?[-g] [symbol|addr ...]", "search for symbol references "
	    "in all known functions", cmd_findsym, NULL },
#endif
	{ "formats", NULL, "list format specifiers", cmd_formats },
	{ "grep", "?expr", "print dot if expression is true", cmd_grep },
	{ "head", "-num|-n num", "limit number of elements in pipe", cmd_head,
	    head_help },
	{ "help", "[cmd]", "list commands/command help", cmd_help, NULL,
	    cmd_help_tab },
	{ "list", "?type member [variable]",
	    "walk list using member as link pointer", cmd_list, NULL,
	    mdb_tab_complete_mt },
	{ "map", "?expr", "print dot after evaluating expression", cmd_map },
	{ "mappings", "?[name]", "print address space mappings", cmd_mappings },
	{ "nm", "?[-DPdghnopuvx] [-f format] [-t types] [object]",
	    "print symbols", cmd_nm, nm_help },
	{ "nmadd", ":[-fo] [-e end] [-s size] name",
	    "add name to private symbol table", cmd_nmadd, nmadd_help },
	{ "nmdel", "name", "remove name from private symbol table", cmd_nmdel },
	{ "obey", NULL, NULL, cmd_obey },
	{ "objects", "[-v]", "print load objects information", cmd_objects },
	{ "offsetof", "type member", "print the offset of a given struct "
	    "or union member", cmd_offsetof, NULL, mdb_tab_complete_mt },
	{ "print", "?[-aCdhiLptx] [-c lim] [-l lim] [type] [member|offset ...]",
	    "print the contents of a data structure", cmd_print, print_help,
	    cmd_print_tab },
	{ "printf", "?format type member ...", "print and format the "
	    "member(s) of a data structure", cmd_printf, printf_help,
	    cmd_printf_tab },
	{ "regs", NULL, "print general purpose registers", cmd_notsup },
	{ "set", "[-wF] [+/-o opt] [-s dist] [-I path] [-L path] [-P prompt]",
	    "get/set debugger properties", cmd_set },
	{ "showrev", "[-pv]", "print version information", cmd_showrev },
	{ "sizeof", "type", "print the size of a type", cmd_sizeof, NULL,
	    cmd_sizeof_tab },
	{ "stack", "?[cnt]", "print stack backtrace", cmd_notsup },
	{ "stackregs", "?", "print stack backtrace and registers",
	    cmd_notsup },
	{ "status", NULL, "print summary of current target", cmd_notsup },
	{ "term", NULL, "display current terminal type", cmd_term },
	{ "typeset", "[+/-t] var ...", "set variable attributes", cmd_typeset },
	{ "typedef", "[-c model | -d | -l | -r file | -w file ] [type] [name]",
		"create synthetic types", cmd_typedef, cmd_typedef_help },
	{ "unset", "[name ...]", "unset variables", cmd_unset },
	{ "vars", "[-npt]", "print listing of variables", cmd_vars },
	{ "version", NULL, "print debugger version string", cmd_version },
	{ "vtop", ":[-a as]", "print physical mapping of virtual address",
	    cmd_vtop },
	{ "walk", "?name [variable]", "walk data structure", cmd_walk, NULL,
	    cmd_walk_tab },
	{ "walkers", NULL, "list available walkers", cmd_walkers },
	{ "whatis", ":[-aikqv]", "given an address, return information",
	    cmd_whatis, whatis_help },
	{ "whence", "[-v] name ...", "show source of walk or dcmd", cmd_which },
	{ "which", "[-v] name ...", "show source of walk or dcmd", cmd_which },
	{ "write", "?[-op] [-l len] value",
	    "write value to the provided memory location", cmd_write,
	    write_help },
	{ "xdata", NULL, "print list of external data buffers", cmd_xdata },

#ifdef _KMDB
	/*
	 * dcmds specific to kmdb, or which have kmdb-specific arguments
	 */
	{ "?", "fmt-list", "format data from virtual as", cmd_print_core },
	{ ":c", NULL, "continue target execution", cmd_cont },
	{ ":e", NULL, "step target over next instruction", cmd_next },
	{ ":s", NULL, "single-step target to next instruction", cmd_step },
	{ ":u", NULL, "step target out of current function", cmd_step_out },
	{ "cont", NULL, "continue target execution", cmd_cont },
	{ "load", "[-sd] module", "load debugger module", cmd_load, load_help },
	{ "next", NULL, "step target over next instruction", cmd_next },
	{ "quit", "[-u]", "quit debugger", cmd_quit, quit_help },
	{ "step", "[ over | out ]",
	    "single-step target to next instruction", cmd_step },
	{ "unload", "[-d] module", "unload debugger module", cmd_unload,
	    unload_help },
	{ "wp", ":[+/-dDelstT] [-rwx] [-pi] [-c cmd] [-n count] [-L size]",
	    "set a watchpoint at the specified address", cmd_wp, wp_help },

#else
	/*
	 * dcmds specific to mdb, or which have mdb-specific arguments
	 */
	{ "?", "fmt-list", "format data from object file", cmd_print_object },
	{ "$>", "[file]", "log session to a file", cmd_old_log },
	{ "$g", "?", "get/set C++ demangling options", cmd_demflags },
	{ "$G", NULL, "enable/disable C++ demangling support", cmd_demangle },
	{ "$i", NULL, "print signals that are ignored", cmd_notsup },
	{ "$l", NULL, "print the representative thread's lwp id", cmd_notsup },
	{ "$p", ":", "change debugger target context", cmd_context },
	{ "$x", NULL, "print floating point registers", cmd_notsup },
	{ "$X", NULL, "print floating point registers", cmd_notsup },
	{ "$y", NULL, "print floating point registers", cmd_notsup },
	{ "$Y", NULL, "print floating point registers", cmd_notsup },
	{ ":A", "?[core|pid]", "attach to process or core file", cmd_notsup },
	{ ":c", "[SIG]", "continue target execution", cmd_cont },
	{ ":e", "[SIG]", "step target over next instruction", cmd_next },
	{ ":i", ":", "ignore signal (delete all matching events)", cmd_notsup },
	{ ":k", NULL, "forcibly kill and release target", cmd_notsup },
	{ ":t", "?[+/-dDestT] [-c cmd] [-n count] SIG ...", "stop on delivery "
	    "of the specified signals", cmd_sigbp, sigbp_help },
	{ ":r", "[ args ... ]", "run a new target process", cmd_run },
	{ ":R", NULL, "release the previously attached process", cmd_notsup },
	{ ":s", "[SIG]", "single-step target to next instruction", cmd_step },
	{ ":u", "[SIG]", "step target out of current function", cmd_step_out },
	{ "attach", "?[core|pid]",
	    "attach to process or core file", cmd_notsup },
	{ "cat", "[file ...]", "concatenate and display files", cmd_cat },
	{ "cont", "[SIG]", "continue target execution", cmd_cont },
	{ "context", ":", "change debugger target context", cmd_context },
	{ "dem", "name ...", "demangle C++ symbol names", cmd_demstr },
	{ "fltbp", "?[+/-dDestT] [-c cmd] [-n count] fault ...",
	    "stop on machine fault", cmd_fltbp, fltbp_help },
	{ "fpregs", NULL, "print floating point registers", cmd_notsup },
	{ "kill", NULL, "forcibly kill and release target", cmd_notsup },
	{ "load", "[-s] module", "load debugger module", cmd_load, load_help },
	{ "log", "[-d | [-e] file]", "log session to a file", cmd_log },
	{ "next", "[SIG]", "step target over next instruction", cmd_next },
	{ "quit", NULL, "quit debugger", cmd_quit },
	{ "release", NULL,
	    "release the previously attached process", cmd_notsup },
	{ "run", "[ args ... ]", "run a new target process", cmd_run },
	{ "sigbp", "?[+/-dDestT] [-c cmd] [-n count] SIG ...", "stop on "
	    "delivery of the specified signals", cmd_sigbp, sigbp_help },
	{ "step", "[ over | out ] [SIG]",
	    "single-step target to next instruction", cmd_step },
	{ "sysbp", "?[+/-dDestT] [-io] [-c cmd] [-n count] syscall ...",
	    "stop on entry or exit from system call", cmd_sysbp, sysbp_help },
	{ "unload", "module", "unload debugger module", cmd_unload },
	{ "wp", ":[+/-dDelstT] [-rwx] [-c cmd] [-n count] [-L size]",
	    "set a watchpoint at the specified address", cmd_wp, wp_help },
#endif

	{ NULL }
};
