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

/*
 * Copyright 2007 Jason King.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 */

/*
 * The sparc disassembler is mostly straightforward, each instruction is
 * represented by an inst_t structure.  The inst_t definitions are organized
 * into tables.  The tables are correspond to the opcode maps documented in the
 * various sparc architecture manuals.  Each table defines the bit range of the
 * instruction whose value act as an index into the array of instructions.  A
 * table can also refer to another table if needed.  Each table also contains
 * a function pointer of type format_fcn that knows how to output the
 * instructions in the table, as well as handle any synthetic instructions
 *
 * Unfortunately, the changes from sparcv8 -> sparcv9 not only include new
 * instructions, they sometimes renamed or just reused the same instruction to
 * do different operations (i.e. the sparcv8 coprocessor instructions).  To
 * accommodate this, each table can define an overlay table.  The overlay table
 * is a list of (table index, architecture, new instruction definition) values.
 *
 *
 * Traversal starts with the first table,
 *   get index value from the instruction
 *   if an relevant overlay entry exists for this index,
 *        grab the overlay definition
 *   else
 *        grab the definition from the array (corresponding to the index value)
 *
 * If the entry is an instruction,
 *     call print function of instruction.
 * If the entry is a pointer to another table
 *     traverse the table
 * If not valid,
 *     return an error
 *
 *
 * To keep dis happy, for sparc, instead of actually returning an error, if
 * the instruction cannot be disassembled, we instead merely place the value
 * of the instruction into the output buffer.
 *
 * Adding new instructions:
 *
 * With the above information, it hopefully makes it clear how to add support
 * for decoding new instructions.  Presumably, with new instructions will come
 * a new dissassembly mode (I.e. DIS_SPARC_V8, DIS_SPARC_V9, etc.).
 *
 * If the dissassembled format does not correspond to one of the existing
 * formats, a new formatter will have to be written.  The 'flags' value of
 * inst_t is intended to instruct the corresponding formatter about how to
 * output the instruction.
 *
 * If the corresponding entry in the correct table is currently unoccupied,
 * simply replace the INVALID entry with the correct definition.  The INST and
 * TABLE macros are suggested to be used for this.  If there is already an
 * instruction defined, then the entry must be placed in an overlay table.  If
 * no overlay table exists for the instruction table, one will need to be
 * created.
 */

#include <libdisasm.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/byteorder.h>
#include <string.h>

#include "libdisasm_impl.h"
#include "dis_sparc.h"

static const inst_t *dis_get_overlay(dis_handle_t *, const table_t *,
    uint32_t);
static uint32_t dis_get_bits(uint32_t, int, int);

#if !defined(DIS_STANDALONE)
static void do_binary(uint32_t);
#endif /* DIS_STANDALONE */

static void
dis_sparc_handle_detach(dis_handle_t *dhp)
{
	dis_free(dhp->dh_arch_private, sizeof (dis_handle_sparc_t));
	dhp->dh_arch_private = NULL;
}

static int
dis_sparc_handle_attach(dis_handle_t *dhp)
{
	dis_handle_sparc_t *dhx;

#if !defined(DIS_STANDALONE)
	char *opt = NULL;
	char *opt2, *save, *end;
#endif

	/* Validate architecture flags */
	if ((dhp->dh_flags & (DIS_SPARC_V8|DIS_SPARC_V9|DIS_SPARC_V9_SGI))
	    == 0) {
		(void) dis_seterrno(E_DIS_INVALFLAG);
		return (-1);
	}

	if ((dhx = dis_zalloc(sizeof (dis_handle_sparc_t))) == NULL) {
		(void) dis_seterrno(E_DIS_NOMEM);
		return (0);
	}
	dhx->dhx_debug = DIS_DEBUG_COMPAT;
	dhp->dh_arch_private = dhx;

#if !defined(DIS_STANDALONE)

	opt = getenv("_LIBDISASM_DEBUG");
	if (opt == NULL)
		return (0);

	opt2 = strdup(opt);
	if (opt2 == NULL) {
		dis_handle_destroy(dhp);
		dis_free(dhx, sizeof (dis_handle_sparc_t));
		(void) dis_seterrno(E_DIS_NOMEM);
		return (-1);
	}
	save = opt2;

	while (opt2 != NULL) {
		end = strchr(opt2, ',');

		if (end != 0)
			*end++ = '\0';

		if (strcasecmp("synth-all", opt2) == 0)
			dhx->dhx_debug |= DIS_DEBUG_SYN_ALL;

		if (strcasecmp("compat", opt2) == 0)
			dhx->dhx_debug |= DIS_DEBUG_COMPAT;

		if (strcasecmp("synth-none", opt2) == 0)
			dhx->dhx_debug &= ~(DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT);

		if (strcasecmp("binary", opt2) == 0)
			dhx->dhx_debug |= DIS_DEBUG_PRTBIN;

		if (strcasecmp("format", opt2) == 0)
			dhx->dhx_debug |= DIS_DEBUG_PRTFMT;

		if (strcasecmp("all", opt2) == 0)
			dhx->dhx_debug = DIS_DEBUG_ALL;

		if (strcasecmp("none", opt2) == 0)
			dhx->dhx_debug = DIS_DEBUG_NONE;

		opt2 = end;
	}
	free(save);
#endif /* DIS_STANDALONE */
	return (0);
}

/* ARGSUSED */
static int
dis_sparc_max_instrlen(dis_handle_t *dhp)
{
	return (4);
}

/* ARGSUSED */
static int
dis_sparc_min_instrlen(dis_handle_t *dhp)
{
	return (4);
}

/* ARGSUSED */
static uint64_t
dis_sparc_previnstr(dis_handle_t *dhp, uint64_t pc, int n)
{
	if (n <= 0)
		return (pc);

	if (pc < n)
		return (pc);

	return (pc - n*4);
}

/* ARGSUSED */
static int
dis_sparc_instrlen(dis_handle_t *dhp, uint64_t pc)
{
	return (4);
}

static int
dis_sparc_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf,
    size_t buflen)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	const table_t *tp = &initial_table;
	const inst_t *inp = NULL;

	uint32_t instr;
	uint32_t idx = 0;

	if (dhp->dh_read(dhp->dh_data, addr, &instr, sizeof (instr)) !=
	    sizeof (instr))
		return (-1);

	dhx->dhx_buf    = buf;
	dhx->dhx_buflen = buflen;
	dhp->dh_addr    = addr;

	buf[0] = '\0';

	/* this allows sparc code to be tested on x86 */
#if !defined(DIS_STANDALONE)
	instr = BE_32(instr);
#endif /* DIS_STANDALONE */

#if !defined(DIS_STANDALONE)
	if ((dhx->dhx_debug & DIS_DEBUG_PRTBIN) != 0)
		do_binary(instr);
#endif /* DIS_STANDALONE */

	/* CONSTCOND */
	while (1) {
		idx = dis_get_bits(instr, tp->tbl_field, tp->tbl_len);
		inp = &tp->tbl_inp[idx];

		inp = dis_get_overlay(dhp, tp, idx);

		if ((inp->in_type == INST_NONE) ||
		    ((inp->in_arch & dhp->dh_flags) == 0))
			goto error;

		if (inp->in_type == INST_TBL) {
			tp = inp->in_data.in_tbl;
			continue;
		}

		break;
	}

	if (tp->tbl_fmt(dhp, instr, inp, idx) == 0)
		return (0);

error:

	(void) dis_snprintf(buf, buflen,
	    ((dhp->dh_flags & DIS_OCTAL) != 0) ? "0%011lo" : "0x%08lx",
	    instr);

	return (0);
}

static uint32_t
dis_get_bits(uint32_t instr, int offset, int length)
{
	uint32_t mask, val;
	int i;

	for (i = 0, mask = 0; i < length; ++i)
		mask |= (1UL << i);

	mask = mask << (offset - length + 1);

	val = instr & mask;

	val = val >> (offset - length + 1);

	return (val);
}

static const inst_t *
dis_get_overlay(dis_handle_t *dhp, const table_t *tp, uint32_t idx)
{
	const inst_t *ip = &tp->tbl_inp[idx];
	int i;

	if (tp->tbl_ovp == NULL)
		return (ip);

	for (i = 0; tp->tbl_ovp[i].ov_idx != -1; ++i) {
		if (tp->tbl_ovp[i].ov_idx != idx)
			continue;

		if ((tp->tbl_ovp[i].ov_inst.in_arch & dhp->dh_flags) == 0)
			continue;

		ip = &tp->tbl_ovp[i].ov_inst;
		break;
	}

	return (ip);
}

#if !defined(DIS_STANDALONE)
static void
do_binary(uint32_t instr)
{
	(void) fprintf(stderr, "DISASM: ");
	prt_binary(instr, 32);
	(void) fprintf(stderr, "\n");
}
#endif /* DIS_STANDALONE */

static int
dis_sparc_supports_flags(int flags)
{
	int archflags = flags & DIS_ARCH_MASK;

	if (archflags == DIS_SPARC_V8 ||
	    (archflags & (DIS_SPARC_V9 | DIS_SPARC_V8)) == DIS_SPARC_V9)
		return (1);

	return (0);
}

const dis_arch_t dis_arch_sparc = {
	.da_supports_flags	= dis_sparc_supports_flags,
	.da_handle_attach	= dis_sparc_handle_attach,
	.da_handle_detach	= dis_sparc_handle_detach,
	.da_disassemble		= dis_sparc_disassemble,
	.da_previnstr		= dis_sparc_previnstr,
	.da_min_instrlen	= dis_sparc_min_instrlen,
	.da_max_instrlen	= dis_sparc_max_instrlen,
	.da_instrlen		= dis_sparc_instrlen
};
