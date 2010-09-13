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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * interface used by unwind support to query frame descriptor info
 */

#ifndef _LIBCRUN_
#include "lint.h"
#endif
#include <sys/types.h>
#include <limits.h>
#include "stack_unwind.h"
#include "unwind_context.h"
#include <dlfcn.h>

/*
 * CIE:
 *	UNUM32		length
 *	UNUM32		ID
 *	UNUM8		version
 *	ZTSTRING	augmentation
 *	ULEB128		Code Align Factor
 *	SLEB128		Data Align Factor
 *	UNUM8		RA
 *	ULEB128		length
 *	UNUM8		personality enc
 *	ADDR		personality
 *	UNUM8		code_enc
 *	UNUM8		lsda_enc
 *
 * FDE:
 *	UNUM32		length
 *	UNUM32		ID
 *	ADDR		initial loc
 *	SIZE		size
 *	ULEB128		length
 *	ADDR		lsda
 */


struct eh_frame_fields *
_Unw_Decode_FDE(struct eh_frame_fields *f, struct _Unwind_Context *ctx)
{
	void *fde_data;    /* location in this process of fde */
	void *fde_end;
	void *data;
	ptrdiff_t reloc;
	uintptr_t base;
	void *cie_data;    /* location in this process of cie */
	void *cie_end;
	void *cdata;
	ptrdiff_t creloc;
	int lsda_enc = 0;
	int per_enc = 0;
	int code_enc = 0;
	char augment[8];
	char *p;
	uint64_t scratch;

	uint64_t func = 0;
	uint64_t range = 0;
	_Unwind_Personality_Fn	pfn = 0;
	void* lsda = 0;

	/* here is where data mapping would happen ??REMOTE?? */
	fde_data = ctx->fde;
	data = fde_data;
	fde_end = (void *)(((intptr_t)fde_data) + 4 +
	    _Unw_get_val(&data, 0, UNUM32, 1, 1, 0));
	reloc = 0;
	base = ((intptr_t)data) + reloc;
	cie_data = (void *)(base -  _Unw_get_val(&data, 0, UNUM32, 1, 1, 0));
	cdata = cie_data;
	cie_end = (void *)(((intptr_t)cie_data) + 4 +
	    _Unw_get_val(&cdata, 0, UNUM32, 1, 1, 0));
	creloc = 0;
	/* data mapping has happened */

	f->cie_ops_end = cie_end;
	f->cie_reloc = creloc;
	f->fde_ops_end = fde_end;
	f->fde_reloc = reloc;

	(void) _Unw_get_val(&cdata, creloc, UNUM32, 1, 1, 0);
	(void) _Unw_get_val(&cdata, creloc, UNUM8, 1, 1, 0);
	/* LINTED alignment */
	(*((uint64_t *)(&(augment[0]))))  =
	    _Unw_get_val(&cdata, creloc, ZTSTRING, 1, 1, 0);
	f->code_align = _Unw_get_val(&cdata, creloc, ULEB128, 1, 1, 0);
	f->data_align = _Unw_get_val(&cdata, creloc, SLEB128, 1, 1, 0);
	(void) _Unw_get_val(&cdata, creloc, UNUM8, 1, 1, 0);
	if (augment[0] == 'z' &&
	    (scratch = _Unw_get_val(&cdata, creloc, ULEB128, 1, 1, 0)) != 0) {
		for (p = &(augment[1]); *p != 0; p++) {
			switch (*p) {
			case 'P':
				per_enc = _Unw_get_val(&cdata, creloc,
				    UNUM8, 1, 1, 0);
				if (per_enc == 0)
					per_enc = 0x4;
				pfn = (_Unwind_Personality_Fn)
				    _Unw_get_val(&cdata, creloc,
				    ADDR, 1, 1, per_enc);
				break;
			case 'R':
				code_enc = _Unw_get_val(&cdata, creloc,
				    UNUM8, 1, 1, 0);
				break;
			case 'L':
				lsda_enc = _Unw_get_val(&cdata, creloc,
				    UNUM8, 1, 1, 0);
				break;
			}
		}
	}
	if (code_enc == 0)
		code_enc = 0x4;

	func = _Unw_get_val(&data, reloc, ADDR, 1, 1, code_enc);
	range = _Unw_get_val(&data, reloc, SIZE, 1, 1, code_enc);
	if ((ctx->pc < func) || (ctx->pc > (func+range)))
		return (0);
	ctx->func = func;
	ctx->range = range;
	if (augment[0] == 'z') {
		scratch = _Unw_get_val(&data, reloc, ULEB128, 1, 1, 0);
		if (scratch == 4 && lsda_enc) {
			/*
			 * without the two work-arounds test would be
			 * (scratch > 0 & lsda_enc)
			 */
			lsda = (void *)_Unw_get_val(&data, reloc,
			    ADDR, 1, 1, lsda_enc);
		} else if (scratch == 4) {
			/*
			 * 11/24/04 compiler is sometimes not outputing
			 * lsda_enc
			 */
			lsda = (void*)_Unw_get_val(&data, reloc,
			    ADDR, 1, 1, 0x1b);
		} else if (scratch == 8) {
			/*
			 * 11/12/04 - compiler is putting out relative
			 * encoding byte and absolute data - inconsistancy
			 * is caught here.
			 */
			lsda = (void *)_Unw_get_val(&data, reloc,
			    ADDR, 1, 1, 0x4);
		}
	}
	if (pfn)
		ctx->pfn = pfn;
	if (lsda)
		ctx->lsda = lsda;
	f->fde_ops = data;
	f->cie_ops = cdata;
	f->code_enc = code_enc;
	return (f);
}

static int
table_ent_log_size(int enc)
{
	int val = enc & 0xf;
	int res;

	switch (val) {
	case 0x3:
		res = 3;
		break;
	case 0x04:
		res = 4;
		break;
	case 0x0b:
		res = 3;
		break;
	case 0x0c:
		res = 4;
		break;
	default:
		break;
	}
	return (res);
}

static void
get_table_ent_val(unsigned char *data, unsigned char *data_end,
	int enc, ptrdiff_t reloc, uintptr_t base,
	uint64_t *codep, uint64_t *next_codep, void **fdep)
{
	int val = enc & 0xf;
	int rel = (enc >> 4) & 0xf;
	unsigned char *second = data;
	unsigned char *third = data;
	uint64_t code;
	void *fde;
	uint64_t next_code;

	switch (val) {
	case 0x3:
		/* LINTED alignment */
		code = (uint64_t)(*((uint32_t *)data));
		second += 4;
		/* LINTED alignment */
		fde = (void *)(uint64_t)(*((uint32_t *)second));
		third += 8;
		next_code = (third >= data_end)? ULONG_MAX :
		    /* LINTED alignment */
		    (uint64_t)(*((uint32_t *)third));
		break;
	case 0x04:
		/* LINTED alignment */
		code = (uint64_t)(*((uint64_t *)data));
		second += 8;
		/* LINTED alignment */
		fde = (void *)(uint64_t)(*((uint64_t *)second));
		third += 16;
		next_code = (third >= data_end)? ULONG_MAX :
		    /* LINTED alignment */
		    (uint64_t)(*((uint64_t *)third));
		break;
	case 0x0b:
		/* LINTED alignment */
		code = (uint64_t)(int64_t)(*((int32_t *)data));
		second += 4;
		/* LINTED alignment */
		fde = (void *)(uint64_t)(int64_t)(*((int32_t *)second));
		third += 8;
		next_code = (third >= data_end)? ULONG_MAX :
		    /* LINTED alignment */
		    (uint64_t)(int64_t)(*((int32_t *)third));
		break;
	case 0x0c:
		/* LINTED alignment */
		code = (uint64_t)(*((int64_t *)data));
		second += 8;
		/* LINTED alignment */
		fde = (void *)(uint64_t)(*((int64_t *)second));
		third += 16;
		next_code = (third >= data_end)? ULONG_MAX :
		    /* LINTED alignment */
		    (uint64_t)(*((int64_t *)third));
		break;
	}

	switch (rel) {
	case 0:
		break;
	case 1:
		code += (uint64_t)data + reloc;
		fde = (void *)(((uint64_t)fde) + (uint64_t)second + reloc);
		if (next_code != ULONG_MAX)
			next_code += (uint64_t)third + reloc;
		break;
	case 3:
		code += base;
		fde = (void *)(((uint64_t)fde) +  base);
		if (next_code != ULONG_MAX)
			next_code += base;
		break;
	default:
		/* remainder not implemented */
		break;
	}
	*codep = code;
	*fdep = fde;
	*next_codep = next_code;
}


static void *
locate_fde_for_pc(uint64_t pc, int enc,
	unsigned char *table, unsigned char *table_end,
	ptrdiff_t reloc, uintptr_t base);

/*
 * Search the eh_frame info with a given pc.  Return a pointer to a
 * FDE.  The search is performed in two stages.
 * First rtld.so identifies the load module containing the target location.
 * This returns the appropiate eh_frame_hdr, and a binary search is
 * then performed on the eh_frame_hdr to locate the entry with
 * a matching pc value.
 */
void *
_Unw_EhfhLookup(struct _Unwind_Context *ctx)
{
	Dl_amd64_unwindinfo dlef;
	void* data;
	void* data_end;
	uint64_t pc = ctx->pc;
	int fp_enc, fc_enc, ft_enc;
	unsigned char *pi, *pj;
	ptrdiff_t reloc;
	uintptr_t base;

	dlef.dlui_version = 1;

	/* Locate the appropiate exception_range_entry table first */
	if (0 == dlamd64getunwind((void*)pc, &dlef)) {
		return (0);
	}

	/*
	 * you now know size and position of block of data needed for
	 * binary search ??REMOTE??
	 */
	data = dlef.dlui_unwindstart;
	if (0 == data)
		return (0);
	base = (uintptr_t)data;
	data_end = dlef.dlui_unwindend;
	reloc = 0;
	/* ??REMOTE?? */

	(void) _Unw_get_val(&data, reloc, UNUM8, 1, 1, 0);
	fp_enc = _Unw_get_val(&data, reloc, UNUM8, 1, 1, 0);
	fc_enc = _Unw_get_val(&data, reloc, UNUM8, 1, 1, 0);
	ft_enc = _Unw_get_val(&data, reloc, UNUM8, 1, 1, 0);
	(void) _Unw_get_val(&data, reloc, ADDR, 1, 1, fp_enc);
	(void) _Unw_get_val(&data, reloc, SIZE, 1, 1, fc_enc);
	pi = data;
	pj = data_end;
	ctx->fde = locate_fde_for_pc(pc, ft_enc, pi,  pj, reloc, base);
	return ((void *)(ctx->fde));
}

static void *
locate_fde_for_pc(uint64_t pc, int enc,
	unsigned char *table_bg, unsigned char *table_end,
	ptrdiff_t reloc, uintptr_t base)
{
	unsigned char *pi = table_bg;
	unsigned char *pj = table_end;
	uint64_t range_start, range_end;
	void* fde;
	int log_size = table_ent_log_size(enc);

	/*
	 * Invariant -- if there is a containing range,
	 * it must lie in the interval [pi,pj).  That is,
	 * pi <= p < pj, if p exists.
	 */
	while (pi < pj) {
		unsigned char *pr =
		    pi + (((pj - pi) >> (log_size + 1)) << log_size);
				/* Don't use (pi+pj)>>1 */
		get_table_ent_val(pr, table_end, enc, reloc, base,
		    &range_start, &range_end, &fde);

		/* Return fde if tpc is in this range. */

		if (range_start <= pc && pc < range_end) {
			return ((void*) fde);
		}

		if (range_start < pc)
			pi = pr + (1 << log_size);
		else
			pj = pr;
	}
	return (0);
}
