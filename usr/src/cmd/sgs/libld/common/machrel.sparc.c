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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Get the sparc version of the relocation engine */
#define	DO_RELOC_LIBLD_SPARC

#include	<string.h>
#include	<stdio.h>
#include	<sys/elf_SPARC.h>
#include	<debug.h>
#include	<reloc.h>
#include	<sparc/machdep_sparc.h>
#include	"msg.h"
#include	"_libld.h"
#include	"machsym.sparc.h"

/*
 * Local Variable Definitions
 */
static Sword neggotoffset = 0;		/* off. of GOT table from GOT symbol */
static Sword smlgotcnt = M_GOT_XNumber;	/* no. of small GOT symbols */
static Sword mixgotcnt = 0;		/* # syms with both large/small GOT */

/*
 * Search the GOT index list for a GOT entry with a matching reference and the
 * proper addend.
 */
static Gotndx *
ld_find_got_ndx(Alist *alp, Gotref gref, Ofl_desc *ofl, Rel_desc *rdesc)
{
	Aliste	idx;
	Gotndx	*gnp;

	assert(rdesc != 0);

	if ((gref == GOT_REF_TLSLD) && ofl->ofl_tlsldgotndx)
		return (ofl->ofl_tlsldgotndx);

	for (ALIST_TRAVERSE(alp, idx, gnp)) {
		if ((rdesc->rel_raddend == gnp->gn_addend) &&
		    (gref == gnp->gn_gotref))
			return (gnp);
	}
	return (NULL);
}

static Xword
ld_calc_got_offset(Rel_desc * rdesc, Ofl_desc * ofl)
{
	Os_desc		*osp = ofl->ofl_osgot;
	Sym_desc	*sdp = rdesc->rel_sym;
	Xword		gotndx;
	Gotref		gref;
	Gotndx		*gnp;

	if (rdesc->rel_flags & FLG_REL_DTLS)
		gref = GOT_REF_TLSGD;
	else if (rdesc->rel_flags & FLG_REL_MTLS)
		gref = GOT_REF_TLSLD;
	else if (rdesc->rel_flags & FLG_REL_STLS)
		gref = GOT_REF_TLSIE;
	else
		gref = GOT_REF_GENERIC;

	gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, rdesc);
	assert(gnp);

	gotndx = (Xword)gnp->gn_gotndx;

	if ((rdesc->rel_flags & FLG_REL_DTLS) &&
	    (rdesc->rel_rtype == M_R_DTPOFF))
		gotndx++;

	return ((Xword)((osp->os_shdr->sh_addr) + (gotndx * M_GOT_ENTSIZE) +
	    (-neggotoffset * M_GOT_ENTSIZE)));
}

static Word
ld_init_rel(Rel_desc *reld, Word *typedata, void *reloc)
{
	Rela	*rela = (Rela *)reloc;

	/* LINTED */
	reld->rel_rtype = (Word)ELF_R_TYPE(rela->r_info, M_MACH);
	reld->rel_roffset = rela->r_offset;
	reld->rel_raddend = rela->r_addend;
	*typedata = (Word)ELF_R_TYPE_DATA(rela->r_info);

	reld->rel_flags |= FLG_REL_RELA;

	return ((Word)ELF_R_SYM(rela->r_info));
}

static void
ld_mach_eflags(Ehdr *ehdr, Ofl_desc *ofl)
{
	Word		eflags = ofl->ofl_dehdr->e_flags;
	Word		memopt1, memopt2;
	static int	firstpass;

	/*
	 * If a *PLUS relocatable is included, the output object is type *PLUS.
	 */
	if ((ehdr->e_machine == EM_SPARC32PLUS) &&
	    (ehdr->e_flags & EF_SPARC_32PLUS))
		ofl->ofl_dehdr->e_machine = EM_SPARC32PLUS;

	/*
	 * On the first pass, we don't yet have a memory model to compare
	 * against, therefore the initial file becomes our baseline.  Subsequent
	 * passes will do the comparison described below.
	 */
	if (firstpass == 0) {
		ofl->ofl_dehdr->e_flags |= ehdr->e_flags;
		firstpass++;
		return;
	}

	/*
	 * Determine which memory model to mark the binary with.  The options
	 * are (most restrictive to least):
	 *
	 *	EF_SPARCV9_TSO		0x0	Total Store Order
	 *	EF_SPARCV9_PSO		0x1	Partial Store Order
	 *	EF_SPARCV9_RMO		0x2	Relaxed Memory Order
	 *
	 * Mark the binary with the most restrictive option encountered from a
	 * relocatable object included in the link.
	 */
	eflags |= (ehdr->e_flags & ~EF_SPARCV9_MM);
	memopt1 = eflags & EF_SPARCV9_MM;
	memopt2 = ehdr->e_flags & EF_SPARCV9_MM;
	eflags &= ~EF_SPARCV9_MM;

	if ((memopt1 == EF_SPARCV9_TSO) || (memopt2 == EF_SPARCV9_TSO))
		/* EMPTY */
		;
	else if ((memopt1 == EF_SPARCV9_PSO) || (memopt2 == EF_SPARCV9_PSO))
		eflags |= EF_SPARCV9_PSO;
	else
		eflags |= EF_SPARCV9_RMO;

	ofl->ofl_dehdr->e_flags = eflags;
}

static void
ld_mach_make_dynamic(Ofl_desc *ofl, size_t *cnt)
{
	if (!(ofl->ofl_flags & FLG_OF_RELOBJ)) {
		/*
		 * Create this entry if we are going to create a PLT table.
		 */
		if (ofl->ofl_pltcnt)
			(*cnt)++;		/* DT_PLTGOT */
	}
}

static void
ld_mach_update_odynamic(Ofl_desc *ofl, Dyn **dyn)
{
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) && ofl->ofl_pltcnt) {
		(*dyn)->d_tag = DT_PLTGOT;
		if (ofl->ofl_osplt)
			(*dyn)->d_un.d_ptr = ofl->ofl_osplt->os_shdr->sh_addr;
		else
			(*dyn)->d_un.d_ptr = 0;
		(*dyn)++;
	}
}

#if	defined(_ELF64)

static Xword
ld_calc_plt_addr(Sym_desc *sdp, Ofl_desc *ofl)
{
	Xword	value, pltndx, farpltndx;

	pltndx = sdp->sd_aux->sa_PLTndx + M_PLT_XNumber - 1;

	if ((pltndx) < M64_PLT_NEARPLTS) {
		value = (Xword)(ofl->ofl_osplt->os_shdr->sh_addr) +
		    (pltndx * M_PLT_ENTSIZE);
		return (value);
	}

	farpltndx = pltndx - M64_PLT_NEARPLTS;

	/*
	 * pltoffset of a far plt is calculated by:
	 *
	 *	<size of near plt table> +
	 *	<size of preceding far plt blocks> +
	 *	<blockndx * sizeof (far plt entsize)>
	 */
	value =
	    /* size of near plt table */
	    (M64_PLT_NEARPLTS * M_PLT_ENTSIZE) +
	    /* size of preceding far plt blocks */
	    ((farpltndx / M64_PLT_FBLKCNTS) *
	    ((M64_PLT_FENTSIZE + sizeof (Addr)) *
	    M64_PLT_FBLKCNTS)) +
	    /* pltblockendx * fentsize */
	    ((farpltndx % M64_PLT_FBLKCNTS) * M64_PLT_FENTSIZE);

	value += (Xword)(ofl->ofl_osplt->os_shdr->sh_addr);
	return (value);
}

/*
 * Instructions required for Far PLT's
 */
static uchar_t farplt_instrs[24] = {
	0x8a, 0x10, 0x00, 0x0f,		/* mov   %o7, %g5	*/
	0x40, 0x00, 0x00, 0x02,		/* call  . + 0x8	*/
	0x01, 0x00, 0x00, 0x00,		/* nop			*/
	0xc2, 0x5b, 0xe0, 0x00,		/* ldx   [%o7 + 0], %g1	*/
	0x83, 0xc3, 0xc0, 0x01,		/* jmpl  %o7 + %g1, %g1	*/
	0x9e, 0x10, 0x00, 0x05		/* mov   %g5, %o7	*/
};

/*
 * Far PLT'S:
 *
 * Far PLT's are established in blocks of '160' at a time.  These
 * PLT's consist of 6 instructions (24 bytes) and 1 pointer (8 bytes).
 * The instructions are collected together in blocks of 160 entries
 * followed by 160 pointers.  The last group of entries and pointers
 * may contain less then 160 items.  No padding is required.
 *
 *	.PLT32768:
 *		mov	%o7, %g5
 *		call	. + 8
 *		nop
 *		ldx	[%o7 + .PLTP32768 - (.PLT32768 + 4)], %g1
 *		jmpl	%o7 + %g1, %g1
 *		mov	%g5, %o7
 *	................................
 *	.PLT32927:
 *		mov	%o7, %g5
 *		call	. + 8
 *		nop
 *		ldx	[%o7 + .PLTP32927 - (.PLT32927 + 4)], %g1
 *		jmpl	%o7 + %g1, %g1
 *		mov	%g5, %o7
 *	.PLTP32768:
 *		.xword .PLT0-(.PLT32768+4)
 *	................................
 *	.PLTP32927:
 *		.xword .PLT0-(.PLT32927+4)
 *
 */
static void
plt_far_entry(Ofl_desc *ofl, Xword pltndx, Xword *roffset, Sxword *raddend)
{
	uint_t		blockndx;	/* # of far PLT blocks */
	uint_t		farblkcnt;	/* Index to far PLT block */
	Xword		farpltndx;	/* index of Far Plt */
	Xword		farpltblkndx;	/* index of PLT in BLOCK */
	uint32_t	*pltent;	/* ptr to plt instr. sequence */
	uint64_t	*pltentptr;	/* ptr to plt addr ptr */
	Sxword		pltblockoff;	/* offset to Far plt block */
	Sxword		pltoff;		/* offset to PLT instr. sequence */
	Sxword		pltptroff;	/* offset to PLT addr ptr */
	uchar_t		*pltbuf;	/* ptr to PLT's in file */


	farblkcnt = ((ofl->ofl_pltcnt - 1 +
	    M_PLT_XNumber - M64_PLT_NEARPLTS) / M64_PLT_FBLKCNTS);

	/*
	 * Determine the 'Far' PLT index.
	 */
	farpltndx = pltndx - 1 + M_PLT_XNumber - M64_PLT_NEARPLTS;
	farpltblkndx = farpltndx % M64_PLT_FBLKCNTS;

	/*
	 * Determine what FPLT block this plt falls into.
	 */
	blockndx = (uint_t)(farpltndx / M64_PLT_FBLKCNTS);

	/*
	 * Calculate the starting offset of the Far PLT block
	 * that this PLT is a member of.
	 */
	pltblockoff = (M64_PLT_NEARPLTS * M_PLT_ENTSIZE) +
	    (blockndx * M64_PLT_FBLOCKSZ);

	pltoff = pltblockoff +
	    (farpltblkndx * M64_PLT_FENTSIZE);

	pltptroff = pltblockoff;


	if (farblkcnt > blockndx) {
		/*
		 * If this is a full block - the 'pltptroffs' start
		 * after 160 fplts.
		 */
		pltptroff += (M64_PLT_FBLKCNTS * M64_PLT_FENTSIZE) +
		    (farpltblkndx * M64_PLT_PSIZE);
	} else {
		Xword	lastblkpltndx;
		/*
		 * If this is the last block - the the pltptr's start
		 * after the last FPLT instruction sequence.
		 */
		lastblkpltndx = (ofl->ofl_pltcnt - 1 + M_PLT_XNumber -
		    M64_PLT_NEARPLTS) % M64_PLT_FBLKCNTS;
		pltptroff += ((lastblkpltndx + 1) * M64_PLT_FENTSIZE) +
		    (farpltblkndx * M64_PLT_PSIZE);
	}
	pltbuf = (uchar_t *)ofl->ofl_osplt->os_outdata->d_buf;

	/*
	 * For far-plts, the Raddend and Roffset fields are defined
	 * to be:
	 *
	 *	roffset:	address of .PLTP#
	 *	raddend:	-(.PLT#+4)
	 */
	*roffset = pltptroff + (Xword)(ofl->ofl_osplt->os_shdr->sh_addr);
	*raddend = -(pltoff + 4 + (Xword)(ofl->ofl_osplt->os_shdr->sh_addr));

	/* LINTED */
	pltent = (uint32_t *)(pltbuf + pltoff);
	/* LINTED */
	pltentptr = (uint64_t *)(pltbuf + pltptroff);
	(void) memcpy(pltent, farplt_instrs, sizeof (farplt_instrs));

	/*
	 *  update
	 *	ldx   [%o7 + 0], %g1
	 * to
	 *	ldx   [%o7 + .PLTP# - (.PLT# + 4)], %g1
	 */
	/* LINTED */
	pltent[3] |= (uint32_t)(pltptroff - (pltoff + 4));

	/*
	 * Store:
	 *	.PLTP#
	 *		.xword	.PLT0 - .PLT# + 4
	 */
	*pltentptr = -(pltoff + 4);
}

/*
 *	Build a single V9 P.L.T. entry - code is:
 *
 *	For Target Addresses +/- 4GB of the entry
 *	-----------------------------------------
 *	sethi	(. - .PLT0), %g1
 *	ba,a	%xcc, .PLT1
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *
 *	For Target Addresses +/- 2GB of the entry
 *	-----------------------------------------
 *
 *	.PLT0 is the address of the first entry in the P.L.T.
 *	This one is filled in by the run-time link editor. We just
 *	have to leave space for it.
 */
static void
plt_entry(Ofl_desc *ofl, Xword pltndx, Xword *roffset, Sxword *raddend)
{
	uchar_t	*pltent;	/* PLT entry being created. */
	Sxword	pltoff;		/* Offset of this entry from PLT top */
	int	bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;

	/*
	 *  The second part of the V9 ABI (sec. 5.2.4)
	 *  applies to plt entries greater than 0x8000 (32,768).
	 *  This is handled in 'plt_far_entry()'
	 */
	if ((pltndx - 1 + M_PLT_XNumber) >= M64_PLT_NEARPLTS) {
		plt_far_entry(ofl, pltndx, roffset, raddend);
		return;
	}

	pltoff = M_PLT_RESERVSZ + (pltndx - 1) * M_PLT_ENTSIZE;
	pltent = (uchar_t *)ofl->ofl_osplt->os_outdata->d_buf + pltoff;

	*roffset = pltoff + (Xword)(ofl->ofl_osplt->os_shdr->sh_addr);
	*raddend = 0;

	/*
	 * PLT[0]: sethi %hi(. - .L0), %g1
	 */
	/* LINTED */
	*(Word *)pltent = M_SETHIG1 | pltoff;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[1]: ba,a %xcc, .PLT1 (.PLT1 accessed as a
	 * PC-relative index of longwords).
	 */
	pltent += M_PLT_INSSIZE;
	pltoff += M_PLT_INSSIZE;
	pltoff = -pltoff;
	/* LINTED */
	*(Word *)pltent = M_BA_A_XCC |
	    (((pltoff + M_PLT_ENTSIZE) >> 2) & S_MASK(19));
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[2]: sethi 0, %g0 (NOP for delay slot of eventual CTI).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_NOP;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[3]: sethi 0, %g0 (NOP for PLT padding).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_NOP;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[4]: sethi 0, %g0 (NOP for PLT padding).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_NOP;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[5]: sethi 0, %g0 (NOP for PLT padding).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_NOP;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[6]: sethi 0, %g0 (NOP for PLT padding).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_NOP;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[7]: sethi 0, %g0 (NOP for PLT padding).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_NOP;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);
}


#else  /* Elf 32 */

static Xword
ld_calc_plt_addr(Sym_desc *sdp, Ofl_desc *ofl)
{
	Xword	value, pltndx;

	pltndx = sdp->sd_aux->sa_PLTndx + M_PLT_XNumber - 1;
	value = (Xword)(ofl->ofl_osplt->os_shdr->sh_addr) +
	    (pltndx * M_PLT_ENTSIZE);
	return (value);
}


/*
 *	Build a single P.L.T. entry - code is:
 *
 *	sethi	(. - .L0), %g1
 *	ba,a	.L0
 *	sethi	0, %g0		(nop)
 *
 *	.L0 is the address of the first entry in the P.L.T.
 *	This one is filled in by the run-time link editor. We just
 *	have to leave space for it.
 */
static void
plt_entry(Ofl_desc * ofl, Xword pltndx, Xword *roffset, Sxword *raddend)
{
	Byte	*pltent;	/* PLT entry being created. */
	Sxword	pltoff;	/* Offset of this entry from PLT top */
	int	bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;

	pltoff = M_PLT_RESERVSZ + (pltndx - 1) * M_PLT_ENTSIZE;
	pltent = (Byte *)ofl->ofl_osplt->os_outdata->d_buf + pltoff;

	*roffset = pltoff + (Xword)(ofl->ofl_osplt->os_shdr->sh_addr);
	*raddend = 0;

	/*
	 * PLT[0]: sethi %hi(. - .L0), %g1
	 */
	/* LINTED */
	*(Word *)pltent = M_SETHIG1 | pltoff;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[1]: ba,a .L0 (.L0 accessed as a PC-relative index of longwords)
	 */
	pltent += M_PLT_INSSIZE;
	pltoff += M_PLT_INSSIZE;
	pltoff = -pltoff;
	/* LINTED */
	*(Word *)pltent = M_BA_A | ((pltoff >> 2) & S_MASK(22));
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[2]: sethi 0, %g0 (NOP for delay slot of eventual CTI).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_SETHIG0;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);

	/*
	 * PLT[3]: sethi 0, %g0 (NOP for PLT padding).
	 */
	pltent += M_PLT_INSSIZE;
	/* LINTED */
	*(Word *)pltent = M_SETHIG0;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);
}

#endif /* _ELF64 */

static uintptr_t
ld_perform_outreloc(Rel_desc *orsp, Ofl_desc *ofl, Boolean *remain_seen)
{
	Os_desc		*relosp, *osp = NULL;
	Xword		ndx, roffset, value;
	Sxword		raddend;
	const Rel_entry	*rep;
	Rela		rea;
	char		*relbits;
	Sym_desc	*sdp, *psym = NULL;
	int		sectmoved = 0;
	Word		dtflags1 = ofl->ofl_dtflags_1;
	ofl_flag_t	flags = ofl->ofl_flags;

	raddend = orsp->rel_raddend;
	sdp = orsp->rel_sym;

	/*
	 * Special case, a regsiter symbol associated with symbol
	 * index 0 is initialized (i.e. relocated) to a constant
	 * in the r_addend field rather than to a symbol value.
	 */
	if ((orsp->rel_rtype == M_R_REGISTER) && !sdp) {
		relosp = ofl->ofl_osrel;
		relbits = (char *)relosp->os_outdata->d_buf;

		rea.r_info = ELF_R_INFO(0,
		    ELF_R_TYPE_INFO(RELAUX_GET_TYPEDATA(orsp),
		    orsp->rel_rtype));
		rea.r_offset = orsp->rel_roffset;
		rea.r_addend = raddend;
		DBG_CALL(Dbg_reloc_out(ofl, ELF_DBG_LD, SHT_RELA, &rea,
		    relosp->os_name, ld_reloc_sym_name(orsp)));

		assert(relosp->os_szoutrels <= relosp->os_shdr->sh_size);
		(void) memcpy((relbits + relosp->os_szoutrels),
		    (char *)&rea, sizeof (Rela));
		relosp->os_szoutrels += (Xword)sizeof (Rela);

		return (1);
	}

	/*
	 * If the section this relocation is against has been discarded
	 * (-zignore), then also discard (skip) the relocation itself.
	 */
	if (orsp->rel_isdesc && ((orsp->rel_flags &
	    (FLG_REL_GOT | FLG_REL_BSS | FLG_REL_PLT | FLG_REL_NOINFO)) == 0) &&
	    (orsp->rel_isdesc->is_flags & FLG_IS_DISCARD)) {
		DBG_CALL(Dbg_reloc_discard(ofl->ofl_lml, M_MACH, orsp));
		return (1);
	}

	/*
	 * If this is a relocation against a move table, or expanded move
	 * table, adjust the relocation entries.
	 */
	if (RELAUX_GET_MOVE(orsp))
		ld_adj_movereloc(ofl, orsp);

	/*
	 * If this is a relocation against a section then we need to adjust the
	 * raddend field to compensate for the new position of the input section
	 * within the new output section.
	 */
	if (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) {
		if (ofl->ofl_parsyms &&
		    (sdp->sd_isc->is_flags & FLG_IS_RELUPD) &&
		    (psym = ld_am_I_partial(orsp, orsp->rel_raddend))) {
			/*
			 * If the symbol is moved, adjust the value
			 */
			DBG_CALL(Dbg_move_outsctadj(ofl->ofl_lml, psym));
			sectmoved = 1;
			if (ofl->ofl_flags & FLG_OF_RELOBJ)
				raddend = psym->sd_sym->st_value;
			else
				raddend = psym->sd_sym->st_value -
				    psym->sd_isc->is_osdesc->os_shdr->sh_addr;
			/* LINTED */
			raddend += (Off)_elf_getxoff(psym->sd_isc->is_indata);
			if (psym->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
				raddend +=
				    psym->sd_isc->is_osdesc->os_shdr->sh_addr;
		} else {
			/* LINTED */
			raddend += (Off)_elf_getxoff(sdp->sd_isc->is_indata);
			if (sdp->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
				raddend +=
				    sdp->sd_isc->is_osdesc->os_shdr->sh_addr;
		}
	}

	value = sdp->sd_sym->st_value;

	if (orsp->rel_flags & FLG_REL_GOT) {
		osp = ofl->ofl_osgot;
		roffset = ld_calc_got_offset(orsp, ofl);

	} else if (orsp->rel_flags & FLG_REL_PLT) {
		osp = ofl->ofl_osplt;
		plt_entry(ofl, sdp->sd_aux->sa_PLTndx, &roffset, &raddend);
	} else if (orsp->rel_flags & FLG_REL_BSS) {
		/*
		 * This must be a R_SPARC_COPY.  For these set the roffset to
		 * point to the new symbols location.
		 */
		osp = ofl->ofl_isbss->is_osdesc;
		roffset = (Xword)value;

		/*
		 * The raddend doesn't mean anything in an R_SPARC_COPY
		 * relocation.  Null it out because it can confuse people.
		 */
		raddend = 0;
	} else if (orsp->rel_flags & FLG_REL_REG) {
		/*
		 * The offsets of relocations against register symbols
		 * identifiy the register directly - so the offset
		 * does not need to be adjusted.
		 */
		roffset = orsp->rel_roffset;
	} else {
		osp = RELAUX_GET_OSDESC(orsp);

		/*
		 * Calculate virtual offset of reference point; equals offset
		 * into section + vaddr of section for loadable sections, or
		 * offset plus section displacement for nonloadable sections.
		 */
		roffset = orsp->rel_roffset +
		    (Off)_elf_getxoff(orsp->rel_isdesc->is_indata);
		if (!(ofl->ofl_flags & FLG_OF_RELOBJ))
			roffset += orsp->rel_isdesc->is_osdesc->
			    os_shdr->sh_addr;
	}

	if ((osp == 0) || ((relosp = osp->os_relosdesc) == 0))
		relosp = ofl->ofl_osrel;

	/*
	 * Verify that the output relocations offset meets the
	 * alignment requirements of the relocation being processed.
	 */
	rep = &reloc_table[orsp->rel_rtype];
	if (((flags & FLG_OF_RELOBJ) || !(dtflags1 & DF_1_NORELOC)) &&
	    !(rep->re_flags & FLG_RE_UNALIGN)) {
		if (((rep->re_fsize == 2) && (roffset & 0x1)) ||
		    ((rep->re_fsize == 4) && (roffset & 0x3)) ||
		    ((rep->re_fsize == 8) && (roffset & 0x7))) {
			Conv_inv_buf_t inv_buf;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_NONALIGN),
			    conv_reloc_SPARC_type(orsp->rel_rtype, 0, &inv_buf),
			    orsp->rel_isdesc->is_file->ifl_name,
			    ld_reloc_sym_name(orsp), EC_XWORD(roffset));
			return (S_ERROR);
		}
	}

	/*
	 * Assign the symbols index for the output relocation.  If the
	 * relocation refers to a SECTION symbol then it's index is based upon
	 * the output sections symbols index.  Otherwise the index can be
	 * derived from the symbols index itself.
	 */
	if (orsp->rel_rtype == R_SPARC_RELATIVE)
		ndx = STN_UNDEF;
	else if ((orsp->rel_flags & FLG_REL_SCNNDX) ||
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION)) {
		if (sectmoved == 0) {
			/*
			 * Check for a null input section. This can
			 * occur if this relocation references a symbol
			 * generated by sym_add_sym().
			 */
			if (sdp->sd_isc && sdp->sd_isc->is_osdesc)
				ndx = sdp->sd_isc->is_osdesc->os_identndx;
			else
				ndx = sdp->sd_shndx;
		} else
			ndx = ofl->ofl_parexpnndx;
	} else
		ndx = sdp->sd_symndx;

	/*
	 * Add the symbols 'value' to the addend field.
	 */
	if (orsp->rel_flags & FLG_REL_ADVAL)
		raddend += value;

	/*
	 * The addend field for R_SPARC_TLS_DTPMOD32 and R_SPARC_TLS_DTPMOD64
	 * mean nothing.  The addend is propagated in the corresponding
	 * R_SPARC_TLS_DTPOFF* relocations.
	 */
	if (orsp->rel_rtype == M_R_DTPMOD)
		raddend = 0;

	/*
	 * Note that the other case which writes out the relocation, above, is
	 * M_R_REGISTER specific and so does not need this check.
	 */
	if ((orsp->rel_rtype != M_R_NONE) &&
	    (orsp->rel_rtype != M_R_REGISTER) &&
	    (orsp->rel_rtype != M_R_RELATIVE)) {
		if (ndx == 0) {
			Conv_inv_buf_t	inv_buf;
			Is_desc *isp = orsp->rel_isdesc;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_NOSYMBOL),
			    conv_reloc_type(ofl->ofl_nehdr->e_machine,
			    orsp->rel_rtype, 0, &inv_buf),
			    isp->is_file->ifl_name, EC_WORD(isp->is_scnndx),
			    isp->is_name, EC_XWORD(roffset));
			return (S_ERROR);
		}
	}

	rea.r_info = ELF_R_INFO(ndx,
	    ELF_R_TYPE_INFO(RELAUX_GET_TYPEDATA(orsp), orsp->rel_rtype));
	rea.r_offset = roffset;
	rea.r_addend = raddend;
	DBG_CALL(Dbg_reloc_out(ofl, ELF_DBG_LD, SHT_RELA, &rea, relosp->os_name,
	    ld_reloc_sym_name(orsp)));

	/*
	 * Assert we haven't walked off the end of our relocation table.
	 */
	assert(relosp->os_szoutrels <= relosp->os_shdr->sh_size);

	relbits = (char *)relosp->os_outdata->d_buf;

	(void) memcpy((relbits + relosp->os_szoutrels),
	    (char *)&rea, sizeof (Rela));
	relosp->os_szoutrels += (Xword)sizeof (Rela);

	/*
	 * Determine if this relocation is against a non-writable, allocatable
	 * section.  If so we may need to provide a text relocation diagnostic.
	 */
	ld_reloc_remain_entry(orsp, osp, ofl, remain_seen);
	return (1);
}


/*
 * Sparc Instructions for TLS processing
 */
#if	defined(_ELF64)
#define	TLS_GD_IE_LD	0xd0580000	/* ldx [%g0 + %g0], %o0 */
#else
#define	TLS_GD_IE_LD	0xd0000000	/* ld [%g0 + %g0], %o0 */
#endif
#define	TLS_GD_IE_ADD	0x9001c008	/* add %g7, %o0, %o0 */

#define	TLS_GD_LE_XOR	0x80182000	/* xor %g0, 0, %g0 */
#define	TLS_IE_LE_OR	0x80100000	/* or %g0, %o0, %o1 */
					/*  synthetic: mov %g0, %g0 */

#define	TLS_LD_LE_CLRO0	0x90100000	/* clr	%o0 */

#define	FM3_REG_MSK_RD	(0x1f << 25)	/* Formate (3) rd register mask */
					/*	bits 25->29 */
#define	FM3_REG_MSK_RS1	(0x1f << 14)	/* Formate (3) rs1 register mask */
					/*	bits 14->18 */
#define	FM3_REG_MSK_RS2	0x1f		/* Formate (3) rs2 register mask */
					/*	bits 0->4 */

#define	REG_G7		7		/* %g7 register */

static Fixupret
tls_fixups(Ofl_desc *ofl, Rel_desc *arsp)
{
	Sym_desc	*sdp = arsp->rel_sym;
	Word		rtype = arsp->rel_rtype;
	Word		*offset, w;
	int		bswap = OFL_SWAP_RELOC_DATA(ofl, arsp);


	offset = (Word *)((uintptr_t)arsp->rel_roffset +
	    (uintptr_t)_elf_getxoff(arsp->rel_isdesc->is_indata) +
	    (uintptr_t)RELAUX_GET_OSDESC(arsp)->os_outdata->d_buf);

	if (sdp->sd_ref == REF_DYN_NEED) {
		/*
		 * IE reference model
		 */
		switch (rtype) {
		case R_SPARC_TLS_GD_HI22:
			DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
			    R_SPARC_TLS_IE_HI22, arsp,
			    ld_reloc_sym_name));
			arsp->rel_rtype = R_SPARC_TLS_IE_HI22;
			return (FIX_RELOC);

		case R_SPARC_TLS_GD_LO10:
			DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
			    R_SPARC_TLS_IE_LO10, arsp,
			    ld_reloc_sym_name));
			arsp->rel_rtype = R_SPARC_TLS_IE_LO10;
			return (FIX_RELOC);

		case R_SPARC_TLS_GD_ADD:
			DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
			    R_SPARC_NONE, arsp, ld_reloc_sym_name));
			w = bswap ? ld_bswap_Word(*offset) : *offset;
			w = (TLS_GD_IE_LD |
			    (w & (FM3_REG_MSK_RS1 | FM3_REG_MSK_RS2)));
			*offset = bswap ? ld_bswap_Word(w) : w;
			return (FIX_DONE);

		case R_SPARC_TLS_GD_CALL:
			DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
			    R_SPARC_NONE, arsp, ld_reloc_sym_name));
			*offset = TLS_GD_IE_ADD;
			if (bswap)
				*offset = ld_bswap_Word(*offset);
			return (FIX_DONE);
		}
		return (FIX_RELOC);
	}

	/*
	 * LE reference model
	 */
	switch (rtype) {
	case R_SPARC_TLS_IE_HI22:
	case R_SPARC_TLS_GD_HI22:
	case R_SPARC_TLS_LDO_HIX22:
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_TLS_LE_HIX22, arsp, ld_reloc_sym_name));
		arsp->rel_rtype = R_SPARC_TLS_LE_HIX22;
		return (FIX_RELOC);

	case R_SPARC_TLS_LDO_LOX10:
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_TLS_LE_LOX10, arsp, ld_reloc_sym_name));
		arsp->rel_rtype = R_SPARC_TLS_LE_LOX10;
		return (FIX_RELOC);

	case R_SPARC_TLS_IE_LO10:
	case R_SPARC_TLS_GD_LO10:
		/*
		 * Current instruction is:
		 *
		 *	or r1, %lo(x), r2
		 *		or
		 *	add r1, %lo(x), r2
		 *
		 * Need to udpate this to:
		 *
		 *	xor r1, %lox(x), r2
		 */
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_TLS_LE_LOX10, arsp, ld_reloc_sym_name));
		w = bswap ? ld_bswap_Word(*offset) : *offset;
		w = TLS_GD_LE_XOR |
		    (w & (FM3_REG_MSK_RS1 | FM3_REG_MSK_RD));
		*offset = bswap ? ld_bswap_Word(w) : w;
		arsp->rel_rtype = R_SPARC_TLS_LE_LOX10;
		return (FIX_RELOC);

	case R_SPARC_TLS_IE_LD:
	case R_SPARC_TLS_IE_LDX:
		/*
		 * Current instruction:
		 *	ld{x}	[r1 + r2], r3
		 *
		 * Need to update this to:
		 *
		 *	mov	r2, r3   (or  %g0, r2, r3)
		 */
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_NONE, arsp, ld_reloc_sym_name));
		w = bswap ? ld_bswap_Word(*offset) : *offset;
		w = (w & (FM3_REG_MSK_RS2 | FM3_REG_MSK_RD)) | TLS_IE_LE_OR;
		*offset = bswap ? ld_bswap_Word(w) : w;
		return (FIX_DONE);

	case R_SPARC_TLS_LDO_ADD:
	case R_SPARC_TLS_GD_ADD:
		/*
		 * Current instruction is:
		 *
		 *	add gptr_reg, r2, r3
		 *
		 * Need to updated this to:
		 *
		 *	add %g7, r2, r3
		 */
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_NONE, arsp, ld_reloc_sym_name));
		w = bswap ? ld_bswap_Word(*offset) : *offset;
		w = w & (~FM3_REG_MSK_RS1);
		w = w | (REG_G7 << 14);
		*offset = bswap ? ld_bswap_Word(w) : w;
		return (FIX_DONE);

	case R_SPARC_TLS_LDM_CALL:
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_NONE, arsp, ld_reloc_sym_name));
		*offset = TLS_LD_LE_CLRO0;
		if (bswap)
			*offset = ld_bswap_Word(*offset);
		return (FIX_DONE);

	case R_SPARC_TLS_LDM_HI22:
	case R_SPARC_TLS_LDM_LO10:
	case R_SPARC_TLS_LDM_ADD:
	case R_SPARC_TLS_IE_ADD:
	case R_SPARC_TLS_GD_CALL:
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_NONE, arsp, ld_reloc_sym_name));
		*offset = M_NOP;
		if (bswap)
			*offset = ld_bswap_Word(*offset);
		return (FIX_DONE);
	}
	return (FIX_RELOC);
}

#define	GOTOP_ADDINST	0x80000000	/* add %g0, %g0, %g0 */

static Fixupret
gotop_fixups(Ofl_desc *ofl, Rel_desc *arsp)
{
	Word		rtype = arsp->rel_rtype;
	Word		*offset, w;
	const char	*ifl_name;
	Conv_inv_buf_t	inv_buf;
	int		bswap;

	switch (rtype) {
	case R_SPARC_GOTDATA_OP_HIX22:
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_GOTDATA_HIX22, arsp, ld_reloc_sym_name));
		arsp->rel_rtype = R_SPARC_GOTDATA_HIX22;
		return (FIX_RELOC);

	case R_SPARC_GOTDATA_OP_LOX10:
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_GOTDATA_LOX10, arsp, ld_reloc_sym_name));
		arsp->rel_rtype = R_SPARC_GOTDATA_LOX10;
		return (FIX_RELOC);

	case R_SPARC_GOTDATA_OP:
		/*
		 * Current instruction:
		 *	ld{x}	[r1 + r2], r3
		 *
		 * Need to update this to:
		 *
		 *	add	r1, r2, r3
		 */
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_SPARC_NONE, arsp, ld_reloc_sym_name));
		offset = (Word *)(uintptr_t)(arsp->rel_roffset +
		    _elf_getxoff(arsp->rel_isdesc->is_indata) +
		    (uintptr_t)RELAUX_GET_OSDESC(arsp)->os_outdata->d_buf);
		bswap = OFL_SWAP_RELOC_DATA(ofl, arsp);
		w = bswap ? ld_bswap_Word(*offset) : *offset;
		w = (w & (FM3_REG_MSK_RS1 |
		    FM3_REG_MSK_RS2 | FM3_REG_MSK_RD)) | GOTOP_ADDINST;
		*offset = bswap ? ld_bswap_Word(w) : w;
		return (FIX_DONE);
	}
	/*
	 * We should not get here
	 */
	if (arsp->rel_isdesc->is_file)
		ifl_name = arsp->rel_isdesc->is_file->ifl_name;
	else
		ifl_name = MSG_INTL(MSG_STR_NULL);

	ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_BADGOTFIX),
	    conv_reloc_SPARC_type(arsp->rel_rtype, 0, &inv_buf),
	    ifl_name, ld_reloc_sym_name(arsp));

	assert(0);
	return (FIX_ERROR);
}

static uintptr_t
ld_do_activerelocs(Ofl_desc *ofl)
{
	Rel_desc	*arsp;
	Rel_cachebuf	*rcbp;
	Aliste		idx;
	uintptr_t	return_code = 1;
	ofl_flag_t	flags = ofl->ofl_flags;

	if (aplist_nitems(ofl->ofl_actrels.rc_list) != 0)
		DBG_CALL(Dbg_reloc_doact_title(ofl->ofl_lml));

	/*
	 * Process active relocations.
	 */
	REL_CACHE_TRAVERSE(&ofl->ofl_actrels, idx, rcbp, arsp) {
		uchar_t		*addr;
		Xword		value;
		Sym_desc	*sdp;
		const char	*ifl_name;
		Xword		refaddr;
		Os_desc		*osp;

		/*
		 * If the section this relocation is against has been discarded
		 * (-zignore), then discard (skip) the relocation itself.
		 */
		if ((arsp->rel_isdesc->is_flags & FLG_IS_DISCARD) &&
		    ((arsp->rel_flags & (FLG_REL_GOT | FLG_REL_BSS |
		    FLG_REL_PLT | FLG_REL_NOINFO)) == 0)) {
			DBG_CALL(Dbg_reloc_discard(ofl->ofl_lml, M_MACH, arsp));
			continue;
		}

		/*
		 * Perform any required TLS fixups.
		 */
		if (arsp->rel_flags & FLG_REL_TLSFIX) {
			Fixupret	ret;

			if ((ret = tls_fixups(ofl, arsp)) == FIX_ERROR)
				return (S_ERROR);
			if (ret == FIX_DONE)
				continue;
		}

		/*
		 * Perform any required GOTOP fixups.
		 */
		if (arsp->rel_flags & FLG_REL_GOTFIX) {
			Fixupret	ret;

			if ((ret = gotop_fixups(ofl, arsp)) == FIX_ERROR)
				return (S_ERROR);
			if (ret == FIX_DONE)
				continue;
		}

		/*
		 * If this is a relocation against the move table, or
		 * expanded move table, adjust the relocation entries.
		 */
		if (RELAUX_GET_MOVE(arsp))
			ld_adj_movereloc(ofl, arsp);

		sdp = arsp->rel_sym;
		refaddr = arsp->rel_roffset +
		    (Off)_elf_getxoff(arsp->rel_isdesc->is_indata);

		if ((arsp->rel_flags & FLG_REL_CLVAL) ||
		    (arsp->rel_flags & FLG_REL_GOTCL))
			value = 0;
		else if (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) {
			Sym_desc	*sym;

			/*
			 * The value for a symbol pointing to a SECTION
			 * is based off of that sections position.
			 */
			if ((sdp->sd_isc->is_flags & FLG_IS_RELUPD) &&
			    (sym = ld_am_I_partial(arsp, arsp->rel_raddend))) {
				/*
				 * The symbol was moved, so adjust the value
				 * relative to the new section.
				 */
				value = _elf_getxoff(sym->sd_isc->is_indata);
				if (sym->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
					value += sym->sd_isc->
					    is_osdesc->os_shdr->sh_addr;

				/*
				 * The original raddend covers the displacement
				 * from the section start to the desired
				 * address. The value computed above gets us
				 * from the section start to the start of the
				 * symbol range. Adjust the old raddend to
				 * remove the offset from section start to
				 * symbol start, leaving the displacement
				 * within the range of the symbol.
				 */
				arsp->rel_raddend -= sym->sd_osym->st_value;
			} else {
				value = _elf_getxoff(sdp->sd_isc->is_indata);
				if (sdp->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
					value += sdp->sd_isc->
					    is_osdesc->os_shdr->sh_addr;
			}

			if (sdp->sd_isc->is_shdr->sh_flags & SHF_TLS)
				value -= ofl->ofl_tlsphdr->p_vaddr;

		} else if (IS_SIZE(arsp->rel_rtype)) {
			/*
			 * Size relocations require the symbols size.
			 */
			value = sdp->sd_sym->st_size;

		} else if ((sdp->sd_flags & FLG_SY_CAP) &&
		    sdp->sd_aux && sdp->sd_aux->sa_PLTndx) {
			/*
			 * If relocation is against a capabilities symbol, we
			 * need to jump to an associated PLT, so that at runtime
			 * ld.so.1 is involved to determine the best binding
			 * choice. Otherwise, the value is the symbols value.
			 */
			value = ld_calc_plt_addr(sdp, ofl);

		} else
			value = sdp->sd_sym->st_value;

		/*
		 * Relocation against the GLOBAL_OFFSET_TABLE.
		 */
		if ((arsp->rel_flags & FLG_REL_GOT) &&
		    !ld_reloc_set_aux_osdesc(ofl, arsp, ofl->ofl_osgot))
			return (S_ERROR);
		osp = RELAUX_GET_OSDESC(arsp);

		/*
		 * If loadable and not producing a relocatable object add the
		 * sections virtual address to the reference address.
		 */
		if ((arsp->rel_flags & FLG_REL_LOAD) &&
		    ((flags & FLG_OF_RELOBJ) == 0))
			refaddr +=
			    arsp->rel_isdesc->is_osdesc->os_shdr->sh_addr;

		/*
		 * If this entry has a PLT assigned to it, its value is actually
		 * the address of the PLT (and not the address of the function).
		 */
		if (IS_PLT(arsp->rel_rtype)) {
			if (sdp->sd_aux && sdp->sd_aux->sa_PLTndx)
				value = ld_calc_plt_addr(sdp, ofl);
		}

		/*
		 * Add relocations addend to value.  Add extra
		 * relocation addend if needed.
		 */
		value += arsp->rel_raddend;
		if (IS_EXTOFFSET(arsp->rel_rtype))
			value += RELAUX_GET_TYPEDATA(arsp);

		/*
		 * Determine whether the value needs further adjustment. Filter
		 * through the attributes of the relocation to determine what
		 * adjustment is required.  Note, many of the following cases
		 * are only applicable when a .got is present.  As a .got is
		 * not generated when a relocatable object is being built,
		 * any adjustments that require a .got need to be skipped.
		 */
		if ((arsp->rel_flags & FLG_REL_GOT) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Xword		R1addr;
			uintptr_t	R2addr;
			Sword		gotndx;
			Gotndx		*gnp;
			Gotref		gref;

			/*
			 * Clear the GOT table entry, on SPARC we clear
			 * the entry and the 'value' if needed is stored
			 * in an output relocations addend.
			 *
			 * Calculate offset into GOT at which to apply
			 * the relocation.
			 */
			if (arsp->rel_flags & FLG_REL_DTLS)
				gref = GOT_REF_TLSGD;
			else if (arsp->rel_flags & FLG_REL_MTLS)
				gref = GOT_REF_TLSLD;
			else if (arsp->rel_flags & FLG_REL_STLS)
				gref = GOT_REF_TLSIE;
			else
				gref = GOT_REF_GENERIC;

			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);

			if (arsp->rel_rtype == M_R_DTPOFF)
				gotndx = gnp->gn_gotndx + 1;
			else
				gotndx = gnp->gn_gotndx;

			/* LINTED */
			R1addr = (Xword)((-neggotoffset * M_GOT_ENTSIZE) +
			    (gotndx * M_GOT_ENTSIZE));

			/*
			 * Add the GOTs data's offset.
			 */
			R2addr = R1addr + (uintptr_t)osp->os_outdata->d_buf;

			DBG_CALL(Dbg_reloc_doact(ofl->ofl_lml,
			    ELF_DBG_LD_ACT, M_MACH, SHT_RELA,
			    arsp, R1addr, value, ld_reloc_sym_name));

			/*
			 * And do it.
			 */
			if (ofl->ofl_flags1 & FLG_OF1_ENCDIFF)
				*(Xword *)R2addr = ld_bswap_Xword(value);
			else
				*(Xword *)R2addr = value;
			continue;

		} else if (IS_GOT_BASED(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			value -= (ofl->ofl_osgot->os_shdr->sh_addr +
			    (-neggotoffset * M_GOT_ENTSIZE));

		} else if (IS_PC_RELATIVE(arsp->rel_rtype)) {
			value -= refaddr;

		} else if (IS_TLS_INS(arsp->rel_rtype) &&
		    IS_GOT_RELATIVE(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Gotndx	*gnp;
			Gotref	gref;

			if (arsp->rel_flags & FLG_REL_STLS)
				gref = GOT_REF_TLSIE;
			else if (arsp->rel_flags & FLG_REL_DTLS)
				gref = GOT_REF_TLSGD;
			else if (arsp->rel_flags & FLG_REL_MTLS)
				gref = GOT_REF_TLSLD;

			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);

			value = gnp->gn_gotndx * M_GOT_ENTSIZE;

		} else if (IS_GOT_RELATIVE(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Gotndx	*gnp;

			gnp = ld_find_got_ndx(sdp->sd_GOTndxs,
			    GOT_REF_GENERIC, ofl, arsp);
			assert(gnp);

			value = gnp->gn_gotndx * M_GOT_ENTSIZE;

		} else if ((arsp->rel_flags & FLG_REL_STLS) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Xword	tlsstatsize;

			/*
			 * This is the LE TLS reference model. Static offset is
			 * hard-coded, and negated so that it can be added to
			 * the thread pointer (%g7)
			 */
			tlsstatsize =
			    S_ROUND(ofl->ofl_tlsphdr->p_memsz, M_TLSSTATALIGN);
			value = -(tlsstatsize - value);
		}

		if (arsp->rel_isdesc->is_file)
			ifl_name = arsp->rel_isdesc->is_file->ifl_name;
		else
			ifl_name = MSG_INTL(MSG_STR_NULL);

		/*
		 * Make sure we have data to relocate.  Compiler and assembler
		 * developers have been known to generate relocations against
		 * invalid sections (normally .bss), so for their benefit give
		 * them sufficient information to help analyze the problem.
		 * End users should never see this.
		 */
		if (arsp->rel_isdesc->is_indata->d_buf == 0) {
			Conv_inv_buf_t	inv_buf;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_EMPTYSEC),
			    conv_reloc_SPARC_type(arsp->rel_rtype, 0, &inv_buf),
			    ifl_name, ld_reloc_sym_name(arsp),
			    EC_WORD(arsp->rel_isdesc->is_scnndx),
			    arsp->rel_isdesc->is_name);
			return (S_ERROR);
		}

		/*
		 * Get the address of the data item we need to modify.
		 */
		addr = (uchar_t *)((uintptr_t)arsp->rel_roffset +
		    (uintptr_t)_elf_getxoff(arsp->rel_isdesc->is_indata));

		DBG_CALL(Dbg_reloc_doact(ofl->ofl_lml, ELF_DBG_LD_ACT,
		    M_MACH, SHT_RELA, arsp, EC_NATPTR(addr), value,
		    ld_reloc_sym_name));
		addr += (uintptr_t)osp->os_outdata->d_buf;

		if ((((uintptr_t)addr - (uintptr_t)ofl->ofl_nehdr) >
		    ofl->ofl_size) || (arsp->rel_roffset >
		    osp->os_shdr->sh_size)) {
			Conv_inv_buf_t	inv_buf;
			int		class;

			if (((uintptr_t)addr - (uintptr_t)ofl->ofl_nehdr) >
			    ofl->ofl_size)
				class = ERR_FATAL;
			else
				class = ERR_WARNING;

			ld_eprintf(ofl, class, MSG_INTL(MSG_REL_INVALOFFSET),
			    conv_reloc_SPARC_type(arsp->rel_rtype, 0, &inv_buf),
			    ifl_name, EC_WORD(arsp->rel_isdesc->is_scnndx),
			    arsp->rel_isdesc->is_name, ld_reloc_sym_name(arsp),
			    EC_ADDR((uintptr_t)addr -
			    (uintptr_t)ofl->ofl_nehdr));

			if (class == ERR_FATAL) {
				return_code = S_ERROR;
				continue;
			}
		}

		/*
		 * If '-z noreloc' is specified - skip the do_reloc stage.
		 */
		if (OFL_DO_RELOC(ofl)) {
			if (do_reloc_ld(arsp, addr, &value, ld_reloc_sym_name,
			    ifl_name, OFL_SWAP_RELOC_DATA(ofl, arsp),
			    ofl->ofl_lml) == 0) {
				ofl->ofl_flags |= FLG_OF_FATAL;
				return_code = S_ERROR;
			}
		}
	}
	return (return_code);
}

static uintptr_t
ld_add_outrel(Word flags, Rel_desc *rsp, Ofl_desc *ofl)
{
	Rel_desc	*orsp;
	Sym_desc	*sdp = rsp->rel_sym;
	Conv_inv_buf_t	inv_buf;

	/*
	 * Static executables *do not* want any relocations against them.
	 * Since our engine still creates relocations against a WEAK UNDEFINED
	 * symbol in a static executable, it's best to disable them here
	 * instead of through out the relocation code.
	 */
	if (OFL_IS_STATIC_EXEC(ofl))
		return (1);

	/*
	 * If the symbol will be reduced, we can't leave outstanding
	 * relocations against it, as nothing will ever be able to satisfy them
	 * (and the symbol won't be in .dynsym
	 */
	if ((sdp != NULL) &&
	    (sdp->sd_sym->st_shndx == SHN_UNDEF) &&
	    (rsp->rel_rtype != M_R_NONE) &&
	    (rsp->rel_rtype != M_R_REGISTER) &&
	    (rsp->rel_rtype != M_R_RELATIVE)) {
		if (ld_sym_reducable(ofl, sdp))
			return (1);
	}

	/*
	 * Certain relocations do not make sense in a 64bit shared object,
	 * if building a shared object do a sanity check on the output
	 * relocations being created.
	 */
	if (ofl->ofl_flags & FLG_OF_SHAROBJ) {
		Word	rtype = rsp->rel_rtype;
		/*
		 * Because the R_SPARC_HIPLT22 & R_SPARC_LOPLT10 relocations
		 * are not relative they make no sense to create in a shared
		 * object - so emit the proper error message if that occurs.
		 */
		if ((rtype == R_SPARC_HIPLT22) || (rtype == R_SPARC_LOPLT10)) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_UNRELREL),
			    conv_reloc_SPARC_type(rsp->rel_rtype, 0, &inv_buf),
			    rsp->rel_isdesc->is_file->ifl_name,
			    ld_reloc_sym_name(rsp));
			return (S_ERROR);
		}
#if	defined(_ELF64)
		/*
		 * Each of the following relocations requires that the
		 * object being built be loaded in either the upper 32 or
		 * 44 bit range of memory.  Since shared libraries traditionally
		 * are loaded in the lower range of memory - this isn't going
		 * to work.
		 */
		if ((rtype == R_SPARC_H44) || (rtype == R_SPARC_M44) ||
		    (rtype == R_SPARC_L44)) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_SHOBJABS44),
			    conv_reloc_SPARC_type(rsp->rel_rtype, 0, &inv_buf),
			    rsp->rel_isdesc->is_file->ifl_name,
			    ld_reloc_sym_name(rsp));
			return (S_ERROR);
		}
#endif
	}

	/*
	 * If we are adding a output relocation against a section
	 * symbol (non-RELATIVE) then mark that section.  These sections
	 * will be added to the .dynsym symbol table.
	 */
	if (sdp && (rsp->rel_rtype != M_R_RELATIVE) &&
	    ((flags & FLG_REL_SCNNDX) ||
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION))) {

		/*
		 * If this is a COMMON symbol - no output section
		 * exists yet - (it's created as part of sym_validate()).
		 * So - we mark here that when it's created it should
		 * be tagged with the FLG_OS_OUTREL flag.
		 */
		if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
		    (sdp->sd_sym->st_shndx == SHN_COMMON)) {
			if (ELF_ST_TYPE(sdp->sd_sym->st_info) != STT_TLS)
				ofl->ofl_flags1 |= FLG_OF1_BSSOREL;
			else
				ofl->ofl_flags1 |= FLG_OF1_TLSOREL;
		} else {
			Os_desc	*osp;
			Is_desc	*isp = sdp->sd_isc;

			if (isp && ((osp = isp->is_osdesc) != NULL) &&
			    ((osp->os_flags & FLG_OS_OUTREL) == 0)) {
				ofl->ofl_dynshdrcnt++;
				osp->os_flags |= FLG_OS_OUTREL;
			}
		}
	}

	/* Enter it into the output relocation cache */
	if ((orsp = ld_reloc_enter(ofl, &ofl->ofl_outrels, rsp, flags)) == NULL)
		return (S_ERROR);

	if (flags & FLG_REL_GOT)
		ofl->ofl_relocgotsz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_PLT)
		ofl->ofl_relocpltsz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_BSS)
		ofl->ofl_relocbsssz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_NOINFO)
		ofl->ofl_relocrelsz += (Xword)sizeof (Rela);
	else
		RELAUX_GET_OSDESC(orsp)->os_szoutrels += (Xword)sizeof (Rela);

	if (orsp->rel_rtype == M_R_RELATIVE)
		ofl->ofl_relocrelcnt++;

#if	defined(_ELF64)
	/*
	 * When building a 64-bit object any R_SPARC_WDISP30 relocation is given
	 * a plt padding entry, unless we're building a relocatable object
	 * (ld -r) or -b is in effect.
	 */
	if ((orsp->rel_rtype == R_SPARC_WDISP30) &&
	    ((ofl->ofl_flags & (FLG_OF_BFLAG | FLG_OF_RELOBJ)) == 0) &&
	    ((orsp->rel_sym->sd_flags & FLG_SY_PLTPAD) == 0)) {
		ofl->ofl_pltpad++;
		orsp->rel_sym->sd_flags |= FLG_SY_PLTPAD;
	}
#endif
	/*
	 * We don't perform sorting on PLT relocations because
	 * they have already been assigned a PLT index and if we
	 * were to sort them we would have to re-assign the plt indexes.
	 */
	if (!(flags & FLG_REL_PLT))
		ofl->ofl_reloccnt++;

	/*
	 * Insure a GLOBAL_OFFSET_TABLE is generated if required.
	 */
	if (IS_GOT_REQUIRED(orsp->rel_rtype))
		ofl->ofl_flags |= FLG_OF_BLDGOT;

	/*
	 * Identify and possibly warn of a displacement relocation.
	 */
	if (orsp->rel_flags & FLG_REL_DISP) {
		ofl->ofl_dtflags_1 |= DF_1_DISPRELPND;

		if (ofl->ofl_flags & FLG_OF_VERBOSE)
			ld_disp_errmsg(MSG_INTL(MSG_REL_DISPREL4), orsp, ofl);
	}
	DBG_CALL(Dbg_reloc_ors_entry(ofl->ofl_lml, ELF_DBG_LD, SHT_RELA,
	    M_MACH, orsp));
	return (1);
}

/*
 * Process relocation against a register symbol.  Note, of -z muldefs is in
 * effect there may have been multiple register definitions, which would have
 * been processed as non-fatal, with the first definition winning.  But, we
 * will also process multiple relocations for these multiple definitions.  In
 * this case we must only preserve the relocation for the definition that was
 * kept.  The sad part is that register relocations don't typically specify
 * the register symbol with which they are associated, so we might have to
 * search the input files global symbols to determine if this relocation is
 * appropriate.
 */
static uintptr_t
ld_reloc_register(Rel_desc *rsp, Is_desc *isp, Ofl_desc *ofl)
{
	if (ofl->ofl_flags & FLG_OF_MULDEFS) {
		Ifl_desc	*ifl = isp->is_file;
		Sym_desc	*sdp = rsp->rel_sym;

		if (sdp == 0) {
			Xword		offset = rsp->rel_roffset;
			Word		ndx;

			for (ndx = ifl->ifl_locscnt;
			    ndx < ifl->ifl_symscnt; ndx++) {
				if (((sdp = ifl->ifl_oldndx[ndx]) != 0) &&
				    (sdp->sd_flags & FLG_SY_REGSYM) &&
				    (sdp->sd_sym->st_value == offset))
					break;
			}
		}
		if (sdp && (sdp->sd_file != ifl))
			return (1);
	}
	return (ld_add_outrel((rsp->rel_flags | FLG_REL_REG), rsp, ofl));
}

/*
 * process relocation for a LOCAL symbol
 */
static uintptr_t
ld_reloc_local(Rel_desc *rsp, Ofl_desc *ofl)
{
	ofl_flag_t	flags = ofl->ofl_flags;
	Sym_desc	*sdp = rsp->rel_sym;
	Word		shndx = sdp->sd_sym->st_shndx;

	/*
	 * if ((shared object) and (not pc relative relocation) and
	 *    (not against ABS symbol))
	 * then
	 *	if (rtype != R_SPARC_32)
	 *	then
	 *		build relocation against section
	 *	else
	 *		build R_SPARC_RELATIVE
	 *	fi
	 * fi
	 */
	if ((flags & FLG_OF_SHAROBJ) && (rsp->rel_flags & FLG_REL_LOAD) &&
	    !(IS_PC_RELATIVE(rsp->rel_rtype)) && !(IS_SIZE(rsp->rel_rtype)) &&
	    !(IS_GOT_BASED(rsp->rel_rtype)) &&
	    !(rsp->rel_isdesc != NULL &&
	    (rsp->rel_isdesc->is_shdr->sh_type == SHT_SUNW_dof)) &&
	    (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) ||
	    (shndx != SHN_ABS) || (sdp->sd_aux && sdp->sd_aux->sa_symspec))) {
		Word	ortype = rsp->rel_rtype;

		if ((rsp->rel_rtype != R_SPARC_32) &&
		    (rsp->rel_rtype != R_SPARC_PLT32) &&
		    (rsp->rel_rtype != R_SPARC_64))
			return (ld_add_outrel((FLG_REL_SCNNDX | FLG_REL_ADVAL),
			    rsp, ofl));

		rsp->rel_rtype = R_SPARC_RELATIVE;
		if (ld_add_outrel(FLG_REL_ADVAL, rsp, ofl) == S_ERROR)
			return (S_ERROR);
		rsp->rel_rtype = ortype;
		return (1);
	}

	/*
	 * If the relocation is against a 'non-allocatable' section
	 * and we can not resolve it now - then give a warning
	 * message.
	 *
	 * We can not resolve the symbol if either:
	 *	a) it's undefined
	 *	b) it's defined in a shared library and a
	 *	   COPY relocation hasn't moved it to the executable
	 *
	 * Note: because we process all of the relocations against the
	 *	text segment before any others - we know whether
	 *	or not a copy relocation will be generated before
	 *	we get here (see reloc_init()->reloc_segments()).
	 */
	if (!(rsp->rel_flags & FLG_REL_LOAD) &&
	    ((shndx == SHN_UNDEF) ||
	    ((sdp->sd_ref == REF_DYN_NEED) &&
	    ((sdp->sd_flags & FLG_SY_MVTOCOMM) == 0)))) {
		Conv_inv_buf_t	inv_buf;
		Os_desc		*osp = RELAUX_GET_OSDESC(rsp);

		/*
		 * If the relocation is against a SHT_SUNW_ANNOTATE
		 * section - then silently ignore that the relocation
		 * can not be resolved.
		 */
		if (osp && (osp->os_shdr->sh_type == SHT_SUNW_ANNOTATE))
			return (0);
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_EXTERNSYM),
		    conv_reloc_SPARC_type(rsp->rel_rtype, 0, &inv_buf),
		    rsp->rel_isdesc->is_file->ifl_name,
		    ld_reloc_sym_name(rsp), osp->os_name);
		return (1);
	}

	/*
	 * Perform relocation.
	 */
	return (ld_add_actrel(0, rsp, ofl));
}

/*
 * Establish a relocation transition.  Note, at this point of input relocation
 * processing, we have no idea of the relocation value that will be used in
 * the eventual relocation calculation.  This value is only known after the
 * initial image has been constructed.  Therefore, there is a small chance
 * that a value can exceed the capabilities of the transitioned relocation.
 * One example might be the offset from the GOT to a symbol.
 *
 * The only instance of this failure discovered so far has been via the use of
 * ABS symbols to represent an external memory location.  This situation is
 * rare, since ABS symbols aren't typically generated by the compilers.
 * Therefore, our solution is to excluded ABS symbols from the transition
 * relocation possibilities.  As an additional safeguard, if an inappropriate
 * value is passed to the final relocation engine, a verification ("V")
 * relocation should trigger a fatal error condition.
 */
static uintptr_t
ld_reloc_GOTOP(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	Word	rtype = rsp->rel_rtype;

	if (!local || (rsp->rel_sym->sd_sym->st_shndx == SHN_ABS)) {
		/*
		 * When binding to a external symbol, no fixups are required
		 * and the GOTDATA_OP relocation can be ignored.
		 */
		if (rtype == R_SPARC_GOTDATA_OP)
			return (1);
		return (ld_reloc_GOT_relative(local, rsp, ofl));
	}

	/*
	 * When binding to a local symbol the relocations can be transitioned:
	 *
	 *	R_*_GOTDATA_OP_HIX22 -> R_*_GOTDATA_HIX22
	 *	R_*_GOTDATA_OP_LOX10 -> R_*_GOTDATA_LOX10
	 *	R_*_GOTDATA_OP ->	instruction fixup
	 */
	return (ld_add_actrel(FLG_REL_GOTFIX, rsp, ofl));
}

static uintptr_t
ld_reloc_TLS(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	Word		rtype = rsp->rel_rtype;
	Sym_desc	*sdp = rsp->rel_sym;
	ofl_flag_t	flags = ofl->ofl_flags;
	Gotndx		*gnp;

	/*
	 * If we're building an executable - use either the IE or LE access
	 * model.  If we're building a shared object process any IE model.
	 */
	if ((flags & FLG_OF_EXEC) || (IS_TLS_IE(rtype))) {
		/*
		 * Set the DF_STATIC_TLS flag.
		 */
		ofl->ofl_dtflags |= DF_STATIC_TLS;

		if (!local || ((flags & FLG_OF_EXEC) == 0)) {
			/*
			 * When processing static TLS - these relocations
			 * can be ignored.
			 */
			if ((rtype == R_SPARC_TLS_IE_LD) ||
			    (rtype == R_SPARC_TLS_IE_LDX) ||
			    (rtype == R_SPARC_TLS_IE_ADD))
				return (1);

			/*
			 * Assign a GOT entry for IE static TLS references.
			 */
			if (((rtype == R_SPARC_TLS_GD_HI22) ||
			    (rtype == R_SPARC_TLS_GD_LO10) ||
			    (rtype == R_SPARC_TLS_IE_HI22) ||
			    (rtype == R_SPARC_TLS_IE_LO10)) &&
			    ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs,
			    GOT_REF_TLSIE, ofl, rsp)) == NULL)) {

				if (ld_assign_got_TLS(local, rsp, ofl, sdp,
				    gnp, GOT_REF_TLSIE, FLG_REL_STLS,
				    rtype, M_R_TPOFF, 0) == S_ERROR)
					return (S_ERROR);
			}

			/*
			 * IE access model.
			 */
			if (IS_TLS_IE(rtype))
				return (ld_add_actrel(FLG_REL_STLS, rsp, ofl));

			/*
			 * Fixups are required for other executable models.
			 */
			return (ld_add_actrel((FLG_REL_TLSFIX | FLG_REL_STLS),
			    rsp, ofl));
		}

		/*
		 * LE access model.
		 */
		if (IS_TLS_LE(rtype))
			return (ld_add_actrel(FLG_REL_STLS, rsp, ofl));

		/*
		 * When processing static TLS - these relocations can be
		 * ignored.
		 */
		if (rtype == R_SPARC_TLS_IE_ADD)
			return (1);

		return (ld_add_actrel((FLG_REL_TLSFIX | FLG_REL_STLS),
		    rsp, ofl));
	}

	/*
	 * Building a shared object.
	 *
	 * For dynamic TLS references, ADD relocations are ignored.
	 */
	if ((rtype == R_SPARC_TLS_GD_ADD) || (rtype == R_SPARC_TLS_LDM_ADD) ||
	    (rtype == R_SPARC_TLS_LDO_ADD))
		return (1);

	/*
	 * Assign a GOT entry for a dynamic TLS reference.
	 */
	if (((rtype == R_SPARC_TLS_LDM_HI22) ||
	    (rtype == R_SPARC_TLS_LDM_LO10)) &&
	    ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs, GOT_REF_TLSLD,
	    ofl, rsp)) == NULL)) {

		if (ld_assign_got_TLS(local, rsp, ofl, sdp, gnp, GOT_REF_TLSLD,
		    FLG_REL_MTLS, rtype, M_R_DTPMOD, 0) == S_ERROR)
			return (S_ERROR);

	} else if (((rtype == R_SPARC_TLS_GD_HI22) ||
	    (rtype == R_SPARC_TLS_GD_LO10)) &&
	    ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs, GOT_REF_TLSGD,
	    ofl, rsp)) == NULL)) {

		if (ld_assign_got_TLS(local, rsp, ofl, sdp, gnp, GOT_REF_TLSGD,
		    FLG_REL_DTLS, rtype, M_R_DTPMOD, M_R_DTPOFF) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * For GD/LD TLS reference - TLS_{GD,LD}_CALL, this will eventually
	 * cause a call to __tls_get_addr().  Convert this relocation to that
	 * symbol now, and prepare for the PLT magic.
	 */
	if ((rtype == R_SPARC_TLS_GD_CALL) || (rtype == R_SPARC_TLS_LDM_CALL)) {
		Sym_desc	*tlsgetsym;

		if ((tlsgetsym = ld_sym_add_u(MSG_ORIG(MSG_SYM_TLSGETADDR_U),
		    ofl, MSG_STR_TLSREL)) == (Sym_desc *)S_ERROR)
			return (S_ERROR);

		rsp->rel_sym = tlsgetsym;
		rsp->rel_rtype = R_SPARC_WPLT30;

		if (ld_reloc_plt(rsp, ofl) == S_ERROR)
			return (S_ERROR);

		rsp->rel_sym = sdp;
		rsp->rel_rtype = rtype;
		return (1);
	}

	if (IS_TLS_LD(rtype))
		return (ld_add_actrel(FLG_REL_MTLS, rsp, ofl));

	return (ld_add_actrel(FLG_REL_DTLS, rsp, ofl));
}

/*
 * ld_allocate_got: if a GOT is to be made, after the section is built this
 * function is called to allocate all the GOT slots.  The allocation is
 * deferred until after all GOTs have been counted and sorted according
 * to their size, for only then will we know how to allocate them on
 * a processor like SPARC which has different models for addressing the
 * GOT.  SPARC has two: small and large, small uses a signed 13-bit offset
 * into the GOT, whereas large uses an unsigned 32-bit offset.
 */
static	Sword small_index;	/* starting index for small GOT entries */
static	Sword mixed_index;	/* starting index for mixed GOT entries */
static	Sword large_index;	/* starting index for large GOT entries */

static uintptr_t
ld_assign_got(Ofl_desc *ofl, Sym_desc *sdp)
{
	Aliste idx;
	Gotndx *gnp;

	for (ALIST_TRAVERSE(sdp->sd_GOTndxs, idx, gnp)) {
		uint_t	gotents;
		Gotref	gref = gnp->gn_gotref;

		if ((gref == GOT_REF_TLSGD) || (gref == GOT_REF_TLSLD))
			gotents = 2;
		else
			gotents = 1;

		switch (gnp->gn_gotndx) {
		case M_GOT_SMALL:
			gnp->gn_gotndx = small_index;
			small_index += gotents;
			if (small_index == 0)
				small_index = M_GOT_XNumber;
			break;
		case M_GOT_MIXED:
			gnp->gn_gotndx = mixed_index;
			mixed_index += gotents;
			break;
		case M_GOT_LARGE:
			gnp->gn_gotndx = large_index;
			large_index += gotents;
			break;
		default:
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_ASSIGNGOT),
			    EC_XWORD(gnp->gn_gotndx), demangle(sdp->sd_name));
			return (S_ERROR);
		}
	}
	return (1);
}

static uintptr_t
ld_assign_got_ndx(Alist **alpp, Gotndx *pgnp, Gotref gref, Ofl_desc *ofl,
    Rel_desc *rsp, Sym_desc *sdp)
{
	Xword		raddend;
	Gotndx		gn, *gnp;
	Aliste		idx;
	uint_t		gotents;

	/* Some TLS requires two relocations with two GOT entries */
	if ((gref == GOT_REF_TLSGD) || (gref == GOT_REF_TLSLD))
		gotents = 2;
	else
		gotents = 1;

	raddend = rsp->rel_raddend;
	if (pgnp && (pgnp->gn_addend == raddend) && (pgnp->gn_gotref == gref)) {

		/*
		 * If an entry for this addend already exists, determine if it
		 * has mixed mode GOT access (both PIC and pic).
		 *
		 * In order to be accessible by both large and small pic,
		 * a mixed mode GOT must be located in the positive index
		 * range above _GLOBAL_OFFSET_TABLE_, and in the range
		 * reachable small pic. This is necessary because the large
		 * PIC mode cannot use a negative offset. This implies that
		 * there can be no more than (M_GOT_MAXSMALL/2 - M_GOT_XNumber)
		 * such entries.
		 */
		switch (pgnp->gn_gotndx) {
		case M_GOT_SMALL:
			/*
			 * This one was previously identified as a small
			 * GOT. If this access is large, then convert
			 * it to mixed.
			 */
			if (rsp->rel_rtype != R_SPARC_GOT13) {
				pgnp->gn_gotndx = M_GOT_MIXED;
				mixgotcnt += gotents;
			}
			break;

		case M_GOT_LARGE:
			/*
			 * This one was previously identified as a large
			 * GOT. If this access is small, convert it to mixed.
			 */
			if (rsp->rel_rtype == R_SPARC_GOT13) {
				smlgotcnt += gotents;
				mixgotcnt += gotents;
				pgnp->gn_gotndx = M_GOT_MIXED;
				sdp->sd_flags |= FLG_SY_SMGOT;
			}
			break;
		}
		return (1);
	}

	gn.gn_addend = raddend;
	gn.gn_gotref = gref;

	if (rsp->rel_rtype == R_SPARC_GOT13) {
		gn.gn_gotndx = M_GOT_SMALL;
		smlgotcnt += gotents;
		sdp->sd_flags |= FLG_SY_SMGOT;
	} else
		gn.gn_gotndx = M_GOT_LARGE;

	ofl->ofl_gotcnt += gotents;

	if (gref == GOT_REF_TLSLD) {
		if (ofl->ofl_tlsldgotndx == NULL) {
			if ((gnp = libld_malloc(sizeof (Gotndx))) == NULL)
				return (S_ERROR);
			(void) memcpy(gnp, &gn, sizeof (Gotndx));
			ofl->ofl_tlsldgotndx = gnp;
		}
		return (1);
	}

	idx = 0;
	for (ALIST_TRAVERSE(*alpp, idx, gnp)) {
		if (gnp->gn_addend > raddend)
			break;
	}

	/*
	 * GOT indexes are maintained on an Alist, where there is typically
	 * only one index.  The usage of this list is to scan the list to find
	 * an index, and then apply that index immediately to a relocation.
	 * Thus there are no external references to these GOT index structures
	 * that can be compromised by the Alist being reallocated.
	 */
	if (alist_insert(alpp, &gn, sizeof (Gotndx),
	    AL_CNT_SDP_GOT, idx) == NULL)
		return (S_ERROR);

	return (1);
}

static void
ld_assign_plt_ndx(Sym_desc * sdp, Ofl_desc *ofl)
{
	sdp->sd_aux->sa_PLTndx = 1 + ofl->ofl_pltcnt++;
}


static uintptr_t
ld_allocate_got(Ofl_desc * ofl)
{
	const Sword	first_large_ndx = M_GOT_MAXSMALL / 2;
	Sym_desc	*sdp;
	Addr		addr;

	/*
	 * Sanity check -- is this going to fit at all? There are two
	 * limits to be concerned about:
	 *	1) There is a limit on the number of small pic GOT indices,
	 *		given by M_GOT_MAXSMALL.
	 *	2) If there are more than (M_GOT_MAXSMALL/2 - M_GOT_XNumber)
	 *		small GOT indices, there will be items at negative
	 *		offsets from _GLOBAL_OFFSET_TABLE_. Items that are
	 *		accessed via large (PIC) code cannot reach these
	 *		negative slots, so mixed mode items must be in the
	 *		non-negative range. This implies a limit of
	 *		(M_GOT_MAXSMALL/2 - M_GOT_XNumber) mixed mode indices.
	 */
	if (smlgotcnt > M_GOT_MAXSMALL) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_SMALLGOT),
		    EC_WORD(smlgotcnt), M_GOT_MAXSMALL);
		return (S_ERROR);
	}
	if (mixgotcnt > (first_large_ndx - M_GOT_XNumber)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_MIXEDGOT),
		    EC_WORD(mixgotcnt), first_large_ndx - M_GOT_XNumber);
		return (S_ERROR);
	}

	/*
	 * Set starting offset to be either 0, or a negative index into
	 * the GOT based on the number of small symbols we've got.
	 */
	neggotoffset = ((smlgotcnt >= first_large_ndx) ?
	    (first_large_ndx - smlgotcnt) : 0);

	/*
	 * Initialize the got offsets used by assign_got() to
	 * locate GOT items:
	 *	small - Starting index of items referenced only
	 *		by small offsets (-Kpic).
	 *	mixed - Starting index of items referenced
	 *		by both large (-KPIC) and small (-Kpic).
	 *	large - Indexes referenced only by large (-KPIC)
	 *
	 *  Small items can have negative indexes (i.e. lie below
	 *	_GLOBAL_OFFSET_TABLE_). Mixed and large items must have
	 *	non-negative offsets.
	 */
	small_index = (neggotoffset == 0) ? M_GOT_XNumber : neggotoffset;
	large_index = neggotoffset + smlgotcnt;
	mixed_index = large_index - mixgotcnt;

	/*
	 * Assign bias to GOT symbols.
	 */
	addr = -neggotoffset * M_GOT_ENTSIZE;
	if ((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_GOFTBL), SYM_NOHASH,
	    NULL, ofl)) != NULL)
		sdp->sd_sym->st_value = addr;
	if ((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_GOFTBL_U), SYM_NOHASH,
	    NULL, ofl)) != NULL)
		sdp->sd_sym->st_value = addr;

	if (ofl->ofl_tlsldgotndx) {
		ofl->ofl_tlsldgotndx->gn_gotndx = large_index;
		large_index += 2;
	}
	return (1);
}

/*
 * Initializes .got[0] with the _DYNAMIC symbol value.
 */
static uintptr_t
ld_fillin_gotplt(Ofl_desc *ofl)
{
	if (ofl->ofl_osgot) {
		Sym_desc	*sdp;

		if ((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_DYNAMIC_U),
		    SYM_NOHASH, NULL, ofl)) != NULL) {
			uchar_t	*genptr;

			genptr = ((uchar_t *)ofl->ofl_osgot->os_outdata->d_buf +
			    (-neggotoffset * M_GOT_ENTSIZE) +
			    (M_GOT_XDYNAMIC * M_GOT_ENTSIZE));
			/* LINTED */
			*((Xword *)genptr) = sdp->sd_sym->st_value;
			if (ofl->ofl_flags1 & FLG_OF1_ENCDIFF)
				/* LINTED */
				*((Xword *)genptr) =
				    /* LINTED */
				    ld_bswap_Xword(*((Xword *)genptr));
		}
	}
	return (1);
}



/*
 * Template for generating "void (*)(void)" function
 */
static const uchar_t nullfunc_tmpl[] = {
/* 0x00 */	0x81, 0xc3, 0xe0, 0x08,		/* retl */
/* 0x04 */	0x01, 0x00, 0x00, 0x00		/* nop */
};



/*
 * Return the ld_targ definition for this target.
 */
const Target *
ld_targ_init_sparc(void)
{
	static const Target _ld_targ = {
		{			/* Target_mach */
			M_MACH,			/* m_mach */
			M_MACHPLUS,		/* m_machplus */
			M_FLAGSPLUS,		/* m_flagsplus */
			M_CLASS,		/* m_class */
			M_DATA,			/* m_data */

			M_SEGM_ALIGN,		/* m_segm_align */
			M_SEGM_ORIGIN,		/* m_segm_origin */
			M_SEGM_AORIGIN,		/* m_segm_aorigin */
			M_DATASEG_PERM,		/* m_dataseg_perm */
			M_STACK_PERM,		/* m_stack_perm */
			M_WORD_ALIGN,		/* m_word_align */
						/* m_def_interp */
#if	defined(_ELF64)
			MSG_ORIG(MSG_PTH_RTLD_SPARCV9),
#else
			MSG_ORIG(MSG_PTH_RTLD),
#endif

			/* Relocation type codes */
			M_R_ARRAYADDR,		/* m_r_arrayaddr */
			M_R_COPY,		/* m_r_copy */
			M_R_GLOB_DAT,		/* m_r_glob_dat */
			M_R_JMP_SLOT,		/* m_r_jmp_slot */
			M_R_NUM,		/* m_r_num */
			M_R_NONE,		/* m_r_none */
			M_R_RELATIVE,		/* m_r_relative */
			M_R_REGISTER,		/* m_r_register */

			/* Relocation related constants */
			M_REL_DT_COUNT,		/* m_rel_dt_count */
			M_REL_DT_ENT,		/* m_rel_dt_ent */
			M_REL_DT_SIZE,		/* m_rel_dt_size */
			M_REL_DT_TYPE,		/* m_rel_dt_type */
			M_REL_SHT_TYPE,		/* m_rel_sht_type */

			/* GOT related constants */
			M_GOT_ENTSIZE,		/* m_got_entsize */
			M_GOT_XNumber,		/* m_got_xnumber */

			/* PLT related constants */
			M_PLT_ALIGN,		/* m_plt_align */
			M_PLT_ENTSIZE,		/* m_plt_entsize */
			M_PLT_RESERVSZ,		/* m_plt_reservsz */
			M_PLT_SHF_FLAGS,	/* m_plt_shf_flags */

			/* Section type of .eh_frame/.eh_frame_hdr sections */
			SHT_PROGBITS,		/* m_sht_unwind */

			M_DT_REGISTER,		/* m_dt_register */
		},
		{			/* Target_machid */
			M_ID_ARRAY,		/* id_array */
			M_ID_BSS,		/* id_bss */
			M_ID_CAP,		/* id_cap */
			M_ID_CAPINFO,		/* id_capinfo */
			M_ID_CAPCHAIN,		/* id_capchain */
			M_ID_DATA,		/* id_data */
			M_ID_DYNAMIC,		/* id_dynamic */
			M_ID_DYNSORT,		/* id_dynsort */
			M_ID_DYNSTR,		/* id_dynstr */
			M_ID_DYNSYM,		/* id_dynsym */
			M_ID_DYNSYM_NDX,	/* id_dynsym_ndx */
			M_ID_GOT,		/* id_got */
			M_ID_GOTDATA,		/* id_gotdata */
			M_ID_HASH,		/* id_hash */
			M_ID_INTERP,		/* id_interp */
			M_ID_UNKNOWN,		/* id_lbss (unused) */
			M_ID_LDYNSYM,		/* id_ldynsym */
			M_ID_NOTE,		/* id_note */
			M_ID_NULL,		/* id_null */
			M_ID_PLT,		/* id_plt */
			M_ID_REL,		/* id_rel */
			M_ID_STRTAB,		/* id_strtab */
			M_ID_SYMINFO,		/* id_syminfo */
			M_ID_SYMTAB,		/* id_symtab */
			M_ID_SYMTAB_NDX,	/* id_symtab_ndx */
			M_ID_TEXT,		/* id_text */
			M_ID_TLS,		/* id_tls */
			M_ID_TLSBSS,		/* id_tlsbss */
			M_ID_UNKNOWN,		/* id_unknown */
			M_ID_UNWIND,		/* id_unwind */
			M_ID_UNWINDHDR,		/* id_unwindhdr */
			M_ID_USER,		/* id_user */
			M_ID_VERSION,		/* id_version */
		},
		{			/* Target_nullfunc */
			nullfunc_tmpl,		/* nf_template */
			sizeof (nullfunc_tmpl),	/* nf_size */
		},
		{			/* Target_fillfunc */
			/*
			 * On sparc, special filling of executable sections
			 * is undesirable, and the default 0 fill supplied
			 * by libelf is preferred:
			 *
			 * -	0 fill is interpreted as UNIMP instructions,
			 *	which cause an illegal_instruction_trap. These
			 *	serve as a sentinel against poorly written
			 *	code. The sparc architecture manual discusses
			 *	this as providing a measure of runtime safety.
			 *
			 * -	The one place where a hole should conceivably
			 *	be filled with NOP instructions is in the
			 *	.init/.fini sections. However, the sparc
			 *	assembler sizes the sections it generates
			 *	to a multiple of the section alignment, and as
			 *	such, takes the filling task out of our hands.
			 *	Furthermore, the sparc assembler uses 0-fill
			 *	for this, forcing the authors of sparc
			 *	assembler for .init/.fini sections to be aware
			 *	of this case and explicitly supply NOP fill.
			 *	Hence, there is no role for the link-editor.
			 */
			NULL			/* ff_execfill */
		},
		{			/* Target_machrel */
			reloc_table,

			ld_init_rel,		/* mr_init_rel */
			ld_mach_eflags,		/* mr_mach_eflags */
			ld_mach_make_dynamic,	/* mr_mach_make_dynamic */
			ld_mach_update_odynamic, /* mr_mach_update_odynamic */
			ld_calc_plt_addr,	/* mr_calc_plt_addr */
			ld_perform_outreloc,	/* mr_perform_outreloc */
			ld_do_activerelocs,	/* mr_do_activerelocs */
			ld_add_outrel,		/* mr_add_outrel */
			ld_reloc_register,	/* mr_reloc_register */
			ld_reloc_local,		/* mr_reloc_local */
			ld_reloc_GOTOP,		/* mr_reloc_GOTOP */
			ld_reloc_TLS,		/* mr_reloc_TLS */
			ld_assign_got,		/* mr_assign_got */
			ld_find_got_ndx,	/* mr_find_got_ndx */
			ld_calc_got_offset,	/* mr_calc_got_offset */
			ld_assign_got_ndx,	/* mr_assign_got_ndx */
			ld_assign_plt_ndx,	/* mr_assign_plt_ndx */
			ld_allocate_got,	/* mr_allocate_got */
			ld_fillin_gotplt,	/* mr_fillin_gotplt */
		},
		{			/* Target_machsym */
			ld_reg_check_sparc,	/* ms_reg_check */
			ld_mach_sym_typecheck_sparc, /* ms_mach_sym_typecheck */
			ld_is_regsym_sparc,	/* ms_is_regsym */
			ld_reg_find_sparc,	/* ms_reg_find */
			ld_reg_enter_sparc	/* ms_reg_enter */
		}
	};

	return (&_ld_targ);
}
