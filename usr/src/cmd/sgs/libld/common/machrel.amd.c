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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Get the x86 version of the relocation engine */
#define	DO_RELOC_LIBLD_X86

#include	<string.h>
#include	<stdio.h>
#include	<strings.h>
#include	<sys/elf_amd64.h>
#include	<debug.h>
#include	<reloc.h>
#include	<i386/machdep_x86.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * This module uses do_reloc_ld() to execute several synthesized relocations.
 * That function expects to be passed two things that we need to construct
 * here:
 *
 * 1)	A Rel_desc descriptor for each relocation type, from which the
 *	rel_rtype field, and nothing else, is obtained. This is easily
 *	handled by constructing the necessary descriptors.
 *
 * 2)	A function, which called with the Rel_desc descriptor, returns
 *	a string representing the name of the symbol associated with
 *	the descriptor. The usual function for this is ld_reloc_sym_name().
 *	However, that function will not work in this case, as these synthetic
 *	relocations do not have an associated symbol. We supply the
 *	syn_rdesc_sym_name() function to simply return the fixed name.
 */
static Rel_desc rdesc_r_amd64_gotpcrel = {
    NULL, NULL, NULL, 0, 0, 0, R_AMD64_GOTPCREL };
static Rel_desc rdesc_r_amd64_32 = {
    NULL, NULL, NULL, 0, 0, 0, R_AMD64_32 };
static Rel_desc rdesc_r_amd64_pc32 = {
    NULL, NULL, NULL, 0, 0, 0, R_AMD64_PC32 };

/*ARGSUSED*/
static const char *
syn_rdesc_sym_name(Rel_desc *rdesc)
{
	return (MSG_ORIG(MSG_SYM_PLTENT));
}

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
		    (gnp->gn_gotref == gref)) {
			return (gnp);
		}
	}
	return (NULL);
}

static Xword
ld_calc_got_offset(Rel_desc *rdesc, Ofl_desc *ofl)
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
	    (rdesc->rel_rtype == R_AMD64_DTPOFF64))
		gotndx++;

	return ((Xword)(osp->os_shdr->sh_addr + (gotndx * M_GOT_ENTSIZE)));
}

static Word
ld_init_rel(Rel_desc *reld, Word *typedata, void *reloc)
{
	Rela	*rel = (Rela *)reloc;

	/* LINTED */
	reld->rel_rtype = (Word)ELF_R_TYPE(rel->r_info, M_MACH);
	reld->rel_roffset = rel->r_offset;
	reld->rel_raddend = rel->r_addend;
	*typedata = 0;

	reld->rel_flags |= FLG_REL_RELA;

	return ((Word)ELF_R_SYM(rel->r_info));
}

static void
ld_mach_eflags(Ehdr *ehdr, Ofl_desc *ofl)
{
	ofl->ofl_dehdr->e_flags |= ehdr->e_flags;
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
		if (ofl->ofl_osgot)
			(*dyn)->d_un.d_ptr = ofl->ofl_osgot->os_shdr->sh_addr;
		else
			(*dyn)->d_un.d_ptr = 0;
		(*dyn)++;
	}
}

static Xword
ld_calc_plt_addr(Sym_desc *sdp, Ofl_desc *ofl)
{
	Xword	value;

	value = (Xword)(ofl->ofl_osplt->os_shdr->sh_addr) +
	    M_PLT_RESERVSZ + ((sdp->sd_aux->sa_PLTndx - 1) * M_PLT_ENTSIZE);
	return (value);
}

/*
 *  Build a single plt entry - code is:
 *	JMP	*name1@GOTPCREL(%rip)
 *	PUSHL	$index
 *	JMP	.PLT0
 */
static uchar_t pltn_entry[M_PLT_ENTSIZE] = {
/* 0x00 jmpq *name1@GOTPCREL(%rip) */	0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
/* 0x06 pushq $index */			0x68, 0x00, 0x00, 0x00, 0x00,
/* 0x0b jmpq  .plt0(%rip) */		0xe9, 0x00, 0x00, 0x00, 0x00
/* 0x10 */
};

static uintptr_t
plt_entry(Ofl_desc * ofl, Sym_desc * sdp)
{
	uchar_t		*plt0, *pltent, *gotent;
	Sword		plt_off;
	Word		got_off;
	Xword		val1;
	int		bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;

	got_off = sdp->sd_aux->sa_PLTGOTndx * M_GOT_ENTSIZE;
	plt_off = M_PLT_RESERVSZ + ((sdp->sd_aux->sa_PLTndx - 1) *
	    M_PLT_ENTSIZE);
	plt0 = (uchar_t *)(ofl->ofl_osplt->os_outdata->d_buf);
	pltent = plt0 + plt_off;
	gotent = (uchar_t *)(ofl->ofl_osgot->os_outdata->d_buf) + got_off;

	bcopy(pltn_entry, pltent, sizeof (pltn_entry));
	/*
	 * Fill in the got entry with the address of the next instruction.
	 */
	/* LINTED */
	*(Word *)gotent = ofl->ofl_osplt->os_shdr->sh_addr + plt_off +
	    M_PLT_INSSIZE;
	if (bswap)
		/* LINTED */
		*(Word *)gotent = ld_bswap_Word(*(Word *)gotent);

	/*
	 * If '-z noreloc' is specified - skip the do_reloc_ld
	 * stage.
	 */
	if (!OFL_DO_RELOC(ofl))
		return (1);

	/*
	 * patchup:
	 *	jmpq	*name1@gotpcrel(%rip)
	 *
	 * NOTE: 0x06 represents next instruction.
	 */
	val1 = (ofl->ofl_osgot->os_shdr->sh_addr + got_off) -
	    (ofl->ofl_osplt->os_shdr->sh_addr + plt_off) - 0x06;

	if (do_reloc_ld(&rdesc_r_amd64_gotpcrel, &pltent[0x02], &val1,
	    syn_rdesc_sym_name, MSG_ORIG(MSG_SPECFIL_PLTENT), bswap,
	    ofl->ofl_lml) == 0) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLTNFAIL),
		    sdp->sd_aux->sa_PLTndx, demangle(sdp->sd_name));
		return (S_ERROR);
	}

	/*
	 * patchup:
	 *	pushq	$pltndx
	 */
	val1 = (Xword)(sdp->sd_aux->sa_PLTndx - 1);

	if (do_reloc_ld(&rdesc_r_amd64_32, &pltent[0x07], &val1,
	    syn_rdesc_sym_name, MSG_ORIG(MSG_SPECFIL_PLTENT), bswap,
	    ofl->ofl_lml) == 0) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLTNFAIL),
		    sdp->sd_aux->sa_PLTndx, demangle(sdp->sd_name));
		return (S_ERROR);
	}

	/*
	 * patchup:
	 *	jmpq	.plt0(%rip)
	 * NOTE: 0x10 represents next instruction. The rather complex
	 * series of casts is necessary to sign extend an offset into
	 * a 64-bit value while satisfying various compiler error
	 * checks.  Handle with care.
	 */
	val1 = (Xword)((intptr_t)((uintptr_t)plt0 -
	    (uintptr_t)(&pltent[0x10])));

	if (do_reloc_ld(&rdesc_r_amd64_pc32, &pltent[0x0c], &val1,
	    syn_rdesc_sym_name, MSG_ORIG(MSG_SPECFIL_PLTENT), bswap,
	    ofl->ofl_lml) == 0) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLTNFAIL),
		    sdp->sd_aux->sa_PLTndx, demangle(sdp->sd_name));
		return (S_ERROR);
	}

	return (1);
}

static uintptr_t
ld_perform_outreloc(Rel_desc * orsp, Ofl_desc * ofl, Boolean *remain_seen)
{
	Os_desc *	relosp, * osp = 0;
	Word		ndx;
	Xword		roffset, value;
	Sxword		raddend;
	Rela		rea;
	char		*relbits;
	Sym_desc *	sdp, * psym = (Sym_desc *)0;
	int		sectmoved = 0;

	raddend = orsp->rel_raddend;
	sdp = orsp->rel_sym;

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
		    /* LINTED */
		    (psym = ld_am_I_partial(orsp, orsp->rel_raddend))) {
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
		/*
		 * Note: for GOT relative relocations on amd64
		 *	 we discard the addend.  It was relevant
		 *	 to the reference - not to the data item
		 *	 being referenced (ie: that -4 thing).
		 */
		raddend = 0;
		osp = ofl->ofl_osgot;
		roffset = ld_calc_got_offset(orsp, ofl);

	} else if (orsp->rel_flags & FLG_REL_PLT) {
		/*
		 * Note that relocations for PLT's actually
		 * cause a relocation againt the GOT.
		 */
		osp = ofl->ofl_osplt;
		roffset = (ofl->ofl_osgot->os_shdr->sh_addr) +
		    sdp->sd_aux->sa_PLTGOTndx * M_GOT_ENTSIZE;
		raddend = 0;
		if (plt_entry(ofl, sdp) == S_ERROR)
			return (S_ERROR);

	} else if (orsp->rel_flags & FLG_REL_BSS) {
		/*
		 * This must be a R_AMD64_COPY.  For these set the roffset to
		 * point to the new symbols location.
		 */
		osp = ofl->ofl_isbss->is_osdesc;
		roffset = value;

		/*
		 * The raddend doesn't mean anything in a R_SPARC_COPY
		 * relocation.  Null it out because it can confuse people.
		 */
		raddend = 0;
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
	 * Assign the symbols index for the output relocation.  If the
	 * relocation refers to a SECTION symbol then it's index is based upon
	 * the output sections symbols index.  Otherwise the index can be
	 * derived from the symbols index itself.
	 */
	if (orsp->rel_rtype == R_AMD64_RELATIVE)
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
	 * The addend field for R_AMD64_DTPMOD64 means nothing.  The addend
	 * is propagated in the corresponding R_AMD64_DTPOFF64 relocation.
	 */
	if (orsp->rel_rtype == R_AMD64_DTPMOD64)
		raddend = 0;

	relbits = (char *)relosp->os_outdata->d_buf;

	rea.r_info = ELF_R_INFO(ndx, orsp->rel_rtype);
	rea.r_offset = roffset;
	rea.r_addend = raddend;
	DBG_CALL(Dbg_reloc_out(ofl, ELF_DBG_LD, SHT_RELA, &rea, relosp->os_name,
	    ld_reloc_sym_name(orsp)));

	/*
	 * Assert we haven't walked off the end of our relocation table.
	 */
	assert(relosp->os_szoutrels <= relosp->os_shdr->sh_size);

	(void) memcpy((relbits + relosp->os_szoutrels),
	    (char *)&rea, sizeof (Rela));
	relosp->os_szoutrels += (Xword)sizeof (Rela);

	/*
	 * Determine if this relocation is against a non-writable, allocatable
	 * section.  If so we may need to provide a text relocation diagnostic.
	 * Note that relocations against the .plt (R_AMD64_JUMP_SLOT) actually
	 * result in modifications to the .got.
	 */
	if (orsp->rel_rtype == R_AMD64_JUMP_SLOT)
		osp = ofl->ofl_osgot;

	ld_reloc_remain_entry(orsp, osp, ofl, remain_seen);
	return (1);
}

/*
 * amd64 Instructions for TLS processing
 */
static uchar_t tlsinstr_gd_ie[] = {
	/*
	 *	0x00 movq %fs:0, %rax
	 */
	0x64, 0x48, 0x8b, 0x04, 0x25,
	0x00, 0x00, 0x00, 0x00,
	/*
	 *	0x09 addq x@gottpoff(%rip), %rax
	 */
	0x48, 0x03, 0x05, 0x00, 0x00,
	0x00, 0x00
};

static uchar_t tlsinstr_gd_le[] = {
	/*
	 *	0x00 movq %fs:0, %rax
	 */
	0x64, 0x48, 0x8b, 0x04, 0x25,
	0x00, 0x00, 0x00, 0x00,
	/*
	 *	0x09 leaq x@gottpoff(%rip), %rax
	 */
	0x48, 0x8d, 0x80, 0x00, 0x00,
	0x00, 0x00
};

static uchar_t tlsinstr_ld_le[] = {
	/*
	 * .byte 0x66
	 */
	0x66,
	/*
	 * .byte 0x66
	 */
	0x66,
	/*
	 * .byte 0x66
	 */
	0x66,
	/*
	 * movq %fs:0, %rax
	 */
	0x64, 0x48, 0x8b, 0x04, 0x25,
	0x00, 0x00, 0x00, 0x00
};

#define	REX_B		0x1
#define	REX_X		0x2
#define	REX_R		0x4
#define	REX_W		0x8
#define	REX_PREFIX	0x40

#define	REX_RW		(REX_PREFIX | REX_R | REX_W)
#define	REX_BW		(REX_PREFIX | REX_B | REX_W)
#define	REX_BRW		(REX_PREFIX | REX_B | REX_R | REX_W)

#define	REG_ESP		0x4

#define	INSN_ADDMR	0x03	/* addq mem,reg */
#define	INSN_ADDIR	0x81	/* addq imm,reg */
#define	INSN_MOVMR	0x8b	/* movq mem,reg */
#define	INSN_MOVIR	0xc7	/* movq imm,reg */
#define	INSN_LEA	0x8d	/* leaq mem,reg */

static Fixupret
tls_fixups(Ofl_desc *ofl, Rel_desc *arsp)
{
	Sym_desc	*sdp = arsp->rel_sym;
	Word		rtype = arsp->rel_rtype;
	uchar_t		*offset;

	offset = (uchar_t *)((uintptr_t)arsp->rel_roffset +
	    (uintptr_t)_elf_getxoff(arsp->rel_isdesc->is_indata) +
	    (uintptr_t)RELAUX_GET_OSDESC(arsp)->os_outdata->d_buf);

	/*
	 * Note that in certain of the original insn sequences below, the
	 * instructions are not necessarily adjacent
	 */
	if (sdp->sd_ref == REF_DYN_NEED) {
		/*
		 * IE reference model
		 */
		switch (rtype) {
		case R_AMD64_TLSGD:
			/*
			 *  GD -> IE
			 *
			 * Transition:
			 *	0x00 .byte 0x66
			 *	0x01 leaq x@tlsgd(%rip), %rdi
			 *	0x08 .word 0x6666
			 *	0x0a rex64
			 *	0x0b call __tls_get_addr@plt
			 *	0x10
			 * To:
			 *	0x00 movq %fs:0, %rax
			 *	0x09 addq x@gottpoff(%rip), %rax
			 *	0x10
			 */
			DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
			    R_AMD64_GOTTPOFF, arsp, ld_reloc_sym_name));
			arsp->rel_rtype = R_AMD64_GOTTPOFF;
			arsp->rel_roffset += 8;
			arsp->rel_raddend = (Sxword)-4;

			/*
			 * Adjust 'offset' to beginning of instruction
			 * sequence.
			 */
			offset -= 4;
			(void) memcpy(offset, tlsinstr_gd_ie,
			    sizeof (tlsinstr_gd_ie));
			return (FIX_RELOC);

		case R_AMD64_PLT32:
			/*
			 * Fixup done via the TLS_GD relocation.
			 */
			DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
			    R_AMD64_NONE, arsp, ld_reloc_sym_name));
			return (FIX_DONE);
		}
	}

	/*
	 * LE reference model
	 */
	switch (rtype) {
	case R_AMD64_TLSGD:
		/*
		 * GD -> LE
		 *
		 * Transition:
		 *	0x00 .byte 0x66
		 *	0x01 leaq x@tlsgd(%rip), %rdi
		 *	0x08 .word 0x6666
		 *	0x0a rex64
		 *	0x0b call __tls_get_addr@plt
		 *	0x10
		 * To:
		 *	0x00 movq %fs:0, %rax
		 *	0x09 leaq x@tpoff(%rax), %rax
		 *	0x10
		 */
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_AMD64_TPOFF32, arsp, ld_reloc_sym_name));
		arsp->rel_rtype = R_AMD64_TPOFF32;
		arsp->rel_roffset += 8;
		arsp->rel_raddend = 0;

		/*
		 * Adjust 'offset' to beginning of instruction sequence.
		 */
		offset -= 4;
		(void) memcpy(offset, tlsinstr_gd_le, sizeof (tlsinstr_gd_le));
		return (FIX_RELOC);

	case R_AMD64_GOTTPOFF: {
		/*
		 * IE -> LE
		 *
		 * Transition 1:
		 *	movq %fs:0, %reg
		 *	addq x@gottpoff(%rip), %reg
		 * To:
		 *	movq %fs:0, %reg
		 *	leaq x@tpoff(%reg), %reg
		 *
		 * Transition (as a special case):
		 *	movq %fs:0, %r12/%rsp
		 *	addq x@gottpoff(%rip), %r12/%rsp
		 * To:
		 *	movq %fs:0, %r12/%rsp
		 *	addq x@tpoff(%rax), %r12/%rsp
		 *
		 * Transition 2:
		 *	movq x@gottpoff(%rip), %reg
		 *	movq %fs:(%reg), %reg
		 * To:
		 *	movq x@tpoff(%reg), %reg
		 *	movq %fs:(%reg), %reg
		 */
		Conv_inv_buf_t	inv_buf;
		uint8_t reg;		/* Register */

		offset -= 3;

		reg = offset[2] >> 3; /* Encoded dest. reg. operand */

		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_AMD64_TPOFF32, arsp, ld_reloc_sym_name));
		arsp->rel_rtype = R_AMD64_TPOFF32;
		arsp->rel_raddend = 0;

		/*
		 * This is transition 2, and the special case of form 1 where
		 * a normal transition would index %rsp or %r12 and need a SIB
		 * byte in the leaq for which we lack space
		 */
		if ((offset[1] == INSN_MOVMR) ||
		    ((offset[1] == INSN_ADDMR) && (reg == REG_ESP))) {
			/*
			 * If we needed an extra bit of MOD.reg to refer to
			 * this register as the dest of the original movq we
			 * need an extra bit of MOD.rm to refer to it in the
			 * dest of the replacement movq or addq.
			 */
			if (offset[0] == REX_RW)
				offset[0] = REX_BW;

			offset[1] = (offset[1] == INSN_MOVMR) ?
			    INSN_MOVIR : INSN_ADDIR;
			offset[2] = 0xc0 | reg;

			return (FIX_RELOC);
		} else if (offset[1] == INSN_ADDMR) {
			/*
			 * If we needed an extra bit of MOD.reg to refer to
			 * this register in the dest of the addq we need an
			 * extra bit of both MOD.reg and MOD.rm to refer to it
			 * in the source and dest of the leaq
			 */
			if (offset[0] == REX_RW)
				offset[0] = REX_BRW;

			offset[1] = INSN_LEA;
			offset[2] = 0x80 | (reg << 3) | reg;

			return (FIX_RELOC);
		}

		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_BADTLSINS),
		    conv_reloc_amd64_type(arsp->rel_rtype, 0, &inv_buf),
		    arsp->rel_isdesc->is_file->ifl_name,
		    ld_reloc_sym_name(arsp),
		    arsp->rel_isdesc->is_name,
		    EC_OFF(arsp->rel_roffset));
		return (FIX_ERROR);
	}
	case R_AMD64_TLSLD:
		/*
		 * LD -> LE
		 *
		 * Transition
		 *	0x00 leaq x1@tlsgd(%rip), %rdi
		 *	0x07 call __tls_get_addr@plt
		 *	0x0c
		 * To:
		 *	0x00 .byte 0x66
		 *	0x01 .byte 0x66
		 *	0x02 .byte 0x66
		 *	0x03 movq %fs:0, %rax
		 */
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_AMD64_NONE, arsp, ld_reloc_sym_name));
		offset -= 3;
		(void) memcpy(offset, tlsinstr_ld_le, sizeof (tlsinstr_ld_le));
		return (FIX_DONE);

	case R_AMD64_DTPOFF32:
		/*
		 * LD->LE
		 *
		 * Transition:
		 *	0x00 leaq x1@dtpoff(%rax), %rcx
		 * To:
		 *	0x00 leaq x1@tpoff(%rax), %rcx
		 */
		DBG_CALL(Dbg_reloc_transition(ofl->ofl_lml, M_MACH,
		    R_AMD64_TPOFF32, arsp, ld_reloc_sym_name));
		arsp->rel_rtype = R_AMD64_TPOFF32;
		return (FIX_RELOC);
	}

	return (FIX_RELOC);
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
		int		moved = 0;
		Gotref		gref;
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
		 * We determine what the 'got reference' model (if required)
		 * is at this point.  This needs to be done before tls_fixup()
		 * since it may 'transition' our instructions.
		 *
		 * The got table entries have already been assigned,
		 * and we bind to those initial entries.
		 */
		if (arsp->rel_flags & FLG_REL_DTLS)
			gref = GOT_REF_TLSGD;
		else if (arsp->rel_flags & FLG_REL_MTLS)
			gref = GOT_REF_TLSLD;
		else if (arsp->rel_flags & FLG_REL_STLS)
			gref = GOT_REF_TLSIE;
		else
			gref = GOT_REF_GENERIC;

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
		 * If this is a relocation against a move table, or
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
			    /* LINTED */
			    (sym = ld_am_I_partial(arsp, arsp->rel_raddend))) {
				/*
				 * The symbol was moved, so adjust the value
				 * relative to the new section.
				 */
				value = sym->sd_sym->st_value;
				moved = 1;

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
					value += sdp->sd_isc->is_osdesc->
					    os_shdr->sh_addr;
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
			refaddr += arsp->rel_isdesc->is_osdesc->
			    os_shdr->sh_addr;

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
		 *
		 * Note: For GOT relative relocations on amd64 we discard the
		 * addend.  It was relevant to the reference - not to the
		 * data item being referenced (ie: that -4 thing).
		 */
		if ((arsp->rel_flags & FLG_REL_GOT) == 0)
			value += arsp->rel_raddend;

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
			Word		gotndx;
			Gotndx		*gnp;

			/*
			 * Perform relocation against GOT table. Since this
			 * doesn't fit exactly into a relocation we place the
			 * appropriate byte in the GOT directly
			 *
			 * Calculate offset into GOT at which to apply
			 * the relocation.
			 */
			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);

			if (arsp->rel_rtype == R_AMD64_DTPOFF64)
				gotndx = gnp->gn_gotndx + 1;
			else
				gotndx = gnp->gn_gotndx;

			R1addr = (Xword)(gotndx * M_GOT_ENTSIZE);

			/*
			 * Add the GOTs data's offset.
			 */
			R2addr = R1addr + (uintptr_t)osp->os_outdata->d_buf;

			DBG_CALL(Dbg_reloc_doact(ofl->ofl_lml, ELF_DBG_LD_ACT,
			    M_MACH, SHT_RELA, arsp, R1addr, value,
			    ld_reloc_sym_name));

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
			value -= ofl->ofl_osgot->os_shdr->sh_addr;

		} else if (IS_GOTPCREL(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Gotndx *gnp;

			/*
			 * Calculation:
			 *	G + GOT + A - P
			 */
			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);
			value = (Xword)(ofl->ofl_osgot->os_shdr-> sh_addr) +
			    ((Xword)gnp->gn_gotndx * M_GOT_ENTSIZE) +
			    arsp->rel_raddend - refaddr;

		} else if (IS_GOT_PC(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			value = (Xword)(ofl->ofl_osgot->os_shdr->
			    sh_addr) - refaddr + arsp->rel_raddend;

		} else if ((IS_PC_RELATIVE(arsp->rel_rtype)) &&
		    (((flags & FLG_OF_RELOBJ) == 0) ||
		    (osp == sdp->sd_isc->is_osdesc))) {
			value -= refaddr;

		} else if (IS_TLS_INS(arsp->rel_rtype) &&
		    IS_GOT_RELATIVE(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Gotndx	*gnp;

			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);
			value = (Xword)gnp->gn_gotndx * M_GOT_ENTSIZE;

		} else if (IS_GOT_RELATIVE(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Gotndx *gnp;

			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);
			value = (Xword)gnp->gn_gotndx * M_GOT_ENTSIZE;

		} else if ((arsp->rel_flags & FLG_REL_STLS) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Xword	tlsstatsize;

			/*
			 * This is the LE TLS reference model.  Static
			 * offset is hard-coded.
			 */
			tlsstatsize = S_ROUND(ofl->ofl_tlsphdr->p_memsz,
			    M_TLSSTATALIGN);
			value = tlsstatsize - value;

			/*
			 * Since this code is fixed up, it assumes a negative
			 * offset that can be added to the thread pointer.
			 */
			if (arsp->rel_rtype == R_AMD64_TPOFF32)
				value = -value;
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
			Conv_inv_buf_t inv_buf;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_EMPTYSEC),
			    conv_reloc_amd64_type(arsp->rel_rtype, 0, &inv_buf),
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
			int		class;
			Conv_inv_buf_t inv_buf;

			if (((uintptr_t)addr - (uintptr_t)ofl->ofl_nehdr) >
			    ofl->ofl_size)
				class = ERR_FATAL;
			else
				class = ERR_WARNING;

			ld_eprintf(ofl, class, MSG_INTL(MSG_REL_INVALOFFSET),
			    conv_reloc_amd64_type(arsp->rel_rtype, 0, &inv_buf),
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
		 * The relocation is additive.  Ignore the previous symbol
		 * value if this local partial symbol is expanded.
		 */
		if (moved)
			value -= *addr;

		/*
		 * If '-z noreloc' is specified - skip the do_reloc_ld stage.
		 */
		if (OFL_DO_RELOC(ofl)) {
			/*
			 * If this is a PROGBITS section and the running linker
			 * has a different byte order than the target host,
			 * tell do_reloc_ld() to swap bytes.
			 */
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

	/*
	 * Static executables *do not* want any relocations against them.
	 * Since our engine still creates relocations against a WEAK UNDEFINED
	 * symbol in a static executable, it's best to disable them here
	 * instead of through out the relocation code.
	 */
	if (OFL_IS_STATIC_EXEC(ofl))
		return (1);

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
			Os_desc *osp;
			Is_desc *isp = sdp->sd_isc;

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
 * process relocation for a LOCAL symbol
 */
static uintptr_t
ld_reloc_local(Rel_desc * rsp, Ofl_desc * ofl)
{
	ofl_flag_t	flags = ofl->ofl_flags;
	Sym_desc	*sdp = rsp->rel_sym;
	Word		shndx = sdp->sd_sym->st_shndx;
	Word		ortype = rsp->rel_rtype;

	/*
	 * if ((shared object) and (not pc relative relocation) and
	 *    (not against ABS symbol))
	 * then
	 *	build R_AMD64_RELATIVE
	 * fi
	 */
	if ((flags & FLG_OF_SHAROBJ) && (rsp->rel_flags & FLG_REL_LOAD) &&
	    !(IS_PC_RELATIVE(rsp->rel_rtype)) && !(IS_SIZE(rsp->rel_rtype)) &&
	    !(IS_GOT_BASED(rsp->rel_rtype)) &&
	    !(rsp->rel_isdesc != NULL &&
	    (rsp->rel_isdesc->is_shdr->sh_type == SHT_SUNW_dof)) &&
	    (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) ||
	    (shndx != SHN_ABS) || (sdp->sd_aux && sdp->sd_aux->sa_symspec))) {

		/*
		 * R_AMD64_RELATIVE updates a 64bit address, if this
		 * relocation isn't a 64bit binding then we can not
		 * simplify it to a RELATIVE relocation.
		 */
		if (reloc_table[ortype].re_fsize != sizeof (Addr)) {
			return (ld_add_outrel(0, rsp, ofl));
		}

		rsp->rel_rtype = R_AMD64_RELATIVE;
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
		    conv_reloc_amd64_type(rsp->rel_rtype, 0, &inv_buf),
		    rsp->rel_isdesc->is_file->ifl_name,
		    ld_reloc_sym_name(rsp), osp->os_name);
		return (1);
	}

	/*
	 * Perform relocation.
	 */
	return (ld_add_actrel(NULL, rsp, ofl));
}


static uintptr_t
ld_reloc_TLS(Boolean local, Rel_desc * rsp, Ofl_desc * ofl)
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
			 * Assign a GOT entry for static TLS references.
			 */
			if ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs,
			    GOT_REF_TLSIE, ofl, rsp)) == NULL) {

				if (ld_assign_got_TLS(local, rsp, ofl, sdp,
				    gnp, GOT_REF_TLSIE, FLG_REL_STLS,
				    rtype, R_AMD64_TPOFF64, 0) == S_ERROR)
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

		return (ld_add_actrel((FLG_REL_TLSFIX | FLG_REL_STLS),
		    rsp, ofl));
	}

	/*
	 * Building a shared object.
	 *
	 * Assign a GOT entry for a dynamic TLS reference.
	 */
	if (IS_TLS_LD(rtype) && ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs,
	    GOT_REF_TLSLD, ofl, rsp)) == NULL)) {

		if (ld_assign_got_TLS(local, rsp, ofl, sdp, gnp, GOT_REF_TLSLD,
		    FLG_REL_MTLS, rtype, R_AMD64_DTPMOD64, NULL) == S_ERROR)
			return (S_ERROR);

	} else if (IS_TLS_GD(rtype) &&
	    ((gnp = ld_find_got_ndx(sdp->sd_GOTndxs, GOT_REF_TLSGD,
	    ofl, rsp)) == NULL)) {

		if (ld_assign_got_TLS(local, rsp, ofl, sdp, gnp, GOT_REF_TLSGD,
		    FLG_REL_DTLS, rtype, R_AMD64_DTPMOD64,
		    R_AMD64_DTPOFF64) == S_ERROR)
			return (S_ERROR);
	}

	if (IS_TLS_LD(rtype))
		return (ld_add_actrel(FLG_REL_MTLS, rsp, ofl));

	return (ld_add_actrel(FLG_REL_DTLS, rsp, ofl));
}

/* ARGSUSED5 */
static uintptr_t
ld_assign_got_ndx(Alist **alpp, Gotndx *pgnp, Gotref gref, Ofl_desc *ofl,
    Rel_desc *rsp, Sym_desc *sdp)
{
	Xword		raddend;
	Gotndx		gn, *gnp;
	Aliste		idx;
	uint_t		gotents;

	raddend = rsp->rel_raddend;
	if (pgnp && (pgnp->gn_addend == raddend) && (pgnp->gn_gotref == gref))
		return (1);

	if ((gref == GOT_REF_TLSGD) || (gref == GOT_REF_TLSLD))
		gotents = 2;
	else
		gotents = 1;

	gn.gn_addend = raddend;
	gn.gn_gotndx = ofl->ofl_gotcnt;
	gn.gn_gotref = gref;

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
	sdp->sd_aux->sa_PLTGOTndx = ofl->ofl_gotcnt++;
	ofl->ofl_flags |= FLG_OF_BLDGOT;
}

static uchar_t plt0_template[M_PLT_ENTSIZE] = {
/* 0x00 PUSHQ GOT+8(%rip) */	0xff, 0x35, 0x00, 0x00, 0x00, 0x00,
/* 0x06 JMP   *GOT+16(%rip) */	0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
/* 0x0c NOP */			0x90,
/* 0x0d NOP */			0x90,
/* 0x0e NOP */			0x90,
/* 0x0f NOP */			0x90
};

/*
 * Initializes .got[0] with the _DYNAMIC symbol value.
 */
static uintptr_t
ld_fillin_gotplt(Ofl_desc *ofl)
{
	int	bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;

	if (ofl->ofl_osgot) {
		Sym_desc	*sdp;

		if ((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_DYNAMIC_U),
		    SYM_NOHASH, NULL, ofl)) != NULL) {
			uchar_t	*genptr;

			genptr = ((uchar_t *)ofl->ofl_osgot->os_outdata->d_buf +
			    (M_GOT_XDYNAMIC * M_GOT_ENTSIZE));
			/* LINTED */
			*(Xword *)genptr = sdp->sd_sym->st_value;
			if (bswap)
				/* LINTED */
				*(Xword *)genptr =
				    /* LINTED */
				    ld_bswap_Xword(*(Xword *)genptr);
		}
	}

	/*
	 * Fill in the reserved slot in the procedure linkage table the first
	 * entry is:
	 *	0x00 PUSHQ	GOT+8(%rip)	    # GOT[1]
	 *	0x06 JMP	*GOT+16(%rip)	    # GOT[2]
	 *	0x0c NOP
	 *	0x0d NOP
	 *	0x0e NOP
	 *	0x0f NOP
	 */
	if ((ofl->ofl_flags & FLG_OF_DYNAMIC) && ofl->ofl_osplt) {
		uchar_t	*pltent;
		Xword	val1;

		pltent = (uchar_t *)ofl->ofl_osplt->os_outdata->d_buf;
		bcopy(plt0_template, pltent, sizeof (plt0_template));

		/*
		 * If '-z noreloc' is specified - skip the do_reloc_ld
		 * stage.
		 */
		if (!OFL_DO_RELOC(ofl))
			return (1);

		/*
		 * filin:
		 *	PUSHQ GOT + 8(%rip)
		 *
		 * Note: 0x06 below represents the offset to the
		 *	 next instruction - which is what %rip will
		 *	 be pointing at.
		 */
		val1 = (ofl->ofl_osgot->os_shdr->sh_addr) +
		    (M_GOT_XLINKMAP * M_GOT_ENTSIZE) -
		    ofl->ofl_osplt->os_shdr->sh_addr - 0x06;

		if (do_reloc_ld(&rdesc_r_amd64_gotpcrel, &pltent[0x02],
		    &val1, syn_rdesc_sym_name, MSG_ORIG(MSG_SPECFIL_PLTENT),
		    bswap, ofl->ofl_lml) == 0) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLT0FAIL));
			return (S_ERROR);
		}

		/*
		 * filin:
		 *  JMP	*GOT+16(%rip)
		 */
		val1 = (ofl->ofl_osgot->os_shdr->sh_addr) +
		    (M_GOT_XRTLD * M_GOT_ENTSIZE) -
		    ofl->ofl_osplt->os_shdr->sh_addr - 0x0c;

		if (do_reloc_ld(&rdesc_r_amd64_gotpcrel, &pltent[0x08],
		    &val1, syn_rdesc_sym_name, MSG_ORIG(MSG_SPECFIL_PLTENT),
		    bswap, ofl->ofl_lml) == 0) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_PLT_PLT0FAIL));
			return (S_ERROR);
		}
	}

	return (1);
}



/*
 * Template for generating "void (*)(void)" function
 */
static const uchar_t nullfunc_tmpl[] = {	/* amd64 */
/* 0x00 */	0x55,				/* pushq  %rbp */
/* 0x01 */	0x48, 0x8b, 0xec,		/* movq   %rsp,%rbp */
/* 0x04 */	0x48, 0x8b, 0xe5,		/* movq   %rbp,%rsp */
/* 0x07 */	0x5d,				/* popq   %rbp */
/* 0x08 */	0xc3				/* ret */
};


/*
 * Function used to provide fill padding in SHF_EXECINSTR sections
 *
 * entry:
 *
 *	base - base address of section being filled
 *	offset - starting offset for fill within memory referenced by base
 *	cnt - # bytes to be filled
 *
 * exit:
 *	The fill has been completed.
 */
static void
execfill(void *base, off_t off, size_t cnt)
{
	/*
	 * 0x90 is an X86 NOP instruction in both 32 and 64-bit worlds.
	 * There are no alignment constraints.
	 */
	(void) memset(off + (char *)base, 0x90, cnt);
}


/*
 * Return the ld_targ definition for this target.
 */
const Target *
ld_targ_init_x86(void)
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
			MSG_ORIG(MSG_PTH_RTLD_AMD64), /* m_def_interp */

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
			SHT_AMD64_UNWIND,	/* m_sht_unwind */

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
			M_ID_UNKNOWN,		/* id_gotdata (unused) */
			M_ID_HASH,		/* id_hash */
			M_ID_INTERP,		/* id_interp */
			M_ID_LBSS,		/* id_lbss */
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
			execfill		/* ff_execfill */
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
			NULL,			/* mr_reloc_register */
			ld_reloc_local,		/* mr_reloc_local */
			NULL,			/* mr_reloc_GOTOP */
			ld_reloc_TLS,		/* mr_reloc_TLS */
			NULL,			/* mr_assign_got */
			ld_find_got_ndx,	/* mr_find_got_ndx */
			ld_calc_got_offset,	/* mr_calc_got_offset */
			ld_assign_got_ndx,	/* mr_assign_got_ndx */
			ld_assign_plt_ndx,	/* mr_assign_plt_ndx */
			NULL,			/* mr_allocate_got */
			ld_fillin_gotplt,	/* mr_fillin_gotplt */
		},
		{			/* Target_machsym */
			NULL,			/* ms_reg_check */
			NULL,			/* ms_mach_sym_typecheck */
			NULL,			/* ms_is_regsym */
			NULL,			/* ms_reg_find */
			NULL			/* ms_reg_enter */
		}
	};

	return (&_ld_targ);
}
