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
 *
 * Copyright 2020 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */
/*
 * Copyright (c) 2017 Joyent, Inc.
 */

/*
 * x86 relocation code.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/bootconf.h>
#include <sys/modctl.h>
#include <sys/elf.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/sdt_impl.h>

#include "reloc.h"

static int
sdt_reloc_resolve(struct module *mp, char *symname, uint8_t *instr)
{
	sdt_probedesc_t *sdp;

	/*
	 * The "statically defined tracing" (SDT) provider for DTrace.
	 * The SDT mechanism works by replacing calls to the
	 * undefined routine __dtrace_probe_[name] with nop instructions.
	 * The relocations are logged, and SDT itself will later patch the
	 * running binary appropriately.
	 */
	if (strncmp(symname, sdt_prefix, strlen(sdt_prefix)) != 0)
		return (1);

	symname += strlen(sdt_prefix);

	sdp = kobj_alloc(sizeof (sdt_probedesc_t), KM_WAIT);
	sdp->sdpd_name = kobj_alloc(strlen(symname) + 1, KM_WAIT);
	bcopy(symname, sdp->sdpd_name, strlen(symname) + 1);

	sdp->sdpd_offset = (uintptr_t)instr;
	sdp->sdpd_next = mp->sdt_probes;
	mp->sdt_probes = sdp;

	/*
	 * The compiler may emit the probe call as a tail call (/sibling call).
	 * On x86 that means instead of a CALL instruction, we get a JMP.  In
	 * that case, we also need to patch in a RET instruction instead of just
	 * NOPs.
	 */
	const boolean_t is_tailcall = instr[-1] != SDT_CALL;
	instr[-1] = SDT_NOP;
	instr[0] = SDT_NOP;
	instr[1] = SDT_NOP;
	instr[2] = SDT_NOP;
	instr[SDT_OFF_RET_IDX] = is_tailcall ? SDT_RET : SDT_NOP;

	return (0);
}


/*
 * We're relying on the fact that the call we're replacing is
 * call (e8) plus 4 bytes of address, making a 5 byte instruction
 */
#define	NOP_INSTR	0x90
#define	SMAP_NOPS	5

/*
 * Currently the only call replaced as a hot inline
 * is smap_enable() and smap_disable(). If more are needed
 * we should probably come up with an sdt probe like prefix
 * and look for those instead of exact call names.
 */
static int
smap_reloc_resolve(struct module *mp, char *symname, uint8_t *instr)
{
	uint_t symlen;
	hotinline_desc_t *hid;

	if (strcmp(symname, "smap_enable") == 0 ||
	    strcmp(symname, "smap_disable") == 0) {

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "smap_reloc_resolve: %s relocating "
			    "enable/disable_smap\n", mp->filename);
		}
#endif

		hid = kobj_alloc(sizeof (hotinline_desc_t), KM_WAIT);
		symlen = strlen(symname) + 1;
		hid->hid_symname = kobj_alloc(symlen, KM_WAIT);
		bcopy(symname, hid->hid_symname, symlen);

		/*
		 * We backtrack one byte here to consume the call
		 * instruction itself.
		 */
		hid->hid_instr_offset = (uintptr_t)instr - 1;
		hid->hid_next = mp->hi_calls;
		mp->hi_calls = hid;

		memset((void *)hid->hid_instr_offset, NOP_INSTR, SMAP_NOPS);

		return (0);
	}

	return (1);
}

int
do_relocate(struct module *mp, char *reltbl, int nreloc, int relocsize,
    Addr baseaddr)
{
	unsigned long stndx;
	unsigned long off;
	register unsigned long reladdr, rend;
	register unsigned int rtype;
	unsigned long value;
	Elf64_Sxword addend;
	Sym *symref = NULL;
	int err = 0;
	int symnum;
	reladdr = (unsigned long)reltbl;
	rend = reladdr + nreloc * relocsize;

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_RELOCATIONS) {
		_kobj_printf(ops, "krtld:\ttype\t\t\toffset\t   addend"
		    "      symbol\n");
		_kobj_printf(ops, "krtld:\t\t\t\t\t   value\n");
	}
#endif

	symnum = -1;
	/* loop through relocations */
	while (reladdr < rend) {
		symnum++;
		rtype = ELF_R_TYPE(((Rela *)reladdr)->r_info);
		off = ((Rela *)reladdr)->r_offset;
		stndx = ELF_R_SYM(((Rela *)reladdr)->r_info);
		if (stndx >= mp->nsyms) {
			_kobj_printf(ops, "do_relocate: bad strndx %d\n",
			    symnum);
			return (-1);
		}
		if ((rtype > R_AMD64_NUM) || IS_TLS_INS(rtype)) {
			_kobj_printf(ops, "krtld: invalid relocation type %d",
			    rtype);
			_kobj_printf(ops, " at 0x%lx:", off);
			_kobj_printf(ops, " file=%s\n", mp->filename);
			return (-1);
		}


		addend = (long)(((Rela *)reladdr)->r_addend);
		reladdr += relocsize;


		if (rtype == R_AMD64_NONE)
			continue;

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			Sym *	symp;
			symp = (Sym *)
			    (mp->symtbl+(stndx * mp->symhdr->sh_entsize));
			_kobj_printf(ops, "krtld:\t%s",
			    conv_reloc_amd64_type(rtype));
			_kobj_printf(ops, "\t0x%8lx", off);
			_kobj_printf(ops, " %8lld", (longlong_t)addend);
			_kobj_printf(ops, "  %s\n",
			    (const char *)mp->strings + symp->st_name);
		}
#endif

		if (!(mp->flags & KOBJ_EXEC))
			off += baseaddr;

		/*
		 * if R_AMD64_RELATIVE, simply add base addr
		 * to reloc location
		 */

		if (rtype == R_AMD64_RELATIVE) {
			value = baseaddr;
		} else {
			/*
			 * get symbol table entry - if symbol is local
			 * value is base address of this object
			 */
			symref = (Sym *)
			    (mp->symtbl+(stndx * mp->symhdr->sh_entsize));

			if (ELF_ST_BIND(symref->st_info) == STB_LOCAL) {
				/* *** this is different for .o and .so */
				value = symref->st_value;
			} else {
				/*
				 * It's global. Allow weak references.  If
				 * the symbol is undefined, give dtrace
				 * a chance to see if it's a probe site,
				 * and fix it up if so.
				 */
				if (symref->st_shndx == SHN_UNDEF &&
				    sdt_reloc_resolve(mp, mp->strings +
				    symref->st_name, (uint8_t *)off) == 0)
					continue;

				if (symref->st_shndx == SHN_UNDEF &&
				    smap_reloc_resolve(mp, mp->strings +
				    symref->st_name, (uint8_t *)off) == 0)
					continue;

				if (symref->st_shndx == SHN_UNDEF) {
					if (ELF_ST_BIND(symref->st_info)
					    != STB_WEAK) {
						_kobj_printf(ops,
						    "not found: %s\n",
						    mp->strings +
						    symref->st_name);
						err = 1;
					}
					continue;
				} else { /* symbol found  - relocate */
					/*
					 * calculate location of definition
					 * - symbol value plus base address of
					 * containing shared object
					 */
					value = symref->st_value;

				} /* end else symbol found */
			} /* end global or weak */
		} /* end not R_AMD64_RELATIVE */

		value += addend;
		/*
		 * calculate final value -
		 * if PC-relative, subtract ref addr
		 */
		if (IS_PC_RELATIVE(rtype))
			value -= off;

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "krtld:\t\t\t\t0x%8lx", off);
			_kobj_printf(ops, " 0x%8lx\n", value);
		}
#endif

		if (do_reloc_krtld(rtype, (unsigned char *)off, &value,
		    (const char *)mp->strings + symref->st_name,
		    mp->filename) == 0)
			err = 1;

	} /* end of while loop */
	if (err)
		return (-1);

	return (0);
}

int
do_relocations(struct module *mp)
{
	uint_t shn;
	Shdr *shp, *rshp;
	uint_t nreloc;

	/* do the relocations */
	for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
		rshp = (Shdr *)
		    (mp->shdrs + shn * mp->hdr.e_shentsize);
		if (rshp->sh_type == SHT_REL) {
			_kobj_printf(ops, "%s can't process type SHT_REL\n",
			    mp->filename);
			return (-1);
		}
		if (rshp->sh_type != SHT_RELA)
			continue;
		if (rshp->sh_link != mp->symtbl_section) {
			_kobj_printf(ops, "%s reloc for non-default symtab\n",
			    mp->filename);
			return (-1);
		}
		if (rshp->sh_info >= mp->hdr.e_shnum) {
			_kobj_printf(ops, "do_relocations: %s sh_info ",
			    mp->filename);
			_kobj_printf(ops, "out of range %d\n", shn);
			goto bad;
		}
		nreloc = rshp->sh_size / rshp->sh_entsize;

		/* get the section header that this reloc table refers to */
		shp = (Shdr *)
		    (mp->shdrs + rshp->sh_info * mp->hdr.e_shentsize);

		/*
		 * Do not relocate any section that isn't loaded into memory.
		 * Most commonly this will skip over the .rela.stab* sections
		 */
		if (!(shp->sh_flags & SHF_ALLOC))
			continue;
#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "krtld: relocating: file=%s ",
			    mp->filename);
			_kobj_printf(ops, "section=%d\n", shn);
		}
#endif

		if (do_relocate(mp, (char *)rshp->sh_addr, nreloc,
		    rshp->sh_entsize, shp->sh_addr) < 0) {
			_kobj_printf(ops,
			    "do_relocations: %s do_relocate failed\n",
			    mp->filename);
			goto bad;
		}
		kobj_free((void *)rshp->sh_addr, rshp->sh_size);
		rshp->sh_addr = 0;
	}
	mp->flags |= KOBJ_RELOCATED;
	return (0);
bad:
	kobj_free((void *)rshp->sh_addr, rshp->sh_size);
	rshp->sh_addr = 0;
	return (-1);
}
