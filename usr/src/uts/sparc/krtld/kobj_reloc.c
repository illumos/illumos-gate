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
 * SPARC relocation code.
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
#include <sys/sdt.h>

#include "krtld/reloc.h"

#define	SDT_RESTORE_MASK	0xc1f80000
#define	SDT_RESTORE		0x81e80000
#define	SDT_NOP			0x01000000
#define	SDT_RET			0x81c7e008
#define	SDT_RETL		0x81c3e008
#define	SDT_RDO7_MASK		0xbf000000
#define	SDT_RDO7		0x9e000000

static int
sdt_reloc_resolve(struct module *mp, char *symname, uint32_t *instr, long roff)
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

	if ((uint32_t *)roff == instr) {
		/*
		 * This isn't an offset -- it's an absolute value.  (This is
		 * typically only true for "unix".)  We need to convert the
		 * value into an offset from mp->text.
		 */
		roff -= (uintptr_t)mp->text;
	}

	sdp->sdpd_offset = roff;

	sdp->sdpd_next = mp->sdt_probes;
	mp->sdt_probes = sdp;

	/*
	 * If the next instruction is a restore (any variant), then the probe
	 * point is being tail-called.  Instead of patching the call to be a
	 * NOP, we must patch it to be a ret.  If the next instruction is
	 * writing to %o7, it must be a tail call from a leaf; we must patch
	 * the instruction to be a retl.
	 */
	if ((*(instr + 1) & SDT_RESTORE_MASK) == SDT_RESTORE) {
		*instr = SDT_RET;
	} else if ((*(instr + 1) & SDT_RDO7_MASK) == SDT_RDO7) {
		*instr = SDT_RETL;
	} else {
		*instr = SDT_NOP;
	}

	return (0);
}

int
do_relocate(struct module *mp, char *reltbl, int nreloc, int relocsize,
    Addr baseaddr)
{
	Word stndx;
	long off, roff;
	uintptr_t reladdr, rend;
	uint_t rtype;
	Elf64_Sxword addend;
	Addr value, destination;
	Sym *symref;
	int symnum;
	int err = 0;

	reladdr = (uintptr_t)reltbl;
	rend = reladdr + nreloc * relocsize;

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_RELOCATIONS) {
		_kobj_printf(ops, "krtld:\ttype\t\t\toffset\t   addend"
		    "      symbol\n");
		_kobj_printf(ops, "krtld:\t\t\t\t\t   value\n");
	}
#endif
	destination = baseaddr;

	/*
	 * If this machine is loading a module through an alternate address
	 * we need to compute the spot where the actual relocation will
	 * take place.
	 */
	if (mp->destination) {
		int i;
		Shdr * shp;
		shp = (Shdr *)mp->shdrs;
		for (i = 0; i < mp->shnum; i++, shp++) {
			if (shp->sh_addr == baseaddr) {
				if ((shp->sh_flags & SHF_ALLOC) &&
				    !(shp->sh_flags & SHF_WRITE))
					destination = (Addr)mp->destination +
					    (baseaddr - (Addr)mp->text);
				break;
			}
		}
	}

	symnum = -1;
	/* loop through relocations */
	while (reladdr < rend) {

		symnum++;
		rtype = ELF_R_TYPE(((Rela *)reladdr)->r_info);
		roff = off = ((Rela *)reladdr)->r_offset;
		stndx = ELF_R_SYM(((Rela *)reladdr)->r_info);
		if (stndx >= mp->nsyms) {
			_kobj_printf(ops,
			    "do_relocate: bad strndx %d\n", symnum);
			return (-1);
		}
		if ((rtype > R_SPARC_NUM) || IS_TLS_INS(rtype)) {
			_kobj_printf(ops, "krtld: invalid relocation type %d",
			    rtype);
			_kobj_printf(ops, " at 0x%llx:", (u_longlong_t)off);
			_kobj_printf(ops, " file=%s\n", mp->filename);
			err = 1;
			continue;
		}
		addend = (long)(((Rela *)reladdr)->r_addend);
		reladdr += relocsize;


#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			Sym *symp;
			symp = (Sym *)
			    (mp->symtbl+(stndx * mp->symhdr->sh_entsize));
			_kobj_printf(ops, "krtld:\t%s",
			    conv_reloc_SPARC_type(rtype));
			_kobj_printf(ops, "\t0x%8llx", (u_longlong_t)off);
			_kobj_printf(ops, " 0x%8llx", (u_longlong_t)addend);
			_kobj_printf(ops, "  %s\n",
			    (const char *)mp->strings + symp->st_name);
		}
#endif

		if (rtype == R_SPARC_NONE)
			continue;

		if (!(mp->flags & KOBJ_EXEC))
			off += destination;

		/*
		 * if R_SPARC_RELATIVE, simply add base addr
		 * to reloc location
		 */
		if (rtype == R_SPARC_RELATIVE) {
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
				    symref->st_name, (uint32_t *)off,
				    roff + ((uintptr_t)baseaddr -
				    (uintptr_t)mp->text)) == 0)
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
			}
		} /* end not R_SPARC_RELATIVE */

		value += addend;
		if (IS_EXTOFFSET(rtype)) {
			value +=
			    (Word) ELF_R_TYPE_DATA(((Rela *)reladdr)->r_info);
		}

		/*
		 * calculate final value -
		 * if PC-relative, subtract ref addr
		 */
		if (IS_PC_RELATIVE(rtype)) {
			if (mp->destination)
				value -= (baseaddr + roff);
			else
				value -= off;
		}

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "krtld:\t\t\t\t0x%8llx",
			    (u_longlong_t)off);
			_kobj_printf(ops, " 0x%8llx\n", (u_longlong_t)value);
		}
#endif
		if (do_reloc_krtld(rtype, (unsigned char *)off, (Xword *)&value,
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
	for (shn = 1; shn < mp->shnum; shn++) {
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
		if (rshp->sh_info >= mp->shnum) {
			_kobj_printf(ops, "do_relocations: %s ", mp->filename);
			_kobj_printf(ops, " sh_info out of range %d\n", shn);
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
			_kobj_printf(ops, " section=%d\n", shn);
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
