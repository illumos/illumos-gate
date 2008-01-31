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

#include	<libelf.h>
#include	<dlfcn.h>
#include	"machdep.h"
#include	"reloc.h"
#include	"msg.h"
#include	"_librtld.h"
#include	"alist.h"

static const char	*unknown = 0;	/* Stash MSG_INTL(MSG_STR_UNKNOWN) */

/*
 * Process all relocation records.  A new `Reloc' structure is allocated to
 * cache the processing decisions deduced, and these will be applied during
 * update_reloc().
 * A count of the number of null relocations (i.e., relocations that will be
 * fixed and whoes records will be nulled out), data and function relocations
 * is maintained.  This allows the relocation records themselves to be
 * rearranged (localized) later if necessary.  Note that the number of function
 * relocations, although coounted, shouldn't differ from the original file,
 * the index of a .plt must be maintained to the index of its relocation record
 * within the associated relocation section.
 *
 * The intention behind this file is to maintain as much relocation logic as
 * possible in a generic form.
 */
int
count_reloc(Cache *cache, Cache *_cache, Rt_map *lmp, int flags, Addr addr,
    Xword *null, Xword *data, Xword *func, Alist *nodirect)
{
	Rel		*rel;
	Reloc		*reloc;
	Shdr		*shdr;
	Xword		ent, cnt, _cnt;
	Sym		*syms;
	const char	*strs;
	Cache		*__cache;
	Xword		pltndx = 0;

	/*
	 * Determine the number of relocation entries we'll be dealing with.
	 */
	shdr = _cache->c_shdr;
	rel = (Rel *)_cache->c_data->d_buf;
	ent = shdr->sh_entsize;
	cnt = shdr->sh_size / ent;

	/*
	 * Allocate a relocation structure for this relocation section.
	 */
	if ((reloc = calloc(cnt, sizeof (Reloc))) == 0)
		return (1);
	_cache->c_info = (void *)reloc;

	/*
	 * Determine the relocations associated symbol and string table.
	 */
	__cache = &cache[shdr->sh_link];
	syms = (Sym *)__cache->c_data->d_buf;
	shdr = __cache->c_shdr;
	__cache = &cache[shdr->sh_link];
	strs = (const char *)__cache->c_data->d_buf;

	/*
	 * Loop through the relocation table.
	 */
	for (_cnt = 0; _cnt < cnt; _cnt++, reloc++,
	    rel = (Rel *)((uintptr_t)rel + ent)) {
		const char	*name;
		/* LINTED */
		uchar_t		type = (uchar_t)ELF_R_TYPE(rel->r_info);
		uchar_t		bind;
		ulong_t		offset = rel->r_offset + addr;
		Rt_map		*_lmp;
		int		_bound, _weak;
		ulong_t		rsymndx = ELF_R_SYM(rel->r_info);
		Slookup		sl;
		uint_t		binfo;
		Sym		*_sym, *sym = (syms + rsymndx);

		if (type == M_R_JMP_SLOT)
			reloc->r_pltndx = ++pltndx;

		/*
		 * Analyze the case where no relocations are to be applied.
		 */
		if ((flags & RTLD_REL_ALL) == 0) {
			/*
			 * Don't apply any relocations to the new image but
			 * insure their offsets are incremented to reflect any
			 * new fixed address.
			 */
			reloc->r_flags = FLG_R_INC;

			/*
			 * Undo any relocations that might have already been
			 * applied to the memory image.
			 */
			if (flags & RTLD_MEMORY) {
				reloc->r_flags |= FLG_R_UNDO;

				/*
				 * If a copy relocation is involved we'll need
				 * to know the size of the copy.
				 */
				if (type == M_R_COPY)
					reloc->r_size = sym->st_size;
				else
					reloc->r_size = 0;
			}

			/*
			 * Save the objects new address.
			 */
			reloc->r_value = addr;

			if (type == M_R_JMP_SLOT)
				(*func)++;
			else
				(*data)++;
			continue;
		}

		/*
		 * Determine the symbol binding of the relocation. Don't assume
		 * that relative relocations are simply M_R_RELATIVE.  Although
		 * a pic generated shared object can normally be viewed as
		 * having relative and non-relative relocations, a non-pic
		 * shared object will contain a number of relocations against
		 * local symbols (normally sections).  If a relocation is
		 * against a local symbol it qualifies as a relative relocation.
		 */
		if ((type == M_R_RELATIVE) || (type == M_R_NONE) ||
		    (ELF_ST_BIND(sym->st_info) == STB_LOCAL))
			bind = STB_LOCAL;
		else
			bind = STB_GLOBAL;

		/*
		 * Analyze the case where only relative relocations are to be
		 * applied.
		 */
		if ((flags & RTLD_REL_ALL) == RTLD_REL_RELATIVE) {
			if (flags & RTLD_MEMORY) {
				if (bind == STB_LOCAL) {
					/*
					 * Save the relative relocations from
					 * the memory image.  The data itself
					 * might already have been relocated,
					 * thus clear the relocation record so
					 * that it will not be performed again.
					 */
					reloc->r_flags = FLG_R_CLR;
					(*null)++;
				} else {
					/*
					 * Any non-relative relocation must be
					 * undone, and the relocation records
					 * offset updated to any new fixed
					 * address.
					 */
					reloc->r_flags =
					    (FLG_R_UNDO | FLG_R_INC);
					reloc->r_value = addr;
					if (type == M_R_JMP_SLOT)
						(*func)++;
					else
						(*data)++;
				}
			} else {
				if (bind == STB_LOCAL) {
					/*
					 * Apply relative relocation to the
					 * file image.  Clear the relocation
					 * record so that it will not be
					 * performed again.
					 */
					reloc->r_flags =
					    (FLG_R_APPLY | FLG_R_CLR);
					reloc->r_value = addr;
					if (IS_PC_RELATIVE(type))
						reloc->r_value -= offset;

					if (unknown == 0)
						unknown =
						    MSG_INTL(MSG_STR_UNKNOWN);
					reloc->r_name = unknown;
					(*null)++;
				} else {
					/*
					 * Any non-relative relocation should be
					 * left alone, but its offset should be
					 * updated to any new fixed address.
					 */
					reloc->r_flags = FLG_R_INC;
					reloc->r_value = addr;
					if (type == M_R_JMP_SLOT)
						(*func)++;
					else
						(*data)++;
				}
			}
			continue;
		}

		/*
		 * Analyze the case where more than just relative relocations
		 * are to be applied.
		 */
		if (bind == STB_LOCAL) {
			if (flags & RTLD_MEMORY) {
				/*
				 * Save the relative relocations from the memory
				 * image.  The data itself has already been
				 * relocated, thus clear the relocation record
				 * so that it will not be performed again.
				 */
				reloc->r_flags = FLG_R_CLR;
			} else {
				/*
				 * Apply relative relocation to the file image.
				 * Clear the relocation record so that it will
				 * not be performed again.
				 */
				reloc->r_flags = (FLG_R_APPLY | FLG_R_CLR);
				reloc->r_value = addr;
				if (IS_PC_RELATIVE(type))
					reloc->r_value -= offset;

				if (unknown == 0)
					unknown = MSG_INTL(MSG_STR_UNKNOWN);
				reloc->r_name = unknown;
			}
			(*null)++;
			continue;
		}

		/*
		 * At this point we're dealing with a non-relative relocation
		 * that requires the symbol definition.
		 */
		name = strs + sym->st_name;

		/*
		 * Find the symbol.  As the object being investigated is already
		 * a part of this process, the symbol lookup will likely
		 * succeed.  However, because of lazy binding, there is still
		 * the possibility of a dangling .plt relocation.  dldump()
		 * users might be encouraged to set LD_FLAGS=loadavail (crle(1)
		 * does this for them).
		 *
		 * Initialize the symbol lookup data structure.
		 */
		SLOOKUP_INIT(sl, name, lmp, LIST(lmp)->lm_head, ld_entry_cnt,
		    0, rsymndx, sym, type, LKUP_STDRELOC);

		_bound = _weak = 0;
		_sym = sym;
		if ((sym = lookup_sym(&sl, &_lmp, &binfo)) != 0) {
			/*
			 * Determine from the various relocation requirements
			 * whether this binding is appropriate.  If we're called
			 * from crle(1), RTLD_CONFSET is set, then only inspect
			 * objects selected from the configuration file
			 * (FL1_RT_CONFSET was set during load()).
			 */
			if (!(flags & RTLD_CONFSET) ||
			    (FLAGS1(_lmp) & FL1_RT_CONFSET)) {
				if (((flags & RTLD_REL_ALL) == RTLD_REL_ALL) ||
				    ((flags & RTLD_REL_EXEC) &&
				    (FLAGS(_lmp) & FLG_RT_ISMAIN)) ||
				    ((flags & RTLD_REL_DEPENDS) &&
				    (!(FLAGS(_lmp) & FLG_RT_ISMAIN))) ||
				    ((flags & RTLD_REL_PRELOAD) &&
				    (FLAGS(_lmp) & FLG_RT_PRELOAD)) ||
				    ((flags & RTLD_REL_SELF) &&
				    (lmp == _lmp))) {
					Aliste	idx;
					Word	*ndx;

					_bound = 1;

					/*
					 * If this symbol is explicitly defined
					 * as nodirect, don't allow any local
					 * binding.
					 */
					for (ALIST_TRAVERSE(nodirect, idx,
					    ndx)) {
						if (*ndx == rsymndx) {
							_bound = 0;
							break;
						}
					}
				}
			}
		} else {
			/*
			 * If this is a weak reference and we've been asked to
			 * bind unresolved weak references consider ourself
			 * bound.  This category is typically set by clre(1) for
			 * an application cache.
			 */
			if ((ELF_ST_BIND(_sym->st_info) == STB_WEAK) &&
			    (_sym->st_shndx == SHN_UNDEF) &&
			    (flags & RTLD_REL_WEAK))
				_bound = _weak = 1;
		}

		if (flags & RTLD_MEMORY) {
			if (_bound) {
				/*
				 * We know that all data relocations will have
				 * been performed at process startup thus clear
				 * the relocation record so that it will not be
				 * performed again.  However, we don't know what
				 * function relocations have been performed
				 * because of lazy binding - regardless, we can
				 * leave all the function relocation records in
				 * place, because if the function has already
				 * been bound the record won't be referenced
				 * anyway.  In the case of using LD_BIND_NOW,
				 * a function may be bound twice - so what.
				 */
				if (type == M_R_JMP_SLOT) {
					reloc->r_flags = FLG_R_INC;
					(*func)++;
				} else {
					if (type != M_R_COPY)
						reloc->r_flags = FLG_R_CLR;
					(*null)++;
				}
			} else {
				/*
				 * Clear any unrequired relocation.
				 */
				reloc->r_flags = FLG_R_UNDO | FLG_R_INC;
				reloc->r_value = addr;
				if (type == M_R_JMP_SLOT)
					(*func)++;
				else
					(*data)++;
			}
		} else {
			if (_bound) {
				/*
				 * Apply the global relocation to the file
				 * image.  Clear the relocation record so that
				 * it will not be performed again.
				 */
				if (_weak) {
					reloc->r_value = 0;
					reloc->r_size = 0;
				} else {
					reloc->r_value = sym->st_value;
					if (IS_PC_RELATIVE(type))
						reloc->r_value -= offset;
					if ((!(FLAGS(_lmp) & FLG_RT_FIXED)) &&
					    (sym->st_shndx != SHN_ABS))
						reloc->r_value += ADDR(_lmp);
					reloc->r_size = sym->st_size;
				}

				reloc->r_flags = FLG_R_APPLY | FLG_R_CLR;
				reloc->r_name = name;
				if (type == M_R_JMP_SLOT)
					(*func)++;
				else
					(*null)++;
			} else {
				/*
				 * Do not apply any unrequired relocations.
				 */
				reloc->r_flags = FLG_R_INC;
				reloc->r_value = addr;
				if (type == M_R_JMP_SLOT)
					(*func)++;
				else
					(*data)++;
			}
		}
	}
	return (0);
}


/*
 * Perform any relocation updates to the new image using the information from
 * the `Reloc' structure constructed during count_reloc().
 */
void
update_reloc(Cache *ocache, Cache *icache, Cache *_icache, const char *name,
    Rt_map *lmp, Rel **null, Rel **data, Rel **func)
{
	Shdr	*shdr;
	Rel	*rel;
	Reloc	*reloc;
	Xword	ent, cnt, _cnt;
	Cache	*orcache, *ircache = 0;
	Half	ndx;

	/*
	 * Set up to read the output relocation table.
	 */
	shdr = _icache->c_shdr;
	rel = (Rel *)_icache->c_data->d_buf;
	reloc = (Reloc *)_icache->c_info;
	ent = shdr->sh_entsize;
	cnt = shdr->sh_size / ent;

	/*
	 * Loop through the relocation table.
	 */
	for (_cnt = 0; _cnt < cnt; _cnt++, reloc++,
	    rel = (Rel *)((uintptr_t)rel + ent)) {
		uchar_t		*iaddr, *oaddr;
		/* LINTED */
		uchar_t		type = (uchar_t)ELF_R_TYPE(rel->r_info);
		Addr		off, bgn, end;

		/*
		 * Ignore null relocations (these may have been created from a
		 * previous dldump() of this image).
		 */
		if (type == M_R_NONE) {
			(*null)++;
			continue;
		}

		/*
		 * Determine the section being relocated if we haven't already
		 * done so (we may have had to skip over some null relocation to
		 * get to the first valid offset).  The System V ABI states that
		 * a relocation sections sh_info field indicates the section
		 * that must be relocated.  However, on Intel it seems that the
		 * .rel.plt sh_info records the section index of the .plt, when
		 * in fact it's the .got that gets relocated.  In addition we
		 * now create combined relocation sections with -zcomreloc.  To
		 * generically be able to cope with these anomalies, search for
		 * the appropriate section to be relocated by comparing the
		 * offset of the first relocation record against each sections
		 * offset and size.
		 */
		/* BEGIN CSTYLED */
#if	!defined(__lint)
		if ((ircache == (Cache *)0) || (rel->r_offset < bgn) ||
			(rel->r_offset > end)) {
#else
		/*
		 * lint sees `bgn' and `end' as potentially referenced
		 * before being set.
		 */
		if (ircache == (Cache *)0) {
#endif
			_icache = icache;
			_icache++;

			for (ndx = 1; _icache->c_flags != FLG_C_END; ndx++,
			    _icache++) {

				shdr = _icache->c_shdr;
				bgn = shdr->sh_addr;
				end = bgn + shdr->sh_size;

				if ((rel->r_offset >= bgn) &&
				    (rel->r_offset <= end))
					break;
			}
			ircache = &icache[ndx];
			orcache = &ocache[ndx];
		}
		/* END CSTYLED */

		/*
		 * Determine the relocation location of both the input and
		 * output data.  Take into account that an input section may be
		 * NOBITS (ppc .plt for example).
		 */
		off = rel->r_offset - ircache->c_shdr->sh_addr;
		if (ircache->c_data->d_buf)
			iaddr = (uchar_t *)ircache->c_data->d_buf + off;
		else
			iaddr = 0;
		oaddr = (uchar_t *)orcache->c_data->d_buf + off;

		/*
		 * Apply the relocation to the new output image.  Any base
		 * address, or symbol value, will have been saved in the reloc
		 * structure during count_reloc().
		 */
		if (reloc->r_flags & FLG_R_APPLY)
			apply_reloc(rel, reloc, name, oaddr, lmp);

		/*
		 * Undo any relocation that might already been applied to the
		 * memory image by the runtime linker.  Using the original
		 * file, determine the relocation offset original value and
		 * restore the new image to that value.
		 */
		if ((reloc->r_flags & FLG_R_UNDO) &&
		    (FLAGS(lmp) & FLG_RT_RELOCED))
			undo_reloc(rel, oaddr, iaddr, reloc);

		/*
		 * If a relocation has been applied then the relocation record
		 * should be cleared so that the relocation isn't applied again
		 * when the new image is used.
		 */
		if (reloc->r_flags & FLG_R_CLR) {
			if (type == M_R_JMP_SLOT) {
				clear_reloc(*func);
				*func = (Rel *)((uintptr_t)*func + ent);
			} else {
				clear_reloc(*null);
				*null = (Rel *)((uintptr_t)*null + ent);
			}
		}

		/*
		 * If a relocation isn't applied, update the relocation record
		 * to take into account the new address of the image.
		 */
		if (reloc->r_flags & FLG_R_INC) {
			if (type == M_R_JMP_SLOT) {
				inc_reloc(*func, rel, reloc, oaddr, iaddr);
				*func = (Rel *)((uintptr_t)*func + ent);
			} else {
				inc_reloc(*data, rel, reloc, oaddr, iaddr);
				*data = (Rel *)((uintptr_t)*data + ent);
			}
		}
	}
}
