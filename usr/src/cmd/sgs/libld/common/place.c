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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Map file parsing and input section to output segment mapping.
 */
#include	<stdio.h>
#include	<string.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Each time a section is placed, the function set_addralign()
 * is called.  This function performs:
 *
 *  .	if the section is from an external file, check if this is empty or not.
 *	If not, we know the segment this section will belong needs a program
 *	header. (Of course, the program is needed only if this section falls
 *	into a loadable segment.)
 *  .	compute the Least Common Multiplier for setting the segment alignment.
 */
static void
set_addralign(Ofl_desc *ofl, Os_desc *osp, Is_desc *isp)
{
	Shdr *		shdr = isp->is_shdr;

	/* A discarded section has no influence on the output */
	if (isp->is_flags & FLG_IS_DISCARD)
		return;

	/*
	 * If this section has data or will be assigned data
	 * later, mark this segment not-empty.
	 */
	if ((shdr->sh_size != 0) ||
	    ((isp->is_flags & FLG_IS_EXTERNAL) == 0))
		osp->os_sgdesc->sg_flags |= FLG_SG_PHREQ;

	if ((ofl->ofl_dtflags_1 & DF_1_NOHDR) &&
	    (osp->os_sgdesc->sg_phdr).p_type != PT_LOAD)
		return;

	osp->os_sgdesc->sg_addralign =
	    ld_lcm(osp->os_sgdesc->sg_addralign, shdr->sh_addralign);
}

/*
 * Append an input section to an output section
 *
 * entry:
 *	ofl - File descriptor
 *	isp - Input section descriptor
 *	osp - Output section descriptor
 *	mstr_only - True if should only append to the merge string section
 *		list.
 *
 * exit:
 *	- If mstr_only is not true, the input section is appended to the
 *		end of the output section's list of input sections (os_isdescs).
 *	- If the input section is a candidate for string table merging,
 *		then it is appended to the output section's list of merge
 *		candidates (os_mstridescs).
 *
 *	On success, returns True (1). On failure, False (0).
 */
int
ld_append_isp(Ofl_desc * ofl, Os_desc *osp, Is_desc *isp, int mstr_only)
{
	if (!mstr_only && (list_appendc(&(osp->os_isdescs), isp) == 0))
		return (0);

	/*
	 * To be mergeable:
	 *	- The SHF_MERGE|SHF_STRINGS flags must be set
	 *	- String table compression must not be disabled (-znocompstrtab)
	 *	- It must not be the generated section being built to
	 *		replace the sections on this list.
	 */
	if (((isp->is_shdr->sh_flags & (SHF_MERGE | SHF_STRINGS)) !=
	    (SHF_MERGE | SHF_STRINGS)) ||
	    ((ofl->ofl_flags1 & FLG_OF1_NCSTTAB) != 0) ||
	    ((isp->is_flags & FLG_IS_GNSTRMRG) != 0))
		return (1);

	/*
	 * Skip sections with (sh_entsize > 1) or (sh_addralign > 1).
	 *
	 * sh_entsize:
	 *	We are currently only able to merge string tables containing
	 *	strings with 1-byte (char) characters. Support for wide
	 *	characters will require our string table compression code
	 *	to be extended to handle larger character sizes.
	 *
	 * sh_addralign:
	 *	Alignments greater than 1 would require our string table
	 *	compression code to insert null bytes to move each
	 *	string to the required alignment.
	 */
	if ((isp->is_shdr->sh_entsize > 1) ||
	    (isp->is_shdr->sh_addralign > 1)) {
		DBG_CALL(Dbg_sec_unsup_strmerge(ofl->ofl_lml, isp));
		return (1);
	}

	if (aplist_append(&osp->os_mstrisdescs, isp,
	    AL_CNT_OS_MSTRISDESCS) == NULL)
		return (0);

	/*
	 * The SHF_MERGE|SHF_STRINGS flags tell us that the program that
	 * created the section intended it to be mergeable. The
	 * FLG_IS_INSTRMRG flag says that we have done validity testing
	 * and decided that it is safe to act on that hint.
	 */
	isp->is_flags |= FLG_IS_INSTRMRG;

	return (1);
}

/*
 * Place a section into the appropriate segment.
 */
Os_desc *
ld_place_section(Ofl_desc * ofl, Is_desc * isp, int ident, Word link)
{
	Listnode *	lnp1, * lnp2;
	Ent_desc *	enp;
	Sg_desc	*	sgp;
	Os_desc		*osp;
	Aliste		idx1, idx2;
	int		os_ndx;
	Shdr *		shdr = isp->is_shdr;
	Xword		shflagmask, shflags = shdr->sh_flags;
	Ifl_desc *	ifl = isp->is_file;

	/*
	 * Define any sections that must be thought of as referenced.  These
	 * sections may not be referenced externaly in a manner ld(1) can
	 * discover, but they must be retained (ie. not removed by -zignore).
	 */
	static const Msg RefSecs[] = {
		MSG_SCN_INIT,		/* MSG_ORIG(MSG_SCN_INIT) */
		MSG_SCN_FINI,		/* MSG_ORIG(MSG_SCN_FINI) */
		MSG_SCN_EX_RANGES,	/* MSG_ORIG(MSG_SCN_EX_RANGES) */
		MSG_SCN_EX_SHARED,	/* MSG_ORIG(MSG_SCN_EX_SHARED) */
		MSG_SCN_CTORS,		/* MSG_ORIG(MSG_SCN_CTORS) */
		MSG_SCN_DTORS,		/* MSG_ORIG(MSG_SCN_DTORS) */
		MSG_SCN_EHFRAME,	/* MSG_ORIG(MSG_SCN_EHFRAME) */
		MSG_SCN_EHFRAME_HDR,	/* MSG_ORIG(MSG_SCN_EHFRAME_HDR) */
		MSG_SCN_JCR,		/* MSG_ORIG(MSG_SCN_JCR) */
		0
	};

	DBG_CALL(Dbg_sec_in(ofl->ofl_lml, isp));

	if ((shflags & SHF_GROUP) || (shdr->sh_type == SHT_GROUP)) {
		Group_desc *	gdesc;

		if ((gdesc = ld_get_group(ofl, isp)) == (Group_desc *)S_ERROR)
			return ((Os_desc *)S_ERROR);

		if (gdesc) {
			DBG_CALL(Dbg_sec_group(ofl->ofl_lml, isp, gdesc));

			/*
			 * If this group is marked as discarded, then this
			 * section needs to be discarded.
			 */
			if (gdesc->gd_flags & GRP_FLG_DISCARD) {
				isp->is_flags |= FLG_IS_DISCARD;
				/*
				 * Since we're discarding the section, we
				 * can skip assigning it to an output section.
				 * The exception is that if the user
				 * specifies -z relaxreloc, then
				 * we need to assign the output section so
				 * that the sloppy relocation logic will have
				 * the information necessary to do its work.
				 */
				if (!(ofl->ofl_flags1 & FLG_OF1_RLXREL))
					return ((Os_desc *)0);
			}
		}

		/*
		 * SHT_GROUP sections can only be included into relocatable
		 * objects.
		 */
		if (shdr->sh_type == SHT_GROUP) {
			if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) {
				isp->is_flags |= FLG_IS_DISCARD;
				return ((Os_desc *)0);
			}
		}
	}

	/*
	 * Always assign SHF_TLS sections to the DATA segment (and then the
	 * PT_TLS embedded inside of there).
	 */
	if (shflags & SHF_TLS)
		shflags |= SHF_WRITE;

	/*
	 * Traverse the entrance criteria list searching for a segment that
	 * matches the input section we have.  If an entrance criterion is set
	 * then there must be an exact match.  If we complete the loop without
	 * finding a segment, then sgp will be NULL.
	 */
	sgp = NULL;
	for (LIST_TRAVERSE(&ofl->ofl_ents, lnp1, enp)) {
		if (enp->ec_segment &&
		    (enp->ec_segment->sg_flags & FLG_SG_DISABLED))
			continue;
		if (enp->ec_type && (enp->ec_type != shdr->sh_type))
			continue;
		if (enp->ec_attrmask &&
		    /* LINTED */
		    (enp->ec_attrmask & enp->ec_attrbits) !=
		    (enp->ec_attrmask & shflags))
			continue;
		if (enp->ec_name && (strcmp(enp->ec_name, isp->is_name) != 0))
			continue;
		if (enp->ec_files.head) {
			char	*file;
			int	found = 0;

			if (isp->is_file == 0)
				continue;

			for (LIST_TRAVERSE(&(enp->ec_files), lnp2, file)) {
				const char	*name = isp->is_file->ifl_name;

				if (file[0] == '*') {
					const char	*basename;

					basename = strrchr(name, '/');
					if (basename == NULL)
						basename = name;
					else if (basename[1] != '\0')
						basename++;

					if (strcmp(&file[1], basename) == 0) {
						found++;
						break;
					}
				} else {
					if (strcmp(file, name) == 0) {
						found++;
						break;
					}
				}
			}
			if (!found)
				continue;
		}
		break;
	}

	if ((sgp = enp->ec_segment) == 0)
		sgp = ((Ent_desc *)(ofl->ofl_ents.tail->data))->ec_segment;

	isp->is_basename = isp->is_name;

	/*
	 * Strip out the % from the section name in all cases except when '-r'
	 * is used without '-M', and '-r' is used with '-M' without
	 * the ?O flag.
	 */
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) &&
	    (sgp->sg_flags & FLG_SG_ORDER)) ||
	    !(ofl->ofl_flags & FLG_OF_RELOBJ)) {
		char	*cp;

		if ((cp = strchr(isp->is_name, '%')) != NULL) {
			char	*name;
			size_t	size = (size_t)(cp - isp->is_name);

			if ((name = libld_malloc(size + 1)) == 0)
				return ((Os_desc *)S_ERROR);
			(void) strncpy(name, isp->is_name, size);
			cp = name + size;
			*cp = '\0';
			isp->is_name = name;
		}
		isp->is_txtndx = enp->ec_ndx;
	}

	/*
	 * Assign a hash value now that the section name has been finalized.
	 */
	isp->is_namehash = sgs_str_hash(isp->is_name);

	if (sgp->sg_flags & FLG_SG_ORDER)
		enp->ec_flags |= FLG_EC_USED;

	/*
	 * If the link is not 0, then the input section is going to be appended
	 * to the output section.  The append occurs at the input section
	 * pointed to by the link.
	 */
	if (link != 0) {
		osp = isp->is_file->ifl_isdesc[link]->is_osdesc;

		/*
		 * If this is a COMDAT section, then see if this
		 * section is a keeper and/or if it is to be discarded.
		 */
		if (shdr->sh_type == SHT_SUNW_COMDAT) {
			Listnode *	clist;
			Is_desc *	cisp;

			for (LIST_TRAVERSE(&(osp->os_comdats), clist, cisp)) {
				if (strcmp(isp->is_basename, cisp->is_basename))
					continue;

				isp->is_flags |= FLG_IS_DISCARD;
				isp->is_osdesc = osp;
				DBG_CALL(Dbg_sec_discarded(ofl->ofl_lml,
				    isp, cisp));
				return (0);
			}

			/*
			 * This is a new COMDAT section - so keep it.
			 */
			if (list_appendc(&(osp->os_comdats), isp) == 0)
				return ((Os_desc *)S_ERROR);
		}

		/*
		 * Set alignment
		 */
		set_addralign(ofl, osp, isp);

		if (ld_append_isp(ofl, osp, isp, 0) == 0)
			return ((Os_desc *)S_ERROR);

		isp->is_osdesc = osp;
		sgp = osp->os_sgdesc;

		DBG_CALL(Dbg_sec_added(ofl->ofl_lml, osp, sgp));
		return (osp);
	}

	/*
	 * Determine if section ordering is turned on.  If so, return the
	 * appropriate os_txtndx.  This information is derived from the
	 * Sg_desc->sg_segorder list that was built up from the Mapfile.
	 */
	os_ndx = 0;
	if (sgp->sg_secorder) {
		Aliste		idx;
		Sec_order	*scop;

		for (APLIST_TRAVERSE(sgp->sg_secorder, idx, scop)) {
			if (strcmp(scop->sco_secname, isp->is_name) == 0) {
				scop->sco_flags |= FLG_SGO_USED;
				os_ndx = scop->sco_index;
				break;
			}
		}
	}

	/*
	 * Mask of section header flags to ignore when
	 * matching sections. We are more strict with
	 * relocatable objects, ignoring only the order
	 * flags, and keeping sections apart if they differ
	 * otherwise. This follows the policy that sections
	 * in a relative object should only be merged if their
	 * flags are the same, and avoids destroying information
	 * prematurely. For final products however, we ignore all
	 * flags that do not prevent a merge.
	 */
	shflagmask = (ofl->ofl_flags & FLG_OF_RELOBJ)
	    ? ALL_SHF_ORDER : ALL_SHF_IGNORE;

	/*
	 * Traverse the input section list for the output section we have been
	 * assigned. If we find a matching section simply add this new section.
	 */
	idx2 = 0;
	for (APLIST_TRAVERSE(sgp->sg_osdescs, idx1, osp)) {
		Shdr	*_shdr = osp->os_shdr;

		if ((ident == osp->os_scnsymndx) && (ident != M_ID_REL) &&
		    (isp->is_namehash == osp->os_namehash) &&
		    (shdr->sh_type != SHT_GROUP) &&
		    (shdr->sh_type != SHT_SUNW_dof) &&
		    ((shdr->sh_type == _shdr->sh_type) ||
		    ((shdr->sh_type == SHT_SUNW_COMDAT) &&
		    (_shdr->sh_type == SHT_PROGBITS))) &&
		    ((shflags & ~shflagmask) ==
		    (_shdr->sh_flags & ~shflagmask)) &&
		    (strcmp(isp->is_name, osp->os_name) == 0)) {
			/*
			 * If this is a COMDAT section, determine if this
			 * section is a keeper, and/or if it is to be discarded.
			 */
			if (shdr->sh_type == SHT_SUNW_COMDAT) {
				Listnode *	clist;
				Is_desc *	cisp;

				for (LIST_TRAVERSE(&(osp->os_comdats),
				    clist, cisp)) {
					if (strcmp(isp->is_basename,
					    cisp->is_basename))
						continue;

					isp->is_flags |= FLG_IS_DISCARD;
					isp->is_osdesc = osp;
					DBG_CALL(Dbg_sec_discarded(ofl->ofl_lml,
					    isp, cisp));
					return (0);
				}

				/*
				 * This is a new COMDAT section - so keep it.
				 */
				if (list_appendc(&(osp->os_comdats), isp) == 0)
					return ((Os_desc *)S_ERROR);
			}

			/*
			 * Set alignment
			 */
			set_addralign(ofl, osp, isp);

			/*
			 * If this section is a non-empty TLS section indicate
			 * that a PT_TLS program header is required.
			 */
			if ((shflags & SHF_TLS) && shdr->sh_size &&
			    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0))
				ofl->ofl_flags |= FLG_OF_TLSPHDR;

			/*
			 * If is_txtndx is 0 then this section was not
			 * seen in mapfile, so put it at the end.
			 * If is_txtndx is not 0 and ?O is turned on
			 * then check to see where this section should
			 * be inserted.
			 */
			if ((sgp->sg_flags & FLG_SG_ORDER) && isp->is_txtndx) {
				Listnode *	tlist;

				tlist = list_where(&(osp->os_isdescs),
				    isp->is_txtndx);
				if (tlist != NULL) {
					if (list_insertc(&(osp->os_isdescs),
					    isp, tlist) == 0)
						return ((Os_desc *)S_ERROR);
				} else {
					if (list_prependc(&(osp->os_isdescs),
					    isp) == 0)
						return ((Os_desc *)S_ERROR);
				}
			} else {
				if (list_appendc(&(osp->os_isdescs), isp) == 0)
					return ((Os_desc *)S_ERROR);
			}
			if (ld_append_isp(ofl, osp, isp, 1) == 0)
				return ((Os_desc *)S_ERROR);

			isp->is_osdesc = osp;

			/*
			 * If this input section and file is associated to an
			 * artificially referenced output section, make sure
			 * they are marked as referenced also. This insures this
			 * input section and file isn't eliminated when -zignore
			 * is in effect.
			 * See -zignore comments when creating a new output
			 * section below.
			 */
			if (((ifl &&
			    (ifl->ifl_flags & FLG_IF_IGNORE)) || DBG_ENABLED) &&
			    (osp->os_flags & FLG_OS_SECTREF)) {
				isp->is_flags |= FLG_IS_SECTREF;
				if (ifl)
					ifl->ifl_flags |= FLG_IF_FILEREF;
			}

			DBG_CALL(Dbg_sec_added(ofl->ofl_lml, osp, sgp));
			return (osp);
		}

		/*
		 * Do we need to worry about section ordering?
		 */
		if (os_ndx) {
			if (osp->os_txtndx) {
				if (os_ndx < osp->os_txtndx)
					/* insert section here. */
					break;
				else {
					idx2 = idx1 + 1;
					continue;
				}
			} else {
				/* insert section here. */
				break;
			}
		} else if (osp->os_txtndx) {
			idx2 = idx1 + 1;
			continue;
		}

		/*
		 * If the new sections identifier is less than that of the
		 * present input section we need to insert the new section
		 * at this point.
		 */
		if (ident < osp->os_scnsymndx)
			break;

		idx2 = idx1 + 1;
	}

	/*
	 * We are adding a new output section.  Update the section header
	 * count and associated string size.
	 */
	ofl->ofl_shdrcnt++;
	if (st_insert(ofl->ofl_shdrsttab, isp->is_name) == -1)
		return ((Os_desc *)S_ERROR);

	/*
	 * Create a new output section descriptor.
	 */
	if ((osp = libld_calloc(sizeof (Os_desc), 1)) == 0)
		return ((Os_desc *)S_ERROR);
	if ((osp->os_shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return ((Os_desc *)S_ERROR);

	/*
	 * We convert COMDAT sections to PROGBITS if this is the first
	 * section of a output section.
	 */
	if (shdr->sh_type == SHT_SUNW_COMDAT) {
		Shdr *	tshdr;

		if ((tshdr = libld_malloc(sizeof (Shdr))) == 0)
			return ((Os_desc *)S_ERROR);
		*tshdr = *shdr;
		isp->is_shdr = shdr = tshdr;
		shdr->sh_type = SHT_PROGBITS;
		if (list_appendc(&(osp->os_comdats), isp) == 0)
			return ((Os_desc *)S_ERROR);
	}

	osp->os_shdr->sh_type = shdr->sh_type;
	osp->os_shdr->sh_flags = shdr->sh_flags;
	osp->os_shdr->sh_entsize = shdr->sh_entsize;
	osp->os_name = isp->is_name;
	osp->os_namehash = isp->is_namehash;
	osp->os_txtndx = os_ndx;
	osp->os_sgdesc = sgp;

	if (ifl && (shdr->sh_type == SHT_PROGBITS)) {
		/*
		 * Try to preserve the intended meaning of sh_link/sh_info.
		 * See the translate_link() in update.c.
		 */
		osp->os_shdr->sh_link = shdr->sh_link;
		if (shdr->sh_flags & SHF_INFO_LINK)
			osp->os_shdr->sh_info = shdr->sh_info;
	}

	/*
	 * When -zignore is in effect, user supplied sections and files that are
	 * not referenced from other sections, are eliminated from the object
	 * being produced.  Some sections, although unreferenced, are special,
	 * and must not be eliminated.  Determine if this new output section is
	 * one of those special sections, and if so mark it artificially as
	 * referenced.  Any input section and file associated to this output
	 * section is also be marked as referenced, and thus won't be eliminated
	 * from the final output.
	 */
	if (ifl && ((ofl->ofl_flags1 & FLG_OF1_IGNPRC) || DBG_ENABLED)) {
		const Msg	*refsec;

		for (refsec = RefSecs; *refsec; refsec++) {
			if (strcmp(osp->os_name, MSG_ORIG(*refsec)) == 0) {
				osp->os_flags |= FLG_OS_SECTREF;

				if ((ifl->ifl_flags & FLG_IF_IGNORE) ||
				    DBG_ENABLED) {
					isp->is_flags |= FLG_IS_SECTREF;
					ifl->ifl_flags |= FLG_IF_FILEREF;
				}
				break;
			}
		}
	}

	/*
	 * Setions of SHT_GROUP are added to the ofl->ofl_osgroups
	 * list - so that they can be updated as a group later.
	 */
	if (shdr->sh_type == SHT_GROUP) {
		if (list_appendc(&ofl->ofl_osgroups, osp) == 0)
			return ((Os_desc *)S_ERROR);
	}

	/*
	 * If this section is a non-empty TLS section indicate that a PT_TLS
	 * program header is required.
	 */
	if ((shflags & SHF_TLS) && shdr->sh_size &&
	    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0))
		ofl->ofl_flags |= FLG_OF_TLSPHDR;

	/*
	 * If a non-allocatable section is going to be put into a loadable
	 * segment then turn on the allocate bit for this section and warn the
	 * user that we have done so.  This could only happen through the use
	 * of a mapfile.
	 */
	if ((sgp->sg_phdr.p_type == PT_LOAD) &&
	    ((osp->os_shdr->sh_flags & SHF_ALLOC) == 0)) {
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_SCN_NONALLOC),
		    ofl->ofl_name, osp->os_name);
		osp->os_shdr->sh_flags |= SHF_ALLOC;
	}

	/*
	 * Retain this sections identifier for future comparisons when placing
	 * a section (after all sections have been processed this variable will
	 * be used to hold the sections symbol index as we don't need to retain
	 * the identifier any more).
	 */
	osp->os_scnsymndx = ident;

	/*
	 * Set alignment
	 */
	set_addralign(ofl, osp, isp);

	if (ld_append_isp(ofl, osp, isp, 0) == 0)
		return ((Os_desc *)S_ERROR);

	DBG_CALL(Dbg_sec_created(ofl->ofl_lml, osp, sgp));
	isp->is_osdesc = osp;

	/*
	 * Insert the new section at the offset given by idx2. If no
	 * position for it was identified above, this will be index 0,
	 * causing the new section to be prepended to the beginning of
	 * the section list. Otherwise, it is the index following the section
	 * that was identified.
	 */
	if (aplist_insert(&sgp->sg_osdescs, osp, AL_CNT_SG_OSDESC,
	    idx2) == NULL)
		return ((Os_desc *)S_ERROR);
	return (osp);
}
