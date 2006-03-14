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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

	/*
	 * If this section has data or will be assigned data
	 * later, mark this segment not-empty.
	 */
	if ((shdr->sh_size != 0) ||
	    ((isp->is_flags & FLG_IS_EXTERNAL) == 0))
		osp->os_sgdesc->sg_flags |= FLG_SG_PHREQ;

	if ((ofl->ofl_flags1 & FLG_OF1_NOHDR) &&
	    (osp->os_sgdesc->sg_phdr).p_type != PT_LOAD)
		return;

	osp->os_sgdesc->sg_addralign =
	    ld_lcm(osp->os_sgdesc->sg_addralign, shdr->sh_addralign);
}

/*
 * Determine if section ordering is turned on.  If so, return the appropriate
 * os_txtndx.  This information is derived from the Sg_desc->sg_segorder
 * list that was built up from the Mapfile.
 */
static int
set_os_txtndx(Is_desc *isp, Sg_desc *sgp)
{
	Listnode *	lnp;
	Sec_order *	scop;

	for (LIST_TRAVERSE(&sgp->sg_secorder, lnp, scop)) {
		if (strcmp(scop->sco_secname, isp->is_name) == 0) {
			scop->sco_flags |= FLG_SGO_USED;
			return ((int)scop->sco_index);
		}
	}
	return (0);
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
	Os_desc	*	osp;
	int		os_ndx;
	Shdr *		shdr = isp->is_shdr;
	Xword		shflagmask, shflags = shdr->sh_flags;
	Ifl_desc *	ifl = isp->is_file;

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
	 * Assign the is_namehash value now that we've settled
	 * on the final name for the section.
	 */
	isp->is_namehash = sgs_str_hash(isp->is_name);

	if (sgp->sg_flags & FLG_SG_ORDER)
		enp->ec_flags |= FLG_EC_USED;

	/*
	 * If the link is not 0, then the isp is going to be appened
	 * to the output section where the input section pointed by
	 * link is placed.
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

		if (list_appendc(&(osp->os_isdescs), isp) == 0)
			return ((Os_desc *)S_ERROR);
		isp->is_osdesc = osp;
		sgp = osp->os_sgdesc;
		DBG_CALL(Dbg_sec_added(ofl->ofl_lml, osp, sgp));
		return (osp);
	}

	/*
	 * call the function set_os_txtndx() to set the
	 * os_txtndx field based upon the sg_segorder list that
	 * was built from a Mapfile.  If there is no match then
	 * os_txtndx will be set to 0.
	 *
	 * for now this value will be held in os_ndx.
	 */
	os_ndx = set_os_txtndx(isp, sgp);

	/*
	 * Setup the masks to flagout when matching sections
	 */
	shflagmask = ALL_SHF_ORDER;
	if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0)
		shflagmask = ALL_SHF_IGNORE;

	/*
	 * Traverse the input section list for the output section we have been
	 * assigned.  If we find a matching section simply add this new section.
	 */
	lnp2 = NULL;
	for (LIST_TRAVERSE(&(sgp->sg_osdescs), lnp1, osp)) {
		Shdr *	_shdr = osp->os_shdr;

		if ((ident == osp->os_scnsymndx) &&
		    (shdr->sh_type != SHT_SUNW_dof) &&
		    ((shdr->sh_type == _shdr->sh_type) ||
		    ((shdr->sh_type == SHT_SUNW_COMDAT) &&
		    (_shdr->sh_type == SHT_PROGBITS))) &&
		    ((shflags & ~shflagmask) ==
		    (_shdr->sh_flags & ~shflagmask)) &&
		    (ident != M_ID_REL) && (shdr->sh_type != SHT_GROUP) &&
		    (isp->is_namehash == osp->os_namehash) &&
		    (strcmp(isp->is_name, osp->os_name) == 0)) {
			/*
			 * If this is a COMDAT section, then see if this
			 * section is a keeper and/or if it is to
			 * be discarded.
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
			} else
				if (list_appendc(&(osp->os_isdescs), isp) == 0)
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
			if (((ifl && (ifl->ifl_flags & FLG_IF_IGNORE)) ||
			    DBG_ENABLED) &&
			    (osp->os_flags & FLG_OS_SECTREF)) {
				isp->is_flags |= FLG_IS_SECTREF;
				if (ifl)
				    ifl->ifl_flags |= FLG_IF_FILEREF;
			}

			DBG_CALL(Dbg_sec_added(ofl->ofl_lml, osp, sgp));
			return (osp);
		}

		/*
		 * check to see if we need to worry about section
		 * ordering.
		 */
		if (os_ndx) {
			if (osp->os_txtndx) {
				if (os_ndx < osp->os_txtndx)
					/* insert section here. */
					break;
				else {
					lnp2 = lnp1;
					continue;
				}
			} else {
				/* insert section here. */
				break;
			}
		} else if (osp->os_txtndx) {
			lnp2 = lnp1;
			continue;
		}

		/*
		 * If the new sections identifier is less than that of the
		 * present input section we need to insert the new section
		 * at this point.
		 */
		if (ident < osp->os_scnsymndx)
			break;
		lnp2 = lnp1;
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
		 * Trying to preserved the possibly intended meaning of
		 * sh_link/sh_info. See the translate_link()
		 * in update.c.
		 */
		osp->os_shdr->sh_link = shdr->sh_link;
		if (shdr->sh_flags & SHF_INFO_LINK)
			osp->os_shdr->sh_info = shdr->sh_info;
	}

	/*
	 * When -zignore is in effect, sections and files that are not
	 * referenced * from other sections, will be eliminated from the
	 * object being produced. Some sections, although unreferenced,
	 * are special, and must not be eliminated.  Determine if this new
	 * output section is one of those special sections, and if so mark
	 * it artificially as referenced.
	 * Any input section and file associated to this output section
	 * will also be marked as referenced, and thus won't be eliminated
	 * from the final output.
	 */
	if ((strcmp(osp->os_name, MSG_ORIG(MSG_SCN_INIT)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_FINI)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_EX_RANGES)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_EX_SHARED)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_CTORS)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_DTORS)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_EHFRAME)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_EHFRAME_HDR)) == 0) ||
	    (strcmp(osp->os_name, MSG_ORIG(MSG_SCN_JCR)) == 0)) {
		osp->os_flags |= FLG_OS_SECTREF;

		if ((ifl && (ifl->ifl_flags & FLG_IF_IGNORE)) || DBG_ENABLED) {
			isp->is_flags |= FLG_IS_SECTREF;
			if (ifl)
			    ifl->ifl_flags |= FLG_IF_FILEREF;
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
	if (sgp->sg_phdr.p_type == PT_LOAD) {
		if (!(osp->os_shdr->sh_flags & SHF_ALLOC)) {
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_SCN_NONALLOC), ofl->ofl_name,
			    osp->os_name);
			osp->os_shdr->sh_flags |= SHF_ALLOC;
		}
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

	if (list_appendc(&(osp->os_isdescs), isp) == 0)
		return ((Os_desc *)S_ERROR);

	DBG_CALL(Dbg_sec_created(ofl->ofl_lml, osp, sgp));
	isp->is_osdesc = osp;
	if (lnp2) {
		if (list_insertc(&(sgp->sg_osdescs), osp, lnp2) == 0)
			return ((Os_desc *)S_ERROR);
	} else {
		if (list_prependc(&(sgp->sg_osdescs), osp) == 0)
			return ((Os_desc *)S_ERROR);
	}
	return (osp);
}
