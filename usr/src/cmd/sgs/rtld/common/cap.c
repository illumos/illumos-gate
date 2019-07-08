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

#include	<sys/types.h>
#include	<sys/mman.h>
#include	<dirent.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<limits.h>
#include	<debug.h>
#include	<conv.h>
#include	<elfcap.h>
#include	"_rtld.h"
#include	"_elf.h"
#include	"_audit.h"
#include	"msg.h"

/*
 * qsort(3c) capability comparison function.
 */
static int
compare(const void *vp_a, const void *vp_b)
{
	Fdesc	*fdp_a = (Fdesc *)vp_a, *fdp_b = (Fdesc *)vp_b;
	char	*strcap_a, *strcap_b;
	Xword	hwcap_a, hwcap_b;

	/*
	 * First, investigate any platform capability.
	 */
	strcap_a = fdp_a->fd_scapset.sc_plat;
	strcap_b = fdp_b->fd_scapset.sc_plat;

	if (strcap_a && (strcap_b == NULL))
		return (-1);
	if (strcap_b && (strcap_a == NULL))
		return (1);

	/*
	 * Second, investigate any machine capability.
	 */
	strcap_a = fdp_a->fd_scapset.sc_mach;
	strcap_b = fdp_b->fd_scapset.sc_mach;

	if (strcap_a && (strcap_b == NULL))
		return (-1);
	if (strcap_b && (strcap_a == NULL))
		return (1);

	/*
	 * Third, investigate any CA_SUNW_HW_2 hardware capabilities.
	 */
	hwcap_a = fdp_a->fd_scapset.sc_hw_2;
	hwcap_b = fdp_b->fd_scapset.sc_hw_2;

	if (hwcap_a > hwcap_b)
		return (-1);
	if (hwcap_a < hwcap_b)
		return (1);

	/*
	 * Finally, investigate any CA_SUNW_HW_1 hardware capabilities.
	 */
	hwcap_a = fdp_a->fd_scapset.sc_hw_1;
	hwcap_b = fdp_b->fd_scapset.sc_hw_1;

	if (hwcap_a > hwcap_b)
		return (-1);
	if (hwcap_a < hwcap_b)
		return (1);

	/*
	 * Normally, a capabilities directory contains one or more capabilities
	 * files, each with different capabilities.  The role of ld.so.1 is to
	 * select the best candidate from these variants.  However, we've come
	 * across cases where files containing the same capabilities have been
	 * placed in the same capabilities directory.  As we can't tell which
	 * file is the best, we select neither, and diagnose this suspicious
	 * scenario.
	 */
	DBG_CALL(Dbg_cap_identical(fdp_a->fd_lml, fdp_a->fd_nname,
	    fdp_b->fd_nname));

	fdp_a->fd_flags |= FLG_FD_IGNORE;
	fdp_b->fd_flags |= FLG_FD_IGNORE;

	return (0);
}

/*
 * Determine whether HWCAP1 capabilities value is supported.
 */
int
hwcap1_check(Syscapset *scapset, Xword val, Rej_desc *rej)
{
	Xword	mval;

	/*
	 * Ensure that the kernel can cope with the required capabilities.
	 */
	if ((rtld_flags2 & RT_FL2_HWCAP) &&
	    ((mval = (val & ~scapset->sc_hw_1)) != 0)) {
		if (rej) {
			static Conv_cap_val_hw1_buf_t	cap_buf;

			rej->rej_type = SGS_REJ_HWCAP_1;
			rej->rej_str = conv_cap_val_hw1(mval,
			    M_MACH, 0, &cap_buf);
		}
		return (0);
	}
	return (1);
}

/*
 * Determine whether HWCAP2 capabilities value is supported.
 */
int
hwcap2_check(Syscapset *scapset, Xword val, Rej_desc *rej)
{
	Xword	mval;

	/*
	 * Ensure that the kernel can cope with the required capabilities.
	 */
	if ((mval = (val & ~scapset->sc_hw_2)) != 0) {
		if (rej) {
			static Conv_cap_val_hw2_buf_t	cap_buf;

			rej->rej_type = SGS_REJ_HWCAP_2;
			rej->rej_str = conv_cap_val_hw2(mval,
			    M_MACH, 0, &cap_buf);
		}
		return (0);
	}
	return (1);
}

/*
 * Process any software capabilities.
 */
/* ARGSUSED0 */
int
sfcap1_check(Syscapset *scapset, Xword val, Rej_desc *rej)
{
#if	defined(_ELF64)
	/*
	 * A 64-bit executable that started the process can be restricted to a
	 * 32-bit address space.  A 64-bit dependency that is restricted to a
	 * 32-bit address space can not be loaded unless the executable has
	 * established this requirement.
	 */
	if ((val & SF1_SUNW_ADDR32) && ((rtld_flags2 & RT_FL2_ADDR32) == 0)) {
		if (rej) {
			static Conv_cap_val_sf1_buf_t	cap_buf;

			rej->rej_type = SGS_REJ_SFCAP_1;
			rej->rej_str = conv_cap_val_sf1(SF1_SUNW_ADDR32,
			    M_MACH, 0, &cap_buf);
		}
		return (0);
	}
#endif
	return (1);
}

/*
 * Process any platform capability.
 */
int
platcap_check(Syscapset *scapset, const char *str, Rej_desc *rej)
{
	/*
	 * If the platform name hasn't been set, try and obtain it.
	 */
	if ((scapset->sc_plat == NULL) &&
	    (scapset->sc_platsz == 0))
		platform_name(scapset);

	if ((scapset->sc_plat == NULL) ||
	    (str && strcmp(scapset->sc_plat, str))) {
		if (rej) {
			/*
			 * Note, the platform name points to a string within an
			 * objects string table, and if that object can't be
			 * loaded, it will be unloaded and thus invalidate the
			 * string.  Duplicate the string here for rejection
			 * message inheritance.
			 */
			rej->rej_type = SGS_REJ_PLATCAP;
			rej->rej_str = stravl_insert(str, 0, 0, 0);
		}
		return (0);
	}
	return (1);
}

/*
 * Process any machine capability.
 */
int
machcap_check(Syscapset *scapset, const char *str, Rej_desc *rej)
{
	/*
	 * If the machine name hasn't been set, try and obtain it.
	 */
	if ((scapset->sc_mach == NULL) &&
	    (scapset->sc_machsz == 0))
		machine_name(scapset);

	if ((scapset->sc_mach == NULL) ||
	    (str && strcmp(scapset->sc_mach, str))) {
		if (rej) {
			/*
			 * Note, the machine name points to a string within an
			 * objects string table, and if that object can't be
			 * loaded, it will be unloaded and thus invalidate the
			 * string.  Duplicate the string here for rejection
			 * message inheritance.
			 */
			rej->rej_type = SGS_REJ_MACHCAP;
			rej->rej_str = stravl_insert(str, 0, 0, 0);
		}
		return (0);
	}
	return (1);
}

/*
 * Generic front-end to capabilities validation.
 */
static int
cap_check(Cap *cptr, char *strs, int alt, Fdesc *fdp, Rej_desc *rej)
{
	Syscapset	*scapset;
	int		totplat, ivlplat, totmach, ivlmach;

	/*
	 * If the caller has no capabilities, then the object is valid.
	 */
	if (cptr == NULL)
		return (1);

	if (alt)
		scapset = alt_scapset;
	else
		scapset = org_scapset;

	totplat = ivlplat = totmach = ivlmach = 0;

	while (cptr->c_tag != CA_SUNW_NULL) {
		Xword	val = cptr->c_un.c_val;
		char	*str;

		switch (cptr->c_tag) {
		case CA_SUNW_HW_1:
			/*
			 * Remove any historic values that should not be
			 * involved with any validation.
			 */
			val &= ~AV_HW1_IGNORE;

			if (hwcap1_check(scapset, val, rej) == 0)
				return (0);
			if (fdp)
				fdp->fd_scapset.sc_hw_1 = val;
			break;
		case CA_SUNW_SF_1:
			if (sfcap1_check(scapset, val, rej) == 0)
				return (0);
			if (fdp)
				fdp->fd_scapset.sc_sf_1 = val;
			break;
		case CA_SUNW_HW_2:
			if (hwcap2_check(scapset, val, rej) == 0)
				return (0);
			if (fdp)
				fdp->fd_scapset.sc_hw_2 = val;
			break;
		case CA_SUNW_PLAT:
			/*
			 * A capabilities group can define multiple platform
			 * names that are appropriate.  Only if all the names
			 * are deemed invalid is the group determined
			 * inappropriate.
			 */
			if (totplat == ivlplat) {
				totplat++;

				str = strs + val;

				if (platcap_check(scapset, str, rej) == 0)
					ivlplat++;
				else if (fdp)
					fdp->fd_scapset.sc_plat = str;
			}
			break;
		case CA_SUNW_MACH:
			/*
			 * A capabilities group can define multiple machine
			 * names that are appropriate.  Only if all the names
			 * are deemed invalid is the group determined
			 * inappropriate.
			 */
			if (totmach == ivlmach) {
				totmach++;

				str = strs + val;

				if (machcap_check(scapset, str, rej) == 0)
					ivlmach++;
				else if (fdp)
					fdp->fd_scapset.sc_mach = str;
			}
			break;
		case CA_SUNW_ID:
			/*
			 * Capabilities identifiers provide for diagnostics,
			 * but are not attributes that must be compared with
			 * the system.  They are ignored.
			 */
			break;
		default:
			rej->rej_type = SGS_REJ_UNKCAP;
			rej->rej_info = cptr->c_tag;
			return (0);
		}
		cptr++;
	}

	/*
	 * If any platform names, or machine names were found, and all were
	 * invalid, indicate that the object is inappropriate.
	 */
	if ((totplat && (totplat == ivlplat)) ||
	    (totmach && (totmach == ivlmach)))
		return (0);

	return (1);
}

#define	HWAVL_RECORDED(n)	pnavl_recorded(&capavl, n, 0, NULL)

/*
 * Determine whether a link-map should use alternative system capabilities.
 */
static void
cap_check_lmp_init(Rt_map *lmp)
{
	int	alt = 0;

	/*
	 * If an alternative set of system capabilities have been established,
	 * and only specific files should use these alternative system
	 * capabilities, determine whether this file is one of those specified.
	 */
	if (capavl) {
		const char	*file;

		/*
		 * The simplest way to reference a file is to use its file name
		 * (soname), however try all of the names that this file is
		 * known by.
		 */
		if ((file = strrchr(NAME(lmp), '/')) != NULL)
			file++;
		else
			file = NULL;

		if ((file && (HWAVL_RECORDED(file) != 0)) ||
		    (HWAVL_RECORDED(NAME(lmp)) != 0) ||
		    ((PATHNAME(lmp) != NAME(lmp)) &&
		    (HWAVL_RECORDED(PATHNAME(lmp)) != 0)))
			alt = 1;

		if (alt == 0) {
			Aliste		idx;
			const char	*cp;

			for (APLIST_TRAVERSE(ALIAS(lmp), idx, cp)) {
				if ((alt = HWAVL_RECORDED(cp)) != 0)
					break;
			}
		}
	}

	/*
	 * Indicate if this link-map should use alternative system capabilities,
	 * and that the alternative system capabilities check has been carried
	 * out.
	 */
	if ((org_scapset != alt_scapset) && ((capavl == NULL) || alt))
		FLAGS1(lmp) |= FL1_RT_ALTCAP;
	FLAGS1(lmp) |= FL1_RT_ALTCHECK;
}

/*
 * Validate the capabilities requirements of a link-map.
 *
 * This routine is called for main, where a link-map is constructed from the
 * mappings returned from exec(), and for any symbol capabilities comparisons.
 */
int
cap_check_lmp(Rt_map *lmp, Rej_desc *rej)
{
	if ((FLAGS1(lmp) & FL1_RT_ALTCHECK) == 0)
		cap_check_lmp_init(lmp);

	return (cap_check(CAP(lmp), STRTAB(lmp),
	    (FLAGS1(lmp) & FL1_RT_ALTCAP), NULL, rej));
}

/*
 * Validate the capabilities requirements of a file under inspection.
 * This file is still under the early stages of loading, and has no link-map
 * yet.  The file must have an object capabilities definition (PT_SUNWCAP), to
 * have gotten us here.  The logic here is the same as cap_check_lmp().
 */
int
cap_check_fdesc(Fdesc *fdp, Cap *cptr, char *strs, Rej_desc *rej)
{
	int	alt = 0;

	/*
	 * If an alternative set of system capabilities have been established,
	 * and only specific files should use these alternative system
	 * capabilities, determine whether this file is one of those specified.
	 */
	if (capavl) {
		const char	*file;

		/*
		 * The simplest way to reference a file is to use its file name
		 * (soname), however try all of the names that this file is
		 * known by.
		 */
		if (fdp->fd_oname &&
		    ((file = strrchr(fdp->fd_oname, '/')) != NULL))
			file++;
		else
			file = NULL;

		if ((file && (HWAVL_RECORDED(file) != 0)) ||
		    (fdp->fd_oname && (HWAVL_RECORDED(fdp->fd_oname) != 0)) ||
		    (fdp->fd_nname && (HWAVL_RECORDED(fdp->fd_nname) != 0)) ||
		    (fdp->fd_pname && (fdp->fd_pname != fdp->fd_nname) &&
		    (HWAVL_RECORDED(fdp->fd_pname) != 0)))
			alt = 1;
	}

	/*
	 * Indicate if this file descriptor should use alternative system
	 * capabilities, and that the alternative system capabilities check has
	 * been carried out.
	 */
	if ((org_scapset != alt_scapset) && ((capavl == NULL) || alt))
		fdp->fd_flags |= FLG_FD_ALTCAP;
	fdp->fd_flags |= FLG_FD_ALTCHECK;

	/*
	 * Verify that the required capabilities are supported by the reference.
	 */
	return (cap_check(cptr, strs, (fdp->fd_flags & FLG_FD_ALTCAP),
	    fdp, rej));
}

/*
 * Free a file descriptor list.  As part of building this list, the original
 * names for each capabilities candidate were duplicated for use in later
 * diagnostics.  These names need to be freed.
 */
void
free_fd(Alist *fdalp)
{
	if (fdalp) {
		Aliste	idx;
		Fdesc	*fdp;

		for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
			if (fdp->fd_oname)
				free((void *)fdp->fd_oname);
		}
		free(fdalp);
	}
}

/*
 * When $CAPABILITY (or $HWCAP) is used to represent dependencies, take the
 * associated directory and analyze all the files it contains.
 */
static int
cap_dir(Alist **fdalpp, Lm_list *lml, const char *dname, Rt_map *clmp,
    uint_t flags, Rej_desc *rej, int *in_nfavl)
{
	char		path[PATH_MAX], *dst;
	const char	*src;
	DIR		*dir;
	struct dirent	*dirent;
	Alist		*fdalp = NULL;
	Aliste		idx;
	Fdesc		*fdp;
	int		error = 0;

	/*
	 * Access the directory in preparation for reading its entries.  If
	 * successful, establish the initial pathname.
	 */
	if ((dir = opendir(dname)) == NULL) {
		Rej_desc	_rej = { 0 };

		_rej.rej_type = SGS_REJ_STR;
		_rej.rej_name = dname;
		_rej.rej_str = strerror(errno);
		DBG_CALL(Dbg_file_rejected(lml, &_rej, M_MACH));
		rejection_inherit(rej, &_rej);
		return (0);
	}

	for (dst = path, src = dname; *src; dst++, src++)
		*dst = *src;
	*dst++ = '/';

	/*
	 * Read each entry from the directory and determine whether it is a
	 * valid ELF file.
	 */
	while ((dirent = readdir(dir)) != NULL) {
		const char	*file = dirent->d_name;
		char		*_dst;
		Fdesc		fd = { 0 };
		Rej_desc	_rej = { 0 };
		Pdesc		pd = { 0 };

		/*
		 * Ignore "." and ".." entries.
		 */
		if ((file[0] == '.') && ((file[1] == '\0') ||
		    ((file[1] == '.') && (file[2] == '\0'))))
			continue;

		/*
		 * Complete the full pathname.
		 */
		for (_dst = dst, src = file, file = dst; *src; _dst++, src++)
			*_dst = *src;
		*_dst = '\0';

		/*
		 * Trace the inspection of this file, and determine any
		 * auditor substitution.
		 */
		pd.pd_pname = path;
		pd.pd_flags = PD_FLG_PNSLASH;

		if (load_trace(lml, &pd, clmp, &fd) == NULL)
			continue;

		/*
		 * Note, all directory entries are processed by find_path(),
		 * even entries that are directories themselves.  This single
		 * point for control keeps the number of stat()'s down, and
		 * provides a single point for error diagnostics.
		 */
		if (find_path(lml, clmp, flags, &fd, &_rej, in_nfavl) == 0) {
			rejection_inherit(rej, &_rej);
			continue;
		}

		DBG_CALL(Dbg_cap_candidate(lml, fd.fd_nname));

		/*
		 * If this object has already been loaded, save the capabilities
		 * for later sorting.  Otherwise we have a new candidate.
		 */
		if (fd.fd_lmp)
			fd.fd_scapset = CAPSET(fd.fd_lmp);
		fd.fd_lml = lml;

		/*
		 * Duplicate the original name, as this may be required for
		 * later diagnostics.  Keep a copy of the file descriptor for
		 * analysis once all capabilities candidates have been
		 * determined.
		 */
		if (((fd.fd_oname = strdup(fd.fd_oname)) == NULL) ||
		    (alist_append(&fdalp, &fd, sizeof (Fdesc),
		    AL_CNT_CAP) == NULL)) {
			error = 1;
			break;
		}
	}
	(void) closedir(dir);

	/*
	 * If no objects have been found, we're done.  Also, if an allocation
	 * error occurred while processing any object, remove any objects that
	 * had already been added to the list and return.
	 */
	if ((fdalp == NULL) || error) {
		if (fdalp)
			free_fd(fdalp);
		return (0);
	}

	/*
	 * Having processed and retained all candidates from this directory,
	 * sort them, based on the precedence of their hardware capabilities.
	 */
	qsort(fdalp->al_data, fdalp->al_nitems, fdalp->al_size, compare);

	/*
	 * If any objects were found to have the same capabilities, then these
	 * objects must be rejected, as we can't tell which object is more
	 * appropriate.
	 */
	for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
		if (fdp->fd_flags & FLG_FD_IGNORE)
			alist_delete(fdalp, &idx);
	}

	if (fdalp->al_nitems == 0) {
		free_fd(fdalp);
		return (0);
	}

	*fdalpp = fdalp;
	return (1);
}

int
cap_filtees(Alist **alpp, Aliste oidx, const char *dir, Aliste nlmco,
    Rt_map *flmp, Rt_map *clmp, const char *ref, int mode, uint_t flags,
    int *in_nfavl)
{
	Alist		*fdalp = NULL;
	Aliste		idx;
	Fdesc		*fdp;
	Lm_list		*lml = LIST(flmp);
	int		unused = 0;
	Rej_desc	rej = { 0 };

	if (cap_dir(&fdalp, lml, dir, flmp, flags, &rej, in_nfavl) == 0)
		return (0);

	/*
	 * Now complete the mapping of each of the ordered objects, adding
	 * each object to a new pathname descriptor.
	 */
	for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
		Rt_map	*nlmp;
		Grp_hdl	*ghp = NULL;
		Pdesc	*pdp;
		int	audit = 0;

		if (unused)
			continue;

		/*
		 * Complete mapping the file, obtaining a handle, and continue
		 * to analyze the object, establishing dependencies and
		 * relocating.  Remove the file descriptor at this point, as it
		 * is no longer required.
		 */
		DBG_CALL(Dbg_file_filtee(lml, NAME(flmp), fdp->fd_nname, 0));

		nlmp = load_path(lml, nlmco, flmp, mode,
		    (flags | FLG_RT_PUBHDL), &ghp, fdp, &rej, in_nfavl);
		if (nlmp == NULL)
			continue;

		/*
		 * Create a new pathname descriptor to represent this filtee,
		 * and insert this descriptor in the Alist following the
		 * hardware descriptor that seeded this processing.
		 */
		if ((pdp = alist_insert(alpp, 0, sizeof (Pdesc),
		    AL_CNT_FILTEES, ++oidx)) == NULL) {
			if (ghp)
				remove_lmc(lml, flmp, nlmco, NAME(nlmp));
			return (0);
		}

		pdp->pd_pname = NAME(nlmp);
		pdp->pd_plen = strlen(NAME(nlmp));

		/*
		 * Establish the filter handle to prevent any recursion.
		 */
		if (nlmp && ghp) {
			ghp->gh_flags |= GPH_FILTEE;
			pdp->pd_info = (void *)ghp;
		}

		/*
		 * Audit the filter/filtee established.  A return of 0
		 * indicates the auditor wishes to ignore this filtee.
		 */
		if (nlmp && (lml->lm_tflags | FLAGS1(flmp)) &
		    LML_TFLG_AUD_OBJFILTER) {
			if (audit_objfilter(flmp, ref, nlmp, 0) == 0) {
				audit = 1;
				nlmp = NULL;
			}
		}

		/*
		 * Finish processing the objects associated with this request.
		 */
		if (nlmp && ghp && (((nlmp = analyze_lmc(lml, nlmco, nlmp,
		    clmp, in_nfavl)) == NULL) ||
		    (relocate_lmc(lml, nlmco, flmp, nlmp, in_nfavl) == 0)))
			nlmp = NULL;

		/*
		 * If the filtee has been successfully processed, then create
		 * an association between the filter and the filtee.  This
		 * association provides sufficient information to tear down the
		 * filter and filtee if necessary.
		 */
		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
		if (nlmp && ghp &&
		    (hdl_add(ghp, flmp, GPD_FILTER, NULL) == NULL))
			nlmp = NULL;

		/*
		 * If this object is marked an end-filtee, we're done.
		 */
		if (nlmp && ghp && (FLAGS1(nlmp) & FL1_RT_ENDFILTE))
			unused = 1;

		/*
		 * If this filtee loading has failed, generate a diagnostic.
		 * Null out the path name descriptor entry, and continue the
		 * search.
		 */
		if (nlmp == NULL) {
			DBG_CALL(Dbg_file_filtee(lml, 0, pdp->pd_pname, audit));

			/*
			 * If attempting to load this filtee required a new
			 * link-map control list to which this request has
			 * added objects, then remove all the objects that
			 * have been associated to this request.
			 */
			if (nlmco != ALIST_OFF_DATA)
				remove_lmc(lml, flmp, nlmco, pdp->pd_pname);

			pdp->pd_plen = 0;
			pdp->pd_info = NULL;
		}
	}

	free_fd(fdalp);
	return (1);
}

/*
 * Load an individual capabilities object.
 */
Rt_map *
load_cap(Lm_list *lml, Aliste lmco, const char *dir, Rt_map *clmp,
    uint_t mode, uint_t flags, Grp_hdl **hdl, Rej_desc *rej, int *in_nfavl)
{
	Alist	*fdalp = NULL;
	Aliste	idx;
	Fdesc	*fdp;
	int	found = 0;
	Rt_map	*lmp = NULL;

	/*
	 * Obtain the sorted list of hardware capabilities objects available.
	 */
	if (cap_dir(&fdalp, lml, dir, clmp, flags, rej, in_nfavl) == 0)
		return (NULL);

	/*
	 * From the list of hardware capability objects, use the first and
	 * discard the rest.
	 */
	for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
		Fdesc	fd = *fdp;

		if ((found == 0) && ((lmp = load_path(lml, lmco, clmp, mode,
		    flags, hdl, &fd, rej, in_nfavl)) != NULL))
			found++;
	}

	free_fd(fdalp);
	return (lmp);
}

/*
 * Use a case insensitive string match when looking up capability mask
 * values by name, and omit the AV_ prefix.
 */
#define	ELFCAP_STYLE	ELFCAP_STYLE_LC | ELFCAP_STYLE_F_ICMP

/*
 * To aid in the development and testing of capabilities, an alternative system
 * capabilities group can be specified.  This alternative set is initialized
 * from the system capabilities that are normally used to validate all object
 * loading.  However, the user can disable, enable or override flags within
 * this alternative set, and thus affect object loading.
 *
 * This technique is usually combined with defining the family of objects
 * that should be compared against this alternative set.  Without defining the
 * family of objects, all objects loaded by ld.so.1 are validated against the
 * alternative set.  This can prevent the loading of critical system objects
 * like libc, and thus prevent process execution.
 */
typedef enum {
	CAP_OVERRIDE =	0,		/* override existing capabilities */
	CAP_ENABLE =	1,		/* enable capabilities */
	CAP_DISABLE =	2		/* disable capabilities */
} cap_mode;

static struct {
	elfcap_mask_t	cs_val[3];	/* value settings, and indicator for */
	int		cs_set[3];	/*	OVERRIDE, ENABLE and DISABLE */
	elfcap_mask_t	*cs_aval;	/* alternative variable for final */
					/*	update */
} cap_settings[3] = {
	{ { 0, 0, 0 }, { 0, 0, 0 }, NULL },		/* CA_SUNW_HW_1 */
	{ { 0, 0, 0 }, { 0, 0, 0 }, NULL },		/* CA_SUNW_SF_1 */
	{ { 0, 0, 0 }, { 0, 0, 0 }, NULL }		/* CA_SUNW_HW_2 */
};

static int
cap_modify(Xword tag, const char *str)
{
	char		*caps, *ptr, *next;
	cap_mode	mode = CAP_OVERRIDE;
	Xword		ndx;

	if ((caps = strdup(str)) == NULL)
		return (0);

	for (ptr = strtok_r(caps, MSG_ORIG(MSG_CAP_DELIMIT), &next);
	    ptr != NULL;
	    ptr = strtok_r(NULL, MSG_ORIG(MSG_CAP_DELIMIT), &next)) {
		Xword		val = 0;

		/*
		 * Determine whether this token should be enabled (+),
		 * disabled (-), or override any existing settings.
		 */
		if (*ptr == '+') {
			mode = CAP_ENABLE;
			ptr++;
		} else if (*ptr == '-') {
			mode = CAP_DISABLE;
			ptr++;
		}

		/*
		 * Process the capabilities as directed by the calling tag.
		 */
		switch (tag) {
		case CA_SUNW_HW_1:
			/*
			 * Determine whether the capabilities string matches
			 * a known hardware capability mask.  Note, the caller
			 * indicates that these are hardware capabilities by
			 * passing in the CA_SUNW_HW_1 tag.  However, the
			 * tokens could be CA_SUNW_HW_1 or CA_SUNW_HW_2.
			 */
			if ((val = (Xword)elfcap_hw2_from_str(ELFCAP_STYLE,
			    ptr, M_MACH)) != 0) {
				ndx = CA_SUNW_HW_2;
				break;
			}
			if ((val = (Xword)elfcap_hw1_from_str(ELFCAP_STYLE,
			    ptr, M_MACH)) != 0)
				ndx = CA_SUNW_HW_1;
			break;
		case CA_SUNW_SF_1:
			/*
			 * Determine whether the capabilities string matches a
			 * known software capability mask.  Note, the callers
			 * indication of what capabilities to process are
			 * triggered by a tag of CA_SUNW_SF_1, but the tokens
			 * processed could be CA_SUNW_SF_1, CA_SUNW_SF_2, etc.
			 */
			if ((val = (Xword)elfcap_sf1_from_str(ELFCAP_STYLE,
			    ptr, M_MACH)) != 0)
				ndx = CA_SUNW_SF_1;
			break;
		}

		/*
		 * If a capabilities token has not been matched, interpret the
		 * string as a number.  To provide for setting the various
		 * families (CA_SUNW_HW_1, CA_SUNW_HW_2), the number can be
		 * prefixed with the (bracketed) family index.
		 *
		 *	LD_HWCAP=[1]0x40    sets CA_SUNW_HW_1 with 0x40
		 *	LD_HWCAP=[2]0x80    sets CA_SUNW_HW_2 with 0x80
		 *
		 * Invalid indexes are ignored.
		 */
		if (val == 0) {
			char *end;

			if ((*ptr == '[') && (*(ptr + 2) == ']')) {
				if (*(ptr + 1) == '1') {
					ndx = tag;
					ptr += 3;
				} else if (*(ptr + 1) == '2') {
					if (tag == CA_SUNW_HW_1) {
						ndx = CA_SUNW_HW_2;
						ptr += 3;
					} else {
						/* invalid index */
						continue;
					}
				} else {
					/* invalid index */
					continue;
				}
			} else
				ndx = tag;

			errno = 0;
			if (((val = strtol(ptr, &end, 16)) == 0) && errno)
				continue;

			/*
			 * If the value wasn't an entirely valid hexadecimal
			 * integer, assume it was intended as a capability
			 * name and skip it.
			 */
			if (*end != '\0') {
				eprintf(NULL, ERR_WARNING,
				    MSG_INTL(MSG_CAP_IGN_UNKCAP), ptr);
				continue;
			}
		}

		cap_settings[ndx - 1].cs_val[mode] |= val;
		cap_settings[ndx - 1].cs_set[mode]++;

	}

	/*
	 * If the "override" token was supplied, set the alternative
	 * system capabilities, then enable or disable others.
	 */
	for (ndx = 0; ndx < CA_SUNW_HW_2; ndx++) {
		if (cap_settings[ndx].cs_set[CAP_OVERRIDE])
			*(cap_settings[ndx].cs_aval) =
			    cap_settings[ndx].cs_val[CAP_OVERRIDE];
		if (cap_settings[ndx].cs_set[CAP_ENABLE])
			*(cap_settings[ndx].cs_aval) |=
			    cap_settings[ndx].cs_val[CAP_ENABLE];
		if (cap_settings[ndx].cs_set[CAP_DISABLE])
			*(cap_settings[ndx].cs_aval) &=
			    ~cap_settings[ndx].cs_val[CAP_DISABLE];
	}
	free(caps);
	return (1);
}
#undef	ELFCAP_STYLE

/*
 * Create an AVL tree of objects that are to be validated against an alternative
 * system capabilities value.
 */
static int
cap_files(const char *str)
{
	char	*caps, *name, *next;

	if ((caps = strdup(str)) == NULL)
		return (0);

	for (name = strtok_r(caps, MSG_ORIG(MSG_CAP_DELIMIT), &next);
	    name != NULL;
	    name = strtok_r(NULL, MSG_ORIG(MSG_CAP_DELIMIT), &next)) {
		avl_index_t	where;
		PathNode	*pnp;
		uint_t		hash = sgs_str_hash(name);

		/*
		 * Determine whether this pathname has already been recorded.
		 */
		if (pnavl_recorded(&capavl, name, hash, &where))
			continue;

		if ((pnp = calloc(sizeof (PathNode), 1)) != NULL) {
			pnp->pn_name = name;
			pnp->pn_hash = hash;
			avl_insert(capavl, pnp, where);
		}
	}

	return (1);
}

/*
 * Set alternative system capabilities.  A user can establish alternative system
 * capabilities from the environment, or from a configuration file.  This
 * routine is called in each instance.  Environment variables only set the
 * replaceable (rpl) variables.  Configuration files can set both replaceable
 * (rpl) and permanent (prm) variables.
 */
int
cap_alternative(void)
{
	/*
	 * If no capabilities have been set, we're done.
	 */
	if ((rpl_hwcap == NULL) && (rpl_sfcap == NULL) &&
	    (rpl_machcap == NULL) && (rpl_platcap == NULL) &&
	    (prm_hwcap == NULL) && (prm_sfcap == NULL) &&
	    (prm_machcap == NULL) && (prm_platcap == NULL))
		return (1);

	/*
	 * If the user has requested to modify any capabilities, establish a
	 * unique set from the present system capabilities.
	 */
	if ((alt_scapset = malloc(sizeof (Syscapset))) == NULL)
		return (0);
	*alt_scapset = *org_scapset;

	cap_settings[CA_SUNW_HW_1 - 1].cs_aval = &alt_scapset->sc_hw_1;
	cap_settings[CA_SUNW_SF_1 - 1].cs_aval = &alt_scapset->sc_sf_1;
	cap_settings[CA_SUNW_HW_2 - 1].cs_aval = &alt_scapset->sc_hw_2;

	/*
	 * Process any replaceable variables.
	 */
	if (rpl_hwcap && (cap_modify(CA_SUNW_HW_1, rpl_hwcap) == 0))
		return (0);
	if (rpl_sfcap && (cap_modify(CA_SUNW_SF_1, rpl_sfcap) == 0))
		return (0);

	if (rpl_platcap) {
		alt_scapset->sc_plat = (char *)rpl_platcap;
		alt_scapset->sc_platsz = strlen(rpl_platcap);
	}
	if (rpl_machcap) {
		alt_scapset->sc_mach = (char *)rpl_machcap;
		alt_scapset->sc_machsz = strlen(rpl_machcap);
	}

	if (rpl_cap_files && (cap_files(rpl_cap_files) == 0))
		return (0);

	/*
	 * Process any permanent variables.
	 */
	if (prm_hwcap && (cap_modify(CA_SUNW_HW_1, prm_hwcap) == 0))
		return (0);
	if (prm_sfcap && (cap_modify(CA_SUNW_SF_1, prm_sfcap) == 0))
		return (0);

	if (prm_platcap) {
		alt_scapset->sc_plat = (char *)prm_platcap;
		alt_scapset->sc_platsz = strlen(prm_platcap);
	}
	if (prm_machcap) {
		alt_scapset->sc_mach = (char *)prm_machcap;
		alt_scapset->sc_machsz = strlen(prm_machcap);
	}

	if (prm_cap_files && (cap_files(prm_cap_files) == 0))
		return (0);

	/*
	 * Reset the replaceable variables.  If this is the environment variable
	 * processing, these variables are now available for configuration file
	 * initialization.
	 */
	rpl_hwcap = rpl_sfcap = rpl_machcap = rpl_platcap =
	    rpl_cap_files = NULL;

	return (1);
}

/*
 * Take the index from a Capinfo entry and determine the associated capabilities
 * set.  Verify that the capabilities are available for this system.
 */
static int
sym_cap_check(Cap *cptr, uint_t cndx, Syscapset *bestcapset, Rt_map *lmp,
    const char *name, uint_t ndx)
{
	Syscapset	*scapset;
	int		totplat, ivlplat, totmach, ivlmach, capfail = 0;

	/*
	 * Determine whether this file requires validation against alternative
	 * system capabilities.
	 */
	if ((FLAGS1(lmp) & FL1_RT_ALTCHECK) == 0)
		cap_check_lmp_init(lmp);

	if (FLAGS1(lmp) & FL1_RT_ALTCAP)
		scapset = alt_scapset;
	else
		scapset = org_scapset;

	totplat = ivlplat = totmach = ivlmach = 0;

	/*
	 * A capabilities index points to a capabilities group that can consist
	 * of one or more capabilities, terminated with a CA_SUNW_NULL entry.
	 */
	for (cptr += cndx; cptr->c_tag != CA_SUNW_NULL; cptr++) {
		Xword	val = cptr->c_un.c_val;
		char	*str;

		switch (cptr->c_tag) {
		case CA_SUNW_HW_1:
			/*
			 * Remove any historic values that should not be
			 * involved with any validation.
			 */
			val &= ~AV_HW1_IGNORE;

			bestcapset->sc_hw_1 = val;
			DBG_CALL(Dbg_syms_cap_lookup(lmp, DBG_CAP_HW_1,
			    name, ndx, M_MACH, bestcapset));

			if (hwcap1_check(scapset, val, NULL) == 0)
				capfail++;
			break;
		case CA_SUNW_SF_1:
			bestcapset->sc_sf_1 = val;
			DBG_CALL(Dbg_syms_cap_lookup(lmp, DBG_CAP_SF_1,
			    name, ndx, M_MACH, bestcapset));

			if (sfcap1_check(scapset, val, NULL) == 0)
				capfail++;
			break;
		case CA_SUNW_HW_2:
			bestcapset->sc_hw_2 = val;
			DBG_CALL(Dbg_syms_cap_lookup(lmp, DBG_CAP_HW_2,
			    name, ndx, M_MACH, bestcapset));

			if (hwcap2_check(scapset, val, NULL) == 0)
				capfail++;
			break;
		case CA_SUNW_PLAT:
			/*
			 * A capabilities set can define multiple platform names
			 * that are appropriate.  Only if all the names are
			 * deemed invalid is the group determined inappropriate.
			 */
			if (totplat == ivlplat) {
				totplat++;

				str = STRTAB(lmp) + val;
				bestcapset->sc_plat = str;

				DBG_CALL(Dbg_syms_cap_lookup(lmp, DBG_CAP_PLAT,
				    name, ndx, M_MACH, bestcapset));

				if (platcap_check(scapset, str, NULL) == 0)
					ivlplat++;
			}
			break;
		case CA_SUNW_MACH:
			/*
			 * A capabilities set can define multiple machine names
			 * that are appropriate.  Only if all the names are
			 * deemed invalid is the group determined inappropriate.
			 */
			if (totmach == ivlmach) {
				totmach++;

				str = STRTAB(lmp) + val;
				bestcapset->sc_mach = str;

				DBG_CALL(Dbg_syms_cap_lookup(lmp, DBG_CAP_MACH,
				    name, ndx, M_MACH, bestcapset));

				if (machcap_check(scapset, str, NULL) == 0)
					ivlmach++;
			}
			break;
		default:
			break;
		}
	}

	/*
	 * If any platform definitions, or machine definitions were found, and
	 * all were invalid, indicate that the object is inappropriate.
	 */
	if (capfail || (totplat && (totplat == ivlplat)) ||
	    (totmach && (totmach == ivlmach))) {
		DBG_CALL(Dbg_syms_cap_lookup(lmp, DBG_CAP_REJECTED, name, ndx,
		    M_MACH, NULL));
		return (0);
	}

	DBG_CALL(Dbg_syms_cap_lookup(lmp, DBG_CAP_CANDIDATE, name, ndx,
	    M_MACH, NULL));
	return (1);
}

/*
 * Determine whether a symbols capabilities are more significant than any that
 * have already been validated.  The precedence of capabilities are:
 *
 *   PLATCAP -> MACHCAP -> HWCAP_2 -> HWCAP_1
 *
 *
 * Presently we make no comparisons of software capabilities.  However, should
 * this symbol capability have required the SF1_SUNW_ADDR32 attribute, then
 * this would have been validated as appropriate or not.
 *
 * bestcapset is the presently available 'best' capabilities group, and
 * symcapset is the present capabilities group under investigation.  Return 0
 * if the bestcapset should remain in affect, or 1 if the symcapset is better.
 */
inline static int
is_sym_the_best(Syscapset *bestcapset, Syscapset *symcapset)
{
	/*
	 * Check any platform capability.  If the new symbol isn't associated
	 * with a CA_SUNW_PLAT capability, and the best symbol is, then retain
	 * the best capabilities group.  If the new symbol is associated with a
	 * CA_SUNW_PLAT capability, and the best symbol isn't, then the new
	 * symbol needs to be taken.
	 */
	if (bestcapset->sc_plat && (symcapset->sc_plat == NULL))
		return (0);

	if ((bestcapset->sc_plat == NULL) && symcapset->sc_plat)
		return (1);

	/*
	 * Check any machine name capability.  If the new symbol isn't
	 * associated with a CA_SUNW_MACH capability, and the best symbol is,
	 * then retain the best capabilities group.  If the new symbol is
	 * associated with a CA_SUNW_MACH capability, and the best symbol isn't,
	 * then the new symbol needs to be taken.
	 */
	if (bestcapset->sc_mach && (symcapset->sc_mach == NULL))
		return (0);

	if ((bestcapset->sc_mach == NULL) && symcapset->sc_mach)
		return (1);

	/*
	 * Check the hardware capabilities.  If the best symbols CA_SUNW_HW_2
	 * capabilities are greater than the new symbols capabilities, then
	 * retain the best capabilities group.  If the new symbols CA_SUNW_HW_2
	 * capabilities are greater than the best symbol, then the new symbol
	 * needs to be taken.
	 */
	if (bestcapset->sc_hw_2 > symcapset->sc_hw_2)
		return (0);

	if (bestcapset->sc_hw_2 < symcapset->sc_hw_2)
		return (1);

	/*
	 * Check the remaining hardware capabilities.  If the best symbols
	 * CA_SUNW_HW_1 capabilities are greater than the new symbols
	 * capabilities, then retain the best capabilities group.  If the new
	 * symbols CA_SUNW_HW_1 capabilities are greater than the best symbol,
	 * then the new symbol needs to be taken.
	 */
	if (bestcapset->sc_hw_1 > symcapset->sc_hw_1)
		return (0);

	if (bestcapset->sc_hw_1 < symcapset->sc_hw_1)
		return (1);

	/*
	 * Both capabilities are the same.  Retain the best on a first-come
	 * first-served basis.
	 */
	return (0);
}

/*
 * Initiate symbol capabilities processing.  If an initial symbol lookup
 * results in binding to a symbol that has an associated SUNW_capinfo entry,
 * we arrive here.
 *
 * The standard model is that this initial symbol is the lead capabilities
 * symbol (defined as CAPINFO_SUNW_GLOB) of a capabilities family.  This lead
 * symbol's SUNW_capinfo information points to the SUNW_capchain entry that
 * provides the family symbol indexes.  We traverse this chain, looking at
 * each family member, to discover the best capabilities instance.  This
 * instance name and symbol information is returned to establish the final
 * symbol binding.
 *
 * If the symbol that got us here is not CAPINFO_SUNW_GLOB, then we've bound
 * directly to a capabilities symbol which must be verified.  This is not the
 * model created by ld(1) using -z symbolcap, but might be created directly
 * within a relocatable object by the compilation system.
 */
int
cap_match(Sresult *srp, uint_t symndx, Sym *symtabptr, char *strtabptr)
{
	Rt_map		*ilmp = srp->sr_dmap;
	Sym		*bsym = NULL;
	const char	*bname;
	Syscapset	bestcapset = { 0 };
	Cap		*cap;
	Capchain	*capchain;
	uchar_t		grpndx;
	uint_t		ochainndx, nchainndx, bndx;

	cap = CAP(ilmp);
	capchain = CAPCHAIN(ilmp);

	grpndx = (uchar_t)ELF_C_GROUP(CAPINFO(ilmp)[symndx]);

	/*
	 * If this symbols capability group is not a lead symbol, then simply
	 * verify the symbol.
	 */
	if (grpndx != CAPINFO_SUNW_GLOB) {
		Syscapset	symcapset = { 0 };

		return (sym_cap_check(cap, grpndx, &symcapset, ilmp,
		    srp->sr_name, symndx));
	}

	/*
	 * If there is no capabilities chain, return the lead symbol.
	 */
	if (capchain == NULL)
		return (1);

	ochainndx = (uint_t)ELF_C_SYM(CAPINFO(ilmp)[symndx]);

	/*
	 * If there is only one member for this family, take it.  Once a family
	 * has been processed, the best family instance is written to the head
	 * of the chain followed by a null entry.  This caching ensures that the
	 * same family comparison doesn't have to be undertaken more than once.
	 */
	if (capchain[ochainndx] && (capchain[ochainndx + 1] == 0)) {
		Sym		*fsym = symtabptr + capchain[ochainndx];
		const char	*fname = strtabptr + fsym->st_name;

		DBG_CALL(Dbg_syms_cap_lookup(ilmp, DBG_CAP_USED, fname,
		    capchain[ochainndx], M_MACH, NULL));

		srp->sr_sym = fsym;
		srp->sr_name = fname;
		return (1);
	}

	/*
	 * As this symbol is the lead symbol of a capabilities family, it is
	 * considered the generic member, and therefore forms the basic
	 * fall-back for the capabilities family.
	 */
	DBG_CALL(Dbg_syms_cap_lookup(ilmp, DBG_CAP_DEFAULT, srp->sr_name,
	    symndx, M_MACH, NULL));
	bsym = srp->sr_sym;
	bname = srp->sr_name;
	bndx = symndx;

	/*
	 * Traverse the capabilities chain analyzing each family member.
	 */
	for (nchainndx = ochainndx + 1, symndx = capchain[nchainndx]; symndx;
	    nchainndx++, symndx = capchain[nchainndx]) {
		Sym		*nsym = symtabptr + symndx;
		const char	*nname = strtabptr + nsym->st_name;
		Syscapset	symcapset = { 0 };

		if ((grpndx =
		    (uchar_t)ELF_C_GROUP(CAPINFO(ilmp)[symndx])) == 0)
			continue;

		if (sym_cap_check(cap, grpndx, &symcapset, ilmp,
		    nname, symndx) == 0)
			continue;

		/*
		 * Determine whether a symbol's capabilities are more
		 * significant than any that have already been validated.
		 */
		if (is_sym_the_best(&bestcapset, &symcapset)) {
			bestcapset = symcapset;
			bsym = nsym;
			bname = nname;
			bndx = symndx;
		}
	}

	DBG_CALL(Dbg_syms_cap_lookup(ilmp, DBG_CAP_USED, bname, bndx,
	    M_MACH, NULL));

	/*
	 * Having found the best symbol, cache the results by overriding the
	 * first element of the associated chain.
	 */
	capchain[ochainndx] = bndx;
	capchain[ochainndx + 1] = 0;

	/*
	 * Update the symbol result information for return to the user.
	 */
	srp->sr_sym = bsym;
	srp->sr_name = bname;
	return (1);
}
