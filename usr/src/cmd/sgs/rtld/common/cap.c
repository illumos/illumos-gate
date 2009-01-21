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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include	"_rtld.h"
#include	"_audit.h"
#include	"msg.h"

/*
 * qsort(3c) comparison function.
 */
static int
compare(const void *fdesc1, const void *fdesc2)
{
	Xword	hwcap1 = ((Fdesc *)fdesc1)->fd_hwcap;
	Xword	hwcap2 = ((Fdesc *)fdesc2)->fd_hwcap;

	if (hwcap1 && (hwcap2 == 0))
		return (-1);
	if ((hwcap1 == 0) && hwcap2)
		return (1);
	if ((hwcap1 == 0) && (hwcap2 == 0))
		return (0);

	if (hwcap1 > hwcap2)
		return (-1);
	if (hwcap1 < hwcap2)
		return (1);
	return (0);
}

/*
 * Process any hardware capabilities.
 */
int
hwcap_check(Xword val, Rej_desc *rej)
{
	Xword	mval;

	/*
	 * Ensure that the kernel can cope with the required capabilities.
	 */
	if ((rtld_flags2 & RT_FL2_HWCAP) && ((mval = (val & ~hwcap)) != 0)) {
		static Conv_cap_val_hw1_buf_t	cap_buf;

		rej->rej_type = SGS_REJ_HWCAP_1;
		rej->rej_str = conv_cap_val_hw1(mval, M_MACH, 0, &cap_buf);
		return (0);
	}
	return (1);
}

/*
 * Process any software capabilities.
 */
/* ARGSUSED0 */
int
sfcap_check(Xword val, Rej_desc *rej)
{
#if	defined(_ELF64)
	/*
	 * A 64-bit executable that started the process can be restricted to a
	 * 32-bit address space.  A 64-bit dependency that is restricted to a
	 * 32-bit address space can not be loaded unless the executable has
	 * established this requirement.
	 */
	if ((val & SF1_SUNW_ADDR32) && ((rtld_flags2 & RT_FL2_ADDR32) == 0)) {
		static Conv_cap_val_sf1_buf_t	cap_buf;

		rej->rej_type = SGS_REJ_SFCAP_1;
		rej->rej_str =
		    conv_cap_val_sf1(SF1_SUNW_ADDR32, M_MACH, 0, &cap_buf);
		return (0);
	}
#endif
	return (1);
}

/*
 * When $HWCAP is used to represent dependencies, take the associated directory
 * and analyze all the files it contains.
 */
static int
hwcap_dir(Alist **fdalpp, Lm_list *lml, const char *dname, Rt_map *clmp,
    uint_t flags, Rej_desc *rej, int *in_nfavl)
{
	char		path[PATH_MAX], *dst;
	const char	*src;
	DIR		*dir;
	struct dirent	*dirent;
	Alist		*fdalp = NULL;
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

		DBG_CALL(Dbg_cap_hw_candidate(lml, fd.fd_nname));

		/*
		 * If this object has already been loaded, obtain the hardware
		 * capabilities for later sorting.  Otherwise we have a new
		 * candidate.
		 */
		if (fd.fd_lmp)
			fd.fd_hwcap = HWCAP(fd.fd_lmp);

		if (alist_append(&fdalp, &fd, sizeof (Fdesc),
		    AL_CNT_HWCAP) == NULL) {
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
			free(fdalp);
		return (0);
	}

	/*
	 * Having processed and retained all candidates from this directory,
	 * sort them, based on the precedence of their hardware capabilities.
	 */
	qsort(fdalp->al_data, fdalp->al_nitems, fdalp->al_size, compare);

	*fdalpp = fdalp;
	return (1);
}

int
hwcap_filtees(Alist **alpp, Aliste oidx, const char *dir, Aliste nlmco,
    Lm_cntl *nlmc, Rt_map *flmp, const char *ref, int mode, uint_t flags,
    int *in_nfavl)
{
	Alist		*fdalp = NULL;
	Aliste		idx;
	Fdesc		*fdp;
	Lm_list		*lml = LIST(flmp);
	int		unused = 0;
	Rej_desc	rej = { 0 };

	if (hwcap_dir(&fdalp, lml, dir, flmp, flags, &rej, in_nfavl) == 0)
		return (0);

	/*
	 * Now complete the mapping of each of the ordered objects, adding
	 * each object to a new pathname descriptor.
	 */
	for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
		Rt_map	*nlmp;
		Grp_hdl	*ghp = 0;
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
		    (flags | FLG_RT_HANDLE), &ghp, fdp, &rej, in_nfavl);
		if (nlmp == 0)
			continue;

		/*
		 * Create a new pathname descriptor to represent this filtee,
		 * and insert this descriptor in the Alist following the
		 * hardware descriptor that seeded this processing.
		 * capability directory).
		 */
		if ((pdp = alist_insert(alpp, 0, sizeof (Pdesc),
		    AL_CNT_FILTEES, ++oidx)) == NULL) {
			if (ghp)
				remove_lmc(lml, flmp, nlmc, nlmco, NAME(nlmp));
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
				nlmp = 0;
			}
		}

		/*
		 * Finish processing the objects associated with this request.
		 */
		if (nlmp && ghp && (((nlmp = analyze_lmc(lml, nlmco, nlmp,
		    in_nfavl)) == NULL) ||
		    (relocate_lmc(lml, nlmco, flmp, nlmp, in_nfavl) == 0)))
			nlmp = NULL;

		/*
		 * If the filtee has been successfully processed, then create
		 * an association between the filter and the filtee.  This
		 * association provides sufficient information to tear down the
		 * filter and filtee if necessary.
		 */
		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
		if (nlmp && ghp && (hdl_add(ghp, flmp, GPD_FILTER) == 0))
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
			if (nlmc && nlmc->lc_head)
				remove_lmc(lml, flmp, nlmc, nlmco,
				    pdp->pd_pname);

			pdp->pd_plen = 0;
			pdp->pd_info = 0;
		}
	}

	free(fdalp);
	return (1);
}

/*
 * Load an individual hardware capabilities object.
 */
Rt_map *
load_hwcap(Lm_list *lml, Aliste lmco, const char *dir, Rt_map *clmp,
    uint_t mode, uint_t flags, Grp_hdl **hdl, Rej_desc *rej, int *in_nfavl)
{
	Alist	*fdalp = NULL;
	Aliste	idx;
	Fdesc	*fdp;
	int	found = 0;
	Rt_map	*lmp = 0;

	/*
	 * Obtain the sorted list of hardware capabilities objects available.
	 */
	if (hwcap_dir(&fdalp, lml, dir, clmp, flags, rej, in_nfavl) == 0)
		return (NULL);

	/*
	 * From the list of hardware capability objects, use the first and
	 * discard the rest.
	 */
	for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
		Fdesc	fd = *fdp;

		if ((found == 0) && ((lmp = load_path(lml, lmco, clmp, mode,
		    flags, hdl, &fd, rej, in_nfavl)) != 0))
			found++;
	}

	free(fdalp);
	return (lmp);
}
