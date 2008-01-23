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

#include	"_synonyms.h"

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
	ulong_t	hwcap1 = ((Fdesc *)fdesc1)->fd_fmap.fm_hwptr;
	ulong_t	hwcap2 = ((Fdesc *)fdesc2)->fd_fmap.fm_hwptr;

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
 * If this object defines a set of hardware capability requirements, insure the
 * kernal can cope with them.
 */
int
hwcap_check(Rej_desc *rej, Ehdr *ehdr)
{
	Cap	*cptr;
	Phdr	*phdr;
	int	cnt;

	/* LINTED */
	phdr = (Phdr *)((char *)ehdr + ehdr->e_phoff);
	for (cnt = 0; cnt < ehdr->e_phnum; cnt++, phdr++) {
		Lword	val;

		if (phdr->p_type != PT_SUNWCAP)
			continue;

		/* LINTED */
		cptr = (Cap *)((char *)ehdr + phdr->p_offset);
		while (cptr->c_tag != CA_SUNW_NULL) {
			if (cptr->c_tag == CA_SUNW_HW_1)
				break;
			cptr++;
		}
		if (cptr->c_tag == CA_SUNW_NULL)
			break;

		if ((val = (cptr->c_un.c_val & ~hwcap)) != 0) {
			static Conv_cap_val_hw1_buf_t cap_buf;

			rej->rej_type = SGS_REJ_HWCAP_1;
			rej->rej_str =
			    conv_cap_val_hw1(val, M_MACH, 0, &cap_buf);
			return (0);
		}

		/*
		 * Retain this hardware capabilities pointer for possible later
		 * inspection should this object be processed as a filtee.
		 */
		fmap->fm_hwptr = cptr->c_un.c_val;
	}
	return (1);
}

static void
remove_fdesc(Fdesc *fdp)
{
#if	defined(MAP_ALIGN)
	if (fdp->fd_fmap.fm_maddr &&
	    ((fdp->fd_fmap.fm_mflags & MAP_ALIGN) == 0)) {
#else
	if (fdp->fd_fmap.fm_maddr) {
#endif
		(void) munmap(fdp->fd_fmap.fm_maddr, fdp->fd_fmap.fm_msize);

		/*
		 * Note, this file descriptor might be duplicating information
		 * from the global fmap descriptor.  If so, clean up the global
		 * descriptor to prevent a duplicate (unnecessary) unmap.
		 */
		if (fmap->fm_maddr == fdp->fd_fmap.fm_maddr) {
			fmap->fm_maddr = 0;
			fmap_setup();
		}
	}
	if (fdp->fd_fd)
		(void) close(fdp->fd_fd);
	if (fdp->fd_pname && (fdp->fd_pname != fdp->fd_nname))
		free((void *)fdp->fd_pname);
	if (fdp->fd_nname)
		free((void *)fdp->fd_nname);
}

/*
 * When $HWCAP is used to represent dependencies, take the associated directory
 * and analyze all the files it contains.
 */
static int
hwcap_dir(Alist **fdalpp, Lm_list *lml, const char *name, Rt_map *clmp,
    uint_t flags, Rej_desc *rej)
{
	char		path[PATH_MAX], *dst;
	const char	*src;
	DIR		*dir;
	struct dirent	*dirent;
	Aliste		idx;
	Alist		*fdalp = NULL;
	Fdesc		*fdp;
	int		error = 0;

	/*
	 * Access the directory in preparation for reading its entries.  If
	 * successful, establish the initial pathname.
	 */
	if ((dir = opendir(name)) == 0) {
		Rej_desc	_rej = { 0 };

		_rej.rej_type = SGS_REJ_STR;
		_rej.rej_name = name;
		_rej.rej_str = strerror(errno);
		DBG_CALL(Dbg_file_rejected(lml, &_rej));
		rejection_inherit(rej, &_rej);
		return (0);
	}

	for (dst = path, src = name; *src; dst++, src++)
		*dst = *src;
	*dst++ = '/';

	/*
	 * Read each entry from the directory and determine whether it is a
	 * valid ELF file.
	 */
	while ((dirent = readdir(dir)) != NULL) {
		const char	*file = dirent->d_name, *oname;
		char		*_dst;
		Fdesc		fdesc = { 0 };
		Rej_desc	_rej = { 0 };

		/*
		 * Ignore "." and ".." entries.
		 */
		if ((file[0] == '.') && ((file[1] == '\0') ||
		    ((file[1] == '.') && (file[2] == '\0'))))
			continue;

		/*
		 * Complete the full pathname, and verify its usability.  Note,
		 * an auditor can supply an alternative name.
		 */
		for (_dst = dst, src = file, file = dst; *src; _dst++, src++)
			*_dst = *src;
		*_dst = '\0';

		if ((oname = strdup(path)) == NULL) {
			error = 1;
			break;
		}

		if (load_trace(lml, &oname, clmp) == 0) {
			free((void *)oname);
			continue;
		}
		name = oname;

		/*
		 * Note, all directory entries are processed by find_path(),
		 * even entries that are directories themselves.  This single
		 * point for control keeps the number of stat()'s down, and
		 * provides a single point for error diagnostics.
		 */
		if (find_path(lml, name, clmp, flags, &fdesc, &_rej) == 0) {
			rejection_inherit(rej, &_rej);
			if ((rej->rej_name != _rej.rej_name) &&
			    (_rej.rej_name == name))
				free((void *)name);
			continue;
		}

		DBG_CALL(Dbg_cap_hw_candidate(lml, name));

		/*
		 * If this object has already been loaded, obtain the hardware
		 * capabilities for later sorting.  Otherwise we have a new
		 * candidate.
		 */
		if (fdesc.fd_lmp)
			fdesc.fd_fmap.fm_hwptr = HWCAP(fdesc.fd_lmp);
		else
			fdesc.fd_fmap = *fmap;

		if (alist_append(&fdalp, &fdesc, sizeof (Fdesc), 10) == 0) {
			remove_fdesc(&fdesc);
			error = 1;
			break;
		}

		/*
		 * Clear the global file mapping structure so that the mapping
		 * for this file won't be overriden.
		 */
		fmap->fm_mflags = MAP_PRIVATE;
		fmap->fm_maddr = 0;
		fmap->fm_msize = FMAP_SIZE;
		fmap->fm_hwptr = 0;
	}
	(void) closedir(dir);

	/*
	 * If no objects have been found, we're done.  Also, if an allocation
	 * error occurred while processing any object, remove any objects that
	 * had already been added to the list and return.
	 */
	if ((fdalp == NULL) || error) {
		if (fdalp) {
			for (ALIST_TRAVERSE(fdalp, idx, fdp))
				remove_fdesc(fdp);
			free(fdalp);
		}
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

static Pnode *
_hwcap_filtees(Pnode **pnpp, Aliste nlmco, Lm_cntl *nlmc, Rt_map *flmp,
    const char *ref, const char *dir, int mode, uint_t flags)
{
	Alist		*fdalp = NULL;
	Aliste		idx;
	Pnode		*fpnp = 0, *lpnp, *npnp = (*pnpp)->p_next;
	Fdesc		*fdp;
	Lm_list		*lml = LIST(flmp);
	int		unused = 0;
	Rej_desc	rej = { 0 };

	if (hwcap_dir(&fdalp, lml, dir, flmp, flags, &rej) == 0) {
		remove_rej(&rej);
		return (0);
	}

	/*
	 * Now complete the mapping of each of the ordered objects, adding
	 * each object to a new Pnode.
	 */
	for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
		Rt_map	*nlmp;
		Grp_hdl	*ghp = 0;
		Pnode	*pnp;
		int	audit = 0;

		if (unused) {
			/*
			 * Flush out objects remaining.
			 */
			remove_fdesc(fdp);
			continue;
		}

		/*
		 * Complete mapping the file, obtaining a handle, and continue
		 * to analyze the object, establishing dependencies and
		 * relocating.  Remove the file descriptor at this point, as it
		 * is no longer required.
		 */
		DBG_CALL(Dbg_file_filtee(lml, NAME(flmp), fdp->fd_nname, 0));

		nlmp = load_path(lml, nlmco, &fdp->fd_nname, flmp, mode,
		    (flags | FLG_RT_HANDLE), &ghp, fdp, &rej);
		remove_fdesc(fdp);
		if (nlmp == 0)
			continue;

		/*
		 * Create a new Pnode to represent this filtee, and substitute
		 * the calling Pnode (which was used to represent the hardware
		 * capability directory).
		 */
		if ((pnp = calloc(1, sizeof (Pnode))) == 0) {
			if (ghp) {
				remove_lmc(lml, flmp, nlmc, nlmco,
				    fdp->fd_nname);
			}
			return (0);
		}
		if ((pnp->p_name = strdup(NAME(nlmp))) == NULL) {
			if (ghp) {
				remove_lmc(lml, flmp, nlmc, nlmco,
				    fdp->fd_nname);
			}
			free(pnp);
			return (0);
		}
		pnp->p_len = strlen(NAME(nlmp));
		pnp->p_info = (void *)ghp;
		pnp->p_next = npnp;

		if (fpnp == 0) {
			Pnode	*opnp = (*pnpp);

			/*
			 * If this is the first pnode, reuse the original after
			 * freeing any of its pathnames.
			 */
			if (opnp->p_name)
				free((void *)opnp->p_name);
			if (opnp->p_oname)
				free((void *)opnp->p_oname);
			*opnp = *pnp;
			free((void *)pnp);
			fpnp = lpnp = pnp = opnp;
		} else {
			lpnp->p_next = pnp;
			lpnp = pnp;
		}

		/*
		 * Establish the filter handle to prevent any recursion.
		 */
		if (nlmp && ghp) {
			ghp->gh_flags |= GPH_FILTEE;
			pnp->p_info = (void *)ghp;
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
		if (nlmp && ghp && ((analyze_lmc(lml, nlmco, nlmp) == 0) ||
		    (relocate_lmc(lml, nlmco, flmp, nlmp) == 0)))
			nlmp = 0;

		/*
		 * If the filtee has been successfully processed, then create
		 * an association between the filter and the filtee.  This
		 * association provides sufficient information to tear down the
		 * filter and filtee if necessary.
		 */
		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
		if (nlmp && ghp && (hdl_add(ghp, flmp, GPD_FILTER) == 0))
			nlmp = 0;

		/*
		 * If this object is marked an end-filtee, we're done.
		 */
		if (nlmp && ghp && (FLAGS1(nlmp) & FL1_RT_ENDFILTE))
			unused = 1;

		/*
		 * If this filtee loading has failed, generate a diagnostic.
		 * Null out the pnode entry, and continue the search.
		 */
		if (nlmp == 0) {
			/*
			 * If attempting to load this filtee required a new
			 * link-map control list to which this request has
			 * added objects, then remove all the objects that
			 * have been associated to this request.
			 */
			if (nlmc && nlmc->lc_head)
				remove_lmc(lml, flmp, nlmc, nlmco, pnp->p_name);

			DBG_CALL(Dbg_file_filtee(lml, 0, pnp->p_name, audit));

			pnp->p_len = 0;
			pnp->p_info = 0;
		}
	}

	free(fdalp);
	return (fpnp);
}

Pnode *
hwcap_filtees(Pnode **pnpp, Aliste nlmco, Lm_cntl *nlmc, Dyninfo *dip,
    Rt_map *flmp, const char *ref, int mode, uint_t flags)
{
	Pnode		*pnp = *pnpp;
	const char	*dir = pnp->p_name;
	Lm_list		*flml = LIST(flmp);

	DBG_CALL(Dbg_cap_hw_filter(flml, dir, flmp));

	if ((pnp = _hwcap_filtees(pnpp, nlmco, nlmc, flmp, ref, dir, mode,
	    flags)) != 0)
		return (pnp);

	/*
	 * If no hardware capability filtees have been found, provide suitable
	 * diagnostics and mark the incoming Pnode as unused.
	 */
	if ((flml->lm_flags & LML_FLG_TRC_ENABLE) &&
	    (dip->di_flags & FLG_DI_AUXFLTR) && (rtld_flags & RT_FL_WARNFLTR))
		(void) printf(MSG_INTL(MSG_LDD_HWCAP_NFOUND), dir);

	DBG_CALL(Dbg_cap_hw_filter(flml, dir, 0));

	pnp = *pnpp;
	pnp->p_len = 0;
	return (pnp);
}

/*
 * Load an individual hardware capabilities object.
 */
Rt_map *
load_hwcap(Lm_list *lml, Aliste lmco, const char *dir, Rt_map *clmp,
    uint_t mode, uint_t flags, Grp_hdl **hdl, Rej_desc *rej)
{
	Alist		*fdalp = NULL;
	Aliste		idx;
	Fdesc		*fdp;
	int		found = 0;
	Rt_map		*lmp = 0;

	/*
	 * Obtain the sorted list of hardware capabilites objects available.
	 */
	if (hwcap_dir(&fdalp, lml, dir, clmp, flags, rej) == 0)
		return (0);

	/*
	 * From the list of hardware capability objects, use the first and
	 * discard the rest.
	 */
	for (ALIST_TRAVERSE(fdalp, idx, fdp)) {
		if ((found == 0) && ((lmp = load_path(lml, lmco, &fdp->fd_nname,
		    clmp, mode, flags, hdl, fdp, rej)) != 0))
			found++;

		/*
		 * Remove the used file descriptor and any objects remaining.
		 */
		remove_fdesc(fdp);
	}

	free(fdalp);
	return (lmp);
}
