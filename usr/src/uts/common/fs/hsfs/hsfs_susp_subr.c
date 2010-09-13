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
 * System Use Sharing protocol subroutines for High Sierra filesystem
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/buf.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>

#include <vm/page.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_impl.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include "fs/fs_subr.h"
#include <sys/cmn_err.h>

/* static declarations */
static void free_cont_area(uchar_t *);
static int get_cont_area(struct hsfs *, uchar_t **, cont_info_t *);
static int parse_signatures(sig_args_t *, int, uchar_t *, int);

/*
 * parse_sua()
 *
 * This is the main SUSP routine, that gets all the SUA areas and
 * continuations.	It calls parse_signatures() to actually interpret
 * the signature fields.
 *
 * XXX - need to implement signature searching to speed things up and
 *		which is needed for the api, which isn't done yet.
 */
int
parse_sua(
	uchar_t			*name_p,	/* location to copy name */
	int			*name_len_p,	/* location to put name len */
	int			*name_change_p,	/* flags to signal name chg */
	uchar_t			*dirp,		/* pointer to ISO dir entry */
	uint_t			last_offset,	/* last ind. in cur. dirblock */
	struct hs_direntry	*hdp,		/* loc to store dir info */
	struct hsfs		*fsp,		/* filesystem pointer */
	uchar_t			*search_sig,	/* signature to search for */
	int			search_num)	/* n^th sig to search for */
{
	uchar_t			*SUA_p = IDE_sys_use_area(dirp);
	int			SUA_len = IDE_SUA_LEN(dirp);
	uchar_t			*tmp_SUA_p = (SUA_p + fsp->hsfs_sua_off);
	int			tmp_SUA_len = (SUA_len - fsp->hsfs_sua_off);
	short			ret_val = -1;
	uchar_t			*cont_p = (uchar_t *)NULL;
	sig_args_t		sig_args;
	cont_info_t		cont_info;

	/*
	 * If there is no SUA, just return, no error
	 */

	if (SUA_len == 0)
		return (0);

	/*
	 * Underflow on the length field means there's a mismatch
	 * between sizes of SUA and ISO directory entry. This entry
	 * is corrupted, return an appropriate error.
	 */
	if (SUA_len < 0) {
		hs_log_bogus_disk_warning(fsp, HSFS_ERR_NEG_SUA_LEN, 0);
		return (SUA_EINVAL);
	}

	if ((tmp_SUA_p + tmp_SUA_len) > (dirp + last_offset)) {
		hs_log_bogus_disk_warning(fsp, HSFS_ERR_BAD_SUA_LEN, 0);
		return (SUA_EINVAL);
	}

	/*
	 * Make sure that the continuation lenth is zero, as that is
	 * the way to tell if we must grab another continuation area.
	 */
	bzero((char *)&cont_info, sizeof (cont_info));

	sig_args.dirp		= dirp;
	sig_args.name_p		= name_p;
	sig_args.name_len_p	= name_len_p;
	sig_args.SUF_ptr	= tmp_SUA_p;
	sig_args.hdp		= hdp;
	sig_args.fsp		= fsp;
	sig_args.cont_info_p	= &cont_info;
	sig_args.flags		= 0;
	sig_args.name_flags	= 0;

	/*
	 * Get ready to put in a new name.	 If no "NM" is found, then
	 * hs_namecopy will come to the rescue.  Make sure you don't
	 * have NULL names, also.
	 */
	if (name_p)
		*(name_p) = '\0';
	if (name_len_p)
		*(name_len_p) = 0;

	while (ret_val == -1) {
		switch (parse_signatures(&sig_args, tmp_SUA_len, search_sig,
		    search_num)) {
		case END_OF_SUA :
			if (cont_info.cont_len) {

				if (get_cont_area(fsp, &cont_p, &cont_info)) {
					ret_val = 1;
					goto clean_up;
				}

				sig_args.SUF_ptr =
				    cont_p + cont_info.cont_offset;

				tmp_SUA_len = cont_info.cont_len;
				cont_info.cont_len = 0;

				continue;
			}
			sig_args.flags = 0;	/* reset */
			ret_val = 0;		/* keep going */
			break;
		case SUA_NULL_POINTER:
			ret_val = SUA_NULL_POINTER;
			goto clean_up;
		case SUA_ENOMEM:
			ret_val = SUA_ENOMEM;
			goto clean_up;
		case SUA_EINVAL:
			ret_val = SUA_EINVAL;
			goto clean_up;
		case RELOC_DIR:
			ret_val = RELOC_DIR;
			goto clean_up;
		}
	}

	if (ret_val != 0)
		goto clean_up;

	if (IS_NAME_BIT_SET(sig_args.name_flags, RRIP_NAME_CHANGE))
		SET_NAME_BIT(*(name_change_p), RRIP_NAME_CHANGE);

clean_up:
	free_cont_area(cont_p);
	return (ret_val);

}

/*
 * parse_signatures()
 *
 * Find the correct handling function for the signature string that is
 * passed to this function.
 *
 * signature searching:
 *
 * The two arguments of search_sig and search_num are for finding the
 * search_num^th occurance of the signature search_sig.  This will come
 * in handy with searching for the "NM" field and is part of the api
 * for rrip (which really can be used for any extension).
 */
/*ARGSUSED*/
static int
parse_signatures(
	sig_args_t	*sig_args_p,
	int		SUA_len,
	uchar_t		*search_sig,	/* possible signature to search for */
	int		search_num)	/* n^th occurance of search_sig to */
					/*   search for */
{
	uchar_t			*sig_string = sig_args_p->SUF_ptr;
	extension_name_t	*extnp;
	ext_signature_t		*ext_sigp;
	int			impl_bit_num = 0;
	int			SUA_rem = SUA_len; /* SUA length */
					/* remaining to be parsed */

	/* This should never happen ... just so we don't panic, literally */
	if (sig_string == (uchar_t *)NULL)
		return (SUA_NULL_POINTER);

	if (SUA_len < 0)
		return (SUA_EINVAL);

	/*
	 * Until the end of SUA, search for the signatures
	 * (check for end of SUA (2 consecutive NULL bytes)) or the
	 * remaining  length of the SUA is <= 3.  The minimum signature
	 * field  is 4.
	 */

	while ((SUA_rem >= SUF_MIN_LEN) && (*sig_string != '\0') &&
		(*(sig_string + 1) != '\0')) {

		/*
		 * Find appropriate extension and signature table
		 */
		for (extnp = extension_name_table, impl_bit_num = 0;
		    extnp->extension_name != (char *)NULL;
		    extnp++, impl_bit_num++)  {

			/*
			 * look at an extension only if it is implemented
			 * on the CD-ROM
			 */
			if (!IS_IMPL_BIT_SET(sig_args_p->fsp, impl_bit_num))
				continue;

			/*
			 * Find the appropriate signature
			 */
			for (ext_sigp = extnp->signature_table;
			    ext_sigp->ext_signature != (char *)NULL;
			    ext_sigp++)  {

				if (strncmp((char *)sig_string,
					    ext_sigp->ext_signature,
					    SUF_SIG_LEN) == 0) {

					SUA_rem -= SUF_LEN(sig_string);
					if (SUA_rem < 0)
						return (END_OF_SUA);

					/*
					 * The SUA_len parameter specifies the
					 * length of the SUA that the kernel
					 * expects. There is also a length
					 * encoded in the SUA data. If they
					 * do not agree, bail out.
					 */
					if (SUA_len < SUF_LEN(sig_string)) {
						cmn_err(CE_NOTE,
					"parse_signatures: SUA length too big: "
					"expected=%d, found=%d",
						    SUA_len,
						    SUF_LEN(sig_string));
						return (SUA_EINVAL);
					}

					sig_args_p->SUF_ptr = sig_string;
					sig_string =
					    (ext_sigp->sig_handler)(sig_args_p);

					switch (sig_args_p->flags) {
					case END_OF_SUA :
						return (END_OF_SUA);
					case SUA_ENOMEM :
						return (SUA_ENOMEM);
					case SUA_EINVAL :
						return (SUA_EINVAL);
					case RELOC_DIR :
						return (RELOC_DIR);
					default :
#if NAME_SEARCH
						case NAME_CONTINUE :
							/* nothing for now */
						case NAME_CHANGE :
							/* nothing for now */
#endif
						break;
					}

					/* reset to be zero */

					sig_args_p->flags = 0;
					goto next_signature;
				}

				/* off to the next signature .... */

			} /* for ext_sigp */

		} /* for extnp	(extension parsing) */

		/*
		 * Opps, did not find this signature. We must
		 * advance on the the next signature in the SUA
		 * and pray to persumedly omniscient, omnipresent,
		 * almighty transcendental being(s) that the next
		 * record is in the susp format, or we get hosed.
		 */
		if (SUA_rem < SUF_MIN_LEN)
			return (END_OF_SUA);

		SUA_rem -= SUF_LEN(sig_string);
		sig_string += SUF_LEN(sig_string);

next_signature:
		/*
		 * Failsafe
		 */
		if (SUA_rem < SUF_MIN_LEN ||
		    sig_string == NULL || SUF_LEN(sig_string) <= 0) {
			return (END_OF_SUA);
		}

	} /* while */

	return (END_OF_SUA);
}

/*
 * hs_fill_root_dirent()
 *
 *
 * This function reads the root directory extent to get to the SUA of
 * the "." entry of the root directory.  It the checks to see if the
 * susp is implemented.
 */
void
hs_check_root_dirent(struct vnode *vp, struct hs_direntry *hdp)
{
	struct buf	*secbp;
	uchar_t		*root_ptr;
	uchar_t		*secp;
	uint_t		secno;
	offset_t	secoff;
	sig_args_t	sig_args;
	struct hsfs	*fsp;
	int		error;

	if (vp->v_type != VDIR) {
		cmn_err(CE_NOTE,
		    "hs_check_root_dirent: vp (0x%p) not a directory",
		    (void *)vp);
		return;
	}

	bzero((caddr_t)&sig_args, sizeof (sig_args));

	fsp = VFS_TO_HSFS(vp->v_vfsp);
	secno = LBN_TO_SEC(hdp->ext_lbn+hdp->xar_len, vp->v_vfsp);
	secoff = LBN_TO_BYTE(hdp->ext_lbn+hdp->xar_len, vp->v_vfsp) &
	    MAXHSOFFSET;
	secbp = bread(fsp->hsfs_devvp->v_rdev, secno * 4, HS_SECTOR_SIZE);
	error = geterror(secbp);

	if (error != 0) {
		cmn_err(CE_NOTE,
		    "hs_check_root_dirent: bread: error=(%d)", error);
		goto end;
	}

	secp = (uchar_t *)secbp->b_un.b_addr;
	root_ptr = &secp[secoff];

	/* quick check */
	if (hdp->ext_lbn != HDE_EXT_LBN(root_ptr)) {
		cmn_err(CE_NOTE, "hs_check_root_dirent: dirent not match\n");
		/* keep on going */
	}

	/*
	 * Here, we know that the "." entry is the first in the sector
	 * just read (ISO 9660).  Let's now check for the sharing
	 * protocol and set call the susp sig_handler() if we should.
	 * Then we run through the hs_parsedir() function to catch all
	 * the other possibilities of SUSP fields and continuations.
	 *
	 * If there is no SUA area, just return, and assume ISO.
	 *
	 * If the SUA area length is invalid (negative, due to a mismatch
	 * between dirent size and SUA size), return and hope for the best.
	 */

	if (IDE_SUA_LEN(root_ptr) <= 0)
		goto end;

	if (strncmp(SUSP_SP, (char *)IDE_sys_use_area(root_ptr),
	    SUF_SIG_LEN) == 0) {
		/*
		 * We have a match of the sharing signature, so let's
		 * call the sig_handler to do what is necessary. We can
		 * ignore the return value, as implemented bits are set.
		 */
		sig_args.SUF_ptr = IDE_sys_use_area(root_ptr);
		sig_args.fsp	 = fsp;

		if ((susp_sp->sig_handler)(&sig_args) == (uchar_t *)NULL) {
			goto end;
		}
	} else {
		goto end;
	}

	/*
	 * If the "ER" signature in the root directory is past any non SU
	 * signature, the Rock Ridge signatures will be ignored. This happens
	 * e.g. for filesystems created by mkisofs. In this case,
	 * IS_RRIP_IMPLEMENTED(fsp) will return 0 when the "ER" signature is
	 * parsed. Unfortunately, the results of this run will be cached for
	 * the root vnode. The solution is to run hs_parsedir() a second time
	 * for the root directory.
	 */
	if (hs_parsedir(fsp, root_ptr, hdp, (char *)NULL, (int *)NULL,
	    HS_SECTOR_SIZE - secoff) == 0) {
		(void) hs_parsedir(fsp, root_ptr, hdp, (char *)NULL,
		    (int *)NULL, HS_SECTOR_SIZE - secoff);
	}

	/*
	 * If we did not get at least 1 extension, let's assume ISO and
	 * NULL out the implementation bits.
	 */
	if (fsp->hsfs_ext_impl <= 1L)
		fsp->hsfs_ext_impl = 0L;

end:
	brelse(secbp);
}


/*
 * get_cont_area()
 *
 * This function allocates a memory block, if necessary, and reads the
 * continuation area into the allocated space.
 *
 * Return value : 	0 if the read and allocation went OK.
 * 			1 if there was an error.
 */
static int
get_cont_area(struct hsfs *fsp, uchar_t **buf_pp, cont_info_t *cont_info_p)
{
	struct buf	*secbp;
	int		error;
	uint_t		secno;

	/*
	 * Guard against invalid continuation area records.
	 * Both cont_offset and cont_len must be no longer than
	 * HS_SECTOR_SIZE. If they are, return an error.
	 */
	if (cont_info_p->cont_offset > HS_SECTOR_SIZE ||
	    cont_info_p->cont_len > HS_SECTOR_SIZE) {
		cmn_err(CE_NOTE, "get_cont_area: invalid offset/length");
		return (1);
	}

	if (*buf_pp == (uchar_t *)NULL)
		*buf_pp = kmem_alloc((size_t)HS_SECTOR_SIZE, KM_SLEEP);

	secno = (uint_t)LBN_TO_SEC(cont_info_p->cont_lbn, fsp->hsfs_vfs);
	secbp = bread(fsp->hsfs_devvp->v_rdev, secno * 4, HS_SECTOR_SIZE);
	error = geterror(secbp);

	if (error != 0) {
		cmn_err(CE_NOTE, "get_cont_area: bread: error=(%d)", error);
		brelse(secbp);
		return (1);
	}

	/*
	 * This continuation area does not extend into the next sector
	 * so just copy the data to the buffer.
	 */
	if ((cont_info_p->cont_offset + cont_info_p->cont_len) <=
	    HS_SECTOR_SIZE) {
		bcopy(secbp->b_un.b_addr, (char *)*buf_pp, HS_SECTOR_SIZE);
	}
	/*
	 * This continuation area extends into the next sector so we
	 * need to do some dancing:
	 *
	 * - zero the return buffer so nothing random is returned
	 * - copy the partial data to the *beginning* of the return buffer
	 * - release the first sector's buffer
	 * - read the next sector
	 * - copy the remainder of the data to the return buffer
	 */
	else {
		uint_t	partial_size;

		bzero((char *)*buf_pp, HS_SECTOR_SIZE);
		partial_size = HS_SECTOR_SIZE - cont_info_p->cont_offset;
		bcopy(&secbp->b_un.b_addr[cont_info_p->cont_offset],
		    (char *)*buf_pp, partial_size);
		cont_info_p->cont_offset = 0;
		brelse(secbp);

		secbp = bread(fsp->hsfs_devvp->v_rdev, (secno + 1) * 4,
		    HS_SECTOR_SIZE);
		error = geterror(secbp);
		if (error != 0) {
			cmn_err(CE_NOTE, "get_cont_area: bread(2): error=(%d)",
			    error);
			brelse(secbp);
			return (1);
		}
		bcopy(secbp->b_un.b_addr, (char *)&(*buf_pp)[partial_size],
		    cont_info_p->cont_len - partial_size);
	}

	brelse(secbp);
	return (0);
}


/*
 * free_cont_area
 *
 * simple function to just free up memory, if it exists
 *
 */
static void
free_cont_area(uchar_t *cont_p)
{
	if (cont_p)
		(void) kmem_free((caddr_t)cont_p, (size_t)HS_SECTOR_SIZE);
	cont_p = (uchar_t *)NULL;
}
