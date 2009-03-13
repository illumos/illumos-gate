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

/*
 * Rock Ridge extensions to the System Use Sharing protocol
 * for the High Sierra filesystem
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
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
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/mkdev.h>
#include <sys/ddi.h>

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

static void form_time(int, uchar_t *, struct timeval *);
static void name_parse(int, uchar_t *, size_t, uchar_t *, int *,
    ulong_t *, int);

/*
 *  Signature table for RRIP
 */
ext_signature_t  rrip_signature_table[ ] = {
	RRIP_CL,	rrip_child_link,
	RRIP_NM,	rrip_name,
	RRIP_PL,	rrip_parent_link,
	RRIP_PN,	rrip_dev_nodes,
	RRIP_PX,	rrip_file_attr,
	RRIP_RE,	rrip_reloc_dir,
	RRIP_RR,	rrip_rock_ridge,
	RRIP_SL,	rrip_sym_link,
	RRIP_TF,	rrip_file_time,
	(char *)NULL,   NULL
};


/*
 * rrip_dev_nodes()
 *
 * sig_handler() for RRIP signature "PN"
 *
 * This function parses out the major and minor numbers from the "PN
 * " SUF.
 */
uchar_t *
rrip_dev_nodes(sig_args_t *sig_args_p)
{
	uchar_t *pn_ptr = sig_args_p->SUF_ptr;
	major_t	major_dev = (major_t)RRIP_MAJOR(pn_ptr);
	minor_t	minor_dev = (minor_t)RRIP_MINOR(pn_ptr);

	sig_args_p->hdp->r_dev = makedevice(major_dev, minor_dev);

	return (pn_ptr + SUF_LEN(pn_ptr));
}

/*
 * rrip_file_attr()
 *
 * sig_handler() for RRIP signature "PX"
 *
 * This function parses out the file attributes of a file from the "PX"
 * SUF.  The attributes is finds are : st_mode, st_nlink, st_uid,
 * and st_gid.
 */
uchar_t *
rrip_file_attr(sig_args_t *sig_args_p)
{
	uchar_t *px_ptr = sig_args_p->SUF_ptr;
	struct hs_direntry *hdp    = sig_args_p->hdp;

	hdp->mode  = RRIP_MODE(px_ptr);
	hdp->nlink = RRIP_NLINK(px_ptr);
	hdp->uid   = RRIP_UID(px_ptr);
	hdp->gid   = RRIP_GID(px_ptr);

	if (SUF_LEN(px_ptr) >= RRIP_PX_SIZE)
		hdp->inode = (ino64_t)RRIP_INO(px_ptr);
	else
		hdp->inode = 0;

	hdp->type = IFTOVT(hdp->mode);

	return (px_ptr + SUF_LEN(px_ptr));
}

/*
 * rrip_file_time()
 *
 * support function for rrip_file_time()
 *
 * This function decides whether to parse the times in a long time form
 * (17 bytes) or a short time form (7 bytes).  These time formats are
 * defined in the ISO 9660 specification.
 */
static void
form_time(int time_length, uchar_t *file_time, struct timeval *tvp)
{
	if (time_length == ISO_DATE_LEN)
		hs_parse_longdate(file_time, tvp);
	else
		hs_parse_dirdate(file_time, tvp);

}

/*
 * rrip_file_time()
 *
 * sig_handler() for RRIP signature RRIP_TF
 *
 * This function parses out the file time attributes of a file from the
 * "TI" SUF.  The times it parses are : st_mtime, st_atime and st_ctime.
 *
 * The function form_time is a support function only used in this
 * function.
 */
uchar_t *
rrip_file_time(sig_args_t *sig_args_p)
{
	uchar_t *tf_ptr = sig_args_p->SUF_ptr;

	if (IS_TIME_BIT_SET(RRIP_TF_FLAGS(tf_ptr), RRIP_TF_ACCESS_BIT)) {
		form_time(RRIP_TF_TIME_LENGTH(tf_ptr),
		    RRIP_tf_access(tf_ptr),
		    &sig_args_p->hdp->adate);
	}

	if (IS_TIME_BIT_SET(RRIP_TF_FLAGS(tf_ptr), RRIP_TF_MODIFY_BIT)) {
		form_time(RRIP_TF_TIME_LENGTH(tf_ptr), RRIP_tf_modify(tf_ptr),
		    &sig_args_p->hdp->mdate);
	}

	if (IS_TIME_BIT_SET(RRIP_TF_FLAGS(tf_ptr), RRIP_TF_ATTRIBUTES_BIT)) {
		form_time(RRIP_TF_TIME_LENGTH(tf_ptr),
		    RRIP_tf_attributes(tf_ptr),
		    &sig_args_p->hdp->cdate);
	}

	return (tf_ptr + SUF_LEN(tf_ptr));
}



/*
 * name_parse()
 *
 * This is a generic fuction used for sym links and filenames.  The
 * flags passed to it effect the way the name/component field is parsed.
 *
 * The return value will be the NAME_CONTINUE or NAME_CHANGE value.
 *
 */
static void
name_parse(
	int		rrip_flags,	/* component/name flag */
	uchar_t		*SUA_string,	/* string from SUA */
	size_t		SUA_string_len, /* length of SUA string */
	uchar_t		*dst,		/* string to copy to */
	int		*dst_lenp,	/* ptr to cur. str len */
	ulong_t		*name_flags_p,	/* internal name flags */
	int		dst_size)	/* limit dest string to */
						/* this value */
{
	size_t	off;
	size_t	len;

	if (IS_NAME_BIT_SET(rrip_flags, RRIP_NAME_ROOT))
		dst[0] = 0;

	if (IS_NAME_BIT_SET(rrip_flags, RRIP_NAME_CURRENT)) {
		SUA_string = (uchar_t *)".";
		SUA_string_len = 1;
	}

	if (IS_NAME_BIT_SET(rrip_flags, RRIP_NAME_PARENT)) {
		SUA_string = (uchar_t *)"..";
		SUA_string_len = 2;
	}

	/*
	 * XXX
	 * For now, ignore the following flags and return.
	 * have to figure out how to get host name in kernel.
	 * Unsure if this even should be done.
	 */
	if (IS_NAME_BIT_SET(rrip_flags, RRIP_NAME_VOLROOT) ||
	    IS_NAME_BIT_SET(rrip_flags, RRIP_NAME_HOST)) {
		cmn_err(CE_NOTE,
			"VOLUME ROOT and NAME_HOST currently unsupported\n");
		return;
	}

	/*
	 * strlcat() has two nice properties:
	 * - the size of the output buffer includes the trailing '\0'
	 * - we pass "total size" not "remaining size"
	 * It'd be the ideal candidate for this codeblock - make it:
	 *
	 *	strlcat(dst, SUA_string,
	 *	    MIN(dstsize, strlen(dst) + SUA_string_len + 1));
	 *
	 * Unfortunately, strlcat() cannot deal with input strings
	 * that are not NULL-terminated - like SUA_string can be in
	 * our case here. So we can't use it :(
	 * Now strncat() doesn't work either - because it doesn't deal
	 * with strings for which the 'potential NULL-termination' isn't
	 * accessible - strncat(dst, NULL, 0) crashes although it copies
	 * nothing in any case. If the SUA ends on a mapping boundary,
	 * then telling strncat() to copy no more than the remaining bytes
	 * in the buffer is of no avail if there's no NULL byte in them.
	 *
	 * Hence - binary copy. What are all these str* funcs for ??
	 */
	dst_size--;	/* trailing '\0' */

	off = strlen((char *)dst);
	len = MIN(dst_size - off, SUA_string_len);
	bcopy((char *)SUA_string, (char *)(dst + off), len);
	dst[off + len] = '\0';
	*dst_lenp = strlen((char *)dst);

	if (IS_NAME_BIT_SET(rrip_flags, RRIP_NAME_CONTINUE))
		SET_NAME_BIT(*(name_flags_p), RRIP_NAME_CONTINUE);
	else
		SET_NAME_BIT(*(name_flags_p), RRIP_NAME_CHANGE);

}

/*
 * rrip_name()
 *
 * sig_handler() for RRIP signature RRIP_NM
 *
 * This function handles the name of the current file.  It is case
 * sensitive to whatever was put into the field and does NO
 * translation. It will take whatever characters were in the field.
 *
 * Because the flags effect the way the name is parsed the same way
 * that the sym_link component parsing is done, we will use the same
 * function to do the actual parsing.
 */
uchar_t  *
rrip_name(sig_args_t *sig_args_p)
{
	uchar_t *nm_ptr = sig_args_p->SUF_ptr;

	if ((sig_args_p->name_p == (uchar_t *)NULL) ||
	    (sig_args_p->name_len_p == (int *)NULL))
		goto end;
	/*
	 * If we have a "." or ".." directory, we should not look for
	 * an alternate name
	 */
	if (HDE_NAME_LEN(sig_args_p->dirp) == 1) {
		if (*((char *)HDE_name(sig_args_p->dirp)) == '\0') {
			(void) strcpy((char *)sig_args_p->name_p, ".");
			*sig_args_p->name_len_p = 1;
			goto end;
		} else if (*((char *)HDE_name(sig_args_p->dirp)) == '\1') {
			(void) strcpy((char *)sig_args_p->name_p, "..");
			*sig_args_p->name_len_p = 2;
			goto end;
		}
	}

	name_parse((int)RRIP_NAME_FLAGS(nm_ptr), RRIP_name(nm_ptr),
	    (size_t)RRIP_NAME_LEN(nm_ptr), sig_args_p->name_p,
	    sig_args_p->name_len_p, &(sig_args_p->name_flags),
	    MAXNAMELEN);

end:
	return (nm_ptr + SUF_LEN(nm_ptr));
}


/*
 * rrip_sym_link()
 *
 * sig_handler() for RRIP signature RRIP_SL
 *
 * creates a symlink buffer to simulate sym_links.
 */
uchar_t *
rrip_sym_link(sig_args_t *sig_args_p)
{
	uchar_t	*sl_ptr = sig_args_p->SUF_ptr;
	uchar_t	*comp_ptr;
	char 	*tmp_sym_link;
	struct hs_direntry *hdp = sig_args_p->hdp;
	int	sym_link_len;
	char	*sym_link;

	if (hdp->type != VLNK)
		goto end;

	/*
	 * If the sym link has already been created, don't recreate it
	 */
	if (IS_NAME_BIT_SET(sig_args_p->name_flags, RRIP_SYM_LINK_COMPLETE))
		goto end;

	sym_link = kmem_alloc(MAXPATHLEN + 1, KM_SLEEP);

	/*
	 * If there is an original string put it into sym_link[], otherwise
	 * initialize sym_link[] to the empty string.
	 */
	if (hdp->sym_link != (char *)NULL) {
		sym_link_len = (int)strlen(strcpy(sym_link, hdp->sym_link));
	} else {
		sym_link[0] = '\0';
		sym_link_len = 0;
	}

	/* for all components */
	for (comp_ptr = RRIP_sl_comp(sl_ptr);
	    comp_ptr < (sl_ptr + SUF_LEN(sl_ptr));
	    comp_ptr += RRIP_COMP_LEN(comp_ptr)) {

		name_parse((int)RRIP_COMP_FLAGS(comp_ptr),
		    RRIP_comp(comp_ptr),
		    (size_t)RRIP_COMP_NAME_LEN(comp_ptr), (uchar_t *)sym_link,
		    &sym_link_len, &(sig_args_p->name_flags),
		    MAXPATHLEN);

		/*
		 * If the component is continued don't put a '/' in
		 * the pathname, but do NULL terminate it.
		 */
		if (IS_NAME_BIT_SET(RRIP_COMP_FLAGS(comp_ptr),
		    RRIP_NAME_CONTINUE)) {
			sym_link[sym_link_len] = '\0';
		} else {
			sym_link[sym_link_len] = '/';
			sym_link[sym_link_len + 1] = '\0';

			/* add 1 to sym_link_len for '/' */
			sym_link_len++;
		}

	}

	/*
	 * If we reached the end of the symbolic link, take out the
	 * last slash, but don't change ROOT "/" to an empty string.
	 */
	if (!IS_NAME_BIT_SET(RRIP_SL_FLAGS(sl_ptr), RRIP_NAME_CONTINUE) &&
	    sym_link_len > 1 && sym_link[sym_link_len - 1] == '/')
		sym_link[--sym_link_len] = '\0';

	/*
	 * if no memory has been allocated, get some, otherwise, append
	 * to the current allocation
	 */

	tmp_sym_link = kmem_alloc(SYM_LINK_LEN(sym_link), KM_SLEEP);

	(void) strcpy(tmp_sym_link, sym_link);

	if (hdp->sym_link != (char *)NULL)
		kmem_free(hdp->sym_link, (size_t)(hdp->ext_size + 1));

	hdp->sym_link = (char *)&tmp_sym_link[0];
	/* the size of a symlink is its length */
	hdp->ext_size = (uint_t)strlen(tmp_sym_link);

	if (!IS_NAME_BIT_SET(RRIP_SL_FLAGS(sl_ptr), RRIP_NAME_CONTINUE)) {
		/* reached the end of the symbolic link */
		SET_NAME_BIT(sig_args_p->name_flags, RRIP_SYM_LINK_COMPLETE);
	}

	kmem_free(sym_link, MAXPATHLEN + 1);
end:
	return (sl_ptr + SUF_LEN(sl_ptr));
}

/*
 * rrip_namecopy()
 *
 * This function will copy the rrip name to the "to" buffer, if it
 * exists.
 *
 * XXX -  We should speed this up by implementing the search in
 * parse_sua().  It works right now, so I don't want to mess with it.
 */
int
rrip_namecopy(
	char 	*from,			/* name to copy */
	char 	*to,			/* string to copy "from" to */
	char  	*tmp_name,		/* temp storage for original name */
	uchar_t	*dirp,			/* directory entry pointer */
	uint_t	last_offset,		/* last index into current dir block */
	struct 	hsfs *fsp,		/* filesystem pointer */
	struct 	hs_direntry *hdp)	/* directory entry pointer to put */
					/* all that good info in */
{
	int	size = 0;
	int	change_flag = 0;
	int	ret_val;

	if ((to == (char *)NULL) ||
	    (from == (char *)NULL) ||
	    (dirp == (uchar_t *)NULL)) {
		return (0);
	}

	/* special handling for '.' and '..' */

	if (HDE_NAME_LEN(dirp) == 1) {
		if (*((char *)HDE_name(dirp)) == '\0') {
			(void) strcpy(to, ".");
			return (1);
		} else if (*((char *)HDE_name(dirp)) == '\1') {
			(void) strcpy(to, "..");
			return (2);
		}
	}


	ret_val = parse_sua((uchar_t *)to, &size, &change_flag,
			dirp, last_offset,
			hdp, fsp, (uchar_t *)NULL, NULL);

	if (IS_NAME_BIT_SET(change_flag, RRIP_NAME_CHANGE) && !ret_val)
		return (size);

	/*
	 * Well, the name was not found
	 *
	 * make rripname an upper case "nm" (to), so that
	 * we can compare it the current HDE_DIR_NAME()
	 * without nuking the original "nm", for future case
	 * sensitive name comparing
	 */
	(void) strcpy(tmp_name, from);		/* keep original */
	size = hs_uppercase_copy(tmp_name, from, (int)strlen(from));

	return (-1);
}



/*
 * rrip_reloc_dir()
 *
 * This function is fairly bogus.  All it does is cause a failure of
 * the hs_parsedir, so that no vnode will be made for it and
 * essentially, the directory will no longer be seen.  This is part
 * of the directory hierarchy mess, where the relocated directory will
 * be hidden as far as ISO 9660 is concerned.  When we hit the child
 * link "CL" SUF, then we will read the new directory.
 */
uchar_t *
rrip_reloc_dir(sig_args_t *sig_args_p)
{
	uchar_t *re_ptr = sig_args_p->SUF_ptr;

	sig_args_p->flags = RELOC_DIR;

	return (re_ptr + SUF_LEN(re_ptr));
}



/*
 * rrip_child_link()
 *
 * This is the child link part of the directory hierarchy stuff and
 * this does not really do much anyway.  All it does is read the
 * directory entry that the child link SUF contains.  All should be
 * fine then.
 */
uchar_t *
rrip_child_link(sig_args_t *sig_args_p)
{
	uchar_t *cl_ptr = sig_args_p->SUF_ptr;

	sig_args_p->hdp->ext_lbn = RRIP_CHILD_LBN(cl_ptr);

	hs_filldirent(sig_args_p->fsp->hsfs_rootvp, sig_args_p->hdp);

	sig_args_p->flags = 0;

	return (cl_ptr + SUF_LEN(cl_ptr));
}


/*
 * rrip_parent_link()
 *
 * This is the parent link part of the directory hierarchy stuff and
 * this does not really do much anyway.  All it does is read the
 * directory entry that the parent link SUF contains.  All should be
 * fine then.
 */
uchar_t *
rrip_parent_link(sig_args_t *sig_args_p)
{
	uchar_t *pl_ptr = sig_args_p->SUF_ptr;

	sig_args_p->hdp->ext_lbn = RRIP_PARENT_LBN(pl_ptr);

	hs_filldirent(sig_args_p->fsp->hsfs_rootvp, sig_args_p->hdp);

	sig_args_p->flags = 0;

	return (pl_ptr + SUF_LEN(pl_ptr));
}


/*
 * rrip_rock_ridge()
 *
 * This function is supposed to aid in speed of the filesystem.
 *
 * XXX - It is only here as a place holder so far.
 */
uchar_t *
rrip_rock_ridge(sig_args_t *sig_args_p)
{
	uchar_t *rr_ptr = sig_args_p->SUF_ptr;

	return (rr_ptr + SUF_LEN(rr_ptr));
}
