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

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <sys/pathname.h>
#include <sys/sdt.h>

static char *smb_pathname_catia_v5tov4(smb_request_t *, char *, char *, int);
static char *smb_pathname_catia_v4tov5(smb_request_t *, char *, char *, int);
static int smb_pathname_lookup(pathname_t *, pathname_t *, int,
    vnode_t **, vnode_t *, vnode_t *, cred_t *);

uint32_t
smb_is_executable(char *path)
{
	char	extension[5];
	int	len = strlen(path);

	if ((len >= 4) && (path[len - 4] == '.')) {
		(void) strcpy(extension, &path[len - 3]);
		(void) utf8_strupr(extension);

		if (strcmp(extension, "EXE") == 0)
			return (NODE_FLAGS_EXECUTABLE);

		if (strcmp(extension, "COM") == 0)
			return (NODE_FLAGS_EXECUTABLE);

		if (strcmp(extension, "DLL") == 0)
			return (NODE_FLAGS_EXECUTABLE);

		if (strcmp(extension, "SYM") == 0)
			return (NODE_FLAGS_EXECUTABLE);
	}

	return (0);
}

/*
 * smb_pathname_reduce
 *
 * smb_pathname_reduce() takes a path and returns the smb_node for the
 * second-to-last component of the path.  It also returns the name of the last
 * component.  Pointers for both of these fields must be supplied by the caller.
 *
 * Upon success, 0 is returned.
 *
 * Upon error, *dir_node will be set to 0.
 *
 * *sr (in)
 * ---
 * smb_request structure pointer
 *
 * *cred (in)
 * -----
 * credential
 *
 * *path (in)
 * -----
 * pathname to be looked up
 *
 * *share_root_node (in)
 * ----------------
 * File operations which are share-relative should pass sr->tid_tree->t_snode.
 * If the call is not for a share-relative operation, this parameter must be 0
 * (e.g. the call from smbsr_setup_share()).  (Such callers will have path
 * operations done using root_smb_node.)  This parameter is used to determine
 * whether mount points can be crossed.
 *
 * share_root_node should have at least one reference on it.  This reference
 * will stay intact throughout this routine.
 *
 * *cur_node (in)
 * ---------
 * The smb_node for the current directory (for relative paths).
 * cur_node should have at least one reference on it.
 * This reference will stay intact throughout this routine.
 *
 * **dir_node (out)
 * ----------
 * Directory for the penultimate component of the original path.
 * (Note that this is not the same as the parent directory of the ultimate
 * target in the case of a link.)
 *
 * The directory smb_node is returned held.  The caller will need to release
 * the hold or otherwise make sure it will get released (e.g. in a destroy
 * routine if made part of a global structure).
 *
 * last_component (out)
 * --------------
 * The last component of the path.  (This may be different from the name of any
 * link target to which the last component may resolve.)
 *
 *
 * ____________________________
 *
 * The CIFS server lookup path needs to have logic equivalent to that of
 * smb_fsop_lookup(), smb_vop_lookup() and other smb_vop_*() routines in the
 * following areas:
 *
 *	- non-traversal of child mounts		(handled by smb_pathname_reduce)
 *	- unmangling 				(handled in smb_pathname)
 *	- "chroot" behavior of share root 	(handled by lookuppnvp)
 *
 * In addition, it needs to replace backslashes with forward slashes.  It also
 * ensures that link processing is done correctly, and that directory
 * information requested by the caller is correctly returned (i.e. for paths
 * with a link in the last component, the directory information of the
 * link and not the target needs to be returned).
 */

int
smb_pathname_reduce(
    smb_request_t	*sr,
    cred_t		*cred,
    const char		*path,
    smb_node_t		*share_root_node,
    smb_node_t		*cur_node,
    smb_node_t		**dir_node,
    char		*last_component)
{
	smb_node_t	*root_node;
	pathname_t	ppn;
	char		*usepath;
	int		lookup_flags = FOLLOW;
	int 		trailing_slash = 0;
	int		err = 0;
	int		len;
	smb_node_t	*vss_cur_node;
	smb_node_t	*vss_root_node;
	smb_node_t	*local_cur_node;
	smb_node_t	*local_root_node;

	ASSERT(dir_node);
	ASSERT(last_component);

	*dir_node = NULL;
	*last_component = '\0';
	vss_cur_node = NULL;
	vss_root_node = NULL;

	if (sr && sr->tid_tree) {
		if (!STYPE_ISDSK(sr->tid_tree->t_res_type))
			return (EACCES);
	}

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		lookup_flags |= FIGNORECASE;

	if (path == NULL)
		return (EINVAL);

	if (*path == '\0')
		return (ENOENT);

	usepath = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if ((len = strlcpy(usepath, path, MAXPATHLEN)) >= MAXPATHLEN) {
		kmem_free(usepath, MAXPATHLEN);
		return (ENAMETOOLONG);
	}

	(void) strsubst(usepath, '\\', '/');

	if (share_root_node)
		root_node = share_root_node;
	else
		root_node = sr->sr_server->si_root_smb_node;

	if (cur_node == NULL)
		cur_node = root_node;

	local_cur_node = cur_node;
	local_root_node = root_node;

	if (sr && (sr->smb_flg2 & SMB_FLAGS2_REPARSE_PATH)) {
		err = smb_vss_lookup_nodes(sr, root_node, cur_node,
		    usepath, &vss_cur_node, &vss_root_node);

		if (err != 0) {
			kmem_free(usepath, MAXPATHLEN);
			return (err);
		}

		len = strlen(usepath);
		local_cur_node = vss_cur_node;
		local_root_node = vss_root_node;
	}

	if (usepath[len - 1] == '/')
		trailing_slash = 1;

	(void) strcanon(usepath, "/");

	(void) pn_alloc(&ppn);

	if ((err = pn_set(&ppn, usepath)) != 0) {
		(void) pn_free(&ppn);
		kmem_free(usepath, MAXPATHLEN);
		if (vss_cur_node != NULL)
			(void) smb_node_release(vss_cur_node);
		if (vss_root_node != NULL)
			(void) smb_node_release(vss_root_node);
		return (err);
	}

	/*
	 * If a path does not have a trailing slash, strip off the
	 * last component.  (We only need to return an smb_node for
	 * the second to last component; a name is returned for the
	 * last component.)
	 */

	if (trailing_slash) {
		(void) strlcpy(last_component, ".", MAXNAMELEN);
	} else {
		(void) pn_setlast(&ppn);
		(void) strlcpy(last_component, ppn.pn_path, MAXNAMELEN);
		ppn.pn_path[0] = '\0';
	}

	if ((strcmp(ppn.pn_buf, "/") == 0) || (ppn.pn_buf[0] == '\0')) {
		smb_node_ref(local_cur_node);
		*dir_node = local_cur_node;
	} else {
		err = smb_pathname(sr, ppn.pn_buf, lookup_flags,
		    local_root_node, local_cur_node, NULL, dir_node, cred);
	}

	(void) pn_free(&ppn);
	kmem_free(usepath, MAXPATHLEN);

	/*
	 * Prevent access to anything outside of the share root, except
	 * when mapping a share because that may require traversal from
	 * / to a mounted file system.  share_root_node is NULL when
	 * mapping a share.
	 *
	 * Note that we disregard whether the traversal of the path went
	 * outside of the file system and then came back (say via a link).
	 */

	if ((err == 0) && share_root_node) {
		if (share_root_node->vp->v_vfsp != (*dir_node)->vp->v_vfsp)
			err = EACCES;
	}

	if (err) {
		if (*dir_node) {
			(void) smb_node_release(*dir_node);
			*dir_node = NULL;
		}
		*last_component = 0;
	}

	if (vss_cur_node != NULL)
		(void) smb_node_release(vss_cur_node);
	if (vss_root_node != NULL)
		(void) smb_node_release(vss_root_node);

	return (err);
}

/*
 * smb_pathname()
 * wrapper to lookuppnvp().  Handles name unmangling.
 *
 * *dir_node is the true directory of the target *node.
 *
 * If any component but the last in the path is not found, ENOTDIR instead of
 * ENOENT will be returned.
 *
 * Path components are processed one at a time so that smb_nodes can be
 * created for each component.  This allows the n_dnode field in the
 * smb_node to be properly populated.
 *
 * Because of the above, links are also processed in this routine
 * (i.e., we do not pass the FOLLOW flag to lookuppnvp()).  This
 * will allow smb_nodes to be created for each component of a link.
 *
 * Mangle checking is per component. If a name is mangled, when the
 * unmangled name is passed to smb_pathname_lookup() do not pass
 * FIGNORECASE, since the unmangled name is the real on-disk name.
 * Otherwise pass FIGNORECASE if it's set in flags. This will cause the
 * file system to return "first match" in the event of a case collision.
 *
 * If CATIA character translation is enabled it is applied to each
 * component before passing the component to smb_pathname_lookup().
 * After smb_pathname_lookup() the reverse translation is applied.
 */

int
smb_pathname(smb_request_t *sr, char *path, int flags,
    smb_node_t *root_node, smb_node_t *cur_node, smb_node_t **dir_node,
    smb_node_t **ret_node, cred_t *cred)
{
	char		*component, *real_name, *namep;
	pathname_t	pn, rpn, upn, link_pn;
	smb_node_t	*dnode, *fnode;
	vnode_t		*rootvp, *vp;
	size_t		pathleft;
	int		err = 0;
	int		nlink = 0;
	int		local_flags;
	uint32_t	abe_flag = 0;
	char		namebuf[MAXNAMELEN];

	if (path == NULL)
		return (EINVAL);

	ASSERT(root_node);
	ASSERT(cur_node);
	ASSERT(ret_node);

	*ret_node = NULL;

	if (dir_node)
		*dir_node = NULL;

	(void) pn_alloc(&upn);

	if ((err = pn_set(&upn, path)) != 0) {
		(void) pn_free(&upn);
		return (err);
	}

	if (SMB_TREE_SUPPORTS_ABE(sr))
		abe_flag = SMB_ABE;

	(void) pn_alloc(&pn);
	(void) pn_alloc(&rpn);

	component = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	real_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	fnode = NULL;
	dnode = cur_node;
	smb_node_ref(dnode);
	rootvp = root_node->vp;

	while ((pathleft = pn_pathleft(&upn)) != 0) {
		if (fnode) {
			smb_node_release(dnode);
			dnode = fnode;
			fnode = NULL;
		}

		if ((err = pn_getcomponent(&upn, component)) != 0)
			break;

		if ((namep = smb_pathname_catia_v5tov4(sr, component,
		    namebuf, sizeof (namebuf))) == NULL) {
			err = EILSEQ;
			break;
		}

		if ((err = pn_set(&pn, namep)) != 0)
			break;

		local_flags = flags & FIGNORECASE;
		err = smb_pathname_lookup(&pn, &rpn, local_flags,
		    &vp, rootvp, dnode->vp, cred);

		if (err) {
			if (smb_maybe_mangled_name(component) == 0)
				break;

			if ((err = smb_unmangle_name(dnode, component,
			    real_name, MAXNAMELEN, abe_flag)) != 0)
				break;

			if ((namep = smb_pathname_catia_v5tov4(sr, real_name,
			    namebuf, sizeof (namebuf))) == NULL) {
				err = EILSEQ;
				break;
			}

			if ((err = pn_set(&pn, namep)) != 0)
				break;

			local_flags = 0;
			err = smb_pathname_lookup(&pn, &rpn, local_flags,
			    &vp, rootvp, dnode->vp, cred);
			if (err)
				break;
		}

		if ((vp->v_type == VLNK) &&
		    ((flags & FOLLOW) || pn_pathleft(&upn))) {

			if (++nlink > MAXSYMLINKS) {
				err = ELOOP;
				VN_RELE(vp);
				break;
			}

			(void) pn_alloc(&link_pn);
			err = pn_getsymlink(vp, &link_pn, cred);
			VN_RELE(vp);

			if (err == 0) {
				if (pn_pathleft(&link_pn) == 0)
					(void) pn_set(&link_pn, ".");
				err = pn_insert(&upn, &link_pn,
				    strlen(component));
			}
			pn_free(&link_pn);

			if (err)
				break;

			if (upn.pn_pathlen == 0) {
				err = ENOENT;
				break;
			}

			if (upn.pn_path[0] == '/') {
				fnode = root_node;
				smb_node_ref(fnode);
			}

			if (pn_fixslash(&upn))
				flags |= FOLLOW;

		} else {
			if (flags & FIGNORECASE) {
				if (strcmp(rpn.pn_path, "/") != 0)
					pn_setlast(&rpn);
				namep = rpn.pn_path;
			} else {
				namep = pn.pn_path;
			}

			namep = smb_pathname_catia_v4tov5(sr, namep,
			    namebuf, sizeof (namebuf));

			fnode = smb_node_lookup(sr, NULL, cred, vp, namep,
			    dnode, NULL);
			VN_RELE(vp);

			if (fnode == NULL) {
				err = ENOMEM;
				break;
			}
		}

		while (upn.pn_path[0] == '/') {
			upn.pn_path++;
			upn.pn_pathlen--;
		}

	}

	if ((pathleft) && (err == ENOENT))
		err = ENOTDIR;

	if (err) {
		if (fnode)
			smb_node_release(fnode);
		if (dnode)
			smb_node_release(dnode);
	} else {
		*ret_node = fnode;

		if (dir_node)
			*dir_node = dnode;
		else
			smb_node_release(dnode);
	}

	kmem_free(component, MAXNAMELEN);
	kmem_free(real_name, MAXNAMELEN);
	(void) pn_free(&pn);
	(void) pn_free(&rpn);
	(void) pn_free(&upn);

	return (err);
}

/*
 * Holds on dvp and rootvp (if not rootdir) are required by lookuppnvp()
 * and will be released within lookuppnvp().
 */
static int
smb_pathname_lookup(pathname_t *pn, pathname_t *rpn, int flags,
    vnode_t **vp, vnode_t *rootvp, vnode_t *dvp, cred_t *cred)
{
	int err;

	*vp = NULL;
	VN_HOLD(dvp);
	if (rootvp != rootdir)
		VN_HOLD(rootvp);

	err = lookuppnvp(pn, rpn, flags, NULL, vp, rootvp, dvp, cred);
	return (err);
}

/*
 * CATIA Translation of a pathname component prior to passing it to lookuppnvp
 *
 * If the translated component name contains a '/' NULL is returned.
 * The caller should treat this as error EILSEQ. It is not valid to
 * have a directory name with a '/'.
 */
static char *
smb_pathname_catia_v5tov4(smb_request_t *sr, char *name,
    char *namebuf, int buflen)
{
	char *namep;

	if (SMB_TREE_SUPPORTS_CATIA(sr)) {
		namep = smb_vop_catia_v5tov4(name, namebuf, buflen);
		if (strchr(namep, '/') != NULL)
			return (NULL);
		return (namep);
	}

	return (name);
}

/*
 * CATIA translation of a pathname component after returning from lookuppnvp
 */
static char *
smb_pathname_catia_v4tov5(smb_request_t *sr, char *name,
    char *namebuf, int buflen)
{
	if (SMB_TREE_SUPPORTS_CATIA(sr)) {
		smb_vop_catia_v4tov5(name, namebuf, buflen);
		return (namebuf);
	}

	return (name);
}

/*
 * sr - needed to check for case sense
 * path - non mangled path needed to be looked up from the startvp
 * startvp - the vnode to start the lookup from
 * rootvp - the vnode of the root of the filesystem
 * returns the vnode found when starting at startvp and using the path
 *
 * Finds a vnode starting at startvp and parsing the non mangled path
 */

vnode_t *
smb_lookuppathvptovp(smb_request_t *sr, char *path, vnode_t *startvp,
    vnode_t *rootvp)
{
	pathname_t pn;
	vnode_t *vp = NULL;
	int lookup_flags = FOLLOW;

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		lookup_flags |= FIGNORECASE;

	(void) pn_alloc(&pn);

	if (pn_set(&pn, path) == 0) {
		VN_HOLD(startvp);
		if (rootvp != rootdir)
			VN_HOLD(rootvp);

		/* lookuppnvp should release the holds */
		if (lookuppnvp(&pn, NULL, lookup_flags, NULL, &vp,
		    rootvp, startvp, kcred) != 0) {
			pn_free(&pn);
			return (NULL);
		}
	}

	pn_free(&pn);
	return (vp);
}
