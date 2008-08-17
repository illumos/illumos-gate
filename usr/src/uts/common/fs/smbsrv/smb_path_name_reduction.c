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

#pragma ident	"@(#)smb_path_name_reduction.c	1.6	08/08/07 SMI"

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <sys/pathname.h>
#include <sys/sdt.h>

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
 * smbd_fs_query
 *
 * Upon success, the caller will need to call smb_node_release() on
 * fqi.last_snode (if it isn't already set to NULL by this routine) and
 * and fqi.dir_snode.  These pointers will not be used after the caller
 * is done with them and should be released immediately.  (The position
 * of smb_fqi in a union in the smb_request structure makes it difficult
 * to free these pointers at smb_request deallocation time.)
 *
 * If smbd_fs_query() returns error, no smb_nodes will need to be released
 * by callers as a result of references taken in this routine, and
 * fqi.last_snode and fqi.dir_snode will be set to NULL.
 */

int
smbd_fs_query(struct smb_request *sr, struct smb_fqi *fqi, int fqm)
{
	int rc;

	fqi->last_comp_was_found = 0;

	rc = smb_pathname_reduce(sr, sr->user_cr, fqi->path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &fqi->dir_snode,
	    fqi->last_comp);

	if (rc)
		return (rc);

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, fqi->dir_snode, fqi->last_comp,
	    &fqi->last_snode, &fqi->last_attr, 0, 0);

	if (rc == 0) {
		fqi->last_comp_was_found = 1;
		(void) strcpy(fqi->last_comp_od,
		    fqi->last_snode->od_name);

		if (fqm == FQM_PATH_MUST_NOT_EXIST) {
			smb_node_release(fqi->dir_snode);
			smb_node_release(fqi->last_snode);
			SMB_NULL_FQI_NODES(*fqi);
			return (EEXIST);
		}

		return (0);
	}

	if (fqm == FQM_PATH_MUST_EXIST) {
		smb_node_release(fqi->dir_snode);
		SMB_NULL_FQI_NODES(*fqi);
		return (rc);
	}

	if (rc == ENOENT) {
		fqi->last_snode = NULL;
		return (0);
	}

	smb_node_release(fqi->dir_snode);
	SMB_NULL_FQI_NODES(*fqi);

	return (rc);
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
	struct pathname	ppn;
	char		*usepath;
	int		lookup_flags = FOLLOW;
	int 		trailing_slash = 0;
	int		err = 0;
	int		len;

	ASSERT(dir_node);
	ASSERT(last_component);

	*dir_node = NULL;
	*last_component = '\0';

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

	if (usepath[len - 1] == '/')
		trailing_slash = 1;

	(void) strcanon(usepath, "/");

	if (share_root_node)
		root_node = share_root_node;
	else
		root_node = sr->sr_server->si_root_smb_node;

	if (cur_node == NULL)
		cur_node = root_node;

	(void) pn_alloc(&ppn);

	if ((err = pn_set(&ppn, usepath)) != 0) {
		(void) pn_free(&ppn);
		kmem_free(usepath, MAXPATHLEN);
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

	if (strcmp(ppn.pn_buf, "/") == 0) {
		smb_node_ref(root_node);
		*dir_node = root_node;
	} else if (ppn.pn_buf[0] == '\0') {
		smb_node_ref(cur_node);
		*dir_node = cur_node;
	} else {
		err = smb_pathname(sr, ppn.pn_buf, lookup_flags, root_node,
		    cur_node, NULL, dir_node, cred);
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

	return (err);
}

/*
 * smb_pathname() - wrapper to lookuppnvp().  Handles name unmangling.
 *
 * *dir_node is the true directory of the target *node.
 *
 * If any component but the last in the path is not found, ENOTDIR instead of
 * ENOENT will be returned.
 *
 * Path components are processed one at a time so that smb_nodes can be
 * created for each component.  This allows the dir_snode field in the
 * smb_node to be properly populated.
 *
 * Mangle checking is also done on each component.
 */

int
smb_pathname(
    smb_request_t	*sr,
    char		*path,
    int			flags,
    smb_node_t		*root_node,
    smb_node_t		*cur_node,
    smb_node_t		**dir_node,
    smb_node_t		**ret_node,
    cred_t		*cred)
{
	char		*component = NULL;
	char		*real_name = NULL;
	char		*namep;
	struct pathname	pn;
	struct pathname	rpn;
	struct pathname	upn;
	struct pathname	link_pn;
	smb_node_t	*dnode = NULL;
	smb_node_t	*fnode = NULL;
	vnode_t		*rootvp;
	vnode_t		*dvp;
	vnode_t		*vp = NULL;
	smb_attr_t	attr;
	size_t		pathleft;
	int		err = 0;
	int		nlink = 0;
	int		local_flags;

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

	(void) pn_alloc(&pn);
	(void) pn_alloc(&rpn);

	component = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	real_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	dnode = cur_node;
	smb_node_ref(dnode);

	rootvp = (vnode_t *)root_node->vp;

	/*
	 * Path components are processed one at a time so that smb_nodes
	 * can be created for each component.  This allows the dir_snode
	 * field in the smb_node to be properly populated.
	 *
	 * Because of the above, links are also processed in this routine
	 * (i.e., we do not pass the FOLLOW flag to lookuppnvp()).  This
	 * will allow smb_nodes to be created for each component of a link.
	 *
	 * Mangle checking is per component.
	 */

	while ((pathleft = pn_pathleft(&upn)) != 0) {
		if (fnode) {
			smb_node_release(dnode);
			dnode = fnode;
			fnode = NULL;
		}

		if ((err = pn_getcomponent(&upn, component)) != 0)
			break;

		if (smb_maybe_mangled_name(component)) {
			if ((err = smb_unmangle_name(sr, cred, dnode,
			    component, real_name, MAXNAMELEN, 0, 0,
			    1)) != 0)
				break;
			/*
			 * Do not pass FIGNORECASE to lookuppnvp().
			 * This is because we would like to do a lookup
			 * on the real name just obtained (which
			 * corresponds to the mangled name).
			 */

			namep = real_name;
			local_flags = 0;
		} else {
			/*
			 * Pass FIGNORECASE to lookuppnvp().
			 * This will cause the file system to
			 * return "first match" in the event of
			 * a case collision.
			 */
			namep = component;
			local_flags = flags & FIGNORECASE;
		}

		if ((err = pn_set(&pn, namep)) != 0)
			break;

		/*
		 * Holds on dvp and rootvp (if not rootdir) are
		 * required by lookuppnvp() and will be released within
		 * that routine.
		 */
		vp = NULL;
		dvp = dnode->vp;

		VN_HOLD(dvp);
		if (rootvp != rootdir)
			VN_HOLD(rootvp);

		err = lookuppnvp(&pn, &rpn, local_flags, NULL, &vp, rootvp, dvp,
		    cred);

		if (err)
			break;

		if ((vp->v_type == VLNK) &&
		    ((flags & FOLLOW) || pn_pathleft(&upn))) {

			if (++nlink > MAXSYMLINKS) {
				err = ELOOP;
				break;
			}

			(void) pn_alloc(&link_pn);
			err = pn_getsymlink(vp, &link_pn, cred);

			if (err) {
				(void) pn_free(&link_pn);
				break;
			}

			if (pn_pathleft(&link_pn) == 0)
				(void) pn_set(&link_pn, ".");
			err = pn_insert(&upn, &link_pn, strlen(namep));
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
			} else
				namep = pn.pn_path;

			fnode = smb_node_lookup(sr, NULL, cred, vp, namep,
			    dnode, NULL, &attr);

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

	/*
	 * Since no parent vp was passed to lookuppnvp(), all
	 * ENOENT errors are returned as ENOENT
	 */

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
