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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <sys/pathname.h>
#include <sys/sdt.h>

static char *smb_pathname_catia_v5tov4(smb_request_t *, char *, char *, int);
static char *smb_pathname_catia_v4tov5(smb_request_t *, char *, char *, int);
static int smb_pathname_lookup(pathname_t *, pathname_t *, int,
    vnode_t **, vnode_t *, vnode_t *, smb_attr_t *attr, cred_t *);
static char *smb_pathname_strdup(smb_request_t *, const char *);
static char *smb_pathname_strcat(smb_request_t *, char *, const char *);
static void smb_pathname_preprocess(smb_request_t *, smb_pathname_t *);
static void smb_pathname_preprocess_quota(smb_request_t *, smb_pathname_t *);
static int smb_pathname_dfs_preprocess(smb_request_t *, char *, size_t);
static void smb_pathname_preprocess_adminshare(smb_request_t *,
    smb_pathname_t *);


uint32_t
smb_is_executable(char *path)
{
	char	extension[5];
	int	len = strlen(path);

	if ((len >= 4) && (path[len - 4] == '.')) {
		(void) strcpy(extension, &path[len - 3]);
		(void) smb_strupr(extension);

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
 *	- traversal of child mounts (handled by smb_pathname_reduce)
 *	- unmangling                (handled in smb_pathname)
 *	- "chroot" behavior of share root (handled by lookuppnvp)
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
		if (STYPE_ISIPC(sr->tid_tree->t_res_type))
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

	if (SMB_TREE_IS_DFSROOT(sr) && (sr->smb_flg2 & SMB_FLAGS2_DFS)) {
		err = smb_pathname_dfs_preprocess(sr, usepath, MAXPATHLEN);
		if (err != 0) {
			kmem_free(usepath, MAXPATHLEN);
			return (err);
		}
		len = strlen(usepath);
	}

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
	 * Prevent traversal to another file system if mount point
	 * traversal is disabled.
	 *
	 * Note that we disregard whether the traversal of the path went
	 * outside of the file system and then came back (say via a link).
	 * This means that only symlinks that are expressed relatively to
	 * the share root work.
	 *
	 * share_root_node is NULL when mapping a share, so we disregard
	 * that case.
	 */

	if ((err == 0) && share_root_node) {
		if (share_root_node->vp->v_vfsp != (*dir_node)->vp->v_vfsp) {
			err = EACCES;
			if ((sr) && (sr)->tid_tree &&
			    smb_tree_has_feature((sr)->tid_tree,
			    SMB_TREE_TRAVERSE_MOUNTS))
				err = 0;
		}
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
	smb_attr_t	attr;
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
		    &vp, rootvp, dnode->vp, &attr, cred);

		if (err) {
			if (!SMB_TREE_SUPPORTS_SHORTNAMES(sr) ||
			    !smb_maybe_mangled(component))
				break;

			if ((err = smb_unmangle(dnode, component,
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
			    &vp, rootvp, dnode->vp, &attr, cred);
			if (err)
				break;
		}

		/*
		 * This check MUST be done before symlink check
		 * since a reparse point is of type VLNK but should
		 * not be handled like a regular symlink.
		 */
		if (attr.sa_dosattr & FILE_ATTRIBUTE_REPARSE_POINT) {
			err = EREMOTE;
			VN_RELE(vp);
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
    vnode_t **vp, vnode_t *rootvp, vnode_t *dvp, smb_attr_t *attr, cred_t *cred)
{
	int err;

	*vp = NULL;
	VN_HOLD(dvp);
	if (rootvp != rootdir)
		VN_HOLD(rootvp);

	err = lookuppnvp(pn, rpn, flags, NULL, vp, rootvp, dvp, cred);
	if ((err == 0) && (attr != NULL))
		(void) smb_vop_getattr(*vp, NULL, attr, 0, zone_kcred());

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
		    rootvp, startvp, zone_kcred()) != 0) {
			pn_free(&pn);
			return (NULL);
		}
	}

	pn_free(&pn);
	return (vp);
}

/*
 * smb_pathname_init
 * Parse path: pname\\fname:sname:stype
 *
 * Elements of the smb_pathname_t structure are allocated using request
 * specific storage and will be free'd when the sr is destroyed.
 *
 * Populate pn structure elements with the individual elements
 * of pn->pn_path. pn->pn_sname will contain the whole stream name
 * including the stream type and preceding colon: :sname:%DATA
 * pn_stype will point to the stream type within pn_sname.
 *
 * If the pname element is missing pn_pname will be set to NULL.
 * If any other element is missing the pointer in pn will be NULL.
 */
void
smb_pathname_init(smb_request_t *sr, smb_pathname_t *pn, char *path)
{
	char *pname, *fname, *sname;
	int len;

	bzero(pn, sizeof (smb_pathname_t));
	pn->pn_path = smb_pathname_strdup(sr, path);

	smb_pathname_preprocess(sr, pn);

	/* parse pn->pn_path into its constituent parts */
	pname = pn->pn_path;
	fname = strrchr(pn->pn_path, '\\');

	if (fname) {
		if (fname == pname) {
			pn->pn_pname = NULL;
		} else {
			*fname = '\0';
			pn->pn_pname =
			    smb_pathname_strdup(sr, pname);
			*fname = '\\';
		}
		++fname;
	} else {
		fname = pname;
		pn->pn_pname = NULL;
	}

	if (fname[0] == '\0') {
		pn->pn_fname = NULL;
		return;
	}

	if (!smb_is_stream_name(fname)) {
		pn->pn_fname = smb_pathname_strdup(sr, fname);
		return;
	}

	/*
	 * find sname and stype in fname.
	 * sname can't be NULL smb_is_stream_name checks this
	 */
	sname = strchr(fname, ':');
	if (sname == fname)
		fname = NULL;
	else {
		*sname = '\0';
		pn->pn_fname =
		    smb_pathname_strdup(sr, fname);
		*sname = ':';
	}

	pn->pn_sname = smb_pathname_strdup(sr, sname);
	pn->pn_stype = strchr(pn->pn_sname + 1, ':');
	if (pn->pn_stype) {
		(void) smb_strupr(pn->pn_stype);
	} else {
		len = strlen(pn->pn_sname);
		pn->pn_sname = smb_pathname_strcat(sr, pn->pn_sname, ":$DATA");
		pn->pn_stype = pn->pn_sname + len;
	}
	++pn->pn_stype;
}

/*
 * smb_pathname_preprocess
 *
 * Perform common pre-processing of pn->pn_path:
 * - if the pn_path is blank, set it to '\\'
 * - perform unicode wildcard converstion.
 * - convert any '/' to '\\'
 * - eliminate duplicate slashes
 * - remove trailing slashes
 * - quota directory specific pre-processing
 */
static void
smb_pathname_preprocess(smb_request_t *sr, smb_pathname_t *pn)
{
	char *p;

	/* treat empty path as "\\" */
	if (strlen(pn->pn_path) == 0) {
		pn->pn_path = smb_pathname_strdup(sr, "\\");
		return;
	}

	if (sr->session->dialect < NT_LM_0_12)
		smb_convert_wildcards(pn->pn_path);

	/* treat '/' as '\\' */
	(void) strsubst(pn->pn_path, '/', '\\');

	(void) strcanon(pn->pn_path, "\\");

	/* remove trailing '\\' */
	p = pn->pn_path + strlen(pn->pn_path) - 1;
	if ((p != pn->pn_path) && (*p == '\\'))
		*p = '\0';

	smb_pathname_preprocess_quota(sr, pn);
	smb_pathname_preprocess_adminshare(sr, pn);
}

/*
 * smb_pathname_preprocess_quota
 *
 * There is a special file required by windows so that the quota
 * tab will be displayed by windows clients. This is created in
 * a special directory, $EXTEND, at the root of the shared file
 * system. To hide this directory prepend a '.' (dot).
 */
static void
smb_pathname_preprocess_quota(smb_request_t *sr, smb_pathname_t *pn)
{
	char *name = "$EXTEND";
	char *new_name = ".$EXTEND";
	char *p, *slash;
	int len;

	if (!smb_node_is_vfsroot(sr->tid_tree->t_snode))
		return;

	p = pn->pn_path;

	/* ignore any initial "\\" */
	p += strspn(p, "\\");
	if (smb_strcasecmp(p, name, strlen(name)) != 0)
		return;

	p += strlen(name);
	if ((*p != ':') && (*p != '\\') && (*p != '\0'))
		return;

	slash = (pn->pn_path[0] == '\\') ? "\\" : "";
	len = strlen(pn->pn_path) + 2;
	pn->pn_path = smb_srm_alloc(sr, len);
	(void) snprintf(pn->pn_path, len, "%s%s%s", slash, new_name, p);
	(void) smb_strupr(pn->pn_path);
}

/*
 * smb_pathname_preprocess_adminshare
 *
 * Convert any path with share name "C$" or "c$" (Admin share) in to lower case.
 */
static void
smb_pathname_preprocess_adminshare(smb_request_t *sr, smb_pathname_t *pn)
{
	if (strcasecmp(sr->tid_tree->t_sharename, "c$") == 0)
		(void) smb_strlwr(pn->pn_path);
}

/*
 * smb_pathname_strdup
 *
 * Duplicate NULL terminated string s.
 *
 * The new string is allocated using request specific storage and will
 * be free'd when the sr is destroyed.
 */
static char *
smb_pathname_strdup(smb_request_t *sr, const char *s)
{
	char *s2;
	size_t n;

	n = strlen(s) + 1;
	s2 = smb_srm_zalloc(sr, n);
	(void) strlcpy(s2, s, n);
	return (s2);
}

/*
 * smb_pathname_strcat
 *
 * Reallocate NULL terminated string s1 to accommodate
 * concatenating  NULL terminated string s2.
 * Append s2 and return resulting NULL terminated string.
 *
 * The string buffer is reallocated using request specific
 * storage and will be free'd when the sr is destroyed.
 */
static char *
smb_pathname_strcat(smb_request_t *sr, char *s1, const char *s2)
{
	size_t n;

	n = strlen(s1) + strlen(s2) + 1;
	s1 = smb_srm_rezalloc(sr, s1, n);
	(void) strlcat(s1, s2, n);
	return (s1);
}

/*
 * smb_pathname_validate
 *
 * Perform basic validation of pn:
 * - If first component of pn->path is ".." -> PATH_SYNTAX_BAD
 * - If there are wildcards in pn->pn_pname -> OBJECT_NAME_INVALID
 * - If fname is "." -> INVALID_OBJECT_NAME
 *
 * On unix .. at the root of a file system links to the root. Thus
 * an attempt to lookup "/../../.." will be the same as looking up "/"
 * CIFs clients expect the above to result in
 * NT_STATUS_OBJECT_PATH_SYNTAX_BAD. It is currently not possible
 * (and questionable if it's desirable) to deal with all cases
 * but paths beginning with \\.. are handled.
 *
 * Returns: B_TRUE if pn is valid,
 *          otherwise returns B_FALSE and sets error status in sr.
 */
boolean_t
smb_pathname_validate(smb_request_t *sr, smb_pathname_t *pn)
{
	char *path = pn->pn_path;

	/* ignore any initial "\\" */
	path += strspn(path, "\\");

	/* If first component of path is ".." -> PATH_SYNTAX_BAD */
	if ((strcmp(path, "..") == 0) || (strncmp(path, "..\\", 3) == 0)) {
		smbsr_error(sr, NT_STATUS_OBJECT_PATH_SYNTAX_BAD,
		    ERRDOS, ERROR_BAD_PATHNAME);
		return (B_FALSE);
	}

	/* If there are wildcards in pn->pn_pname -> OBJECT_NAME_INVALID */
	if (pn->pn_pname && smb_contains_wildcards(pn->pn_pname)) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (B_FALSE);
	}

	/* If fname is "." -> INVALID_OBJECT_NAME */
	if (pn->pn_fname && (strcmp(pn->pn_fname, ".") == 0)) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_PATH_NOT_FOUND);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * smb_validate_dirname
 *
 * smb_pathname_validate() should have already been performed on pn.
 *
 * Very basic directory name validation:  checks for colons in a path.
 * Need to skip the drive prefix since it contains a colon.
 *
 * Returns: B_TRUE if the name is valid,
 *          otherwise returns B_FALSE and sets error status in sr.
 */
boolean_t
smb_validate_dirname(smb_request_t *sr, smb_pathname_t *pn)
{
	char *name;
	char *path = pn->pn_path;

	if ((name = path) != 0) {
		name += strspn(name, "\\");

		if (strchr(name, ':') != 0) {
			smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY,
			    ERRDOS, ERROR_INVALID_NAME);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * smb_validate_object_name
 *
 * smb_pathname_validate() should have already been pertformed on pn.
 *
 * Very basic file name validation.
 * For filenames, we check for names of the form "AAAn:". Names that
 * contain three characters, a single digit and a colon (:) are reserved
 * as DOS device names, i.e. "COM1:".
 * Stream name validation is handed off to smb_validate_stream_name
 *
 * Returns: B_TRUE if pn->pn_fname is valid,
 *          otherwise returns B_FALSE and sets error status in sr.
 */
boolean_t
smb_validate_object_name(smb_request_t *sr, smb_pathname_t *pn)
{
	if (pn->pn_fname &&
	    strlen(pn->pn_fname) == 5 &&
	    smb_isdigit(pn->pn_fname[3]) &&
	    pn->pn_fname[4] == ':') {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (B_FALSE);
	}

	if (pn->pn_sname)
		return (smb_validate_stream_name(sr, pn));

	return (B_TRUE);
}

/*
 * smb_stream_parse_name
 *
 * smb_stream_parse_name should only be called for a path that
 * contains a valid named stream.  Path validation should have
 * been performed before this function is called.
 *
 * Find the last component of path and split it into filename
 * and stream name.
 *
 * On return the named stream type will be present.  The stream
 * type defaults to ":$DATA", if it has not been defined
 * For exmaple, 'stream' contains :<sname>:$DATA
 */
void
smb_stream_parse_name(char *path, char *filename, char *stream)
{
	char *fname, *sname, *stype;

	ASSERT(path);
	ASSERT(filename);
	ASSERT(stream);

	fname = strrchr(path, '\\');
	fname = (fname == NULL) ? path : fname + 1;
	(void) strlcpy(filename, fname, MAXNAMELEN);

	sname = strchr(filename, ':');
	(void) strlcpy(stream, sname, MAXNAMELEN);
	*sname = '\0';

	stype = strchr(stream + 1, ':');
	if (stype == NULL)
		(void) strlcat(stream, ":$DATA", MAXNAMELEN);
	else
		(void) smb_strupr(stype);
}

/*
 * smb_is_stream_name
 *
 * Determines if 'path' specifies a named stream.
 *
 * path is a NULL terminated string which could be a stream path.
 * [pathname/]fname[:stream_name[:stream_type]]
 *
 * - If there is no colon in the path or it's the last char
 *   then it's not a stream name
 *
 * - '::' is a non-stream and is commonly used by Windows to designate
 *   the unamed stream in the form "::$DATA"
 */
boolean_t
smb_is_stream_name(char *path)
{
	char *colonp;

	if (path == NULL)
		return (B_FALSE);

	colonp = strchr(path, ':');
	if ((colonp == NULL) || (*(colonp+1) == '\0'))
		return (B_FALSE);

	if (strstr(path, "::"))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * smb_validate_stream_name
 *
 * B_FALSE will be returned, and the error status ser in the sr, if:
 * - the path is not a stream name
 * - a path is specified but the fname is ommitted.
 * - the stream_type is specified but not valid.
 *
 * Note: the stream type is case-insensitive.
 */
boolean_t
smb_validate_stream_name(smb_request_t *sr, smb_pathname_t *pn)
{
	static char *strmtype[] = {
		"$DATA",
		"$INDEX_ALLOCATION"
	};
	int i;

	ASSERT(pn);
	ASSERT(pn->pn_sname);

	if ((!(pn->pn_sname)) ||
	    ((pn->pn_pname) && !(pn->pn_fname))) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (B_FALSE);
	}


	if (pn->pn_stype != NULL) {
		for (i = 0; i < sizeof (strmtype) / sizeof (strmtype[0]); ++i) {
			if (strcasecmp(pn->pn_stype, strmtype[i]) == 0)
				return (B_TRUE);
		}

		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * valid DFS I/O path:
 *
 * \server-or-domain\share
 * \server-or-domain\share\path
 *
 * All the returned errors by this function needs to be
 * checked against Windows.
 */
static int
smb_pathname_dfs_preprocess(smb_request_t *sr, char *path, size_t pathsz)
{
	smb_unc_t unc;
	char *linkpath;
	int rc;

	if (sr->tid_tree == NULL)
		return (0);

	if ((rc = smb_unc_init(path, &unc)) != 0)
		return (rc);

	if (smb_strcasecmp(unc.unc_share, sr->tid_tree->t_sharename, 0)) {
		smb_unc_free(&unc);
		return (EINVAL);
	}

	linkpath = unc.unc_path;
	(void) snprintf(path, pathsz, "/%s", (linkpath) ? linkpath : "");

	smb_unc_free(&unc);
	return (0);
}
