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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of smb_rdir_open, smb_rdir_next and smb_rdir_close.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

/*
 * smb_rdir_open
 */
int
smb_rdir_open(smb_request_t *sr, char *path, unsigned short sattr)
{
	smb_odir_t	*od;
	smb_node_t	*node;
	char		*last_component;
	smb_session_t	*session = sr->session;
	unsigned int	rc;
	int		erc;

	last_component = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if ((rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode,
	    &node, last_component)) != 0) {
		kmem_free(last_component, MAXNAMELEN);
		smbsr_raise_errno(sr, rc);
		/* NOTREACHED */
	}

	if ((node->vp)->v_type != VDIR) {
		smb_node_release(node);
		kmem_free(last_component, MAXNAMELEN);
		smbsr_raise_error(sr, ERRDOS, ERRbadpath);
		/* NOTREACHED */
	}

	erc = smb_fsop_access(sr, sr->user_cr, node, FILE_LIST_DIRECTORY);
	if (erc != 0) {
		smb_node_release(node);
		kmem_free(last_component, MAXNAMELEN);
		if (sr->smb_com == SMB_COM_SEARCH) {
			if (session->capabilities & CAP_STATUS32) {
				smbsr_setup_nt_status(sr,
				    ERROR_SEVERITY_WARNING,
				    NT_STATUS_NO_MORE_FILES);
				return (SDRC_NORMAL_REPLY);
			} else {
				smbsr_raise_error(sr,
				    ERRDOS, ERROR_NO_MORE_FILES);
				/* NOTREACHED */
			}
		} else {
			smbsr_raise_cifs_error(sr, NT_STATUS_ACCESS_DENIED,
			    ERRDOS, ERROR_ACCESS_DENIED);
			/* NOTREACHED */
		}
	}

	od = smb_odir_open(sr->tid_tree, node, last_component, sr->smb_pid,
	    sattr);
	kmem_free(last_component, sizeof (od->d_pattern));
	if (od == NULL) {
		smb_node_release(node);
		smbsr_raise_error(sr, ERRDOS, ERROR_NO_MORE_FILES);
		/* NOTREACHED */
	}

	sr->smb_sid = od->d_sid;
	sr->sid_odir = od;

	return (-1);
}


/*
 * smb_rdir_next
 *
 * Returns:
 *              0           Found an entry
 *              ENOENT      There is no (more) entry
 *              error code  An error happened
 */
int
smb_rdir_next(
    smb_request_t	*sr,
    smb_node_t		**rnode,
    smb_odir_context_t	*pc)
{
	struct smb_odir	*dir;
	ino64_t		fileid;
	int		rc, n_name;
	char		last_component[MAXNAMELEN];
	char		namebuf[MAXNAMELEN];
	smb_node_t	*tmp_snode;
	smb_node_t	*dnode;
	smb_node_t	*fnode;
	smb_attr_t	ret_attr;

	ASSERT(sr->sid_odir);
	dir = sr->sid_odir;

	if (dir->d_state == SMB_ODIR_STATE_CLOSED) {
		return (ENOENT);
	}

	if (dir->d_wildcards == 0) {
		/* There are no wildcards in pattern */
		if (pc->dc_cookie != 0) {
			/* Already found entry... */
			return (ENOENT);
		}

		pc->dc_name[0] = '\0';
		pc->dc_shortname[0] = '\0';
		pc->dc_name83[0] = '\0';

		rc = smb_fsop_lookup(sr, sr->user_cr, 0,
		    sr->tid_tree->t_snode, dir->d_dir_snode, dir->d_pattern,
		    &fnode, &pc->dc_attr, pc->dc_shortname, pc->dc_name83);

		if (rc != 0)
			return (rc);

		/*
		 * We are here if there was a successful lookup of the
		 * name.  The name may be a mangled name.  If it was,
		 * then shortname has the copy of it.  So, we may
		 * not need to do mangling later.
		 *
		 * dir->name will contain the case-preserved name.
		 * If that name is not available (this should not
		 * happen), then copy dir->pattern into dir->name.
		 */

		if (fnode->od_name) {
			(void) strcpy(pc->dc_name, fnode->od_name);
		} else {
			(void) strcpy(pc->dc_name, dir->d_pattern);
		}

		/* Root of file system? */
		if ((strcmp(dir->d_pattern, "..") == 0) &&
		    (dir->d_dir_snode == sr->tid_tree->t_snode)) {
			smb_node_release(fnode);
			smb_node_ref(sr->tid_tree->t_snode);
			fnode = sr->tid_tree->t_snode;
		} else if (pc->dc_attr.sa_vattr.va_type == VLNK) {
			(void) strcpy(namebuf, dir->d_pattern);

			tmp_snode = fnode;
			rc = smb_pathname_reduce(sr, sr->user_cr, namebuf,
			    sr->tid_tree->t_snode, dir->d_dir_snode,
			    &dnode, last_component);

			if (rc != 0) {
				fnode = tmp_snode;
			} else {
				rc = smb_fsop_lookup(sr, sr->user_cr,
				    SMB_FOLLOW_LINKS, sr->tid_tree->t_snode,
				    dnode, last_component, &fnode, &ret_attr,
				    0, 0);

				smb_node_release(dnode);
				if (rc != 0) {
					fnode = tmp_snode;
				} else {
					pc->dc_attr = ret_attr;
					smb_node_release(tmp_snode);
				}
			}
		}

		pc->dc_dattr = smb_node_get_dosattr(fnode);
		/*
		 * If name not already mangled, do it.
		 *
		 * The name will only be mangled if smb_needs_mangle()
		 * determines that it is required.  Mangling due to
		 * case-insensitive collisions is not necessary here.
		 */
		if (pc->dc_name83[0] == '\0')
			(void) smb_mangle_name(fnode->attr.sa_vattr.va_nodeid,
			    pc->dc_name, pc->dc_shortname, pc->dc_name83, 0);
		if (rnode)
			*rnode = fnode;
		else
			smb_node_release(fnode);

		pc->dc_cookie = (uint32_t)-1;
		return (0);
	} /* No wild card search */

	for (;;) {
		if (dir->d_state == SMB_ODIR_STATE_CLOSED) {
			return (ENOENT);
		}

		/* sizeof dir->name == 256 */
		n_name = (sizeof (pc->dc_name)) - 1;

		rc = smb_fsop_readdir(sr, sr->user_cr, dir->d_dir_snode,
		    &pc->dc_cookie, pc->dc_name, &n_name, &fileid, NULL,
		    NULL, NULL);
		if (rc != 0) {
			return (rc);
		}

		if (n_name == 0) 		/* EOF */
			break;
		pc->dc_name[n_name] = '\0';

		/*
		 * Don't return "." or ".." unless SMB_FA_HIDDEN bit is set
		 * We have to code these specially since we cannot set the
		 * SMB_FA_HIDDEN bits in these because they are simply links to
		 * the real directory and the real directory is NOT hidden.
		 */
		if (((dir->d_sattr & SMB_FA_HIDDEN) == 0) &&
		    ((strcmp(pc->dc_name,  ".") == 0) ||
		    ((strcmp(pc->dc_name, "..") == 0)))) {
			continue;
		}

		/* may match a mangled name or "real" name */
		if (smb_component_match(sr, fileid, dir, pc) <= 0)
			continue;

		/* Look up the "real" name */
		rc = smb_fsop_lookup(sr, sr->user_cr, 0, sr->tid_tree->t_snode,
		    dir->d_dir_snode, pc->dc_name, &fnode, &pc->dc_attr, 0, 0);

		if (rc != 0) {
			if (rc != ENOENT) {
				return (rc);
			}
			else
				continue;
			/* NOTREACHED */
		}

		/* Root of file system? */
		if ((strcmp(pc->dc_name, "..") == 0) &&
		    (dir->d_dir_snode == sr->tid_tree->t_snode)) {
			smb_node_release(fnode);
			smb_node_ref(sr->tid_tree->t_snode);
			fnode = sr->tid_tree->t_snode;
		} else if (pc->dc_attr.sa_vattr.va_type == VLNK)  {
			(void) strcpy(namebuf, pc->dc_name);

			smb_node_release(fnode);
			rc = smb_pathname_reduce(sr, sr->user_cr, namebuf,
			    sr->tid_tree->t_snode, dir->d_dir_snode, &dnode,
			    last_component);

			if (rc != 0) {
				continue;
			}

			rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
			    sr->tid_tree->t_snode, dnode, last_component,
			    &fnode, &ret_attr, 0, 0);

			smb_node_release(dnode);
			if (rc != 0) {
				continue;
			}
			pc->dc_attr = ret_attr;
		}

		pc->dc_dattr = smb_node_get_dosattr(fnode);

		/* Obey search attributes */
		if ((pc->dc_dattr & SMB_FA_DIRECTORY) &&
		    !(dir->d_sattr & SMB_FA_DIRECTORY)) {
			smb_node_release(fnode);
			continue;
		}

		if ((pc->dc_dattr & SMB_FA_HIDDEN) &&
		    !(dir->d_sattr & SMB_FA_HIDDEN)) {
			smb_node_release(fnode);
			continue;
		}

		if ((pc->dc_dattr & SMB_FA_SYSTEM) &&
		    !(dir->d_sattr & SMB_FA_SYSTEM)) {
			smb_node_release(fnode);
			continue;
		}

		if (rnode)
			*rnode = fnode;
		else
			smb_node_release(fnode);

		return (0);
	}

	return (ENOENT);
}

/*
 * smb_rdir_close
 */
void
smb_rdir_close(struct smb_request *sr)
{
	smb_odir_t	*od = sr->sid_odir;

	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	smb_odir_close(od);
	smb_odir_release(od);
	sr->sid_odir = NULL;
}
