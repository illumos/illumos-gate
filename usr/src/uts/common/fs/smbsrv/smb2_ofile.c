/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Helper functions for SMB2 open handles
 */

#include <smbsrv/smb2_kproto.h>

uint32_t
smb2_ofile_getattr(smb_request_t *sr, smb_ofile_t *of, smb_attr_t *ap)
{
	uint_t mask;
	int rc;

	mask = ap->sa_mask;
	bzero(ap, sizeof (*ap));
	ap->sa_mask = mask;

	switch (of->f_ftype) {
	case SMB_FTYPE_DISK:
	case SMB_FTYPE_PRINTER:
		rc = smb_node_getattr(sr, of->f_node, of->f_cr, of, ap);
		break;
	case SMB_FTYPE_BYTE_PIPE:
	case SMB_FTYPE_MESG_PIPE:
		rc = smb_opipe_getattr(of, ap);
		break;
	default:
		rc = ENOTTY;
		break;
	}
	if (rc)
		return (smb_errno2status(rc));

	return (0);
}

/*
 * Get the stuff needed by FileStandardInformation that was
 * not already obtained by smb2_ofile_getattr().
 * (qi_delete_on_close, qi_isdir)
 */
uint32_t
smb2_ofile_getstd(smb_ofile_t *of, smb_queryinfo_t *qi)
{
	smb_node_t *node;

	switch (of->f_ftype) {
	case SMB_FTYPE_DISK:
	case SMB_FTYPE_PRINTER:
		node = of->f_node;
		qi->qi_delete_on_close =
		    (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) != 0;
		qi->qi_isdir = smb_node_is_dir(node);
		break;
	case SMB_FTYPE_BYTE_PIPE:
	case SMB_FTYPE_MESG_PIPE:
		qi->qi_delete_on_close = 1;
		qi->qi_isdir = 0;
		break;
	default:
		return (NT_STATUS_INVALID_DEVICE_REQUEST);
	}

	return (0);
}

/*
 * Get info for FileNameInformation, FileAlternateNameInformation.
 * (qi_name, qi_shortname)
 */
uint32_t
smb2_ofile_getname(smb_ofile_t *of, smb_queryinfo_t *qi)
{
	int rc;

	switch (of->f_ftype) {
	case SMB_FTYPE_DISK:
	case SMB_FTYPE_PRINTER:
		rc = smb_node_getshrpath(of->f_node, of->f_tree,
		    qi->qi_name, MAXPATHLEN);
		break;
	case SMB_FTYPE_BYTE_PIPE:
	case SMB_FTYPE_MESG_PIPE:
		rc = smb_opipe_getname(of, qi->qi_name, MAXPATHLEN);
		break;
	default:
		rc = ENOTTY;
		break;
	}
	if (rc)
		return (smb_errno2status(rc));
	qi->qi_namelen = smb_wcequiv_strlen(qi->qi_name);

	return (0);

}
