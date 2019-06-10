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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Create context handler for "AAPL" extensions.
 * See: smbsrv/smb2_aapl.h for documentation.
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb2_aapl.h>
#include <smbsrv/smb_fsops.h>

/* SMB2 AAPL extensions: enabled? */
int smb2_aapl_extensions = 1;
uint64_t smb2_aapl_server_caps =
	kAAPL_SUPPORTS_READ_DIR_ATTR;
	/* | kAAPL_SUPPORTS_OSX_COPYFILE; (not yet) */
	/* | kAAPL_UNIX_BASED; */
/*
 * We could turn on kAAPL_UNIX_BASED above and report UNIX modes in
 * directory listings (see smb2_aapl_get_macinfo below) but don't
 * because the modes ZFS presents with non-trivial ACLs cause mac
 * clients to misbehave when copying files from the share to local.
 * For example, we may have a file that we can read, but which has
 * mode 0200.  When the mac copies such a file to the local disk,
 * the copy cannot be opened for read.  For now just turn off the
 * kAAPL_UNIX_BASED flag.  Later we might set this flag and return
 * modes only when we have a trivial ACL.
 */

uint64_t smb2_aapl_volume_caps = kAAPL_SUPPORTS_FULL_SYNC;

/*
 * Normally suppress file IDs for MacOS because it
 * requires them to be unique per share, and ours
 * can have duplicates under .zfs or sub-mounts.
 */
int smb2_aapl_use_file_ids = 0;

static uint32_t smb2_aapl_srv_query(smb_request_t *,
	mbuf_chain_t *, mbuf_chain_t *);

static int smb_aapl_ext_maxlen = 512;

/*
 * Decode an AAPL create context (command code) and build the
 * corresponding AAPL c.c. response.
 */
uint32_t
smb2_aapl_crctx(smb_request_t *sr,
	mbuf_chain_t *mbcin,
	mbuf_chain_t *mbcout)
{
	uint32_t cmdcode;
	uint32_t status;
	int rc;

	if (smb2_aapl_extensions == 0)
		return (NT_STATUS_NOT_SUPPORTED);

	rc = smb_mbc_decodef(mbcin, "l4.", &cmdcode);
	if (rc != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);
	mbcout->max_bytes = smb_aapl_ext_maxlen;
	(void) smb_mbc_encodef(mbcout, "ll", cmdcode, 0);

	switch (cmdcode) {
	case kAAPL_SERVER_QUERY:
		status = smb2_aapl_srv_query(sr, mbcin, mbcout);
		break;
	case kAAPL_RESOLVE_ID:
	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	return (status);
}

/*
 * Handle an AAPL c.c. kAAPL_SERVER_QUERY
 * Return our Mac-ish capabilities.  We also need to remember
 * that this client wants AAPL readdir etc.
 * Typically see: client_bitmap=7, client_caps=7
 */
static uint32_t
smb2_aapl_srv_query(smb_request_t *sr,
	mbuf_chain_t *mbcin, mbuf_chain_t *mbcout)
{
	uint64_t client_bitmap;
	uint64_t client_caps;
	uint64_t server_bitmap;
	int rc;

	rc = smb_mbc_decodef(
	    mbcin, "qq",
	    &client_bitmap,
	    &client_caps);
	if (rc != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	smb_rwx_rwenter(&sr->session->s_lock, RW_WRITER);

	/* Remember that this is a MacOS client. */
	sr->session->native_os = NATIVE_OS_MACOS;
	sr->session->s_flags |= SMB_SSN_AAPL_CCEXT;

	/*
	 * Select which parts of the bitmap we use.
	 */
	server_bitmap = client_bitmap &
	    (kAAPL_SERVER_CAPS | kAAPL_VOLUME_CAPS);
	(void) smb_mbc_encodef(mbcout, "q", server_bitmap);

	if ((server_bitmap & kAAPL_SERVER_CAPS) != 0) {
		uint64_t server_caps =
		    smb2_aapl_server_caps & client_caps;
		if (server_caps & kAAPL_SUPPORTS_READ_DIR_ATTR)
			sr->session->s_flags |= SMB_SSN_AAPL_READDIR;
		(void) smb_mbc_encodef(mbcout, "q", server_caps);
	}
	if ((server_bitmap & kAAPL_VOLUME_CAPS) != 0) {
		(void) smb_mbc_encodef(mbcout, "q", smb2_aapl_volume_caps);
	}

	/* Pad2, null model string. */
	(void) smb_mbc_encodef(mbcout, "ll", 0, 0);

	smb_rwx_rwexit(&sr->session->s_lock);

	return (0);
}

/*
 * Get additional information about a directory entry
 * needed when MacOS is using the AAPL extensions.
 * This is called after smb_odir_read_fileinfo has
 * filled in the fileinfo.  This fills in macinfo.
 *
 * This does a couple FS operations per directory entry.
 * That has some cost, but if we don't do it for them here,
 * the client has to make two more round trips for each
 * directory entry, which is much worse.
 */
int
smb2_aapl_get_macinfo(smb_request_t *sr, smb_odir_t *od,
	smb_fileinfo_t *fileinfo, smb_macinfo_t *mi,
	char *tbuf, size_t tbuflen)
{
	int		rc;
	cred_t		*kcr = zone_kcred();
	smb_node_t	*fnode, *snode;
	smb_attr_t	attr;
	uint32_t	AfpInfo[15];

	bzero(mi, sizeof (*mi));

	rc = smb_fsop_lookup(sr, od->d_cred, SMB_CASE_SENSITIVE,
	    od->d_tree->t_snode, od->d_dnode, fileinfo->fi_name, &fnode);
	if (rc != 0)
		return (rc);
	/* Note: hold ref on fnode, must release */

	smb_fsop_eaccess(sr, od->d_cred, fnode, &mi->mi_maxaccess);

	/*
	 * mi_rforksize
	 * Get length of stream: "AFP_Resource"
	 * Return size=zero if not found.
	 */
	(void) snprintf(tbuf, tbuflen, "%s:AFP_Resource", fileinfo->fi_name);
	rc = smb_fsop_lookup_name(sr, kcr, 0, sr->tid_tree->t_snode,
	    od->d_dnode, tbuf, &snode);
	if (rc == 0) {
		bzero(&attr, sizeof (attr));
		attr.sa_mask = SMB_AT_SIZE | SMB_AT_ALLOCSZ;
		rc = smb_node_getattr(NULL, snode, kcr, NULL, &attr);
		if (rc == 0) {
			mi->mi_rforksize = attr.sa_vattr.va_size;
		}
		smb_node_release(snode);
		snode = NULL;
	}

	/*
	 * mi_finder
	 * Get contents of stream: "AFP_AfpInfo"
	 * read 60 bytes, copy 32 bytes at off 16
	 */
	(void) snprintf(tbuf, tbuflen, "%s:AFP_AfpInfo", fileinfo->fi_name);
	rc = smb_fsop_lookup_name(sr, kcr, 0, sr->tid_tree->t_snode,
	    od->d_dnode, tbuf, &snode);
	if (rc == 0) {
		iovec_t iov;
		uio_t uio;

		bzero(&AfpInfo, sizeof (AfpInfo));
		bzero(&uio, sizeof (uio));

		iov.iov_base = (void *) &AfpInfo;
		iov.iov_len = sizeof (AfpInfo);
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_resid = sizeof (AfpInfo);
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_extflg = UIO_COPY_DEFAULT;
		rc = smb_fsop_read(sr, kcr, snode, &uio);
		if (rc == 0 && uio.uio_resid == 0) {
			bcopy(&AfpInfo[4], &mi->mi_finderinfo,
			    sizeof (mi->mi_finderinfo));
		}
		smb_node_release(snode);
		snode = NULL;
	}

	/*
	 * Later: Fill in the mode if we have a trivial ACL
	 * (otherwise leaving it zero as we do now).
	 */
	if (smb2_aapl_server_caps & kAAPL_UNIX_BASED) {
		bzero(&attr, sizeof (attr));
		attr.sa_mask = SMB_AT_MODE;
		rc = smb_node_getattr(NULL, fnode, kcr, NULL, &attr);
		if (rc == 0) {
			mi->mi_unixmode = (uint16_t)attr.sa_vattr.va_mode;
		}
	}

	smb_node_release(fnode);
	return (0);
}
