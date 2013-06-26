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
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_share.h>

static void
smb_tcon_puterror(smb_request_t *sr, uint32_t status)
{

	switch (status) {

	case NT_STATUS_BAD_NETWORK_NAME:
		/* Intentional status=0 */
		smbsr_error(sr, 0, ERRSRV, ERRinvnetname);
		break;

	case NT_STATUS_ACCESS_DENIED:
		smbsr_error(sr, status, ERRSRV, ERRaccess);
		break;

	case NT_STATUS_BAD_DEVICE_TYPE:
		smbsr_error(sr, status, ERRDOS, ERROR_BAD_DEV_TYPE);
		break;

	default:
	case NT_STATUS_INTERNAL_ERROR:
		/* Intentional status=0 */
		smbsr_error(sr, 0, ERRSRV, ERRsrverror);
		break;
	}
}

/*
 * SmbTreeConnect: Map a share to a tree and obtain a tree-id (TID).
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes;    min = 4
 * UCHAR BufferFormat1;               0x04
 * STRING Path[];                     Server name and share name
 * UCHAR BufferFormat2;               0x04
 * STRING Password[];                 Password
 * UCHAR BufferFormat3;               0x04
 * STRING Service[];                  Service name
 *
 * The CIFS server responds with:
 *
 * Server Response                  Description
 * ================================ =================================
 *
 * UCHAR WordCount;                 Count of parameter words = 2
 * USHORT MaxBufferSize;            Max size message the server handles
 * USHORT Tid;                      Tree ID
 * USHORT ByteCount;                Count of data bytes = 0
 *
 * If the negotiated dialect is MICROSOFT NETWORKS 1.03 or earlier,
 * MaxBufferSize in the response message indicates the maximum size
 * message that the server can handle.  The client should not generate
 * messages, nor expect to receive responses, larger than this.  This
 * must be constant for a given server. For newer dialects, this field
 * is ignored.
 */
smb_sdrc_t
smb_pre_tree_connect(smb_request_t *sr)
{
	smb_arg_tcon_t	*tcon = &sr->sr_tcon;
	int		rc;

	/*
	 * Perhaps this should be "%A.sA" now that unicode is enabled.
	 */
	rc = smbsr_decode_data(sr, "%AAA", sr, &tcon->path,
	    &tcon->password, &tcon->service);

	tcon->flags = 0;
	tcon->optional_support = 0;

	DTRACE_SMB_2(op__TreeConnect__start, smb_request_t *, sr,
	    smb_arg_tcon_t *, tcon);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_tree_connect(smb_request_t *sr)
{
	DTRACE_SMB_1(op__TreeConnect__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_tree_connect(smb_request_t *sr)
{
	uint32_t status;
	int rc;

	status = smb_tree_connect(sr);
	if (status) {
		smb_tcon_puterror(sr, status);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_result(sr, 2, 0, "bwww",
	    2,				/* wct */
	    (WORD)smb_maxbufsize,	/* MaxBufferSize */
	    sr->smb_tid,		/* TID */
	    0);				/* bcc */

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * SmbTreeConnectX: Map a share to a tree and obtain a tree-id (TID).
 *
 * Client Request                     Description
 * =================================  =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 4
 * UCHAR AndXCommand;                 Secondary (X) command; 0xFF = none
 * UCHAR AndXReserved;                Reserved (must be 0)
 * USHORT AndXOffset;                 Offset to next command WordCount
 * USHORT Flags;                      Additional information
 *                                    bit 0 set = disconnect Tid
 * USHORT PasswordLength;             Length of Password[]
 * USHORT ByteCount;                  Count of data bytes;    min = 3
 * UCHAR Password[];                  Password
 * STRING Path[];                     Server name and share name
 * STRING Service[];                  Service name
 *
 * If the negotiated dialect is LANMAN1.0 or later, then it is a protocol
 * violation for the client to send this message prior to a successful
 * SMB_COM_SESSION_SETUP_ANDX, and the server ignores Password.
 *
 * If the negotiated dialect is prior to LANMAN1.0 and the client has not
 * sent a successful SMB_COM_SESSION_SETUP_ANDX request when the tree
 * connect arrives, a user level security mode server must nevertheless
 * validate the client's credentials.
 *
 * Flags (prefix with TREE_CONNECT_ANDX_):
 * ==========================  ========================================
 * 0x0001 DISCONECT_TID        The tree specified by TID in the SMB header
 *                             should be disconnected - disconnect errors
 *                             should be ignored.
 *
 * 0x0004 EXTENDED_SIGNATURES  Client request for signing key protection.
 *
 * 0x0008 EXTENDED_RESPONSE    Client request for extended information.
 *
 * Path follows UNC style syntax (\\server\share) and indicates the name
 * of the resource to which the client wishes to connect.
 *
 * Because Password may be an authentication response, it is a variable
 * length field with the length specified by PasswordLength.   If
 * authentication is not being used, Password should be a null terminated
 * ASCII string with PasswordLength set to the string size including the
 * terminating null.
 *
 * The server can enforce whatever policy it desires to govern share
 * access.  Administrative privilege is required for administrative
 * shares (C$, etc.).
 *
 * The Service component indicates the type of resource the client
 * intends to access.  Valid values are:
 *
 * Service   Description               Earliest Dialect Allowed
 * ========  ========================  ================================
 *
 * A:        disk share                PC NETWORK PROGRAM 1.0
 * LPT1:     printer                   PC NETWORK PROGRAM 1.0
 * IPC       named pipe                MICROSOFT NETWORKS 3.0
 * COMM      communications device     MICROSOFT NETWORKS 3.0
 * ?????     any type of device        MICROSOFT NETWORKS 3.0
 *
 * If the negotiated dialect is earlier than DOS LANMAN2.1, the response to
 * this SMB is:
 *
 * Server Response                  Description
 * ================================ ===================================
 *
 * UCHAR WordCount;                 Count of parameter words = 2
 * UCHAR AndXCommand;               Secondary (X) command;  0xFF = none
 * UCHAR AndXReserved;              Reserved (must be 0)
 * USHORT AndXOffset;               Offset to next command WordCount
 * USHORT ByteCount;                Count of data bytes;    min = 3
 *
 * If the negotiated is DOS LANMAN2.1 or later, the response to this SMB
 * is:
 *
 * Server Response                  Description
 * ================================ ===================================
 *
 * UCHAR WordCount;                 Count of parameter words = 3
 * UCHAR AndXCommand;               Secondary (X) command;  0xFF = none
 * UCHAR AndXReserved;              Reserved (must be 0)
 * USHORT AndXOffset;               Offset to next command WordCount
 * USHORT OptionalSupport;          Optional support bits
 * USHORT ByteCount;                Count of data bytes;    min = 3
 * UCHAR Service[];                 Service type connected to.  Always
 *                                   ANSII.
 * STRING NativeFileSystem[];       Native file system for this tree
 *
 * NativeFileSystem is the name of the filesystem; values to be expected
 * include FAT, NTFS, etc.
 *
 * OptionalSupport:
 * ==============================  ==========================
 * 0x0001 SMB_SUPPORT_SEARCH_BITS  The server supports the use of Search
 *                                 Attributes in client requests.
 * 0x0002 SMB_SHARE_IS_IN_DFS      The share is managed by DFS.
 * 0x000C SMB_CSC_MASK             Offline-caching mask - see CSC flags.
 * 0x0010 SMB_UNIQUE_FILE_NAME     The server uses long names and does not
 *                                 support short names.  Indicator for
 *                                 clients directory/name-space caching.
 * 0x0020 SMB_EXTENDED_SIGNATURES  The server will use signing key protection.
 *
 * Client-side caching (offline files):
 * ==============================  ==========================
 * 0x0000 SMB_CSC_CACHE_MANUAL_REINT Clients may cache files for offline use
 *                                 but automatic file-by-file reintegration
 *                                 is not allowed.
 * 0x0004 SMB_CSC_CACHE_AUTO_REINT Automatic file-by-file reintegration is
 *                                 allowed.
 * 0x0008 SMB_CSC_CACHE_VDO        File opens do not need to be flowed.
 * 0x000C SMB_CSC_CACHE_NONE       CSC is disabled for this share.
 *
 * Some servers negotiate "DOS LANMAN2.1" dialect or later and still send
 * the "downlevel" (i.e. wordcount==2) response.  Valid AndX following
 * commands are
 *
 * SMB_COM_OPEN              SMB_COM_OPEN_ANDX          SMB_COM_CREATE
 * SMB_COM_CREATE_NEW        SMB_COM_CREATE_DIRECTORY   SMB_COM_DELETE
 * SMB_COM_DELETE_DIRECTORY  SMB_COM_FIND               SMB_COM_COPY
 * SMB_COM_FIND_UNIQUE       SMB_COM_RENAME
 * SMB_COM_CHECK_DIRECTORY   SMB_COM_QUERY_INFORMATION
 * SMB_COM_GET_PRINT_QUEUE   SMB_COM_OPEN_PRINT_FILE
 * SMB_COM_TRANSACTION       SMB_COM_NO_ANDX_CMD
 * SMB_COM_SET_INFORMATION   SMB_COM_NT_RENAME
 *
 * Errors:
 * ERRDOS/ERRnomem
 * ERRDOS/ERRbadpath
 * ERRDOS/ERRinvdevice
 * ERRSRV/ERRaccess
 * ERRSRV/ERRbadpw
 * ERRSRV/ERRinvnetname
 */
smb_sdrc_t
smb_pre_tree_connect_andx(smb_request_t *sr)
{
	smb_arg_tcon_t	*tcon = &sr->sr_tcon;
	uint8_t		*pwbuf = NULL;
	uint16_t	pwlen = 0;
	int		rc;

	rc = smbsr_decode_vwv(sr, "b.www", &sr->andx_com, &sr->andx_off,
	    &tcon->flags, &pwlen);
	if (rc == 0) {
		if (pwlen != 0)
			pwbuf = smb_srm_zalloc(sr, pwlen);

		rc = smbsr_decode_data(sr, "%#cus", sr, pwlen, pwbuf,
		    &tcon->path, &tcon->service);

		tcon->pwdlen = pwlen;
		tcon->password = (char *)pwbuf;
	}

	tcon->optional_support = 0;

	DTRACE_SMB_2(op__TreeConnectX__start, smb_request_t *, sr,
	    smb_arg_tcon_t *, tcon);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_tree_connect_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__TreeConnectX__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_tree_connect_andx(smb_request_t *sr)
{
	smb_arg_tcon_t	*tcon = &sr->sr_tcon;
	char		*service;
	uint32_t	status;
	int		rc;

	status = smb_tree_connect(sr);
	if (status) {
		smb_tcon_puterror(sr, status);
		return (SDRC_ERROR);
	}

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_IPC:
		service = "IPC";
		break;
	case STYPE_PRINTQ:
		service = "LPT1:";
		break;
	case STYPE_DISKTREE:
	default:
		service = "A:";
	}

	if (sr->session->dialect < NT_LM_0_12) {
		rc = smbsr_encode_result(sr, 2, VAR_BCC, "bb.wwss",
		    (char)2,		/* wct */
		    sr->andx_com,
		    VAR_BCC,
		    VAR_BCC,
		    service,
		    sr->tid_tree->t_typename);
	} else {
		rc = smbsr_encode_result(sr, 3, VAR_BCC, "bb.wwws%u",
		    (char)3,		/* wct */
		    sr->andx_com,
		    (short)64,
		    tcon->optional_support,
		    VAR_BCC,
		    service,
		    sr,
		    sr->tid_tree->t_typename);
	}

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * SmbTreeDisconnect: Disconnect a tree.
 *
 * Note: SDDF_SUPPRESS_UID is set for this operation, which means the sr
 * uid_user field will not be valid on entry to these functions.  Do not
 * use it until it is set up in smb_com_tree_disconnect() or the system
 * will panic.
 *
 * Note: there are scenarios in which the client does not send a tree
 * disconnect request, for example, when ERRbaduid is returned from
 * SmbReadX after a user has logged off.  Any open files will remain
 * around until the session is destroyed.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * The resource sharing connection identified by Tid in the SMB header is
 * logically disconnected from the server. Tid is invalidated; it will not
 * be recognized if used by the client for subsequent requests. All locks,
 * open files, etc. created on behalf of Tid are released.
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * Errors:
 * ERRSRV/ERRinvnid
 * ERRSRV/ERRbaduid
 */
smb_sdrc_t
smb_pre_tree_disconnect(smb_request_t *sr)
{
	sr->uid_user = smb_session_lookup_uid(sr->session, sr->smb_uid);
	sr->tid_tree = smb_session_lookup_tree(sr->session, sr->smb_tid);

	DTRACE_SMB_1(op__TreeDisconnect__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_tree_disconnect(smb_request_t *sr)
{
	DTRACE_SMB_1(op__TreeDisconnect__done, smb_request_t *, sr);
}

/*
 * SmbTreeDisconnect requires a valid UID as well as a valid TID.  Some
 * clients logoff a user and then try to disconnect the trees connected
 * by the user who has just been logged off, which would normally fail
 * in the dispatch code with ERRbaduid but, unfortunately, ERRbaduid
 * causes a problem for some of those clients.  Windows returns ERRinvnid.
 *
 * To prevent ERRbaduid being returned, the UID and TID are looked up here
 * rather than prior to dispatching SmbTreeDisconnect requests.  If either
 * the UID or the TID is invalid, ERRinvnid is returned.
 */
smb_sdrc_t
smb_com_tree_disconnect(smb_request_t *sr)
{
	if (sr->uid_user == NULL || sr->tid_tree == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRinvnid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_user_getcred(sr->uid_user);

	smb_session_cancel_requests(sr->session, sr->tid_tree, sr);
	smb_tree_disconnect(sr->tid_tree, B_TRUE);

	if (smbsr_encode_empty_result(sr))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
