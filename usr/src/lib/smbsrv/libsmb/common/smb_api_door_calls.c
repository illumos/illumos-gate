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

#pragma ident	"@(#)smb_api_door_calls.c	1.6	08/07/16 SMI"

/*
 * Door calls invoked by CLIs to obtain various SMB door service provided
 * by SMB daemon.
 */

#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>

/* indexed via opcode (smb_dr_opcode_t) */
char *smbapi_desc[] = {
	"",
	"",
	"",
	"",
	"SmbapiUserList",
	"SmbLookupSid",
	"SmbLookupName",
	"SmbJoin",
	"SmbGetDCInfo",
	0
};

/*
 * This function will return information on the connected users
 * starting at the given offset.
 *
 * At most 50 users (i.e. SMB_DR_MAX_USER) will be returned via this
 * function. Multiple calls might be needed to obtain all connected
 * users.
 *
 * smb_dr_ulist_free must be called to free memory allocated for the
 * account and workstation fields of each user in the returned list.
 */
int
smb_api_ulist(int offset, smb_dr_ulist_t *users)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	int rc = -1;
	uint_t opcode = SMB_DR_USER_LIST;
	int fd;

	bzero(users, sizeof (smb_dr_ulist_t));
	buf = smb_dr_encode_common(opcode, &offset, xdr_uint32_t, &buflen);
	if (!buf)
		return (-1);

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (-1);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);
	if (rbufp) {
		rc = smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_smb_dr_ulist_t, users);

	}
	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

/*
 * smb_lookup_sid
 *
 * Tries to get the account name associated with the given SID
 * The mapping is requested to be performed by smbd via a door
 * call. If no account name can be found the string format of
 * the SID will be returned as the name.
 *
 * The passed namebuf should be big enough to hold the string
 * format of a SID.
 */
int
smb_lookup_sid(smb_sid_t *sid, char *namebuf, int namebuflen)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	int opcode = SMB_DR_LOOKUP_SID;
	char *name = NULL;
	int fd;

	assert((namebuf != NULL) && (namebuflen != 0));

	if (!smb_sid_isvalid(sid))
		return (NT_STATUS_INVALID_SID);

	smb_sid_tostr(sid, namebuf);

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1) {
		/* returning string SID */
		return (NT_STATUS_SUCCESS);
	}

	/* Encode */
	if ((buf = smb_dr_encode_string(opcode, namebuf, &buflen)) == 0) {
		/* returning string SID */
		(void) close(fd);
		return (NT_STATUS_SUCCESS);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		name = smb_dr_decode_string(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET);
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);

	if (name) {
		if (*name != '\0')
			(void) strlcpy(namebuf, name, namebuflen);

		xdr_free(xdr_string, (char *)&name);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_lookup_name
 *
 * Tries to get the SID associated with the given account name
 * The mapping is requested to be performed by smbd via a door
 * call. If no SID can be found NT_STATUS_NONE_MAPPED is returned.
 */
int
smb_lookup_name(char *name, smb_gsid_t *sid)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	int opcode = SMB_DR_LOOKUP_NAME;
	char *strsid = NULL;
	char *p;
	int fd;

	assert(name && sid);

	if (*name == '\0')
		return (NT_STATUS_NONE_MAPPED);

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((buf = smb_dr_encode_string(opcode, name, &buflen)) == 0) {
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		strsid = smb_dr_decode_string(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET);
		if (strsid == NULL) {
			smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);

	p = strchr(strsid, '-');
	if (p == NULL) {
		xdr_free(xdr_string, (char *)&strsid);
		return (NT_STATUS_NONE_MAPPED);
	}

	*p++ = '\0';
	sid->gs_type = atoi(strsid);
	sid->gs_sid = smb_sid_fromstr(p);
	xdr_free(xdr_string, (char *)&strsid);
	return (NT_STATUS_SUCCESS);
}

uint32_t
smb_join(smb_joininfo_t *jdi)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	int opcode = SMB_DR_JOIN;
	uint32_t status;
	int fd, rc;

	if (jdi == NULL) {
		syslog(LOG_ERR, "%s: invalid parameter", smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	buf = smb_dr_encode_common(opcode, jdi, xdr_smb_dr_joininfo_t, &buflen);
	if (buf == NULL)
		return (NT_STATUS_INTERNAL_ERROR);

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1) {
		free(buf);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);
	if (rbufp) {
		rc = smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &status);
		if (rc != 0)
			status = NT_STATUS_INTERNAL_ERROR;
	} else {
		status = NT_STATUS_INTERNAL_ERROR;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (status);
}

/*
 * Gets information about the Domain Controller in the joined resource domain.
 *
 * Returns: NT_STATUS_SUCCESS if the successful in getting
 *	    domain information.
 */
uint32_t
smb_get_dcinfo(smb_ntdomain_t *dc_info)
{
	char *buf = NULL, *rbufp;
	size_t buflen, rbufsize;
	int opcode = SMB_DR_GET_DCINFO;
	int fd, rc = NT_STATUS_SUCCESS;

	if ((buf = smb_dr_set_opcode(opcode, &buflen)) == NULL)
		return (NT_STATUS_INTERNAL_ERROR);

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME,
	    smbapi_desc[opcode]) == -1) {
		free(buf);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_smb_dr_domain_t,
		    dc_info) != NULL)
			rc = NT_STATUS_INTERNAL_ERROR;
	}
	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);

	return (rc);
}

bool_t
xdr_smb_dr_joininfo_t(XDR *xdrs, smb_joininfo_t *objp)
{
	if (!xdr_vector(xdrs, (char *)objp->domain_name, MAXHOSTNAMELEN,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_vector(xdrs, (char *)objp->domain_username, BUF_LEN + 1,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_vector(xdrs, (char *)objp->domain_passwd, BUF_LEN + 1,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->mode))
		return (FALSE);

	return (TRUE);
}

bool_t
xdr_smb_dr_domain_t(XDR *xdrs, smb_ntdomain_t *objp)
{
	if (!xdr_vector(xdrs, (char *)objp->domain, SMB_PI_MAX_DOMAIN,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->server, SMB_PI_MAX_DOMAIN,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ipaddr))
		return (FALSE);
	return (TRUE);
}
