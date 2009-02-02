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
 * Door calls invoked by CLIs to obtain various SMB door service provided
 * by SMB daemon.
 */

#include <fcntl.h>
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
	door_arg_t arg;
	char *buf;
	size_t len;
	int rc = -1;
	uint_t opcode = SMB_DR_USER_LIST;
	int fd;

	bzero(users, sizeof (smb_dr_ulist_t));

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0)
		return (-1);

	buf = smb_dr_encode_common(opcode, &offset, xdr_uint32_t, &len);
	if (buf == NULL) {
		(void) close(fd);
		return (-1);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;
		rc = smb_dr_decode_common(buf, len, xdr_smb_dr_ulist_t, users);
	}

	smb_dr_clnt_cleanup(&arg);
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
	door_arg_t arg;
	char *buf;
	size_t len;
	int opcode = SMB_DR_LOOKUP_SID;
	char *name = NULL;
	int fd;

	assert((namebuf != NULL) && (namebuflen != 0));

	if (!smb_sid_isvalid(sid))
		return (NT_STATUS_INVALID_SID);

	smb_sid_tostr(sid, namebuf);

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0) {
		/* returning string SID */
		return (NT_STATUS_SUCCESS);
	}

	if ((buf = smb_dr_encode_string(opcode, namebuf, &len)) == 0) {
		/* returning string SID */
		(void) close(fd);
		return (NT_STATUS_SUCCESS);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;
		name = smb_dr_decode_string(buf, len);
	}

	smb_dr_clnt_cleanup(&arg);
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
	door_arg_t arg;
	char *buf;
	size_t len;
	int opcode = SMB_DR_LOOKUP_NAME;
	char *strsid = NULL;
	char *p;
	int fd;

	assert(name && sid);

	if (*name == '\0')
		return (NT_STATUS_NONE_MAPPED);

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0)
		return (NT_STATUS_INTERNAL_ERROR);

	if ((buf = smb_dr_encode_string(opcode, name, &len)) == 0) {
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;
		strsid = smb_dr_decode_string(buf, len);
	}

	smb_dr_clnt_cleanup(&arg);
	(void) close(fd);

	if (strsid == NULL)
		return (NT_STATUS_INTERNAL_ERROR);

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
	door_arg_t arg;
	char *buf;
	size_t len;
	int opcode = SMB_DR_JOIN;
	uint32_t status;
	int fd, rc;

	if (jdi == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0)
		return (NT_STATUS_INTERNAL_ERROR);

	buf = smb_dr_encode_common(opcode, jdi, xdr_smb_dr_joininfo_t, &len);
	if (buf == NULL) {
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;
		rc = smb_dr_decode_common(buf, len, xdr_uint32_t, &status);
		if (rc != 0)
			status = NT_STATUS_INTERNAL_ERROR;
	} else {
		status = NT_STATUS_INTERNAL_ERROR;
	}

	smb_dr_clnt_cleanup(&arg);
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
smb_get_dcinfo(char *namebuf, uint32_t namebuflen, smb_inaddr_t *ipaddr)
{
	door_arg_t arg;
	char *buf;
	size_t len;
	int opcode = SMB_DR_GET_DCINFO;
	int fd;
	char *srvname = NULL;
	struct hostent *h;
	int error_num;

	assert((namebuf != NULL) && (namebuflen != 0));
	*namebuf = '\0';

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0)
		return (NT_STATUS_INTERNAL_ERROR);

	if ((buf = smb_dr_set_opcode(opcode, &len)) == NULL) {
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;
		srvname = smb_dr_decode_string(buf, len);
	}

	smb_dr_clnt_cleanup(&arg);
	(void) close(fd);

	if (srvname) {
		(void) strlcpy(namebuf, srvname, namebuflen);
		if ((h = smb_gethostbyname(srvname, &error_num)) == NULL) {
			bzero(ipaddr, sizeof (smb_inaddr_t));
		} else {
			(void) memcpy(ipaddr, h->h_addr, h->h_length);
			freehostent(h);
		}
		xdr_free(xdr_string, (char *)&srvname);
	}
	return (NT_STATUS_SUCCESS);
}

bool_t
xdr_smb_dr_joininfo_t(XDR *xdrs, smb_joininfo_t *objp)
{
	if (!xdr_vector(xdrs, (char *)objp->domain_name, MAXHOSTNAMELEN,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_vector(xdrs, (char *)objp->domain_username,
	    SMB_USERNAME_MAXLEN + 1, sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_vector(xdrs, (char *)objp->domain_passwd,
	    SMB_PASSWD_MAXLEN + 1, sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->mode))
		return (FALSE);

	return (TRUE);
}
