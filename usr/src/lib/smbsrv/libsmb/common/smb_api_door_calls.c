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
 * Given a SID, make a door call to get  the associated name.
 *
 * Returns 0 if the door call is successful, otherwise -1.
 *
 * If 0 is returned, the lookup result will be available in a_status.
 * NT_STATUS_SUCCESS		The SID was mapped to a name.
 * NT_STATUS_NONE_MAPPED	The SID could not be mapped to a name.
 */
int
smb_lookup_sid(const char *sid, lsa_account_t *acct)
{
	door_arg_t	arg;
	char		*buf;
	size_t		len;
	int		opcode = SMB_DR_LOOKUP_SID;
	int		fd;
	int		rc;

	assert((sid != NULL) && (acct != NULL));

	bzero(acct, sizeof (lsa_account_t));
	(void) strlcpy(acct->a_sid, sid, SMB_SID_STRSZ);

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0)
		return (-1);

	buf = smb_dr_encode_common(opcode, acct, lsa_account_xdr, &len);
	if (buf == NULL) {
		(void) close(fd);
		return (-1);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if ((rc = smb_dr_clnt_call(fd, &arg)) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;

		rc = smb_dr_decode_common(buf, len, lsa_account_xdr, acct);
	}

	smb_dr_clnt_cleanup(&arg);
	(void) close(fd);
	return (rc);
}

/*
 * Given a name, make a door call to get the associated SID.
 *
 * Returns 0 if the door call is successful, otherwise -1.
 *
 * If 0 is returned, the lookup result will be available in a_status.
 * NT_STATUS_SUCCESS		The name was mapped to a SID.
 * NT_STATUS_NONE_MAPPED	The name could not be mapped to a SID.
 */
int
smb_lookup_name(const char *name, sid_type_t sidtype, lsa_account_t *acct)
{
	char		tmp[MAXNAMELEN];
	door_arg_t	arg;
	char		*buf;
	char		*dp = NULL;
	char		*np = NULL;
	size_t		len;
	int		opcode = SMB_DR_LOOKUP_NAME;
	int		fd;
	int		rc;

	assert((name != NULL) && (acct != NULL));

	(void) strlcpy(tmp, name, MAXNAMELEN);
	smb_name_parse(tmp, &np, &dp);

	bzero(acct, sizeof (lsa_account_t));
	acct->a_sidtype = sidtype;

	if (dp != NULL && np != NULL) {
		(void) strlcpy(acct->a_domain, dp, MAXNAMELEN);
		(void) strlcpy(acct->a_name, np, MAXNAMELEN);
	} else {
		(void) strlcpy(acct->a_name, name, MAXNAMELEN);
	}

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0)
		return (-1);

	buf = smb_dr_encode_common(opcode, acct, lsa_account_xdr, &len);
	if (buf == NULL) {
		(void) close(fd);
		return (-1);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if ((rc = smb_dr_clnt_call(fd, &arg)) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;

		rc = smb_dr_decode_common(buf, len, lsa_account_xdr, acct);
	}

	smb_dr_clnt_cleanup(&arg);
	(void) close(fd);
	return (rc);
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
			ipaddr->a_family = h->h_addrtype;
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

/*
 * Parameters:
 *   fqdn (input) - fully-qualified domain name
 *   srvbuf (output) - fully-qualified hostname of the AD server found
 *                  by this function.
 *   srvbuflen (input) - length of the 'buf'
 *
 * Return:
 *   B_TRUE if an AD server is found. Otherwise, returns B_FALSE;
 *
 * The buffer passed in should be big enough to hold a fully-qualified
 * hostname (MAXHOSTNAMELEN); otherwise, a truncated string will be
 * returned. On error, an empty string will be returned.
 */
boolean_t
smb_find_ads_server(char *fqdn, char *srvbuf, int srvbuflen)
{
	door_arg_t arg;
	char *buf;
	size_t len;
	int opcode = SMB_DR_ADS_FIND_HOST;
	char *server = NULL;
	int fd;
	boolean_t found = B_FALSE;

	if (!srvbuf)
		return (B_FALSE);

	*srvbuf = '\0';

	if (!fqdn)
		return (B_FALSE);

	if ((fd = open(SMB_DR_SVC_NAME, O_RDONLY)) < 0)
		return (B_FALSE);

	if ((buf = smb_dr_encode_string(opcode, fqdn, &len)) == 0) {
		(void) close(fd);
		return (B_FALSE);
	}

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;
		if ((server = smb_dr_decode_string(buf, len)) != NULL) {
			if (*server != '\0') {
				(void) strlcpy(srvbuf, server, srvbuflen);
				found = B_TRUE;
			}
			xdr_free(xdr_string, (char *)&server);
		}
	}

	smb_dr_clnt_cleanup(&arg);
	(void) close(fd);

	return (found);
}
