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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * NT Token library (kernel/user)
 */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/kmem.h>
#else /* _KERNEL */
#include <stdlib.h>
#include <strings.h>
#include <thread.h>
#include <synch.h>
#include <syslog.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/varargs.h>
#include <smbsrv/alloc.h>
#endif /* _KERNEL */

#include <sys/socket.h>
#include <netinet/in.h>

#include <smbsrv/alloc.h>
#include <smbsrv/string.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smb_xdr.h>

#ifndef _KERNEL
#include <assert.h>
#define	ASSERT assert
void (*smb_token_logfunc)(int, const char *, ...) = syslog;
int smb_token_errlog = LOG_ERR;
int smb_token_infolog = LOG_INFO;
#else /* _KERNEL */
void (*smb_token_logfunc)(int, const char *, ...) = cmn_err;
int smb_token_errlog = CE_WARN;
int smb_token_infolog = CE_NOTE;
#endif /* _KERNEL */

int smb_token_debug = 0;

#ifdef _KERNEL
extern char *inet_ntop(int, const void *, char *, int);
#endif /* _KERNEL */

/*
 * Returns -1 on error. Otherwise, returns 0.
 */
int
smb_token_tobuf(smb_dr_user_ctx_t *usr, char *buf, int len)
{
	char ipaddr_buf[INET_ADDRSTRLEN];

	if (!usr) {
		(void) strcpy(buf, "N/A");
		return (-1);
	}

	(void) inet_ntop(AF_INET, (char *)&usr->du_ipaddr, ipaddr_buf,
	    sizeof (ipaddr_buf));
	(void) snprintf(buf, len, "%s\\%s %s (%s)",
	    usr->du_domain ? usr->du_domain : "",
	    usr->du_account ? usr->du_account : "",
	    usr->du_workstation ? usr->du_workstation : "",
	    ipaddr_buf);

	return (0);
}

/*PRINTFLIKE3*/
void
smb_token_log(int level, smb_dr_user_ctx_t *usr, char *fmt, ...)
{
	va_list ap;
	char *msg;
	int len;
	char tokenbuf[NTTOKEN_BASIC_INFO_MAXLEN];

	msg = MEM_MALLOC("nttoken", 1024);
	if (!msg) {
		smb_token_logfunc(smb_token_errlog, "smb_token_log: "
		    "resource shortage");
		return;
	}

	if (usr)
		(void) smb_token_tobuf(usr, tokenbuf, sizeof (tokenbuf));
	else
		(void) strcpy(tokenbuf, "UNKNOWN");

	va_start(ap, fmt);
	(void) snprintf(msg, 1024, "Token[%s]: ", tokenbuf);
	len = strlen(msg);
	(void) vsnprintf(msg + len, 1024 - len, fmt, ap);
	va_end(ap);
#ifdef _KERNEL
	cmn_err(level, "%s", msg);
#else
	syslog(level, "%s", msg);
#endif /* _KERNEL */

	MEM_FREE("nttoken", msg);
}

#ifndef _KERNEL
/*
 * smb_token_print
 *
 * Diagnostic routine to write the contents of a token to the log.
 */
void
smb_token_print(smb_token_t *token)
{
	smb_win_grps_t *w_grps;
	smb_posix_grps_t *x_grps;
	smb_sid_attrs_t *grp;
	char sidstr[128];
	int i;

	if (token == NULL)
		return;

	smb_token_logfunc(smb_token_infolog, "Token for %s\\%s",
	    (token->tkn_domain_name) ? token->tkn_domain_name : "-NULL-",
	    (token->tkn_account_name) ? token->tkn_account_name : "-NULL-");

	smb_token_logfunc(smb_token_infolog, "   User->Attr: %d",
	    token->tkn_user->i_sidattr.attrs);
	nt_sid_format2((nt_sid_t *)token->tkn_user->i_sidattr.sid, sidstr);
	smb_token_logfunc(smb_token_infolog, "   User->Sid: %s (id=%u)",
	    sidstr, token->tkn_user->i_id);

	nt_sid_format2((nt_sid_t *)token->tkn_owner->i_sidattr.sid, sidstr);
	smb_token_logfunc(smb_token_infolog, "   Ownr->Sid: %s (id=%u)",
	    sidstr, token->tkn_owner->i_id);

	nt_sid_format2((nt_sid_t *)token->tkn_primary_grp->i_sidattr.sid,
	    sidstr);
	smb_token_logfunc(smb_token_infolog, "   PGrp->Sid: %s (id=%u)",
	    sidstr, token->tkn_primary_grp->i_id);

	w_grps = token->tkn_win_grps;
	if (w_grps) {
		smb_token_logfunc(smb_token_infolog, "   Windows groups: %d",
		    w_grps->wg_count);

		for (i = 0; i < w_grps->wg_count; ++i) {
			grp = &w_grps->wg_groups[i].i_sidattr;
			smb_token_logfunc(smb_token_infolog,
			    "    Grp[%d].Attr:%d", i, grp->attrs);
			if (w_grps->wg_groups[i].i_sidattr.sid) {
				nt_sid_format2((nt_sid_t *)grp->sid, sidstr);
				smb_token_logfunc(smb_token_infolog,
				    "    Grp[%d].Sid: %s (id=%u)", i, sidstr,
				    w_grps->wg_groups[i].i_id);
			}
		}
	}
	else
		smb_token_logfunc(smb_token_infolog, "   No Windows groups");

	x_grps = token->tkn_posix_grps;
	if (x_grps) {
		smb_token_logfunc(smb_token_infolog, "   Solaris groups: %d",
		    x_grps->pg_ngrps);
		for (i = 0; i < x_grps->pg_ngrps; i++)
			smb_token_logfunc(smb_token_infolog, "    %u",
			    x_grps->pg_grps[i]);
	}
	else
		smb_token_logfunc(smb_token_infolog, "   No Solaris groups");

	if (token->tkn_privileges)
		smb_privset_log(token->tkn_privileges);
	else
		smb_token_logfunc(smb_token_infolog, "   No privileges");
}
#endif /* _KERNEL */

/*
 * smb_token_query_privilege
 *
 * Find out if the specified privilege is enable in the given
 * access token.
 */
int
smb_token_query_privilege(smb_token_t *token, int priv_id)
{
	smb_privset_t *privset;
	int i;

	if ((token == NULL) || (token->tkn_privileges == NULL))
		return (0);

	privset = token->tkn_privileges;
	for (i = 0; privset->priv_cnt; i++) {
		if (privset->priv[i].luid.lo_part == priv_id) {
			if (privset->priv[i].attrs == SE_PRIVILEGE_ENABLED)
				return (1);
			else
				return (0);
		}
	}

	return (0);
}

#ifndef _KERNEL
/*
 * smb_token_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
uint8_t *
smb_token_mkselfrel(smb_token_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!obj) {
		smb_token_logfunc(smb_token_errlog,
		    "smb_token_mkselfrel: invalid parameter");
		return (NULL);
	}

	*len = xdr_sizeof(xdr_smb_token_t, obj);
	buf = (uint8_t *)malloc(*len);
	if (!buf) {
		smb_token_logfunc(smb_token_errlog,
		    "smb_token_mkselfrel: resource shortage");
		return (NULL);
	}

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!xdr_smb_token_t(&xdrs, obj)) {
		smb_token_logfunc(smb_token_errlog,
		    "smb_token_mkselfrel: XDR encode error");
		*len = 0;
		free(buf);
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * netr_client_mkabsolute
 *
 * decode: flat buffer -> structure
 */
netr_client_t *
netr_client_mkabsolute(uint8_t *buf, uint32_t len)
{
	netr_client_t *obj;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);
	obj = (netr_client_t *)malloc(sizeof (netr_client_t));
	if (!obj) {
		smb_token_logfunc(smb_token_errlog, "netr_client_mkabsolute: "
		    "resource shortage");
		xdr_destroy(&xdrs);
		return (NULL);
	}

	bzero(obj, sizeof (netr_client_t));
	if (!xdr_netr_client_t(&xdrs, obj)) {
		smb_token_logfunc(smb_token_errlog, "netr_client_mkabsolute: "
		    "XDR decode error");
		free(obj);
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

void
netr_client_xfree(netr_client_t *clnt)
{
	xdr_free(xdr_netr_client_t, (char *)clnt);
	free(clnt);
}
#else /* _KERNEL */
/*
 * smb_token_mkabsolute
 *
 * decode: flat buffer -> structure
 */
smb_token_t *
smb_token_mkabsolute(uint8_t *buf, uint32_t len)
{
	smb_token_t *obj;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);
	obj = kmem_zalloc(sizeof (smb_token_t), KM_SLEEP);

	if (!xdr_smb_token_t(&xdrs, obj)) {
		smb_token_logfunc(smb_token_errlog, "smb_token_mkabsolute: XDR "
		    "decode error");
		kmem_free(obj, sizeof (smb_token_t));
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

/*
 * netr_client_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
uint8_t *
netr_client_mkselfrel(netr_client_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	*len = xdr_sizeof(xdr_netr_client_t, obj);
	buf = kmem_alloc(*len, KM_SLEEP);

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!xdr_netr_client_t(&xdrs, obj)) {
		smb_token_logfunc(smb_token_errlog, "netr_client_mkselfrel: "
		    "XDR encode error");
		kmem_free(buf, *len);
		*len = 0;
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

void
smb_token_free(smb_token_t *token)
{
	if (!token)
		return;

	/*
	 * deallocate any pointer field of an access token object
	 * using xdr_free since they are created by the XDR decode
	 * operation.
	 */
	xdr_free(xdr_smb_token_t, (char *)token);
	kmem_free(token, sizeof (smb_token_t));
}
#endif /* _KERNEL */
