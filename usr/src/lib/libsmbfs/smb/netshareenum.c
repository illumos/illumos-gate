/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/* BEGIN CSTYLED */
/*
 *      @(#)ui.c      *
 *      (c) 2004   Apple Computer, Inc.  All Rights Reserved
 *
 *
 *      netshareenum.c -- Routines for getting a list of share information
 *			  from a server.
 *
 *      MODIFICATION HISTORY:
 *       27-Nov-2004     Guy Harris	New today
 */
/* END CSTYLED */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <netsmb/mchain.h>
#include <netsmb/smb_lib.h>
#include <netsmb/smb_rap.h>
#include <netsmb/smb_netshareenum.h>
#include <smb/charsets.h>

#if 0 /* XXX see below */
#include <dce/exc_handling.h>
#include <rpc/attrb.h>
#include "srvsvc.h"
#endif

/*
 * Don't want RPC client-side code in here.
 * It's good code; just doesn't belong here.
 *
 * The API provided by this library should be
 * just files and pipes (and not much more).
 * It MAY be useful to provide some of the
 * RAP (remote API) functions functions like
 * rap_netshareenum below...
 *
 * XXX: Not sure this file belongs here at all.
 * smb_rap.h looks like a reasonable API
 * for this library to export.
 */
#if 0 /* XXX */

static int
rpc_netshareenum(struct smb_ctx *ctx, int *entriesp, int *totalp,
    struct share_info **entries_listp)
{
	char ctx_string[2+16+1];	/* enough for 64-bit pointer, in hex */
	unsigned_char_p_t binding;
	unsigned32 binding_status;
	rpc_binding_handle_t binding_h;
	int error, i, entries;
	char *addrstr, *srvnamestr;
	unsigned short *usrvnamestr;
	unsigned32 level;
	SHARE_ENUM_STRUCT share_info;
	SHARE_INFO_1_CONTAINER share_info_1_container;
	SHARE_INFO_1 *shares, *share;
	unsigned32 total_entries;
	unsigned32 status, free_status;
	struct share_info *entry_list, *elp;
	static EXCEPTION rpc_x_connect_rejected;
	static int exceptions_initialized;

	sprintf(ctx_string, "%p", ctx);
	rpc_string_binding_compose(NULL, "ncacn_np", ctx_string,
	    "srvsvc", NULL, &binding, &binding_status);
	if (binding_status != rpc_s_ok) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "rpc_string_binding_compose failed with %d"),
		    0, binding_status);
		return (EINVAL);
	}
	rpc_binding_from_string_binding(binding, &binding_h, &status);
	rpc_string_free(&binding, (unsigned32 *)&free_status);
	if (binding_status != rpc_s_ok) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "rpc_binding_from_string_binding failed with %d"), 0,
		    binding_status);
		return (EINVAL);
	}
	level = 1;
	share_info.share_union.level = 1;
	share_info.share_union.tagged_union.share1 = &share_info_1_container;
	share_info_1_container.share_count = 0;
	share_info_1_container.shares = NULL;
	/*
	 * Convert the server IP address to a string, and send that as
	 * the "server name" - that's what Windows appears to do, and
	 * that avoids problems with NetBIOS names containing
	 * non-ASCII characters.
	 */
	addrstr = inet_ntoa(ctx->ct_srvinaddr.sin_addr);
	srvnamestr = malloc(strlen(addrstr) + 3);
	if (srvnamestr == NULL) {
		status = errno;
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't allocate string for server address"), status);
		rpc_binding_free(&binding_h, &free_status);
		return (status);
	}
	strcpy(srvnamestr, "\\\\");
	strcat(srvnamestr, addrstr);
	usrvnamestr = convert_utf8_to_leunicode(srvnamestr);
	if (usrvnamestr == NULL) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't convert string for server address to Unicode"), 0);
		rpc_binding_free(&binding_h, &free_status);
		free(srvnamestr);
		return (EINVAL);
	}
	if (!exceptions_initialized) {
		EXCEPTION_INIT(rpc_x_connect_rejected);
		exc_set_status(&rpc_x_connect_rejected, rpc_s_connect_rejected);
		exceptions_initialized = 1;
	}
	/* printf("Calling NetrShareEnum.."); XXX */
	TRY
		status = NetrShareEnum(binding_h, usrvnamestr, &level,
		    &share_info, 4294967295U, &total_entries, NULL);
		if (status != 0)
			smb_error(dgettext(TEXT_DOMAIN,
			    "error from NetrShareEnum call: status = 0x%08x"),
			    0, status);
	/*CSTYLED*/
	CATCH (rpc_x_connect_rejected)
		/*
		 * This is what we get if we can't open the pipe.
		 * That's a normal occurrence when we're talking
		 * to a system that (presumably) doesn't support
		 * DCE RPC on the server side, such as Windows 95/98/Me,
		 * so we don't log an error.
		 */
		/*CSTYLED*/
		status = ENOTSUP;
	CATCH_ALL
		/*
		 * XXX - should we handle some exceptions differently,
		 * returning different errors, and try RAP only for
		 * ENOTSUP?
		 */
		smb_error(dgettext(TEXT_DOMAIN,
		    "error from NetrShareEnum call: exception = %u"),
		    0, THIS_CATCH->match.value);
		status = ENOTSUP;
	ENDTRY
	rpc_binding_free(&binding_h, &free_status);
	free(srvnamestr);
	free(usrvnamestr);
	if (status != 0)
		return (ENOTSUP);

	/*
	 * XXX - if the IDL is correct, it's not clear whether the
	 * unmarshalling code will properly handle the case where
	 * a packet where "share_count" and the max count for the
	 * array of shares don't match; a valid DCE RPC implementation
	 * won't marshal something like that, but there's no guarantee
	 * that the server we're talking to has a valid implementation
	 * (which could be a *malicious* implementation!).
	 */
	entries = share_info.share_union.tagged_union.share1->share_count;
	shares = share_info.share_union.tagged_union.share1->shares;
	entry_list = calloc(entries, sizeof (struct share_info));
	if (entry_list == NULL) {
		error = errno;
		goto cleanup_and_return;
	}
	for (share = shares, elp = entry_list, i = 0; i < entries;
	    i++, share++) {
		elp->type = share->shi1_type;
		elp->netname = convert_unicode_to_utf8(share->shi1_share);
		if (elp->netname == NULL)
			goto fail;
		elp->remark = convert_unicode_to_utf8(share->shi1_remark);
		if (elp->remark == NULL)
			goto fail;
		elp++;
	}
	*entriesp = entries;
	*totalp = total_entries;
	*entries_listp = entry_list;
	error = 0;
	goto cleanup_and_return;

fail:
	error = errno;
	for (elp = entry_list, i = 0; i < entries; i++, elp++) {
		/*
		 * elp->netname is set before elp->remark, so if
		 * elp->netname is null, elp->remark is also null.
		 * If either of them is null, we haven't done anything
		 * to any entries after this one.
		 */
		if (elp->netname == NULL)
			break;
		free(elp->netname);
		if (elp->remark == NULL)
			break;
		free(elp->remark);
	}
	free(entry_list);

cleanup_and_return:
	for (share = shares, i = 0; i < entries; i++, share++) {
		free(share->shi1_share);
		free(share->shi1_remark);
	}
	free(shares);
	/*
	 * XXX - "share1" should be a unique pointer, but we haven't
	 * changed the marshalling code to support non-full pointers
	 * in unions, so we leave it as a full pointer.
	 *
	 * That means that this might, or might not, be changed from
	 * pointing to "share_info_1_container" to pointing to a
	 * mallocated structure, according to the DCE RPC 1.1 IDL spec;
	 * we free it only if it's changed.
	 */
	if (share_info.share_union.tagged_union.share1 !=
	    &share_info_1_container)
		free(share_info.share_union.tagged_union.share1);
	return (error);
}
#endif /* XXX */

/*
 * Enumerate shares using RAP
 */

struct smb_share_info_1 {
	char		shi1_netname[13];
	char		shi1_pad;
	uint16_t	shi1_type;
	uint32_t	shi1_remark;		/* char * */
};

static int
smb_rap_NetShareEnum(struct smb_ctx *ctx, int sLevel, void *pbBuffer,
	int *cbBuffer, int *pcEntriesRead, int *pcTotalAvail)
{
	struct smb_rap *rap;
	long lval = -1;
	int error;
	char *pass;
	int i;

	error = smb_rap_create(0, "WrLeh", "B13BWz", &rap);
	if (error)
		return (error);
	smb_rap_setNparam(rap, sLevel);		/* W - sLevel */
	smb_rap_setPparam(rap, pbBuffer);	/* r - pbBuffer */
	smb_rap_setNparam(rap, *cbBuffer);	/* L - cbBuffer */
	error = smb_rap_request(rap, ctx);
	if (error == 0) {
		*pcEntriesRead = rap->r_entries;
		error = smb_rap_getNparam(rap, &lval);
		*pcTotalAvail = lval;
		/* Copy the data length into the IN/OUT variable. */
		*cbBuffer = rap->r_rcvbuflen;
	}
	error = smb_rap_error(rap, error);
	smb_rap_done(rap);
	return (error);
}

static int
rap_netshareenum(struct smb_ctx *ctx, int *entriesp, int *totalp,
    struct share_info **entries_listp)
{
	int error, bufsize, i, entries, total, nreturned;
	struct smb_share_info_1 *rpbuf, *ep;
	struct share_info *entry_list, *elp;
	char *cp;
	int lbound, rbound;

	bufsize = 0xffe0;	/* samba notes win2k bug for 65535 */
	rpbuf = malloc(bufsize);
	if (rpbuf == NULL)
		return (errno);

	error = smb_rap_NetShareEnum(ctx, 1, rpbuf, &bufsize, &entries, &total);
	if (error &&
	    error != (SMB_ERROR_MORE_DATA | SMB_RAP_ERROR)) {
		free(rpbuf);
		return (error);
	}
	entry_list = malloc(entries * sizeof (struct share_info));
	if (entry_list == NULL) {
		error = errno;
		free(rpbuf);
		return (error);
	}
	lbound = entries * (sizeof (struct smb_share_info_1));
	rbound = bufsize;
	for (ep = rpbuf, elp = entry_list, i = 0, nreturned = 0; i < entries;
	    i++, ep++) {
		elp->type = letohs(ep->shi1_type);
		ep->shi1_pad = '\0'; /* ensure null termination */
		elp->netname = convert_wincs_to_utf8(ep->shi1_netname);
		if (elp->netname == NULL)
			continue;	/* punt on this entry */
		/*
		 * Check for validity of offset.
		 */
		if (ep->shi1_remark >= lbound && ep->shi1_remark < rbound) {
			cp = (char *)rpbuf + ep->shi1_remark;
			elp->remark = convert_wincs_to_utf8(cp);
		} else
			elp->remark = NULL;
		elp++;
		nreturned++;
	}
	*entriesp = nreturned;
	*totalp = total;
	*entries_listp = entry_list;
	free(rpbuf);
	return (0);
}

/*
 * First we try the RPC-based NetrShareEnum, and, if that fails, we fall
 * back on the RAP-based NetShareEnum.
 */
int
smb_netshareenum(struct smb_ctx *ctx, int *entriesp, int *totalp,
    struct share_info **entry_listp)
{
	int error;

#ifdef NOTYETDEFINED
	/*
	 * Try getting a list of shares with the SRVSVC RPC service.
	 */
	error = rpc_netshareenum(ctx, entriesp, totalp, entry_listp);
	if (error == 0)
		return (0);
#endif

	/*
	 * OK, that didn't work - try RAP.
	 * XXX - do so only if it failed because we couldn't open
	 * the pipe?
	 */
	return (rap_netshareenum(ctx, entriesp, totalp, entry_listp));
}
