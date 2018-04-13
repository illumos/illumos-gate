/*
 * Copyright (c) 2000-2002, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from: Id: view.c,v 1.9 2002/02/20 09:26:42 bp Exp
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netsmb/mchain.h>	/* letohs, etc. */
#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/smb_rap.h>

#include "common.h"

/*
 * Enumerate shares using Remote Administration Protocol (RAP)
 * Was in libsmbfs netshareenum.c
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

int
share_enum_rap(smb_ctx_t *ctx)
{
	struct smb_share_info_1 *shi;
	void *rpbuf;
	char *cp;
	int error, bufsize, i, rcnt, total;
	int lbound, rbound;
	uint16_t type;

	bufsize = 0xffe0;	/* samba notes win2k bug for 65535 */
	rpbuf = malloc(bufsize);
	if (rpbuf == NULL)
		return (errno);

	error = smb_rap_NetShareEnum(ctx, 1, rpbuf, &bufsize, &rcnt, &total);
	if (error &&
	    error != (ERROR_MORE_DATA | SMB_RAP_ERROR))
		goto out;

	/*
	 * Bounds for offsets to comments strings.
	 * After the array, and before the end.
	 */
	lbound = rcnt * (sizeof (struct smb_share_info_1));
	rbound = bufsize;

	/* Print the header line. */
	view_print_share(NULL, 0, NULL);

	for (shi = rpbuf, i = 0; i < rcnt; i++, shi++) {
		type = letohs(shi->shi1_type);

		shi->shi1_pad = '\0'; /* ensure null termination */

		/*
		 * Offsets to comment strings can be trash.
		 * Only print when the offset is valid.
		 */
		if (shi->shi1_remark >= lbound &&
		    shi->shi1_remark < rbound) {
			cp = (char *)rpbuf + shi->shi1_remark;
		} else
			cp = NULL;

		/* Convert from OEM to local codeset? */
		view_print_share(shi->shi1_netname, type, cp);
	}
	error = 0;

out:
	free(rpbuf);
	return (error);
}
