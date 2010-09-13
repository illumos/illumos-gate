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

#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "libilb.h"
#include "libilb_impl.h"

enum which_tbl {
	show_nat = 1,
	show_persist
};

/* The common function to show kernel info. */
static ilb_status_t ilb_show_info(ilb_handle_t, char *, size_t *, boolean_t *,
    enum which_tbl);

/*
 * To get the ILB NAT table.
 *
 * buf: The buffer to return the NAT table entries.
 * num: The caller sets it to the number of ilb_nat_info_t entries buf can
 *      hold.  On return, it contains the actual number of entries put in buf.
 * end: The caller sets it to B_TRUE if it only wants at most num entries to
 *      be returned.  The transaction to ilbd will be termianted when this
 *      call returns.
 *      The caller sets it to B_FALSE if it intends to get the whole table.
 *      If the whole table has more than num entries, the caller can call
 *      this function again to retrieve the rest of the table.
 *      On return, end is set to B_TRUE if end of table is reached; B_FALSE
 *      if there are still remaining entries.
 */
ilb_status_t
ilb_show_nat(ilb_handle_t h, ilb_nat_info_t buf[], size_t *num,
    boolean_t *end)
{
	return (ilb_show_info(h, (char *)buf, num, end, show_nat));
}

/*
 * To get the ILB persistent entry table.
 *
 * buf: The buffer to return the persistent table entries.
 * num: The caller sets it to the number of ilb_persist_info_t entries buf can
 *      hold.  On return, it contains the actual number of entries put in buf.
 * end: The caller sets it to B_TRUE if it only wants at most num entries to
 *      be returned.  The transaction to ilbd will be termianted when this
 *      call returns.
 *      The caller sets it to B_FALSE if it intends to get the whole table.
 *      If the whole table has more than num entries, the caller can call
 *      this function again to retrieve the rest of the table.
 *      On return, end is set to B_TRUE if end of table is reached; B_FALSE
 *      if there are still remaining entries.
 */
ilb_status_t
ilb_show_persist(ilb_handle_t h, ilb_persist_info_t buf[], size_t *num,
    boolean_t *end)
{
	return (ilb_show_info(h, (char *)buf, num, end, show_persist));
}

/*
 * The function doing the work...  The tbl parameter determines whith table
 * to show.
 */
static ilb_status_t
ilb_show_info(ilb_handle_t h, char *buf, size_t *num, boolean_t *end,
    enum which_tbl tbl)
{
	ilb_comm_t	*req, *rbuf;
	ilb_show_info_t	*req_si, *tmp_si;
	size_t		reqsz, rbufsz, tmp_rbufsz, cur_num;
	size_t		entry_sz;
	ilb_status_t	rc;

	if (*num == 0)
		return (ILB_STATUS_EINVAL);

	reqsz = sizeof (ilb_comm_t) + sizeof (ilb_show_info_t);
	if ((req = malloc(reqsz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	req_si = (ilb_show_info_t *)&req->ic_data;

	/*
	 * Need to allocate a receive buffer and then copy the buffer
	 * content to the passed in buf.  The reason is that the
	 * communication to ilbd is message based and the protocol
	 * includes a header in the reply.  We need to remove this header
	 * from the message, hence the copying...
	 */
	if (tbl == show_nat)
		entry_sz = sizeof (ilb_nat_info_t);
	else
		entry_sz = sizeof (ilb_persist_info_t);
	rbufsz = *num * entry_sz + sizeof (ilb_comm_t) +
	    sizeof (ilb_show_info_t);
	if ((rbuf = malloc(rbufsz)) == NULL) {
		free(req);
		return (ILB_STATUS_ENOMEM);
	}

	if (tbl == show_nat)
		req->ic_cmd = ILBD_SHOW_NAT;
	else
		req->ic_cmd = ILBD_SHOW_PERSIST;
	req->ic_flags = 0;
	req_si->sn_num = *num;
	cur_num = 0;

	do {
		tmp_rbufsz = rbufsz;
		rc = i_ilb_do_comm(h, req, reqsz, rbuf, &tmp_rbufsz);
		if (rc != ILB_STATUS_OK)
			goto out;
		if (rbuf->ic_cmd != ILBD_CMD_OK) {
			rc = *(ilb_status_t *)&rbuf->ic_data;
			goto out;
		}

		tmp_si = (ilb_show_info_t *)&rbuf->ic_data;

		cur_num += tmp_si->sn_num;
		bcopy(&tmp_si->sn_data, buf, tmp_si->sn_num * entry_sz);
		buf += tmp_si->sn_num * entry_sz;

		/*
		 * Buffer is filled, regardless of this is the end of table or
		 * not, we need to stop.
		 */
		if (cur_num == *num)
			break;
		/* Try to fill in the rest. */
		req_si->sn_num = *num - cur_num;
	} while (!(rbuf->ic_flags & ILB_COMM_END));

	*num = cur_num;

	/* End of transaction, let the caller know. */
	if (rbuf->ic_flags & ILB_COMM_END) {
		*end = B_TRUE;
	} else {
		/* The user wants to terminate the transaction */
		if (*end) {
			req->ic_flags = ILB_COMM_END;
			tmp_rbufsz = rbufsz;
			rc = i_ilb_do_comm(h, req, reqsz, rbuf, &tmp_rbufsz);
		}
	}
out:
	free(req);
	free(rbuf);
	return (rc);
}
