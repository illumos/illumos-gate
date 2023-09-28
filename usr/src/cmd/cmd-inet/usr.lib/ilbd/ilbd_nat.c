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

#include <sys/types.h>
#include <libilb.h>
#include <inet/ilb.h>
#include <stddef.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <macros.h>
#include "libilb_impl.h"
#include "ilbd.h"

/*
 * We only allow one show nat/persist command running at any time.  Note that
 * there is no lock for this since ilbd is single threaded.  And we only care
 * about the pointer value of client, not its type.
 *
 * The following variables store the current client making the request.
 */
static void *nat_cur_cli;
static void *sticky_cur_cli;

/* Maximum number of NAT/sticky entries to request from kernel. */
#define	NUM_ENTRIES	500

/*
 * Clear the current requesting client.  This will allow a new client
 * to make a request.
 */
void
ilbd_show_nat_cleanup(void)
{
	nat_cur_cli = NULL;
}

void
ilbd_show_sticky_cleanup(void)
{
	sticky_cur_cli = NULL;
}

/*
 * To show the kernel NAT table.
 *
 * cli: the client pointer making the request.
 * ic: the client request.
 * rbuf: reply buffer to be filled in.
 * rbufsz: reply buffer size.
 */
ilb_status_t
ilbd_show_nat(void *cli, const ilb_comm_t *ic, uint32_t *rbuf, size_t *rbufsz)
{
	ilb_show_info_t *req_si = (ilb_show_info_t *)&ic->ic_data;
	ilb_list_nat_cmd_t *kcmd;
	boolean_t start;
	size_t tmp_rbufsz, kbufsz;
	uint32_t max_num;
	ilb_status_t ret;
	int i;
	ilb_show_info_t *reply;
	ilb_nat_info_t *nat_ret;

	/* For new client request, start from the beginning of the table. */
	if (nat_cur_cli == NULL) {
		nat_cur_cli = cli;
		start = B_TRUE;
	} else if (cli == nat_cur_cli) {
		/*
		 * Another request from client.  If the client does not
		 * want to continue, reset the current client and reply OK.
		 */
		if (ic->ic_flags & ILB_COMM_END) {
			ilbd_show_nat_cleanup();
			ilbd_reply_ok(rbuf, rbufsz);
			return (ILB_STATUS_OK);
		}
		start = B_FALSE;
	} else {
		/* A request is on-going, so reject a new client. */
		return (ILB_STATUS_INPROGRESS);
	}

	tmp_rbufsz = *rbufsz;
	ilbd_reply_ok(rbuf, rbufsz);
	reply = (ilb_show_info_t *)&((ilb_comm_t *)rbuf)->ic_data;

	/*
	 * Calculate the max number of ilb_nat_info_t can be fitted in the
	 * reply.
	 */
	*rbufsz += sizeof (ilb_show_info_t *);
	tmp_rbufsz -= *rbufsz;
	max_num = tmp_rbufsz / sizeof (ilb_nat_info_t);

	/*
	 * Calculate the exact number of entries we should request from kernel.
	 */
	max_num = min(req_si->sn_num, min(NUM_ENTRIES, max_num));

	kbufsz = max_num * sizeof (ilb_nat_entry_t) +
	    offsetof(ilb_list_nat_cmd_t, entries);
	if ((kcmd = malloc(kbufsz)) == NULL) {
		logdebug("ilbd_show_nat: malloc(cmd)");
		ilbd_reply_err(rbuf, rbufsz, ILB_STATUS_ENOMEM);
		return (ILB_STATUS_ENOMEM);
	}

	kcmd->cmd = ILB_LIST_NAT_TABLE;
	kcmd->flags = start ? ILB_LIST_BEGIN : ILB_LIST_CONT;
	kcmd->num_nat = max_num;
	if ((ret = do_ioctl(kcmd, kbufsz)) != ILB_STATUS_OK) {
		logperror("ilbd_show_nat: ioctl(ILB_LIST_NAT_TABLE)");
		ilbd_reply_err(rbuf, rbufsz, ret);
		free(kcmd);
		return (ret);
	}

	reply->sn_num = kcmd->num_nat;
	*rbufsz += reply->sn_num * sizeof (ilb_nat_info_t);

	/*
	 * It is the end of table, let the client know.  And the transaction
	 * is done.
	 */
	if (kcmd->flags & ILB_LIST_END) {
		nat_cur_cli = NULL;
	} else {
		/*
		 * ilbd_reply_ok() sets ic_flags to ILB_COMM_END by default.
		 * Need to clear it here.
		 */
		((ilb_comm_t *)rbuf)->ic_flags = 0;
	}

	nat_ret = (ilb_nat_info_t *)&reply->sn_data;

	for (i = 0; i < kcmd->num_nat; i++) {
		ilb_nat_entry_t *nat;

		nat = &kcmd->entries[i];

		nat_ret->nat_proto = nat->proto;

		nat_ret->nat_in_local = nat->in_local;
		nat_ret->nat_in_global = nat->in_global;
		nat_ret->nat_out_local = nat->out_local;
		nat_ret->nat_out_global = nat->out_global;

		nat_ret->nat_in_local_port = nat->in_local_port;
		nat_ret->nat_in_global_port = nat->in_global_port;
		nat_ret->nat_out_local_port = nat->out_local_port;
		nat_ret->nat_out_global_port = nat->out_global_port;

		nat_ret++;
	}

	free(kcmd);
	return (ret);
}

/*
 * To show the kernel sticky table.
 *
 * cli: the client pointer making the request.
 * req_si: information about the show-persist request.
 * rbuf: reply buffer to be filled in.
 * rbufsz: reply buffer size.
 */
ilb_status_t
ilbd_show_sticky(void *cli, const ilb_comm_t *ic, uint32_t *rbuf,
    size_t *rbufsz)
{
	ilb_show_info_t *req_si = (ilb_show_info_t *)&ic->ic_data;
	ilb_list_sticky_cmd_t *kcmd;
	boolean_t start;
	size_t tmp_rbufsz, kbufsz;
	uint32_t max_num;
	ilb_status_t ret;
	int i;
	ilb_show_info_t *reply;
	ilb_persist_info_t *st_ret;

	/* For new client request, start from the beginning of the table. */
	if (sticky_cur_cli == NULL) {
		sticky_cur_cli = cli;
		start = B_TRUE;
	} else if (cli == sticky_cur_cli) {
		/*
		 * Another request from client.  If the client does not
		 * want to continue, reset the current client and reply OK.
		 */
		if (ic->ic_flags & ILB_COMM_END) {
			ilbd_show_sticky_cleanup();
			ilbd_reply_ok(rbuf, rbufsz);
			return (ILB_STATUS_OK);
		}
		start = B_FALSE;
	} else {
		/* A request is on-going, so reject a new client. */
		return (ILB_STATUS_INPROGRESS);
	}

	tmp_rbufsz = *rbufsz;
	ilbd_reply_ok(rbuf, rbufsz);
	reply = (ilb_show_info_t *)&((ilb_comm_t *)rbuf)->ic_data;

	/*
	 * Calculate the max number of ilb_persist_info_t can be fitted in the
	 * reply.
	 */
	*rbufsz += sizeof (ilb_show_info_t *);
	tmp_rbufsz -= *rbufsz;
	max_num = tmp_rbufsz / sizeof (ilb_persist_info_t);

	/*
	 * Calculate the exact number of entries we should request from kernel.
	 */
	max_num = min(req_si->sn_num, min(NUM_ENTRIES, max_num));

	kbufsz = max_num * sizeof (ilb_sticky_entry_t) +
	    offsetof(ilb_list_sticky_cmd_t, entries);
	if ((kcmd = malloc(kbufsz)) == NULL) {
		logdebug("ilbd_show_nat: malloc(cmd)");
		ilbd_reply_err(rbuf, rbufsz, ILB_STATUS_ENOMEM);
		return (ILB_STATUS_ENOMEM);
	}

	kcmd->cmd = ILB_LIST_STICKY_TABLE;
	kcmd->flags = start ? ILB_LIST_BEGIN : ILB_LIST_CONT;
	kcmd->num_sticky = max_num;
	if ((ret = do_ioctl(kcmd, kbufsz)) != ILB_STATUS_OK) {
		logperror("ilbd_show_nat: ioctl(ILB_LIST_STICKY_TABLE)");
		ilbd_reply_err(rbuf, rbufsz, ret);
		free(kcmd);
		return (ret);
	}

	reply->sn_num = kcmd->num_sticky;
	*rbufsz += reply->sn_num * sizeof (ilb_persist_info_t);

	if (kcmd->flags & ILB_LIST_END) {
		sticky_cur_cli = NULL;
	} else {
		/*
		 * ilbd_reply_ok() sets ic_flags to ILB_COMM_END by default.
		 * Need to clear it here.
		 */
		((ilb_comm_t *)rbuf)->ic_flags = 0;
	}

	st_ret = (ilb_persist_info_t *)&reply->sn_data;

	for (i = 0; i < kcmd->num_sticky; i++) {
		ilb_sticky_entry_t *st;

		st = &kcmd->entries[i];

		(void) strlcpy(st_ret->persist_rule_name, st->rule_name,
		    ILB_NAMESZ);
		st_ret->persist_req_addr = st->req_addr;
		st_ret->persist_srv_addr = st->srv_addr;
		st_ret++;
	}

	free(kcmd);
	return (ret);
}
