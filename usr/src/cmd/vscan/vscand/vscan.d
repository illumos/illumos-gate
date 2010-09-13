#!/usr/sbin/dtrace -s
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
#pragma D option flowindent
*/

/*
 *** vscan kernel pseudo driver ***
 */

/*
 * vscan_svc.c
 */
sdt:vscan::vscan-req-counts
{
	printf("%s reql: %d, node: %d, taskq: %d",
	    stringof(arg0), 
	    ((vscan_svc_counts_t *)arg1)->vsc_reql,
	    ((vscan_svc_counts_t *)arg1)->vsc_node,
	    ((vscan_svc_counts_t *)arg1)->vsc_tq);
}

sdt:vscan::vscan-svc-state-violation
{
	printf("%d %s", arg0,
		arg0 == 0 ? "UNCONFIG" :
		arg0 == 1 ? "IDLE" :
		arg0 == 2 ? "ENABLED" :
		arg0 == 3 ? "DISABLED" : "UNKNOWN");
}

sdt:vscan::vscan-scan-timeout
{
	printf("idx: %d, seqnum: %d - %s",
	    ((vscan_req_t *)arg0)->vsr_idx,
		((vscan_req_t *)arg0)->vsr_seqnum,
		stringof(((vscan_req_t *)arg0)->vsr_vp->v_path));
}

sdt:vscan::vscan-scan-file
{
	printf("%s (%s)", stringof(arg0), arg1 ? "async" : "sync");
}

sdt:vscan::vscan-exempt-filesize
{
	printf("%s EXEMPT (%s)", stringof(arg0), arg1 ? "DENY" : "ALLOW");
}

sdt:vscan::vscan-type-match
{
	printf("ext: %s matched: %s", stringof(arg0), stringof(arg1));
}

sdt:vscan::vscan-exempt-filetype
{
	printf("%s EXEMPT", stringof(arg0));
}

sdt:vscan::vscan-getattr
{
	printf("%s, m: %d, q: %d, scanstamp: %s",
		stringof(((vscan_svc_node_t *)arg0)->vsn_req->vsr_vp->v_path),
		((vscan_svc_node_t *)arg0)->vsn_modified,
		((vscan_svc_node_t *)arg0)->vsn_quarantined,
		stringof(((vscan_svc_node_t *)arg0)->vsn_scanstamp));
}

sdt:vscan::vscan-setattr
{
	/* XAT_AV_QUARANTINED */
	printf("%s", (arg1 & 0x400) == 0 ? "" :
	    ((vscan_svc_node_t *)arg0)->vsn_quarantined ? "q: 1, " : "q: 0, ");

	/* XAT_AV_MODIFIED */
	printf("%s", (arg1 & 0x800) == 0 ? "" :
	    ((vscan_svc_node_t *)arg0)->vsn_modified ? "m: 1, " : "m: 0, ");

	/* XAT_AV_SCANSTAMP */
	printf("%s", (arg1 & 0x1000) == 0 ? "" : "scanstamp: ");
	printf("%s", (arg1 & 0x1000) == 0 ? "" :
	    stringof(((vscan_svc_node_t *)arg0)->vsn_scanstamp));
}


sdt:vscan::vscan-mtime-changed
{
	printf("%s",
		stringof(((vscan_svc_node_t *)arg0)->vsn_req->vsr_vp->v_path));
}


sdt:vscan::vscan-result
{
	printf("idx: %d, seqnum: %d, VS_STATUS_%s - VS_ACCESS_%s",
		arg0, arg1,
	    arg2 == 0 ? "UNDEFINED" :
	    arg2 == 1 ? "NO_SCAN" :
	    arg2 == 2 ? "ERROR" :
	    arg2 == 3 ? "CLEAN" :
	    arg2 == 4 ? "INFECTED" :
	    arg2 == 5 ? "SCANNING" : "XXX unknown",
	    arg3 == 0 ? "UNDEFINED" :
	    arg3 == 1 ? "ALLOW" : "DENY");
}

/* insert request into request list */
fbt:vscan:vscan_svc_reql_insert:entry
{
	printf("%s", stringof(args[0]->v_path));
}
fbt:vscan:vscan_svc_reql_insert:return
/args[1] != 0/
{
	printf("seqnum %d %s", args[1]->vsr_seqnum,
	    stringof(args[1]->vsr_vp->v_path));
}
fbt:vscan:vscan_svc_reql_insert:return
/args[1] == 0/
{
	printf("request list full");
}
/* insert request into scan table */
fbt:vscan:vscan_svc_insert_req:entry
{
	printf("seqnum: %d - %s",
	    args[0]->vsr_seqnum, stringof(args[0]->vsr_vp->v_path));
}
fbt:vscan:vscan_svc_insert_req:return
{
	printf("idx: %d", args[1]);
}
/* remove request from request list and  scan table and delete it*/
fbt:vscan:vscan_svc_delete_req:entry
{
	printf("idx: %d, seqnum: %d - %s",
	    args[0]->vsr_idx, args[0]->vsr_seqnum,
		stringof(args[0]->vsr_vp->v_path));
}

fbt:vscan:vscan_svc_delete_req:return,
fbt:vscan:vscan_svc_reql_handler:entry,
fbt:vscan:vscan_svc_reql_handler:return
{
}

fbt:vscan:vscan_svc_taskq_callback:entry,
fbt:vscan:vscan_svc_do_scan:entry
{
	printf("idx: %d, seqnum: %d - %s",
	    ((vscan_req_t *)(args[0]))->vsr_idx,
		((vscan_req_t *)(args[0]))->vsr_seqnum,
		stringof(((vscan_req_t *)(args[0]))->vsr_vp->v_path));
}
fbt:vscan:vscan_svc_scan_complete:entry
{
	printf("idx: %d, seqnum: %d, state: %s - %s",
	    args[0]->vsr_idx, args[0]->vsr_seqnum,
		args[0]->vsr_state == 0 ? "INIT" :
		args[0]->vsr_state == 1 ? "QUEUED" :
		args[0]->vsr_state == 2 ? "IN_PROGRESS" :
		args[0]->vsr_state == 3 ? "SCANNING" :
		args[0]->vsr_state == 4 ? "ASYNC_COMPLETE" :
		args[0]->vsr_state == 5 ? "COMPLETE" : "UNKNOWN",
		stringof(args[0]->vsr_vp->v_path));
}

fbt:vscan:vscan_svc_taskq_callback:return,
fbt:vscan:vscan_svc_do_scan:return,
fbt:vscan:vscan_svc_scan_complete:return
{
}

sdt:vscan::vscan-abort
{
	printf("idx: %d, seqnum: %d - %s",
	    ((vscan_req_t *)(arg0))->vsr_idx,
		((vscan_req_t *)(arg0))->vsr_seqnum,
		stringof(((vscan_req_t *)(arg0))->vsr_vp->v_path));
}

fbt:vscan:vscan_svc_enable:entry,
fbt:vscan:vscan_svc_enable:return,
fbt:vscan:vscan_svc_disable:entry,
fbt:vscan:vscan_svc_disable:return,
fbt:vscan:vscan_svc_configure:entry,
fbt:vscan:vscan_svc_configure:return
{
}

/*
 * vscan_door.c
 */
fbt:vscan:vscan_door_open:entry,
fbt:vscan:vscan_door_open:return,
fbt:vscan:vscan_door_close:entry,
fbt:vscan:vscan_door_close:return
{
}

fbt:vscan:vscan_door_scan_file:entry
{
	printf("idx: %d, seqnum: %d - %s",
	    args[0]->vsr_idx, args[0]->vsr_seqnum, args[0]->vsr_path);
}
fbt:vscan:vscan_door_scan_file:return
{
	printf("VS_STATUS_%s",
	    args[1] == 0 ? "UNDEFINED" :
	    args[1] == 1 ? "NO_SCAN" :
	    args[1] == 2 ? "ERROR" :
	    args[1] == 3 ? "CLEAN" :
	    args[1] == 4 ? "INFECTED" :
	    args[1] == 5 ? "SCANNING" : "XXX unknown");
}


/*
 * vscan_drv.c
 */
sdt:vscan::vscan-drv-state-violation
{
	printf("%d %s", arg0,
		arg0 == 0 ? "UNCONFIG" :
		arg0 == 1 ? "IDLE" :
		arg0 == 2 ? "CONNECTED" :
		arg0 == 3 ? "ENABLED" : 
		arg0 == 4 ? "DELAYED_DISABLE" : "UNKNOWN");
}

sdt:vscan::vscan-minor-node
{
	printf("vscan%d %s", arg0, arg1 != 0 ? "created" : "error");
}

/* unprivileged vscan driver access attempt */
sdt:vscan::vscan-priv
/arg0 != 0/
{
	printf("vscan driver access attempt by unprivileged process");
}

/* daemon-driver synchronization */
sdt:vscan::vscan-reconnect
{
}

fbt:vscan:vscan_drv_open:entry
/ *(int *)args[0] == 0/
{
	printf("vscan daemon attach");
}

fbt:vscan:vscan_drv_close:entry
/ (int)args[0] == 0/
{
	printf("vscan daemon detach");
}

fbt:vscan:vscan_drv_ioctl:entry
/ (int)args[0] == 0/
{
	printf("vscan daemon ioctl %d %s", args[1],
		args[1] == 1 ? "ENABLE" :
		args[1] == 2 ? "DISABLE" :
		args[1] == 3 ? "CONFIG" :
		args[1] == 4 ? "RESULT" :
		args[1] == 5 ? "MAX FILES" : "unknown");
}

fbt:vscan:vscan_drv_delayed_disable:entry,
fbt:vscan:vscan_drv_delayed_disable:return,
fbt:vscan:vscan_drv_attach:entry,
fbt:vscan:vscan_drv_detach:entry
{
}

fbt:vscan:vscan_drv_attach:return,
fbt:vscan:vscan_drv_detach:return
{
	printf("%s", args[1] ? "DDI_FAILURE" : "DDI_SUCCESS");
}

fbt:vscan:vscan_drv_in_use:return
{
	printf("%s", args[1] ? "TRUE" : "FALSE");
}


/* file access */

/*
fbt:vscan:vscan_drv_open:entry
/ *(int *)args[0] != 0/
{
	printf("%d", *(int *)args[0]);
}

fbt:vscan:vscan_drv_close:entry,
fbt:vscan:vscan_drv_read:entry
/ (int)args[0] != 0/
{
	printf("%d", (int)args[0]);
}
*/


/*
 *** vscan daemon - vscand ***
 */

pid$target::vs_svc_init:entry
{
	printf("Max concurrent scan requests from kernel: %d", arg1);
}

pid$target::vs_svc_init:return
{
}


pid$target::vs_door_scan_req:entry,
pid$target::vs_svc_scan_file:entry,
pid$target::vs_svc_queue_scan_req:entry,
pid$target::vs_svc_async_scan:entry,
pid$target::vs_eng_scanstamp_current:entry,
pid$target::vs_icap_scan_file:entry
{
}

pid$target::vs_svc_queue_scan_req:return,
pid$target::vs_svc_async_scan:return
{
}

pid$target::vs_svc_scan_file:return
{
	printf("VS_STATUS_%s",
	    arg1 == 0 ? "UNDEFINED" :
	    arg1 == 1 ? "NO_SCAN" :
	    arg1 == 2 ? "ERROR" :
	    arg1 == 3 ? "CLEAN" :
	    arg1 == 4 ? "INFECTED" :
	    arg1 == 5 ? "SCANNING" : "XXX unknown");
}

pid$target::vs_eng_scanstamp_current:return
{
	printf("%sCURRENT", arg1 == 0 ? "NOT " : "");
}

pid$target::vs_icap_scan_file:return
{
	printf("%d VS_RESULT_%s", (int)arg1,
	    (int)arg1 == 0 ? "UNDEFINED" :
	    (int)arg1 == 1 ? "CLEAN" :
	    (int)arg1 == 2 ? "CLEANED" :
	    (int)arg1 == 3 ? "FORBIDDEN" : "(SE)_ERROR");
}

pid$target::vs_stats_set:entry
{
	printf("%s", (arg0 == 1) ? "CLEAN" :
		(arg0 == 2) ? "CLEANED" :
		(arg0 == 3) ? "QUARANTINE" : "ERROR");
}

pid$target::vs_stats_set:return
{
}

/* get engine connection */
pid$target::vs_eng_get:entry,
pid$target::vs_eng_connect:entry,
pid$target::vs_eng_release:entry,
pid$target::vs_eng_release:return
{
}
pid$target::vs_eng_get:return,
pid$target::vs_eng_connect:return
{
	printf("%s", arg1 == 0 ? "success" : "error");
}

/* engine errors */
pid$target::vs_eng_set_error:entry
/ arg1 == 1 /
{
	printf("scan engine error");
}

/* configuration */
pid$target::vscand_cfg_init:entry,
pid$target::vscand_cfg_fini:entry,
pid$target::vscand_cfg_init:return,
pid$target::vscand_cfg_fini:return,
pid$target::vscand_cfg_handler:entry,
pid$target::vscand_cfg_handler:return
{
}

pid$target::vscand_dtrace_gen:entry
{
	printf("maxsize: %s action: %s\n",
		copyinstr(arg0), (arg1 == 1) ? "allow" : "deny");
	printf("types: %s\n", copyinstr(arg2));
	printf("log: %s\n", copyinstr(arg3));
}
pid$target::vscand_dtrace_eng:entry
{
	printf("\n%s %s \nhost: %s \nport: %d \nmax connections: %d\n",
		copyinstr(arg0), (arg1 == 1) ? "enabled" : "disabled",
		copyinstr(arg2), arg3, arg4);
}



/* shutdown */
pid$target::vscand_sig_handler:entry
{
	printf("received signal %d", arg0);
}
pid$target::vscand_sig_handler:return,
pid$target::vscand_fini:entry,
pid$target::vscand_fini:return,
pid$target::vscand_kernel_disable:entry,
pid$target::vscand_kernel_disable:return,
pid$target::vscand_kernel_unbind:entry,
pid$target::vscand_kernel_unbind:return,
pid$target::vscand_kernel_result:entry,
pid$target::vscand_kernel_result:return,
pid$target::vs_svc_terminate:entry,
pid$target::vs_svc_terminate:return,
pid$target::vs_eng_fini:entry,
pid$target::vs_eng_fini:return,
pid$target::vs_eng_close_connections:entry,
pid$target::vs_eng_close_connections:return
{
}

/* vs_icap.c */

/* trace entry and exit (inc status) */
pid$target::vs_icap_option_request:entry,
pid$target::vs_icap_send_option_req:entry,
pid$target::vs_icap_read_option_resp:entry,
pid$target::vs_icap_respmod_request:entry,
pid$target::vs_icap_may_preview:entry,
pid$target::vs_icap_send_preview:entry,
pid$target::vs_icap_send_respmod_hdr:entry,
pid$target::vs_icap_read_respmod_resp:entry
{
}

pid$target::vs_icap_option_request:return,
pid$target::vs_icap_send_option_req:return,
pid$target::vs_icap_read_option_resp:return,
pid$target::vs_icap_respmod_request:return,
pid$target::vs_icap_send_preview:return,
pid$target::vs_icap_send_respmod_hdr:return,
pid$target::vs_icap_read_respmod_resp:return
{
	printf("%s", (int)arg1 < 0 ? "error" : "success");
}

pid$target::vs_icap_may_preview:return
{
	printf("TRANSFER %s", arg1 == 1 ? "PREVIEW" : "COMPLETE");
}

/* trace failures only  - these functions return -1 on failure */
pid$target::vs_icap_read_resp_code:return,
pid$target::vs_icap_read_hdr:return,
pid$target::vs_icap_send_termination:return,
pid$target::vs_icap_write:return,
pid$target::vs_icap_set_scan_result:return,
pid$target::vs_icap_read_encap_hdr:return,
pid$target::vs_icap_read_encap_data:return,
pid$target::vs_icap_read_resp_body:return,
pid$target::vs_icap_read_body_chunk:return,
pid$target::vs_icap_read:return,
pid$target::vs_icap_readline:return,
pid$target::vs_icap_send_chunk:return,
pid$target::gethostname:return
/(int)arg1 == -1/
{
	printf("error");
}

/* trace failures only  - these functions return 1 on success */
pid$target::vs_icap_opt_value:return,
pid$target::vs_icap_opt_ext:return,
pid$target::vs_icap_resp_infection:return,
pid$target::vs_icap_resp_virus_id:return,
pid$target::vs_icap_resp_violations:return,
pid$target::vs_icap_resp_violation_rec:return,
pid$target::vs_icap_resp_istag:return,
pid$target::vs_icap_resp_encap:return
/arg1 != 1/
{
	printf("error");
}

pid$target::write:return,
pid$target::read:return,
pid$target::open:return,
pid$target::calloc:return
/arg1 <= 0/
{
	printf("error");
}
/*
pid$target::recv:return,
*/
