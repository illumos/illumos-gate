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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <macros.h>
#include <dirent.h>
#include <libgen.h>
#include <libdevinfo.h>
#define	CFGA_PLUGIN_LIB
#include <config_admin.h>
#include "ap.h"

#ifdef	__x86
#include <libscf_priv.h>

static int fastreboot_disabled;
#endif	/* __x86 */

static cfga_err_t
ap_suspend_check(apd_t *a, int cmd, int first, int last, int *suspend)
{
	int c;
	int rc;
	int skip;
	int check;

	skip = a->opts.skip;

	/*
	 * Check if any of the steps in the sequence
	 * may require a suspension of service and ask
	 * the user to confirm.
	 */
	for (check = 0, c = first; c <= last; c++)
		if (mask(c) & skip)
			continue;
		else if ((rc = ap_suspend_query(a, c, &check)) != CFGA_OK)
			return (rc);

	*suspend = check;

	/*
	 * If a suspend is required, ask for user confirmation.
	 * The force flag overrides the user confirmation.
	 */
	if (check && (!ap_getopt(a, OPT_FORCE)) && (!ap_confirm(a))) {
		ap_err(a, ERR_CMD_NACK, cmd);
		return (CFGA_NACK);
	}

	return (CFGA_OK);
}

#define	AP_SEQ_OK	0
#define	AP_SEQ_NULL	1
#define	AP_SEQ_FAIL	-1

/*
 * Sequence a cfgadm state change command into driver commands.
 * The rstate and ostate of the AP are needed at this point
 * in order to compute the proper sequence.
 */
static int
ap_seq_get(apd_t *a, int cmd, int *first, int *last)
{
	int done = 0;
	int f = CMD_NONE;
	int l = CMD_NONE;
	cfga_stat_t rs, os;

	ap_state(a, &rs, &os);

	switch (rs) {
	case CFGA_STAT_EMPTY:
		switch (os) {
		case CFGA_STAT_UNCONFIGURED:
			switch (cmd) {
			case CMD_UNCONFIGURE:
				done++;
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		break;
	case CFGA_STAT_DISCONNECTED:
		switch (os) {
		case CFGA_STAT_UNCONFIGURED:
			switch (cmd) {
			case CMD_DISCONNECT:
				/*
				 * skip the disconnect command since
				 * the rstate is already disconnected
				 */
				f = CMD_DISCONNECT;
				a->opts.skip |= mask(CMD_DISCONNECT);
				l = CMD_UNASSIGN;
				break;
			case CMD_UNCONFIGURE:
				done++;
				break;
			case CMD_CONNECT:
				f = CMD_ASSIGN;
				l = CMD_CONNECT;
				break;
			case CMD_CONFIGURE:
				f = CMD_ASSIGN;
				l = CMD_RCM_CAP_ADD;
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		break;
	case CFGA_STAT_CONNECTED:
		switch (os) {
		case CFGA_STAT_UNCONFIGURED:
			switch (cmd) {
			case CMD_CONNECT:
			case CMD_UNCONFIGURE:
				done++;
				break;
			case CMD_DISCONNECT:
				f = CMD_DISCONNECT;
				l = CMD_UNASSIGN;
				break;
			case CMD_CONFIGURE:
				f = CMD_CONFIGURE;
				l = CMD_RCM_CAP_ADD;
				break;
			default:
				break;
			}
			break;
		case CFGA_STAT_CONFIGURED:
			switch (cmd) {
			case CMD_CONNECT:
				done++;
				break;
			case CMD_DISCONNECT:
				f = CMD_SUSPEND_CHECK;
				l = CMD_UNASSIGN;
				break;
			case CMD_CONFIGURE:
				f = CMD_CONFIGURE;
				l = CMD_RCM_CAP_ADD;
				break;
			case CMD_UNCONFIGURE:
				f = CMD_SUSPEND_CHECK;
				l = CMD_RCM_CAP_NOTIFY;
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (f == CMD_NONE) {
		if (done)
			return (AP_SEQ_NULL);
		ap_err(a, ERR_TRANS_INVAL, cmd);
		return (AP_SEQ_FAIL);
	}

	*first = f;
	*last = l;

	DBG("ap_seq(%d, %d, %d, %p, %p) = (%d, %d)\n",
	    rs, os, cmd, (void *)first, (void *)last, f, l);

	return (AP_SEQ_OK);
}

#define	DBG_RECOVER_MSG(f, l) \
	DBG("Sequencing recovery: first = %s, last = %s\n", \
	ap_cmd_name(f), ap_cmd_name(l))

cfga_err_t
ap_seq_exec(apd_t *a, int cmd, int first, int last)
{
	int c;
	int skip;
	int suspend;
	int resume;
	cfga_err_t rc;
	int recover_f = CMD_NONE;	/* first recovery cmd */
	int recover_l = CMD_NONE;	/* last recovery cmd */


	suspend = 0;
	resume = 0;

	skip = a->opts.skip;

	/*
	 * The unassign step is skipped unless explicity requested
	 * either by a -x request or as an option to a disconnect
	 * request.
	 */
	if (cmd != CMD_UNASSIGN && ap_getopt(a, OPT_UNASSIGN) == 0)
		skip |= mask(CMD_UNASSIGN);

	/*
	 * Check for platform options
	 */
	rc = ap_platopts_check(a, first, last);

	if (rc != CFGA_OK) {
		goto done;
	}

	for (c = first; c <= last; c++) {
		if (mask(c) & skip) {
			ap_msg(a, MSG_SKIP, c, a->target);
			continue;
		}

		DBG("exec %s\n", ap_cmd_name(c));

		/*
		 * If the suspend operation does not
		 * succeed, resume any devices already
		 * suspended as well as the device on
		 * which the operation failed.
		 */
		switch (c) {
		case CMD_SUSPEND_CHECK:
			/*
			 * Check whether the user allows a suspend
			 * operation if the suspend is required.
			 * Next step is to allow RCM clients to
			 * interpose on the suspend operation.
			 */
			rc = ap_suspend_check(a, cmd,
			    first + 1, last, &suspend);
			break;
		case CMD_RCM_SUSPEND:
			if (suspend && ((rc = ap_rcm_ctl(a, c)) == CFGA_OK)) {
				/*
				 * Mark the fact that a suspend operation
				 * is required, and that RCM clients have
				 * allowed the suspend.
				 */
				ap_setopt(a, OPT_SUSPEND_OK);
				resume++;
			}
			break;
		case CMD_RCM_RESUME:
			if (resume) {
				(void) ap_rcm_ctl(a, c);
				resume--;
			}
			break;
		case CMD_RCM_OFFLINE:
		case CMD_RCM_CAP_DEL:
			rc = ap_rcm_ctl(a, c);
			break;
		case CMD_RCM_ONLINE:
		case CMD_RCM_CAP_ADD:
		case CMD_RCM_REMOVE:
		case CMD_RCM_CAP_NOTIFY:
			(void) ap_rcm_ctl(a, c);
			break;

#ifdef	__x86
		/*
		 * Disable fast reboot if a CPU/MEM/IOH hotplug event happens.
		 * Note: this is a temporary solution and will be revised when
		 * fast reboot can support CPU/MEM/IOH DR operations in the
		 * future.
		 *
		 * ACPI BIOS generates some static ACPI tables, such as MADT,
		 * SRAT and SLIT, to describe the system hardware configuration
		 * on power-on. When a CPU/MEM/IOH hotplug event happens, those
		 * static tables won't be updated and will become stale.
		 *
		 * If we reset the system by fast reboot, BIOS will have no
		 * chance to regenerate those staled static tables. Fast reboot
		 * can't tolerate such inconsistency between staled ACPI tables
		 * and real hardware configuration yet.
		 *
		 * A temporary solution is introduced to disable fast reboot if
		 * CPU/MEM/IOH hotplug event happens. This solution should be
		 * revised when fast reboot is enhanced to support CPU/MEM/IOH
		 * DR operations.
		 */
		case CMD_ASSIGN:
		case CMD_POWERON:
		case CMD_POWEROFF:
		case CMD_UNASSIGN:
			if (!fastreboot_disabled &&
			    scf_fastreboot_default_set_transient(B_FALSE) ==
			    SCF_SUCCESS) {
				fastreboot_disabled = 1;
			}
#endif	/* __x86 */
			/* FALLTHROUGH */

		default:
			rc = ap_ioctl(a, c);
			break;
		}

		if (rc != CFGA_OK)
			break;

	}
done:

	if (resume)
		(void) ap_rcm_ctl(a, CMD_RCM_RESUME);

	/*
	 * Check if any operations failed. If so, attempt to rollback
	 * to previously known states.
	 * Note: The rollback is currently limited to RCM operations.
	 */
	if (rc != CFGA_OK) {
		if (c == CMD_UNCONFIGURE ||
		    c == CMD_RCM_OFFLINE ||
		    c == CMD_RCM_CAP_DEL) {
			DBG("ap_seq_exec: %s failed\n", ap_cmd_name(c));

			switch (c) {
			case CMD_UNCONFIGURE:
				/*
				 * If the unconfigure operation fails, perform
				 * an RCM_ONLINE and RCM_CAP_NOTIFY only. This
				 * keeps RCM clients consistent with the domain.
				 */
				recover_f = CMD_RCM_ONLINE;
				recover_l = CMD_RCM_ONLINE;
				DBG_RECOVER_MSG(recover_f, recover_l);
				(void) ap_seq_exec(a, cmd, recover_f,
				    recover_l);

				recover_f = CMD_RCM_CAP_NOTIFY;
				recover_l = CMD_RCM_CAP_NOTIFY;
				DBG_RECOVER_MSG(recover_f, recover_l);
				(void) ap_seq_exec(a, cmd, recover_f,
				    recover_l);
				break;
			case CMD_RCM_OFFLINE:
				recover_f = CMD_RCM_ONLINE;
				recover_l = CMD_RCM_CAP_ADD;
				DBG_RECOVER_MSG(recover_f, recover_l);
				(void) ap_seq_exec(a, cmd, recover_f,
				    recover_l);
				break;
			case CMD_RCM_CAP_DEL:
				recover_f = CMD_RCM_CAP_ADD;
				recover_l = CMD_RCM_CAP_ADD;
				DBG_RECOVER_MSG(recover_f, recover_l);
				(void) ap_seq_exec(a, cmd, recover_f,
				    recover_l);
				break;
			default:
				break;
			}

			DBG("recovery complete!\n");
		}
	}
	return (rc);
}

cfga_err_t
ap_cmd_exec(apd_t *a, int cmd)
{
	return (ap_seq_exec(a, cmd, cmd, cmd));
}

cfga_err_t
ap_cmd_seq(apd_t *a, int cmd)
{
	int first, last;
	cfga_err_t rc;

	switch (ap_seq_get(a, cmd, &first, &last)) {
	case AP_SEQ_OK:
		rc = ap_seq_exec(a, cmd, first, last);
		break;
	case AP_SEQ_NULL:
		rc = CFGA_OK;
		break;
	case AP_SEQ_FAIL:
	default:
		rc = CFGA_LIB_ERROR;
		break;
	}

	return (rc);
}
