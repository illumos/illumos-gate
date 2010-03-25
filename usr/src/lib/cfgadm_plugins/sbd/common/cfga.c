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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <macros.h>
#include <libdevinfo.h>
#define	CFGA_PLUGIN_LIB
#include <config_admin.h>
#include "ap.h"

int cfga_version = CFGA_HSL_V2;

/*ARGSUSED*/
cfga_err_t
cfga_change_state(
	cfga_cmd_t cfga_cmd,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int cmd;
	const char *name;
	apd_t *a;
	cfga_err_t rc;

	if ((rc = ap_state_cmd(cfga_cmd, &cmd)) != CFGA_OK)
		return (rc);

	rc = CFGA_LIB_ERROR;

	if ((a = apd_alloc(ap_id, flags, errstring, msgp, confp)) == NULL)
		return (rc);

	name = ap_cmd_name(cmd);

	if ((rc = ap_cmd_parse(a, name, options, NULL)) == CFGA_OK)
		rc = ap_cmd_seq(a, cmd);

	apd_free(a);

	return (rc);
}

/*
 * Check if this is a valid -x command.
 */
static int
private_func(const char *function)
{
	char **f;
	static char *
	private_funcs[] = {
		"assign",
		"unassign",
		"poweron",
		"poweroff",
		"passthru",
		"errtest",
		NULL
	};

	for (f = private_funcs; *f != NULL; f++)
		if (strcmp(*f, function) == 0)
			break;

	return (*f == NULL ? CFGA_INVAL : CFGA_OK);
}

/*ARGSUSED*/
cfga_err_t
cfga_private_func(
	const char *function,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int cmd;
	apd_t *a;
	cfga_err_t rc;

	DBG("cfga_private_func(%s)\n", ap_id);

	rc = CFGA_LIB_ERROR;

	if ((a = apd_alloc(ap_id, flags, errstring, msgp, confp)) == NULL)
		return (rc);
	else if ((rc = private_func(function)) != CFGA_OK)  {
		ap_err(a, ERR_CMD_INVAL, function);
		goto done;
	} else if ((rc = ap_cmd_parse(a, function, options, &cmd)) != CFGA_OK)
		goto done;
	else if (cmd == CMD_ERRTEST)
		rc = ap_test_err(a, options);
	else
		rc = ap_cmd_exec(a, cmd);
done:
	apd_free(a);
	return (rc);
}


/*ARGSUSED*/
cfga_err_t
cfga_test(
	const char *ap_id,
	const char *options,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int cmd;
	const char *f;
	apd_t *a;
	cfga_err_t rc;

	DBG("cfga_test(%s)\n", ap_id);

	f = "test";
	rc = CFGA_LIB_ERROR;

	/*
	 * A test that is not sequenced by a change
	 * state operation should be forced.
	 */
	flags |= CFGA_FLAG_FORCE;

	if ((a = apd_alloc(ap_id, flags, errstring, msgp, NULL)) == NULL)
		return (rc);
	else if ((rc = ap_cmd_parse(a, f, options, &cmd)) != CFGA_OK)
		goto done;
	else
		rc = ap_cmd_exec(a, cmd);
done:
	apd_free(a);
	return (rc);
}

/*ARGSUSED*/
cfga_err_t
cfga_list_ext(
	const char *ap_id,
	cfga_list_data_t **ap_id_list,
	int *nlist,
	const char *options,
	const char *listopts,
	char **errstring,
	cfga_flags_t flags)
{
	int i;
	int apcnt;
	const char *f;
	apd_t *a;
	size_t szl, szp;
	cfga_list_data_t *aplist, *ap;
	cfga_err_t rc;

	rc = CFGA_LIB_ERROR;

	aplist = NULL;
	f = ap_cmd_name(CMD_STATUS);

	DBG("cfga_list_ext(%s %x)\n", ap_id, flags);

	if ((a = apd_alloc(ap_id, flags, errstring, NULL, NULL)) == NULL)
		return (rc);
	else if ((rc = ap_cmd_parse(a, f, options, NULL)) != CFGA_OK)
		goto done;

	apcnt = ap_cnt(a);

	DBG("apcnt=%d\n", apcnt);

	if ((aplist = calloc(apcnt, sizeof (*aplist))) == NULL) {
		rc = CFGA_LIB_ERROR;
		ap_err(a, ERR_CMD_FAIL, CMD_STATUS);
		goto done;
	}

	ap = aplist;
	szl = sizeof (ap->ap_log_id);
	szp = sizeof (ap->ap_phys_id);

	/*
	 * Initialize the AP specified directly by the caller.
	 * The target ID for the 0th element already includes
	 * the (potential) dynamic portion. The dynamic portion
	 * does need to be appended to the path to form the
	 * physical apid for components.
	 */
	(void) strncpy(ap->ap_log_id, a->target, szl - 1);
	(void) snprintf(ap->ap_phys_id, szp, "%s%s%s", a->path,
	    a->tgt != AP_BOARD ? "::" : "",
	    a->tgt != AP_BOARD ? a->cid : "");


	DBG("ap_phys_id=%s ap_log_id=%s\n", ap->ap_phys_id, ap->ap_log_id);

	if (a->tgt == AP_BOARD) {

		ap_init(a, ap++);

		/*
		 * Initialize the components, if any.
		 */
		for (i = 0; i < apcnt - 1; i++, ap++) {
			char dyn[MAXPATHLEN];

			ap_cm_id(a, i, dyn, sizeof (dyn));

			(void) snprintf(ap->ap_log_id, szl, "%s::%s",
			    a->target, dyn);
			(void) snprintf(ap->ap_phys_id, szp, "%s::%s",
			    a->path, dyn);

			ap_cm_init(a, ap, i);

			DBG("ap_phys_id=%s ap_log_id=%s\n",
			    ap->ap_phys_id, ap->ap_log_id);
		}

	} else
		ap_cm_init(a, ap, 0);

	apd_free(a);
	*ap_id_list = aplist;
	*nlist = apcnt;
	return (CFGA_OK);

done:
	s_free(aplist);
	apd_free(a);
	return (rc);
}

/*ARGSUSED*/
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	return (ap_help(msgp, options, flags));
}


/*
 * cfga_ap_id_cmp -- use default_ap_id_cmp() in libcfgadm
 */
