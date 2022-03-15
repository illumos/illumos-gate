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

#include "cfga_scsi.h"

/*
 * This file contains the entry points to the plug-in as defined in the
 * config_admin(3CFGADM) man page.
 */

/*
 * Set the version number
 */
int cfga_version = CFGA_HSL_V2;

/*
 * For debugging - higher values increase verbosity
 */
int _scfga_debug = 0;

#pragma init(_cfgadm_scsi_init)

static void
_cfgadm_scsi_init()
{
	char *tstr;

	if (tstr = getenv("SCFGA_DEBUG")) {
		_scfga_debug = atoi(tstr);
	}
}

/*ARGSUSED*/
cfga_err_t
cfga_change_state(
	cfga_cmd_t state_change_cmd,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	apid_t apidt = {NULL};
	scfga_ret_t ret;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	/*
	 * All sub-commands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		return (CFGA_PRIV);
	}

	if (options != NULL && strcmp(options, OPT_DISABLE_RCM) != 0) {
		cfga_err(errstring, 0, ERRARG_OPT_INVAL, options, 0);
		return (CFGA_ERROR);
	}

	if ((ret = apidt_create(ap_id, &apidt, errstring)) != SCFGA_OK) {
		return (err_cvt(ret));
	}

	if (options != NULL)
		apidt.flags |= FLAG_DISABLE_RCM;

	/* A dynamic component indicates a device, else it is the bus */
	if (apidt.dyncomp != NULL) {
		ret = dev_change_state(state_change_cmd, &apidt, flags,
		    errstring);
	} else {
		ret = bus_change_state(state_change_cmd, &apidt, confp, flags,
		    errstring);
	}

	apidt_free(&apidt);
	return (err_cvt(ret));
}

/*ARGSUSED*/
cfga_err_t
cfga_private_func(
	const char *func,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	apid_t apidt = {NULL};
	prompt_t args = {NULL};
	scfga_ret_t ret;

	if (errstring != NULL)
		*errstring = NULL;

	if (geteuid() != 0) {
		return (CFGA_PRIV);
	}

	if (func == NULL) {
		return (CFGA_ERROR);
	}

	if (options != NULL && strcmp(options, OPT_DISABLE_RCM) != 0) {
		cfga_err(errstring, 0, ERRARG_OPT_INVAL, options, 0);
		return (CFGA_ERROR);
	}

	if ((ret = apidt_create(ap_id, &apidt, errstring)) != SCFGA_OK) {
		return (err_cvt(ret));
	}

	if (apidt.dyntype == PATH_APID) {
		return (CFGA_OPNOTSUPP);
	}

	if (options != NULL)
		apidt.flags |= FLAG_DISABLE_RCM;

	args.confp = confp;
	args.msgp = msgp;

	/*
	 * Process command
	 */
	ret = invoke_cmd(func, &apidt, &args, flags, errstring);

	apidt_free(&apidt);
	return (err_cvt(ret));
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
	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (geteuid() != 0) {
		return (CFGA_PRIV);
	}

	return (CFGA_OPNOTSUPP);
}

/*ARGSUSED*/
cfga_err_t
cfga_list_ext(
	const char *ap_id,
	cfga_list_data_t **ap_id_list,
	int *nlistp,
	const char *options,
	const char *listopts,
	char **errstring,
	cfga_flags_t flags)
{
	int hba, expand, nelem;
	ldata_list_t *llp = NULL;
	apid_t apidt = {NULL};
	scfga_cmd_t cmd;
	scfga_ret_t ret;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (ap_id_list == NULL || nlistp == NULL) {
		return (CFGA_ERROR);
	}

	*ap_id_list = NULL;
	*nlistp = 0;

	/*
	 * There is no RCM involvement in "list" operations.
	 * The only supported option is OPT_USE_DIFORCE.
	 */
	if (options != NULL && strcmp(options, OPT_USE_DIFORCE) != 0) {
		cfga_err(errstring, 0, ERRARG_OPT_INVAL, options, 0);
		return (CFGA_ERROR);
	}

	hba = 0;
	if (GET_DYN(ap_id) == NULL) {
		hba = 1;
	}

	expand = 0;
	if ((flags & CFGA_FLAG_LIST_ALL) == CFGA_FLAG_LIST_ALL) {
		expand = 1;
	}

	/*
	 * We expand published attachment points but not
	 * dynamic attachment points
	 */

	if (!hba) { /* Stat a single device - no expansion for devices */
		cmd = SCFGA_STAT_DEV;
	} else if (!expand) { /* Stat only the HBA */
		cmd = SCFGA_STAT_BUS;
	} else { /* Expand HBA attachment point */
		cmd = SCFGA_STAT_ALL;
	}

	if ((ret = apidt_create(ap_id, &apidt, errstring)) != SCFGA_OK) {
		return (err_cvt(ret));
	}

	/*
	 * Currently only 1 option supported
	 */
	if (options)
		apidt.flags |= FLAG_USE_DIFORCE;

	llp = NULL;
	nelem = 0;

	ret = do_list(&apidt, cmd, &llp, &nelem, errstring);
	if (ret != SCFGA_OK) {
		goto out;
	}

	assert(llp != NULL);

	if (list_ext_postprocess(&llp, nelem, ap_id_list, nlistp,
	    errstring) != SCFGA_OK) {
		assert(*ap_id_list == NULL && *nlistp == 0);
		ret = SCFGA_LIB_ERR;
	} else {
		assert(*ap_id_list != NULL && *nlistp == nelem);
		ret = SCFGA_OK;
	}

	/* FALLTHROUGH */
out:
	list_free(&llp);
	apidt_free(&apidt);
	return (err_cvt(ret));
}


/*ARGSUSED*/
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	cfga_msg(msgp, MSG_HELP_HDR, MSG_HELP_USAGE, 0);

	return (CFGA_OK);
}

/*
 * cfga_ap_id_cmp -- use default_ap_id_cmp() in libcfgadm
 */
