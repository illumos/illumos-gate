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

#include "cfga_fp.h"

/*
 * This file contains the entry points to the plug-in as defined in the
 * config_admin(3X) man page.
 */

/*
 * Set the version number
 */
int cfga_version = CFGA_HSL_V2;

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
	apid_t		apidt = {NULL};
	fpcfga_ret_t	ret;
	la_wwn_t	pwwn;
	char *value, *hw_option, *hw_option_p;
	char *fp_cs_hw_opts[] = {"disable_rcm", "force_update",
		"no_update", "unusable_SCSI_LUN", "unusable_FCP_dev", NULL};
	HBA_HANDLE	handle;
	HBA_PORTATTRIBUTES	portAttrs;
	int			portIndex;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	/* Check for super user priveleges */
	if (geteuid() != 0) {
		return (CFGA_PRIV);
	}

	/* Only configure and unconfigure operations are supported */
	if (state_change_cmd != CFGA_CMD_CONFIGURE &&
	    state_change_cmd != CFGA_CMD_UNCONFIGURE) {
		return (CFGA_OPNOTSUPP);
	}

	if ((ret = apidt_create(ap_id, &apidt, errstring)) != FPCFGA_OK) {
		return (err_cvt(ret));
	}

	if (options != NULL) {
		hw_option = calloc(1, strlen(options) + 1);
		(void) snprintf(hw_option, strlen(options) + 1, "%s", options);
		hw_option_p = hw_option;
		/* Use getsubopt() if more options get added */
		while (*hw_option_p != '\0') {
			switch (getsubopt(&hw_option_p, fp_cs_hw_opts,
			    &value)) {
			case OPT_DISABLE_RCM :
				apidt.flags |= FLAG_DISABLE_RCM;
				break;
			case OPT_FORCE_UPDATE_REP :
				apidt.flags |= FLAG_FORCE_UPDATE_REP;
				break;
			case OPT_NO_UPDATE_REP :
				apidt.flags |= FLAG_NO_UPDATE_REP;
				break;
			case OPT_REMOVE_UNUSABLE_FCP_DEV :
			case OPT_REMOVE_UNUSABLE_SCSI_LUN:
				if (state_change_cmd != CFGA_CMD_UNCONFIGURE) {
					cfga_err(errstring, 0, ERRARG_OPT_INVAL,
					    options, 0);
					S_FREE(hw_option);
					apidt_free(&apidt);
					return (CFGA_ERROR);
				}
				apidt.flags |= FLAG_REMOVE_UNUSABLE_FCP_DEV;
				break;
			default :
				/* process unknonw option. */
				cfga_err(errstring, 0, ERRARG_OPT_INVAL,
				    options, 0);
				S_FREE(hw_option);
				apidt_free(&apidt);
				return (CFGA_ERROR);
			}
		}
		S_FREE(hw_option);
	}

	if (options != NULL && apidt.flags == 0) {
		/* invalid option specified. */
		cfga_err(errstring, 0, ERRARG_OPT_INVAL, options, 0);
		apidt_free(&apidt);
		return (CFGA_ERROR);
	}

	if (apidt.dyncomp != NULL) {	/* Was there a port WWN passed ? */
		/*
		 * Yes - so change state of the particular device
		 *
		 * First Get the WWN in la_wwn_t form
		 */
		if (cvt_dyncomp_to_lawwn(apidt.dyncomp, &pwwn)) {
			cfga_err(errstring, 0, ERR_APID_INVAL, 0);
			return (err_cvt(FPCFGA_LIB_ERR));
		}

		if ((ret = findMatchingAdapterPort(apidt.xport_phys,
		    &handle, &portIndex, &portAttrs, errstring)) ==
		    FPCFGA_OK) {
			ret = dev_change_state(state_change_cmd, &apidt, &pwwn,
			    flags, errstring, handle, portAttrs);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
		}
	} else {
		/* Change state of all devices on FCA and the FCA itself */
		ret = fca_change_state(state_change_cmd, &apidt,
		    flags, errstring);
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
	int fca, expand, nelem;
	ldata_list_t *ldatalistp = NULL;
	apid_t apidt = {NULL};
	fpcfga_cmd_t cmd;
	fpcfga_ret_t ret;
	char *value, *hw_option, *hw_option_p;
	uint_t fp_flags = 0;
	char *fp_list_hw_opts[] = {"devinfo_force", "show_SCSI_LUN",
		"show_FCP_dev", NULL};

	if (errstring != NULL) {
		*errstring = NULL;
	}

	/* Check for super user privileges */
	if (geteuid() != 0) {
		return (CFGA_PRIV);
	}

	if (ap_id_list == NULL || nlistp == NULL) {
		return (CFGA_ERROR);
	}

	*ap_id_list = NULL;
	*nlistp = 0;

	if (options != NULL) {
		hw_option = calloc(1, strlen(options) + 1);
		(void) snprintf(hw_option, strlen(options) + 1, "%s", options);
		hw_option_p = hw_option;
		/* Use getsubopt() if more options get added */
		while (*hw_option_p != '\0') {
			switch (getsubopt(&hw_option_p, fp_list_hw_opts,
			    &value)) {
			case OPT_DEVINFO_FORCE :
				fp_flags |= FLAG_DEVINFO_FORCE;
				break;
			case OPT_FCP_DEV :
			case OPT_SHOW_SCSI_LUN:
				fp_flags |= FLAG_FCP_DEV;
				break;
			default :
				/* process unknonw option. */
				cfga_err(errstring, 0, ERRARG_OPT_INVAL,
				    options, 0);
				S_FREE(hw_option);
			return (CFGA_ERROR);
			}
		}
		S_FREE(hw_option);
	}

	/* if force_devinfo is specified check uid = 0 or not. */
	if (((fp_flags & FLAG_DEVINFO_FORCE) == FLAG_DEVINFO_FORCE) &&
	    (geteuid() != 0)) {
		return (CFGA_PRIV);
	}

	fca = 0;
	if (GET_DYN(ap_id) == NULL) {
		fca = 1;
	}

	expand = 0;
	if ((flags & CFGA_FLAG_LIST_ALL) == CFGA_FLAG_LIST_ALL) {
		expand = 1;
	}

	/*
	 * We expand published attachment points but not
	 * dynamic attachment points
	 */

	if (!fca) { /* Stat a single device - no expansion for devices */
		cmd = FPCFGA_STAT_FC_DEV;
	} else if (!expand) { /* Stat only the HBA */
		cmd = FPCFGA_STAT_FCA_PORT;
	} else { /* Expand HBA attachment point */
		cmd = FPCFGA_STAT_ALL;
	}

	ldatalistp = NULL;
	nelem = 0;

	if ((fp_flags & FLAG_FCP_DEV) == FLAG_FCP_DEV) {
		ret = do_list_FCP_dev(ap_id, fp_flags, cmd, &ldatalistp, &nelem,
		    errstring);
		if (ret != FPCFGA_OK) {
			list_free(&ldatalistp);
			return (err_cvt(ret));
		}
	} else {
		if ((ret = apidt_create(ap_id, &apidt, errstring))
		    != FPCFGA_OK) {
			return (err_cvt(ret));
		}

		if (options != NULL) {
			apidt.flags |= fp_flags;
		}

		ret = do_list(&apidt, cmd, &ldatalistp, &nelem, errstring);
		if (ret != FPCFGA_OK) {
			list_free(&ldatalistp);
			apidt_free(&apidt);
			return (err_cvt(ret));
		}
		apidt_free(&apidt);
	}

	assert(ldatalistp != NULL);

	if (list_ext_postprocess(&ldatalistp, nelem, ap_id_list, nlistp,
	    errstring) != FPCFGA_OK) {
		assert(*ap_id_list == NULL && *nlistp == 0);
		ret = FPCFGA_LIB_ERR;
	} else {
		assert(*ap_id_list != NULL && *nlistp == nelem);
		ret = FPCFGA_OK;
	}

	list_free(&ldatalistp);
	return (err_cvt(ret));
}


/*ARGSUSED*/
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	cfga_msg(msgp, MSG_HELP_HDR, MSG_HELP_USAGE, 0);

	return (CFGA_OK);

}

/*ARGSUSED*/
int
cfga_ap_id_cmp(const char *ap_id1, const char *ap_id2)
{
	int i = 0;
	long long ret;

	if (ap_id1 == ap_id2) {
		return (0);
	}

	if (ap_id1 == NULL || ap_id2 == NULL) {
		if (ap_id1 == NULL) {
			/* Return a negative value */
			return (0 - (uchar_t)ap_id2[0]);
		} else {
			return ((uchar_t)ap_id1[0]);
		}
	}

	/*
	 * Search for first different char
	 */
	while (ap_id1[i] == ap_id2[i] && ap_id1[i] != '\0')
		i++;

	if ((ap_id1[i] == '\0') &&
	    !(strncmp(&ap_id2[i], LUN_COMP_SEP, strlen(LUN_COMP_SEP)))) {
		return (0);
	} else if ((ap_id2[i] == '\0') &&
	    !(strncmp(&ap_id1[i], LUN_COMP_SEP, strlen(LUN_COMP_SEP)))) {
		return (0);
	}

	/*
	 * If one of the char is a digit, back up to where the
	 * number started, compare the number.
	 */
	if (isxdigit(ap_id1[i]) || isxdigit(ap_id2[i])) {
		while ((i > 0) && isxdigit(ap_id1[i - 1]))
			i--;

		if (isxdigit(ap_id1[i]) && isxdigit(ap_id2[i])) {
			ret = (strtoll((ap_id1 + i), NULL, 16)) -
			    (strtoll((ap_id2 + i), NULL, 16));
			if (ret > 0) {
				return (1);
			} else if (ret < 0) {
				return (-1);
			} else {
				return (0);
			}
		}
	}

	/* One of them isn't a number, compare the char */
	return (ap_id1[i] - ap_id2[i]);
}
