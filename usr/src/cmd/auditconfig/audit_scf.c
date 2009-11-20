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

/* auditd smf(5)/libscf(3LIB) interface - set and display audit parameters */
#include <audit_scf.h>
#include <auditconfig_impl.h>

/* propvec array must be NULL terminated */
extern scf_propvec_t    prop_vect[MAX_PROPVECS + 1];

static boolean_t set_val_scf(scf_propvec_t *, char *);

/*
 * do_getqbufsz_scf() - get the qbufsz audit service property value
 */
boolean_t
do_getqbufsz_scf(size_t *cval)
{
	uint64_t	cval_l;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QBUFSZ, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	if (!get_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL)) {
		return (B_FALSE);
	}

	*cval = (size_t)cval_l;

	return (B_TRUE);
}

/*
 * do_getqdelay_scf() - get the qdelay audit service property value
 */
boolean_t
do_getqdelay_scf(clock_t *cval)
{
	uint64_t	cval_l;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QDELAY, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	if (!get_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL)) {
		return (B_FALSE);
	}

	*cval = (clock_t)cval_l;

	return (B_TRUE);
}

/*
 * do_getqhiwater_scf() - get the qhiwater audit service property value
 */
boolean_t
do_getqhiwater_scf(size_t *cval)
{
	uint64_t	cval_l;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QHIWATER, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	if (!get_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL)) {
		return (B_FALSE);
	}

	*cval = (size_t)cval_l;

	return (B_TRUE);
}

/*
 * do_getqlowater_scf() - get the qlowater audit service property value
 */
boolean_t
do_getqlowater_scf(size_t *cval)
{
	uint64_t	cval_l;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QLOWATER, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	if (!get_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL)) {
		return (B_FALSE);
	}

	*cval = (size_t)cval_l;

	return (B_TRUE);
}

/*
 * do_setpolicy_scf() - sets the policy flags in audit service configuration
 */
boolean_t
do_setpolicy_scf(uint32_t policy)
{
	int		i;
	char		*cur_policy_str;
	scf_propvec_t	*prop_vect_ptr;
	boolean_t	bool_arr[POLICY_TBL_SZ];
	boolean_t	*bool_arr_ptr;

	prop_vect_ptr = prop_vect;
	bool_arr_ptr = bool_arr;

	bzero(prop_vect, sizeof (prop_vect));
	bzero(bool_arr, sizeof (bool_arr));

	for (i = 0; i < POLICY_TBL_SZ; i++) {

		cur_policy_str = policy_table[i].policy_str;

		/* Do some basic policy dependent checks */
		if (!chk_policy_context(cur_policy_str)) {
			continue;
		}

		if (policy_table[i].policy_mask & policy) {
			*bool_arr_ptr = B_TRUE;
		} else {
			*bool_arr_ptr = B_FALSE;
		}

		DPRINT((dbfp, "%s%s\n", (*bool_arr_ptr == B_TRUE ? "+" : "-"),
		    cur_policy_str));

		add_prop_vect_scf(prop_vect_ptr++, cur_policy_str,
		    SCF_TYPE_BOOLEAN, (void *)bool_arr_ptr++);

	}

	return (set_val_scf(prop_vect, ASI_PGROUP_POLICY));
}

/*
 * do_setqctrl_scf() - set the values of qctrl properties of the audit service
 */
boolean_t
do_setqctrl_scf(struct au_qctrl *cval)
{
	scf_propvec_t		*prop_vect_ptr;
	scf_qctrl_t		cval_scf;

	if (!CHK_BDRY_QHIWATER(cval->aq_lowater, cval->aq_hiwater) &&
	    cval->aq_hiwater != 0) {
		(void) printf(gettext("Specified audit queue hiwater mark "
		    " out of allowed boundaries.\n"));
		return (B_FALSE);
	}
	if (!CHK_BDRY_QLOWATER(cval->aq_lowater, cval->aq_hiwater) &&
	    cval->aq_lowater != 0) {
		(void) printf(gettext("Specified audit queue lowater mark is "
		    " out of allowed boundaries.\n"));
		return (B_FALSE);
	}
	if (!CHK_BDRY_QBUFSZ(cval->aq_bufsz) && cval->aq_bufsz != 0) {
		(void) printf(gettext("Specified audit queue buffer size is "
		    "out of allowed boundaries.\n"));
		return (B_FALSE);
	}
	if (!CHK_BDRY_QDELAY(cval->aq_delay) && cval->aq_delay != 0) {
		(void) printf(gettext("Specified audit queue delay is "
		    "out of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_scf.scf_qhiwater = (uint64_t)cval->aq_hiwater;
	cval_scf.scf_qlowater = (uint64_t)cval->aq_lowater;
	cval_scf.scf_qbufsz = (uint64_t)cval->aq_bufsz;
	cval_scf.scf_qdelay = (uint64_t)cval->aq_delay;

	bzero(prop_vect, sizeof (prop_vect));

	prop_vect_ptr = prop_vect;
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QHIWATER, SCF_TYPE_COUNT,
	    (void *)&cval_scf.scf_qhiwater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QLOWATER, SCF_TYPE_COUNT,
	    (void *)&cval_scf.scf_qlowater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QBUFSZ, SCF_TYPE_COUNT,
	    (void *)&cval_scf.scf_qbufsz);
	add_prop_vect_scf(prop_vect_ptr, QUEUECTRL_QDELAY, SCF_TYPE_COUNT,
	    (void *)&cval_scf.scf_qdelay);

	return (set_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL));
}

/*
 * do_setqbufsz_scf() - set the qbufsz property value of the audit service
 */
boolean_t
do_setqbufsz_scf(size_t *cval)
{
	uint64_t	cval_l;

	if (!CHK_BDRY_QBUFSZ(*cval) && *cval != 0) {
		(void) printf(gettext("Specified audit queue buffer size is "
		    "out of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QBUFSZ, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	return (set_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL));
}

/*
 * do_setqdelay_scf() - set the qdelay property value of the audit service
 */
boolean_t
do_setqdelay_scf(clock_t *cval)
{
	uint64_t	cval_l;

	if (!CHK_BDRY_QDELAY(*cval) && *cval != 0) {
		(void) printf(gettext("Specified audit queue delay is "
		    " out of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QDELAY, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	return (set_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL));
}

/*
 * do_setqhiwater_scf() - set the qhiwater property value of the audit service
 */
boolean_t
do_setqhiwater_scf(size_t *cval)
{
	uint64_t	cval_l;
	size_t		cval_lowater;

	if (!do_getqlowater_scf(&cval_lowater)) {
		(void) printf(gettext("Could not get configured value of "
		    "queue lowater mark.\n"));
		return (B_FALSE);
	}
	if (cval_lowater == 0) {
		cval_lowater = AQ_MINLOW;
	}
	if (!CHK_BDRY_QHIWATER(cval_lowater, *cval) && *cval != 0) {
		(void) printf(gettext("Specified audit queue hiwater mark "
		    "is out of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QHIWATER, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	return (set_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL));
}

/*
 * do_setqlowater_scf() - set the qlowater property value of the audit service
 */
boolean_t
do_setqlowater_scf(size_t *cval)
{
	uint64_t	cval_l;
	size_t		cval_hiwater;

	if (!do_getqhiwater_scf(&cval_hiwater)) {
		(void) printf(gettext("Could not get configured value of "
		    "queue hiwater mark.\n"));
		return (B_FALSE);
	}
	if (cval_hiwater == 0) {
		cval_hiwater = AQ_MAXHIGH;
	}
	if (!CHK_BDRY_QLOWATER(*cval, cval_hiwater) && *cval != 0) {
		(void) printf(gettext("Specified audit queue lowater mark is "
		    "out of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QLOWATER, SCF_TYPE_COUNT,
	    (void *)&cval_l);

	return (set_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL));
}

/*
 * set_val_scf() - set property values of the audit service.
 *
 * arguments:	vector = pointers to the head end of array of property vectors
 * 		pgroup_str = property group of property in AUDITD_FMRI
 *
 */
static boolean_t
set_val_scf(scf_propvec_t *vector, char *pgroup_str)
{
	scf_propvec_t	*bad_prop_vec = NULL;

	/* for documentation on property vectors see <libscf_priv.h> */
	if (scf_write_propvec(AUDITD_FMRI, pgroup_str,
	    vector, (scf_propvec_t **)&bad_prop_vec) != SCF_SUCCESS) {
		prt_scf_err();
		if (bad_prop_vec != NULL) {
			prt_error(gettext("Setting the %s property in the %s "
			    "property group failed.\n"), bad_prop_vec->pv_prop,
			    pgroup_str);
		}
		prt_error(gettext("Unable to set property value."));
		return (B_FALSE);
	}

	return (B_TRUE);
}
