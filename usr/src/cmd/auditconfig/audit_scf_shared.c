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
scf_propvec_t    prop_vect[MAX_PROPVECS + 1];

/*
 * do_getqctrl_scf() - get the values of qctrl properties of the audit service
 */
boolean_t
do_getqctrl_scf(struct au_qctrl *cval)
{
	scf_propvec_t   	*prop_vect_ptr;
	scf_qctrl_t		cval_scf;

	bzero(prop_vect, sizeof (prop_vect));

	prop_vect_ptr = prop_vect;
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QHIWATER,
	    SCF_TYPE_COUNT, (void *)&cval_scf.scf_qhiwater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QLOWATER,
	    SCF_TYPE_COUNT, (void *)&cval_scf.scf_qlowater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QBUFSZ,
	    SCF_TYPE_COUNT, (void *)&cval_scf.scf_qbufsz);
	add_prop_vect_scf(prop_vect_ptr, QUEUECTRL_QDELAY,
	    SCF_TYPE_COUNT, (void *)&cval_scf.scf_qdelay);

	if (!get_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL)) {
		return (B_FALSE);
	}

	cval->aq_hiwater = (size_t)cval_scf.scf_qhiwater;
	cval->aq_lowater = (size_t)cval_scf.scf_qlowater;
	cval->aq_bufsz = (size_t)cval_scf.scf_qbufsz;
	cval->aq_delay = (clock_t)cval_scf.scf_qdelay;

	return (B_TRUE);
}

/*
 * do_getpolicy_scf() - get the audit policy flags from service
 */
boolean_t
do_getpolicy_scf(uint32_t *policy_mask)
{
	int			i;
	scf_propvec_t		*prop_vect_ptr;
	char			*cur_policy_str;
	policy_sw_t		policy_arr[POLICY_TBL_SZ + 1];
	policy_sw_t		*policy_arr_ptr;

	prop_vect_ptr = prop_vect;
	policy_arr_ptr = policy_arr;

	bzero(prop_vect, sizeof (prop_vect));
	bzero(policy_arr, sizeof (policy_arr));

	/* prepare the smf(5) query */
	for (i = 0; i < POLICY_TBL_SZ; i++) {

		cur_policy_str = policy_table[i].policy_str;

		/* Do some basic policy dependent checks */
		if (!chk_policy_context(cur_policy_str)) {
			continue;
		}
		DPRINT((dbfp, "will be queried\n"));

		add_prop_vect_scf(prop_vect_ptr++, cur_policy_str,
		    SCF_TYPE_BOOLEAN, (void *)&policy_arr_ptr->flag);

		policy_arr_ptr->policy = cur_policy_str;
		policy_arr_ptr++;

	}
	if (!get_val_scf(prop_vect, ASI_PGROUP_POLICY)) {
		return (B_FALSE);
	}

	/* set the policy mask */
	policy_arr_ptr = policy_arr;
	*policy_mask = 0;
	while (policy_arr_ptr->policy != NULL) {
		if (policy_arr_ptr->flag) {
			*policy_mask |= get_policy(policy_arr_ptr->policy);
		}
		policy_arr_ptr++;
	}

	return (B_TRUE);
}

/*
 * get_policy() - get policy mask entry
 */
uint32_t
get_policy(char *policy)
{
	int i;

	for (i = 0; i < POLICY_TBL_SZ; i++) {
		if (strcasecmp(policy, policy_table[i].policy_str) == 0) {
			return (policy_table[i].policy_mask);
		}
	}

	return (0);
}

/*
 * chk_policy_context() - does some policy based checks, checks the context
 * (zone, smf) in which the policy could make some sense.
 */
boolean_t
chk_policy_context(char *policy_str)
{

	/*
	 * "all" and "none" policy flags, since they represent
	 * sub/set of auditing policies, are not stored in the
	 * AUDITD_FMRI service instance configuration.
	 */
	DPRINT((dbfp, "Walking policy - %s: ", policy_str));
	if (strcmp("all", policy_str) == 0 ||
	    strcmp("none", policy_str) == 0) {
		DPRINT((dbfp, "skipped\n"));
		return (B_FALSE);
	}
	/*
	 * In the local zone (!= GLOBAL_ZONEID) we do not touch
	 * "ahlt" and "perzone" policy flags, since these are
	 * relevant only in the global zone.
	 */
	if ((getzoneid() != GLOBAL_ZONEID) &&
	    (strcmp("ahlt", policy_str) == 0 ||
	    strcmp("perzone", policy_str) == 0)) {
		DPRINT((dbfp, "skipped\n"));
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * prt_error() - prt_error_va() wrapper; see prt_error_va() for more contextual
 * information. Inputs - program error format and message.
 *
 */
/*PRINTFLIKE1*/
void
prt_error(char *fmt, ...)
{
	va_list 	args;

	va_start(args, fmt);
	prt_error_va(fmt, args);
	va_end(args);
}

/*
 * prt_error_va() - prints an error message along with corresponding system
 * error number. Inputs - program error format and the va_list already prepared
 * by the preceding functions.
 *
 */
/*PRINTFLIKE1*/
void
prt_error_va(char *fmt, va_list args)
{
	(void) vfprintf(stderr, fmt, args);
	(void) fputc('\n', stderr);
	if (errno)
		(void) fprintf(stderr, gettext("error: %s(%d)\n"),
		    strerror(errno), errno);
	(void) fflush(stderr);
}

/*
 * add_prop_vect_scf() - adds vector to the array of vectors later passed to
 * get_/set_val_scf(). The first argument (vector) points to particular position
 * in the vector of properties.
 */
void
add_prop_vect_scf(scf_propvec_t *vector, const char *prop_str,
    scf_type_t prop_type, void *prop_val_ptr)
{
	vector->pv_prop = prop_str;
	vector->pv_type = prop_type;
	vector->pv_ptr = prop_val_ptr;
}

/*
 * get_val_scf() - get a property values from the audit service
 *
 * Arguments:	vector = pointers to the head end of array of property vectors
 * 		pgroup_str = property group of property in AUDITD_FMRI
 *
 */
boolean_t
get_val_scf(scf_propvec_t *vector, char *pgroup_str)
{
	scf_propvec_t	*bad_prop_vec = NULL;

	/*
	 * Get the property vector from the editing snapshot (B_FALSE).
	 * For documentation on property vectors see <libscf_priv.h>.
	 */
	if (scf_read_propvec(AUDITD_FMRI, pgroup_str, B_FALSE,
	    vector, (scf_propvec_t **)&bad_prop_vec) != SCF_SUCCESS) {
		prt_scf_err();
		if (bad_prop_vec != NULL) {
			prt_error(gettext("Reading the %s property in the %s "
			    "property group failed.\n"), bad_prop_vec->pv_prop,
			    pgroup_str);
		}
		prt_error(gettext("Unable to get property value."));
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * prt_scf_err() - scf_error()/scf_strerror() wrapper.
 */
void
prt_scf_err(void)
{
	(void) fprintf(stderr, "error: %s\n", scf_strerror(scf_error()));
}
