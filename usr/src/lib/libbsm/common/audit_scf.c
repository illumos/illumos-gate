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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* auditd smf(5)/libscf(3LIB) interface - set and display audit parameters */
#include <audit_scf.h>
#include <audit_policy.h>

/* propvec array must be NULL terminated */
scf_propvec_t	prop_vect[MAX_PROPVECS + 1];

/*
 * prt_error() - prt_error_va() wrapper; see prt_error_va() for more contextual
 * information. Note, that the function disregards errno; if you need to print
 * out strerror()/errno use directly prt_error_va().
 * Inputs - program error format and message.
 */
/*PRINTFLIKE1*/
static void
prt_error(char *fmt, ...)
{
	va_list 	args;

	errno = 0;

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
		(void) fprintf(stderr, "error: %s(%d)\n",
		    strerror(errno), errno);
	(void) fflush(stderr);
}

/*
 * prt_scf_err() - scf_error()/scf_strerror() wrapper.
 */
static void
prt_scf_err(void)
{
	(void) fprintf(stderr, "error: %s\n", scf_strerror(scf_error()));
}

/*
 * add_prop_vect_scf() - adds vector to the array of vectors later passed to
 * get_/set_val_scf(). The first argument (vector) points to particular position
 * in the vector of properties.
 */
static void
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
static boolean_t
get_val_scf(scf_propvec_t *vector, char *pgroup_str)
{
	scf_propvec_t	*bad_prop_vec = NULL;

	/*
	 * Get the property vector from the editing snapshot (B_FALSE).
	 * For documentation on property vectors see <libscf_priv.h>.
	 */
	if (scf_read_propvec(AUDITD_FMRI, pgroup_str, B_FALSE, vector,
	    &bad_prop_vec) != SCF_SUCCESS) {
		prt_scf_err();
		if (bad_prop_vec != NULL) {
			prt_error(gettext("Reading the %s property in the %s "
			    "property group failed.\n"), bad_prop_vec->pv_prop,
			    pgroup_str);
		}
		return (B_FALSE);
	}

	return (B_TRUE);
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
	if (scf_write_propvec(AUDITD_FMRI, pgroup_str, vector,
	    &bad_prop_vec) != SCF_SUCCESS) {
		prt_scf_err();
		if (bad_prop_vec != NULL) {
			prt_error(gettext("Setting the %s property in the %s "
			    "property group failed.\n"), bad_prop_vec->pv_prop,
			    pgroup_str);
		}
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * free_prop_vect() - deallocate heap memory used for propvect values.
 */
static void
free_prop_vect(void)
{
	scf_propvec_t	*prop_vect_ptr;

	prop_vect_ptr = prop_vect;

	while (prop_vect_ptr->pv_prop != NULL) {
		if (stack_inbounds(prop_vect_ptr->pv_ptr) == 0) {
			free(prop_vect_ptr->pv_ptr);
		}
		prop_vect_ptr++;
	}
}

/*
 * chk_prop_vect() - check for prop_vect boundaries and possibly process
 * (typically) full prop_vect.
 */
static boolean_t
chk_prop_vect(scf_propvec_t **prop_vect_ptr, char *pgrp_str)
{
	if (*prop_vect_ptr < prop_vect ||
	    *prop_vect_ptr >= (prop_vect + MAX_PROPVECS)) {
		DPRINT((dbfp, "prop_vect is full; flushing\n"));
		if (!set_val_scf(prop_vect, pgrp_str)) {
			return (B_FALSE);
		}
		free_prop_vect();
		bzero(prop_vect, sizeof (prop_vect));
		*prop_vect_ptr = prop_vect;
	}
	return (B_TRUE);
}

/*
 * get_props_kva_all() - get all properties and fill in the plugin_kva.
 */
static boolean_t
get_props_kva_all(asi_scfhandle_t *handle, asi_scfhandle_iter_t *handle_iter,
    kva_t **plugin_kva)
{
	char		key_buf[PLUGIN_MAXKEY];
	char		val_buf[PLUGIN_MAXVAL];
	char		attr_string[PLUGIN_MAXATT];
	char		attr_buf[PLUGIN_MAXATT];
	int		len = 0;
	scf_type_t	prop_type;

	attr_string[0] = 0;
	attr_buf[0] = 0;

	while (scf_iter_next_property(handle_iter->prop, handle->prop) == 1) {
		if (scf_property_get_name(handle->prop, key_buf,
		    PLUGIN_MAXKEY) == -1) {
			prt_scf_err();
			return (B_FALSE);
		}

		/*
		 * We do not fully support multi-valued properties.
		 * scf_property_get_value() only supports single-valued
		 * properties. It returns SCF_ERROR_CONSTRAINT_VIOLATED and one
		 * of the property values. The audit service configuration
		 * values are all single-valued properties. The authorizations
		 * to configure and read the audit service properties may be
		 * multi-valued, these may safely be ignored here as not an
		 * error.
		 */
		if (scf_property_get_value(handle->prop,
		    handle_iter->prop_val) != 0 &&
		    scf_error() != SCF_ERROR_CONSTRAINT_VIOLATED) {
			prt_scf_err();
			return (B_FALSE);
		}
		if (scf_property_type(handle->prop, &prop_type) == -1) {
			prt_scf_err();
			return (B_FALSE);
		}
		switch (prop_type) {
		case SCF_TYPE_BOOLEAN: {
			uint8_t	pval_bool;
			if (scf_value_get_boolean(handle_iter->prop_val,
			    &pval_bool) == -1) {
				prt_scf_err();
				return (B_FALSE);
			}
			len = snprintf(attr_buf, PLUGIN_MAXATT, "%s=%d;",
			    key_buf, pval_bool);
			if (len < 0 || len >= PLUGIN_MAXATT) {
				prt_error(gettext("Too long attribute: %s\n"),
				    key_buf);
				return (B_FALSE);
			}
			if (strlcat(attr_string, attr_buf, PLUGIN_MAXATT) >=
			    PLUGIN_MAXATT) {
				prt_error(gettext("Too long attribute string: "
				    "%s\n"), key_buf);
				return (B_FALSE);
			}
			break;
		}
		case SCF_TYPE_ASTRING: {
			if (scf_value_get_as_string(handle_iter->prop_val,
			    val_buf, PLUGIN_MAXATT) == -1) {
				prt_scf_err();
				return (B_FALSE);
			}
			len = snprintf(attr_buf, PLUGIN_MAXATT, "%s=%s;",
			    key_buf, val_buf);
			if (len < 0 || len >= PLUGIN_MAXATT) {
				prt_error(gettext("Too long attribute: %s\n"),
				    key_buf);
				return (B_FALSE);
			}
			if (strlcat(attr_string, attr_buf, PLUGIN_MAXATT) >=
			    PLUGIN_MAXATT) {
				prt_error(gettext("Too long attribute string: "
				    "%s\n"), key_buf);
				return (B_FALSE);
			}
			break;
		}
		case SCF_TYPE_COUNT: {
			uint64_t	pval_count;
			if (scf_value_get_count(handle_iter->prop_val,
			    &pval_count) == -1) {
				prt_scf_err();
				return (B_FALSE);
			}
			len = snprintf(attr_buf, PLUGIN_MAXATT, "%s=%llu;",
			    key_buf, pval_count);
			if (len < 0 || len >= PLUGIN_MAXATT) {
				prt_error(gettext("Too long attribute: %s\n"),
				    key_buf);
				return (B_FALSE);
			}
			if (strlcat(attr_string, attr_buf, PLUGIN_MAXATT) >=
			    PLUGIN_MAXATT) {
				prt_error(gettext("Too long attribute string: "
				    "%s\n"), key_buf);
				return (B_FALSE);
			}
			break;
		}
		default:
			(void) printf("Unsupported value type %s [%d]\n",
			    key_buf, prop_type);
			break;
		}
	}

	if (*attr_string == '\0' ||
	    (*plugin_kva = _str2kva(attr_string, "=", ";")) == NULL) {
		prt_error(gettext("Empty or invalid attribute string."));
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * get_plugin_kva() - get and save config attributes of given plugin plugin_str
 * (or all plugins in case plugin_str == NULL) into scf_plugin_kva_node_t.
 */
static boolean_t
get_plugin_kva(asi_scfhandle_t *handle, asi_scfhandle_iter_t *handle_iter,
    scf_plugin_kva_node_t **plugin_kva_ll, char *plugin_str)
{

	scf_plugin_kva_node_t	*node = NULL;
	scf_plugin_kva_node_t	*node_prev = NULL;
	scf_plugin_kva_node_t	*node_head = NULL;
	char			plugin_str_tmp[PLUGIN_MAXBUF];

	bzero(plugin_str_tmp, PLUGIN_MAXBUF);

	if (scf_iter_instance_pgs_typed(handle_iter->pgrp, handle->inst,
	    (const char *)"plugin") == -1) {
		prt_scf_err();
		return (B_FALSE);
	}

	while (scf_iter_next_pg(handle_iter->pgrp, handle->pgrp) == 1) {
		if (scf_pg_get_name(handle->pgrp, plugin_str_tmp,
		    PLUGIN_MAXBUF) == -1) {
			prt_scf_err();
			plugin_kva_ll_free(node);
			return (B_FALSE);
		}

		if (plugin_str != NULL &&
		    strcmp(plugin_str_tmp, plugin_str) != 0) {
			continue;
		}

		if ((node =
		    calloc(1, sizeof (scf_plugin_kva_node_t))) == NULL) {
			prt_error(gettext("No available memory."));
			plugin_kva_ll_free(node_prev);
			return (B_FALSE);
		}
		if (node_head == NULL) {
			node_head = node;
		}
		if (node_prev != NULL) {
			node_prev->next = node;
			node->prev = node_prev;
		}
		node_prev = node;

		(void) strlcat((char *)&(node->plugin_name), plugin_str_tmp,
		    PLUGIN_MAXBUF);

		if (scf_iter_pg_properties(handle_iter->prop,
		    handle->pgrp) != 0) {
			prt_scf_err();
			plugin_kva_ll_free(node);
			return (B_FALSE);
		}

		if (!get_props_kva_all(handle, handle_iter,
		    &(node->plugin_kva))) {
			plugin_kva_ll_free(node);
			return (B_FALSE);
		}
	}

#if DEBUG
	{
		scf_plugin_kva_node_t	*node_debug = node_head;
		char			attr_string[PLUGIN_MAXATT];

		while (node_debug != NULL) {
			if (_kva2str(node_debug->plugin_kva, attr_string,
			    PLUGIN_MAXATT, "=", ";") == 0) {
				DPRINT((dbfp, "Found plugin - %s: %s\n",
				    node_debug->plugin_name, attr_string));
			} else {
				DPRINT((dbfp, "Could not get attribute string "
				    "for %s\n", node_debug->plugin_name));
			}
			node_debug = node_debug->prev;
		}
	}
#endif

	*plugin_kva_ll = node_head;

	return (B_TRUE);
}

/*
 * scf_free() - free scf handles
 */
static void
scf_free(asi_scfhandle_t *handle)
{
	if (handle == NULL) {
		return;
	}

	if (handle->prop != NULL) {
		scf_property_destroy(handle->prop);
	}
	if (handle->pgrp != NULL) {
		scf_pg_destroy(handle->pgrp);
	}
	if (handle->inst != NULL) {
		scf_instance_destroy(handle->inst);
	}
	if (handle->hndl != NULL) {
		if (scf_handle_unbind(handle->hndl) == -1) {
			prt_error(gettext("Internal error."));
			prt_scf_err();
		}
		scf_handle_destroy(handle->hndl);
	}
}

/*
 * scf_init() - initiate scf handles
 */
static boolean_t
scf_init(asi_scfhandle_t *handle)
{
	bzero(handle, sizeof (asi_scfhandle_t));

	if ((handle->hndl = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(handle->hndl) != 0) {
		goto err_out;
	}
	if ((handle->inst = scf_instance_create(handle->hndl)) == NULL) {
		goto err_out;
	}
	if ((handle->pgrp = scf_pg_create(handle->hndl)) == NULL) {
		goto err_out;
	}
	if ((handle->prop = scf_property_create(handle->hndl)) == NULL) {
		goto err_out;
	}

	return (B_TRUE);

err_out:
	prt_scf_err();
	scf_free(handle);
	return (B_FALSE);
}

/*
 * scf_free_iter() - free scf iter handles
 */
static void
scf_free_iter(asi_scfhandle_iter_t *handle_iter)
{
	if (handle_iter == NULL) {
		return;
	}

	if (handle_iter->pgrp != NULL) {
		scf_iter_destroy(handle_iter->pgrp);
	}
	if (handle_iter->prop != NULL) {
		scf_iter_destroy(handle_iter->prop);
	}
	if (handle_iter->prop_val != NULL) {
		scf_value_destroy(handle_iter->prop_val);
	}
}

/*
 * scf_init_iter() - initiate scf iter handles
 */
static boolean_t
scf_init_iter(asi_scfhandle_iter_t *handle_iter,
    asi_scfhandle_t *handle)
{
	bzero(handle_iter, sizeof (asi_scfhandle_iter_t));

	if ((handle_iter->pgrp = scf_iter_create(handle->hndl)) == NULL) {
		goto err_out;
	}
	if ((handle_iter->prop = scf_iter_create(handle->hndl)) == NULL) {
		goto err_out;
	}
	if ((handle_iter->prop_val = scf_value_create(handle->hndl)) == NULL) {
		goto err_out;
	}

	return (B_TRUE);

err_out:
	prt_scf_err();
	scf_free_iter(handle_iter);
	return (B_FALSE);
}

/*
 * chk_policy_context() - does some policy based checks, checks the context
 * (zone, smf) in which the policy could make some sense.
 */
static boolean_t
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
 * free_static_att_kva() - free hardcoded/static plugin attributes (key/value
 * pairs) from the kva plugin structure.
 */
void
free_static_att_kva(kva_t *plugin_kva)
{
	_kva_free_value(plugin_kva, PLUGIN_ACTIVE);
	_kva_free_value(plugin_kva, PLUGIN_PATH);
	_kva_free_value(plugin_kva, PLUGIN_QSIZE);
	_kva_free_value(plugin_kva, "read_authorization");
	_kva_free_value(plugin_kva, "value_authorization");
}


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
	    SCF_TYPE_COUNT, &cval_scf.scf_qhiwater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QLOWATER,
	    SCF_TYPE_COUNT, &cval_scf.scf_qlowater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QBUFSZ,
	    SCF_TYPE_COUNT, &cval_scf.scf_qbufsz);
	add_prop_vect_scf(prop_vect_ptr, QUEUECTRL_QDELAY,
	    SCF_TYPE_COUNT, &cval_scf.scf_qdelay);

	if (!get_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL)) {
		return (B_FALSE);
	}

	cval->aq_hiwater = (size_t)cval_scf.scf_qhiwater;
	cval->aq_lowater = (size_t)cval_scf.scf_qlowater;
	cval->aq_bufsz = (size_t)cval_scf.scf_qbufsz;
	cval->aq_delay = (clock_t)cval_scf.scf_qdelay;

	scf_clean_propvec(prop_vect);

	return (B_TRUE);
}

/*
 * do_getqbufsz_scf() - get the qbufsz audit service property value
 */
boolean_t
do_getqbufsz_scf(size_t *cval)
{
	uint64_t	cval_l;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QBUFSZ, SCF_TYPE_COUNT, &cval_l);

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
	add_prop_vect_scf(prop_vect, QUEUECTRL_QDELAY, SCF_TYPE_COUNT, &cval_l);

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
	    &cval_l);

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
	    &cval_l);

	if (!get_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL)) {
		return (B_FALSE);
	}

	*cval = (size_t)cval_l;

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
		    SCF_TYPE_BOOLEAN, &policy_arr_ptr->flag);

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
		    SCF_TYPE_BOOLEAN, bool_arr_ptr++);

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
		(void) printf(gettext("Specified audit queue hiwater mark is "
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}
	if (!CHK_BDRY_QLOWATER(cval->aq_lowater, cval->aq_hiwater) &&
	    cval->aq_lowater != 0) {
		(void) printf(gettext("Specified audit queue lowater mark is "
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}
	if (!CHK_BDRY_QBUFSZ(cval->aq_bufsz) && cval->aq_bufsz != 0) {
		(void) printf(gettext("Specified audit queue buffer size is "
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}
	if (!CHK_BDRY_QDELAY(cval->aq_delay) && cval->aq_delay != 0) {
		(void) printf(gettext("Specified audit queue delay is "
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_scf.scf_qhiwater = (uint64_t)cval->aq_hiwater;
	cval_scf.scf_qlowater = (uint64_t)cval->aq_lowater;
	cval_scf.scf_qbufsz = (uint64_t)cval->aq_bufsz;
	cval_scf.scf_qdelay = (uint64_t)cval->aq_delay;

	bzero(prop_vect, sizeof (prop_vect));

	prop_vect_ptr = prop_vect;
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QHIWATER, SCF_TYPE_COUNT,
	    &cval_scf.scf_qhiwater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QLOWATER, SCF_TYPE_COUNT,
	    &cval_scf.scf_qlowater);
	add_prop_vect_scf(prop_vect_ptr++, QUEUECTRL_QBUFSZ, SCF_TYPE_COUNT,
	    &cval_scf.scf_qbufsz);
	add_prop_vect_scf(prop_vect_ptr, QUEUECTRL_QDELAY, SCF_TYPE_COUNT,
	    &cval_scf.scf_qdelay);

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
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QBUFSZ, SCF_TYPE_COUNT, &cval_l);

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
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QDELAY, SCF_TYPE_COUNT, &cval_l);

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
		(void) printf(gettext("Specified audit queue hiwater mark is "
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QHIWATER, SCF_TYPE_COUNT,
	    &cval_l);

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
		    "outside of allowed boundaries.\n"));
		return (B_FALSE);
	}

	cval_l = (uint64_t)*cval;

	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, QUEUECTRL_QLOWATER, SCF_TYPE_COUNT,
	    &cval_l);

	return (set_val_scf(prop_vect, ASI_PGROUP_QUEUECTRL));
}

/*
 * do_getflags_scf() - get the audit attributable flags from service
 */
boolean_t
do_getflags_scf(char **flags)
{
	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, PRESELECTION_FLAGS, SCF_TYPE_ASTRING,
	    flags);

	if (!get_val_scf(prop_vect, ASI_PGROUP_PRESELECTION)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * do_getnaflags_scf() - get the audit non-attributable flags from service
 */
boolean_t
do_getnaflags_scf(char **naflags)
{
	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, PRESELECTION_NAFLAGS, SCF_TYPE_ASTRING,
	    naflags);

	if (!get_val_scf(prop_vect, ASI_PGROUP_PRESELECTION)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * do_setflags_scf() - set the attributable mask property value of the audit
 * service
 */
boolean_t
do_setflags_scf(char *flags)
{
	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, PRESELECTION_FLAGS, SCF_TYPE_ASTRING,
	    flags);

	return (set_val_scf(prop_vect, ASI_PGROUP_PRESELECTION));
}

/*
 * do_setnaflags_scf() - set the attributable mask property value of the audit
 * service
 */
boolean_t
do_setnaflags_scf(char *naflags)
{
	bzero(prop_vect, sizeof (prop_vect));
	add_prop_vect_scf(prop_vect, PRESELECTION_NAFLAGS, SCF_TYPE_ASTRING,
	    naflags);

	return (set_val_scf(prop_vect, ASI_PGROUP_PRESELECTION));
}

/*
 * plugin_avail_scf() - look for the plugin in the audit service configuration
 */
boolean_t
plugin_avail_scf(const char *plugin_str)
{
	scf_simple_handle_t	*sh;

	if (plugin_str == NULL || *plugin_str == '\0') {
		return (B_FALSE);
	}

	if ((sh = scf_general_pg_setup(AUDITD_FMRI, plugin_str)) == NULL) {
		DPRINT((dbfp, "No such plugin found: %s (%s)\n", plugin_str,
		    scf_strerror(scf_error())));
		return (B_FALSE);
	}

	scf_simple_handle_destroy(sh);
	return (B_TRUE);
}

/*
 * do_getpluginconfig_scf() - get plugin configuration from the audit service
 * configuration.
 */
boolean_t
do_getpluginconfig_scf(char *plugin_str, scf_plugin_kva_node_t **plugin_kva_ll)
{

	char			*asi_fmri;
	asi_scfhandle_t		handle;
	asi_scfhandle_iter_t	handle_iter;
	boolean_t		plugin_all = B_FALSE;
	boolean_t		rv = B_TRUE;

	if (plugin_str == NULL || *plugin_str == '\0') {
		if (asprintf(&asi_fmri, "%s", AUDITD_FMRI) == -1) {
			prt_error(gettext("Out of memory."));
			return (B_FALSE);
		}
		plugin_all = B_TRUE;
	} else {
		if (asprintf(&asi_fmri, "%s%s%s", AUDITD_FMRI,
		    SCF_FMRI_PROPERTYGRP_PREFIX, plugin_str) == -1) {
			prt_error(gettext("Out of memory."));
			return (B_FALSE);
		}
	}
	DPRINT((dbfp, "%s will be decoded\n", asi_fmri));

	if (!scf_init(&handle)) {
		prt_error(gettext("Unable to initialize scf handles."));
		free(asi_fmri);
		return (B_FALSE);
	}

	if (scf_handle_decode_fmri(handle.hndl, asi_fmri, NULL, NULL,
	    handle.inst, plugin_all ? NULL : handle.pgrp, NULL,
	    SCF_DECODE_FMRI_EXACT) == -1) {
		prt_scf_err();
		scf_free(&handle);
		free(asi_fmri);
		return (B_FALSE);
	}

	if (!scf_init_iter(&handle_iter, &handle)) {
		prt_error(gettext("Unable to initialize scf iter handles."));
		scf_free(&handle);
		free(asi_fmri);
		return (B_FALSE);
	}


	if (plugin_all) {
		rv = get_plugin_kva(&handle, &handle_iter, plugin_kva_ll, NULL);
	} else {
		rv = get_plugin_kva(&handle, &handle_iter, plugin_kva_ll,
		    plugin_str);
	}

	scf_free(&handle);
	scf_free_iter(&handle_iter);
	free(asi_fmri);
	return (rv);
}

/*
 * do_setpluginconfig_scf() - set plugin configuration in the audit service
 * configuration.
 */
boolean_t
do_setpluginconfig_scf(char *plugin_str, boolean_t plugin_state,
    char *plugin_att, int plugin_qsize)
{
	kva_t			*plugin_att_kva = NULL;
	char			*plugin_att_ptr = plugin_att;
	char			*plugin_att_clr_ptr = plugin_att;
	scf_simple_prop_t	*plugin_prop;
	scf_type_t		plugin_prop_type;
	scf_propvec_t		*prop_vect_ptr;
	int			cnt = 0;
	kv_t			*data;
	boolean_t		rval = B_TRUE;
	uint64_t		plugin_qsize_l = (uint64_t)plugin_qsize;

	DPRINT((dbfp, "Auditd plugin configuration to be set:\n\tplugin=%s\n\t"
	    "state=%d (%s)\n\tattributes=%s\n\tqsize=%d%s\n", plugin_str,
	    plugin_state, plugin_state == B_TRUE ? "active" : "inactive",
	    plugin_att == NULL ? " (unspecified)" : plugin_att,
	    plugin_qsize, plugin_qsize == -1 ? " (unspecified)" : ""));

	bzero(prop_vect, sizeof (prop_vect));
	prop_vect_ptr = prop_vect;

	if (plugin_att != NULL) {

		/* get rid of white-space chars */
		if (*plugin_att_ptr != '\0') {
			while (*plugin_att_ptr != '\0') {
				if (isspace(*plugin_att_ptr) == 0) {
					*plugin_att_clr_ptr++ = *plugin_att_ptr;
				}
				plugin_att_ptr++;
			}
			*plugin_att_clr_ptr = '\0';
		}
		DPRINT((dbfp, "attributes (no white-space): %s\n", plugin_att));

		/* allow empty plugin_att */
		if (*plugin_att == '\0') {
			cnt = 0;
			data = NULL;
		} else {
			plugin_att_kva = _str2kva(plugin_att, "=", ";");
			if (plugin_att_kva == NULL) {
				prt_error(gettext("Could not parse plugin "
				    "attributes."));
				return (B_FALSE);
			}

			free_static_att_kva(plugin_att_kva);
			cnt = plugin_att_kva->length;
			data = plugin_att_kva->data;
		}
	}

	/* set state */
	add_prop_vect_scf(prop_vect_ptr++, PLUGIN_ACTIVE, SCF_TYPE_BOOLEAN,
	    &plugin_state);
	DPRINT((dbfp, "Prepared active -> %d\n", plugin_state));

	/* set attributes */
	while (cnt) {
		if (data->value == NULL) {
			cnt--;
			data++;
			continue;
		}
		if (!chk_prop_vect(&prop_vect_ptr, plugin_str)) {
			rval = B_FALSE;
			goto err_out;
		}

		if ((plugin_prop = scf_simple_prop_get(NULL,
		    AUDITD_FMRI, plugin_str, data->key)) == NULL) {
			prt_error(gettext("Could not get configuration for "
			    "attribute: %s"), data->key);
			prt_scf_err();
			rval = B_FALSE;
			goto err_out;
		}
		if ((plugin_prop_type = scf_simple_prop_type(plugin_prop))
		    == -1) {
			prt_error(gettext("Could not get property type: %s"),
			    data->key);
			prt_scf_err();
			rval = B_FALSE;
			goto err_out;
		}

		switch (plugin_prop_type) {
		case SCF_TYPE_BOOLEAN: {
			uint8_t	*pval_bool;
			pval_bool = (uint8_t *)malloc(sizeof (uint8_t));
			if (pval_bool == NULL) {
				prt_error(gettext("No free memory available."));
				rval = B_FALSE;
				goto err_out;
			}
			*pval_bool = (uint8_t)atoi(data->value);
			add_prop_vect_scf(prop_vect_ptr++, data->key,
			    SCF_TYPE_BOOLEAN, pval_bool);
			break;
		}
		case SCF_TYPE_ASTRING: {
			char	*pval_str;
			if ((pval_str = strdup(data->value)) == NULL) {
				prt_error(gettext("No free memory available."));
				rval = B_FALSE;
				goto err_out;
			}
			add_prop_vect_scf(prop_vect_ptr++, data->key,
			    SCF_TYPE_ASTRING, pval_str);
			break;
		}
		case SCF_TYPE_COUNT: {
			uint64_t	*pval_count;
			pval_count = (uint64_t *)malloc(sizeof (uint64_t));
			if (pval_count == NULL) {
				prt_error(gettext("No free memory available."));
				rval = B_FALSE;
				goto err_out;
			}
			*pval_count = (uint64_t)atoll(data->value);
			add_prop_vect_scf(prop_vect_ptr++, data->key,
			    SCF_TYPE_COUNT, pval_count);
			break;
		}
		default:
			prt_error(gettext("Unsupported property type: %s (%d)"),
			    data->key, plugin_prop_type);
			break;
		}

		DPRINT((dbfp, "Prepared %s -> %s\n", data->key, data->value));
		scf_simple_prop_free(plugin_prop);
		data++;
		cnt--;
	}

	if (!chk_prop_vect(&prop_vect_ptr, plugin_str)) {
		rval = B_FALSE;
		goto err_out;
	}

	/* set qsize */
	if (plugin_qsize != -1) {
		add_prop_vect_scf(prop_vect_ptr, PLUGIN_QSIZE, SCF_TYPE_COUNT,
		    &plugin_qsize_l);
		DPRINT((dbfp, "Prepared qsize -> %d\n", plugin_qsize));
	}

	if (!set_val_scf(prop_vect, plugin_str)) {
		rval = B_FALSE;
	}

err_out:
	free_prop_vect();
	_kva_free(plugin_att_kva);
	return (rval);
}

/*
 * plugin_kva_ll_free() - free the memory used by plugin kva linked list.
 */
void
plugin_kva_ll_free(scf_plugin_kva_node_t *node)
{
	scf_plugin_kva_node_t *node_next;

	if (node == NULL) {
		return;
	}

	while (node->prev != NULL) {
		node = node->prev;
	}
	while (node != NULL) {
		_kva_free(node->plugin_kva);
		node_next = node->next;
		free(node);
		node = node_next;
	}
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
