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

/*
 * Service Control Manager (SCM) for SVCCTL service.
 *
 * This routine maintains a list of SMF service and their states. A list
 * of Solaris SMF service are displayed on the Server/Connection Manager
 * Windows client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <time.h>
#include <sys/types.h>

#include "svcctl_scm.h"

#define	LEGACY_UNKNOWN	"unknown"
#define	SVC_NAME_PROP	"name"

/* Flags for svcctl_scm_pg_get_val() */
#define	EMPTY_OK	0x01
#define	MULTI_OK	0x02

/*
 * svcctl_scm_avl_nodecmp
 *
 * Comparision function for nodes in an AVL tree of services.
 */
/* ARGSUSED */
static int
svcctl_scm_avl_nodecmp(const void *l_arg, const void *r_arg, void *m_name_len)
{
	const svcctl_svc_node_t *l = l_arg;
	const svcctl_svc_node_t *r = r_arg;
	int *max_name_len = m_name_len;
	int ret = 0;

	ret = strncasecmp(l->sn_name, r->sn_name, *max_name_len);

	if (ret > 0)
		return (1);
	if (ret < 0)
		return (-1);
	return (0);
}

/*
 * svcctl_scm_pg_get_val
 *
 * Get the single value of the named property in the given property group,
 * which must have type ty, and put it in *vp.  If ty is SCF_TYPE_ASTRING, vp
 * is taken to be a char **, and sz is the size of the buffer.  sz is unused
 * otherwise.  Return 0 on success, -1 if the property doesn't exist, has the
 * wrong type, or doesn't have a single value.  If flags has EMPTY_OK, don't
 * complain if the property has no values (but return nonzero).  If flags has
 * MULTI_OK and the property has multiple values, succeed with E2BIG.
 */
static int
svcctl_scm_pg_get_val(svcctl_manager_context_t *mgr_ctx,
    scf_propertygroup_t *pg, const char *propname, scf_type_t ty, void *vp,
    size_t sz, uint_t flags)
{
	int ret = -1, r;
	boolean_t multi = B_FALSE;

	assert((flags & ~(EMPTY_OK | MULTI_OK)) == 0);

	if (scf_pg_get_property(pg, propname, mgr_ctx->mc_scf_gprop) == -1)
		return (ret);

	if (scf_property_is_type(mgr_ctx->mc_scf_gprop, ty) != SCF_SUCCESS)
		return (ret);

	if (scf_property_get_value(mgr_ctx->mc_scf_gprop,
	    mgr_ctx->mc_scf_gval) != SCF_SUCCESS) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (ret);

		case SCF_ERROR_CONSTRAINT_VIOLATED:
			if (flags & MULTI_OK) {
				multi = B_TRUE;
				break;
			}
			return (ret);

		case SCF_ERROR_PERMISSION_DENIED:
		default:
			return (ret);
		}
	}

	switch (ty) {
	case SCF_TYPE_ASTRING:
		r = scf_value_get_astring
		    (mgr_ctx->mc_scf_gval, vp, sz) > 0 ? SCF_SUCCESS : -1;
		break;

	case SCF_TYPE_BOOLEAN:
		r = scf_value_get_boolean(mgr_ctx->mc_scf_gval, (uint8_t *)vp);
		break;

	case SCF_TYPE_COUNT:
		r = scf_value_get_count(mgr_ctx->mc_scf_gval, (uint64_t *)vp);
		break;

	case SCF_TYPE_INTEGER:
		r = scf_value_get_integer(mgr_ctx->mc_scf_gval, (int64_t *)vp);
		break;

	case SCF_TYPE_TIME: {
		int64_t sec;
		int32_t ns;
		r = scf_value_get_time(mgr_ctx->mc_scf_gval, &sec, &ns);
		((struct timeval *)vp)->tv_sec = sec;
		((struct timeval *)vp)->tv_usec = ns / 1000;
		break;
	}

	case SCF_TYPE_USTRING:
		r = scf_value_get_ustring(mgr_ctx->mc_scf_gval, vp, sz) > 0 ?
		    SCF_SUCCESS : -1;
		break;

	default:
		return (ret);
	}

	if (r != SCF_SUCCESS)
		return (ret);

	ret = multi ? E2BIG : 0;

	return (ret);
}

/*
 * svcctl_scm_get_running_snapshot
 *
 * Get running snapshot of a service instance.
 */
static scf_snapshot_t *
svcctl_scm_get_running_snapshot(svcctl_manager_context_t *mgr_ctx,
    scf_instance_t *inst)
{
	scf_snapshot_t *snap;

	snap = scf_snapshot_create(mgr_ctx->mc_scf_hdl);
	if (snap == NULL)
		return (NULL);

	if (scf_instance_get_snapshot(inst, "running", snap) == 0)
		return (snap);

	if (scf_error() != SCF_ERROR_NOT_FOUND)
		return (NULL);

	scf_snapshot_destroy(snap);
	return (NULL);
}

/*
 * svcctl_scm_inst_get_val
 *
 * As svcctl_scm_pg_get_val(), except look the property group up in an
 * instance.  If "use_running" is set, and the running snapshot exists,
 * do a composed lookup there.  Otherwise, do an (optionally composed)
 * lookup on the current values.  Note that lookups using snapshots are
 * always composed.
 */
static int
svcctl_scm_inst_get_val(svcctl_manager_context_t *mgr_ctx, scf_instance_t *inst,
    const char *pgname, const char *propname, scf_type_t ty, void *vp,
    size_t sz, uint_t flags, int use_running, int composed)
{
	scf_snapshot_t *snap = NULL;
	int r;

	if (use_running)
		snap = svcctl_scm_get_running_snapshot(mgr_ctx, inst);
	if (composed || use_running)
		r = scf_instance_get_pg_composed(inst, snap, pgname,
		    mgr_ctx->mc_scf_gpg);
	else
		r = scf_instance_get_pg(inst, pgname, mgr_ctx->mc_scf_gpg);
	if (snap)
		scf_snapshot_destroy(snap);
	if (r == -1)
		return (-1);

	r = svcctl_scm_pg_get_val(mgr_ctx, mgr_ctx->mc_scf_gpg, propname, ty,
	    vp, sz, flags);

	return (r);
}

/*
 * svcctl_scm_get_restarter_string_prop
 *
 * Get a string property from the restarter property group of the given
 * instance.  Return an empty string on normal problems.
 */
static void
svcctl_scm_get_restarter_string_prop(svcctl_manager_context_t *mgr_ctx,
    scf_instance_t *inst, const char *pname, char *buf, size_t buf_sz)
{
	if (svcctl_scm_inst_get_val(mgr_ctx, inst, SCF_PG_RESTARTER, pname,
	    SCF_TYPE_ASTRING, buf, buf_sz, 0, 0, 1) != 0)
		*buf = '\0';
}

/*
 * svcctl_scm_svc_transitioning
 *
 * Return true if a service instance is transitioning.
 */
static int
svcctl_scm_svc_transitioning(svcctl_manager_context_t *mgr_ctx,
    scf_instance_t *inst)
{
	char nstate_name[MAX_SCF_STATE_STRING_SZ];

	bzero(nstate_name, MAX_SCF_STATE_STRING_SZ);
	svcctl_scm_get_restarter_string_prop(mgr_ctx, inst,
	    SCF_PROPERTY_NEXT_STATE, nstate_name, sizeof (nstate_name));

	return ((*nstate_name == '\0'));
}

/*
 * svcctl_scm_get_svcstate
 *
 * Gets the state of an SMF service.
 */
static int
svcctl_scm_get_svcstate(svcctl_manager_context_t *mgr_ctx,
    char **buf, scf_walkinfo_t *wip)
{
	char *state_name;
	size_t max_state_size;

	max_state_size = MAX_SCF_STATE_STRING_SZ + 1;

	if ((state_name = malloc(max_state_size)) == NULL)
		return (-1);

	if (wip->pg == NULL) {
		svcctl_scm_get_restarter_string_prop(mgr_ctx, wip->inst,
		    SCF_PROPERTY_STATE, state_name, max_state_size);

		/* Don't print blank fields, to ease parsing. */
		if (state_name[0] == '\0') {
			state_name[0] = '-';
			state_name[1] = '\0';
		}

		if (svcctl_scm_svc_transitioning(mgr_ctx, wip->inst))
			/* Append an asterisk if new state is valid. */
			(void) strlcat(state_name, "*", max_state_size);

	} else
		(void) strlcpy(state_name, SCF_STATE_STRING_LEGACY,
		    max_state_size);

	*buf = state_name;
	return (0);
}

/*
 * svcctl_scm_get_svcdesc
 *
 * Gets the description of an SMF service.
 */
static int
svcctl_scm_get_svcdesc(svcctl_manager_context_t *mgr_ctx,
    char **buf, scf_walkinfo_t *wip)
{
	char *x;
	size_t newsize;
	char *newbuf;
	char *desc_buf = NULL;

	if ((desc_buf = malloc(mgr_ctx->mc_scf_max_value_len + 1)) == NULL)
		return (-1);

	bzero(desc_buf, mgr_ctx->mc_scf_max_value_len + 1);
	if (wip->pg != NULL)
		desc_buf[0] = '-';
	else if (svcctl_scm_inst_get_val(mgr_ctx, wip->inst,
	    SCF_PG_TM_COMMON_NAME, "C", SCF_TYPE_USTRING, desc_buf,
	    mgr_ctx->mc_scf_max_value_len, 0, 1, 1) == -1)
		desc_buf[0] = '-';

	/*
	 * Collapse multi-line tm_common_name values into a single line.
	 */
	for (x = desc_buf; *x != '\0'; x++)
		if (*x == '\n')
			*x = ' ';

	newsize = strlen(desc_buf) + 1;
	if ((newbuf = malloc(newsize)) == NULL) {
		free(desc_buf);
		return (-1);
	}

	(void) snprintf(newbuf, newsize, "%s", desc_buf);
	free(desc_buf);

	*buf = newbuf;
	return (0);
}

/*
 * svcctl_scm_get_svcfmri
 *
 * Gets the FMRI of an SMF service.
 */
static int
svcctl_scm_get_svcfmri(svcctl_manager_context_t *mgr_ctx,
    char **buf, scf_walkinfo_t *wip)
{
	size_t newsize;
	char *newbuf;
	char *fmri_buf = NULL;
	void *fmri_p = NULL;
	size_t fmri_size;

	if ((fmri_buf = malloc(mgr_ctx->mc_scf_max_fmri_len + 1)) == NULL)
		return (-1);

	if (wip->pg == NULL) {
		if (scf_instance_to_fmri(wip->inst, fmri_buf,
		    mgr_ctx->mc_scf_max_fmri_len + 1) == -1) {
			free(fmri_buf);
			return (-1);
		}
	} else {
		(void) strlcpy(fmri_buf, SCF_FMRI_LEGACY_PREFIX,
		    mgr_ctx->mc_scf_max_fmri_len + 1);

		fmri_p = fmri_buf + sizeof (SCF_FMRI_LEGACY_PREFIX) - 1;
		fmri_size = mgr_ctx->mc_scf_max_fmri_len + 1 - \
		    (sizeof (SCF_FMRI_LEGACY_PREFIX) - 1);

		if (svcctl_scm_pg_get_val(mgr_ctx, wip->pg,
		    SCF_LEGACY_PROPERTY_NAME, SCF_TYPE_ASTRING,
		    fmri_p, fmri_size, 0) != 0)
			(void) strlcat(fmri_buf, LEGACY_UNKNOWN,
			    mgr_ctx->mc_scf_max_fmri_len + 1);
	}

	newsize = strlen(fmri_buf) + 1;
	if ((newbuf = malloc(newsize)) == NULL) {
		free(fmri_buf);
		return (-1);
	}

	(void) snprintf(newbuf, newsize, "%s", fmri_buf);
	free(fmri_buf);

	*buf = newbuf;
	return (0);
}

/*
 * svcctl_scm_get_svcname
 *
 * Gets the FMRI of an SMF service.
 */
static int
svcctl_scm_get_svcname(char **buf, char *fmri)
{
	char *nm_buf = NULL;
	char *newbuf;
	size_t newsize;

	if (fmri == NULL)
		return (-1);

	newsize = strlen(fmri);
	if ((newbuf = malloc(newsize)) == NULL)
		return (-1);

	if ((nm_buf = strchr(fmri, '/')) == NULL)
		return (-1);

	(void) snprintf(newbuf, newsize, "%s", ++nm_buf);
	*buf = newbuf;
	return (0);
}

/*
 * svcctl_scm_cb_list_svcinst
 *
 * Callback function to walk all the services in an SCF repository.
 */
static int
svcctl_scm_cb_list_svcinst(void *context, scf_walkinfo_t *wip)
{
	svcctl_svc_node_t *node = NULL;
	uu_avl_index_t idx;
	svcctl_manager_context_t *mgr_ctx = (svcctl_manager_context_t *)context;

	node = malloc(sizeof (*node));
	if (node == NULL)
		return (-1);

	node->sn_fmri = NULL;
	if (svcctl_scm_get_svcfmri(mgr_ctx, &node->sn_fmri, wip) != 0)
		return (-1);

	node->sn_name = NULL;
	if (svcctl_scm_get_svcname(&node->sn_name, node->sn_fmri) != 0)
		return (-1);

	node->sn_desc = NULL;
	if (svcctl_scm_get_svcdesc(mgr_ctx, &node->sn_desc, wip) != 0)
		return (-1);

	node->sn_state = NULL;
	if (svcctl_scm_get_svcstate(mgr_ctx, &node->sn_state, wip) != 0)
		return (-1);

	/* Insert into AVL tree. */
	uu_avl_node_init(node, &node->sn_node, mgr_ctx->mc_svcs_pool);
	(void) uu_avl_find(mgr_ctx->mc_svcs, node,
	    &mgr_ctx->mc_scf_max_fmri_len, &idx);
	uu_avl_insert(mgr_ctx->mc_svcs, node, idx);

	return (0);
}

/*
 * svcctl_scm_map_status
 *
 * Report the service status.
 *
 * The mapping between the Microsoft service states and SMF service states
 * are as follows.
 *
 * SMF service states
 * ==================
 *	SCF_STATE_UNINIT                0x00000001
 *	SCF_STATE_MAINT                 0x00000002
 *	SCF_STATE_OFFLINE               0x00000004
 *	SCF_STATE_DISABLED              0x00000008
 *	SCF_STATE_ONLINE                0x00000010
 *	SCF_STATE_DEGRADED              0x00000020
 *	SCF_STATE_ALL                   0x0000003F
 *
 * Microsoft service states
 * ========================
 *	SERVICE_CONTINUE_PENDING	0x00000005
 *	SERVICE_PAUSE_PENDING		0x00000006
 *	SERVICE_PAUSED			0x00000007
 *	SERVICE_RUNNING			0x00000004
 *	SERVICE_START_PENDING		0x00000002
 *	SERVICE_STOP_PENDING		0x00000003
 *	SERVICE_STOPPED			0x00000001
 *
 * Mapping
 * =======
 *
 *	SCF_STATE_ONLINE	<->	SERVICE_RUNNING
 *	SCF_STATE_OFFLINE	<->	SERVICE_PAUSED
 *	SCF_STATE_DISABLED	<->	SERVICE_STOPPED
 *	SCF_STATE_UNINIT	<->	SERVICE_START_PENDING
 *	SCF_STATE_DEGRADED	<->	SERVICE_STOP_PENDING
 *	SCF_STATE_MAINT		<->	SERVICE_PAUSE_PENDING
 *	SCF_STATE_STRING_LEGACY <->	SERVICE_RUNNING
 *	Service Transitioning	<->	SERVICE_STOP_PENDING
 */
uint32_t
svcctl_scm_map_status(const char *state)
{
	int i;

	struct {
		const char	*scf_state;
		uint32_t	scm_state;
	} state_map[] = {
		{ SCF_STATE_STRING_ONLINE,	SERVICE_RUNNING },
		{ SCF_STATE_STRING_OFFLINE,	SERVICE_PAUSED },
		{ SCF_STATE_STRING_DISABLED,	SERVICE_STOPPED },
		{ SCF_STATE_STRING_UNINIT,	SERVICE_START_PENDING },
		{ SCF_STATE_STRING_DEGRADED,	SERVICE_STOP_PENDING },
		{ SCF_STATE_STRING_MAINT,	SERVICE_PAUSE_PENDING },
		{ SCF_STATE_STRING_LEGACY,	SERVICE_RUNNING }
	};

	for (i = 0; i < (sizeof (state_map)/sizeof (state_map[0])); ++i) {
		if (strcmp(state, state_map[i].scf_state) == 0)
			return (state_map[i].scm_state);
	}

	if (strrchr(state, '*') != 0)	/* State Transitioning */
		return (SERVICE_STOP_PENDING);

	return (SERVICE_RUNNING);
}

/*
 * svcctl_scm_enum_services
 *
 * Enumerates all SMF services.
 */
void
svcctl_scm_enum_services(svcctl_manager_context_t *mgr_ctx,
    unsigned char *services)
{
	svcctl_svc_node_t *node = NULL;
	int base_offset, offset, i;
	mts_wchar_t *wide_name;
	char *name;

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	svc_enum_status_t *svc = (svc_enum_status_t *)services;

	base_offset = mgr_ctx->mc_scf_numsvcs * sizeof (svc_enum_status_t);

	offset = base_offset;
	node = uu_avl_first(mgr_ctx->mc_svcs);

	for (i = 0; ((i < mgr_ctx->mc_scf_numsvcs) && (node != NULL)); ++i) {
		svc[i].svc_name = offset;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		wide_name = (mts_wchar_t *)&services[offset];
		name = node->sn_name;
		(void) mts_mbstowcs(wide_name, name, (strlen(name) + 1));

		offset += SVCCTL_WNSTRLEN(name);

		svc[i].display_name = offset;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		wide_name = (mts_wchar_t *)&services[offset];
		name = node->sn_fmri;
		(void) mts_mbstowcs(wide_name, name, (strlen(name) + 1));

		offset += SVCCTL_WNSTRLEN(name);

		svc[i].svc_status.cur_state =
		    svcctl_scm_map_status(node->sn_state);
		svc[i].svc_status.service_type = SERVICE_WIN32_SHARE_PROCESS;
		svc[i].svc_status.ctrl_accepted = 0;
		svc[i].svc_status.w32_exitcode = 0;
		svc[i].svc_status.svc_specified_exitcode = 0;
		svc[i].svc_status.check_point = 0;
		svc[i].svc_status.wait_hint = 0;

		node = uu_avl_next(mgr_ctx->mc_svcs, node);
	}
}

/*
 * svcctl_scm_cb_bytes_needed
 *
 * Callback function to calculate bytes needed to enumerate SMF services.
 */
static int
svcctl_scm_cb_bytes_needed(void *svc_node, void *byte_cnt)
{
	svcctl_svc_node_t *node = svc_node;
	int *cnt = byte_cnt;

	*cnt += (strlen(node->sn_fmri) + 1) * sizeof (mts_wchar_t);
	*cnt += (strlen(node->sn_name) + 1) * sizeof (mts_wchar_t);

	return (UU_WALK_NEXT);
}

/*
 * svcctl_scm_bytes_needed
 *
 * Calculates bytes needed to enumerate SMF services.
 */
void
svcctl_scm_bytes_needed(svcctl_manager_context_t *mgr_ctx)
{
	int bytes_needed = 0, svc_enum_status_size = 0;

	(void) uu_avl_walk(mgr_ctx->mc_svcs, svcctl_scm_cb_bytes_needed,
	    &bytes_needed, 0);

	svc_enum_status_size =
	    mgr_ctx->mc_scf_numsvcs * sizeof (svc_enum_status_t);
	bytes_needed += svc_enum_status_size;

	mgr_ctx->mc_bytes_needed = bytes_needed;
}

/*
 * svcctl_scm_validate_service
 *
 * Check to see whether or not a service is supported.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_SERVICE_DOES_NOT_EXIST
 */
uint32_t
svcctl_scm_validate_service(svcctl_manager_context_t *mgr_ctx, char *svc_name)
{
	svcctl_svc_node_t node;
	uu_avl_index_t idx;

	if (svc_name == NULL)
		return (ERROR_SERVICE_DOES_NOT_EXIST);

	bzero(&node, sizeof (svcctl_svc_node_t));
	node.sn_name = svc_name;
	if (uu_avl_find(mgr_ctx->mc_svcs, &node,
	    &mgr_ctx->mc_scf_max_fmri_len, &idx) != NULL)
		return (ERROR_SUCCESS);

	return (ERROR_SERVICE_DOES_NOT_EXIST);
}

/*
 * svcctl_scm_find_service
 *
 * Lookup a service.
 */
svcctl_svc_node_t *
svcctl_scm_find_service(svcctl_manager_context_t *mgr_ctx, char *svc_name)
{
	svcctl_svc_node_t node;
	uu_avl_index_t idx;
	svcctl_svc_node_t *f_node = NULL;

	if (svc_name == NULL)
		return (NULL);

	bzero(&node, sizeof (svcctl_svc_node_t));
	node.sn_name = svc_name;
	f_node = uu_avl_find(mgr_ctx->mc_svcs, &node,
	    &mgr_ctx->mc_scf_max_fmri_len, &idx);
	if (f_node != NULL)
		return (f_node);

	return (NULL);
}

/*
 * svcctl_scm_refresh
 *
 * Refresh SCM services per context.
 */
int
svcctl_scm_refresh(svcctl_manager_context_t *mgr_ctx)
{
	svcctl_scm_fini(mgr_ctx);
	return (svcctl_scm_init(mgr_ctx));
}

/*
 * svcctl_scm_scf_handle_init
 *
 * Initialize SCF handle per context.
 */
int
svcctl_scm_scf_handle_init(svcctl_manager_context_t *mgr_ctx)
{
	mgr_ctx->mc_scf_hdl = scf_handle_create(SCF_VERSION);
	if (mgr_ctx->mc_scf_hdl == NULL)
		return (-1);

	if (scf_handle_bind(mgr_ctx->mc_scf_hdl) == -1) {
		scf_handle_destroy(mgr_ctx->mc_scf_hdl);
		return (-1);
	}

	mgr_ctx->mc_scf_gpg = scf_pg_create(mgr_ctx->mc_scf_hdl);
	mgr_ctx->mc_scf_gprop = scf_property_create(mgr_ctx->mc_scf_hdl);
	mgr_ctx->mc_scf_gval = scf_value_create(mgr_ctx->mc_scf_hdl);

	if ((mgr_ctx->mc_scf_gpg == NULL) ||
	    (mgr_ctx->mc_scf_gprop == NULL) ||
	    (mgr_ctx->mc_scf_gval == NULL)) {
		(void) scf_handle_unbind(mgr_ctx->mc_scf_hdl);
		scf_handle_destroy(mgr_ctx->mc_scf_hdl);
		return (-1);
	}

	mgr_ctx->mc_scf_max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	mgr_ctx->mc_scf_max_value_len = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	return (0);
}

/*
 * svcctl_scm_scf_handle_init
 *
 * Destroy SCF handle per context.
 */
void
svcctl_scm_scf_handle_fini(svcctl_manager_context_t *mgr_ctx)
{
	scf_value_destroy(mgr_ctx->mc_scf_gval);
	scf_property_destroy(mgr_ctx->mc_scf_gprop);
	scf_pg_destroy(mgr_ctx->mc_scf_gpg);
	(void) scf_handle_unbind(mgr_ctx->mc_scf_hdl);
	scf_handle_destroy(mgr_ctx->mc_scf_hdl);
}

/*
 * svcctl_scm_init
 *
 * Initialize SCM repository per context.
 * SCM repository holds a list of SMF services.
 * Each SMF service node contains state, description and FMRI.
 */
int
svcctl_scm_init(svcctl_manager_context_t *mgr_ctx)
{
	int exit_status = 0;

	assert(mgr_ctx->mc_svcs_pool == NULL);
	assert(mgr_ctx->mc_svcs == NULL);

	mgr_ctx->mc_svcs_pool = uu_avl_pool_create("smf_svcs_pool",
	    sizeof (svcctl_svc_node_t), offsetof(svcctl_svc_node_t, sn_node),
	    svcctl_scm_avl_nodecmp, UU_AVL_DEBUG);

	if (mgr_ctx->mc_svcs_pool == NULL)
		return (-1);

	mgr_ctx->mc_svcs = uu_avl_create(mgr_ctx->mc_svcs_pool, NULL, 0);
	if (mgr_ctx->mc_svcs == NULL) {
		uu_avl_pool_destroy(mgr_ctx->mc_svcs_pool);
		return (-1);
	}

	if (scf_walk_fmri(mgr_ctx->mc_scf_hdl, 0, NULL,
	    SCF_WALK_MULTIPLE | SCF_WALK_LEGACY,
	    svcctl_scm_cb_list_svcinst, mgr_ctx, &exit_status, NULL) != 0) {
		uu_avl_destroy(mgr_ctx->mc_svcs);
		uu_avl_pool_destroy(mgr_ctx->mc_svcs_pool);
		return (-1);
	}

	mgr_ctx->mc_scf_numsvcs = uu_avl_numnodes(mgr_ctx->mc_svcs);
	if (mgr_ctx->mc_scf_numsvcs > 0)
		svcctl_scm_bytes_needed(mgr_ctx);

	return (0);
}

/*
 * svcctl_scm_fini
 *
 * Destroy SCM repository per context.
 */
void
svcctl_scm_fini(svcctl_manager_context_t *mgr_ctx)
{
	uu_avl_walk_t *walk;
	svcctl_svc_node_t *node;

	if ((mgr_ctx == NULL) || (mgr_ctx->mc_svcs_pool == NULL) ||
	    (mgr_ctx->mc_svcs == NULL))
		return;

	if ((walk =
	    uu_avl_walk_start(mgr_ctx->mc_svcs, UU_WALK_ROBUST)) == NULL)
		return;

	while ((node = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_remove(mgr_ctx->mc_svcs, node);
		free(node->sn_name);
		free(node->sn_fmri);
		free(node->sn_desc);
		free(node->sn_state);
		free(node);
	}
	uu_avl_walk_end(walk);
	uu_avl_destroy(mgr_ctx->mc_svcs);
	uu_avl_pool_destroy(mgr_ctx->mc_svcs_pool);
	mgr_ctx->mc_svcs_pool = NULL;
	mgr_ctx->mc_svcs = NULL;
}
