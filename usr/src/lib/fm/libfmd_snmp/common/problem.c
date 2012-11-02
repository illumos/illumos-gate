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

#include <sys/fm/protocol.h>
#include <fm/fmd_adm.h>
#include <fm/fmd_snmp.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <pthread.h>
#include <stddef.h>
#include <errno.h>
#include <alloca.h>
#include <locale.h>
#include <libuutil.h>
#include <libnvpair.h>
#include "sunFM_impl.h"
#include "problem.h"

/*
 * We assume that the number of suspect fault events associated with a
 * particular case will generally be sufficiently small that the overhead
 * associated with indexing them in a tree would exceed the gain from
 * not traversing the fault list for each request.
 */
static uu_avl_pool_t	*problem_uuid_avl_pool;
static uu_avl_t		*problem_uuid_avl;

#define	VALID_AVL_STATE	(problem_uuid_avl_pool != NULL &&	\
	problem_uuid_avl != NULL)

#define	UPDATE_WAIT_MILLIS	10	/* poll interval in milliseconds */

/*
 * Update types.  Single-index and all are mutually exclusive.
 */
#define	UCT_INDEX	0x1
#define	UCT_ALL		0x2
#define	UCT_FLAGS	0x3

/*
 * Locking strategy is described in module.c.
 */
static int		valid_stamp;
static pthread_mutex_t	update_lock;
static pthread_cond_t	update_cv;
static volatile enum { US_QUIET, US_NEEDED, US_INPROGRESS } update_status;

static Netsnmp_Node_Handler	sunFmProblemTable_handler;
static Netsnmp_Node_Handler	sunFmFaultEventTable_handler;

static sunFmProblem_data_t *
problem_key_build(const char *uuid)
{
	static sunFmProblem_data_t	key;

	key.d_aci_uuid = uuid;

	return (&key);
}

static sunFmProblem_data_t *
problem_lookup_uuid_exact(const char *uuid)
{
	sunFmProblem_data_t	*key, *data;

	key = problem_key_build(uuid);

	DEBUGMSGTL((MODNAME_STR, "lookup_exact for uuid %s\n", uuid));
	data = uu_avl_find(problem_uuid_avl, key, NULL, NULL);

	return (data);
}

static sunFmProblem_data_t *
problem_lookup_uuid_next(const char *uuid)
{
	sunFmProblem_data_t	*key, *data;
	uu_avl_index_t		idx;

	key = problem_key_build(uuid);

	DEBUGMSGTL((MODNAME_STR, "lookup_next for uuid %s\n", uuid));
	(void) uu_avl_find(problem_uuid_avl, key, NULL, &idx);

	data = uu_avl_nearest_next(problem_uuid_avl, idx);

	DEBUGMSGTL((MODNAME_STR, "lookup_next: entry is %p\n", data));

	return (data);
}

static sunFmFaultEvent_data_t *
faultevent_lookup_index_exact(sunFmProblem_data_t *data, ulong_t index)
{
	if (index > data->d_nsuspects)
		return (NULL);

	if (data->d_suspects == NULL)
		return (NULL);

	return (data->d_suspects[index - 1]);
}

static sunFmFaultStatus_data_t
faultstatus_lookup_index_exact(sunFmProblem_data_t *data, ulong_t index)
{
	if (index > data->d_nsuspects)
		return (0);

	if (data->d_statuses == NULL)
		return (0);

	if (data->d_valid != valid_stamp)
		return (0);

	return (data->d_statuses[index - 1]);
}

/*ARGSUSED*/
static int
problem_update_one(const fmd_adm_caseinfo_t *acp, void *arg)
{
	sunFmProblem_data_t		*data;
	nvlist_t			*nvl;
	int64_t				*diag_time;
	uint_t				nelem;
	uint32_t			nsusp;
	int				err;

	DEBUGMSGTL((MODNAME_STR, "update_one\n"));

	ASSERT(acp->aci_uuid != NULL);

	if ((data = problem_lookup_uuid_exact(acp->aci_uuid)) == NULL) {
		uu_avl_index_t idx;

		DEBUGMSGTL((MODNAME_STR, "found new problem %s\n",
		    acp->aci_uuid));
		if ((data = SNMP_MALLOC_TYPEDEF(sunFmProblem_data_t)) == NULL) {
			(void) snmp_log(LOG_ERR, MODNAME_STR ": Out of memory "
			    "for new problem data at %s:%d\n", __FILE__,
			    __LINE__);
			return (0);
		}
		if ((err = nvlist_dup(acp->aci_event, &data->d_aci_event, 0))
		    != 0) {
			(void) snmp_log(LOG_ERR, MODNAME_STR ": Problem data "
			    "setup failed: %s\n", strerror(err));
			SNMP_FREE(data);
			return (0);
		}

		data->d_aci_uuid = data->d_aci_code = data->d_aci_url = "-";
		(void) nvlist_lookup_string(data->d_aci_event, FM_SUSPECT_UUID,
		    (char **)&data->d_aci_uuid);
		(void) nvlist_lookup_string(data->d_aci_event,
		    FM_SUSPECT_DIAG_CODE, (char **)&data->d_aci_code);
		data->d_aci_url = strdup(acp->aci_url);

		if (nvlist_lookup_nvlist(data->d_aci_event, FM_SUSPECT_DE,
		    &nvl) == 0)
			if ((data->d_diag_engine = sunFm_nvl2str(nvl)) == NULL)
				data->d_diag_engine = "-";

		if (nvlist_lookup_int64_array(data->d_aci_event,
		    FM_SUSPECT_DIAG_TIME, &diag_time, &nelem) == 0 &&
		    nelem >= 2) {
			data->d_diag_time.tv_sec = (long)diag_time[0];
			data->d_diag_time.tv_usec = (long)diag_time[1];
		}

		(void) nvlist_lookup_uint32(data->d_aci_event,
		    FM_SUSPECT_FAULT_SZ, &nsusp);
		data->d_nsuspects = (ulong_t)nsusp;

		(void) nvlist_lookup_nvlist_array(data->d_aci_event,
		    FM_SUSPECT_FAULT_LIST, &data->d_suspects, &nelem);

		ASSERT(nelem == data->d_nsuspects);

		(void) nvlist_lookup_uint8_array(data->d_aci_event,
		    FM_SUSPECT_FAULT_STATUS, &data->d_statuses, &nelem);

		ASSERT(nelem == data->d_nsuspects);

		uu_avl_node_init(data, &data->d_uuid_avl,
		    problem_uuid_avl_pool);
		(void) uu_avl_find(problem_uuid_avl, data, NULL, &idx);
		uu_avl_insert(problem_uuid_avl, data, idx);

		data->d_valid = valid_stamp;

		DEBUGMSGTL((MODNAME_STR, "completed new problem %s@%p\n",
		    data->d_aci_uuid, data));
	} else {
		uint8_t *statuses;
		int i;

		(void) nvlist_lookup_uint8_array(acp->aci_event,
		    FM_SUSPECT_FAULT_STATUS, &statuses, &nelem);

		ASSERT(nelem == data->d_nsuspects);

		for (i = 0; i < nelem; i++)
			data->d_statuses[i] = statuses[i];

		data->d_valid = valid_stamp;
	}

	/*
	 * We don't touch problems we've seen before; they shouldn't change
	 * in any way we care about, since they've already been solved.  The
	 * state, however, could change, and if we later expose that to the
	 * client we need to update it here.
	 */

	return (0);
}

static int
problem_update(sunFmProblem_update_ctx_t *update_ctx)
{
	fmd_adm_t *adm;

	ASSERT(update_ctx != NULL);
	ASSERT((update_ctx->uc_type & (UCT_INDEX|UCT_ALL)) !=
	    (UCT_INDEX|UCT_ALL));
	ASSERT((update_ctx->uc_type & ~UCT_FLAGS) == 0);
	ASSERT(VALID_AVL_STATE);

	if ((adm = fmd_adm_open(update_ctx->uc_host, update_ctx->uc_prog,
	    update_ctx->uc_version)) == NULL) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": Communication with fmd "
		    "failed: %s\n", strerror(errno));
		return (SNMP_ERR_RESOURCEUNAVAILABLE);
	}

	++valid_stamp;
	if (fmd_adm_case_iter(adm, SNMP_URL_MSG, problem_update_one,
	    update_ctx) != 0) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": fmd case information "
		    "update failed: %s\n", fmd_adm_errmsg(adm));
		fmd_adm_close(adm);
		return (SNMP_ERR_RESOURCEUNAVAILABLE);
	}

	DEBUGMSGTL((MODNAME_STR, "case iteration completed\n"));

	fmd_adm_close(adm);
	return (SNMP_ERR_NOERROR);
}

/*ARGSUSED*/
static void
update_thread(void *arg)
{
	/*
	 * The current problem_update implementation offers minimal savings
	 * for the use of index-only updates; therefore we always do a full
	 * update.  If it becomes advantageous to limit updates to a single
	 * index, the contexts can be queued by the handler instead.
	 */
	sunFmProblem_update_ctx_t	uc;

	uc.uc_host = NULL;
	uc.uc_prog = FMD_ADM_PROGRAM;
	uc.uc_version = FMD_ADM_VERSION;

	uc.uc_index = NULL;
	uc.uc_type = UCT_ALL;

	for (;;) {
		(void) pthread_mutex_lock(&update_lock);
		update_status = US_QUIET;
		while (update_status == US_QUIET)
			(void) pthread_cond_wait(&update_cv, &update_lock);
		update_status = US_INPROGRESS;
		(void) pthread_mutex_unlock(&update_lock);
		(void) problem_update(&uc);
	}
}

static void
request_update(void)
{
	(void) pthread_mutex_lock(&update_lock);
	if (update_status != US_QUIET) {
		(void) pthread_mutex_unlock(&update_lock);
		return;
	}
	update_status = US_NEEDED;
	(void) pthread_cond_signal(&update_cv);
	(void) pthread_mutex_unlock(&update_lock);
}

/*ARGSUSED*/
static int
problem_compare_uuid(const void *l, const void *r, void *private)
{
	sunFmProblem_data_t	*l_data = (sunFmProblem_data_t *)l;
	sunFmProblem_data_t	*r_data = (sunFmProblem_data_t *)r;

	ASSERT(l_data != NULL && r_data != NULL);

	return (strcmp(l_data->d_aci_uuid, r_data->d_aci_uuid));
}

int
sunFmProblemTable_init(void)
{
	static oid sunFmProblemTable_oid[] = { SUNFMPROBLEMTABLE_OID };
	netsnmp_table_registration_info *table_info;
	netsnmp_handler_registration *handler;
	int err;

	if ((err = pthread_mutex_init(&update_lock, NULL)) != 0) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": mutex_init failure: "
		    "%s\n", strerror(err));
		return (MIB_REGISTRATION_FAILED);
	}
	if ((err = pthread_cond_init(&update_cv, NULL)) != 0) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": cond_init failure: "
		    "%s\n", strerror(err));
		return (MIB_REGISTRATION_FAILED);
	}

	if ((err = pthread_create(NULL, NULL, (void *(*)(void *))update_thread,
	    NULL)) != 0) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": error creating update "
		    "thread: %s\n", strerror(err));
		return (MIB_REGISTRATION_FAILED);
	}

	if ((table_info =
	    SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info)) == NULL)
		return (MIB_REGISTRATION_FAILED);

	if ((handler = netsnmp_create_handler_registration("sunFmProblemTable",
	    sunFmProblemTable_handler, sunFmProblemTable_oid,
	    OID_LENGTH(sunFmProblemTable_oid), HANDLER_CAN_RONLY)) == NULL) {
		SNMP_FREE(table_info);
		return (MIB_REGISTRATION_FAILED);
	}

	/*
	 * The Net-SNMP template uses add_indexes here, but that
	 * function is unsafe because it does not check for failure.
	 */
	if (netsnmp_table_helper_add_index(table_info, ASN_OCTET_STR) == NULL) {
		SNMP_FREE(table_info);
		SNMP_FREE(handler);
		return (MIB_REGISTRATION_FAILED);
	}

	table_info->min_column = SUNFMPROBLEM_COLMIN;
	table_info->max_column = SUNFMPROBLEM_COLMAX;

	if ((problem_uuid_avl_pool = uu_avl_pool_create("problem_uuid",
	    sizeof (sunFmProblem_data_t),
	    offsetof(sunFmProblem_data_t, d_uuid_avl), problem_compare_uuid,
	    UU_AVL_DEBUG)) == NULL) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": problem_uuid avl pool "
		    "creation failed: %s\n", uu_strerror(uu_error()));
		snmp_free_varbind(table_info->indexes);
		SNMP_FREE(table_info);
		SNMP_FREE(handler);
		return (MIB_REGISTRATION_FAILED);
	}

	if ((problem_uuid_avl = uu_avl_create(problem_uuid_avl_pool, NULL,
	    UU_AVL_DEBUG)) == NULL) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": problem_uuid avl "
		    "creation failed: %s\n", uu_strerror(uu_error()));
		snmp_free_varbind(table_info->indexes);
		SNMP_FREE(table_info);
		SNMP_FREE(handler);
		uu_avl_pool_destroy(problem_uuid_avl_pool);
		return (MIB_REGISTRATION_FAILED);
	}

	if ((err = netsnmp_register_table(handler, table_info)) !=
	    MIB_REGISTERED_OK) {
		snmp_free_varbind(table_info->indexes);
		SNMP_FREE(table_info);
		SNMP_FREE(handler);
		uu_avl_destroy(problem_uuid_avl);
		uu_avl_pool_destroy(problem_uuid_avl_pool);
		return (err);
	}

	return (MIB_REGISTERED_OK);
}

int
sunFmFaultEventTable_init(void)
{
	static oid sunFmFaultEventTable_oid[] = { SUNFMFAULTEVENTTABLE_OID };
	netsnmp_table_registration_info *table_info;
	netsnmp_handler_registration *handler;
	int err;

	if ((table_info =
	    SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info)) == NULL)
		return (MIB_REGISTRATION_FAILED);

	if ((handler =
	    netsnmp_create_handler_registration("sunFmFaultEventTable",
	    sunFmFaultEventTable_handler, sunFmFaultEventTable_oid,
	    OID_LENGTH(sunFmFaultEventTable_oid), HANDLER_CAN_RONLY)) == NULL) {
		SNMP_FREE(table_info);
		return (MIB_REGISTRATION_FAILED);
	}

	/*
	 * The Net-SNMP template uses add_indexes here, but that
	 * function is unsafe because it does not check for failure.
	 */
	if (netsnmp_table_helper_add_index(table_info, ASN_OCTET_STR) == NULL) {
		SNMP_FREE(table_info);
		SNMP_FREE(handler);
		return (MIB_REGISTRATION_FAILED);
	}
	if (netsnmp_table_helper_add_index(table_info, ASN_UNSIGNED) == NULL) {
		snmp_free_varbind(table_info->indexes);
		SNMP_FREE(table_info);
		SNMP_FREE(handler);
		return (MIB_REGISTRATION_FAILED);
	}

	table_info->min_column = SUNFMFAULTEVENT_COLMIN;
	table_info->max_column = SUNFMFAULTEVENT_COLMAX;

	if ((err = netsnmp_register_table(handler, table_info)) !=
	    MIB_REGISTERED_OK) {
		snmp_free_varbind(table_info->indexes);
		SNMP_FREE(table_info);
		SNMP_FREE(handler);
		return (err);
	}

	return (MIB_REGISTERED_OK);
}

/*
 * Returns the problem data for the problem whose uuid is next according
 * to ASN.1 lexical ordering after the request in table_info.  Indexes are
 * updated to reflect the OID of the value being returned.  This allows
 * us to implement GETNEXT.
 */
static sunFmProblem_data_t *
sunFmProblemTable_nextpr(netsnmp_handler_registration *reginfo,
    netsnmp_table_request_info *table_info)
{
	sunFmProblem_data_t	*data;
	char			*uuid = "";

	if (table_info->number_indexes < 1) {
		oid tmpoid[MAX_OID_LEN];

		DEBUGMSGTL((MODNAME_STR, "nextpr: no indexes given\n"));

		snmp_free_varbind(table_info->indexes);
		table_info->indexes =
		    SNMP_MALLOC_TYPEDEF(netsnmp_variable_list);
		(void) snmp_set_var_typed_value(table_info->indexes,
		    ASN_OCTET_STR, (const uchar_t *)uuid, 0);
		(void) memcpy(tmpoid, reginfo->rootoid,
		    reginfo->rootoid_len * sizeof (oid));
		tmpoid[reginfo->rootoid_len] = 1;
		tmpoid[reginfo->rootoid_len + 1] = table_info->colnum;
		if (build_oid_segment(table_info->indexes) != SNMPERR_SUCCESS) {
			snmp_free_varbind(table_info->indexes);
			return (NULL);
		}
		table_info->number_indexes = 1;
		table_info->index_oid_len = table_info->indexes->name_length;
		(void) memcpy(table_info->index_oid, table_info->indexes->name,
		    table_info->indexes->name_length);

		DEBUGMSGTL((MODNAME_STR, "nextpr: built fake index:\n"));
		DEBUGMSGVAR((MODNAME_STR, table_info->indexes));
		DEBUGMSG((MODNAME_STR, "\n"));
	} else {
		/*
		 * Construct the next possible UUID to look for.  We can
		 * simply increment the least significant byte of the last
		 * UUID because (a) that preserves SNMP lex order and (b)
		 * the characters that may appear in a UUID do not include
		 * 127 nor 255.
		 */
		uuid = alloca(table_info->indexes->val_len + 1);
		(void) strlcpy(uuid,
		    (const char *)table_info->indexes->val.string,
		    table_info->indexes->val_len + 1);
		++uuid[table_info->indexes->val_len - 1];

		DEBUGMSGTL((MODNAME_STR, "nextpr: received index:\n"));
		DEBUGMSGVAR((MODNAME_STR, table_info->indexes));
		DEBUGMSG((MODNAME_STR, "\n"));
	}

	if ((data = problem_lookup_uuid_next(uuid)) == NULL) {
		DEBUGMSGTL((MODNAME_STR, "nextpr: next match not found for "
		    "%s; trying next column\n", uuid));
		if (table_info->colnum >=
		    netsnmp_find_table_registration_info(reginfo)->max_column) {
			snmp_free_varbind(table_info->indexes);
			table_info->indexes = NULL;
			table_info->number_indexes = 0;
			DEBUGMSGTL((MODNAME_STR, "nextpr: out of columns\n"));
			return (NULL);
		}
		table_info->colnum++;
		DEBUGMSGTL((MODNAME_STR, "nextpr: search for col %u empty "
		    "uuid\n", table_info->colnum));

		if ((data = problem_lookup_uuid_next("")) == NULL) {
			DEBUGMSGTL((MODNAME_STR, "nextpr: next match not found "
			    "for empty uuid; stopping\n"));
			snmp_free_varbind(table_info->indexes);
			table_info->indexes = NULL;
			table_info->number_indexes = 0;
			return (NULL);
		}
	}

	(void) snmp_set_var_typed_value(table_info->indexes, ASN_OCTET_STR,
	    (uchar_t *)data->d_aci_uuid, strlen(data->d_aci_uuid));
	table_info->number_indexes = 1;

	DEBUGMSGTL((MODNAME_STR, "matching data is %s@%p\n", data->d_aci_uuid,
	    data));

	return (data);
}

/*
 * Returns the problem data corresponding to the request in table_info.
 * All request parameters are unmodified.
 */
/*ARGSUSED*/
static sunFmProblem_data_t *
sunFmProblemTable_pr(netsnmp_handler_registration *reginfo,
    netsnmp_table_request_info *table_info)
{
	char			*uuid;

	ASSERT(table_info->number_indexes >= 1);

	uuid = alloca(table_info->indexes->val_len + 1);
	(void) strlcpy(uuid, (const char *)table_info->indexes->val.string,
	    table_info->indexes->val_len + 1);

	return (problem_lookup_uuid_exact(uuid));
}

/*
 * Returns the ASN.1 lexicographically first fault event after the one
 * identified by table_info.  Indexes are updated to reflect the OID
 * of the data returned.  This allows us to implement GETNEXT.
 */
static sunFmFaultEvent_data_t *
sunFmFaultEventTable_nextfe(netsnmp_handler_registration *reginfo,
    netsnmp_table_request_info *table_info, sunFmFaultStatus_data_t *statusp)
{
	sunFmProblem_data_t	*data;
	sunFmFaultEvent_data_t	*rv;
	netsnmp_variable_list	*var;
	ulong_t			index;

	for (;;) {
		switch (table_info->number_indexes) {
		case 2:
		default:
			DEBUGMSGTL((MODNAME_STR, "nextfe: 2 indices:\n"));
			DEBUGMSGVAR((MODNAME_STR, table_info->indexes));
			DEBUGMSG((MODNAME_STR, "\n"));
			DEBUGMSGVAR((MODNAME_STR,
			    table_info->indexes->next_variable));
			DEBUGMSG((MODNAME_STR, "\n"));
			index = *(ulong_t *)
			    table_info->indexes->next_variable->val.integer + 1;

			if ((data = sunFmProblemTable_pr(reginfo,
			    table_info)) != NULL &&
			    (*statusp = faultstatus_lookup_index_exact(data,
			    index)) != 0 &&
			    (rv = faultevent_lookup_index_exact(data, index)) !=
			    NULL) {
				(void) snmp_set_var_typed_value(
				    table_info->indexes->next_variable,
				    ASN_UNSIGNED, (uchar_t *)&index,
				    sizeof (index));
				return (rv);
			}

			if (sunFmProblemTable_nextpr(reginfo, table_info) ==
			    NULL)
				return (NULL);
			break;
		case 1:
			if ((data = sunFmProblemTable_pr(reginfo,
			    table_info)) != NULL) {
				oid tmpoid[MAX_OID_LEN];
				index = 0;

				DEBUGMSGTL((MODNAME_STR, "nextfe: 1 index:\n"));
				DEBUGMSGVAR((MODNAME_STR, table_info->indexes));
				DEBUGMSG((MODNAME_STR, "\n"));
				var =
				    SNMP_MALLOC_TYPEDEF(netsnmp_variable_list);
				(void) snmp_set_var_typed_value(var,
				    ASN_UNSIGNED, (uchar_t *)&index,
				    sizeof (index));
				(void) memcpy(tmpoid, reginfo->rootoid,
				    reginfo->rootoid_len * sizeof (oid));
				tmpoid[reginfo->rootoid_len] = 1;
				tmpoid[reginfo->rootoid_len + 1] =
				    table_info->colnum;
				if (build_oid_segment(var) != SNMPERR_SUCCESS) {
					snmp_free_varbind(var);
					return (NULL);
				}
				snmp_free_varbind(
				    table_info->indexes->next_variable);
				table_info->indexes->next_variable = var;
				table_info->number_indexes = 2;
				DEBUGMSGTL((MODNAME_STR, "nextfe: built fake "
				    "index:\n"));
				DEBUGMSGVAR((MODNAME_STR, table_info->indexes));
				DEBUGMSG((MODNAME_STR, "\n"));
				DEBUGMSGVAR((MODNAME_STR,
				    table_info->indexes->next_variable));
				DEBUGMSG((MODNAME_STR, "\n"));
			} else {
				if (sunFmProblemTable_nextpr(reginfo,
				    table_info) == NULL)
					return (NULL);
			}
			break;
		case 0:
			if (sunFmProblemTable_nextpr(reginfo, table_info) ==
			    NULL)
				return (NULL);
			break;
		}
	}
}

static sunFmFaultEvent_data_t *
sunFmFaultEventTable_fe(netsnmp_handler_registration *reginfo,
    netsnmp_table_request_info *table_info, sunFmFaultStatus_data_t *statusp)
{
	sunFmProblem_data_t	*data;

	ASSERT(table_info->number_indexes == 2);

	if ((data = sunFmProblemTable_pr(reginfo, table_info)) == NULL)
		return (NULL);

	*statusp = faultstatus_lookup_index_exact(data,
	    *(ulong_t *)table_info->indexes->next_variable->val.integer);
	if (*statusp == 0)
		return (NULL);
	return (faultevent_lookup_index_exact(data,
	    *(ulong_t *)table_info->indexes->next_variable->val.integer));
}

/*ARGSUSED*/
static void
sunFmProblemTable_return(unsigned int reg, void *arg)
{
	netsnmp_delegated_cache		*cache = (netsnmp_delegated_cache *)arg;
	netsnmp_request_info		*request;
	netsnmp_agent_request_info	*reqinfo;
	netsnmp_handler_registration	*reginfo;
	netsnmp_table_request_info	*table_info;
	sunFmProblem_data_t		*data;

	ASSERT(netsnmp_handler_check_cache(cache) != NULL);

	(void) pthread_mutex_lock(&update_lock);
	if (update_status != US_QUIET) {
		struct timeval			tv;

		tv.tv_sec = UPDATE_WAIT_MILLIS / 1000;
		tv.tv_usec = (UPDATE_WAIT_MILLIS % 1000) * 1000;

		(void) snmp_alarm_register_hr(tv, 0, sunFmProblemTable_return,
		    cache);
		(void) pthread_mutex_unlock(&update_lock);
		return;
	}

	request = cache->requests;
	reqinfo = cache->reqinfo;
	reginfo = cache->reginfo;

	table_info = netsnmp_extract_table_info(request);
	request->delegated = 0;

	ASSERT(table_info->colnum >= SUNFMPROBLEM_COLMIN);
	ASSERT(table_info->colnum <= SUNFMPROBLEM_COLMAX);

	/*
	 * table_info->colnum contains the column number requested.
	 * table_info->indexes contains a linked list of snmp variable
	 * bindings for the indexes of the table.  Values in the list
	 * have been set corresponding to the indexes of the
	 * request.  We have other guarantees as well:
	 *
	 * - The column number is always within range.
	 * - If we have no index data, table_info->index_oid_len is 0.
	 * - We will never receive requests outside our table nor
	 *   those with the first subid anything other than 1 (Entry)
	 *   nor those without a column number.  This is true even
	 *   for GETNEXT requests.
	 */

	switch (reqinfo->mode) {
	case MODE_GET:
		if ((data = sunFmProblemTable_pr(reginfo, table_info)) ==
		    NULL) {
			netsnmp_free_delegated_cache(cache);
			(void) pthread_mutex_unlock(&update_lock);
			return;
		}
		break;
	case MODE_GETNEXT:
	case MODE_GETBULK:
		if ((data = sunFmProblemTable_nextpr(reginfo, table_info)) ==
		    NULL) {
			netsnmp_free_delegated_cache(cache);
			(void) pthread_mutex_unlock(&update_lock);
			return;
		}
		break;
	default:
		(void) snmp_log(LOG_ERR, MODNAME_STR ": Unsupported request "
		    "mode %d\n", reqinfo->mode);
		netsnmp_free_delegated_cache(cache);
		(void) pthread_mutex_unlock(&update_lock);
		return;
	}

	switch (table_info->colnum) {
	case SUNFMPROBLEM_COL_UUID:
	{
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)data->d_aci_uuid,
		    strlen(data->d_aci_uuid));
		break;
	}
	case SUNFMPROBLEM_COL_CODE:
	{
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)data->d_aci_code,
		    strlen(data->d_aci_code));
		break;
	}
	case SUNFMPROBLEM_COL_URL:
	{
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)data->d_aci_url,
		    strlen(data->d_aci_url));
		break;
	}
	case SUNFMPROBLEM_COL_DIAGENGINE:
	{
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)data->d_diag_engine,
		    strlen(data->d_diag_engine));
		break;
	}
	case SUNFMPROBLEM_COL_DIAGTIME:
	{
		/*
		 * The date_n_time function is not Y2038-safe; this may
		 * need to be updated when a suitable Y2038-safe Net-SNMP
		 * API is available.
		 */
		size_t	dt_size;
		time_t	dt_time = (time_t)data->d_diag_time.tv_sec;
		uchar_t	*dt = date_n_time(&dt_time, &dt_size);

		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, dt, dt_size);
		break;
	}
	case SUNFMPROBLEM_COL_SUSPECTCOUNT:
	{
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_UNSIGNED, (uchar_t *)&data->d_nsuspects,
		    sizeof (data->d_nsuspects));
		break;
	}
	default:
		break;
	}

	netsnmp_free_delegated_cache(cache);
	(void) pthread_mutex_unlock(&update_lock);
}

static int
sunFmProblemTable_handler(netsnmp_mib_handler *handler,
    netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo,
    netsnmp_request_info *requests)
{
	netsnmp_request_info		*request;
	struct timeval			tv;

	tv.tv_sec = UPDATE_WAIT_MILLIS / 1000;
	tv.tv_usec = (UPDATE_WAIT_MILLIS % 1000) * 1000;

	request_update();

	for (request = requests; request; request = request->next) {
		if (request->processed != 0)
			continue;

		if (netsnmp_extract_table_info(request) == NULL)
			continue;

		request->delegated = 1;
		(void) snmp_alarm_register_hr(tv, 0,
		    sunFmProblemTable_return,
		    (void *) netsnmp_create_delegated_cache(handler, reginfo,
		    reqinfo, request, NULL));
	}

	return (SNMP_ERR_NOERROR);
}

/*ARGSUSED*/
static void
sunFmFaultEventTable_return(unsigned int reg, void *arg)
{
	netsnmp_delegated_cache		*cache = (netsnmp_delegated_cache *)arg;
	netsnmp_request_info		*request;
	netsnmp_agent_request_info	*reqinfo;
	netsnmp_handler_registration	*reginfo;
	netsnmp_table_request_info	*table_info;
	sunFmProblem_data_t		*pdata;
	sunFmFaultEvent_data_t		*data;
	sunFmFaultStatus_data_t		status;

	ASSERT(netsnmp_handler_check_cache(cache) != NULL);

	(void) pthread_mutex_lock(&update_lock);
	if (update_status != US_QUIET) {
		struct timeval			tv;

		tv.tv_sec = UPDATE_WAIT_MILLIS / 1000;
		tv.tv_usec = (UPDATE_WAIT_MILLIS % 1000) * 1000;

		(void) snmp_alarm_register_hr(tv, 0,
		    sunFmFaultEventTable_return, cache);
		(void) pthread_mutex_unlock(&update_lock);
		return;
	}

	request = cache->requests;
	reqinfo = cache->reqinfo;
	reginfo = cache->reginfo;

	table_info = netsnmp_extract_table_info(request);
	request->delegated = 0;

	ASSERT(table_info->colnum >= SUNFMFAULTEVENT_COLMIN);
	ASSERT(table_info->colnum <= SUNFMFAULTEVENT_COLMAX);

	/*
	 * table_info->colnum contains the column number requested.
	 * table_info->indexes contains a linked list of snmp variable
	 * bindings for the indexes of the table.  Values in the list
	 * have been set corresponding to the indexes of the
	 * request.  We have other guarantees as well:
	 *
	 * - The column number is always within range.
	 * - If we have no index data, table_info->index_oid_len is 0.
	 * - We will never receive requests outside our table nor
	 *   those with the first subid anything other than 1 (Entry)
	 *   nor those without a column number.  This is true even
	 *   for GETNEXT requests.
	 */

	switch (reqinfo->mode) {
	case MODE_GET:
		if ((data = sunFmFaultEventTable_fe(reginfo, table_info,
		    &status)) == NULL) {
			netsnmp_free_delegated_cache(cache);
			(void) pthread_mutex_unlock(&update_lock);
			return;
		}
		break;
	case MODE_GETNEXT:
	case MODE_GETBULK:
		if ((data = sunFmFaultEventTable_nextfe(reginfo, table_info,
		    &status)) == NULL) {
			netsnmp_free_delegated_cache(cache);
			(void) pthread_mutex_unlock(&update_lock);
			return;
		}
		break;
	default:
		(void) snmp_log(LOG_ERR, MODNAME_STR ": Unsupported request "
		    "mode %d\n", reqinfo->mode);
		netsnmp_free_delegated_cache(cache);
		(void) pthread_mutex_unlock(&update_lock);
		return;
	}

	switch (table_info->colnum) {
	case SUNFMFAULTEVENT_COL_PROBLEMUUID:
	{
		if ((pdata = sunFmProblemTable_pr(reginfo, table_info))
		    == NULL) {
			(void) netsnmp_table_build_result(reginfo, request,
			    table_info, ASN_OCTET_STR, NULL, 0);
			break;
		}
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)pdata->d_aci_uuid,
		    strlen(pdata->d_aci_uuid));
		break;
	}
	case SUNFMFAULTEVENT_COL_CLASS:
	{
		char	*class = "-";

		(void) nvlist_lookup_string(data, FM_CLASS, &class);
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)class, strlen(class));
		break;
	}
	case SUNFMFAULTEVENT_COL_CERTAINTY:
	{
		uint8_t	pct = 0;
		ulong_t	pl;

		(void) nvlist_lookup_uint8(data, FM_FAULT_CERTAINTY,
		    &pct);
		pl = (ulong_t)pct;
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_UNSIGNED, (uchar_t *)&pl, sizeof (pl));
		break;
	}
	case SUNFMFAULTEVENT_COL_ASRU:
	{
		nvlist_t	*asru = NULL;
		char		*fmri, *str;

		(void) nvlist_lookup_nvlist(data, FM_FAULT_ASRU, &asru);
		if ((str = sunFm_nvl2str(asru)) == NULL)
			fmri = "-";
		else
			fmri = str;

		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)fmri, strlen(fmri));
		free(str);
		break;
	}
	case SUNFMFAULTEVENT_COL_FRU:
	{
		nvlist_t	*fru = NULL;
		char		*fmri, *str;

		(void) nvlist_lookup_nvlist(data, FM_FAULT_FRU, &fru);
		if ((str = sunFm_nvl2str(fru)) == NULL)
			fmri = "-";
		else
			fmri = str;

		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)fmri, strlen(fmri));
		free(str);
		break;
	}
	case SUNFMFAULTEVENT_COL_RESOURCE:
	{
		nvlist_t	*rsrc = NULL;
		char		*fmri, *str;

		(void) nvlist_lookup_nvlist(data, FM_FAULT_RESOURCE, &rsrc);
		if ((str = sunFm_nvl2str(rsrc)) == NULL)
			fmri = "-";
		else
			fmri = str;

		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)fmri, strlen(fmri));
		free(str);
		break;
	}
	case SUNFMFAULTEVENT_COL_STATUS:
	{
		ulong_t	pl = SUNFMFAULTEVENT_STATE_OTHER;

		if (status & FM_SUSPECT_FAULTY)
			pl = SUNFMFAULTEVENT_STATE_FAULTY;
		else if (status & FM_SUSPECT_NOT_PRESENT)
			pl = SUNFMFAULTEVENT_STATE_REMOVED;
		else if (status & FM_SUSPECT_REPLACED)
			pl = SUNFMFAULTEVENT_STATE_REPLACED;
		else if (status & FM_SUSPECT_REPAIRED)
			pl = SUNFMFAULTEVENT_STATE_REPAIRED;
		else if (status & FM_SUSPECT_ACQUITTED)
			pl = SUNFMFAULTEVENT_STATE_ACQUITTED;
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_INTEGER, (uchar_t *)&pl, sizeof (pl));
		break;
	}
	case SUNFMFAULTEVENT_COL_LOCATION:
	{
		char	*location = "-";

		(void) nvlist_lookup_string(data, FM_FAULT_LOCATION, &location);
		(void) netsnmp_table_build_result(reginfo, request, table_info,
		    ASN_OCTET_STR, (uchar_t *)location, strlen(location));
		break;
	}
	default:
		break;
	}

	netsnmp_free_delegated_cache(cache);
	(void) pthread_mutex_unlock(&update_lock);
}

static int
sunFmFaultEventTable_handler(netsnmp_mib_handler *handler,
    netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo,
    netsnmp_request_info *requests)
{
	netsnmp_request_info		*request;
	struct timeval			tv;

	tv.tv_sec = UPDATE_WAIT_MILLIS / 1000;
	tv.tv_usec = (UPDATE_WAIT_MILLIS % 1000) * 1000;

	request_update();

	for (request = requests; request; request = request->next) {
		if (request->processed != 0)
			continue;

		if (netsnmp_extract_table_info(request) == NULL)
			continue;

		request->delegated = 1;
		(void) snmp_alarm_register_hr(tv, 0,
		    sunFmFaultEventTable_return,
		    (void *) netsnmp_create_delegated_cache(handler, reginfo,
		    reqinfo, request, NULL));
	}

	return (SNMP_ERR_NOERROR);
}
