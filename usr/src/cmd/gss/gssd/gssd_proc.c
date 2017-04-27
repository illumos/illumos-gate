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
 * Copyright 2017 Joyent Inc
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *  RPC server procedures for the gssapi usermode daemon gssd.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <strings.h>
#include <limits.h>
#include <sys/param.h>
#include <mechglueP.h>
#include "gssd.h"
#include <gssapi/gssapi.h>
#include <rpc/rpc.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/debug.h>

#define	SRVTAB	""
#define	FDCACHE_PERCENTAGE	.75	/* Percentage of total FD limit */
#define	FDCACHE_DEFAULT		16	/* Default LRU cache size */
#define	GSSD_FD_LIMIT		255	/* Increase number of fds allowed */

extern int gssd_debug;			/* declared in gssd.c */
static OM_uint32 gssd_time_verf;	/* verifies same gssd */
static OM_uint32 context_verf;		/* context sequence numbers */

struct gssd_ctx_slot {
	struct gssd_ctx_slot *lru_next;
	struct gssd_ctx_slot *lru_prev;
	bool_t		inuse;
	OM_uint32	create_time;
	OM_uint32	verf;
	gss_ctx_id_t	ctx;
	gss_ctx_id_t	rpcctx;
};

struct gssd_ctx_slot *gssd_ctx_slot_tbl;
struct gssd_ctx_slot *gssd_lru_head;

static int max_contexts;

static int checkfrom(struct svc_req *, uid_t *);
extern void set_gssd_uid(uid_t);
extern int __rpc_get_local_uid(SVCXPRT *, uid_t *);

/*
 * Syslog (and output to stderr if debug set) the GSSAPI major
 * and minor numbers.
 */
static void
syslog_gss_error(OM_uint32 maj_stat, OM_uint32 min_stat, char *errstr)
{
	OM_uint32 gmaj_stat, gmin_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx = 0;


	if (gssd_debug)
		fprintf(stderr,
		    "gssd: syslog_gss_err: called from %s: maj=%d min=%d\n",
		    errstr ? errstr : "<null>", maj_stat, min_stat);

	/* Print the major status error from the mech. */
	/* msg_ctx - skip the check for it as is probably unnecesary */
	gmaj_stat = gss_display_status(&gmin_stat, maj_stat,
	    GSS_C_GSS_CODE,
	    GSS_C_NULL_OID, &msg_ctx, &msg);
	if ((gmaj_stat == GSS_S_COMPLETE)||
	    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
		syslog(LOG_DAEMON|LOG_NOTICE,
		    "GSSAPI error major: %s", (char *)msg.value);
		if (gssd_debug)
			(void) fprintf(stderr,
			    "gssd: GSSAPI error major: %s\n",
			    (char *)msg.value);

		(void) gss_release_buffer(&gmin_stat, &msg);
	}

	/* Print the minor status error from the mech. */
	msg_ctx = 0;
	/* msg_ctx - skip the check for it as is probably unnecesary */
	gmaj_stat = gss_display_status(&gmin_stat, min_stat,
	    GSS_C_MECH_CODE,
	    GSS_C_NULL_OID,
	    &msg_ctx, &msg);
	if ((gmaj_stat == GSS_S_COMPLETE)||
	    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
		syslog(LOG_DAEMON|LOG_NOTICE,
		    "GSSAPI error minor: %s",
		    (char *)msg.value);
		if (gssd_debug)
			(void) fprintf(stderr,
			    "gssd: GSSAPI error minor: %s\n",
			    (char *)msg.value);
		(void) gss_release_buffer(&gmin_stat, &msg);
	}
}

void
gssd_setup(char *arg)
{
	int i;
	struct rlimit rl;
	hrtime_t high_res_time;

	gssd_time_verf = (OM_uint32)time(NULL);
	max_contexts = FDCACHE_DEFAULT;

	/*
	 * Use low order bits of high resolution time to get a reasonably
	 * random number to start the context sequencing.  This alternative
	 * to using a time value avoid clock resets via NTP or ntpdate.
	 */
	high_res_time = gethrtime();
	context_verf = (OM_uint32)high_res_time;

	/*
	 * Increase resource limit of FDs in case we get alot accept/init_
	 * sec_context calls before we're able to export them.  This can
	 * happen in very heavily load environments where gssd doesn't get
	 * much time to work on its backlog.
	 */
	if ((getrlimit(RLIMIT_NOFILE, &rl)) == 0) {
		rl.rlim_cur = (rl.rlim_max >= GSSD_FD_LIMIT) ?
				GSSD_FD_LIMIT : rl.rlim_max;
		if ((setrlimit(RLIMIT_NOFILE, &rl)) == 0)
			max_contexts = rl.rlim_cur * FDCACHE_PERCENTAGE;
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	gssd_ctx_slot_tbl = (struct gssd_ctx_slot *)
		malloc(sizeof (struct gssd_ctx_slot) * max_contexts);

	if (gssd_ctx_slot_tbl == NULL) {
		(void) fprintf(stderr,
			gettext("[%s] could not allocate %d byte context table"
			"\n"), arg,
			(sizeof (struct gssd_ctx_slot) * max_contexts));
		exit(1);
	}

	for (i = 1; i < max_contexts; i++) {
		gssd_ctx_slot_tbl[i-1].lru_next = &gssd_ctx_slot_tbl[i];
		gssd_ctx_slot_tbl[i].lru_prev = &gssd_ctx_slot_tbl[i-1];
		gssd_ctx_slot_tbl[i].inuse = FALSE;
		gssd_ctx_slot_tbl[i].verf = 0;
		gssd_ctx_slot_tbl[i].create_time = 0;
		gssd_ctx_slot_tbl[i].rpcctx = (gss_ctx_id_t)(i + 1);
	}

	gssd_ctx_slot_tbl[max_contexts - 1].lru_next = &gssd_ctx_slot_tbl[0];
	gssd_ctx_slot_tbl[0].lru_prev = &gssd_ctx_slot_tbl[max_contexts - 1];
	gssd_ctx_slot_tbl[0].inuse = FALSE;
	gssd_ctx_slot_tbl[0].verf = 0;
	gssd_ctx_slot_tbl[0].create_time = 0;
	gssd_ctx_slot_tbl[0].rpcctx = (gss_ctx_id_t)1;

	gssd_lru_head = &gssd_ctx_slot_tbl[0];
}

static OM_uint32 syslog_interval = 60;

static struct gssd_ctx_slot *
gssd_alloc_slot(gss_ctx_id_t ctx)
{
	struct gssd_ctx_slot *lru;
	OM_uint32 current_time;
	static OM_uint32 last_syslog = 0;
	static bool_t first_take = TRUE;
	static int tooks;
	OM_uint32 minor_status;

	lru = gssd_lru_head;
	gssd_lru_head = lru->lru_next;

	current_time = (OM_uint32) time(NULL);

	if (last_syslog == 0)
		last_syslog = current_time;	/* Save 1st alloc time */

	if (lru->inuse) {
		if (lru->ctx != GSS_C_NO_CONTEXT)
			(void) gss_delete_sec_context(&minor_status,
				&lru->ctx, NULL);
		tooks++;

		if (((current_time - last_syslog) > syslog_interval) ||
			first_take) {
			syslog(LOG_WARNING, gettext("re-used an existing "
				"context slot of age %u seconds (%d slots re-"
				"used during last %u seconds)"),
				current_time - lru->create_time, tooks,
				current_time - last_syslog);

			last_syslog = current_time;
			tooks = 0;
			first_take = FALSE;
		}
	}

	/*
	 * Assign the next context verifier to the context (avoiding zero).
	 */
	context_verf++;
	if (context_verf == 0)
		context_verf = 1;
	lru->verf = context_verf;

	lru->create_time = current_time;
	lru->ctx = ctx;
	lru->inuse = TRUE;
	return (lru);
}

/*
 * We always add 1 because we don't want slot 0 to be confused
 * with GSS_C_NO_CONTEXT.
 */

static struct gssd_ctx_slot *
gssd_handle_to_slot(GSS_CTX_ID_T *h)
{
	intptr_t i;

	if (h->GSS_CTX_ID_T_len == 0) {
		return (NULL);
	}
	if (h->GSS_CTX_ID_T_len != sizeof (i))
		return (NULL);

	i = (*(intptr_t *)(h->GSS_CTX_ID_T_val)) - 1;

	if (i < 0 || i >= max_contexts)
		return (NULL);

	return (&gssd_ctx_slot_tbl[i]);
}

static void
gssd_rel_slot(struct gssd_ctx_slot *lru)
{
	struct gssd_ctx_slot *prev, *next;

	if (lru == NULL)
		return;

	lru->inuse = FALSE;

	/*
	 * Remove entry from its current location in list
	 */
	prev = lru->lru_prev;
	next = lru->lru_next;
	prev->lru_next = next;
	next->lru_prev = prev;

	/*
	 * Since it is no longer in use, it is the least recently
	 * used.
	 */
	prev = gssd_lru_head->lru_prev;
	next = gssd_lru_head;

	prev->lru_next = lru;
	lru->lru_prev = prev;

	next->lru_prev = lru;
	lru->lru_next = next;

	gssd_lru_head = lru;
}

static void
gssd_convert_context_handle(GSS_CTX_ID_T *h,
	gss_ctx_id_t *context_handle,
	OM_uint32 verf,
	bool_t *context_verf_ok,
	struct gssd_ctx_slot **slotp)
{
	struct gssd_ctx_slot *slot;

	*context_verf_ok = FALSE;
	*context_handle = (gss_ctx_id_t)1;
	if (slotp != NULL)
		*slotp = NULL;

	if (h->GSS_CTX_ID_T_len == 0) {
		*context_handle = GSS_C_NO_CONTEXT;
		*context_verf_ok = TRUE;
		return;
	}

	slot = gssd_handle_to_slot(h);

	if (slot == NULL)
		return;

	if (verf != slot->verf)
		return;

	*context_verf_ok = TRUE;
	*context_handle = slot->ctx;
	if (slotp != NULL)
		*slotp = slot;
}

bool_t
gss_acquire_cred_1_svc(argp, res, rqstp)
	gss_acquire_cred_arg *argp;
	gss_acquire_cred_res *res;
	struct svc_req *rqstp;
{
	OM_uint32 		minor_status;
	gss_name_t		desired_name;
	gss_OID_desc		name_type_desc;
	gss_OID			name_type = &name_type_desc;
	OM_uint32		time_req;
	gss_OID_set_desc	desired_mechs_desc;
	gss_OID_set		desired_mechs;
	int			cred_usage;
	gss_cred_id_t 		output_cred_handle;
	gss_OID_set 		actual_mechs;
	gss_buffer_desc		external_name;
	uid_t			uid;
	int			i, j;

	if (gssd_debug)
		fprintf(stderr, gettext("gss_acquire_cred\n"));

	memset(res, 0, sizeof (*res));

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->output_cred_handle.GSS_CRED_ID_T_val = NULL;
		res->actual_mechs.GSS_OID_SET_val = NULL;
		return (FALSE);
	}

/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

/* convert the desired name from external to internal format */

	external_name.length = argp->desired_name.GSS_BUFFER_T_len;
	external_name.value = (void *)malloc(external_name.length);
	if (!external_name.value)
		return (GSS_S_FAILURE);
	memcpy(external_name.value, argp->desired_name.GSS_BUFFER_T_val,
		external_name.length);

	if (argp->name_type.GSS_OID_len == 0) {
		name_type = GSS_C_NULL_OID;
	} else {
		name_type->length = argp->name_type.GSS_OID_len;
		name_type->elements = (void *)malloc(name_type->length);
		if (!name_type->elements) {
			free(external_name.value);
			return (GSS_S_FAILURE);
		}
		memcpy(name_type->elements, argp->name_type.GSS_OID_val,
			name_type->length);
	}

	if (gss_import_name(&minor_status, &external_name, name_type,
			    &desired_name) != GSS_S_COMPLETE) {

		res->status = (OM_uint32) GSS_S_FAILURE;
		res->minor_status = minor_status;

		free(external_name.value);
		if (name_type != GSS_C_NULL_OID)
			free(name_type->elements);

		return (TRUE);
	}

/*
 * copy the XDR structured arguments into their corresponding local GSSAPI
 * variables.
 */

	cred_usage = argp->cred_usage;
	time_req = argp->time_req;

	if (argp->desired_mechs.GSS_OID_SET_len != 0) {
		desired_mechs = &desired_mechs_desc;
		desired_mechs->count =
			(int)argp->desired_mechs.GSS_OID_SET_len;
		desired_mechs->elements = (gss_OID)
			malloc(sizeof (gss_OID_desc) * desired_mechs->count);
		if (!desired_mechs->elements) {
			free(external_name.value);
			free(name_type->elements);
			return (GSS_S_FAILURE);
		}
		for (i = 0; i < desired_mechs->count; i++) {
			desired_mechs->elements[i].length =
				(OM_uint32)argp->desired_mechs.
				GSS_OID_SET_val[i].GSS_OID_len;
			desired_mechs->elements[i].elements =
				(void *)malloc(desired_mechs->elements[i].
						length);
			if (!desired_mechs->elements[i].elements) {
				free(external_name.value);
				free(name_type->elements);
				for (j = 0; j < (i -1); j++) {
					free
					(desired_mechs->elements[j].elements);
				}
				free(desired_mechs->elements);
				return (GSS_S_FAILURE);
			}
			memcpy(desired_mechs->elements[i].elements,
				argp->desired_mechs.GSS_OID_SET_val[i].
				GSS_OID_val,
				desired_mechs->elements[i].length);
		}
	} else
		desired_mechs = GSS_C_NULL_OID_SET;

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_acquire_cred(&res->minor_status,
				desired_name,
				time_req,
				desired_mechs,
				cred_usage,
				&output_cred_handle,
				&actual_mechs,
				&res->time_rec);

	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result
	 */

	res->output_cred_handle.GSS_CRED_ID_T_len = sizeof (gss_cred_id_t);
	res->output_cred_handle.GSS_CRED_ID_T_val =
		(void *)malloc(sizeof (gss_cred_id_t));
	if (!res->output_cred_handle.GSS_CRED_ID_T_val) {
		free(external_name.value);
		free(name_type->elements);
		for (i = 0; i < desired_mechs->count; i++) {
			free(desired_mechs->elements[i].elements);
			}
		free(desired_mechs->elements);
		return (GSS_S_FAILURE);
	}
	memcpy(res->output_cred_handle.GSS_CRED_ID_T_val, &output_cred_handle,
		sizeof (gss_cred_id_t));

	if (actual_mechs != GSS_C_NULL_OID_SET) {
		res->actual_mechs.GSS_OID_SET_len =
			(uint_t)actual_mechs->count;
		res->actual_mechs.GSS_OID_SET_val = (GSS_OID *)
			malloc(sizeof (GSS_OID) * actual_mechs->count);
		if (!res->actual_mechs.GSS_OID_SET_val) {
			free(external_name.value);
			free(name_type->elements);
			for (i = 0; i < desired_mechs->count; i++) {
				free(desired_mechs->elements[i].elements);
			}
			free(desired_mechs->elements);
			free(res->output_cred_handle.GSS_CRED_ID_T_val);
			return (GSS_S_FAILURE);
		}
		for (i = 0; i < actual_mechs->count; i++) {
			res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_len =
				(uint_t)actual_mechs->elements[i].length;
			res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_val =
				(char *)malloc(actual_mechs->elements[i].
						length);
			if (!res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_val) {
				free(external_name.value);
				free(name_type->elements);
				free(desired_mechs->elements);
				for (j = 0; j < desired_mechs->count; j++) {
					free
					(desired_mechs->elements[i].elements);
				}
				free(res->actual_mechs.GSS_OID_SET_val);
				for (j = 0; j < (i - 1); j++) {
					free
					(res->actual_mechs.
						GSS_OID_SET_val[j].GSS_OID_val);
				}
				return (GSS_S_FAILURE);
			}
			memcpy(res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_val,
				actual_mechs->elements[i].elements,
				actual_mechs->elements[i].length);
		}
	} else
		res->actual_mechs.GSS_OID_SET_len = 0;

	/*
	 * set the time verifier for credential handle.  To ensure that the
	 * timestamp is not the same as previous gssd process, verify that
	 * time is not the same as set earlier at start of process.  If it
	 * is, sleep one second and reset. (due to one second granularity)
	 */

	if (res->status == GSS_S_COMPLETE) {
		res->gssd_cred_verifier = (OM_uint32)time(NULL);
		if (res->gssd_cred_verifier == gssd_time_verf) {
			sleep(1);
			gssd_time_verf = (OM_uint32)time(NULL);
		}
		res->gssd_cred_verifier = gssd_time_verf;
	} else
		syslog_gss_error(res->status, res->minor_status,
		    "acquire_cred");

	/*
	 * now release the space allocated by the underlying gssapi mechanism
	 * library for actual_mechs as well as by this routine for
	 * external_name, name_type and desired_name
	 */

	free(external_name.value);
	if (name_type != GSS_C_NULL_OID)
		free(name_type->elements);
	gss_release_name(&minor_status, &desired_name);

	if (actual_mechs != GSS_C_NULL_OID_SET) {
		for (i = 0; i < actual_mechs->count; i++)
			free(actual_mechs->elements[i].elements);
		free(actual_mechs->elements);
		free(actual_mechs);
	}

	if (desired_mechs != GSS_C_NULL_OID_SET) {
		for (i = 0; i < desired_mechs->count; i++)
			free(desired_mechs->elements[i].elements);
		free(desired_mechs->elements);

	}

/* return to caller */

	return (TRUE);
}

bool_t
gss_add_cred_1_svc(argp, res, rqstp)
	gss_add_cred_arg *argp;
	gss_add_cred_res *res;
	struct svc_req *rqstp;
{

	OM_uint32 		minor_status;
	gss_name_t		desired_name;
	gss_OID_desc		name_type_desc;
	gss_OID			name_type = &name_type_desc;
	gss_OID_desc		desired_mech_type_desc;
	gss_OID			desired_mech_type = &desired_mech_type_desc;
	int			cred_usage;
	gss_cred_id_t 		input_cred_handle;
	gss_OID_set 		actual_mechs;
	gss_buffer_desc		external_name;
	uid_t			uid;
	int			i, j;

	if (gssd_debug)
		fprintf(stderr, gettext("gss_add_cred\n"));

	if (argp->gssd_cred_verifier != gssd_time_verf) {
		res->status = (OM_uint32)GSS_S_DEFECTIVE_CREDENTIAL;
		res->minor_status = 0;
		res->actual_mechs.GSS_OID_SET_len = 0;
		res->actual_mechs.GSS_OID_SET_val = NULL;
		res->initiator_time_rec = 0;
		res->acceptor_time_rec = 0;
		fprintf(stderr, gettext("gss_add_cred defective cred\n"));
		return (TRUE);
	}
	memset(res, 0, sizeof (*res));

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		return (FALSE);
	}

/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

/* convert the desired name from external to internal format */

	external_name.length = argp->desired_name.GSS_BUFFER_T_len;
	external_name.value = (void *)argp->desired_name.GSS_BUFFER_T_val;
	name_type->length = argp->name_type.GSS_OID_len;
	name_type->elements = (void *)argp->name_type.GSS_OID_val;

	if (gss_import_name(&minor_status, &external_name, name_type,
			    &desired_name) != GSS_S_COMPLETE) {

		if (gssd_debug)
			fprintf(stderr,
				gettext("gss_add_cred:import name"),
				gettext(" failed status %d \n"),
				res->status);
		res->status = (OM_uint32)GSS_S_FAILURE;
		res->minor_status = minor_status;
		return (TRUE);
	}

/*
 * copy the XDR structured arguments into their corresponding local GSSAPI
 * variables.
 */

	cred_usage = argp->cred_usage;
	if (argp->desired_mech_type.GSS_OID_len == 0)
		desired_mech_type = GSS_C_NULL_OID;
	else {
		desired_mech_type->length =
			(OM_uint32)argp->desired_mech_type.GSS_OID_len;
		desired_mech_type->elements =
			(void *)malloc(desired_mech_type->length);
		if (!desired_mech_type->elements) {
			return (GSS_S_FAILURE);
		}
		memcpy(desired_mech_type->elements,
			argp->desired_mech_type.GSS_OID_val,
			desired_mech_type->length);
	}
	input_cred_handle =
		(argp->input_cred_handle.GSS_CRED_ID_T_len == 0 ?
			GSS_C_NO_CREDENTIAL :
			/*LINTED*/
			*((gss_cred_id_t *)argp->input_cred_handle.
				GSS_CRED_ID_T_val));

	if (input_cred_handle != GSS_C_NO_CREDENTIAL)
	/* verify the input_cred_handle */
		if (argp->gssd_cred_verifier != gssd_time_verf) {
			res->status = (OM_uint32)GSS_S_DEFECTIVE_CREDENTIAL;
			res->minor_status = 0;
			return (TRUE);
		}

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_add_cred(&res->minor_status,
				input_cred_handle,
				desired_name,
				desired_mech_type,
				cred_usage,
				argp->initiator_time_req,
				argp->acceptor_time_req,
				NULL,
				&actual_mechs,
				&res->initiator_time_rec,
				&res->acceptor_time_rec);

	if ((res->status != GSS_S_COMPLETE) &&
		(res->status != GSS_S_DUPLICATE_ELEMENT))
		syslog_gss_error(res->status, res->minor_status, "add_cred");

	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result
	 */
	if (actual_mechs != GSS_C_NULL_OID_SET) {
		res->actual_mechs.GSS_OID_SET_len =
			(uint_t)actual_mechs->count;
		res->actual_mechs.GSS_OID_SET_val = (GSS_OID *)
			malloc(sizeof (GSS_OID) * actual_mechs->count);
		if (!res->actual_mechs.GSS_OID_SET_val) {
			free(desired_mech_type->elements);
			free(desired_mech_type);
			return (GSS_S_FAILURE);
		}
		for (i = 0; i < actual_mechs->count; i++) {
			res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_len =
				(uint_t)actual_mechs->elements[i].length;
			res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_val =
				(char *)malloc(actual_mechs->elements[i].
						length);
			if (!res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_val) {
				free(desired_mech_type->elements);
				free(desired_mech_type);
				free(res->actual_mechs.GSS_OID_SET_val);
				for (j = 0; j < (i - 1); j++) {
					free
					(res->actual_mechs.
						GSS_OID_SET_val[j].GSS_OID_val);
				}
				return (GSS_S_FAILURE);
			}
			memcpy(res->actual_mechs.GSS_OID_SET_val[i].GSS_OID_val,
				actual_mechs->elements[i].elements,
				actual_mechs->elements[i].length);
		}
	} else
		res->actual_mechs.GSS_OID_SET_len = 0;

	/*
	 * now release the space allocated for
	 * desired_name  and desired_mech_type
	 */

	gss_release_name(&minor_status, &desired_name);
	free(desired_mech_type->elements);
	gss_release_oid_set(&minor_status, &actual_mechs);
	/*
	 * if (actual_mechs != GSS_C_NULL_OID_SET) {
	 * 	for (i = 0; i < actual_mechs->count; i++)
	 * 		free(actual_mechs->elements[i].elements);
	 * 	free(actual_mechs->elements);
	 * 	free(actual_mechs);
	 * }
	 */


/* return to caller */

	return (TRUE);
}

bool_t
gss_release_cred_1_svc(argp, res, rqstp)
gss_release_cred_arg *argp;
gss_release_cred_res *res;
struct svc_req *rqstp;
{

	uid_t uid;
	gss_cred_id_t cred_handle;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_release_cred\n"));

	if (checkfrom(rqstp, &uid) == 0)
		return (FALSE);

	/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

	/*
	 * if the cred_handle verifier is not correct,
	 * set status to GSS_S_DEFECTIVE_CREDENTIAL and return
	 */

	if (argp->gssd_cred_verifier != gssd_time_verf) {
		res->status = (OM_uint32)GSS_S_DEFECTIVE_CREDENTIAL;
		return (TRUE);
	}

	/*
	 * if the cred_handle length is 0
	 * set cred_handle argument to GSS_S_NO_CREDENTIAL
	 */

	if (argp->cred_handle.GSS_CRED_ID_T_len == 0)
		cred_handle = GSS_C_NO_CREDENTIAL;
	else
		cred_handle =
		(gss_cred_id_t)argp->cred_handle.GSS_CRED_ID_T_val;

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_release_cred(&res->minor_status,
					&cred_handle);

	/* return to caller */

	return (TRUE);
}

bool_t
gss_init_sec_context_1_svc(argp, res, rqstp)
gss_init_sec_context_arg *argp;
gss_init_sec_context_res *res;
struct svc_req *rqstp;
{

	OM_uint32 	minor_status;
	gss_ctx_id_t	context_handle;
	bool_t context_verf_ok;
	gss_cred_id_t	claimant_cred_handle;
	gss_buffer_desc	external_name;
	gss_OID_desc	name_type_desc;
	gss_OID		name_type = &name_type_desc;
	gss_name_t	internal_name;

	gss_OID_desc	mech_type_desc;
	gss_OID		mech_type = &mech_type_desc;
	struct gss_channel_bindings_struct
			input_chan_bindings;
	gss_channel_bindings_t input_chan_bindings_ptr;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token;
	gss_buffer_t input_token_ptr;
	gss_OID actual_mech_type;
	struct gssd_ctx_slot *slot = NULL;

	uid_t uid;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_init_sec_context\n"));

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->context_handle.GSS_CTX_ID_T_val =  NULL;
		res->actual_mech_type.GSS_OID_val = NULL;
		res->output_token.GSS_BUFFER_T_val = NULL;
		return (FALSE);
	}

/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

/*
 * copy the supplied context handle into the local context handle, so it
 * can be supplied to the gss_init_sec_context call
 */

	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, &slot);

	claimant_cred_handle =
		(argp->claimant_cred_handle.GSS_CRED_ID_T_len == 0 ?
		GSS_C_NO_CREDENTIAL :
		/*LINTED*/
		*((gss_cred_id_t *)argp->claimant_cred_handle.
			GSS_CRED_ID_T_val));

	if (claimant_cred_handle != GSS_C_NO_CREDENTIAL) {
		/* verify the verifier_cred_handle */
		if (argp->gssd_cred_verifier != gssd_time_verf) {
			res->context_handle.GSS_CTX_ID_T_val = NULL;
			res->output_token.GSS_BUFFER_T_val = NULL;
			res->actual_mech_type.GSS_OID_val = NULL;
			res->context_handle.GSS_CTX_ID_T_len = 0;
			res->output_token.GSS_BUFFER_T_len = 0;
			res->actual_mech_type.GSS_OID_len = 0;
			res->status = (OM_uint32)GSS_S_DEFECTIVE_CREDENTIAL;
			res->minor_status = 0;
			return (TRUE);
		}
	}

	if (context_handle != GSS_C_NO_CONTEXT) {
		/* verify the verifier_context_handle */

		if (!context_verf_ok) {
			res->context_handle.GSS_CTX_ID_T_val = NULL;
			res->output_token.GSS_BUFFER_T_val = NULL;
			res->actual_mech_type.GSS_OID_val = NULL;
			res->context_handle.GSS_CTX_ID_T_len = 0;
			res->output_token.GSS_BUFFER_T_len = 0;
			res->actual_mech_type.GSS_OID_len = 0;
			res->status = (OM_uint32)GSS_S_NO_CONTEXT;
			res->minor_status = 0;
			return (TRUE);
		}
	}

	/* convert the target name from external to internal format */

	external_name.length = argp->target_name.GSS_BUFFER_T_len;
	external_name.value = (void *)argp->target_name.GSS_BUFFER_T_val;

	if (argp->name_type.GSS_OID_len == 0) {
		name_type = GSS_C_NULL_OID;
	} else {
		name_type->length = argp->name_type.GSS_OID_len;
		name_type->elements = (void *)malloc(name_type->length);
		if (!name_type->elements)
			return (GSS_S_FAILURE);
		memcpy(name_type->elements, argp->name_type.GSS_OID_val,
			name_type->length);
	}

	if (argp->mech_type.GSS_OID_len == 0)
		mech_type = GSS_C_NULL_OID;
	else {
		mech_type->length = (OM_uint32)argp->mech_type.GSS_OID_len;
		mech_type->elements = (void *)argp->mech_type.GSS_OID_val;
	}

	if (gss_import_name(&minor_status, &external_name, name_type,
			    &internal_name) != GSS_S_COMPLETE) {

		if (name_type != GSS_C_NULL_OID)
			free(name_type->elements);
		res->status = (OM_uint32)GSS_S_FAILURE;
		res->minor_status = minor_status;

		return (TRUE);
	}
/*
 * copy the XDR structured arguments into their corresponding local GSSAPI
 * variables.
 */

	if (argp->input_chan_bindings.present == YES) {
		input_chan_bindings_ptr = &input_chan_bindings;
		input_chan_bindings.initiator_addrtype =
			(OM_uint32)argp->input_chan_bindings.
			initiator_addrtype;
		input_chan_bindings.initiator_address.length =
			(uint_t)argp->input_chan_bindings.initiator_address.
			GSS_BUFFER_T_len;
		input_chan_bindings.initiator_address.value =
			(void *)argp->input_chan_bindings.initiator_address.
			GSS_BUFFER_T_val;
		input_chan_bindings.acceptor_addrtype =
			(OM_uint32)argp->input_chan_bindings.acceptor_addrtype;
		input_chan_bindings.acceptor_address.length =
			(uint_t)argp->input_chan_bindings.acceptor_address.
			GSS_BUFFER_T_len;
		input_chan_bindings.acceptor_address.value =
			(void *)argp->input_chan_bindings.acceptor_address.
			GSS_BUFFER_T_val;
		input_chan_bindings.application_data.length =
			(uint_t)argp->input_chan_bindings.application_data.
			GSS_BUFFER_T_len;
		input_chan_bindings.application_data.value =
			(void *)argp->input_chan_bindings.application_data.
			GSS_BUFFER_T_val;
	} else {
		input_chan_bindings_ptr = GSS_C_NO_CHANNEL_BINDINGS;
		input_chan_bindings.initiator_addrtype = 0;
		input_chan_bindings.initiator_address.length = 0;
		input_chan_bindings.initiator_address.value = 0;
		input_chan_bindings.acceptor_addrtype = 0;
		input_chan_bindings.acceptor_address.length = 0;
		input_chan_bindings.acceptor_address.value = 0;
		input_chan_bindings.application_data.length = 0;
		input_chan_bindings.application_data.value = 0;
	}

	if (argp->input_token.GSS_BUFFER_T_len == 0) {
		input_token_ptr = GSS_C_NO_BUFFER;
	} else {
		input_token_ptr = &input_token;
		input_token.length = (size_t)
				argp->input_token.GSS_BUFFER_T_len;
		input_token.value = (void *)argp->input_token.GSS_BUFFER_T_val;
	}

/* call the gssapi routine */

	res->status = (OM_uint32)gss_init_sec_context(&res->minor_status,
			(gss_cred_id_t)argp->claimant_cred_handle.
						GSS_CRED_ID_T_val,
					&context_handle,
					internal_name,
					mech_type,
					argp->req_flags,
					argp->time_req,
					input_chan_bindings_ptr,
					input_token_ptr,
					&actual_mech_type,
					&output_token,
					&res->ret_flags,
					&res->time_rec);

	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result
	 */

	if (res->status == (OM_uint32)GSS_S_COMPLETE ||
		res->status == (OM_uint32)GSS_S_CONTINUE_NEEDED) {

		if (slot == NULL || slot->ctx != context_handle) {
			/*
			 * Note that gssd_alloc_slot() will delete ctx's as long
			 * as we don't call gssd_rel_slot().
			 */
			slot = gssd_alloc_slot(context_handle);
		}

		res->gssd_context_verifier = slot->verf;

		res->context_handle.GSS_CTX_ID_T_len = sizeof (gss_ctx_id_t);
		res->context_handle.GSS_CTX_ID_T_val =
			(void *)malloc(sizeof (gss_ctx_id_t));
		if (!res->context_handle.GSS_CTX_ID_T_val) {
			free(name_type->elements);
			return (GSS_S_FAILURE);
		}

		memcpy(res->context_handle.GSS_CTX_ID_T_val, &slot->rpcctx,
			sizeof (gss_ctx_id_t));

		res->output_token.GSS_BUFFER_T_len =
			(uint_t)output_token.length;
		res->output_token.GSS_BUFFER_T_val =
			(char *)output_token.value;

		/*
		 * the actual mech type parameter
		 * is ready only upon GSS_S_COMPLETE
		 */
		if (res->status == GSS_S_COMPLETE) {
			res->actual_mech_type.GSS_OID_len =
				(uint_t)actual_mech_type->length;
			res->actual_mech_type.GSS_OID_val =
				(void *)malloc(actual_mech_type->length);
			if (!res->actual_mech_type.GSS_OID_val) {
				free(name_type->elements);
				free(res->context_handle.GSS_CTX_ID_T_val);
				return (GSS_S_FAILURE);
			}
			memcpy(res->actual_mech_type.GSS_OID_val,
				(char *)actual_mech_type->elements,
				actual_mech_type->length);
		} else
			res->actual_mech_type.GSS_OID_len = 0;
	} else {
		syslog_gss_error(res->status, res->minor_status,
			    "init_sec_context");
		if (context_handle != GSS_C_NO_CONTEXT) {
			(void) gss_delete_sec_context(&minor_status,
				&context_handle, NULL);
		}
		res->context_handle.GSS_CTX_ID_T_len = 0;
		res->actual_mech_type.GSS_OID_len = 0;
		res->output_token.GSS_BUFFER_T_len = 0;
	}

	/*
	 * now release the space allocated by the underlying gssapi mechanism
	 * library for internal_name and for the name_type.
	 */

	gss_release_name(&minor_status, &internal_name);
	if (name_type != GSS_C_NULL_OID)
		free(name_type->elements);


	/* return to caller */
	return (TRUE);
}

bool_t
gss_accept_sec_context_1_svc(argp, res, rqstp)
gss_accept_sec_context_arg *argp;
gss_accept_sec_context_res *res;
struct svc_req *rqstp;
{
	uid_t uid;
	OM_uint32 minor_status;
	gss_ctx_id_t context_handle = NULL;
	gss_cred_id_t verifier_cred_handle;
	gss_buffer_desc external_name;
	gss_name_t internal_name = NULL;

	gss_buffer_desc input_token_buffer;
	gss_buffer_t input_token_buffer_ptr;
	struct gss_channel_bindings_struct
			input_chan_bindings;
	gss_channel_bindings_t input_chan_bindings_ptr;
	gss_OID mech_type;
	gss_buffer_desc output_token;
	gss_cred_id_t delegated_cred_handle;
	bool_t context_verf_ok;
	struct gssd_ctx_slot *slot = NULL;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_accept_sec_context\n"));

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->context_handle.GSS_CTX_ID_T_val = NULL;
		res->src_name.GSS_BUFFER_T_val = NULL;
		res->mech_type.GSS_OID_val = NULL;
		res->output_token.GSS_BUFFER_T_val = NULL;
		res->delegated_cred_handle.GSS_CRED_ID_T_val = NULL;
		return (FALSE);
	}

	/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

	/*
	 * copy the supplied context handle into the local context handle, so
	 * it can be supplied to the gss_accept_sec_context call
	 */

	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, &slot);

	if (context_handle != GSS_C_NO_CONTEXT)
		/* verify the context_handle */
		if (!context_verf_ok) {
			res->context_handle.GSS_CTX_ID_T_val = NULL;
			res->src_name.GSS_BUFFER_T_val = NULL;
			res->mech_type.GSS_OID_val = NULL;
			res->output_token.GSS_BUFFER_T_val = NULL;
			res->delegated_cred_handle.GSS_CRED_ID_T_val = NULL;
			res->src_name.GSS_BUFFER_T_len = 0;
			res->context_handle.GSS_CTX_ID_T_len = 0;
			res->delegated_cred_handle.GSS_CRED_ID_T_len = 0;
			res->output_token.GSS_BUFFER_T_len = 0;
			res->mech_type.GSS_OID_len = 0;
			res->status = (OM_uint32)GSS_S_NO_CONTEXT;
			res->minor_status = 0;
			return (TRUE);
		}

	/*
	 * copy the XDR structured arguments into their corresponding local
	 * GSSAPI variable equivalents.
	 */


	verifier_cred_handle =
		(argp->verifier_cred_handle.GSS_CRED_ID_T_len == 0 ?
			GSS_C_NO_CREDENTIAL :
			/*LINTED*/
			*((gss_cred_id_t *)argp->verifier_cred_handle.
				GSS_CRED_ID_T_val));

	if (verifier_cred_handle != GSS_C_NO_CREDENTIAL)
	/* verify the verifier_cred_handle */
		if (argp->gssd_cred_verifier != gssd_time_verf) {
			res->context_handle.GSS_CTX_ID_T_val = NULL;
			res->src_name.GSS_BUFFER_T_val = NULL;
			res->mech_type.GSS_OID_val = NULL;
			res->output_token.GSS_BUFFER_T_val = NULL;
			res->delegated_cred_handle.GSS_CRED_ID_T_val = NULL;
			res->src_name.GSS_BUFFER_T_len = 0;
			res->context_handle.GSS_CTX_ID_T_len = 0;
			res->delegated_cred_handle.GSS_CRED_ID_T_len = 0;
			res->output_token.GSS_BUFFER_T_len = 0;
			res->mech_type.GSS_OID_len = 0;
			res->status = (OM_uint32)GSS_S_DEFECTIVE_CREDENTIAL;
			res->minor_status = 0;
			return (TRUE);
		}

	input_token_buffer_ptr = &input_token_buffer;
	input_token_buffer.length = (size_t)argp->input_token_buffer.
		GSS_BUFFER_T_len;
	input_token_buffer.value = (void *)argp->input_token_buffer.
		GSS_BUFFER_T_val;

	if (argp->input_chan_bindings.present == YES) {
		input_chan_bindings_ptr = &input_chan_bindings;
		input_chan_bindings.initiator_addrtype =
			(OM_uint32)argp->input_chan_bindings.
					initiator_addrtype;
		input_chan_bindings.initiator_address.length =
			(uint_t)argp->input_chan_bindings.initiator_address.
					GSS_BUFFER_T_len;
		input_chan_bindings.initiator_address.value =
			(void *)argp->input_chan_bindings.initiator_address.
					GSS_BUFFER_T_val;
		input_chan_bindings.acceptor_addrtype =
			(OM_uint32)argp->input_chan_bindings.
					acceptor_addrtype;
		input_chan_bindings.acceptor_address.length =
			(uint_t)argp->input_chan_bindings.acceptor_address.
					GSS_BUFFER_T_len;
		input_chan_bindings.acceptor_address.value =
			(void *)argp->input_chan_bindings.acceptor_address.
					GSS_BUFFER_T_val;
		input_chan_bindings.application_data.length =
			(uint_t)argp->input_chan_bindings.application_data.
					GSS_BUFFER_T_len;
		input_chan_bindings.application_data.value =
			(void *)argp->input_chan_bindings.application_data.
					GSS_BUFFER_T_val;
	} else {
		input_chan_bindings_ptr = GSS_C_NO_CHANNEL_BINDINGS;
		input_chan_bindings.initiator_addrtype = 0;
		input_chan_bindings.initiator_address.length = 0;
		input_chan_bindings.initiator_address.value = 0;
		input_chan_bindings.acceptor_addrtype = 0;
		input_chan_bindings.acceptor_address.length = 0;
		input_chan_bindings.acceptor_address.value = 0;
		input_chan_bindings.application_data.length = 0;
		input_chan_bindings.application_data.value = 0;
	}


	/* call the gssapi routine */

	res->status = (OM_uint32)gss_accept_sec_context(&res->minor_status,
						&context_handle,
						verifier_cred_handle,
						input_token_buffer_ptr,
						input_chan_bindings_ptr,
						&internal_name,
						&mech_type,
						&output_token,
						&res->ret_flags,
						&res->time_rec,
						&delegated_cred_handle);

	/* convert the src name from internal to external format */

	if (res->status == (OM_uint32)GSS_S_COMPLETE ||
		res->status == (OM_uint32)GSS_S_CONTINUE_NEEDED) {

		/*
		 * upon GSS_S_CONTINUE_NEEDED only the following
		 * parameters are ready: minor, ctxt, and output token
		 */
		res->context_handle.GSS_CTX_ID_T_len = sizeof (gss_ctx_id_t);
		res->context_handle.GSS_CTX_ID_T_val =
			(void *)malloc(sizeof (gss_ctx_id_t));
		if (!res->context_handle.GSS_CTX_ID_T_val) {
			res->status = (OM_uint32)GSS_S_FAILURE;
			res->minor_status = 0;
			return (TRUE);
		}

		if (slot == NULL || slot->ctx != context_handle) {
			/*
			 * Note that gssd_alloc_slot() will delete ctx's as long
			 * as we don't call gssd_rel_slot().
			 */
			slot = gssd_alloc_slot(context_handle);
		}

		memcpy(res->context_handle.GSS_CTX_ID_T_val, &slot->rpcctx,
			sizeof (gss_ctx_id_t));
		res->gssd_context_verifier = slot->verf;

		res->output_token.GSS_BUFFER_T_len =
				(uint_t)output_token.length;
		res->output_token.GSS_BUFFER_T_val =
				(char *)output_token.value;

		if (res->status == GSS_S_COMPLETE) {
			if (gss_export_name(&minor_status, internal_name,
					&external_name)
				!= GSS_S_COMPLETE) {

				res->status = (OM_uint32)GSS_S_FAILURE;
				res->minor_status = minor_status;
				gss_release_name(&minor_status, &internal_name);
				gss_delete_sec_context(&minor_status,
						&context_handle, NULL);
				free(res->context_handle.GSS_CTX_ID_T_val);
				res->context_handle.GSS_CTX_ID_T_val = NULL;
				res->context_handle.GSS_CTX_ID_T_len = 0;
				gss_release_buffer(&minor_status,
						&output_token);
				res->output_token.GSS_BUFFER_T_len = 0;
				res->output_token.GSS_BUFFER_T_val = NULL;
				return (TRUE);
			}
			res->src_name.GSS_BUFFER_T_len =
				(uint_t)external_name.length;
			res->src_name.GSS_BUFFER_T_val =
				(void *)external_name.value;

			res->delegated_cred_handle.GSS_CRED_ID_T_len =
				sizeof (gss_cred_id_t);
			res->delegated_cred_handle.GSS_CRED_ID_T_val =
				(void *)malloc(sizeof (gss_cred_id_t));
			if (!res->delegated_cred_handle.GSS_CRED_ID_T_val) {
				free(res->context_handle.GSS_CTX_ID_T_val);
				gss_release_name(&minor_status, &internal_name);
				gss_delete_sec_context(&minor_status,
						&context_handle, NULL);
				gss_release_buffer(&minor_status,
						&external_name);
				res->status = (OM_uint32)GSS_S_FAILURE;
				res->minor_status = 0;
				return (TRUE);
			}
			memcpy(res->delegated_cred_handle.GSS_CRED_ID_T_val,
				&delegated_cred_handle,
				sizeof (gss_cred_id_t));

			res->mech_type.GSS_OID_len = (uint_t)mech_type->length;
			res->mech_type.GSS_OID_val =
				(void *)malloc(mech_type->length);
			if (!res->mech_type.GSS_OID_val) {
			    free(res->context_handle.GSS_CTX_ID_T_val);
			    free(res->delegated_cred_handle.GSS_CRED_ID_T_val);
			    gss_release_name(&minor_status, &internal_name);
			    gss_delete_sec_context(&minor_status,
						&context_handle, NULL);
			    gss_release_buffer(&minor_status, &external_name);
			    res->status = (OM_uint32)GSS_S_FAILURE;
			    res->minor_status = 0;
			    return (TRUE);
			}
			memcpy(res->mech_type.GSS_OID_val, mech_type->elements,
				mech_type->length);

			/* release the space allocated for internal_name */
			gss_release_name(&minor_status, &internal_name);

		} else {    /* GSS_S_CONTINUE_NEEDED */
			res->src_name.GSS_BUFFER_T_len = 0;
			res->delegated_cred_handle.GSS_CRED_ID_T_len = 0;
			res->mech_type.GSS_OID_len = 0;
		}
	} else {
		syslog_gss_error(res->status, res->minor_status,
			    "accept_sec_context");

		if (context_handle != GSS_C_NO_CONTEXT) {
			(void) gss_delete_sec_context(&minor_status,
				&context_handle, NULL);
		}
		res->src_name.GSS_BUFFER_T_len = 0;
		res->context_handle.GSS_CTX_ID_T_len = 0;
                res->delegated_cred_handle.GSS_CRED_ID_T_len = 0;
                res->output_token.GSS_BUFFER_T_len =
			(uint_t)output_token.length;
                res->output_token.GSS_BUFFER_T_val =
			(char *)output_token.value;

                res->mech_type.GSS_OID_len = 0;
	}

/* return to caller */

	return (TRUE);
}

bool_t
gss_process_context_token_1_svc(argp, res, rqstp)
gss_process_context_token_arg *argp;
gss_process_context_token_res *res;
struct svc_req *rqstp;
{

	uid_t uid;
	gss_buffer_desc token_buffer;
	gss_ctx_id_t context_handle;
	bool_t context_verf_ok;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_process_context_token\n"));

	if (checkfrom(rqstp, &uid) == 0)
		return (FALSE);

	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, NULL);

	/* verify the context_handle */

	if (!context_verf_ok) {
		res->status = (OM_uint32) GSS_S_NO_CONTEXT;
		res->minor_status = 0;
		return (TRUE);
	}

	/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

	/*
	 * copy the XDR structured arguments into their corresponding local
	 * GSSAPI variable equivalents.
	 */

	token_buffer.length = (size_t)argp->token_buffer.GSS_BUFFER_T_len;
	token_buffer.value = (void *)argp->token_buffer.GSS_BUFFER_T_val;


	/* call the gssapi routine */

	res->status = (OM_uint32)gss_process_context_token(&res->minor_status,
				context_handle,
				&token_buffer);

	if (GSS_ERROR(res->status))
		syslog_gss_error(res->status, res->minor_status,
			    "process_context_token");

	/* return to caller */

	return (TRUE);
}

bool_t
gss_delete_sec_context_1_svc(argp, res, rqstp)
gss_delete_sec_context_arg *argp;
gss_delete_sec_context_res *res;
struct svc_req *rqstp;
{
	uid_t uid;
	gss_ctx_id_t  context_handle;
	gss_buffer_desc output_token;
	bool_t context_verf_ok;
	struct gssd_ctx_slot *slot = NULL;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_delete_sec_context\n"));


	/*
	 * copy the supplied context handle into the local context handle, so it
	 * can be supplied to the gss_delete_sec_context call
	 */
	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, &slot);

	/* verify the context_handle */
	if (!context_verf_ok) {
		res->context_handle.GSS_CTX_ID_T_val = NULL;
		res->context_handle.GSS_CTX_ID_T_len = 0;
		res->output_token.GSS_BUFFER_T_val = NULL;
		res->output_token.GSS_BUFFER_T_len = 0;
		res->status = (OM_uint32)GSS_S_NO_CONTEXT;
		res->minor_status = 0;
		return (TRUE);
	}

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->context_handle.GSS_CTX_ID_T_val = NULL;
		res->output_token.GSS_BUFFER_T_val = NULL;
		return (FALSE);
	}

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_delete_sec_context(&res->minor_status,
						&context_handle,
						&output_token);

	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result. If the delete succeeded, return a zero
	 * context handle.
	 */

	if (res->status == GSS_S_COMPLETE) {
		if (context_handle != GSS_C_NO_CONTEXT)
			return (GSS_S_FAILURE);
		res->context_handle.GSS_CTX_ID_T_len = 0;
		res->context_handle.GSS_CTX_ID_T_val = NULL;
		res->output_token.GSS_BUFFER_T_len =
			(uint_t)output_token.length;
		res->output_token.GSS_BUFFER_T_val =
			(char *)output_token.value;

		if (slot != NULL) {
			/*
			 * gss_delete_sec_context deletes the context if it
			 * succeeds so clear slot->ctx to avoid a dangling
			 * reference.
			 */
			slot->ctx = GSS_C_NO_CONTEXT;
			gssd_rel_slot(slot);
		}
	} else {
		res->context_handle.GSS_CTX_ID_T_len = sizeof (gss_ctx_id_t);
		res->context_handle.GSS_CTX_ID_T_val =
			(void *)malloc(sizeof (gss_ctx_id_t));
		if (!res->context_handle.GSS_CTX_ID_T_val) {
			return (GSS_S_FAILURE);
		}

		if (slot == NULL || slot->ctx != context_handle) {
			/*
			 * Note that gssd_alloc_slot() will delete ctx's as long
			 * as we don't call gssd_rel_slot().
			 */
			slot = gssd_alloc_slot(context_handle);
			/*
			 * Note that no verifier is returned in the .x
			 * protocol. So if the context changes, we won't
			 * be able to release it now. So it will have to
			 * be LRUed out.
			 */
		}

		memcpy(res->context_handle.GSS_CTX_ID_T_val, &slot->rpcctx,
			sizeof (gss_ctx_id_t));

		res->output_token.GSS_BUFFER_T_len = 0;
		res->output_token.GSS_BUFFER_T_val = NULL;
	}

	/* return to caller */


	return (TRUE);
}


bool_t
gss_export_sec_context_1_svc(argp, res, rqstp)
	gss_export_sec_context_arg *argp;
	gss_export_sec_context_res *res;
	struct svc_req *rqstp;
{

	uid_t		uid;
	gss_ctx_id_t	context_handle;
	gss_buffer_desc	output_token;
	bool_t		context_verf_ok;
	struct gssd_ctx_slot *slot = NULL;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, "gss_export_sec_context\n");

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->context_handle.GSS_CTX_ID_T_val = NULL;
		res->output_token.GSS_BUFFER_T_val = NULL;
		return (FALSE);
	}

/*
 * copy the supplied context handle into the local context handle, so it
 * can be supplied to the gss_export_sec_context call
 */

	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, &slot);

	/* verify the context_handle */

	if (!context_verf_ok) {
		res->status = (OM_uint32)GSS_S_NO_CONTEXT;
		/* the rest of "res" was cleared by a previous memset() */
		return (TRUE);
	}

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_export_sec_context(&res->minor_status,
					&context_handle,
					&output_token);

/*
 * convert the output args from the parameter given in the call to the
 * variable in the XDR result. If the delete succeeded, return a zero context
 * handle.
 */
	if (res->status == GSS_S_COMPLETE) {
		if (context_handle != GSS_C_NO_CONTEXT)
			return (GSS_S_FAILURE);
		res->context_handle.GSS_CTX_ID_T_len = 0;
		res->context_handle.GSS_CTX_ID_T_val = NULL;
		res->output_token.GSS_BUFFER_T_len =
						(uint_t)output_token.length;
		res->output_token.GSS_BUFFER_T_val =
						(char *)output_token.value;

		if (slot != NULL) {
			/*
			 * gss_export_sec_context deletes the context if it
			 * succeeds so set slot->ctx to avoid a dangling
			 * reference.
			 */
			slot->ctx = GSS_C_NO_CONTEXT;
			gssd_rel_slot(slot);
		}
	} else {
		res->context_handle.GSS_CTX_ID_T_len = sizeof (gss_ctx_id_t);
		res->context_handle.GSS_CTX_ID_T_val =
					(void *)malloc(sizeof (gss_ctx_id_t));

		if (slot == NULL || slot->ctx != context_handle) {
			/*
			 * Note that gssd_alloc_slot() will delete ctx's as long
			 * as we don't call gssd_rel_slot().
			 */
			slot = gssd_alloc_slot(context_handle);
			/*
			 * Note that no verifier is returned in the .x
			 * protocol. So if the context changes, we won't
			 * be able to release it now. So it will have to
			 * be LRUed out.
			 */
		}

		memcpy(res->context_handle.GSS_CTX_ID_T_val, &slot->rpcctx,
			sizeof (gss_ctx_id_t));
		res->output_token.GSS_BUFFER_T_len = 0;
		res->output_token.GSS_BUFFER_T_val = NULL;
	}


	/* return to caller */

	return (TRUE);
}

/*
 * This routine doesn't appear to ever be called.
 */
bool_t
gss_import_sec_context_1_svc(argp, res, rqstp)
	gss_import_sec_context_arg *argp;
	gss_import_sec_context_res *res;
	struct svc_req *rqstp;
{

	uid_t		uid;
	gss_ctx_id_t	context_handle;
	gss_buffer_desc	input_token;
	gss_buffer_t input_token_ptr;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, "gss_export_sec_context\n");

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->context_handle.GSS_CTX_ID_T_val = NULL;
		return (FALSE);
	}


	if (argp->input_token.GSS_BUFFER_T_len == 0) {
		input_token_ptr = GSS_C_NO_BUFFER;
	} else {
		input_token_ptr = &input_token;
		input_token.length = (size_t)
				argp->input_token.GSS_BUFFER_T_len;
		input_token.value = (void *) argp->input_token.GSS_BUFFER_T_val;
	}


/* call the gssapi routine */

	res->status = (OM_uint32) gss_import_sec_context(&res->minor_status,
					input_token_ptr,
					&context_handle);

/*
 * convert the output args from the parameter given in the call to the
 * variable in the XDR result. If the delete succeeded, return a zero context
 * handle.
 */
	if (res->status == GSS_S_COMPLETE) {
		res->context_handle.GSS_CTX_ID_T_len = sizeof (gss_ctx_id_t);
		res->context_handle.GSS_CTX_ID_T_val =
					(void *) malloc(sizeof (gss_ctx_id_t));
		memcpy(res->context_handle.GSS_CTX_ID_T_val, &context_handle,
			sizeof (gss_ctx_id_t));
	} else {
		res->context_handle.GSS_CTX_ID_T_len = 0;
		res->context_handle.GSS_CTX_ID_T_val = NULL;
	}


	/* return to caller */

	return (TRUE);
}

bool_t
gss_context_time_1_svc(argp, res, rqstp)
gss_context_time_arg *argp;
gss_context_time_res *res;
struct svc_req *rqstp;
{
	uid_t uid;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_context_time\n"));

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0)
		return (FALSE);

	/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

	/* Semantics go here */

	return (TRUE);
}

bool_t
gss_sign_1_svc(argp, res, rqstp)
gss_sign_arg *argp;
gss_sign_res *res;
struct svc_req *rqstp;
{

	uid_t uid;

	gss_buffer_desc message_buffer;
	gss_buffer_desc msg_token;
	gss_ctx_id_t	context_handle;
	bool_t context_verf_ok;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_sign\n"));

	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, NULL);

	/* verify the context_handle */
	if (!context_verf_ok) {
		res->msg_token.GSS_BUFFER_T_val = NULL;
		res->msg_token.GSS_BUFFER_T_len = 0;
		res->status = (OM_uint32) GSS_S_NO_CONTEXT;
		res->minor_status = 0;
		return (TRUE);
	}


	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->msg_token.GSS_BUFFER_T_val = NULL;
		return (FALSE);
	}

	/*
	 * copy the XDR structured arguments into their corresponding local
	 * GSSAPI variable equivalents.
	 */

	message_buffer.length = (size_t)argp->message_buffer.GSS_BUFFER_T_len;
	message_buffer.value = (void *)argp->message_buffer.GSS_BUFFER_T_val;

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_sign(&res->minor_status,
					context_handle,
					argp->qop_req,
					(gss_buffer_t)&message_buffer,
					(gss_buffer_t)&msg_token);
	/*
	 * convert the output args from the parameter given in the call to
	 * the variable in the XDR result
	 */

	if (res->status == GSS_S_COMPLETE) {
		res->msg_token.GSS_BUFFER_T_len = (uint_t)msg_token.length;
		res->msg_token.GSS_BUFFER_T_val = (char *)msg_token.value;
	} else
		syslog_gss_error(res->status, res->minor_status, "sign");

	/* return to caller */

	return (TRUE);
}

bool_t
gss_verify_1_svc(argp, res, rqstp)
gss_verify_arg *argp;
gss_verify_res *res;
struct svc_req *rqstp;
{

	uid_t uid;

	gss_buffer_desc message_buffer;
	gss_buffer_desc token_buffer;
	gss_ctx_id_t context_handle;
	bool_t context_verf_ok;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_verify\n"));

	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, NULL);

	/* verify the context_handle */
	if (!context_verf_ok) {
		res->status = (OM_uint32) GSS_S_NO_CONTEXT;
		res->minor_status = 0;
		return (TRUE);
	}

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0)
		return (FALSE);

	/*
	 * copy the XDR structured arguments into their corresponding local
	 * GSSAPI variable equivalents.
	 */

	message_buffer.length = (size_t)argp->message_buffer.GSS_BUFFER_T_len;
	message_buffer.value = (void *)argp->message_buffer.GSS_BUFFER_T_val;

	token_buffer.length = (size_t)argp->token_buffer.GSS_BUFFER_T_len;
	token_buffer.value = (void *)argp->token_buffer.GSS_BUFFER_T_val;

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_verify(&res->minor_status,
				context_handle,
				&message_buffer,
				&token_buffer,
				&res->qop_state);

	if (GSS_ERROR(res->status))
		syslog_gss_error(res->status, res->minor_status, "verify");

	/* return to caller */
	return (TRUE);
}

bool_t
gss_seal_1_svc(argp, res, rqstp)
gss_seal_arg *argp;
gss_seal_res *res;
struct svc_req *rqstp;
{
	uid_t uid;

	gss_buffer_desc input_message_buffer;
	gss_buffer_desc output_message_buffer;
	gss_ctx_id_t context_handle;
	bool_t context_verf_ok;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_seal\n"));

	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, NULL);

	/* verify the context_handle */

	if (!context_verf_ok) {
		res->output_message_buffer.GSS_BUFFER_T_val = NULL;
		res->output_message_buffer.GSS_BUFFER_T_len = 0;
		res->status = (OM_uint32) GSS_S_NO_CONTEXT;
		res->minor_status = 0;
		return (TRUE);
	}

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->output_message_buffer.GSS_BUFFER_T_val = NULL;
		return (FALSE);

	}


	/*
	 * copy the XDR structured arguments into their corresponding local
	 * GSSAPI variable equivalents.
	 */

	input_message_buffer.length = (size_t)argp->input_message_buffer.
					GSS_BUFFER_T_len;
	input_message_buffer.value = (void *)argp->input_message_buffer.
					GSS_BUFFER_T_val;


	/* call the gssapi routine */

	res->status = (OM_uint32)gss_seal(&res->minor_status,
				context_handle,
				argp->conf_req_flag,
				argp->qop_req,
				&input_message_buffer,
				&res->conf_state,
				&output_message_buffer);
	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result
	 */

	if (res->status == GSS_S_COMPLETE) {
		res->output_message_buffer.GSS_BUFFER_T_len =
				(uint_t)output_message_buffer.length;
		res->output_message_buffer.GSS_BUFFER_T_val =
				(char *)output_message_buffer.value;
	} else
		syslog_gss_error(res->status, res->minor_status, "seal");

/* return to caller */

	return (TRUE);
}

bool_t
gss_unseal_1_svc(argp, res, rqstp)
gss_unseal_arg *argp;
gss_unseal_res *res;
struct svc_req *rqstp;
{

	uid_t uid;

	gss_buffer_desc input_message_buffer;
	gss_buffer_desc output_message_buffer;
	gss_ctx_id_t context_handle;
	bool_t context_verf_ok;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_unseal\n"));

	/* verify the context_handle */
	gssd_convert_context_handle(&argp->context_handle, &context_handle,
		argp->gssd_context_verifier, &context_verf_ok, NULL);

	/* verify the context_handle */
	if (!context_verf_ok) {
		res->output_message_buffer.GSS_BUFFER_T_val = NULL;
		res->output_message_buffer.GSS_BUFFER_T_len = 0;
		res->status = (OM_uint32)GSS_S_NO_CONTEXT;
		res->minor_status = 0;
		return (TRUE);
	}

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->output_message_buffer.GSS_BUFFER_T_val = NULL;
		return (FALSE);
	}


	/*
	 * copy the XDR structured arguments into their corresponding local
	 * GSSAPI variable equivalents.
	 */

	input_message_buffer.length = (size_t)argp->input_message_buffer.
					GSS_BUFFER_T_len;
	input_message_buffer.value = (void *)argp->input_message_buffer.
					GSS_BUFFER_T_val;

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_unseal(&res->minor_status,
				context_handle,
				&input_message_buffer,
				&output_message_buffer,
				&res->conf_state,
				&res->qop_state);

	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result
	 */

	if (res->status == GSS_S_COMPLETE) {
		res->output_message_buffer.GSS_BUFFER_T_len =
				(uint_t)output_message_buffer.length;
		res->output_message_buffer.GSS_BUFFER_T_val =
				(char *)output_message_buffer.value;
	} else
		syslog_gss_error(res->status, res->minor_status, "unseal");


	/* return to caller */

	return (TRUE);
}

bool_t
gss_display_status_1_svc(argp, res, rqstp)
gss_display_status_arg *argp;
gss_display_status_res *res;
struct svc_req *rqstp;
{
	uid_t uid;
	gss_OID mech_type;
	gss_OID_desc mech_type_desc;
	gss_buffer_desc status_string;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_display_status\n"));

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->status_string.GSS_BUFFER_T_val = NULL;
		return (FALSE);
	}

	/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

	/*
	 * copy the XDR structured arguments into their corresponding local
	 * GSSAPI variables.
	 */

	if (argp->mech_type.GSS_OID_len == 0)
		mech_type = GSS_C_NULL_OID;
	else {
		mech_type = &mech_type_desc;
		mech_type_desc.length = (OM_uint32) argp->mech_type.GSS_OID_len;
		mech_type_desc.elements = (void *) argp->mech_type.GSS_OID_val;
	}


	/* call the gssapi routine */

	res->status = (OM_uint32) gss_display_status(&res->minor_status,
					argp->status_value,
					argp->status_type,
					mech_type,
					(OM_uint32 *)&res->message_context,
					&status_string);

	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result
	 */

	if (res->status == GSS_S_COMPLETE) {
		res->status_string.GSS_BUFFER_T_len =
			(uint_t)status_string.length;
		res->status_string.GSS_BUFFER_T_val =
			(char *)status_string.value;
	}

	return (TRUE);

}

/*ARGSUSED*/
bool_t
gss_indicate_mechs_1_svc(argp, res, rqstp)
	void *argp;
	gss_indicate_mechs_res *res;
	struct svc_req *rqstp;
{
	gss_OID_set oid_set;
	uid_t uid;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_indicate_mechs\n"));

	res->mech_set.GSS_OID_SET_val = NULL;

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		return (FALSE);
	}

	res->status = gss_indicate_mechs(&res->minor_status, &oid_set);

	if (res->status == GSS_S_COMPLETE) {
		int i, j;

		res->mech_set.GSS_OID_SET_len = oid_set->count;
		res->mech_set.GSS_OID_SET_val = (void *)
				malloc(oid_set->count * sizeof (GSS_OID));
		if (!res->mech_set.GSS_OID_SET_val) {
			return (GSS_S_FAILURE);
		}
		for (i = 0; i < oid_set->count; i++) {
			res->mech_set.GSS_OID_SET_val[i].GSS_OID_len =
				oid_set->elements[i].length;
			res->mech_set.GSS_OID_SET_val[i].GSS_OID_val =
				(char *)malloc(oid_set->elements[i].length);
			if (!res->mech_set.GSS_OID_SET_val[i].GSS_OID_val) {
				for (j = 0; j < (i -1); j++) {
				free
				(res->mech_set.GSS_OID_SET_val[i].GSS_OID_val);
				}
				free(res->mech_set.GSS_OID_SET_val);
				return (GSS_S_FAILURE);
			}
			memcpy(res->mech_set.GSS_OID_SET_val[i].GSS_OID_val,
				oid_set->elements[i].elements,
				oid_set->elements[i].length);
		}
	}

	return (TRUE);
}

bool_t
gss_inquire_cred_1_svc(argp, res, rqstp)
gss_inquire_cred_arg *argp;
gss_inquire_cred_res *res;
struct svc_req *rqstp;
{

	uid_t uid;

	OM_uint32 minor_status;
	gss_cred_id_t cred_handle;
	gss_buffer_desc external_name;
	gss_OID name_type;
	gss_name_t internal_name;
	gss_OID_set mechanisms;
	int i, j;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_inquire_cred\n"));

	/* verify the verifier_cred_handle */

	if (argp->gssd_cred_verifier != gssd_time_verf) {
		res->name.GSS_BUFFER_T_val = NULL;
		res->name_type.GSS_OID_val = NULL;
		res->mechanisms.GSS_OID_SET_val = NULL;
		res->status = (OM_uint32) GSS_S_DEFECTIVE_CREDENTIAL;
		res->minor_status = 0;
		return (TRUE);
	}

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		res->name.GSS_BUFFER_T_val = NULL;
		res->name_type.GSS_OID_val = NULL;
		res->mechanisms.GSS_OID_SET_val = NULL;
		return (FALSE);
	}

	/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

	cred_handle = (argp->cred_handle.GSS_CRED_ID_T_len == 0 ?
			GSS_C_NO_CREDENTIAL :
			/*LINTED*/
			*((gss_cred_id_t *)argp->cred_handle.
				GSS_CRED_ID_T_val));

	/* call the gssapi routine */

	res->status = (OM_uint32)gss_inquire_cred(&res->minor_status,
					cred_handle,
					&internal_name,
					&res->lifetime,
					&res->cred_usage,
					&mechanisms);

	if (res->status != GSS_S_COMPLETE) {
		syslog_gss_error(res->status, res->minor_status,
				"inquire_cred");
		return (TRUE);
	}

	/* convert the returned name from internal to external format */

	if (gss_display_name(&minor_status, internal_name,
				&external_name, &name_type)
			!= GSS_S_COMPLETE) {

		res->status = (OM_uint32)GSS_S_FAILURE;
		res->minor_status = minor_status;

		gss_release_name(&minor_status, &internal_name);

		if (mechanisms != GSS_C_NULL_OID_SET) {
			for (i = 0; i < mechanisms->count; i++)
				free(mechanisms->elements[i].elements);
			free(mechanisms->elements);
			free(mechanisms);
		}

		return (TRUE);
	}

	/*
	 * convert the output args from the parameter given in the call to the
	 * variable in the XDR result
	 */


	res->name.GSS_BUFFER_T_len = (uint_t)external_name.length;
	res->name.GSS_BUFFER_T_val = (void *)external_name.value;

	/*
	 * we have to allocate storage for name_type here, since the value
	 * returned from gss_display_name points to the underlying mechanism
	 * static storage. If we didn't allocate storage, the next time
	 * through this routine, the xdr_free() call at the beginning would
	 * try to free up that static storage.
	 */

	res->name_type.GSS_OID_len = (uint_t)name_type->length;
	res->name_type.GSS_OID_val = (void *)malloc(name_type->length);
	if (!res->name_type.GSS_OID_val) {
		return (GSS_S_FAILURE);
	}
	memcpy(res->name_type.GSS_OID_val, name_type->elements,
		name_type->length);

	if (mechanisms != GSS_C_NULL_OID_SET) {
		res->mechanisms.GSS_OID_SET_len =
			(uint_t)mechanisms->count;
		res->mechanisms.GSS_OID_SET_val = (GSS_OID *)
				malloc(sizeof (GSS_OID) * mechanisms->count);
		if (!res->mechanisms.GSS_OID_SET_val) {
			free(res->name_type.GSS_OID_val);
			return (GSS_S_FAILURE);
		}
		for (i = 0; i < mechanisms->count; i++) {
			res->mechanisms.GSS_OID_SET_val[i].GSS_OID_len =
				(uint_t)mechanisms->elements[i].length;
			res->mechanisms.GSS_OID_SET_val[i].GSS_OID_val =
				(char *)malloc(mechanisms->elements[i].
						length);
			if (!res->mechanisms.GSS_OID_SET_val[i].GSS_OID_val) {
				free(res->name_type.GSS_OID_val);
				for (j = 0; j < i; j++) {
				free(res->mechanisms.
					GSS_OID_SET_val[i].GSS_OID_val);
				}
				free(res->mechanisms.GSS_OID_SET_val);
				return (GSS_S_FAILURE);
			}
			memcpy(res->mechanisms.GSS_OID_SET_val[i].GSS_OID_val,
				mechanisms->elements[i].elements,
				mechanisms->elements[i].length);
		}
	} else
		res->mechanisms.GSS_OID_SET_len = 0;

	/* release the space allocated for internal_name and mechanisms */
	gss_release_name(&minor_status, &internal_name);

	if (mechanisms != GSS_C_NULL_OID_SET) {
		for (i = 0; i < mechanisms->count; i++)
			free(mechanisms->elements[i].elements);
		free(mechanisms->elements);
		free(mechanisms);
	}

	/* return to caller */
	return (TRUE);
}


bool_t
gss_inquire_cred_by_mech_1_svc(argp, res, rqstp)
gss_inquire_cred_by_mech_arg *argp;
gss_inquire_cred_by_mech_res *res;
struct svc_req *rqstp;
{

	uid_t uid;

	gss_cred_id_t cred_handle;
	gss_OID_desc		mech_type_desc;
	gss_OID 		mech_type = &mech_type_desc;

	memset(res, 0, sizeof (*res));

	if (gssd_debug)
		fprintf(stderr, gettext("gss_inquire_cred\n"));

	/* verify the verifier_cred_handle */

	if (argp->gssd_cred_verifier != gssd_time_verf) {
		res->status = (OM_uint32) GSS_S_DEFECTIVE_CREDENTIAL;
		res->minor_status = 0;
		return (TRUE);
	}

	/*
	 * if the request isn't from root, null out the result pointer
	 * entries, so the next time through xdr_free won't try to
	 * free unmalloc'd memory and then return NULL
	 */

	if (checkfrom(rqstp, &uid) == 0) {
		return (FALSE);
	}

	/* set the uid sent as the RPC argument */

	uid = argp->uid;
	set_gssd_uid(uid);

	cred_handle = (argp->cred_handle.GSS_CRED_ID_T_len == 0 ?
			GSS_C_NO_CREDENTIAL :
			/*LINTED*/
			*((gss_cred_id_t *)argp->cred_handle.
				GSS_CRED_ID_T_val));

	/* call the gssapi routine */

	if (argp->mech_type.GSS_OID_len == 0)
		mech_type = GSS_C_NULL_OID;
	else {
		mech_type->length =
			(OM_uint32)argp->mech_type.GSS_OID_len;
		mech_type->elements =
			(void *)malloc(mech_type->length);
		if (!mech_type->elements) {
			return (GSS_S_FAILURE);
		}
		memcpy(mech_type->elements,
			argp->mech_type.GSS_OID_val,
			mech_type->length);
	}
	res->status = (OM_uint32)gss_inquire_cred_by_mech(
					&res->minor_status, cred_handle,
					mech_type, NULL, NULL,
					NULL, NULL);

	/* return to caller */
	return (TRUE);
}


bool_t
gsscred_name_to_unix_cred_1_svc(argsp, res, rqstp)
gsscred_name_to_unix_cred_arg *argsp;
gsscred_name_to_unix_cred_res *res;
struct svc_req *rqstp;
{
	uid_t uid;
	gss_OID_desc oid;
	gss_name_t gssName;
	gss_buffer_desc gssBuf = GSS_C_EMPTY_BUFFER;
	OM_uint32 minor;
	int gidsLen;
	gid_t *gids, gidOut;

	if (gssd_debug)
		fprintf(stderr, gettext("gsscred_name_to_unix_cred\n"));

	memset(res, 0, sizeof (*res));

	/*
	 * check the request originator
	 */
	if (checkfrom(rqstp, &uid) == 0)
		return (FALSE);

	/* set the uid from the rpc request */
	uid = argsp->uid;
	set_gssd_uid(uid);

	/*
	 * convert the principal name to gss internal format
	 * need not malloc the input parameters
	 */
	gssBuf.length = argsp->pname.GSS_BUFFER_T_len;
	gssBuf.value = (void*)argsp->pname.GSS_BUFFER_T_val;
	oid.length = argsp->name_type.GSS_OID_len;
	oid.elements = (void*)argsp->name_type.GSS_OID_val;

	res->major = gss_import_name(&minor, &gssBuf, &oid, &gssName);
	if (res->major != GSS_S_COMPLETE)
		return (TRUE);

	/* retrieve the mechanism type from the arguments */
	oid.length = argsp->mech_type.GSS_OID_len;
	oid.elements = (void*)argsp->mech_type.GSS_OID_val;

	/* call the gss extensions to map the principal name to unix creds */
	res->major = gsscred_name_to_unix_cred(gssName, &oid, &uid, &gidOut,
					&gids, &gidsLen);
	gss_release_name(&minor, &gssName);

	if (res->major == GSS_S_COMPLETE) {
		res->uid = uid;
		res->gid = gidOut;
		res->gids.GSSCRED_GIDS_val = gids;
		res->gids.GSSCRED_GIDS_len = gidsLen;
	}

	return (TRUE);
} /* gsscred_name_to_unix_cred_svc_1 */

bool_t
gsscred_expname_to_unix_cred_1_svc(argsp, res, rqstp)
gsscred_expname_to_unix_cred_arg *argsp;
gsscred_expname_to_unix_cred_res *res;
struct svc_req *rqstp;
{
	uid_t uid;
	gss_buffer_desc expName = GSS_C_EMPTY_BUFFER;
	int gidsLen;
	gid_t *gids, gidOut;

	if (gssd_debug)
		fprintf(stderr, gettext("gsscred_expname_to_unix_cred\n"));

	memset(res, 0, sizeof (*res));

	/*
	 * check the request originator
	 */
	if (checkfrom(rqstp, &uid) == 0)
		return (FALSE);

	/* set the uid from the rpc request */
	uid = argsp->uid;
	set_gssd_uid(uid);

	/*
	 * extract the export name from arguments
	 * need not malloc the input parameters
	 */
	expName.length = argsp->expname.GSS_BUFFER_T_len;
	expName.value = (void*)argsp->expname.GSS_BUFFER_T_val;

	res->major = gsscred_expname_to_unix_cred(&expName, &uid,
					&gidOut, &gids, &gidsLen);

	if (res->major == GSS_S_COMPLETE) {
		res->uid = uid;
		res->gid = gidOut;
		res->gids.GSSCRED_GIDS_val = gids;
		res->gids.GSSCRED_GIDS_len = gidsLen;
	}

	return (TRUE);
} /* gsscred_expname_to_unix_cred_1_svc */

bool_t
gss_get_group_info_1_svc(argsp, res, rqstp)
gss_get_group_info_arg *argsp;
gss_get_group_info_res *res;
struct svc_req *rqstp;
{
	uid_t uid;
	int gidsLen;
	gid_t *gids, gidOut;

	if (gssd_debug)
		fprintf(stderr, gettext("gss_get_group_info\n"));

	memset(res, 0, sizeof (*res));

	/*
	 * check the request originator
	 */
	if (checkfrom(rqstp, &uid) == 0)
		return (FALSE);

	/* set the uid from the rpc request */
	uid = argsp->uid;
	set_gssd_uid(uid);

	/*
	 * extract the uid from the arguments
	 */
	uid = argsp->puid;
	res->major = gss_get_group_info(uid, &gidOut, &gids, &gidsLen);
	if (res->major == GSS_S_COMPLETE) {
		res->gid = gidOut;
		res->gids.GSSCRED_GIDS_val = gids;
		res->gids.GSSCRED_GIDS_len = gidsLen;
	}

	return (TRUE);
} /* gss_get_group_info_1_svc */

/*ARGSUSED*/
bool_t
gss_get_kmod_1_svc(argsp, res, rqstp)
	gss_get_kmod_arg *argsp;
	gss_get_kmod_res *res;
	struct svc_req *rqstp;
{
	gss_OID_desc oid;
	char *kmodName;

	if (gssd_debug)
		fprintf(stderr, gettext("gss_get_kmod\n"));

	res->module_follow = FALSE;
	oid.length = argsp->mech_oid.GSS_OID_len;
	oid.elements = (void *)argsp->mech_oid.GSS_OID_val;
	kmodName = __gss_get_kmodName(&oid);

	if (kmodName != NULL) {
		res->module_follow = TRUE;
		res->gss_get_kmod_res_u.modname = kmodName;
	}

	return (TRUE);
}

/*
 *  Returns 1 if caller is ok, else 0.
 *  If caller ok, the uid is returned in uidp.
 */
static int
checkfrom(rqstp, uidp)
struct svc_req *rqstp;
uid_t *uidp;
{
	SVCXPRT *xprt = rqstp->rq_xprt;
	struct authunix_parms *aup;
	uid_t uid;

	/* check client agent uid to ensure it is privileged */
	if (__rpc_get_local_uid(xprt, &uid) < 0) {
		syslog(LOG_ERR, gettext("__rpc_get_local_uid failed %s %s"),
			xprt->xp_netid, xprt->xp_tp);
		goto weakauth;
	}
	if (gssd_debug)
		fprintf(stderr, gettext("checkfrom: local_uid  %d\n"), uid);
	if (uid != 0) {
		syslog(LOG_ERR,
			gettext("checkfrom: caller (uid %d) not privileged"),
			uid);
		goto weakauth;
	}

	/*
	 *  Request came from local privileged process.
	 *  Proceed to get uid of client if needed by caller.
	 */
	if (uidp) {
		if (rqstp->rq_cred.oa_flavor != AUTH_SYS) {
		syslog(LOG_ERR, gettext("checkfrom: not UNIX credentials"));
			goto weakauth;
		}
		CTASSERT(sizeof (struct authunix_parms) <= RQCRED_SIZE);
		/*LINTED*/
		aup = (struct authunix_parms *)rqstp->rq_clntcred;
		*uidp = aup->aup_uid;
		if (gssd_debug) {
			fprintf(stderr,
				gettext("checkfrom: caller's uid %d\n"), *uidp);
		}
	}
	return (1);

	weakauth:
	svcerr_weakauth(xprt);
	return (0);
}
