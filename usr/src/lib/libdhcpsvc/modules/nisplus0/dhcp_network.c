/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains public API functions for managing historical dhcp
 * network containers (pre-enterprise).
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <regexpr.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dhcp_svc_public.h>
#include "nisplus_impl.h"
#include <libinetutil.h>

/*
 * Historical DHCP network table column description
 */
static table_col	dn_desc[COLS_DN] = {
	{ "client_id",	TA_SEARCHABLE,	0	},
	{ "flags",	0,		0	},
	{ "client_ip",	TA_SEARCHABLE,	0	},
	{ "server_ip",	TA_SEARCHABLE,	0	},
	{ "expire",	TA_SEARCHABLE,	0	},
	{ "macro",	TA_SEARCHABLE,	0	},
	{ "comment",	0,		0	}
};

/*
 * Convert a dn_rec_t to a nis_object ENTRY_OBJ. Table related fields
 * will be filled in by the functions with the appropriate context.
 * Caller is responsible for freeing result.
 */
static int
dsvcnis_dnrec_to_entryobj(const dn_rec_t *dnp, nis_object **eop)
{
	unsigned int	cid_buf_len;
	struct in_addr	hip;
	nis_object	*nop;

	if ((nop = calloc(1, sizeof (nis_object))) == NULL)
		return (DSVC_NO_MEMORY);

	__type_of(nop) = ENTRY_OBJ;
	nop->zo_access = DEFAULT_RIGHTS;
	if ((nop->EN_data.en_type = strdup(TYPE_DN)) == NULL) {
		free(nop);
		return (DSVC_NO_MEMORY);
	}
	nop->EN_data.en_cols.en_cols_val = calloc(COLS_DN, sizeof (entry_col));
	if (nop->EN_data.en_cols.en_cols_val == NULL) {
		free(nop->EN_data.en_type);
		free(nop);
		return (DSVC_NO_MEMORY);
	}
	nop->EN_data.en_cols.en_cols_len = COLS_DN;

	/* cid */
	cid_buf_len = (dnp->dn_cid_len * 2) + 1;
	ENTRY_LEN(nop, CID_DN) = sizeof (char) * cid_buf_len;
	ENTRY_VAL(nop, CID_DN) = calloc(1, ENTRY_LEN(nop, CID_DN));
	if (ENTRY_VAL(nop, CID_DN) == NULL) {
		ENTRY_LEN(nop, CID_DN) = 0;
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	if (octet_to_hexascii(dnp->dn_cid, dnp->dn_cid_len,
	    ENTRY_VAL(nop, CID_DN), &cid_buf_len) != 0) {
		nis_destroy_object(nop);
		return (DSVC_INTERNAL);
	}

	/* flags */
	if ((ENTRY_VAL(nop, FLAGS_DN) = calloc(1, sizeof (char) * 3)) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	(void) sprintf(ENTRY_VAL(nop, FLAGS_DN), "%02u", dnp->dn_flags);
	ENTRY_LEN(nop, FLAGS_DN) = strlen(ENTRY_VAL(nop, FLAGS_DN)) + 1;

	/* cip */
	ENTRY_VAL(nop, CIP_DN) = calloc(1, INET_ADDRSTRLEN);
	if (ENTRY_VAL(nop, CIP_DN) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	hip.s_addr = htonl(dnp->dn_cip.s_addr);
	(void) inet_ntop(AF_INET, &hip, ENTRY_VAL(nop, CIP_DN),
	    INET_ADDRSTRLEN);
	ENTRY_LEN(nop, CIP_DN) = strlen(ENTRY_VAL(nop, CIP_DN)) + 1;

	/* sip */
	ENTRY_VAL(nop, SIP_DN) = calloc(1, INET_ADDRSTRLEN);
	if (ENTRY_VAL(nop, SIP_DN) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	hip.s_addr = htonl(dnp->dn_sip.s_addr);
	(void) inet_ntop(AF_INET, &hip, ENTRY_VAL(nop, SIP_DN),
	    INET_ADDRSTRLEN);
	ENTRY_LEN(nop, SIP_DN) = strlen(ENTRY_VAL(nop, SIP_DN)) + 1;

	/* lease */
	ENTRY_VAL(nop, LEASE_DN) = calloc(1, LEASE_BUF_DN);
	if (ENTRY_VAL(nop, LEASE_DN) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	(void) sprintf(ENTRY_VAL(nop, LEASE_DN), "%d", dnp->dn_lease);
	ENTRY_LEN(nop, LEASE_DN) = strlen(ENTRY_VAL(nop, LEASE_DN)) + 1;

	/* macro */
	if ((ENTRY_VAL(nop, MACRO_DN) = strdup(dnp->dn_macro)) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	ENTRY_LEN(nop, MACRO_DN) = strlen(ENTRY_VAL(nop, MACRO_DN)) + 1;

	/* comment */
	if ((ENTRY_VAL(nop, COMMENT_DN) = strdup(dnp->dn_comment)) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	ENTRY_LEN(nop, COMMENT_DN) = strlen(ENTRY_VAL(nop, COMMENT_DN)) + 1;

	/* signature -> oid */
	dsvcnis_sig_to_obj(dnp->dn_sig, nop);

	*eop = nop;

	return (DSVC_SUCCESS);
}

/*
 * Convert a nis_object ENTRY_OBJ to a dn_rec_t. Caller is responsible for
 * freeing result.
 */
static int
dsvcnis_entryobj_to_dnrec(const nis_object *op, dn_rec_t **dnpp)
{
	uint_t		t_cid_len;
	dn_rec_t	*dnp;

	if ((dnp = calloc(1, sizeof (dn_rec_t))) == NULL)
		return (DSVC_NO_MEMORY);

	/* cid */
	t_cid_len = sizeof (dnp->dn_cid);
	if (hexascii_to_octet(ENTRY_VAL(op, CID_DN),
	    strlen(ENTRY_VAL(op, CID_DN)), dnp->dn_cid, &t_cid_len) != 0) {
		free(dnp);
		return (DSVC_INTERNAL);
	}
	dnp->dn_cid_len = t_cid_len - 1; /* less the null */

	/* flags */
	dnp->dn_flags = atoi(ENTRY_VAL(op, FLAGS_DN));

	/* cip */
	dnp->dn_cip.s_addr = ntohl(inet_addr(ENTRY_VAL(op, CIP_DN)));
	if (dnp->dn_cip.s_addr == (ipaddr_t)-1) {
		free(dnp);
		return (DSVC_INTERNAL);
	}

	/* sip */
	dnp->dn_sip.s_addr = ntohl(inet_addr(ENTRY_VAL(op, SIP_DN)));
	if (dnp->dn_sip.s_addr == (ipaddr_t)-1) {
		free(dnp);
		return (DSVC_INTERNAL);
	}

	/* lease */
	dnp->dn_lease = atoi(ENTRY_VAL(op, LEASE_DN));

	/* macro */
	(void) strlcpy(dnp->dn_macro, ENTRY_VAL(op, MACRO_DN),
	    sizeof (dnp->dn_macro));

	/* comment */
	(void) strlcpy(dnp->dn_comment, ENTRY_VAL(op, COMMENT_DN),
	    sizeof (dnp->dn_comment));

	/* oid -> signature */
	dnp->dn_sig = dsvcnis_obj_to_sig(op);

	*dnpp = dnp;
	return (DSVC_SUCCESS);
}

/*
 * Given a dn_rec_t and a query, generate a nisplus search criteria string.
 *
 * cid, cip, sip, lease, and macro are searchable.
 *
 * Returns dynamically allocated search criteria if successful, NULL otherwise
 */
static char *
query_to_searchcriteria(const dn_rec_t *dnp, uint_t query, nis_name tablep)
{
	nis_object	*op;
	char		*scp = NULL, *tp;
	int		err = DSVC_SUCCESS, len;

	if ((err = dsvcnis_dnrec_to_entryobj(dnp, &op)) != DSVC_SUCCESS)
		return (NULL);

	/* cid */
	if (DSVC_QISEQ(query, DN_QCID) && dnp->dn_cid_len != 0) {
		err = dsvcnis_add_to_qspec(&scp, dn_desc[CID_DN].tc_name,
		    DSVCNIS_STR, ENTRY_VAL(op, CID_DN));
	}

	/* cip */
	if (err == DSVC_SUCCESS && DSVC_QISEQ(query, DN_QCIP)) {
		err = dsvcnis_add_to_qspec(&scp, dn_desc[CIP_DN].tc_name,
		    DSVCNIS_STR, ENTRY_VAL(op, CIP_DN));
	}

	/* sip */
	if (err == DSVC_SUCCESS && DSVC_QISEQ(query, DN_QSIP)) {
		err = dsvcnis_add_to_qspec(&scp, dn_desc[SIP_DN].tc_name,
		    DSVCNIS_STR, ENTRY_VAL(op, SIP_DN));
	}

	/* lease */
	if (err == DSVC_SUCCESS && DSVC_QISEQ(query, DN_QLEASE)) {
		err = dsvcnis_add_to_qspec(&scp, dn_desc[LEASE_DN].tc_name,
		    DSVCNIS_STR, ENTRY_VAL(op, LEASE_DN));
	}

	/* macro */
	if (err == DSVC_SUCCESS && DSVC_QISEQ(query, DN_QMACRO)) {
		err = dsvcnis_add_to_qspec(&scp, dn_desc[MACRO_DN].tc_name,
		    DSVCNIS_STR, ENTRY_VAL(op, MACRO_DN));
	}

	nis_destroy_object(op);

	if (err != DSVC_SUCCESS) {
		free(scp);
		return (NULL);
	}

	/* if this is a NULL query, allocate just enough for start spec */
	if (scp == NULL) {
		if ((scp = calloc(1, 2)) == NULL) /* [ + \0 */
			return (NULL);
	}

	scp[0] = '[';	/* Start of spec */
	len = strlen(tablep) + 3; /* room for ']' + ',' + \0 */
	if ((tp = realloc(scp, strlen(scp) + len)) == NULL) {
		free(scp);
		return (NULL);
	}
	scp = tp;
	(void) snprintf(&scp[strlen(scp)], len, "],%s", tablep); /* end spec */

	return (scp);
}

/*
 * List the current number of dhcp network container objects located at the
 * NIS_DIRECTORY 'location' in listppp. Return number of list elements in
 * 'count'.   If no objects exist, then 'count' is set to 0 and DSVC_SUCCESS
 * is returned.
 *
 * Note - all objects of TYPE_DN and with valid names are returned.
 *
 * This function blocks if NIS+ is unavailable.
 */
int
list_dn(const char *location, char ***listppp, uint_t *count)
{
	int		i, error, terr;
	nis_result	*resp;
	char		*regp, **tlistpp = NULL;

	*count = 0;
	*listppp = NULL;

	error = dsvcnis_validate_object(NIS_DIRECTORY_OBJ, (nis_name)location,
	    &resp, HARD_LOOKUP);
	if (error != DSVC_SUCCESS)
		return (error);
	nis_freeresult(resp);

	for (;;) {
		resp = nis_list((nis_name)location, FOLLOW_LINKS, NULL, NULL);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_TABLE_OBJ);
		if (error == DSVC_SUCCESS)
			break;

		nis_freeresult(resp);

		if (error == DSVC_NO_TABLE) {
			/* Not having any containers is a fine result */
			return (DSVC_SUCCESS);
		}

		if (error != DSVC_BUSY)
			return (error);

		(void) sleep(NIS_BUSY_PAUSE);
	}

	if ((regp = compile(PATTERN_DN, NULL, NULL)) == NULL) {
		nis_freeresult(resp);
		return (DSVC_NO_MEMORY);
	}

	for (i = 0; i < NIS_RES_NUMOBJ(resp); i++) {
		nis_object	*nop, *op = &NIS_RES_OBJECT(resp)[i];

		for (;;) {
			terr = dsvcnis_get_tobject(TYPE_DN, op->zo_name,
			    (nis_name)location, &nop);
			if (terr == DSVC_BUSY)
				(void) sleep(NIS_BUSY_PAUSE);
			else
				break;
		}
		if (terr != DSVC_SUCCESS)
			continue;

		if (__type_of(nop) == TABLE_OBJ && step(op->zo_name, regp) &&
		    dsvcnis_valid_ip(op->zo_name) &&
		    strcmp(nop->TA_data.ta_type, TYPE_DN) == 0) {
			nis_destroy_object(nop);
			tlistpp = realloc(tlistpp, (++*count) *
			    sizeof (char **));
			if (tlistpp == NULL || (tlistpp[*count - 1] =
			    strdup(DN_TO_IP(op->zo_name))) == NULL) {
				error = DSVC_NO_MEMORY;
				if (tlistpp != NULL)
					*listppp = tlistpp;
				break;
			}
			*listppp = tlistpp;
		} else
			nis_destroy_object(nop);
	}

	free(regp);
	nis_freeresult(resp);
	if (error != DSVC_SUCCESS) {
		if (*listppp != NULL) {
			for (i = *count - 1; i >= 0; i--)
				free((*listppp)[i]);
			free(*listppp);
			*listppp = NULL;
		}
		*count = 0;
	}
	return (error);
}

/*
 * opens the dhcp network container netp (host order) with mask
 * (host order) in location for reading only and initializes handlep to
 * point to the instance handle. Performs any initialization needed by
 * data store.
 */
/* ARGSUSED */
int
open_dn(void **handlepp, const char *location, uint_t flags,
    const struct in_addr *netp, const struct in_addr *maskp)
{
	nis_result		*resp;
	nis_object		*op = NULL;
	dsvcnis_handle_t	*nhp;
	struct in_addr		netnbo;
	int			error;
	uint_t			f_access = 0;
	char			network[INET_ADDRSTRLEN],
				full_name[NIS_MAXNAMELEN + 1];

	netnbo.s_addr = htonl(netp->s_addr);
	(void) inet_ntop(AF_INET, &netnbo, network, sizeof (network));
	(void) IP_TO_DN(network);
	(void) snprintf(full_name, sizeof (full_name), "%s.%s", network,
	    location);

	if (flags & DSVC_READ)
		f_access |= NIS_READ_ACC;
	if (flags & DSVC_WRITE)
		f_access |= (NIS_MODIFY_ACC | NIS_CREATE_ACC | NIS_DESTROY_ACC);

	if (flags & DSVC_CREATE) {
		uint_t		access = DEFAULT_RIGHTS;
		nis_object	dn_obj;
		table_obj	*dn_tblp;
		char		owner[NIS_MAXNAMELEN + 1],
				group[NIS_MAXNAMELEN + 1];

		(void) memset(&dn_obj, 0, sizeof (dn_obj));

		dn_obj.zo_owner = owner;
		if ((error = dsvcnis_get_username(dn_obj.zo_owner,
		    sizeof (owner))) != DSVC_SUCCESS)
			return (error);

		dn_obj.zo_group = group;
		if ((error = dsvcnis_get_groupname(dn_obj.zo_group,
		    sizeof (group))) != DSVC_SUCCESS)
			dn_obj.zo_group = "";

		dn_obj.zo_name = network;
		dn_obj.zo_domain = (nis_name)location;

		if (default_nis_access != 0)
			access = default_nis_access;

		dn_obj.zo_access = access | f_access;

		if (default_nis_ttl == 0)
			dn_obj.zo_ttl = NIS_DEF_TTL;
		else
			dn_obj.zo_ttl = default_nis_ttl;

		__type_of(&dn_obj) = TABLE_OBJ;
		dn_tblp = &dn_obj.TA_data;
		dn_tblp->ta_type = TYPE_DN;
		dn_tblp->ta_path = "";
		dn_tblp->ta_maxcol = COLS_DN;
		dn_tblp->ta_sep = DEFAULT_COL_SEP;
		dn_tblp->ta_cols.ta_cols_len = COLS_DN;
		dn_tblp->ta_cols.ta_cols_val = dn_desc;

		resp = nis_add(full_name, &dn_obj);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_TABLE_OBJ);
		nis_freeresult(resp);
		if (error != DSVC_SUCCESS)
			return (error);
	}

	error = dsvcnis_get_tobject(TYPE_DN, network, (nis_name)location, &op);

	if (error != DSVC_SUCCESS) {
		if (error == DSVC_NOENT && !(flags & DSVC_CREATE))
			error = DSVC_NO_TABLE;
		return (error);
	}

	if (!dsvcnis_ckperms(f_access, op->zo_access, op)) {
		nis_destroy_object(op);
		return (DSVC_ACCESS);
	}

	nhp = dsvcnis_init_handle(full_name, flags, op);
	nis_destroy_object(op);
	if (nhp == NULL)
		return (DSVC_NO_MEMORY);

	*handlepp = nhp;

	return (DSVC_SUCCESS);
}

/*
 * Remove DHCP network container netp (host order) in location
 *
 * This function blocks if NIS+ is unavailable.
 */
int
remove_dn(const char *location, const struct in_addr *netp)
{
	nis_result	*resp;
	nis_object	*op;
	struct in_addr	netnbo;
	int		error;
	char		network[INET_ADDRSTRLEN], full_name[NIS_MAXNAMELEN + 1],
			sc[NIS_MAXNAMELEN + 1];

	netnbo.s_addr = htonl(netp->s_addr);
	(void) inet_ntop(AF_INET, &netnbo, network, sizeof (network));
	(void) IP_TO_DN(network);
	(void) snprintf(full_name, sizeof (full_name), "%s.%s", network,
	    location);

	/* Empty the entire table */
	(void) snprintf(sc, sizeof (sc), "[],%s", full_name);

	for (;;) {
		resp = nis_remove_entry(sc, NULL, REM_MULTIPLE);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		nis_freeresult(resp);
		if (error == DSVC_SUCCESS || error == DSVC_NOENT)
			break;
		if (error != DSVC_BUSY)
			return (error);
		(void) sleep(NIS_BUSY_PAUSE);
	}

	/* now remove the table */
	for (;;) {
		error = dsvcnis_get_tobject(TYPE_DN, network,
		    (nis_name)location, &op);
		if (error == DSVC_SUCCESS)
			break;
		if (error != DSVC_BUSY)
			return (error);
		(void) sleep(NIS_BUSY_PAUSE);
	}

	for (;;) {
		resp = nis_remove((nis_name)full_name, op);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_TABLE_OBJ);
		nis_freeresult(resp);
		if (error != DSVC_BUSY)
			break;
		(void) sleep(NIS_BUSY_PAUSE);
	}

	nis_destroy_object(op);

	return (error);
}

/*
 * Searches DHCP network container for instances that match the query
 * described by the combination of query and targetp.  If the partial
 * argument is true, then lookup operations that are unable to
 * complete entirely are allowed (and considered successful).  The
 * query argument consists of 2 fields, each 16 bits long.  The lower
 * 16 bits selects which fields {client_id, flags, client_ip,
 * server_ip, expiration, macro, or comment} of targetp are to be
 * considered in the query.  The upper 16 bits identifies whether a
 * particular field value must match (bit set) or not match (bit
 * clear).  Bits 7-15 in both 16 bit fields are currently unused, and
 * must be set to 0.  The count field specifies the maximum number of
 * matching records to return, or -1 if any number of records may be
 * returned.  The recordspp argument is set to point to the resulting
 * list of records; if recordspp is passed in as NULL then no records
 * are actually returned. Note that these records are dynamically
 * allocated, thus the caller is responsible for freeing them.  The
 * number of records found is returned in nrecordsp; a value of 0 means
 * that no records matched the query.
 */
int
lookup_dn(void *handle, boolean_t partial, uint_t query, int count,
    const dn_rec_t *targetp, dn_rec_list_t **recordspp, uint_t *nrecordsp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_result		*resp;
	dn_rec_list_t		*hlp = NULL, *tlp;
	dn_rec_t		*dnp;
	char			*scp;
	int			error, i;
	uint_t			num, flags = FOLLOW_LINKS;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	scp = query_to_searchcriteria(targetp, query, nhp->h_name);
	if (scp == NULL)
		return (DSVC_NO_MEMORY);

	if (!(nhp->h_flags & DSVC_NONBLOCK))
		flags |= HARD_LOOKUP;

	resp = nis_list(scp, flags, NULL, NULL);
	free(scp);
	error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp), NIS_ENTRY_OBJ);
	if (error != DSVC_SUCCESS) {
		if (error == DSVC_NOENT) {
			/* no records matched the query */
			error = 0;
			*nrecordsp = 0;
			if (recordspp != NULL)
				*recordspp = NULL;
		}
		nis_freeresult(resp);
		return (error);
	}

	/*
	 * Fastpath for queries w/o negative aspects for which no records
	 * are to be returned.
	 */
	if (recordspp == NULL && !DSVC_QISNEQ(query, DN_QALL)) {
		*nrecordsp = NIS_RES_NUMOBJ(resp);
		nis_freeresult(resp);
		return (DSVC_SUCCESS);
	}

	for (i = 0, num = 0; i < NIS_RES_NUMOBJ(resp) && (count < 0 ||
	    num < count); i++) {

		nis_object	*op = &NIS_RES_OBJECT(resp)[i];

		error = dsvcnis_entryobj_to_dnrec(op, &dnp);
		if (error != DSVC_SUCCESS) {
			if (partial)
				break;
			nis_freeresult(resp);
			free_dnrec_list(hlp);
			return (error);
		}

		/*
		 * The query has gotten the records that match the "positive"
		 * aspects of the query. Weed out the records that match the
		 * "negative" aspect.
		 */
		if ((DSVC_QISNEQ(query, DN_QCID) &&
		    targetp->dn_cid_len == dnp->dn_cid_len &&
		    memcmp(targetp->dn_cid, dnp->dn_cid,
			dnp->dn_cid_len) == 0) ||
		    (DSVC_QISNEQ(query, DN_QCIP) &&
		    targetp->dn_cip.s_addr == dnp->dn_cip.s_addr) ||
		    (DSVC_QISNEQ(query, DN_QSIP) &&
		    targetp->dn_sip.s_addr == dnp->dn_sip.s_addr) ||
		    (DSVC_QISNEQ(query, DN_QLEASE) &&
		    targetp->dn_lease == dnp->dn_lease) ||
		    (DSVC_QISNEQ(query, DN_QMACRO) &&
		    strncmp(targetp->dn_macro,  dnp->dn_macro,
		    sizeof (dnp->dn_macro)) == 0)) {
			free_dnrec(dnp);
			continue;
		}

		if ((tlp = add_dnrec_to_list(dnp, hlp)) == NULL) {
			if (partial)
				break;
			nis_freeresult(resp);
			free_dnrec(dnp);
			free_dnrec_list(hlp);
			return (DSVC_NO_MEMORY);
		} else {
			hlp = tlp;
			num++;
		}
	}

	nis_freeresult(resp);

	*nrecordsp = num;
	if (recordspp != NULL)
		*recordspp = hlp;

	return (DSVC_SUCCESS);
}

/*
 * Add the record pointed to by addp from the dhcp network container
 * referred to by the handle.  addp's signature will be updated by the
 * underlying public module.
 */
int
add_dn(void *handle, dn_rec_t *addp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_object		*op;
	nis_result		*resp;
	int			error;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	if (!(nhp->h_flags & DSVC_WRITE))
		return (DSVC_ACCESS);

	addp->dn_sig = 0;	/* New records have 0 signature */

	if ((error = dsvcnis_dnrec_to_entryobj(addp, &op)) != DSVC_SUCCESS)
		return (error);

	if ((error = dsvcnis_set_table_fields(nhp, op)) != DSVC_SUCCESS) {
		nis_destroy_object(op);
		return (error);
	}

	for (;;) {
		resp = nis_add_entry(nhp->h_name, op, RETURN_RESULT);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		if (error == DSVC_BUSY && !(nhp->h_flags & DSVC_NONBLOCK)) {
			nis_freeresult(resp);
			(void) sleep(NIS_BUSY_PAUSE);
		} else
			break;
	}

	nis_destroy_object(op);

	if (error == DSVC_SUCCESS) {
		nis_object	*nop;

		nop = NIS_RES_OBJECT(resp);

		/* oid -> signature */
		addp->dn_sig = dsvcnis_obj_to_sig(nop);
	}

	nis_freeresult(resp);

	return (error);
}

/*
 * Atomically modify the record origp with the record newp in the dhcp
 * network container referred to by the handle.  newp's signature will
 * be updated by the underlying public module.  If an update collision
 * occurs, no update of the data store occurs.
 */
int
modify_dn(void *handle, const dn_rec_t *origp, dn_rec_t *newp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_object		*op, *nop;
	nis_result		*resp;
	int			error;
	uint_t			query, flags;
	char			*scp;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	if (!(nhp->h_flags & DSVC_WRITE))
		return (DSVC_ACCESS);

	/*
	 * MOD_SAMEOBJ ensures that the signature of the obj to modify has
	 * not changed in the table (detects update collisions).
	 */
	flags = MOD_SAMEOBJ | RETURN_RESULT;

	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QCIP);
	if ((scp = query_to_searchcriteria(origp, query, nhp->h_name)) == NULL)
		return (DSVC_NO_MEMORY);

	if ((error = dsvcnis_dnrec_to_entryobj(origp, &op)) != DSVC_SUCCESS) {
		free(scp);
		return (error);
	}

	if ((error = dsvcnis_dnrec_to_entryobj(newp, &nop)) != DSVC_SUCCESS) {
		free(scp);
		nis_destroy_object(op);
		return (error);
	}

	if ((error = dsvcnis_set_table_fields(nhp, nop)) != DSVC_SUCCESS) {
		free(scp);
		nis_destroy_object(op);
		nis_destroy_object(nop);
		return (error);
	}

	/* copy object ID */
	nop->zo_oid.ctime = op->zo_oid.ctime;
	nop->zo_oid.mtime = op->zo_oid.mtime;

	nis_destroy_object(op);

	/* cid */
	if (origp->dn_cid_len != newp->dn_cid_len ||
	    memcmp(origp->dn_cid, newp->dn_cid, newp->dn_cid_len) != 0) {
		ENTRY_FLAGS(nop, CID_DN) |= EN_MODIFIED;
	}

	/* flags */
	if (origp->dn_flags != newp->dn_flags)
		ENTRY_FLAGS(nop, FLAGS_DN) |= EN_MODIFIED;

	/* cip */
	if (origp->dn_sip.s_addr != newp->dn_sip.s_addr) {
		/*
		 * We set MOD_EXCLUSIVE because CIP is unique, and
		 * we want nisplus to check to see if there will be a
		 * collision (matching record), and not perform the modify
		 * if a collision occurs. Allows us to do an atomic
		 * modify.
		 */
		flags |= MOD_EXCLUSIVE;
		ENTRY_FLAGS(nop, CIP_DN) |= EN_MODIFIED;
	}

	/* sip */
	if (origp->dn_sip.s_addr != newp->dn_sip.s_addr)
		ENTRY_FLAGS(nop, SIP_DN) |= EN_MODIFIED;

	/* lease */
	if (origp->dn_lease != newp->dn_lease)
		ENTRY_FLAGS(nop, LEASE_DN) |= EN_MODIFIED;

	/* macro */
	if (strcmp(origp->dn_macro, newp->dn_macro) != 0)
		ENTRY_FLAGS(nop, MACRO_DN) |= EN_MODIFIED;

	/* comment */
	if (strcmp(origp->dn_comment, newp->dn_comment) != 0)
		ENTRY_FLAGS(nop, COMMENT_DN) |= EN_MODIFIED;

	for (;;) {
		resp = nis_modify_entry(scp, nop, flags);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		if (error == DSVC_BUSY && !(nhp->h_flags & DSVC_NONBLOCK)) {
			nis_freeresult(resp);
			(void) sleep(NIS_BUSY_PAUSE);
		} else
			break;
	}

	free(scp);
	nis_destroy_object(nop);

	if (error == DSVC_SUCCESS)
		newp->dn_sig = dsvcnis_obj_to_sig(NIS_RES_OBJECT(resp));

	nis_freeresult(resp);

	return (error);
}

/*
 * Delete the record pointed to by pnp from the dhcp network container
 * referred to by the handle.  If an update collision occurs, no
 * deletion of record in the data store occurs.
 */
int
delete_dn(void *handle, const dn_rec_t *pnp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_result		*resp;
	nis_object		*op;
	int			error;
	uint_t			query;
	char			*scp;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	if (!(nhp->h_flags & DSVC_WRITE))
		return (DSVC_ACCESS);

	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QCIP);

	if ((scp = query_to_searchcriteria(pnp, query, nhp->h_name)) == NULL)
		return (DSVC_NO_MEMORY);

	if (pnp->dn_sig != 0) {
		/* Caller is interested in knowing about a collision */
		error = dsvcnis_dnrec_to_entryobj(pnp, &op);
		if (error != DSVC_SUCCESS) {
			free(scp);
			return (error);
		}
	} else
		op = NULL;

	for (;;) {
		resp = nis_remove_entry(scp, op, 0);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		nis_freeresult(resp);
		if (error == DSVC_BUSY && !(nhp->h_flags & DSVC_NONBLOCK))
			(void) sleep(NIS_BUSY_PAUSE);
		else
			break;
	}

	free(scp);

	if (op != NULL)
		nis_destroy_object(op);

	return (error);
}
