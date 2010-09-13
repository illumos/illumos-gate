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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file only contains the transaction commit logic.
 */

#include <assert.h>
#include <alloca.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/sysmacros.h>
#include "configd.h"

#define	INVALID_OBJ_ID ((uint32_t)-1)
#define	INVALID_TYPE ((uint32_t)-1)

struct tx_cmd {
	const struct rep_protocol_transaction_cmd *tx_cmd;
	const char	*tx_prop;
	uint32_t	*tx_values;
	uint32_t	tx_nvalues;
	uint32_t	tx_orig_value_id;
	char		tx_found;
	char		tx_processed;
	char		tx_bad;
};

static int
tx_cmd_compare(const void *key, const void *elem_arg)
{
	const struct tx_cmd *elem = elem_arg;

	return (strcmp((const char *)key, elem->tx_prop));
}

struct tx_commit_data {
	uint32_t	txc_pg_id;
	uint32_t	txc_gen;
	uint32_t	txc_oldgen;
	short		txc_backend;
	backend_tx_t	*txc_tx;
	backend_query_t	*txc_inserts;
	size_t		txc_count;
	rep_protocol_responseid_t txc_result;
	struct tx_cmd	txc_cmds[1];		/* actually txc_count */
};
#define	TX_COMMIT_DATA_SIZE(count) \
	offsetof(struct tx_commit_data, txc_cmds[count])

/*ARGSUSED*/
static int
tx_check_genid(void *data_arg, int columns, char **vals, char **names)
{
	tx_commit_data_t *data = data_arg;
	assert(columns == 1);
	if (atoi(vals[0]) != data->txc_oldgen)
		data->txc_result = REP_PROTOCOL_FAIL_NOT_LATEST;
	else
		data->txc_result = REP_PROTOCOL_SUCCESS;
	return (BACKEND_CALLBACK_CONTINUE);
}

/*
 * tx_process_property() is called once for each property in current
 * property group generation.  Its purpose is threefold:
 *
 *	1. copy properties not mentioned in the transaction over unchanged.
 *	2. mark DELETEd properties as seen (they will be left out of the new
 *	   generation).
 *	3. consistancy-check NEW, CLEAR, and REPLACE commands.
 *
 * Any consistancy problems set tx_bad, and seen properties are marked
 * tx_found.  These is used later, in tx_process_cmds().
 */
/*ARGSUSED*/
static int
tx_process_property(void *data_arg, int columns, char **vals, char **names)
{
	tx_commit_data_t *data = data_arg;
	struct tx_cmd *elem;

	const char *prop_name = vals[0];
	const char *prop_type = vals[1];
	const char *lnk_val_id = vals[2];

	char *endptr;

	assert(columns == 3);

	elem = bsearch(prop_name, data->txc_cmds, data->txc_count,
	    sizeof (*data->txc_cmds), tx_cmd_compare);

	if (elem == NULL) {
		backend_query_add(data->txc_inserts,
		    "INSERT INTO prop_lnk_tbl"
		    "    (lnk_pg_id, lnk_gen_id, lnk_prop_name, lnk_prop_type,"
		    "    lnk_val_id) "
		    "VALUES ( %d, %d, '%q', '%q', %Q );",
		    data->txc_pg_id, data->txc_gen, prop_name, prop_type,
		    lnk_val_id);
	} else {
		assert(!elem->tx_found);
		elem->tx_found = 1;

		if (lnk_val_id != NULL) {
			errno = 0;
			elem->tx_orig_value_id =
			    strtoul(lnk_val_id, &endptr, 10);
			if (elem->tx_orig_value_id == 0 || *endptr != 0 ||
			    errno != 0) {
				return (BACKEND_CALLBACK_ABORT);
			}
		} else {
			elem->tx_orig_value_id = 0;
		}

		switch (elem->tx_cmd->rptc_action) {
		case REP_PROTOCOL_TX_ENTRY_NEW:
			elem->tx_bad = 1;
			data->txc_result = REP_PROTOCOL_FAIL_EXISTS;
			break;
		case REP_PROTOCOL_TX_ENTRY_CLEAR:
			if (REP_PROTOCOL_BASE_TYPE(elem->tx_cmd->rptc_type) !=
			    prop_type[0] &&
			    REP_PROTOCOL_SUBTYPE(elem->tx_cmd->rptc_type) !=
			    prop_type[1]) {
				elem->tx_bad = 1;
				data->txc_result =
				    REP_PROTOCOL_FAIL_TYPE_MISMATCH;
			}
			break;
		case REP_PROTOCOL_TX_ENTRY_REPLACE:
			break;
		case REP_PROTOCOL_TX_ENTRY_DELETE:
			elem->tx_processed = 1;
			break;
		default:
			assert(0);
			break;
		}
	}
	return (BACKEND_CALLBACK_CONTINUE);
}

/*
 * tx_process_cmds() finishes the job tx_process_property() started:
 *
 *	1. if tx_process_property() marked a command as bad, we skip it.
 *	2. if a DELETE, REPLACE, or CLEAR operated on a non-existant property,
 *	    we mark it as bad.
 *	3. we complete the work of NEW, REPLACE, and CLEAR, by inserting the
 *	    appropriate values into the database.
 *	4. we delete all replaced data, if it is no longer referenced.
 *
 * Finally, we check all of the commands, and fail if anything was marked bad.
 */
static int
tx_process_cmds(tx_commit_data_t *data)
{
	int idx;
	int r;
	int count = data->txc_count;
	struct tx_cmd *elem;
	uint32_t val_id = 0;
	uint8_t type[3];

	backend_query_t *q;
	int do_delete;

	/*
	 * For persistent pgs, we use backend_fail_if_seen to abort the
	 * deletion if there is a snapshot using our current state.
	 *
	 * All of the deletions in this function are safe, since
	 * rc_tx_commit() guarantees that all the data is in-cache.
	 */
	q = backend_query_alloc();

	if (data->txc_backend != BACKEND_TYPE_NONPERSIST) {
		backend_query_add(q,
		    "SELECT 1 FROM snaplevel_lnk_tbl "
		    "    WHERE (snaplvl_pg_id = %d AND snaplvl_gen_id = %d); ",
		    data->txc_pg_id, data->txc_oldgen);
	}
	backend_query_add(q,
	    "DELETE FROM prop_lnk_tbl"
	    "    WHERE (lnk_pg_id = %d AND lnk_gen_id = %d)",
	    data->txc_pg_id, data->txc_oldgen);
	r = backend_tx_run(data->txc_tx, q, backend_fail_if_seen, NULL);
	backend_query_free(q);

	if (r == REP_PROTOCOL_SUCCESS)
		do_delete = 1;
	else if (r == REP_PROTOCOL_DONE)
		do_delete = 0;		/* old gen_id is in use */
	else
		return (r);

	for (idx = 0; idx < count; idx++) {
		elem = &data->txc_cmds[idx];

		if (elem->tx_bad)
			continue;

		switch (elem->tx_cmd->rptc_action) {
		case REP_PROTOCOL_TX_ENTRY_DELETE:
		case REP_PROTOCOL_TX_ENTRY_REPLACE:
		case REP_PROTOCOL_TX_ENTRY_CLEAR:
			if (!elem->tx_found) {
				elem->tx_bad = 1;
				continue;
			}
			break;
		case REP_PROTOCOL_TX_ENTRY_NEW:
			break;
		default:
			assert(0);
			break;
		}

		if (do_delete &&
		    elem->tx_cmd->rptc_action != REP_PROTOCOL_TX_ENTRY_NEW &&
		    elem->tx_orig_value_id != 0) {
			/*
			 * delete the old values, if they are not in use
			 */
			q = backend_query_alloc();
			backend_query_add(q,
			    "SELECT 1 FROM prop_lnk_tbl "
			    "    WHERE (lnk_val_id = %d); "
			    "DELETE FROM value_tbl"
			    "    WHERE (value_id = %d)",
			    elem->tx_orig_value_id, elem->tx_orig_value_id);
			r = backend_tx_run(data->txc_tx, q,
			    backend_fail_if_seen, NULL);
			backend_query_free(q);
			if (r != REP_PROTOCOL_SUCCESS && r != REP_PROTOCOL_DONE)
				return (r);
		}

		if (elem->tx_cmd->rptc_action == REP_PROTOCOL_TX_ENTRY_DELETE)
			continue;		/* no further work to do */

		type[0] = REP_PROTOCOL_BASE_TYPE(elem->tx_cmd->rptc_type);
		type[1] = REP_PROTOCOL_SUBTYPE(elem->tx_cmd->rptc_type);
		type[2] = 0;

		if (elem->tx_nvalues == 0) {
			r = backend_tx_run_update(data->txc_tx,
			    "INSERT INTO prop_lnk_tbl"
			    "    (lnk_pg_id, lnk_gen_id, "
			    "    lnk_prop_name, lnk_prop_type, lnk_val_id) "
			    "VALUES ( %d, %d, '%q', '%q', NULL );",
			    data->txc_pg_id, data->txc_gen, elem->tx_prop,
			    type);
		} else {
			uint32_t *v, i = 0;
			const char *str;

			val_id = backend_new_id(data->txc_tx, BACKEND_ID_VALUE);
			if (val_id == 0)
				return (REP_PROTOCOL_FAIL_NO_RESOURCES);
			r = backend_tx_run_update(data->txc_tx,
			    "INSERT INTO prop_lnk_tbl "
			    "    (lnk_pg_id, lnk_gen_id, "
			    "    lnk_prop_name, lnk_prop_type, lnk_val_id) "
			    "VALUES ( %d, %d, '%q', '%q', %d );",
			    data->txc_pg_id, data->txc_gen, elem->tx_prop,
			    type, val_id);

			v = elem->tx_values;

			for (i = 0; i < elem->tx_nvalues; i++) {
				str = (const char *)&v[1];

				/*
				 * Update values in backend,  imposing
				 * ordering via the value_order column.
				 * This ordering is then used in subseqent
				 * value retrieval operations.  We can
				 * safely assume that the repository schema
				 * has been upgraded (and hence has the
				 * value_order column in value_tbl),  since
				 * it is upgraded as soon as the repository
				 * is writable.
				 */
				r = backend_tx_run_update(data->txc_tx,
				    "INSERT INTO value_tbl (value_id, "
				    "value_type, value_value, "
				    "value_order) VALUES (%d, '%c', "
				    "'%q', '%d');\n",
				    val_id, elem->tx_cmd->rptc_type,
				    str, i);
				if (r != REP_PROTOCOL_SUCCESS)
					break;

				/*LINTED alignment*/
				v = (uint32_t *)((caddr_t)str + TX_SIZE(*v));
			}
		}
		if (r != REP_PROTOCOL_SUCCESS)
			return (REP_PROTOCOL_FAIL_UNKNOWN);
		elem->tx_processed = 1;
	}

	for (idx = 0; idx < count; idx++) {
		elem = &data->txc_cmds[idx];

		if (elem->tx_bad)
			return (REP_PROTOCOL_FAIL_BAD_TX);
	}
	return (REP_PROTOCOL_SUCCESS);
}

static boolean_t
check_string(uintptr_t loc, uint32_t len, uint32_t sz)
{
	const char *ptr = (const char *)loc;

	if (len == 0 || len > sz || ptr[len - 1] != 0 || strlen(ptr) != len - 1)
		return (0);
	return (1);
}

static int
tx_check_and_setup(tx_commit_data_t *data, const void *cmds_arg,
    uint32_t count)
{
	const struct rep_protocol_transaction_cmd *cmds;
	struct tx_cmd *cur;
	struct tx_cmd *prev = NULL;

	uintptr_t loc;
	uint32_t sz, len;
	int idx;

	loc = (uintptr_t)cmds_arg;

	for (idx = 0; idx < count; idx++) {
		cur = &data->txc_cmds[idx];

		cmds = (struct rep_protocol_transaction_cmd *)loc;
		cur->tx_cmd = cmds;

		sz = cmds->rptc_size;

		loc += REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE;
		sz -= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE;

		len = cmds->rptc_name_len;
		if (len <= 1 || !check_string(loc, len, sz)) {
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);
		}
		cur->tx_prop = (const char *)loc;

		len = TX_SIZE(len);
		loc += len;
		sz -= len;

		cur->tx_nvalues = 0;
		cur->tx_values = (uint32_t *)loc;

		while (sz > 0) {
			if (sz < sizeof (uint32_t))
				return (REP_PROTOCOL_FAIL_BAD_REQUEST);

			cur->tx_nvalues++;

			len = *(uint32_t *)loc;
			loc += sizeof (uint32_t);
			sz -= sizeof (uint32_t);

			if (!check_string(loc, len, sz))
				return (REP_PROTOCOL_FAIL_BAD_REQUEST);

			/*
			 * XXX here, we should be checking that the values
			 * match the purported type
			 */

			len = TX_SIZE(len);

			if (len > sz)
				return (REP_PROTOCOL_FAIL_BAD_REQUEST);

			loc += len;
			sz -= len;
		}

		if (prev != NULL && strcmp(prev->tx_prop, cur->tx_prop) >= 0)
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);

		prev = cur;
	}
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Free the memory associated with a tx_commit_data structure.
 */
void
tx_commit_data_free(tx_commit_data_t *tx_data)
{
	uu_free(tx_data);
}

/*
 * Parse the data of a REP_PROTOCOL_PROPERTYGRP_TX_COMMIT message into a
 * more useful form.  The data in the message will be represented by a
 * tx_commit_data_t structure which is allocated by this function.  The
 * address of the allocated structure is returned to *tx_data and must be
 * freed by calling tx_commit_data_free().
 *
 * Parameters:
 *	cmds_arg	Address of the commands in the
 *			REP_PROTOCOL_PROPERTYGRP_TX_COMMIT message.
 *
 *	cmds_sz		Number of message bytes at cmds_arg.
 *
 *	tx_data		Points to the place to receive the address of the
 *			allocated memory.
 *
 * Fails with
 *	_BAD_REQUEST
 *	_NO_RESOURCES
 */
int
tx_commit_data_new(const void *cmds_arg, size_t cmds_sz,
    tx_commit_data_t **tx_data)
{
	const struct rep_protocol_transaction_cmd *cmds;
	tx_commit_data_t *data;
	uintptr_t loc;
	uint32_t count;
	uint32_t sz;
	int ret;

	/*
	 * First, verify that the reported sizes make sense, and count
	 * the number of commands.
	 */
	count = 0;
	loc = (uintptr_t)cmds_arg;

	while (cmds_sz > 0) {
		cmds = (struct rep_protocol_transaction_cmd *)loc;

		if (cmds_sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);

		sz = cmds->rptc_size;
		if (sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);

		sz = TX_SIZE(sz);
		if (sz > cmds_sz)
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);

		loc += sz;
		cmds_sz -= sz;
		count++;
	}

	data = uu_zalloc(TX_COMMIT_DATA_SIZE(count));
	if (data == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	/*
	 * verify that everything looks okay, and set up our command
	 * datastructures.
	 */
	data->txc_count = count;
	ret = tx_check_and_setup(data, cmds_arg, count);
	if (ret == REP_PROTOCOL_SUCCESS) {
		*tx_data = data;
	} else {
		*tx_data = NULL;
		uu_free(data);
	}
	return (ret);
}

/*
 * The following are a set of accessor functions to retrieve data from a
 * tx_commit_data_t that has been allocated by tx_commit_data_new().
 */

/*
 * Return the action of the transaction command whose command number is
 * cmd_no.  The action is placed at *action.
 *
 * Returns:
 *	_FAIL_BAD_REQUEST	cmd_no is out of range.
 */
int
tx_cmd_action(tx_commit_data_t *tx_data, size_t cmd_no,
    enum rep_protocol_transaction_action *action)
{
	struct tx_cmd *cur;

	assert(cmd_no < tx_data->txc_count);
	if (cmd_no >= tx_data->txc_count)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	cur = &tx_data->txc_cmds[cmd_no];
	*action = cur->tx_cmd->rptc_action;
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Return the number of transaction commands held in tx_data.
 */
size_t
tx_cmd_count(tx_commit_data_t *tx_data)
{
	return (tx_data->txc_count);
}

/*
 * Return the number of property values that are associated with the
 * transaction command whose number is cmd_no.  The number of values is
 * returned to *nvalues.
 *
 * Returns:
 *	_FAIL_BAD_REQUEST	cmd_no is out of range.
 */
int
tx_cmd_nvalues(tx_commit_data_t *tx_data, size_t cmd_no, uint32_t *nvalues)
{
	struct tx_cmd *cur;

	assert(cmd_no < tx_data->txc_count);
	if (cmd_no >= tx_data->txc_count)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	cur = &tx_data->txc_cmds[cmd_no];
	*nvalues = cur->tx_nvalues;
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Return a pointer to the property name of the command whose number is
 * cmd_no.  The property name pointer is returned to *pname.
 *
 * Returns:
 *	_FAIL_BAD_REQUEST	cmd_no is out of range.
 */
int
tx_cmd_prop(tx_commit_data_t *tx_data, size_t cmd_no, const char **pname)
{
	struct tx_cmd *cur;

	assert(cmd_no < tx_data->txc_count);
	if (cmd_no >= tx_data->txc_count)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	cur = &tx_data->txc_cmds[cmd_no];
	*pname = cur->tx_prop;
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Return the property type of the property whose command number is
 * cmd_no.  The property type is returned to *ptype.
 *
 * Returns:
 *	_FAIL_BAD_REQUEST	cmd_no is out of range.
 */
int
tx_cmd_prop_type(tx_commit_data_t *tx_data, size_t cmd_no, uint32_t *ptype)
{
	struct tx_cmd *cur;

	assert(cmd_no < tx_data->txc_count);
	if (cmd_no >= tx_data->txc_count)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	cur = &tx_data->txc_cmds[cmd_no];
	*ptype = cur->tx_cmd->rptc_type;
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * This function is used to retrieve a property value from the transaction
 * data.  val_no specifies which value is to be retrieved from the
 * transaction command whose number is cmd_no.  A pointer to the specified
 * value is placed in *val.
 *
 * Returns:
 *	_FAIL_BAD_REQUEST	cmd_no or val_no is out of range.
 */
int
tx_cmd_value(tx_commit_data_t *tx_data, size_t cmd_no, uint32_t val_no,
    const char **val)
{
	const char *bp;
	struct tx_cmd *cur;
	uint32_t i;
	uint32_t value_len;

	assert(cmd_no < tx_data->txc_count);
	if (cmd_no >= tx_data->txc_count)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	cur = &tx_data->txc_cmds[cmd_no];
	assert(val_no < cur->tx_nvalues);
	if (val_no >= cur->tx_nvalues)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	/* Find the correct value */
	bp = (char *)cur->tx_values;
	for (i = 0; i < val_no; i++) {
		/* LINTED alignment */
		value_len = *(uint32_t *)bp;
		bp += sizeof (uint32_t) + TX_SIZE(value_len);
	}

	/* Bypass the count & return pointer to value. */
	bp += sizeof (uint32_t);
	*val = bp;
	return (REP_PROTOCOL_SUCCESS);
}

int
object_tx_commit(rc_node_lookup_t *lp, tx_commit_data_t *data, uint32_t *gen)
{
	uint32_t new_gen;
	int ret;
	rep_protocol_responseid_t r;
	backend_tx_t *tx;
	backend_query_t *q;
	int backend = lp->rl_backend;

	ret = backend_tx_begin(backend, &tx);
	if (ret != REP_PROTOCOL_SUCCESS)
		return (ret);

	/* Make sure the pg is up-to-date. */
	data->txc_oldgen = *gen;
	data->txc_backend = backend;
	data->txc_result = REP_PROTOCOL_FAIL_NOT_FOUND;

	q = backend_query_alloc();
	backend_query_add(q, "SELECT pg_gen_id FROM pg_tbl WHERE (pg_id = %d);",
	    lp->rl_main_id);
	r = backend_tx_run(tx, q, tx_check_genid, data);
	backend_query_free(q);

	if (r != REP_PROTOCOL_SUCCESS ||
	    (r = data->txc_result) != REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(tx);
		goto end;
	}

	/* If the transaction is empty, cut out early. */
	if (data->txc_count == 0) {
		backend_tx_rollback(tx);
		r = REP_PROTOCOL_DONE;
		goto end;
	}

	new_gen = backend_new_id(tx, BACKEND_ID_GENERATION);
	if (new_gen == 0) {
		backend_tx_rollback(tx);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	data->txc_pg_id = lp->rl_main_id;
	data->txc_gen = new_gen;
	data->txc_tx = tx;

	r = backend_tx_run_update(tx,
	    "UPDATE pg_tbl SET pg_gen_id = %d "
	    "    WHERE (pg_id = %d AND pg_gen_id = %d);",
	    new_gen, lp->rl_main_id, *gen);

	if (r != REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(tx);
		goto end;
	}

	q = backend_query_alloc();

	backend_query_add(q,
	    "SELECT lnk_prop_name, lnk_prop_type, lnk_val_id "
	    "FROM prop_lnk_tbl "
	    "WHERE (lnk_pg_id = %d AND lnk_gen_id = %d)",
	    lp->rl_main_id, *gen);

	data->txc_inserts = backend_query_alloc();
	r = backend_tx_run(tx, q, tx_process_property, data);
	backend_query_free(q);

	if (r == REP_PROTOCOL_DONE)
		r = REP_PROTOCOL_FAIL_UNKNOWN;		/* corruption */

	if (r != REP_PROTOCOL_SUCCESS ||
	    (r = data->txc_result) != REP_PROTOCOL_SUCCESS) {
		backend_query_free(data->txc_inserts);
		backend_tx_rollback(tx);
		goto end;
	}

	r = backend_tx_run(tx, data->txc_inserts, NULL, NULL);
	backend_query_free(data->txc_inserts);

	if (r != REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(tx);
		goto end;
	}

	r = tx_process_cmds(data);
	if (r != REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(tx);
		goto end;
	}
	r = backend_tx_commit(tx);

	if (r == REP_PROTOCOL_SUCCESS)
		*gen = new_gen;
end:
	return (r);
}
