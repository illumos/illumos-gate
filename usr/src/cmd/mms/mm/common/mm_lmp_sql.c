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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <ctype.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <libpq-fe.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_commands.h"
#include "mm_sql.h"
#include "mm_sql_impl.h"

static char *_SrcFile = __FILE__;

static int mm_lm_state_hard(mm_wka_t *mm_wka, char *state);
static int mm_lm_state_soft(mm_wka_t *mm_wka, char *state);
mm_command_t *mm_lmp_add_dm_enable(char *drive_name, char *cart_pcl,
    char *state_soft, char *drive_online, mm_wka_t *mm_wka);
mm_command_t *mm_alloc_dm_enable(mm_wka_t *mm_wka);



#define	MM_LM_READY 0
#define	MM_LM_NOT_READY 1
#define	MM_LM_ABSENT 2
#define	MM_LM_PRESENT 3
#define	MM_LM_DISCONNECTED 4
#define	MM_LM_ERROR 5
#define	MM_LM_WAIT 6
#define	MM_LM_SEND 7


int
mm_lm_get_state(mm_command_t *cmd, mm_wka_t *lm_wka) {

	mm_db_t		*db = &lm_wka->mm_data->mm_db;
	char		*lm_name = lm_wka->wka_conn.cci_instance;
	char		*lm_state = NULL;

	if (mm_db_exec(HERE, db, "select \"LMStateSoft\" from \"LM\" "
		"where \"LMName\" = '%s'",
		lm_name) != MM_DB_DATA) {
		mms_trace(MMS_DEVP, "Error getting state info");
		mm_sql_db_err_rsp_new(cmd, db);
		return (MM_LM_ERROR);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		mms_trace(MMS_DEVP, "could not find lm in database");
		mm_system_error(cmd,
			"could not find lm in database");
		mm_clear_db(&db->mm_db_results);
		return (MM_LM_ERROR);
	}
	lm_state = PQgetvalue(db->mm_db_results, 0, 0);
	mms_trace(MMS_DEVP,
	    "%s is %s",
	    lm_name, lm_state);
	if (strcmp(lm_state, "ready") == 0) {
		mm_clear_db(&db->mm_db_results);
		return (MM_LM_READY);
	}
	if (strcmp(lm_state, "not ready") == 0) {
		mm_clear_db(&db->mm_db_results);
		return (MM_LM_NOT_READY);
	}
	if (strcmp(lm_state, "present") == 0) {
		mm_clear_db(&db->mm_db_results);
		return (MM_LM_PRESENT);
	}
	if (strcmp(lm_state, "absent") == 0) {
		mm_clear_db(&db->mm_db_results);
		return (MM_LM_ABSENT);
	}
	if (strcmp(lm_state, "disconnected") == 0) {
		mm_clear_db(&db->mm_db_results);
		return (MM_LM_DISCONNECTED);
	}
	mm_clear_db(&db->mm_db_results);
	return (MM_LM_ERROR);
}

int
mm_lm_send_ok(mm_command_t *cmd, mm_wka_t *lm_wka) {
	int		 rc = 0;
	mm_db_t		*db = &lm_wka->mm_data->mm_db;
	char		*lm_name = lm_wka->wka_conn.cci_instance;

	/* check if lm is supposed to be online/active */
	/* if not, then return MM_LM_ERROR */
	/* because this lmp command cannot be sent to the lm */
	if (mm_db_exec(HERE, db,
		    "select \"LibraryName\" from \"LIBRARY\""
		    " where \"LibraryOnline\" = 'true' and "
		    "\"LMName\" = '%s'; ",
		    lm_name) != MM_DB_DATA) {
		mms_trace(MMS_DEVP, "Error getting online info");
		mm_sql_db_err_rsp_new(cmd, db);
		return (MM_LM_ERROR);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		/* this lm is not an active online lm */
		mms_trace(MMS_DEVP, "LM is not the active lm for "
		    "an online library");
		mm_system_error(cmd, "LM is not the active lm for "
		    "an online library");
		mm_clear_db(&db->mm_db_results);
		return (MM_LM_ERROR);
	}
	mm_clear_db(&db->mm_db_results);
	/* LM is supposed to be online and active */

	rc = mm_lm_get_state(cmd, lm_wka);
	if (rc == MM_LM_ERROR) {
		mms_trace(MMS_DEVP, "Error getting state info");
		cmd->cmd_remove = 1;
		return (MM_LM_ERROR);
	}
	if (rc == MM_LM_NOT_READY) {
		mms_trace(MMS_DEVP,
		    "need to wait on this cmd ");
		return (MM_LM_WAIT);
	} else if (rc == MM_LM_READY) {
		mms_trace(MMS_DEVP,
		    "lm ready continue");
		return (MM_LM_SEND);
	} else if (rc == MM_LM_PRESENT) {
		mms_trace(MMS_DEVP,
		    "active but not ready");
		return (MM_LM_WAIT);
	} else {
		/* lm is present/disconnected/absent */
		mms_trace(MMS_DEVP, "Current LM state prevents "
		    "this command from running");
		cmd->cmd_remove = 1;
		mm_system_error(cmd, "Current LM state prevents "
			    "this command from running");
		return (MM_LM_ERROR);
	}
}




int
mm_add_lmp_scan(mm_data_t *mm_data, mm_command_t *parent_cmd, char *drive_name,
		char *cartridge_pcl, char *library_name) {

	/* THIS FUNCTION MAY ONLY BE CALLED BY WORKER THREAD */
	/* To multi thread, must pass the db ptr */

	mm_command_t		*cmd = NULL;
	mm_db_t			*db = &mm_data->mm_db;
	mm_wka_t		*lm_wka = NULL;
	uuid_text_t		uuid;

	PGresult		*lm_name = NULL;

	mms_trace(MMS_DEVP, "mm_add_lmp_scan");

	/* check args */
	if (mm_data == NULL) {
		mms_trace(MMS_ERR, "mm_data cannot be NULL");
		return (1);
	}
	if (library_name == NULL) {
		mms_trace(MMS_ERR, "missing a library name");
		return (1);
	}
	if ((drive_name == NULL) &&
	    (cartridge_pcl == NULL)) {
		mms_trace(MMS_ERR,
		    "need a drive name or cartridge pcl");
		return (1);
	} else if ((drive_name) &&
		(cartridge_pcl)) {
		mms_trace(MMS_ERR,
		    "cannot have both a drive name and a pcl");
		return (1);
	}
	if (parent_cmd == NULL) {
		mms_trace(MMS_DEVP,
		    "No parent command, scan will run independantly");
	} else {
		mms_trace(MMS_DEVP,
		    "Found a parent, scan will be a child command");
	}

	/* get the lm name */
	if (mm_db_exec(HERE, db,
		    "select \"LMName\" from "
		    "\"LIBRARY\" where "
		    "\"LibraryName\" = '%s';",
		    library_name) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error getting lm name for LMP scan");
		return (1);
	}
	lm_name = db->mm_db_results;
	if (PQntuples(lm_name) != 1) {
		mms_trace(MMS_ERR,
		    "Error getting lm name information, "
		    "library %s, db results != 1",
		    library_name);
		mm_clear_db(&lm_name);
		return (1);
	}

	/* find the lm's wka */
	lm_wka = NULL;
	mms_list_foreach(&mm_data->mm_wka_list, lm_wka) {
		if ((lm_wka->mm_wka_mm_lang == MM_LANG_LMP) &&
		    (strcmp(lm_wka->wka_conn.cci_instance,
			    PQgetvalue(lm_name, 0, 0)) == 0)) {
			/* Found the wka of dm */
			break;
		}

	}
	if ((lm_wka == NULL) || (strcmp(lm_wka->wka_conn.cci_instance,
				    PQgetvalue(lm_name, 0, 0)) != 0)) {
		/* bad wka */
		mms_trace(MMS_DEBUG, "Could not find lm's wka, "
		    "lm may not have connected yet");
		mm_clear_db(&lm_name);
		return (1);
	}
	mm_clear_db(&lm_name);

	if ((cmd = mm_alloc_cmd(lm_wka)) == NULL) {
		mms_trace(MMS_ERR,
			"Unable to malloc mm_command_t: %s",
			strerror(errno));
		return (1);
	}

	mm_get_uuid(uuid);
	cmd->cmd_task = strdup(uuid);
	cmd->cmd_func = mm_lmp_scan_cmd_func;
	cmd->cmd_name = strdup("lmp scan");
	mm_add_depend(cmd, parent_cmd);
	/* Create the text command */
	cmd->cmd_textcmd = NULL;
	cmd->cmd_textcmd = mms_strapp(cmd->cmd_textcmd,
			"scan task[\"%s\"] ",
			cmd->cmd_task);
	if (drive_name) {
		cmd->cmd_textcmd = mms_strapp(cmd->cmd_textcmd,
				"drive [\"%s\"]",
				drive_name);
	} else if (cartridge_pcl) {
		cmd->cmd_textcmd = mms_strapp(cmd->cmd_textcmd,
				"slot [\"%s\"]",
				cartridge_pcl);
	}
	cmd->cmd_textcmd = mms_strapp(cmd->cmd_textcmd, ";");

	mms_trace(MMS_DEVP, "%s", cmd->cmd_textcmd);
	pthread_mutex_lock(&mm_data->
			mm_queue_mutex);
	mms_list_insert_tail(&mm_data->mm_cmd_queue, cmd);
	pthread_mutex_unlock(&mm_data->
			mm_queue_mutex);
	mms_trace(MMS_DEVP, "LMP Scan Command Added to Queue");
	return (0);
}

/*
 * mm_library_lm_clear_states(db)
 *
 * Clear all library and lm states at mm startup.
 */
int
mm_library_lm_clear_states(mm_db_t *db)
{
	int		rc = 0;

	/*
	 * Reset all libraries and lms states
	 */
	if (mm_db_exec(HERE, db, "UPDATE \"LIBRARY\" SET "
	    "\"LibraryBroken\" = default, "
	    "\"LibraryStateHard\" = default, "
	    "\"LibraryStateSoft\" = default;") != MM_DB_OK) {
		rc = 1;
	}

	if (mm_db_exec(HERE, db, "UPDATE \"LM\" SET "
	    "\"LMStateHard\" = default, "
	    "\"LMStateSoft\" = default, "
	    "\"LMHost\" = NULL;") != MM_DB_OK) {
		rc = 1;
	}

	return (rc);
}

/*
 * mm_library_mm_wka(mm_data, library, lm)
 *
 * Find library in list of work areas by library, lm, or both.
 */
mm_wka_t *
mm_library_lm_wka(mm_data_t *mm_data, char *library, char *lm)
{
	mm_wka_t	*mm_wka = NULL;

	/* pthread_mutex_lock(&mm_data->mm_wka_mutex); */
	mms_list_foreach(&mm_data->mm_wka_list, mm_wka) {
		if ((library != NULL && lm == NULL) &&
		    strcmp(mm_wka->wka_conn.cci_client, library) == 0) {
			break;
		} else if ((library == NULL && lm != NULL) &&
		    strcmp(mm_wka->wka_conn.cci_instance, lm) == 0) {
			break;
		} else if ((library != NULL && lm != NULL) &&
		    strcmp(mm_wka->wka_conn.cci_client, library) == 0 &&
		    strcmp(mm_wka->wka_conn.cci_instance, lm) == 0) {
			break;
		}
	}
	/* pthread_mutex_unlock(&mm_data->mm_wka_mutex); */

	return (mm_wka);
}

/*
 * mm_library_lm_connect(mm_wka)
 *
 * Activate library lm at connection time if possiable.
 */
int
mm_library_lm_connect(mm_wka_t *mm_wka)
{
	/*
	 * Set lm states
	 */
	if (mm_lm_state_hard(mm_wka, "ready") ||
	    mm_lm_state_soft(mm_wka, "present")) {
		mms_trace(MMS_DEVP, "unable to change lm states");
		return (1);
	}
	return (0);
}

/*
 * mm_library_lm_activate_enable(mm_wka)
 *
 * Activate the library lm if possiable.
 */
int
mm_library_lm_activate_enable(mm_wka_t *mm_wka)
{
	int		 rc = 0;
	uuid_text_t	 task;
	int		 rows = 0;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*cmd = NULL;

	/*
	 * Determine if activate enable can be sent
	 */
	rc = mm_db_exec(HERE, db, "SELECT \"LIBRARY\".\"LibraryName\" FROM "
	    "\"LIBRARY\",\"LM\" WHERE "
	    "\"LIBRARY\".\"LibraryDisabled\" = 'false' AND "
	    "\"LIBRARY\".\"LibraryStateSoft\" = 'ready' AND "
	    "\"LIBRARY\".\"LibraryBroken\" = 'false' AND "
	    "\"LIBRARY\".\"LibraryOnline\" = 'true' AND "
	    "\"LIBRARY\".\"LibraryName\" = '%s' AND "
	    "\"LIBRARY\".\"LMName\" = '%s' AND "
	    "\"LM\".\"LMStateHard\" = 'ready' AND "
	    "\"LM\".\"LMStateSoft\" = 'present' AND "
	    "\"LM\".\"LibraryName\" = '%s' AND "
	    "\"LM\".\"LMName\" = '%s';", mm_wka->wka_conn.cci_client,
	    mm_wka->wka_conn.cci_instance, mm_wka->wka_conn.cci_client,
	    mm_wka->wka_conn.cci_instance);
	rows = PQntuples(db->mm_db_results);
	mm_clear_db(&db->mm_db_results);
	if (rc != MM_DB_DATA) {
		mms_trace(MMS_DEVP, "library state query failed");
		return (1);
	} else if (rows != 1) {
		mms_trace(MMS_DEVP, "library not ready for activate");
		return (0);
	}

	/*
	 * Build library activate enable command
	 */

	if ((cmd = mm_alloc_cmd(mm_wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		return (1);
	}

	mm_get_uuid(task);
	cmd->cmd_textcmd = mms_strnew(ACTIVATE_ENABLE, task);
	cmd->cmd_root = mm_text_to_par_node(cmd->cmd_textcmd, mms_lmpm_parse);
	cmd->cmd_task = mm_get_task(cmd->cmd_root);
	cmd->cmd_func = mm_lmp_activate_cmd_func;
	cmd->cmd_name = strdup("lmp activate enable");

	if (cmd->cmd_textcmd == NULL || cmd->cmd_root == NULL) {
		MM_ABORT_NO_MEM();
		return (1);
	}

	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, cmd);
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

	/*
	 * Activate library is inprogress.
	 */
	return (0);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);
}

/*
 * mm_library_lm_disconnect(mm_wka)
 *
 * Clear library and lm connection states.
 */
int
mm_library_lm_disconnect(mm_wka_t *mm_wka)
{

	/*
	 * Only change the library state soft and lm state soft
	 * preserving possiable 'broken' state.
	 */

	if (mm_lm_state_soft(mm_wka, "absent")) {
		return (1);
	}

	return (0);
}

/*
 * mm_lm_state_hard(mm_wka, state)
 *
 * Set lm hard state to 'ready' or 'broken'.
 */
static int
mm_lm_state_hard(mm_wka_t *mm_wka, char *state)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;

	if (mm_db_exec(HERE, db, "UPDATE \"LM\" SET "
	    "\"LMStateHard\" = '%s' WHERE \"LibraryName\" = '%s' AND "
	    "\"LMName\" = '%s';", state, mm_wka->wka_conn.cci_client,
	    mm_wka->wka_conn.cci_instance) != MM_DB_OK) {
		return (1);
	}
	return (0);
}

/*
 * mm_lm_state_soft(mm_wka, state)
 *
 * Set lm soft state to 'absent', 'present', 'not ready',
 * 'disconnected', or 'ready'.
 */
static int
mm_lm_state_soft(mm_wka_t *mm_wka, char *state)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;

	if (mm_db_exec(HERE, db, "UPDATE \"LM\" SET "
	    "\"LMStateSoft\" = '%s' WHERE \"LibraryName\" = '%s' AND "
	    "\"LMName\" = '%s';", state, mm_wka->wka_conn.cci_client,
	    mm_wka->wka_conn.cci_instance) != MM_DB_OK) {
		return (1);
	}
	return (0);
}

#ifdef	MM_LIBRARY_LM_REMOVE

static int
mm_library_lm_remove(mm_wka_t *mm_wka)
{
	mms_trace(MMS_DEVP, "library lm remove");

	/*
	 * Unrecoverable error, deactivate the client,
	 * flag the library as not in use, and
	 * remove the client
	 */
	mm_wka->wka_remove = 1;
	return (mm_lm_state_soft(mm_wka, "not ready"));
}
#endif

/* Library and lm configured, connected, and ready. */
int
mm_library_lm_cfg_conn_rdy(mm_command_t *cmd, char *library, char *lm)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;

	mms_trace(MMS_DEVP, "library lm cfg conn rdy");

	if (mm_db_exec(HERE, db, "SELECT "
	    "\"LIBRARY\".\"LibraryStateSoft\",\"LM\".\"LMStateSoft\" "
	    "FROM \"LIBRARY\",\"LM\" "
	    "WHERE (\"LIBRARY\".\"LibraryName\" = '%s' AND "
	    "\"LIBRARY\".\"LMName\" = '%s') AND "
	    "(\"LM\".\"LibraryName\" = '%s' AND "
	    "\"LM\".\"LMName\" = '%s');",
	    library, lm, library, lm) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		return (1);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_CONFIG) +
		    strlen(ELIBNOLMCONFIGURED) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR,
		    cmd->cmd_task, ECLASS_CONFIG, ELIBNOLMCONFIGURED);
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0), "ready") != 0 ||
	    strcmp(PQgetvalue(db->mm_db_results, 0, 1), "absent") == 0) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_RETRY) + strlen(ELMNOTCONNECTED) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR,
		    cmd->cmd_task, ECLASS_RETRY, ELMNOTCONNECTED);
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0), "ready") != 0 ||
	    strcmp(PQgetvalue(db->mm_db_results, 0, 1), "ready") != 0) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_RETRY) + strlen(ELMNOTREADY) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR,
		    cmd->cmd_task, ECLASS_RETRY, ELMNOTREADY);
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	mm_clear_db(&db->mm_db_results);

	return (0);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);
}

/* Find a library lm cap for import export */
char *
mm_library_lm_get_cap(mm_command_t *cmd, char *library, char *lm)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	char		*slotgroup = NULL;

	mms_trace(MMS_DEVP, "library lm get cap");

	if (mm_db_exec(HERE, db, "SELECT * FROM \"SLOTGROUP\" "
	    "WHERE \"LibraryName\" = '%s' "
	    "AND \"LMName\" = '%s' "
	    "AND \"Type\" = 'port' "
	    "AND (\"Direction\" = 'both' "
	    "OR \"Direction\" = 'in');",
	    library, lm) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		mms_trace(MMS_DEVP, "%s doesn't have a cap", library);
		SQL_CHK_LEN(&cmd->cmd_buf, 0,
		    &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) +
		    strlen(cmd->cmd_task) +
		    strlen(ECLASS_EXIST) +
		    strlen(ENOMATCH) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR,
		    cmd->cmd_task, ECLASS_EXIST, ENOMATCH);
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}

	/* default to using first cap in list */
	slotgroup = strdup(PQgetvalue(db->mm_db_results, 0, 0));
	mm_clear_db(&db->mm_db_results);
	return (slotgroup);

no_mem:
	MM_ABORT_NO_MEM();
	return (NULL);
}

/*
 * mm_lmp_activate_cmd_func(mm_wka, cmd)
 *
 * Activate enable or disable library lm.
 */
int
mm_lmp_activate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_response_t	 response;
	int		 flag = 0;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;

	int		rc2 = 0;
	PGresult	*drives = NULL;
	int		rows = 0;
	int		i = 0;

	char		*cart_pcl = NULL;
	char		*drive_name = NULL;
	char		*state_soft = NULL;
	char		*drive_online = NULL;

	char		*library_name = NULL;
	char		*lm_name = NULL;

	library_name = mm_wka->wka_conn.cci_client;
	lm_name = mm_wka->wka_conn.cci_instance;

	mms_trace(MMS_DEVP, "activate cmd func state=%d %s %s",
	    cmd->cmd_state,
	    library_name, lm_name);

	flag = (mms_pn_lookup(cmd->cmd_root, "enable",
	    MMS_PN_KEYWORD, NULL) != NULL ? 1 : 0);

	if (cmd->cmd_state == 0) {
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp activate %d accepted", flag);
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR,
			    "lmp activate %d not accepted", flag);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp activate %d success", flag);
			if (flag == 0) {
				/*
				 * Library should not get any more
				 * lmp commands
				 */
				mms_trace(MMS_DEVP, "LM disabled, "
				    "set state 'present'");
				if (mm_lm_state_soft(mm_wka, "present")) {
					mms_trace(MMS_ERR,
					    "mm_lmp_activate_cmd_func: "
					    "LM state changed failed");
				}
				/* remove and return */
				cmd->cmd_remove = 1;
				if (mm_has_depend(cmd)) {
					return (MM_DEPEND_DONE);
				}
				return (MM_CMD_DONE);

			} else {
				/*
				 * Library is ready for lmp commands
				 */
				if (mm_lm_state_soft(mm_wka, "ready")) {
					mms_trace(MMS_ERR,
					    "mm_lmp_activate_cmd_func: "
					    "LM state changed failed");
				}
			}

			/* An LMP activate enable is finishing successfully */
			/* Get list of drives for this lib/lm */
			/* mm_lmp_add_dm_enable will: */
			/* 1) Add DM enable for all ready drives */
			/* 2 )Clear drives with cartridges loaded */
			/* and setup DM enables dependent on the clear */
			rc2 = mm_db_exec(HERE, db,
			    "select distinct \"DRIVE\".\"DriveName\", "
			    "\"DRIVE\".\"CartridgePCL\", "
			    "\"DRIVE\".\"DriveStateSoft\", "
			    "\"DRIVE\".\"DriveOnline\" "
			    "from \"DRIVE\""
			    "where (\"DRIVE\".\"LibraryName\" = '%s'); ",
			    library_name);
			if (rc2 != MM_DB_DATA) {
				/* error */
				mms_trace(MMS_ERR,
				    "Error getting DRIVE information");
				return (MM_CMD_DONE);
			}
			drives = db->mm_db_results;
			rows = PQntuples(drives);
			for (i = 0; i < rows; i ++) {
				drive_name = PQgetvalue(drives, i, 0);
				cart_pcl = PQgetvalue(drives, i, 1);
				state_soft = PQgetvalue(drives, i, 2);
				drive_online = PQgetvalue(drives, i, 3);
				/* For ready and online drives */
				/* add the activate enable now */
				if (mm_lmp_add_dm_enable(drive_name, cart_pcl,
				    state_soft, drive_online, mm_wka) == NULL) {
					mms_trace(MMS_ERR,
					    "mm_lmp_activate_cmd_func: "
					    "add dm enabled failed");
				}
			}
			mm_clear_db(&drives);
			rows = 0;
			rc2 = 0;

			/* remove and return */
			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
	}

	mms_trace(MMS_ERR, "lm activate %d failed", flag);
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}


int
mm_lmp_ready_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	int		 rc = 0;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*lib_name = mm_wka->wka_conn.cci_client;
	cmd->cmd_remove = 1;

	if (mms_pn_lookup(cmd->cmd_root, "not",
	    MMS_PN_KEYWORD, NULL)) {
		/* Do state changes for 'not ready' */
		rc = mm_lm_state_soft(mm_wka, "not ready");
	} else if (mms_pn_lookup(cmd->cmd_root, "broken",
	    MMS_PN_KEYWORD, NULL)) {
		/* Do state changes for 'broken' */
		if (mm_lm_state_hard(mm_wka, "broken") ||
		    mm_lm_state_soft(mm_wka, "not ready")) {
			rc = 1;
		}
		if (rc != 1) {
			mms_trace(MMS_INFO,
			    "%s set %s to broken",
			    mm_wka->wka_conn.cci_instance,
			    lib_name);
			/* Update library state */
			if (mm_db_exec(HERE, db,
			    "update \"LIBRARY\" "
			    "set \"LibraryBroken\" = 't' "
			    "where \"LibraryName\" = '%s';",
			    lib_name) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "Error setting LIBRARY.LibraryBroken");
				rc = 1;
			}
			/* Library Down event */
			if (mm_notify_add_lmdown(mm_wka, cmd)) {
				mms_trace(MMS_ERR,
				    "mm_lmp_ready_cmd_func: "
				    "error adding lm down event");
			}
		}


	} else if (mms_pn_lookup(cmd->cmd_root, "disconnected",
	    MMS_PN_KEYWORD, NULL)) {
		/* Do state changes for 'disconnected' */
		rc = mm_lm_state_soft(mm_wka, "disconnected");
		mms_trace(MMS_INFO,
		    "%s disconnected from %s",
		    mm_wka->wka_conn.cci_instance,
		    lib_name);
		/* Library Down event */
		if (mm_notify_add_lmdown(mm_wka, cmd)) {
			mms_trace(MMS_ERR,
			    "mm_lmp_ready_cmd_func: "
			    "error adding lm down event");
		}
	} else if (mms_pn_lookup(cmd->cmd_root, "present",
	    MMS_PN_KEYWORD, NULL)) {
		/* Do state changes for 'present' */
		rc = mm_lm_state_soft(mm_wka, "present");
		mms_trace(MMS_INFO,
		    "%s, %s in present state ",
		    mm_wka->wka_conn.cci_instance,
		    lib_name);
		/* Library Down event */
		if (mm_notify_add_lmdown(mm_wka, cmd)) {
			mms_trace(MMS_ERR,
			    "mm_lmp_ready_cmd_func: "
			    "error adding lm down event");
		}
	} else {
		mms_trace(MMS_INFO, "LM ready for commands -> %s",
		    mm_wka->wka_conn.cci_instance);
		rc = mm_lm_state_soft(mm_wka, "ready");
		/* Library Ready event */
		if (mm_notify_add_lmup(mm_wka, cmd)) {
			mms_trace(MMS_ERR,
			    "mm_lmp_ready_cmd_func: "
			    "error adding lm up event");
		}
	}

	if (rc) {
		mms_trace(MMS_DEVP, "lm state soft change failed");
		mm_sql_db_err_rsp_new(cmd, db);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_SUCCESS, cmd->cmd_task);

	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);

	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}

mm_command_t *
mm_lmp_add_dm_enable(char *drive_name, char *cart_pcl,
    char *state_soft, char *drive_online, mm_wka_t *mm_wka) {


	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	int		i = 0;
	int		num_dm = 0;
	PGresult	*dm_results = NULL;
	char		*cur_dm_name = NULL;
	char		*cur_dm_state = NULL;
	mm_wka_t	*cur_wka = NULL;
	mm_data_t	*data = mm_wka->mm_data;
	mm_command_t	*dm_enable = NULL;
	mm_command_t	*clear_cmd = NULL;

	int		request_oper = 0;
	int		auto_clear = 0;

	mms_trace(MMS_DEVP, "mm_lmp_add_dm_enable");

	if (drive_name == NULL ||
	    cart_pcl == NULL ||
	    state_soft == NULL ||
	    drive_online == NULL ||
	    mm_wka == NULL) {
		mms_trace(MMS_ERR,
		    "mm_lmp_add_dm_enable passed a NULL arg, "
		    "cannot enable DM");
		return (NULL);
	}



	mms_trace(MMS_DEVP, "drive name, %s",
	    drive_name);
	mms_trace(MMS_DEVP, "cart pcl, %s",
	    cart_pcl);
	mms_trace(MMS_DEVP, "state soft, %s",
	    state_soft);
	mms_trace(MMS_DEVP, "drive online, %s",
	    drive_online);

	/* Determine if this drive needs a clear */
	/* if so set up the clear */
	if (mm_system_settings(db,
	    &request_oper, &auto_clear)) {
		mms_trace(MMS_ERR,
		    "mm_lmp_add_dm_enable: "
		    "db error getting system settings");
		request_oper = 0;
		auto_clear = 1;
	}


	if ((strcmp(cart_pcl, MM_NON_MMS_CART) == 0) &&
	    (auto_clear)) {
		clear_cmd = mm_add_clear_drive(drive_name,
		    mm_wka->mm_data,
		    db, NULL,
		    MM_NON_MMS_CART, 1, 0);
		if (clear_cmd == NULL) {
			mms_trace(MMS_ERR,
			    "mm_lmp_add_dm_enable : error "
			    "adding clear drive"
			    "for non-mms cart");
		} else {
			mms_trace(MMS_DEVP,
			    "added clear for non-mms tape, %s",
			    drive_name);
		}

		/* If this drive is 'in use' do not add a clear */
		/* This function is only called as part on an lmp enable */
		/* If state is 'in use' this MUST be an LM that has */
		/* Restarted while a client has a tape mounted */

	} else if ((strcmp(cart_pcl, "") != 0) &&
	    (strcmp(state_soft, "in use") != 0)) {
		/* This cart_pcl is not empty */
		/*
		 * Check for MOUNTPHYSICAL
		 * only add a clear drive func
		 * for drives W/O a MOUNTPHYSICAL
		 */
		mms_trace(MMS_INFO, "Adding clear drive "	\
		    "func for %s",
		    drive_name);
		clear_cmd = mm_add_clear_drive(drive_name,
		    mm_wka->mm_data, db,
		    NULL, NULL, 0, 0);
		if (clear_cmd == NULL) {
			mms_trace(MMS_ERR,
			    "mm_lmp_add_dm_enable : error "
			    "adding clear drive"
			    "for %s %s",
			    drive_name,
			    cart_pcl);
		} else {
			mms_trace(MMS_DEVP,
			    "added clear for %s %s",
			    drive_name, cart_pcl);
		}
	}

	/* Check the DM's */
	if (mm_db_exec(HERE, db,
	    "select distinct \"DM\".\"DMName\","
	    "\"DM\".\"DMStateSoft\" from \"DM\""
	    "cross join \"DRIVE\" where"
		"((\"DM\".\"DriveName\" = \"DRIVE\".\"DriveName\")"
		" and((\"DRIVE\".\"DriveName\" = '%s') AND"
		"(\"DRIVE\".\"DriveOnline\" = 'true')));",
		drive_name) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "error getting DM names for drive, %s",
		    drive_name);
		return (NULL);
	}
	dm_results = db->mm_db_results;
	num_dm = PQntuples(dm_results);
	mms_trace(MMS_DEVP,
	    "trying to activate %d dm's for drive %s",
	    num_dm, drive_name);
	/* call mm_drive_dm_activate_enable(mm_wka_t *mm_wka) */
	/* on the wka of each dm whose name is in PQresults */
	for (i = 0; i < num_dm; i++) {
		cur_dm_name = PQgetvalue(dm_results, i, 0);
		cur_dm_state = PQgetvalue(dm_results, i, 1);
		cur_wka = NULL;

		/* check DM state soft */
		/* if state soft is ready, or reserved */
		/* Dont attempt to enable */

		if ((strcmp(cur_dm_state, "ready") == 0) ||
		    (strcmp(cur_dm_state, "reserved") == 0)) {
			mms_trace(MMS_DEVP,
			    "DM, %s, StateSoft == %s, "
			    "skip enable",
			    cur_dm_name,
			    cur_dm_state);
			continue;
		}
		mms_list_foreach(&data->mm_wka_list, cur_wka) {
			if (strcmp(cur_wka->wka_conn.cci_instance,
				cur_dm_name) == 0) {
				/* to wka found */
				break;
			}
		}

		if (cur_wka == NULL) {
			mms_trace(MMS_DEVP,
			    "didn't find a wka for %s",
			    cur_dm_name);
		} else {
			if (clear_cmd == NULL) {
				dm_enable =
				    mm_drive_dm_activate_enable(cur_wka);
			} else {
				mms_trace(MMS_DEVP,
				    "alloc dm enable, run enable "
				    "before clear drive");
				/* Have the dm enable run */
				/* before the clear drive */
				dm_enable =
				    mm_alloc_dm_enable(cur_wka);
				if (dm_enable != NULL) {
					mm_add_depend(dm_enable,
					    clear_cmd);
					MM_UNSET_FLAG(clear_cmd->cmd_flags,
					    MM_CMD_DISPATCHABLE);
					MM_SET_FLAG(dm_enable->cmd_flags,
					    MM_CMD_DISPATCHABLE);
				}
			}
		}
	}
	mm_clear_db(&dm_results);
	return (dm_enable);


}


void
mm_update_cart_loaded(mm_wka_t *mm_wka, char *cart_id)
{
	mm_data_t		*mm_data = mm_wka->mm_data;
	mm_command_t		*cur_cmd = NULL;
	cmd_mount_info_t	*mount_info = NULL;
	cmi_cart_list_t		*cart = NULL;
	char			*cur_cartid = NULL;

	mms_trace(MMS_DEVP,
	    "mm_update_cart_loaded: ");

	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		mount_info = &cur_cmd->cmd_mount_info;
		if (cur_cmd->cmd_func ==
		    mm_mount_cmd_func) {
			mms_list_foreach(&mount_info->cmi_cart_list, cart) {
				cur_cartid = cart->cmi_cart_id;
				if ((cart->cmi_cart_loaded == 1) &&
				    (strcmp(cart_id, cur_cartid) == 0)) {
					/* same cart */
					cart->cmi_cart_loaded = 0;
					cart->cmi_cart_not_ready = 0;
					mms_trace(MMS_DEVP,
					    "mm_update_cart_loaded: "
					    "set cart unloaded and ready");
				}
			}
		}
	}
	pthread_mutex_unlock(&mm_data->mm_queue_mutex);

}

void
mm_lmp_set_clear_pcl(mm_wka_t *mm_wka, char *drive_name, char *drive_cart_pcl) {
	mm_data_t *mm_data = mm_wka->mm_data;
	/* If there is a clear drive for this drive */
	mm_command_t *cur_cmd = NULL;
	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if ((cur_cmd->cmd_func ==
		    mm_clear_drive_cmd_func) &&
		    (cur_cmd->cmd_state == 1) &&
		    (strcmp(cur_cmd->cmd_mount_info.cmi_drive,
		    drive_name) == 0)) {
			mms_trace(MMS_DEVP,
			    "set pcl, %s, in clear drive "
			    "for this non-mms tape",
			    drive_cart_pcl);
			mm_set_mount_info_pcl(drive_cart_pcl,
			    &cur_cmd->cmd_mount_info);
		}
	}
	pthread_mutex_unlock(&mm_data->mm_queue_mutex);
}

/*
 * mm_lmp_config_cmd_func(mm_wka, cmd)
 *
 * Process lmp config partial and full commands.
 */
int
mm_lmp_config_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg = NULL;
	mms_par_node_t	*value = NULL;
	mm_lmp_scope_t	 scope;
	mms_par_node_t	*work = NULL;
	mms_par_node_t	*item = NULL;
	mms_par_node_t	*slot = NULL;
	char		*slot_name = NULL;
	char		*slot_bay_name = NULL;
	char		*slotgroup_name = NULL;
	char		*slot_cart_id = NULL;
	char		*slot_cart_id_status = NULL;
	char		*slot_cart_pcl = NULL;
	char		*slot_type = NULL;
	char		*slot_occupied = NULL;
	char		*slot_accessible = NULL;
	mms_par_node_t	*bay = NULL;
	char		*bay_name = NULL;
	char		*bay_accessible = NULL;
	mms_par_node_t	*drive = NULL;
	char		*drive_name = NULL;
	char		*drive_bay_name = NULL;
	char		*drive_cart_pcl = NULL;
	char		*drive_occupied = NULL;
	char		*drive_accessible = NULL;
	PGresult	*results = NULL;
	PGresult	*drive_state_results = NULL;
	mms_par_node_t	*freeslots = NULL;
	char		*freeslots_bay_name = NULL;
	char		*freeslots_slot_type = NULL;
	int		 freeslots_num_slots = NULL;
	mms_par_node_t	*delslots = NULL;
	char		*delslots_slot_name = NULL;
	mms_par_node_t	*slotgrp = NULL;
	char		*slotgrp_name = NULL;
	char		*slotgrp_bay_name = NULL;
	char		*slotgrp_direction = NULL;
	char		*slotgrp_type = NULL;
	mms_par_node_t	*perf = NULL;
	int		 perfno = 0;
	char		*drive_serial_num = NULL;
	char		*drive_geometry = NULL;
	int		 rc = 0;
	int		 row = 0;
	int		 rows = 0;
	int		 found = 0;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	int		 do_update_drive = 0;


	int		has_serial = 1;
	int		has_geometry = 1;
	int		has_cart_pcl = 0;
	int		update_cart_state = 0;

	mms_trace(MMS_DEBUG, "lmp config cmd");

	/*
	 * Partial or full config
	 */
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "scope", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_KEYWORD, NULL);
	if (strcmp(value->pn_string, "full") == 0) {
		scope = SCOPE_FULL;
		mms_trace(MMS_DEBUG, "scope: full");
	} else if (strcmp(value->pn_string, "partial") == 0) {
		scope = SCOPE_PARTIAL;
		mms_trace(MMS_DEBUG, "scope: partial");
	}

	/*
	 * Full config delete. The difference between full and partial
	 * scope is a full scope deletes the config. A full scope does
	 * not check for all attributes being present in the command.
	 */
	if (scope == SCOPE_FULL) {
		if (mm_db_exec(HERE, db, "DELETE FROM \"SLOT\" WHERE "
		    "\"LibraryName\" = '%s' AND \"LMName\" = '%s';",
		    conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_db_exec(HERE, db, "DELETE FROM \"SLOTCONFIG\" WHERE "
		    "\"LibraryName\" = '%s' AND \"LMName\" = '%s';",
		    conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_db_exec(HERE, db, "DELETE FROM \"SLOTGROUP\" WHERE "
		    "\"LibraryName\" = '%s' AND \"LMName\" = '%s';",
		    conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_db_exec(HERE, db, "UPDATE \"DRIVE\" SET "
		    "\"BayName\" = NULL, "
		    "\"DriveLibraryAccessible\" = 'false', "
		    "\"DriveLibraryOccupied\" = 'false', "
		    "\"CartridgePCL\" = NULL WHERE "
		    "\"LibraryName\" = '%s';",
		    conn->cci_client) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_db_exec(HERE, db, "DELETE FROM \"BAY\" WHERE "
		    "\"LibraryName\" = '%s' AND \"LMName\" = '%s';",
		    conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}

	/*
	 * Library config
	 */

	mms_trace(MMS_DEBUG, "bay");
	work = NULL;
	for (bay = mms_pn_lookup(cmd->cmd_root, "bay",
	    MMS_PN_CLAUSE, &work);
	    bay != NULL;
	    bay = mms_pn_lookup(cmd->cmd_root, "bay",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		MMS_PN_LOOKUP(value, bay, NULL, MMS_PN_STRING, &item);
		bay_name = value->pn_string;

		MMS_PN_LOOKUP(value, bay, NULL, MMS_PN_KEYWORD, &item);
		bay_accessible = value->pn_string;

		mms_trace(MMS_DEBUG, "bay: %s, %s", bay_name, bay_accessible);

		/* partial config */
		if (scope == SCOPE_PARTIAL &&
		    mm_db_exec(HERE, db, "SELECT \"BayAccessible\" FROM "
		    "\"BAY\" WHERE \"BayName\" = '%s' AND "
		    "\"LibraryName\" = '%s' AND \"LMName\" = '%s';",
		    bay_name, conn->cci_client,
		    conn->cci_instance) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (scope == SCOPE_PARTIAL) {
			rows = PQntuples(db->mm_db_results);
			mm_clear_db(&db->mm_db_results);
		} else {
			rows = 0;
		}

		/* update bay */
		if (rows == 0 && mm_db_exec(HERE, db, "INSERT INTO \"BAY\" "
		    "(\"BayName\", \"LibraryName\", "\
		    "\"LMName\", "
		    "\"BayAccessible\") "\
		    "VALUES ('%s', '%s', '%s', '%s');",
		    bay_name, conn->cci_client,
		    conn->cci_instance,
		    bay_accessible) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		} else if (mm_db_exec(HERE, db, "UPDATE \"BAY\" SET "
		    "\"BayAccessible\" = '%s' "\
		    "WHERE \"BayName\" = '%s' AND "
		    "\"LibraryName\" = '%s' AND "\
		    "\"LMName\" = '%s';",
		    bay_accessible, bay_name,
		    conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}

	mms_trace(MMS_DEBUG, "slotgroup");
	work = NULL;
	for (slotgrp = mms_pn_lookup(cmd->cmd_root, "slotgroup",
	    MMS_PN_CLAUSE, &work);
	    slotgrp != NULL;
	    slotgrp = mms_pn_lookup(cmd->cmd_root, "slotgroup",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		MMS_PN_LOOKUP(value, slotgrp, NULL, MMS_PN_STRING, &item);
		slotgrp_name = value->pn_string;

		MMS_PN_LOOKUP(value, slotgrp, NULL, MMS_PN_STRING, &item);
		slotgrp_bay_name = value->pn_string;

		MMS_PN_LOOKUP(value, slotgrp, NULL, MMS_PN_KEYWORD, &item);
		slotgrp_direction = value->pn_string;

		MMS_PN_LOOKUP(value, slotgrp, NULL, MMS_PN_STRING, &item);
		slotgrp_type = value->pn_string;

		mms_trace(MMS_DEBUG, "slotgroup: %s, %s, %s, %s",
		    slotgrp_name, slotgrp_bay_name, slotgrp_direction,
		    slotgrp_type);

		/* partial config */
		if (scope == SCOPE_PARTIAL &&
		    mm_db_exec(HERE, db, "SELECT \"SlotGroupName\" "
		    "FROM \"SLOTGROUP\" "\
		    "WHERE \"BayName\" = '%s' AND "
		    "\"LibraryName\" = '%s' AND \"LMName\" = '%s';",
		    slotgrp_bay_name, conn->cci_client,
		    conn->cci_instance) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (scope == SCOPE_PARTIAL) {
			rows = PQntuples(db->mm_db_results);
			mm_clear_db(&db->mm_db_results);
		} else {
			rows = 0;
		}

		/* full or partial config */
		if (rows == 0 && mm_db_exec(HERE, db,
		    "INSERT INTO \"SLOTGROUP\" "
		    "(\"SlotGroupName\", \"BayName\", "
		    "\"Direction\", "
		    "\"Type\", \"LibraryName\", "
		    "\"LMName\") VALUES "
		    "('%s', '%s', '%s', '%s', "
		    "'%s', '%s');",
		    slotgrp_name,
		    slotgrp_bay_name, slotgrp_direction,
		    slotgrp_type, conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		} else if (mm_db_exec(HERE, db, "UPDATE \"SLOTGROUP\" SET "
		    "\"Direction\" = '%s', "\
		    "\"Type\" = '%s' WHERE "
		    "\"SlotGroupName\" = '%s' AND "\
		    "\"BayName\" = '%s' AND "
		    "\"LibraryName\" = '%s' AND "\
		    "\"LMName\" = '%s';",
		    slotgrp_direction,
		    slotgrp_type,
		    slotgrp_name,
		    slotgrp_bay_name, conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}

	mms_trace(MMS_DEBUG, "slot");
	work = NULL;
	for (slot = mms_pn_lookup(cmd->cmd_root, "slot",
	    MMS_PN_CLAUSE, &work);
	    slot != NULL;
	    slot = mms_pn_lookup(cmd->cmd_root, "slot",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		MMS_PN_LOOKUP(value, slot, NULL, MMS_PN_STRING, &item);
		slot_name = value->pn_string;

		MMS_PN_LOOKUP(value, slot, NULL, MMS_PN_STRING, &item);
		slot_bay_name = value->pn_string;

		MMS_PN_LOOKUP(value, slot, NULL, MMS_PN_STRING, &item);
		slotgroup_name = value->pn_string;

		MMS_PN_LOOKUP(value, slot, NULL, MMS_PN_STRING, &item);
		slot_cart_pcl = value->pn_string;

		MMS_PN_LOOKUP(value, slot, NULL, MMS_PN_STRING, &item);
		slot_type = value->pn_string;

		MMS_PN_LOOKUP(value, slot, NULL, MMS_PN_KEYWORD, &item);
		slot_occupied = value->pn_string;

		MMS_PN_LOOKUP(value, slot, NULL, MMS_PN_KEYWORD, &item);
		slot_accessible = value->pn_string;

		mms_trace(MMS_DEBUG, "slot: %s, %s, %s, %s, %s, %s, %s",
		    slot_name, slot_bay_name, slotgroup_name,
		    slot_cart_pcl, slot_type, slot_occupied,
		    slot_accessible);

		/* verify mms object depends on */
		if (mm_db_exec(HERE, db, "SELECT \"SlotTypeName\", "
		    "\"CartridgeShapeName\" FROM "
		    "\"SLOTTYPE\" WHERE \"SlotTypeName\" = '%s';",
		    slot_type) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		rows = PQntuples(db->mm_db_results);
		for (row = 0, found = 0; row < rows; row++) {
			if (strcmp(slot_type,
			    PQgetvalue(db->mm_db_results, 0, 0)) == 0) {
				found = 1;
				break;
			}
		}
		mm_clear_db(&db->mm_db_results);
		if (found == 0) {
			mms_trace(MMS_ERR,
			    "no slot type found");
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(ECLASS_LANGUAGE) +
			    strlen(cmd->cmd_task) +
			    strlen(ESYNTAX) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR,
			    cmd->cmd_task,
			    ECLASS_LANGUAGE, ESYNTAX);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		/* get cartridge id by cartridge pcl */
		if (mm_db_exec(HERE, db, "SELECT \"CartridgeID\","
		    "\"CartridgeStatus\" FROM "
		    "\"CARTRIDGE\" WHERE "\
		    "\"CartridgePCL\" = '%s' AND "
		    "\"LibraryName\" = '%s';", slot_cart_pcl,
		    conn->cci_client) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if ((rows = PQntuples(db->mm_db_results)) != 1) {
			results = NULL;
			slot_cart_id = NULL;
			mm_clear_db(&db->mm_db_results);
		} else {
			results = db->mm_db_results;
			slot_cart_id = PQgetvalue(results, 0, 0);
			slot_cart_id_status = PQgetvalue(results, 0, 1);
		}

		/* partial config find slot */
		if (scope == SCOPE_PARTIAL &&
		    mm_db_exec(HERE, db, "SELECT \"SlotTypeName\" FROM "
		    "\"SLOT\" WHERE \"SlotName\" = '%s' AND "
		    "\"LibraryName\" = '%s' AND "
		    "\"LMName\" = '%s';",
		    slot_name, conn->cci_client,
		    conn->cci_instance) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (scope == SCOPE_PARTIAL) {
			rows = PQntuples(db->mm_db_results);
			mm_clear_db(&db->mm_db_results);
		} else {
			rows = 0;
		}

		if (slot_cart_id) {
			/* Cartridge is not in a drive */
			if (strcmp(slot_cart_id_status, "unavailable") == 0) {
				/* This cartridge has not */
				/* had a config done yet */
				if (mm_db_exec(HERE, db,
				    "update \"CARTRIDGE\" "
				    "set \"CartridgeStatus\" "
				    "= 'available' where "
				    "\"CartridgeID\" = '%s';",
				    slot_cart_id) !=
				    MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					mm_clear_db(&results);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					return (MM_CMD_ERROR);
				}
			}
			if (mm_db_exec(HERE, db,
			    "update \"CARTRIDGE\" "
			    "set \"CartridgeDriveOccupied\" "
			    "= 'false' where "
			    "\"CartridgeID\" = '%s';",
			    slot_cart_id) !=
			    MM_DB_OK) {
				mm_sql_db_err_rsp_new(cmd, db);
				mm_clear_db(&results);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			/* If this cartridge is a candidate for a mount */
			/* must update cart->cmi_cart_loaded */
			/* since this cart is no longer loaded */
			mm_update_cart_loaded(mm_wka, slot_cart_id);


		}

		if (slot_cart_id && rows == 0 &&
		    mm_db_exec(HERE, db, "INSERT INTO \"SLOT\" "
		    "(\"SlotName\", \"LibraryName\", \"LMName\", "
		    "\"BayName\", \"SlotGroupName\", "
		    "\"SlotTypeName\", "
		    "\"CartridgeID\", \"CartridgePCL\", "
		    "\"SlotAccessable\", "
		    "\"SlotOccupied\") VALUES "
		    "('%s', '%s', '%s', '%s', '%s', "
		    "'%s', '%s', '%s', '%s', '%s');", slot_name,
		    conn->cci_client,
		    conn->cci_instance,
		    slot_bay_name, slotgroup_name, slot_type,
		    slot_cart_id, slot_cart_pcl,
		    slot_accessible, slot_occupied) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		} else if (slot_cart_id &&
		    mm_db_exec(HERE, db, "UPDATE \"SLOT\" "
		    "SET \"SlotTypeName\" = '%s', "
		    "\"CartridgeID\" = '%s', "
		    "\"CartridgePCL\" = '%s', "
		    "\"SlotAccessable\" = '%s', "
		    "\"SlotOccupied\" = '%s', "
		    "\"BayName\" = '%s', "
		    "\"SlotGroupName\" = '%s' WHERE "
		    "\"SlotName\" = '%s' AND "
		    "\"LibraryName\" = '%s' AND "
		    "\"LMName\" = '%s';",
		    slot_type, slot_cart_id,
		    slot_cart_pcl, slot_accessible,
		    slot_occupied, slot_bay_name,
		    slotgroup_name, slot_name,
		    conn->cci_client,
		    conn->cci_instance) !=
		    MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (results) {
			mm_clear_db(&results);
		}
	}

	mms_trace(MMS_DEBUG, "drive");
	work = NULL;
	for (drive = mms_pn_lookup(cmd->cmd_root, "drive",
	    MMS_PN_CLAUSE, &work);
	    drive != NULL;
	    drive = mms_pn_lookup(cmd->cmd_root, "drive",
	    MMS_PN_CLAUSE, &work)) {

		has_serial = 1;
		has_geometry = 1;
		has_cart_pcl = 0;
		update_cart_state = 0;

		item = NULL;
		MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, &item);
		drive_serial_num =
		    value->pn_string; /* drive serial number */

		MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, &item);
		drive_geometry =
		    value->pn_string; /* drive geometry */

		MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, &item);
		drive_bay_name = value->pn_string;

		MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_STRING, &item);
		drive_cart_pcl = value->pn_string;

		MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_KEYWORD, &item);
		drive_occupied = value->pn_string;

		MMS_PN_LOOKUP(value, drive, NULL, MMS_PN_KEYWORD, &item);
		drive_accessible = value->pn_string;

		if (strcmp(drive_serial_num, "") == 0) {
			has_serial = 0;
		}
		if (strcmp(drive_geometry, "") == 0) {
			has_geometry = 0;
		}
		if (!has_serial && !has_geometry) {
			mms_trace(MMS_ERR,
			    "drive spec missing serialnumber/geometry");
			continue;
		}
		if (has_serial) {
			if (has_geometry) {
				mms_trace(MMS_DEBUG,
				    "drive: %s, %s, %s, %s, %s, %s",
				    drive_serial_num, drive_geometry,
				    drive_bay_name,
				    drive_cart_pcl, drive_occupied,
				    drive_accessible);
			} else {
				mms_trace(MMS_DEBUG,
				    "drive: %s, %s, %s, %s, %s",
				    drive_serial_num,
				    drive_bay_name, drive_cart_pcl,
				    drive_occupied,
				    drive_accessible);
			}
		} else {
			mms_trace(MMS_DEBUG, "drive: %s, %s, %s, %s, %s",
			    drive_geometry,
			    drive_bay_name, drive_cart_pcl,
			    drive_occupied,
			    drive_accessible);
		}



		/* determine if drive is configured */
		if (has_serial) {
			rc =  mm_db_exec(HERE, db, "SELECT \"DriveName\","
			    "\"DriveStateSoft\" FROM "
			    "\"DRIVE\" WHERE \"DriveSerialNum\" = '%s';",
			    drive_serial_num);
		} else {
			rc = mm_db_exec(HERE, db, "SELECT \"DriveName\","
			    "\"DriveStateSoft\" FROM "
			    "\"DRIVE\" WHERE \"DriveGeometry\" = '%s';",
			    drive_geometry);
		}
		if (rc != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		drive_state_results = db->mm_db_results;
		if ((do_update_drive = PQntuples(drive_state_results)) == 1) {
			/* get mm drive name from db */
			drive_name = PQgetvalue(drive_state_results, 0, 0);

			/* set geometry for this drive */
			if (has_geometry &&
			    has_serial &&
			    (mm_db_exec(HERE, db,
			    "update \"DRIVE\" set \"DriveGeometry\" = '%s' "
			    "where \"DriveSerialNum\" = '%s';",
			    drive_geometry, drive_serial_num) != MM_DB_OK)) {
				mm_sql_db_err_rsp_new(cmd, db);
				mms_trace(MMS_ERR,
				    "error setting drive geometry");
			}
		} else {
			/* drive not configured */
			drive_name = NULL;
			do_update_drive = 0;
		}

		if (strcmp(drive_occupied, "true") == 0 &&
		    strcmp(drive_cart_pcl, "none") != 0) {
			has_cart_pcl = 1;
		}


		/* update drive states and location */
		if ((do_update_drive) &&
		    has_cart_pcl) {
			if (mm_db_exec(HERE, db,
			    "select \"CartridgePCL\", "
			    "\"CartridgeStatus\" "
			    "from \"CARTRIDGE\" where "
			    "\"CartridgePCL\" = '%s' "
			    "and \"LibraryName\" = '%s';",
			    drive_cart_pcl,
			    conn->cci_client) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				mm_clear_db(&drive_state_results);
				return (MM_CMD_ERROR);
			} else {
				if (PQntuples(db->mm_db_results) != 1) {

					/* PCL does not exists to MMS */
					mms_trace(MMS_ERR,
					    "Cartridge %s does not "
					    "belong to MMS",
					    drive_cart_pcl);
					do_update_drive = 0;
					mm_clear_db(&db->mm_db_results);
					if (mm_db_exec(HERE, db,
					    "UPDATE \"DRIVE\" SET "
					    "\"DriveLibrary"
					    "Accessible\" "
					    "= '%s', "
					    "\"DriveLibraryOccupied\" "
					    "= '%s', "
					    "\"BayName\" = '%s', "
					    "\"CartridgePCL\" "
					    "= '%s' "
					    "WHERE "
					    "\"DRIVE\".\"LibraryName\" "
					    "= '%s' AND "
					    "\"DRIVE\".\"DriveName\" "
					    "= '%s' ;",
					    drive_accessible,
					    drive_occupied,
					    drive_bay_name,
					    MM_NON_MMS_CART,
					    conn->cci_client,
					    drive_name) != MM_DB_OK) {
						mm_sql_db_err_rsp_new(cmd,
						    db);
						cmd->cmd_remove = 1;
						mm_send_text(mm_wka->
						    mm_wka_conn,
						    cmd->cmd_buf);
						mm_clear_db(
						    &drive_state_results);
						return (MM_CMD_ERROR);
					}
					mm_lmp_set_clear_pcl(mm_wka, drive_name,
					    drive_cart_pcl);

				} else {
					mm_clear_db(&db->mm_db_results);
				}
			}
		}


		if (do_update_drive) {
			/* PCL exists to MMS */

			if (strcmp(drive_cart_pcl, "none") != 0) {
				if (mm_db_exec(HERE, db, "UPDATE \"DRIVE\" SET "
				    "\"DriveLibraryAccessible\" = '%s', "
				    "\"DriveLibraryOccupied\" = '%s', "
				    "\"BayName\" = '%s', "
				    "\"CartridgePCL\" = '%s' WHERE "
				    "\"DRIVE\".\"LibraryName\" = '%s' AND "
				    "\"DRIVE\".\"DriveName\" = '%s' ;",
				    drive_accessible, drive_occupied,
				    drive_bay_name, drive_cart_pcl,
				    conn->cci_client,
				    drive_name) != MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&drive_state_results);
					return (MM_CMD_ERROR);
				}
			} else {
				if (mm_db_exec(HERE, db, "UPDATE \"DRIVE\" SET "
				    "\"DriveLibraryAccessible\" = '%s', "
				    "\"DriveLibraryOccupied\" = '%s', "
				    "\"BayName\" = '%s', "
				    "\"DriveStateHard\" = 'unloaded', "
				    "\"CartridgePCL\" = NULL WHERE "
				    "\"DRIVE\".\"LibraryName\" = '%s' AND "
				    "\"DRIVE\".\"DriveName\" = '%s' ;",
				    drive_accessible, drive_occupied,
				    drive_bay_name,
				    conn->cci_client,
				    drive_name) != MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&drive_state_results);
					return (MM_CMD_ERROR);
				}
			}
			if (strcmp(drive_cart_pcl, "none") != 0) {
				if (mm_db_exec(HERE, db,
				    "update \"CARTRIDGE\" set "
				    "\"CartridgeDriveOccupied\" = 'true' "
				    "where \"CartridgePCL\" = "
				    "'%s' and \"LibraryName\" = '%s';",
				    drive_cart_pcl,
				    conn->cci_client) != MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&drive_state_results);
					return (MM_CMD_ERROR);
				}
			} else if (strcmp(PQgetvalue(drive_state_results, 0, 1),
			    "unavailable") == 0) {
				/* this drive does not have a cart loaded */
				/* if this drive state is not 'unavailable' */
				/* set the state to 'ready' */
				if (mm_db_exec(HERE, db,
				    "update \"DRIVE\" set "
				    "\"DriveStateSoft\" = 'ready' "
				    "where \"DriveName\" = "
				    "'%s';",
				    drive_name) != MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&drive_state_results);
					return (MM_CMD_ERROR);
				}


			}
			if (update_cart_state) {
				/* This cartridge does not have a */
				/* SLOT object yet */
				if (mm_db_exec(HERE, db,
				    "update \"CARTRIDGE\" set "
				    "\"CartridgeStatus\" = 'available' "
				    "where \"CartridgePCL\" = "
				    "'%s' and \"LibraryName\" = '%s';",
				    drive_cart_pcl,
				    conn->cci_client) != MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&drive_state_results);
					return (MM_CMD_ERROR);
				}
			}

		}
		mm_clear_db(&drive_state_results);
	}

	mms_trace(MMS_DEBUG, "%s", "freeslots");
	work = NULL;
	for (freeslots = mms_pn_lookup(cmd->cmd_root, "freeslots",
	    MMS_PN_CLAUSE, &work);
	    freeslots != NULL;
	    freeslots = mms_pn_lookup(cmd->cmd_root, "freeslots",
	    MMS_PN_CLAUSE, &work)) {
		mms_trace(MMS_DEBUG, "%s", "freeslots bay name");
		item = NULL;
		MMS_PN_LOOKUP(value, freeslots, NULL, MMS_PN_STRING, &item);
		freeslots_bay_name = value->pn_string;

		mms_trace(MMS_DEBUG, "freeslots slot type");
		MMS_PN_LOOKUP(value, freeslots, NULL, MMS_PN_STRING, &item);
		freeslots_slot_type = value->pn_string;

		mms_trace(MMS_DEBUG, "freeslots num slots");
		MMS_PN_LOOKUP(value, freeslots, NULL, MMS_PN_STRING, &item);
		freeslots_num_slots = atoi(value->pn_string);

		mms_trace(MMS_DEBUG,
		    "freeslots: %s, %s, %d", freeslots_bay_name,
		    freeslots_slot_type, freeslots_num_slots);

		if (scope == SCOPE_PARTIAL &&
		    mm_db_exec(HERE, db, "SELECT \"SlotConfigNumberFree\" FROM "
		    "\"SLOTCONFIG\" WHERE "\
		    "\"LibraryName\" = '%s' AND "
		    "\"LMName\" = '%s' AND \"BayName\" = '%s' AND "
		    "\"SlotTypeName\" = '%s';") != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (scope == SCOPE_PARTIAL) {
			rows = PQntuples(db->mm_db_results);
			mm_clear_db(&db->mm_db_results);
		} else {
			rows = 0;
		}

		if (rows == 0 && mm_db_exec(HERE, db,
		    "INSERT INTO \"SLOTCONFIG\" "
		    "(\"LibraryName\", \"LMName\", "
		    "\"BayName\", "
		    "\"SlotTypeName\", "
		    "\"SlotConfigNumberFree\") VALUES "
		    "('%s', '%s', '%s', '%s', '%d');",
		    conn->cci_client,
		    conn->cci_instance,
		    freeslots_bay_name,
		    freeslots_slot_type,
		    freeslots_num_slots) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		} else if (mm_db_exec(HERE, db, "UPDATE \"SLOTCONFIG\" SET "
		    "\"SlotConfigNumberFree\" = '%d' WHERE "
		    "\"LibraryName\" = '%s' AND "\
		    "\"LMName\" = '%s' AND "
		    "\"BayName\" = '%s' AND "\
		    "\"SlotTypeName\" = '%s';",
		    freeslots_num_slots, conn->cci_client,
		    conn->cci_instance, freeslots_bay_name,
		    freeslots_slot_type) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}

	mms_trace(MMS_DEBUG, "delslots");
	work = NULL;
	for (delslots = mms_pn_lookup(cmd->cmd_root, "delslots",
	    MMS_PN_CLAUSE, &work);
	    delslots != NULL;
	    delslots = mms_pn_lookup(cmd->cmd_root, "delslots",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		MMS_PN_LOOKUP(value, delslots, NULL, MMS_PN_STRING, &item);
		delslots_slot_name = value->pn_string;

		mms_trace(MMS_DEBUG, "delslots: %s", delslots_slot_name);

		if (mm_db_exec(HERE, db, "DELETE FROM \"SLOT\" WHERE "
		    "\"SlotName\" = '%s' AND "\
		    "\"LibraryName\" = '%s' AND "
		    "\"LMName\" = '%s';", delslots_slot_name,
		    conn->cci_client,
		    conn->cci_instance) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}

	mms_trace(MMS_DEBUG, "perf");
	work = NULL;
	for (perf = mms_pn_lookup(cmd->cmd_root, "perf",
	    MMS_PN_CLAUSE, &work);
	    perf != NULL;
	    perf = mms_pn_lookup(cmd->cmd_root, "perf",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		MMS_PN_LOOKUP(value, perf, NULL, MMS_PN_STRING, &item);
		perfno = atoi(value->pn_string);

		mms_trace(MMS_DEBUG, "perf: %d", perfno);
	}

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_SUCCESS, cmd->cmd_task);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);

}

/*
 * mm_lmp_private_cmd_func(mm_wka, cmd)
 *
 * Send private command to set, unset, or get lm attribute values.
 */
int
mm_lmp_private_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_response_t	 response;


	mms_trace(MMS_DEVP, "lmp private cmd func: state=%d",
	    cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp private accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp private success");
			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp private failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

/*
 * mm_lmp_mount_cmd_func(mm_wka, cmd)
 *
 * Mount a cartridge on a drive.
 */
int
mm_lmp_mount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	int			rc = 0;
	mm_response_t		response;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	char			*cart_pcl = NULL;

	mms_trace(MMS_DEVP, "lmp mount cmd func: state=%d",
	    cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		/* Check LM state before sending */
		mms_trace(MMS_DEVP,
		    "check lm state before sending");
		rc =  mm_lm_send_ok(cmd, mm_wka);
		if (rc == MM_LM_ERROR) {
			mms_trace(MMS_DEVP, "Cannot send this lmp command");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		} else if (rc == MM_LM_WAIT) {
			mms_trace(MMS_DEVP,
			    "wait to send the lmp command ");
			MM_SET_FLAG(cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
			return (MM_NO_DISPATCH);
		} else if (rc == MM_LM_SEND) {
			mms_trace(MMS_DEVP,
			    "lm send the lmp command");
		}


		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp mount accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}

	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp mount success");

			/* Verify the drive and cartridge */
			/* states have been correctly set */
			/* should be set from the lmp partial */
			/* config that accompanies */
			/* the mount command */
			cart_pcl = mm_get_cart_pcl(cmd,
			    mount_info->cmi_cartridge, db);
			if (mm_db_exec(HERE, db,
			    "select \"DriveLibraryOccupied\", "
			    "\"CartridgePCL\" from \"DRIVE\" "
			    "where \"DriveName\" = '%s';",
			    mount_info->cmi_drive) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "error checking drive states after mount");
				mm_sql_db_err_rsp_new(cmd, db);
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}
			if (PQntuples(db->mm_db_results) != 1) {
				mms_trace(MMS_ERR,
				    "error checking drive state,"
				    "num drives returned != 1, %d returned",
				    PQntuples(db->mm_db_results));
				mm_system_error(cmd,
				    "error checking drive state,"
				    "num drives returned != 1, %d returned",
				    PQntuples(db->mm_db_results));
				mm_clear_db(&db->mm_db_results);
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}
			if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
			    "t") != 0) {
				mms_trace(MMS_ERR,
				    "error checking drive state,"
				    "DriveOccupied is not true");
				mm_system_error(cmd,
				    "error checking drive state,"
				    "DriveOccupied is not true");
				mm_clear_db(&db->mm_db_results);
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}
			if (strcmp(PQgetvalue(db->mm_db_results, 0, 1),
			    cart_pcl) != 0) {
				mms_trace(MMS_ERR,
				    "error checking drive state,"
				    "CartridgePCL, %s != %s",
				    cart_pcl,
				    PQgetvalue(db->mm_db_results, 0, 1));
				mm_system_error(cmd,
				    "error checking drive state,"
				    "CartridgePCL, %s != %s",
				    cart_pcl,
				    PQgetvalue(db->mm_db_results, 0, 1));
				mm_clear_db(&db->mm_db_results);
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}
			mm_clear_db(&db->mm_db_results);


			/* Update Drive and Cartridge Stats */
			rc = mm_db_exec(HERE, db,
			    "update \"DRIVE\" "
			    "set \"DriveNumberMounts\" = "
			    "\"DriveNumberMounts\" + 1, "
			    "\"DriveTimeMountedLast\" = now(), "
			    "\"DriveNumberMountsSinceCleaning\" "
			    "= \"DriveNumberMountsSinceCleaning\" + 1 "
			    "where \"DriveName\" = '%s';",
			    mount_info->cmi_drive);
			if (rc != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "db error updating stats");
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}

			/* Update Cartridge Table */
			rc = mm_db_exec(HERE, db,
			    "update \"CARTRIDGE\" "	\
			    "set \"CartridgeTimeMountedLast\" = now(), " \
			    "\"CartridgeNumberMounts\" = "\
			    "\"CartridgeNumberMounts\" + 1 "	\
			    "where \"CartridgeID\" = '%s';",
			    mount_info->cmi_cartridge);
			if (rc != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "db error updating stats");
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}
			/* Update Side Table */
			rc = mm_db_exec(HERE, db,
			    "update \"SIDE\" "	\
			    "set \"SideTimeMountedLast\" = now(), "\
			    "\"SideNumberMounts\" = "\
			    "\"SideNumberMounts\" + 1 "\
			    "where \"CartridgeID\" = '%s';",
			    mount_info->cmi_cartridge);
			if (rc != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "db error updating stats");
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}
			/* Update Partition Table */
			rc = mm_db_exec(HERE, db,
			    "update \"PARTITION\" "\
			    "set \"PartitionNumberMounts\" = "\
			    "\"PartitionNumberMounts\" + 1, "\
			    "\"PartitionTimeMountedLast\" = now() "\
			    "where \"CartridgeID\" = '%s';",
			    mount_info->cmi_cartridge);
			if (rc != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "db error updating stats");
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}
			/* Update Volume Table */
			rc = mm_db_exec(HERE, db,
			    "update \"VOLUME\" "\
			    "set \"VolumeNumberMounts\" = "\
			    "\"VolumeNumberMounts\" + 1, "\
			    "\"VolumeTimeMountedLast\" = now() "\
			    "where \"CartridgeID\" = '%s';",
			    mount_info->cmi_cartridge);
			if (rc != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "db error updating stats");
				free(cart_pcl);
				return (MM_CMD_ERROR);
			}

			free(cart_pcl);
			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp mount failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

/*
 * mm_lmp_unmount_cmd_func(mm_wka, cmd)
 *
 * Unmount cartridge from drive.
 */
int
mm_lmp_unmount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	int			rc = 0;
	mm_response_t		response;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	mms_trace(MMS_DEVP, "lmp unmount cmd func: state=%d",
	    cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		/* Check LM state before sending */
		mms_trace(MMS_DEVP,
		    "check lm state before sending");
		rc =  mm_lm_send_ok(cmd, mm_wka);
		if (rc == MM_LM_ERROR) {
			mms_trace(MMS_DEVP, "Cannot send this lmp command");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		} else if (rc == MM_LM_WAIT) {
			mms_trace(MMS_DEVP,
			    "wait to send the lmp command ");
			MM_SET_FLAG(cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
			return (MM_NO_DISPATCH);
		} else if (rc == MM_LM_SEND) {
			mms_trace(MMS_DEVP,
			    "lm send the lmp command");
		}

		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp unmount accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp unmount success");

			/* Verify the drive and cartridge */
			/* states have been correctly set */
			/* should be set from the lmp partial */
			/* config that accompanies */
			/* the mount command */
			if (mm_db_exec(HERE, db,
			    "select \"DriveLibraryOccupied\", "
			    "\"CartridgePCL\" from \"DRIVE\" "
			    "where \"DriveName\" = '%s';",
			    mount_info->cmi_drive) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "error checking drive states after mount");
				mm_sql_db_err_rsp_new(cmd, db);
				return (MM_CMD_ERROR);
			}
			if (PQntuples(db->mm_db_results) != 1) {
				mms_trace(MMS_ERR,
				    "error checking drive state,"
				    "num drives returned != 1, %d returned",
				    PQntuples(db->mm_db_results));
				mm_system_error(cmd,
				    "error checking drive state,"
				    "num drives returned != 1, %d returned",
				    PQntuples(db->mm_db_results));
				mm_clear_db(&db->mm_db_results);
				return (MM_CMD_ERROR);
			}
			if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
			    "f") != 0) {
				mms_trace(MMS_ERR,
				    "error checking drive state,"
				    "DriveOccupied is not true");
				mm_system_error(cmd,
				    "error checking drive state,"
				    "DriveOccupied is not true");
				mm_clear_db(&db->mm_db_results);
				return (MM_CMD_ERROR);
			}
			if (strcmp(PQgetvalue(db->mm_db_results, 0, 1),
			    "") != 0) {
				mms_trace(MMS_ERR,
				    "error checking drive state,"
				    "CartridgePCL, %s != NULL",
				    PQgetvalue(db->mm_db_results, 0, 1));
				mm_system_error(cmd,
				    "error checking drive state,"
				    "CartridgePCL, %s != NULL",
				    PQgetvalue(db->mm_db_results, 0, 1));
				mm_clear_db(&db->mm_db_results);
				return (MM_CMD_ERROR);
			}
			mm_clear_db(&db->mm_db_results);
			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp unmount failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

/*
 * mm_lmp_inject_cmd_func(mm_wka, cmd)
 *
 * Inject (import) cartridge from mailslot (cap).
 */
int
mm_lmp_inject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_response_t		response;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;

	mms_par_node_t		*arg = NULL;
	mms_par_node_t		*work = NULL;

	mms_par_node_t		*cart_pcl = NULL;

	mms_trace(MMS_DEVP, "lmp inject cmd func: state=%d",
	    cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp inject accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp inject success");
			/* Add eject event for all injected cartridges */
			arg = mms_pn_lookup(cmd->cmd_response, "text",
			    MMS_PN_CLAUSE, 0);
			if (arg != NULL) {
				mms_trace(MMS_INFO,
				    "Injected Cartridges:");
				while ((cart_pcl = mms_pn_lookup(arg, NULL,
				    MMS_PN_STRING, &work)) != NULL) {
					/* Add event for this cartridge here */
					mms_trace(MMS_INFO,
					    "    %s",
					    cart_pcl->pn_string);
					if (mm_notify_add_volumeinject(mm_wka,
					    cmd,
					    cart_pcl->pn_string,
					    db)) {
						mms_trace(MMS_ERR,
						    "mm_lmp_inject_cmd_func: "
						    "error adding volume "
						    "inject event");
					}
				}
			}

			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp inject failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

/*
 * mm_lmp_eject_cmd_func(mm_wka, cmd)
 *
 * Eject (export) cartridge from mailslot (cap).
 */
int
mm_lmp_eject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	mm_response_t		response;

	mms_par_node_t		*arg = NULL;
	mms_par_node_t		*work = NULL;

	mms_par_node_t		*cart_pcl = NULL;


	mms_trace(MMS_DEVP, "lmp eject cmd func: state=%d",
	    cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp eject accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp eject success");
			mms_trace(MMS_DEVP, "Looking up arg's");
			/* Add eject event for all ejected cartridges */
			arg = mms_pn_lookup(cmd->cmd_response, "text",
			    MMS_PN_CLAUSE, 0);
			if (arg != NULL) {
				mms_trace(MMS_INFO,
				    "Ejected Cartridges:");
				while ((cart_pcl = mms_pn_lookup(arg, NULL,
				    MMS_PN_STRING, &work)) != NULL) {
					/* Add event for this cartridge here */
					mms_trace(MMS_INFO,
					    "    %s",
					    cart_pcl->pn_string);
					if (mm_notify_add_volumeeject(mm_wka,
					    cmd,
					    cart_pcl->pn_string,
					    db)) {
						mms_trace(MMS_ERR,
						    "mm_lmp_eject_cmd_func: "
						    "error adding volume "
						    "eject event");
					}
				}
			}

			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp eject failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

/*
 * mm_lmp_cpscan_cmd_func(mm_wka, cmd)
 *
 * Scan the robot.
 */
int
mm_lmp_scan_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	int		 rc = 0;
	mm_response_t	 response;


	if (mm_wka->mm_wka_mm_lang != MM_LANG_LMP) {
		mms_trace(MMS_ERR,
		    "lmp scan sent to non-lmp client");
		return (MM_CMD_ERROR);
	}

	mms_trace(MMS_DEVP, "lmp scan cmd func: state=%d",
	    cmd->cmd_state);

	if (cmd->cmd_state == 0) {

		/* Check LM state before sending */
		mms_trace(MMS_DEVP,
		    "check lm state before sending");
		rc =  mm_lm_send_ok(cmd, mm_wka);
		if (rc == MM_LM_ERROR) {
			mms_trace(MMS_DEVP, "Cannot send this lmp command");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		} else if (rc == MM_LM_WAIT) {
			mms_trace(MMS_DEVP,
			    "wait to send the lmp command ");
			MM_SET_FLAG(cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
			return (MM_NO_DISPATCH);
		} else if (rc == MM_LM_SEND) {
			mms_trace(MMS_DEVP,
			    "lm send the lmp command");
		}

		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp scan accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp scan success");
			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp scan failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

int
mm_lmp_cancel_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*value = NULL;
	mms_par_node_t	*arg = NULL;
	mm_data_t	*data = mm_wka->mm_data;
	char		*taskid = NULL;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*cmd_p = NULL;
	mm_command_t	*cmd_q = NULL;
	char		*cmd_name = NULL;
	uuid_text_t	cmd_reqid;

	mms_trace(MMS_DEBUG, "mm_lmp_cancel_cmd_func");

	MMS_PN_LOOKUP(arg, cmd->cmd_root, "whichtask", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, NULL);
	taskid = value->pn_string;

	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&data->mm_cmd_queue, cmd_p) {
		if (strcmp(cmd_p->wka_ptr->wka_conn.cci_uuid,
		    cmd->wka_ptr->wka_conn.cci_uuid) == 0 &&
		    strcmp(cmd_p->cmd_task, taskid) == 0) {

			/* is this a command we know how to cancel */
			if (strcmp(mms_pn_token(cmd_p->cmd_root),
			    "request") == 0) {
				cmd_name = strdup("request");
				strcpy(cmd_reqid, cmd_p->cmd_reqid);
			}
			break;
		}
	}
	pthread_mutex_unlock(&data->mm_queue_mutex);

	/* command not found */
	if (cmd_p == NULL) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INVALID) + strlen(ELM_E_NOTASK) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INVALID, ELM_E_NOTASK);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* cancel command */
	if (strcmp(cmd_name, "request") == 0) {
		free(cmd_name);
		if (mm_db_exec(HERE, db, "select \"RequestState\" "
		    "from \"REQUEST\" where \"RequestID\" = '%s';",
		    cmd_reqid) != MM_DB_DATA ||
		    PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INTERNAL) +
			    strlen(EDATABASE) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR,
			    cmd->cmd_task, ECLASS_INTERNAL, EDATABASE);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "responded") == 0) {
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INVALID) +
			    strlen(ELM_E_NOCANC) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR,
			    cmd->cmd_task,
			    ECLASS_INVALID, ELM_E_NOCANC);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);

		/* remove the request */
		if (mm_db_exec(HERE, db, "delete from \"REQUEST\" where "
		    "\"RequestID\" = '%s';", cmd_reqid) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INTERNAL) +
			    strlen(EDATABASE) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR,
			    cmd->cmd_task, ECLASS_INTERNAL, EDATABASE);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else {
		free(cmd_name);
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INVALID) + strlen(ELM_E_NOCANC) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INVALID, ELM_E_NOCANC);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* send cancelled command's final-command response */
	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&data->mm_cmd_queue, cmd_q) {
		if (cmd_q == cmd_p) {
			/* send cancelled command response */
			SQL_CHK_LEN(&cmd_p->cmd_buf, 0,
			    &cmd_p->cmd_bufsize,
			    strlen(RESPONSE_CANCELLED) +
			    strlen(cmd_p->cmd_task) + 1);
			(void) snprintf(cmd_p->cmd_buf, cmd_p->cmd_bufsize,
			    RESPONSE_CANCELLED, cmd_p->cmd_task);
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd_p->cmd_buf);
			cmd_p->cmd_remove = 1;
			break;
		}
	}
	pthread_mutex_unlock(&data->mm_queue_mutex);

	/* same command not found or error sending cancelled response */
	if (cmd_q == NULL) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INVALID) + strlen(ELM_E_NOTASK) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INVALID, ELM_E_NOTASK);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_SUCCESS, cmd->cmd_task);
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_DONE);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}

int
mm_lmp_reset_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	cci_t		*conn = &mm_wka->wka_conn;
	mm_response_t	 response;


	mms_trace(MMS_DEBUG,
	    "lmp reset state %d, %s",
	    cmd->cmd_state,
	    cmd->cmd_textcmd);

	if (cmd->cmd_state == 0) {
		mms_trace(MMS_INFO,
		    "Issuing reset for %s %s",
		    conn->cci_instance,
		    conn->cci_client);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp reset accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp reset success");
			cmd->cmd_remove = 1;
			return (MM_DEPEND_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp reset failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

int
mm_lmp_exit_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	cci_t		*conn = &mm_wka->wka_conn;
	mm_response_t	 response;


	mms_trace(MMS_DEBUG,
	    "lmp exit state %d, %s",
	    cmd->cmd_state,
	    cmd->cmd_textcmd);

	if (cmd->cmd_state == 0) {
		mms_trace(MMS_INFO,
		    "Issuing exit for %s %s",
		    conn->cci_instance,
		    conn->cci_client);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "lmp exit accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "lmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "lmp exit success");
			cmd->cmd_remove = 1;
			return (MM_DEPEND_DONE);
		}
	}

	mms_trace(MMS_DEVP, "lmp exit failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}
