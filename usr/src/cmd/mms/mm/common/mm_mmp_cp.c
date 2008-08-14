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
#include "mm_task.h"
#include "mm_path.h"



static char *_SrcFile = __FILE__;

extern  mm_privilege_t mm_privileged(mm_wka_t *mm_wka, mm_command_t *cmd);


int
mm_cpexit_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	char		*type;
	int		 rows;
	PGresult	*dev_results;
	int		 rc;
	uuid_text_t	 task;
	char		*dev_name;
	char		*mgr_name;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_wka_t	*mgr_wka = NULL;
	mm_data_t	*data = mm_wka->mm_data;
	mm_command_t	*exit_cmd;
	char		*query;
	char		*host;
	char		*disabled;

	mms_trace(MMS_DEVP, "mm cpexit command, state %d", cmd->cmd_state);
	if (cmd->cmd_state == 1) {
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			char *response_message = NULL;
			mms_trace(MMS_DEVP, "device manager exit failed");
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    5055,
			    "msg_rsp", response_message,
			    MESS_END);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);

		}

		mms_trace(MMS_INFO, "Device Manager exit success");
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_DONE);

	}

	if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
		return (MM_CMD_ERROR);
	}

	/* device type */
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "cptype", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_KEYWORD, NULL);
	type = value->pn_string;


	/* find device manager */
	(void) mm_get_dest(mm_wka, cmd);
	(void) mm_get_const(mm_wka, cmd);
	if (strcmp(type, "DM") == 0) {
		if (mm_add_char("DM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_cpexit_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		query = "select distinct "
		    "\"DM\".\"DriveName\",\"DM\".\"DMName\","
		    "\"DM\".\"DMTargetHost\",\"DM\".\"DMDisabled\" from ";
	} else {
		if (mm_add_char("LM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_cpexit_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		query = "select distinct "
		    "\"LM\".\"LibraryName\",\"LM\".\"LMName\","
		    "\"LM\".\"LMTargetHost\",\"LM\".\"LMDisabled\" from ";
	}
	cmd->cmd_source_num = 1;
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) + 1);
	strcpy(cmd->cmd_buf, query);
	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_cpexit_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_sql_order(cmd);
	mm_sql_number(cmd);

	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		goto db_error;
	}
	rows = PQntuples(db->mm_db_results);
	if (rows == 0) {
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_EXPLICIT,
		    ENOMATCH,
		    5079,
		    MESS_END);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	} else if (rows > 1) {
		/* Can only have 1 dev manager */
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_EXPLICIT,
		    ETOOMANY,
		    5076,
		    MESS_END);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	dev_results = db->mm_db_results;

	dev_name = PQgetvalue(dev_results, 0, 0);
	mgr_name = PQgetvalue(dev_results, 0, 1);
	host = PQgetvalue(dev_results, 0, 2);
	disabled = PQgetvalue(dev_results, 0, 3);

	/*
	 * Disable device manager
	 */
	if (strcmp(disabled, "false") == 0) {
		if (strcmp(type, "DM") == 0) {
			rc = mm_db_exec(HERE, db, "update \"DM\" "
			    "set \"DMDisabled\" = 'true' "
			    "where \"DriveName\" = '%s' and "
			    "\"DMName\" = '%s';",
			    dev_name, mgr_name);
		} else {
			rc = mm_db_exec(HERE, db, "update \"LM\" "
			    "set \"LMDisabled\" = 'true' "
			    "where \"LibraryName\" = '%s' and "
			    "\"LMName\" = '%s';",
			    dev_name, mgr_name);
		}
		if (rc != MM_DB_OK) {
			goto db_error;
		}

	}

	/*
	 * Check for connection
	 */
	mms_list_foreach(&data->mm_wka_list, mgr_wka) {
		if ((strcmp(mgr_wka->wka_conn.cci_instance,
		    mgr_name) == 0) &&
		    (strcmp(mgr_wka->wka_conn.cci_client,
		    dev_name) == 0)) {
			/* Found the wka of dev manager */
			break;
		}
	}
	if (mgr_wka == NULL) {
		mms_trace(MMS_INFO, "Device Manager exit success");
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_DONE);
	}

	/* Allocate command and add to the queue */

	/*
	 * exit command
	 */
	if ((exit_cmd = mm_alloc_cmd(mgr_wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		return (1);
	}
	if (strcmp(type, "DM") == 0) {
		exit_cmd->cmd_func = mm_dmp_exit_cmd_func;
	} else {
		exit_cmd->cmd_func = mm_lmp_exit_cmd_func;
	}
	mm_get_uuid(task);
	exit_cmd->cmd_textcmd = mms_strnew("exit task[\"%s\"];", task);

	mms_trace(MMS_DEVP, "%s", exit_cmd->cmd_textcmd);
	if (strcmp(type, "DM") == 0) {
		exit_cmd->cmd_root =
		    mm_text_to_par_node(exit_cmd->cmd_textcmd,
		    mms_dmpm_parse);
		exit_cmd->cmd_name = strdup("dmp exit");
	} else {
		exit_cmd->cmd_root =
		    mm_text_to_par_node(exit_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		exit_cmd->cmd_name = strdup("lmp exit");
	}
	exit_cmd->cmd_task = mms_strapp(exit_cmd->cmd_task,
	    task);
	mm_add_depend(exit_cmd, cmd);

	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, exit_cmd);
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

	mm_clear_db(&dev_results);


	/*
	 * Notify watcher
	 */
	if (mm_notify_add_config(mm_wka, cmd, "disable",
	    type, mgr_name, host)) {
		mm_system_error(cmd,
		    "failed to add config "
		    "event for watcher");
		mm_clear_db(&dev_results);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}


	cmd->cmd_state = 1;
	mms_trace(MMS_DEBUG,
	    "added exit command for %s %s",
	    mgr_name, dev_name);

	return (MM_DISPATCH_DEPEND);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    5062,
	    MESS_END);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	return (rc);
}



int
mm_cpstart_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	char		*type;
	int		 rows;
	PGresult	*dev_results;
	int		 rc;
	char		*dev_name;
	char		*mgr_name;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*query;
	char		*host;
	char		*disabled;
	char		*state_soft;
	char		*state_hard;

	mms_trace(MMS_DEVP, "mm cpstart command");

	if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
		return (MM_CMD_ERROR);
	}

	/* device type */
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "cptype", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_KEYWORD, NULL);
	type = value->pn_string;


	/* find device manager */
	(void) mm_get_dest(mm_wka, cmd);
	(void) mm_get_const(mm_wka, cmd);
	if (strcmp(type, "DM") == 0) {
		if (mm_add_char("DM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_cpstart_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		query = "select distinct "
		    "\"DM\".\"DriveName\",\"DM\".\"DMName\","
		    "\"DM\".\"DMTargetHost\",\"DM\".\"DMDisabled\", "
		    "\"DM\".\"DMStateSoft\",\"DM\".\"DMStateHard\" from ";
	} else {
		if (mm_add_char("LM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_cpstart_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		query = "select distinct "
		    "\"LM\".\"LibraryName\",\"LM\".\"LMName\","
		    "\"LM\".\"LMTargetHost\",\"LM\".\"LMDisabled\", "
		    "\"LM\".\"LMStateSoft\",\"LM\".\"LMStateHard\" from ";
	}
	cmd->cmd_source_num = 1;
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) + 1);
	strcpy(cmd->cmd_buf, query);
	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_cpstart_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_sql_order(cmd);
	mm_sql_number(cmd);

	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		goto db_error;
	}
	rows = PQntuples(db->mm_db_results);
	if (rows == 0) {
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_EXPLICIT,
		    ENOMATCH,
		    5079,
		    MESS_END);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	} else if (rows > 1) {
		/* Can only have 1 dev manager */
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_EXPLICIT,
		    ETOOMANY,
		    5076,
		    MESS_END);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	dev_results = db->mm_db_results;

	dev_name = PQgetvalue(dev_results, 0, 0);
	mgr_name = PQgetvalue(dev_results, 0, 1);
	host = PQgetvalue(dev_results, 0, 2);
	disabled = PQgetvalue(dev_results, 0, 3);
	state_soft = PQgetvalue(dev_results, 0, 4);
	state_hard = PQgetvalue(dev_results, 0, 5);

	if ((strcmp(disabled, "false") == 0) &&
	    (strcmp(state_soft, "absent") != 0)) {
		/* manager is already enabled + connected */
		mms_trace(MMS_DEVP, "device manager already "
		    "enabled and connected");
		mm_write_success(cmd,
		    "%s is already enabled and connected",
		    mgr_name);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		mm_clear_db(&dev_results);
		return (MM_CMD_DONE);
	}

	/*
	 * Clear broken state
	 */
	if (strcmp(state_hard, "broken") == 0) {
		if (strcmp(type, "DM") == 0) {
			rc = mm_db_exec(HERE, db, "update \"DM\" "
			    "set \"DMStateHard\" = 'ready' "
			    "where \"DriveName\" = '%s' and "
			    "\"DMName\" = '%s';",
			    dev_name, mgr_name);
		} else {
			rc = mm_db_exec(HERE, db, "update \"LM\" "
			    "set \"LMStateHard\" = 'ready' "
			    "where \"LibraryName\" = '%s' and "
			    "\"LMName\" = '%s';",
			    dev_name, mgr_name);
		}
		if (rc != MM_DB_OK) {
			goto db_error;
		}
	}

	/*
	 * Enable device manager
	 */
	if (strcmp(disabled, "true") == 0) {
		if (strcmp(type, "DM") == 0) {
			rc = mm_db_exec(HERE, db, "update \"DM\" "
			    "set \"DMDisabled\" = 'false' "
			    "where \"DriveName\" = '%s' and "
			    "\"DMName\" = '%s';",
			    dev_name, mgr_name);
		} else {
			rc = mm_db_exec(HERE, db, "update \"LM\" "
			    "set \"LMDisabled\" = 'false' "
			    "where \"LibraryName\" = '%s' and "
			    "\"LMName\" = '%s';",
			    dev_name, mgr_name);
		}
		if (rc != MM_DB_OK) {
			goto db_error;
		}
		if (strcmp(state_soft, "absent") != 0) {
			mms_trace(MMS_DEVP, "disabled device manager "
			    "is already connected, %s",
			    mgr_name);
			mm_write_success(cmd,
			    "disabled device manager "
			    "is already connected, %s",
			    mgr_name);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			mm_clear_db(&dev_results);
			return (MM_CMD_DONE);
		}
		/*
		 * Notify watcher
		 */
		if (mm_notify_add_config(mm_wka, cmd,
		    "enable",
		    type, mgr_name, host)) {
			mm_system_error(cmd,
			    "failed to add config "
			    "enable event");
			mm_clear_db(&dev_results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}


		mms_trace(MMS_INFO, "Notified watcher that "
		    "device manager should be started, %s",
		    mgr_name);
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);

		mm_clear_db(&dev_results);
		return (MM_CMD_DONE);
	}
	if ((strcmp(disabled, "false") == 0) &&
	    (strcmp(state_soft, "absent") == 0)) {
		mms_trace(MMS_INFO,
		    "manager is enabled but not connecetd,"
		    " notify watcher to restart, %s",
		    mgr_name);
		/*
		 * Notify watcher
		 */
		if (mm_notify_add_config(mm_wka, cmd,
		    "enable",
		    type, mgr_name, host)) {
			mm_system_error(cmd,
			    "failed to add config "
			    "enable event");
			mm_clear_db(&dev_results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}


		mms_trace(MMS_INFO, "Notified watcher that "
		    "device manager should be started, %s",
		    mgr_name);
		mm_write_success(cmd,
		    "%s is already enabled but not connected, "
		    "attempting to restart",
		    mgr_name);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		mm_clear_db(&dev_results);
		return (MM_CMD_DONE);
	}


	mm_clear_db(&dev_results);

	mms_trace(MMS_INFO, "Device Manager start success");
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_SUCCESS, cmd->cmd_task);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_DONE);


no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    5062,
	    MESS_END);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	return (rc);
}



int
mm_cpscan_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	char		*fromslot;
	char		*toslot;
	char		*drive_name;
	char		*slot_name;
	int		slot = 0;
	int		drive = 0;
	int		 range = 0;	/* all slots */
	int		 rows;
	PGresult	*lm_results;
	uuid_text_t	 lm_task;
	char		*lib_name;
	char		*lm_name;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*lmp_scan_cmd;
	const char	*query;
	mm_wka_t	*lm_wka;
	int		 rc;


	mms_trace(MMS_DEVP, "mm cpscan command %d", cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
			return (MM_CMD_ERROR);
		}

		/* slot range */
		if (arg = mms_pn_lookup(cmd->cmd_root, "fromslot",
		    MMS_PN_CLAUSE, NULL)) {
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			fromslot = value->pn_string;
			MMS_PN_LOOKUP(arg, cmd->cmd_root, "toslot",
			    MMS_PN_CLAUSE, NULL);
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			toslot = value->pn_string;
			range = 1;
		}
		/* single slot */
		if (arg = mms_pn_lookup(cmd->cmd_root, "slot",
		    MMS_PN_CLAUSE, NULL)) {
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			slot_name = value->pn_string;
			slot = 1;
		}
		/* single drive */
		if (arg = mms_pn_lookup(cmd->cmd_root, "drive",
		    MMS_PN_CLAUSE, NULL)) {
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			drive_name = value->pn_string;
			drive = 1;
		}

		/* find lm */

		(void) mm_get_dest(mm_wka, cmd);
		(void) mm_get_const(mm_wka, cmd);
		if (mm_add_char("LM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_cpscan_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_source_num = 1;
		query = "select \"LM\".\"LibraryName\","
		    "\"LM\".\"LMName\" from ";
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(query) + 1);
		strcpy(cmd->cmd_buf, query);
		if (mm_sql_from_where(cmd, db)) {
			mms_trace(MMS_ERR,
			    "mm_cpscan_cmd_func: "
			    "db error creating helper functions");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		mm_sql_order(cmd);
		mm_sql_number(cmd);
		if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&db->mm_db_results);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		if ((rows = PQntuples(db->mm_db_results)) == 0) {
			mm_clear_db(&db->mm_db_results);
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    ELIBNOLMCONFIGURED,
			    5080,
			    MESS_END);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		} else if (rows > 1) {
			mm_clear_db(&db->mm_db_results);
			mm_response_error(cmd,
			    ECLASS_EXPLICIT,
			    ETOOMANY,
			    5076,
			    MESS_END);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		lm_results = db->mm_db_results;
		lib_name = PQgetvalue(lm_results, 0, 0);
		lm_name = PQgetvalue(lm_results, 0, 1);

		/* check for library ready and online */
		if (mm_db_exec(HERE, db, "SELECT "
		    "\"LIBRARY\".\"LibraryStateSoft\","
		    "\"LM\".\"LMStateSoft\","
		    "\"LIBRARY\".\"LibraryOnline\" "
		    "FROM \"LIBRARY\",\"LM\" "
		    "WHERE (\"LIBRARY\".\"LibraryName\" = '%s' AND "
		    "\"LIBRARY\".\"LMName\" = '%s') AND "
		    "(\"LM\".\"LibraryName\" = '%s' AND "
		    "\"LM\".\"LMName\" = '%s')",
		    lib_name, lm_name, lib_name, lm_name) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&lm_results);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    ELIBNOLMCONFIGURED,
			    5021,
			    "lm",
			    lm_name,
			    MESS_END);
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&lm_results);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "ready") != 0 ||
		    strcmp(PQgetvalue(db->mm_db_results, 0, 1),
		    "ready") != 0 ||
		    strcmp(PQgetvalue(db->mm_db_results, 0, 2),
		    "true") != 0) {
			mms_trace(MMS_DEVP, "%s %s - %s %s %s", lib_name,
			    lm_name,
			    PQgetvalue(db->mm_db_results, 0, 0),
			    PQgetvalue(db->mm_db_results, 0, 1),
			    PQgetvalue(db->mm_db_results, 0, 2));
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    ELMNOTREADY,
			    5021,
			    "lm",
			    lm_name,
			    MESS_END);
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&lm_results);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);

		/* begin lm scan command */
		mm_get_uuid(lm_task);

		if (range) { /* build lm scan cmd */
			/* scan part of slots */
			query = "scan task[\"%s\"] fromslot[\"%s\"] "
			    "toslot[\"%s\"];";
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(query) + strlen(lm_task) +
			    strlen(fromslot) + strlen(toslot) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    query,
			    lm_task, fromslot, toslot);
		} else if (slot) {
			/* single slot */
			query = "scan task[\"%s\"] slot[\"%s\"];";
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(query) + strlen(lm_task) +
			    strlen(slot_name) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    query,
			    lm_task, slot_name);
		} else if (drive) {
			/* single drive */
			query = "scan task[\"%s\"] drive[\"%s\"];";
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(query) + strlen(lm_task) +
			    strlen(drive_name) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    query,
			    lm_task, drive_name);
		} else {
			/* scan all slots */
			query = "scan task[\"%s\"] all;";
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(query) + strlen(lm_task) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    query, lm_task);
		}

		mms_trace(MMS_DEVP, "Adding lmp scan command");

		/*
		 * LMP scan command
		 */
		lm_wka = mm_library_lm_wka(cmd->wka_ptr->mm_data,
		    lib_name, NULL);



		lmp_scan_cmd = mm_alloc_cmd(lm_wka);
		lmp_scan_cmd->cmd_func = mm_lmp_scan_cmd_func;
		lmp_scan_cmd->cmd_textcmd = strdup(cmd->cmd_buf);
		lmp_scan_cmd->cmd_root =
		    mm_text_to_par_node(lmp_scan_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		lmp_scan_cmd->cmd_task = mm_get_task(lmp_scan_cmd->cmd_root);
		lmp_scan_cmd->cmd_flags |= MM_CMD_DISPATCHABLE;
		lmp_scan_cmd->cmd_language = MM_LANG_LMP;
		lmp_scan_cmd->cmd_name = strdup("lmp scan");
		mm_add_depend(lmp_scan_cmd, cmd);

		mm_clear_db(&lm_results);

		cmd->cmd_state = 1;

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue,
		    lmp_scan_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		return (MM_DISPATCH_DEPEND);

	} else if (cmd->cmd_state == 1) {

		free(cmd->cmd_buf);
		cmd->cmd_buf = NULL;
		cmd->cmd_bufsize = 0;

		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			/* Send Failure */
			char *response_message = NULL;
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    5055,
			    "msg_rsp", response_message,
			    MESS_END);
			free(response_message);
			rc = MM_CMD_ERROR;
		} else {
			/* Send Success */
			mm_path_match_report(cmd, db);
			rc = MM_CMD_DONE;
		}
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		cmd->cmd_remove = 1;

		return (rc);
	}

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    5062,
	    MESS_END);
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}


int
mm_cpreset_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	char		*type;
	int		 scope = 0;	/* full reset */
	int		 rows;
	PGresult	*dev_results;
	int		 rc;
	uuid_text_t	 task;
	char		*dev_name;
	char		*mgr_name;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_wka_t	*mgr_wka = NULL;
	mm_data_t	*data = mm_wka->mm_data;
	mm_command_t	*reset_cmd;
	char		*query;

	mms_trace(MMS_DEVP, "mm cpreset command, state %d", cmd->cmd_state);
	if (cmd->cmd_state == 1) {
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			char *response_message = NULL;
			mms_trace(MMS_DEVP, "device manager reset failed");
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    5055,
			    "msg_rsp", response_message,
			    MESS_END);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);

		}

		mms_trace(MMS_INFO, "Device Manager reset success");
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_DONE);

	}

	if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
		return (MM_CMD_ERROR);
	}

	/* device type */
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "cptype", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_KEYWORD, NULL);
	type = value->pn_string;

	/* reset scope */
	if (arg = mms_pn_lookup(cmd->cmd_root, "partial",
	    MMS_PN_KEYWORD, NULL)) {
		scope = 1;
	}


	/* find device manager */
	(void) mm_get_dest(mm_wka, cmd);
	(void) mm_get_const(mm_wka, cmd);
	if (strcmp(type, "DM") == 0) {
		if (mm_add_char("DM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_cpreset_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		query = "select distinct "
		    "\"DM\".\"DriveName\",\"DM\".\"DMName\" from ";
	} else {
		if (mm_add_char("LM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_cpreset_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		query = "select distinct "
		    "\"LM\".\"LibraryName\",\"LM\".\"LMName\" from ";
	}
	cmd->cmd_source_num = 1;
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) + 1);
	strcpy(cmd->cmd_buf, query);
	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_cpreset_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_sql_order(cmd);
	mm_sql_number(cmd);


	mms_trace(MMS_DEVP,
	    "cmd buf is %s",
	    cmd->cmd_buf);
	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		goto db_error;
	}
	rows = PQntuples(db->mm_db_results);
	if (rows == 0) {
		mm_clear_db(&db->mm_db_results);
		if (strcmp(type, "DM") == 0) {
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    EDRVNODMCONFIGURED,
			    5074,
			    MESS_END);
		} else {
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    ELIBNOLMCONFIGURED,
			    5075,
			    MESS_END);
		}
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	} else if (rows > 1) {
		/* Can only have 1 dev manager */
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_EXPLICIT,
		    ETOOMANY,
		    5076,
		    MESS_END);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	dev_results = db->mm_db_results;

	/* check device connections */

	dev_name = PQgetvalue(dev_results, 0, 0);
	mgr_name = PQgetvalue(dev_results, 0, 1);

	/* check for connected device */
	if (strcmp(type, "DM") == 0) {
		if (mm_db_exec(HERE, db, "SELECT "
		    "\"DM\".\"DMStateSoft\" FROM \"DM\" "
		    "WHERE \"DM\".\"DriveName\" = '%s' AND "
		    "\"DM\".\"DMName\" ='%s';",
		    dev_name, mgr_name) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&dev_results);
			goto db_error;
		}
	} else if (mm_db_exec(HERE, db, "SELECT "
	    "\"LM\".\"LMStateSoft\" FROM \"LM\" "
	    "WHERE \"LM\".\"LibraryName\" = '%s' AND "
	    "\"LM\".\"LMName\" = '%s';",
	    dev_name, mgr_name) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&dev_results);
		goto db_error;
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR,
		    "Error getting device manager state");
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&dev_results);
		mm_system_error(cmd,
		    "Error getting device manager state");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}

	mms_trace(MMS_DEVP,
	    "Device and Manager State:");
	mms_trace(MMS_DEVP,
	    "  Device = %s",
	    PQgetvalue(db->mm_db_results, 0, 0));

	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0), "absent") == 0) {
		if (strcmp(type, "DM") == 0) {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    EDMNOTCONNECTED,
			    5077,
			    "dm",
			    mgr_name,
			    MESS_END);
		} else {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    ELMNOTCONNECTED,
			    5078,
			    "lm",
			    mgr_name,
			    MESS_END);
		}
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&dev_results);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);

	}
	mm_clear_db(&db->mm_db_results);

	mms_list_foreach(&data->mm_wka_list, mgr_wka) {
		if ((strcmp(mgr_wka->wka_conn.cci_instance,
		    mgr_name) == 0) &&
		    (strcmp(mgr_wka->wka_conn.cci_client,
		    dev_name) == 0)) {
			/* Found the wka of dev manager */
			break;
		}
	}
	if (mgr_wka == NULL) {
		if (strcmp(type, "DM") == 0) {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    EDMNOTCONNECTED,
			    5077,
			    "dm",
			    mgr_name,
			    MESS_END);
		} else {
			mm_response_error(cmd,
			    ECLASS_RETRY,
			    ELMNOTCONNECTED,
			    5078,
			    "lm",
			    mgr_name,
			    MESS_END);
		}
		mm_clear_db(&dev_results);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	/* Allocate command and add to the queue */

	/*
	 * reset command
	 */

	if ((reset_cmd = mm_alloc_cmd(mgr_wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		return (1);
	}
	if (strcmp(type, "DM") == 0) {
		reset_cmd->cmd_func = mm_dmp_reset_cmd_func;
	} else {
		reset_cmd->cmd_func = mm_lmp_reset_cmd_func;
	}
	mm_get_uuid(task);
	if (scope) {	/* build device reset cmd */
		reset_cmd->cmd_textcmd = mms_strnew("reset task[\"%s\"] "
		    "partial;", task);
	} else {
		reset_cmd->cmd_textcmd = mms_strnew("reset task[\"%s\"] full;",
		    task);
	}

	mms_trace(MMS_DEVP, "%s", reset_cmd->cmd_textcmd);
	if (strcmp(type, "DM") == 0) {
		reset_cmd->cmd_root =
		    mm_text_to_par_node(reset_cmd->cmd_textcmd,
		    mms_dmpm_parse);
		reset_cmd->cmd_name = strdup("dmp reset");
	} else {
		reset_cmd->cmd_root =
		    mm_text_to_par_node(reset_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		reset_cmd->cmd_name = strdup("lmp reset");
	}
	reset_cmd->cmd_task = mm_get_task(reset_cmd->cmd_root);
	mm_add_depend(reset_cmd, cmd);

	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, reset_cmd);
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

	mm_clear_db(&dev_results);

	cmd->cmd_state = 1;
	mms_trace(MMS_DEBUG,
	    "added reset command for %s %s",
	    mgr_name, dev_name);

	return (MM_DISPATCH_DEPEND);


no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    5062,
	    MESS_END);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	return (rc);
}
