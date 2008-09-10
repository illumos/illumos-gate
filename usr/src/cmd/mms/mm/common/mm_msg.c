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


#include <sys/types.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <libpq-fe.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libintl.h>
#include <locale.h>
#include <ctype.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include <msg_sub.h>
#include <mms_cat.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_commands.h"
#include "mm_sql.h"
#include "mm_sql_impl.h"

static char *_SrcFile = __FILE__;
#define	NOT_FOUND() goto not_found

#define	MESS_EMERG_STR		"emergency"
#define	MESS_ALERT_STR		"alert"
#define	MESS_CRIT_STR		"critical"
#define	MESS_ERROR_STR		"error"
#define	MESS_WARN_STR		"warning"
#define	MESS_NOTICE_STR		"notice"
#define	MESS_INFO_STR		"information"
#define	MESS_DEBUG_STR		"debug"
#define	MESS_DEVP_STR		"developer"

#define	MESS_OPER_STR		"operator"
#define	MESS_ADMIN_STR		"administrator"
#define	MESS_LOG_STR		"log"

typedef struct {
	char		*msg_client;
	char		*msg_instance;
	char		*msg_host;

	int		slog_fd;
	char		slog_fname[PATH_MAX];
	uint64_t	slog_size;
	int		slog_sync;
	int		slog_count;
	mm_msg_sev_t	slog_level;
	uint64_t	slog_rot_size;
	pthread_mutex_t	slog_mutex;
} mm_msg_data_t;

/* message */
static int mm_msg_add_private(mm_wka_t *mm_wka, char *client, char *inst);
static int mm_msg_avail(mm_command_t *cmd);
static int mm_msg_fifo(mm_db_t *db, mm_msg_t *mess);

/* system log file */
static int mm_slog_open(mm_db_t *db);
static void mm_slog_close(void);
static void mm_slog_flush(void);
static int mm_slog(mm_msg_t *mess);

/* utility */
static char *mm_msg_sev2str(mm_msg_sev_t severity);
static mm_msg_sev_t mm_msg_str2sev(char *serverity);
static char *mm_msg_who2str(mm_msg_who_t who);
static mm_msg_who_t mm_msg_str2who(char *who);
static void mm_get_timestamp(mm_db_t *db, char *timestamp);

static mm_msg_data_t mm_msg_data;

int
mm_message_init(mm_db_t *db, mm_data_t *data)
{
	mms_cat_open();
	(void) setlocale(LC_MESSAGES, "");

	memset(&mm_msg_data, 0, sizeof (mm_msg_data_t));
	mm_msg_data.msg_client = data->mm_cfg.mm_network_cfg.cli_name;
	mm_msg_data.msg_instance = data->mm_cfg.mm_network_cfg.cli_inst;
	mm_msg_data.msg_host = data->mm_host_name;
	pthread_mutex_init(&mm_msg_data.slog_mutex, NULL);
	if (mm_slog_open(db)) {
		mms_trace(MMS_ERR, "unable to open system log file");
		return (1);
	}
	return (0);
}

void
mm_message_close(void)
{
	mm_slog_close();
	pthread_mutex_destroy(&mm_msg_data.slog_mutex);
	memset(&mm_msg_data, 0, sizeof (mm_msg_data_t));
	mm_msg_data.slog_fd = -1;
}

int
mm_msg_tracing_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_response_t	response;

	mms_trace(MMS_DEVP,
	    "mm_msg_tracing_cmd_func, state %d", cmd->cmd_state);

	/*
	 * Handle device manager change tracing private command
	 */

	if (cmd->cmd_state == 0) {
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		mms_trace(MMS_DEVP, "set tracing sent");
		cmd->cmd_flags |= MM_CMD_NEED_ACCEPT;
		cmd->cmd_state = 1;
		return (MM_ACCEPT_NEEDED);
	} else if (cmd->cmd_state == 1) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_ACCEPTED) {
			mms_trace(MMS_DEVP, "set tracing accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "set tracing success");
			cmd->cmd_remove = 1;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);
		}
		mms_trace(MMS_DEVP, "set tracing failed");
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	mms_trace(MMS_DEVP, "set tracing state");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

int
mm_msg_send_tracing(mm_wka_t *mm_wka)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	uuid_text_t	task;
	char		*buf;
	mm_command_t	*pvt_cmd;

	/*
	 * Add change tracing private command to command queue
	 */

	if (mm_wka->mm_wka_mm_lang == MM_LANG_LMP) {

		mms_trace(MMS_DEVP, "Set lmp tracing");

		if (mm_db_exec(HERE, db, "select \"LMMessageLevel\","
		    "\"TraceLevel\",\"TraceFileSize\" from \"LM\" where "
		    "\"LMName\" = '%s';", conn->cci_instance) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			return (1);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			return (1);
		}

		mm_get_uuid(task);

		buf = mms_strnew("private task[\"%s\"] "
		    "set[\"LMMessageLevel\" \"%s\" "
		    "\"TraceLevel\" \"%s\" "
		    "\"TraceFileSize\" \"%s\"];",
		    task,
		    PQgetvalue(db->mm_db_results, 0, 0),
		    PQgetvalue(db->mm_db_results, 0, 1),
		    PQgetvalue(db->mm_db_results, 0, 2));

		mm_clear_db(&db->mm_db_results);
		pvt_cmd = mm_alloc_cmd(mm_wka);
		pvt_cmd->cmd_textcmd = buf;
		pvt_cmd->cmd_root = mm_text_to_par_node(pvt_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		pvt_cmd->cmd_task = mm_get_task(pvt_cmd->cmd_root);
		pvt_cmd->wka_ptr = mm_wka;
		pvt_cmd->cmd_func = mm_msg_tracing_cmd_func;
		pvt_cmd->cmd_flags = MM_CMD_DISPATCHABLE;
		pvt_cmd->cmd_language = MM_LANG_LMP;
		pvt_cmd->cmd_name = strdup("lmp tracing");

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, pvt_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		mms_trace(MMS_DEVP, "Added set lmp tracing");

	} else if (mm_wka->mm_wka_mm_lang == MM_LANG_DMP) {

		mms_trace(MMS_DEVP, "Set dmp tracing");

		if (mm_db_exec(HERE, db, "select \"DMMessageLevel\","
		    "\"TraceLevel\",\"TraceFileSize\" from \"DM\" where "
		    "\"DMName\" = '%s';", conn->cci_instance) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			return (1);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			return (1);
		}

		mm_get_uuid(task);

		buf = mms_strnew("private task[\"%s\"] "
		    "set[\"DMMessageLevel\" \"%s\" "
		    "\"TraceLevel\" \"%s\" "
		    "\"TraceFileSize\" \"%s\"];",
		    task,
		    PQgetvalue(db->mm_db_results, 0, 0),
		    PQgetvalue(db->mm_db_results, 0, 1),
		    PQgetvalue(db->mm_db_results, 0, 2));

		mm_clear_db(&db->mm_db_results);


		pvt_cmd = mm_alloc_cmd(mm_wka);
		pvt_cmd->cmd_textcmd = buf;
		pvt_cmd->cmd_root = mm_text_to_par_node(pvt_cmd->cmd_textcmd,
		    mms_dmpm_parse);
		pvt_cmd->cmd_task = mm_get_task(pvt_cmd->cmd_root);
		pvt_cmd->wka_ptr = mm_wka;
		pvt_cmd->cmd_func = mm_msg_tracing_cmd_func;
		pvt_cmd->cmd_flags = MM_CMD_DISPATCHABLE;
		pvt_cmd->cmd_language = MM_LANG_DMP;
		pvt_cmd->cmd_name = strdup("dmp tracing");

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, pvt_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		mms_trace(MMS_DEVP, "Added set dmp tracing");
	}

	return (0);
}

static int
mm_msg_add_private(mm_wka_t *mm_wka, char *client, char *inst)
{
	mm_wka_t	*cli_wka;
	int		rc = 0;

	/* find client work area */
	mms_list_foreach(&mm_wka->mm_data->mm_wka_list, cli_wka) {

		/* only connected clients have work areas */
		if (strcmp(cli_wka->wka_conn.cci_client, client) == 0 &&
		    strcmp(cli_wka->wka_conn.cci_instance, inst) == 0) {

			/* send private command to change tracing */
			if (rc = mm_msg_send_tracing(cli_wka)) {
				break;
			}
		}
	}
	return (rc);
}

int
mm_msg_set_tracing(mm_wka_t *mm_wka, mm_command_t *cmd, int id)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	PGresult	*results;
	char		*query;
	int		row;
	char		*client;
	char		*inst;
	char		*level;
	char		*fsize;
	int		num;

	/*
	 * Change mm or device manager tracing
	 */

	if (id == LM) {

		/* clear path matching */
		mm_clear_source(cmd);
		mm_clear_dest(cmd);
		mm_clear_const(cmd);

		/* sql command */
		(void) mm_get_dest(mm_wka, cmd);
		(void) mm_get_const(mm_wka, cmd);
		(void) mm_add_match_list("LM", &cmd->cmd_source_list);
		if (mm_add_char("LM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_msg_set_tracing: "
			    "out of mem creating source list");
			return (1);
		}

		cmd->cmd_source_num = 1;

		query = "select distinct \"LM\".\"LibraryName\","
		    "\"LM\".\"LMName\" from ";
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(query) + 1);
		strcpy(cmd->cmd_buf, query);

		if (mm_sql_from_where(cmd, db)) {
			mms_trace(MMS_ERR,
			    "mm_msg_set_tracing: "
			    "db error creating helper functions");
			return (1);
		}
		mm_sql_order(cmd);
		mm_sql_number(cmd);

		if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
			mms_trace(MMS_ERR, "lm tracing");
			mm_clear_db(&db->mm_db_results);
			return (1);
		}
		if (PQntuples(db->mm_db_results) < 1) {
			mms_trace(MMS_ERR, "lm tracing results");
			mm_clear_db(&db->mm_db_results);
			/* see if any lms are configed */
			if (mm_db_exec(HERE, db, "select \"LM\".\"LMName\" "
			    "from \"LM\" limit 1;") != MM_DB_DATA) {
				mms_trace(MMS_ERR, "lms configed");
				mm_clear_db(&db->mm_db_results);
				return (1);
			}
			num = PQntuples(db->mm_db_results);
			PQntuples(db->mm_db_results);
			if (num == 0 && cmd->cmd_dest_num == 0) {
				/* no lms configured or specified */
				return (0);
			}
			/* lm not found */
			return (1);
		}
		results = db->mm_db_results;
		for (row = 0; row < PQntuples(results); row++) {
			client = PQgetvalue(results, row, 0);
			inst = PQgetvalue(results, row, 1);

			mms_trace(MMS_DEVP, "%d of %d - %s %s",
			    row,
			    PQntuples(results),
			    client,
			    inst);

			if (mm_msg_add_private(mm_wka, client, inst)) {
				mm_clear_db(&results);
				return (1);
			}
		}
		mm_clear_db(&results);

	} else if (id == DM) {

		/* clear path matching */
		mm_clear_source(cmd);
		mm_clear_dest(cmd);
		mm_clear_const(cmd);

		/* sql command */
		(void) mm_get_dest(mm_wka, cmd);
		(void) mm_get_const(mm_wka, cmd);
		(void) mm_add_match_list("DM", &cmd->cmd_source_list);
		if (mm_add_char("DM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_msg_set_tracing: "
			    "out of mem creating source list");
			return (1);
		}
		cmd->cmd_source_num = 1;

		query = "select distinct \"DM\".\"DriveName\","
		    "\"DM\".\"DMName\" from ";
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(query) + 1);
		strcpy(cmd->cmd_buf, query);


		if (mm_sql_from_where(cmd, db)) {
			mms_trace(MMS_ERR,
			    "mm_msg_set_tracing: "
			    "db error creating helper functions");
			return (1);
		}
		mm_sql_order(cmd);
		mm_sql_number(cmd);

		if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
			mms_trace(MMS_ERR, "dm tracing");
			mm_clear_db(&db->mm_db_results);
			return (1);
		}
		if (PQntuples(db->mm_db_results) < 1) {
			mms_trace(MMS_ERR, "dm tracing results");
			mm_clear_db(&db->mm_db_results);
			/* see if any dms are configed */
			if (mm_db_exec(HERE, db, "select \"DM\".\"DMName\" "
			    "from \"DM\" limit 1;") != MM_DB_DATA) {
				mms_trace(MMS_ERR, "dms configed");
				mm_clear_db(&db->mm_db_results);
				return (1);
			}
			num = PQntuples(db->mm_db_results);
			PQntuples(db->mm_db_results);
			if (num == 0 && cmd->cmd_dest_num == 0) {
				/* no dms configed or specified */
				return (0);
			}
			/* dm not found */
			return (1);
		}
		results = db->mm_db_results;
		for (row = 0; row < PQntuples(results); row++) {
			client = PQgetvalue(results, row, 0);
			inst = PQgetvalue(results, row, 1);

			mms_trace(MMS_DEVP, "%d of %d - %s %s",
			    row,
			    PQntuples(results),
			    client,
			    inst);

			if (mm_msg_add_private(mm_wka, client, inst)) {
				mm_clear_db(&results);
				return (1);
			}
		}
		mm_clear_db(&results);

	} else if (id == MM) {

		if (mm_db_exec(HERE, db, "select \"MessageLevel\", "
		    "\"TraceLevel\",\"TraceFileSize\" from \"SYSTEM\";")
		    != MM_DB_DATA) {
			mms_trace(MMS_ERR, "mm tracing");
			mm_clear_db(&db->mm_db_results);
			return (1);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR, "mm tracing results");
			mm_clear_db(&db->mm_db_results);
			return (1);
		}
		level = PQgetvalue(db->mm_db_results, 0, 1);
		fsize = PQgetvalue(db->mm_db_results, 0, 2);

		if (mms_trace_set_fsize(fsize)) {
			mms_trace(MMS_ERR, "invalid mms_trace fsize %s", fsize);
			return (1);
		}
		if (mms_trace_str_filter(level)) {
			mms_trace(MMS_ERR,
			    "invalid mms_trace filter %s", level);
			return (1);
		}
		mm_write_trace_level(mms_trace_get_severity());
		mm_clear_db(&db->mm_db_results);

	} else {
		mms_trace(MMS_ERR, "invalid id %d", id);
		return (1);
	}

	return (0);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);
}

int
mm_message_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mms_par_node_t	*clause;
	mms_par_node_t	*value;

	mms_trace(MMS_DEVP, "mm_message_cmd_func");

	/*
	 * Device manager message command
	 */

	cmd->cmd_msg.msg_flags |= MESS_FLAG_HANDLED;

	/* message command */
	MMS_PN_LOOKUP(clause, cmd->cmd_root, "who", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_KEYWORD, NULL);
	cmd->cmd_msg.msg_who = mm_msg_str2who(mms_pn_token(value));

	MMS_PN_LOOKUP(clause, cmd->cmd_root, "severity",
	    MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_KEYWORD, NULL);
	cmd->cmd_msg.msg_severity = mm_msg_str2sev(mms_pn_token(value));

	if (mm_msg_parse(cmd, cmd->cmd_root)) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INTERNAL) + strlen(MM_E_CMDARGS) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INTERNAL, MM_E_CMDARGS);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	mm_get_timestamp(db, cmd->cmd_msg.msg_timestamp);

	cmd->cmd_msg.msg_client_uuid = cmd->wka_ptr->wka_conn.cci_uuid;
	mm_get_uuid(cmd->cmd_msg.msg_uuid);
	cmd->cmd_msg.msg_type = mm_msg_lang2component(mm_wka->mm_wka_mm_lang);
	cmd->cmd_msg.msg_client = cmd->wka_ptr->wka_conn.cci_client;
	cmd->cmd_msg.msg_instance = cmd->wka_ptr->wka_conn.cci_instance;
	cmd->cmd_msg.msg_cid = cmd->wka_ptr->wka_conn.cci_uuid;
	cmd->cmd_msg.msg_host = cmd->wka_ptr->wka_conn.cci_host;

	/* add message to system log file */
	if (mm_slog(&cmd->cmd_msg)) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INTERNAL) + strlen(MM_E_INTERNAL) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INTERNAL, MM_E_INTERNAL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* add message to message fifo */
	if (mm_msg_fifo(db, &cmd->cmd_msg)) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INTERNAL) + strlen(MM_E_INTERNAL) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INTERNAL, MM_E_INTERNAL);
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
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
	    strlen(ECLASS_INTERNAL) + strlen(MM_E_CMDARGS) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_ERROR, cmd->cmd_task,
	    ECLASS_INTERNAL, MM_E_CMDARGS);
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}

static int
mm_msg_avail(mm_command_t *cmd)
{
	/*
	 * Tell caller if command contains message-clause
	 */

	if (mms_pn_lookup(cmd->cmd_root, "message", MMS_PN_CLAUSE, NULL)) {
		return (1); /* command has message-clause */
	}
	return (0);
}

int
mm_message_command(mm_command_t *cmd)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	mm_response_t	response;
	int		rc;

	mms_trace(MMS_DEVP, "mm_msg_command");

	/*
	 * Handle message in non-message command
	 */

	if (cmd->cmd_msg.msg_flags & MESS_FLAG_HANDLED) {
		return (0);	/* already handled this command's message */
	}
	cmd->cmd_msg.msg_flags |= MESS_FLAG_HANDLED;

	if (cmd->wka_ptr->mm_wka_mm_lang == MM_LANG_MMP) {
		return (0);		/* ignore messages in mmp commands */
	}

	if (mm_msg_avail(cmd) == 0)
		return (0);		/* command does not have a message */

	if (mm_msg_parse(cmd, cmd->cmd_root))
		return (0);		/* failed to parse command message */

	if (mm_parse_response(cmd->cmd_root, &response) == 0) {
		/* command response */
		switch (response.response_type) {
		case MM_RESPONSE_ERROR:
			cmd->cmd_msg.msg_severity = MESS_ERROR;
			break;

		case MM_RESPONSE_ACCEPTED:
		case MM_RESPONSE_UNACCEPTABLE:
		case MM_RESPONSE_SUCCESS:
		case MM_RESPONSE_CANCELLED:
		default:
			cmd->cmd_msg.msg_severity = MESS_INFO;
			break;
		}
	} else {
		/* not command response */
		cmd->cmd_msg.msg_severity = MESS_INFO;
	}

	mm_get_timestamp(db, cmd->cmd_msg.msg_timestamp);

	cmd->cmd_msg.msg_client_uuid = cmd->wka_ptr->wka_conn.cci_uuid;
	mm_get_uuid(cmd->cmd_msg.msg_uuid);
	cmd->cmd_msg.msg_type =
	    mm_msg_lang2component(cmd->wka_ptr->mm_wka_mm_lang);
	cmd->cmd_msg.msg_client = cmd->wka_ptr->wka_conn.cci_client,
	    cmd->cmd_msg.msg_instance = cmd->wka_ptr->wka_conn.cci_instance,
	    cmd->cmd_msg.msg_cid = cmd->wka_ptr->wka_conn.cci_uuid;
	cmd->cmd_msg.msg_host = cmd->wka_ptr->wka_conn.cci_host,
	    cmd->cmd_msg.msg_who = MESS_LOG;

	if ((rc = mm_slog(&cmd->cmd_msg)) == 0) {
		rc = mm_msg_fifo(db, &cmd->cmd_msg);
	}

	return (rc);
}

int
mm_message(mm_db_t *db, mm_msg_who_t who, mm_msg_sev_t severity,
    int messageid, ...)
{
	mm_msg_t	mess;
	va_list		args;
	int		rc;

	mms_trace(MMS_DEVP, "mm_message: %s %s %d",
	    mm_msg_who2str(who), mm_msg_sev2str(severity), messageid);

	memset(&mess, 0, sizeof (mm_msg_t));

	mm_get_timestamp(db, mess.msg_timestamp);

	mess.msg_client_uuid = NULL;
	mm_get_uuid(mess.msg_uuid);
	mess.msg_type = MESS_MM_STR;
	mess.msg_client = mm_msg_data.msg_client;
	mess.msg_instance = mm_msg_data.msg_instance;
	mess.msg_host = mm_msg_data.msg_host;
	mess.msg_who = who;
	mess.msg_severity = severity;
	mess.msg_manufacturer = MESS_MANUFACTURER;
	mess.msg_model = MESS_MODEL;
	mess.msg_messageid = messageid;
	mess.msg_lang = MESS_LANG;
	va_start(args, messageid);
	mess.msg_localized = mms_get_locstr(messageid, args);
	va_end(args);

	if ((rc = mm_slog(&mess)) == 0) {
		rc = mm_msg_fifo(db, &mess);
	}

	free(mess.msg_localized);

	return (rc);
}

int
mm_msg_exists(int message_id)
{
	char	*fmt;

	fmt = mms_get_cat_msg(message_id);
	if (fmt == NULL || fmt[0] == '\0') {
		return (0);
	}
	return (1);
}

int
mm_msg_parse(mm_command_t *cmd, mms_par_node_t *root)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*name;
	mms_par_node_t	*value;
	mms_par_node_t	*count;
	mms_par_node_t	*work;
	char		*p;
	char		*fmt;

	mms_trace(MMS_DEVP, "mm_msg_parse");

	/*
	 * Parse and localize command's message-clause
	 */

	/* message-clause */
	MMS_PN_LOOKUP(arg, root, "message", MMS_PN_CLAUSE, NULL);

	MMS_PN_LOOKUP(arg, root, "id", MMS_PN_CLAUSE, NULL);
	work = NULL;
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, &work);
	cmd->cmd_msg.msg_manufacturer = value->pn_string;

	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, &work);
	cmd->cmd_msg.msg_model = value->pn_string;

	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, &work);
	cmd->cmd_msg.msg_messageid = atoi(value->pn_string);

	/* locale-text-clause */
	count = NULL;
	while (arg = mms_pn_lookup(root, "loctext",
	    MMS_PN_CLAUSE, &count)) {

		work = NULL;
		value = mms_pn_lookup(arg, NULL, MMS_PN_STRING, &work);
		if (value == NULL)
			NOT_FOUND();
		cmd->cmd_msg.msg_lang = value->pn_string;

		value = mms_pn_lookup(arg, NULL, MMS_PN_STRING, &work);
		if (value == NULL)
			NOT_FOUND();
		cmd->cmd_msg.msg_text = value->pn_string;
	}

	/* lookup localized message */
	fmt = mms_get_cat_msg(cmd->cmd_msg.msg_messageid);
	if (fmt == NULL || fmt[0] == '\0') {
		/* no catalog message found so use default if it exists */
		mms_trace(MMS_DEVP, "catalog messageid %d not found",
		    cmd->cmd_msg.msg_messageid);
		if (cmd->cmd_msg.msg_text) {
			fmt = cmd->cmd_msg.msg_text;
		}
		if (fmt == NULL) {
			fmt = "\0";
		}
	}

	/* copy localized message */
	if (cmd->cmd_msg.msg_localized)
		free(cmd->cmd_msg.msg_localized);
	cmd->cmd_msg.msg_localized = strdup(fmt);

	/* arg-clause */
	if (arg = mms_pn_lookup(root, "arguments",
	    MMS_PN_CLAUSE, NULL)) {

		/* save arguments list */
		cmd->cmd_msg.msg_args = &arg->pn_arglist;

		/* substitue each text argument with value */
		mms_list_pair_foreach(&arg->pn_arglist, name, value) {

			if (name == NULL || value == NULL) {
				NOT_FOUND();
			}

			if ((p = mms_msg_sub(cmd->cmd_msg.msg_localized,
			    name->pn_string,
			    value->pn_string)) == NULL) {
				MM_ABORT_NO_MEM();
				return (1);
			}
			free(cmd->cmd_msg.msg_localized);
			cmd->cmd_msg.msg_localized = p;
		}
	}

	mms_trace(MMS_DEVP, "parsed message: %s %s %d - %s",
	    cmd->cmd_msg.msg_manufacturer,
	    cmd->cmd_msg.msg_model,
	    cmd->cmd_msg.msg_messageid,
	    cmd->cmd_msg.msg_localized);

	return (0);

not_found:
	mms_trace(MMS_DEVP, "parse message: not found");
	return (1);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);
}

static int
mm_msg_fifo(mm_db_t *db, mm_msg_t *mess)
{
	mm_msg_sev_t	sys_acc_level;
	int		sys_msg_limit;
	int		sys_msg_count;
	char		cid[UUID_PRINTF_SIZE + 3];
	char		*localized;

	mms_trace(MMS_DEVP, "mm_msg_fifo");

	/*
	 * Add message to mm's message fifo
	 */

	if (mm_db_exec(HERE, db, "select \"SystemAcceptLevel\","
	    "\"SystemMessageLimit\",\"SystemMessageCount\" from "
	    "\"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	sys_acc_level = mm_msg_str2sev(PQgetvalue(db->mm_db_results, 0, 0));
	sys_msg_limit = atoi(PQgetvalue(db->mm_db_results, 0, 1));
	sys_msg_count = atoi(PQgetvalue(db->mm_db_results, 0, 2));
	mm_clear_db(&db->mm_db_results);

	if (mess->msg_severity < sys_acc_level) {
		return (0);
	}

	if (sys_msg_limit == 0) {
		return (0);
	}

	if (mess->msg_cid == NULL) {
		(void) strlcpy(cid, "NULL", sizeof (cid));
	} else {
		(void) snprintf(cid, sizeof (cid), "'%s'", mess->msg_cid);
	}

	if ((localized = mm_db_escape_string(mess->
	    msg_localized)) == NULL) {
		mms_trace(MMS_ERR, "db mms_escape string - %s",
		    mess->msg_localized);
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	if (sys_msg_count < sys_msg_limit) {

		if (mm_db_exec(HERE, db, "insert into \"MESSAGE\" "
		    "(\"MessageID\","
		    "\"MessageSenderType\","
		    "\"MessageSenderName\","
		    "\"MessageSenderInstance\","
		    "\"MessageConnectionID\","
		    "\"MessageLevel\","
		    "\"MessageManufacturer\","
		    "\"MessageModel\","
		    "\"MessageNumber\","
		    "\"MessageText\","
		    "\"MessageTimeCreated\","
		    "\"MessageHost\") "
		    "values ('%s','%s','%s','%s',%s,"
		    "'%s','%s','%s','%d','%s','%s','%s');",
		    mess->msg_uuid,
		    mess->msg_type,
		    mess->msg_client,
		    mess->msg_instance,
		    cid,
		    mm_msg_sev2str(mess->msg_severity),
		    mess->msg_manufacturer,
		    mess->msg_model,
		    mess->msg_messageid,
		    localized,
		    mess->msg_timestamp,
		    mess->msg_host) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			free(localized);
			return (1);
		}
		free(localized);

		if (mm_db_exec(HERE, db, "update \"SYSTEM\" set "
		    "\"SystemMessageCount\" = '%d';",
		    sys_msg_count + 1) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			return (1);
		}

		if (db->mm_db_count != 1) {
			return (1);
		}

	} else {

		if (mm_db_exec(HERE, db, "update \"MESSAGE\" set "
		    "\"MessageID\" = '%s',"
		    "\"MessageSenderType\" = '%s',"
		    "\"MessageSenderName\" = '%s',"
		    "\"MessageSenderInstance\" = '%s',"
		    "\"MessageConnectionID\" = %s,"
		    "\"MessageLevel\" = '%s',"
		    "\"MessageManufacturer\" = '%s',"
		    "\"MessageModel\" = '%s',"
		    "\"MessageNumber\" = '%d',"
		    "\"MessageText\" = '%s',"
		    "\"MessageTimeCreated\" = '%s',"
		    "\"MessageHost\" = '%s' "
		    "where \"MessageID\" = (select \"MessageID\" from "
		    "\"MESSAGE\" order by \"MessageTimeCreated\" limit 1);",
		    mess->msg_uuid,
		    mess->msg_type,
		    mess->msg_client,
		    mess->msg_instance,
		    cid,
		    mm_msg_sev2str(mess->msg_severity),
		    mess->msg_manufacturer,
		    mess->msg_model,
		    mess->msg_messageid,
		    localized,
		    mess->msg_timestamp,
		    mess->msg_host) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			free(localized);
			return (1);
		}
		free(localized);

		if (db->mm_db_count != 1) {
			return (1);
		}
	}

	mess->msg_flags |= MESS_FLAG_FIFO;
	mms_trace(MMS_DEVP, "message added to fifo");

	return (0);
}

int
mm_msg_set_limit(mm_db_t *db)
{
	int limit;
	int count;
	int actual_count;

	mms_trace(MMS_DEVP, "mm_msg_set_limit");

	/*
	 * Change message fifo size.
	 */

	if (mm_db_exec(HERE, db, "select \"SystemMessageLimit\","
	    "\"SystemMessageCount\" from \"SYSTEM\";") != MM_DB_DATA) {
		return (1);
	}
	limit = atoi(PQgetvalue(db->mm_db_results, 0, 0));
	count = atoi(PQgetvalue(db->mm_db_results, 0, 1));
	mm_clear_db(&db->mm_db_results);

	if (mm_db_exec(HERE, db, "select \"MessageID\" "
	    "from \"MESSAGE\";") != MM_DB_DATA) {
		return (1);
	}
	actual_count = PQntuples(db->mm_db_results);
	mm_clear_db(&db->mm_db_results);

	if (count != actual_count) {
		count = actual_count;
	}

	/* remove excess messages from message fifo */
	while (count > limit) {
		/* remove oldest message */
		if (mm_db_exec(HERE, db, "delete from \"MESSAGE\" "
		    "where \"MessageID\" = (select \"MessageID\" "
		    "from \"MESSAGE\" "
		    "order by \"MessageTimeCreated\" "
		    "limit 1);") != MM_DB_OK) {
			return (1);
		}
		if (db->mm_db_count != 1) {
			return (1);
		}
		count--;
	}

	if (count < 0) {
		count = 0;
	}

	if (mm_db_exec(HERE, db, "update \"SYSTEM\" set "
	    "\"SystemMessageCount\" = '%d';", count) != MM_DB_OK) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	return (0);
}

/*
 * System Log File
 */

static int
mm_slog_open(mm_db_t *db)
{
	int		oflags = O_CREAT | O_RDWR | O_APPEND;
	struct stat	buf;

	mms_trace(MMS_DEVP, "mm_slog_open");

	if (mm_db_exec(HERE, db, "select \"SystemLogFile\" from "
	    "\"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR, "query system log file name");
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR, "missing system log file name");
		return (1);
	}
	snprintf(mm_msg_data.slog_fname, PATH_MAX,
	    "%s", PQgetvalue(db->mm_db_results, 0, 0));
	mm_clear_db(&db->mm_db_results);

	if (mm_slog_set_sync(db)) {
		mms_trace(MMS_ERR, "system log file sync");
		return (1);
	}

	if (mm_slog_set_level(db)) {
		mms_trace(MMS_ERR, "system log file level");
		return (1);
	}

	if (mm_slog_set_size(db)) {
		mms_trace(MMS_ERR, "system log file size");
		return (1);
	}

	mm_msg_data.slog_fd = open(mm_msg_data.slog_fname, oflags, 0644);
	if (mm_msg_data.slog_fd < 0) {
		mms_trace(MMS_ERR, "open %s %s", mm_msg_data.slog_fname,
		    strerror(errno));
		return (1);
	}

	if (fstat(mm_msg_data.slog_fd, &buf) != 0) {
		mms_trace(MMS_ERR, "fstat %s %s", mm_msg_data.slog_fname,
		    strerror(errno));
		close(mm_msg_data.slog_fd);
		mm_msg_data.slog_fd = -1;
		return (1);
	}

	mm_msg_data.slog_size = buf.st_size;

	return (0);
}

static void
mm_slog_close(void)
{
	mms_trace(MMS_DEVP, "mm_slog_close");
	close(mm_msg_data.slog_fd);
	mm_msg_data.slog_fd = -1;
}

static void
mm_slog_flush(void)
{
	(void) fsync(mm_msg_data.slog_fd);
}

static int
mm_slog(mm_msg_t *mess)
{
	char	*buf;
	int	len;
	char	*localized;

	/*
	 * Write message to system log file.
	 */

	if (mess->msg_severity > MESS_EMERG ||
	    mess->msg_severity < MESS_DEVP) {
		mms_trace(MMS_ERR, "invalid severity %d", mess->msg_severity);
		return (1);		/* invalid severity */
	}

	if (mess->msg_severity < mm_msg_data.slog_level) {
		return (0);		/* not logging this severity */
	}

	localized = mms_strpar_undo_escape_sequence(mess->msg_localized);
	if (localized == NULL) {
		mms_trace(MMS_ERR, "unable to localized message");
		return (1);		/* mms_escape sequence removal failed */
	}

	if ((buf = mms_strnew(
	    "%s %s %.2s %s %s %s %d %s\n",
	    mess->msg_timestamp,
	    mess->msg_host,
	    mess->msg_type,
	    mess->msg_client,
	    mess->msg_instance,
	    mm_msg_sev2str(mess->msg_severity),
	    mess->msg_messageid,
	    localized)) == NULL) {
		mms_trace(MMS_ERR, "message allocation failed");
		free(localized);
		return (1);
	}
	free(localized);

	len = strlen(buf);

	pthread_mutex_lock(&mm_msg_data.slog_mutex);
	if (write(mm_msg_data.slog_fd, buf, len) == len) {
		mess->msg_flags |= MESS_FLAG_SLOG;
	}
	free(buf);
	mm_msg_data.slog_size += len;
	mm_msg_data.slog_count++;

	/* flush system log file to disk */
	if (mm_msg_data.slog_count > mm_msg_data.slog_sync) {
		mm_slog_flush();
		mm_msg_data.slog_count = 0;
	}

	pthread_mutex_unlock(&mm_msg_data.slog_mutex);
	return (0);
}

int
mm_slog_set_fname(mm_db_t *db)
{
	int	rc;

	mms_trace(MMS_DEVP, "mm_slog_set_fname");

	pthread_mutex_lock(&mm_msg_data.slog_mutex);
	mm_slog_close();
	rc = mm_slog_open(db);
	pthread_mutex_unlock(&mm_msg_data.slog_mutex);
	return (rc);
}

int
mm_slog_set_sync(mm_db_t *db)
{
	mms_trace(MMS_DEVP, "mm_slog_set_sync");

	if (mm_db_exec(HERE, db, "select \"SystemSyncLimit\" from "
	    "\"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	mm_msg_data.slog_sync = atoi(PQgetvalue(db->mm_db_results, 0, 0));
	mm_clear_db(&db->mm_db_results);
	return (0);
}

int
mm_slog_set_level(mm_db_t *db)
{
	char		*level;

	mms_trace(MMS_DEVP, "mm_slog_set_level");

	if (mm_db_exec(HERE, db, "select \"SystemLogLevel\" from "
	    "\"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	level = PQgetvalue(db->mm_db_results, 0, 0);
	mm_msg_data.slog_level = mm_msg_str2sev(level);
	mm_clear_db(&db->mm_db_results);
	return (0);
}

int
mm_slog_set_size(mm_db_t *db)
{
	uint64_t	value;
	int		rc;
	char		*size;

	mms_trace(MMS_DEVP, "mm_slog_set_size");

	if (mm_db_exec(HERE, db, "select \"SystemLogFileSize\" from "
	    "\"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	size = PQgetvalue(db->mm_db_results, 0, 0);
	if ((rc = mms_trace_str_to_fsize(size, &value)) == 0) {
		mm_msg_data.slog_rot_size = value;
	}
	mm_clear_db(&db->mm_db_results);
	return (rc);
}

/*
 * Get message-clause strings
 */

void
mm_response_error(mm_command_t *cmd, char *eclass, char *ecode,
    int messageid, ...)
{
	va_list args;
	char *buf;
	char *text;

	mms_trace(MMS_ERR, "mm_response_error");
	mms_trace(MMS_ERR, "Class:: %s",
	    eclass);
	mms_trace(MMS_ERR, "Token:: %s",
	    ecode);
	mms_trace(MMS_ERR, "ID:: %d",
	    messageid);

	/*
	 * Get final-command response error with message-clause
	 */

	if (cmd->cmd_eclass != NULL) {
		free(cmd->cmd_eclass);
		cmd->cmd_eclass = NULL;
	}
	cmd->cmd_eclass = strdup(eclass);

	if (cmd->cmd_ecode != NULL) {
		free(cmd->cmd_ecode);
		cmd->cmd_ecode = NULL;
	}
	cmd->cmd_ecode = strdup(ecode);

	va_start(args, messageid);
	text = mms_bld_msgcl(messageid, args);
	va_end(args);

	buf = mms_strnew("response task[\"%s\"] error[%s %s] %s;",
	    cmd->cmd_task, eclass, ecode, text);
	free(text);

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(buf) + 1);
	strcpy(cmd->cmd_buf, buf);
	free(buf);
	return;

no_mem:
	MM_ABORT_NO_MEM();
}

static mm_msg_sev_t
mm_msg_str2sev(char *serverity)
{
	mm_msg_sev_t rc;

	/* convert mms severity string to enum. */
	if (strcmp(serverity, MESS_EMERG_STR) == 0) {
		rc = MESS_EMERG;
	} else if (strcmp(serverity, MESS_ALERT_STR) == 0) {
		rc = MESS_ALERT;
	} else if (strcmp(serverity, MESS_CRIT_STR) == 0) {
		rc = MESS_CRIT;
	} else if (strcmp(serverity, MESS_ERROR_STR) == 0) {
		rc = MESS_ERROR;
	} else if (strcmp(serverity, MESS_WARN_STR) == 0) {
		rc = MESS_WARN;
	} else if (strcmp(serverity, MESS_NOTICE_STR) == 0) {
		rc = MESS_NOTICE;
	} else if (strcmp(serverity, MESS_INFO_STR) == 0) {
		rc = MESS_INFO;
	} else if (strcmp(serverity, MESS_DEBUG_STR) == 0) {
		rc = MESS_DEBUG;
	} else {
		rc = MESS_DEVP;
	}
	return (rc);
}

/* Convert mms severity enum to string. */
char *
mm_msg_sev2str(mm_msg_sev_t severity)
{
	char *rc;

	if (severity == MESS_EMERG) {
		rc = MESS_EMERG_STR;
	} else if (severity == MESS_ALERT) {
		rc = MESS_ALERT_STR;
	} else if (severity == MESS_CRIT) {
		rc = MESS_CRIT_STR;
	} else if (severity == MESS_ERROR) {
		rc = MESS_ERROR_STR;
	} else if (severity == MESS_WARN) {
		rc = MESS_WARN_STR;
	} else if (severity == MESS_NOTICE) {
		rc = MESS_NOTICE_STR;
	} else if (severity == MESS_INFO) {
		rc = MESS_INFO_STR;
	} else if (severity == MESS_DEBUG) {
		rc = MESS_DEBUG_STR;
	} else {
		rc = MESS_DEVP_STR;
	}
	return (rc);
}

/* Convert message cmd who enum to string. */
static char *
mm_msg_who2str(mm_msg_who_t who)
{
	char *rc;

	if (who == MESS_OPER) {
		rc = MESS_OPER_STR;
	} else if (who == MESS_ADMIN) {
		rc = MESS_ADMIN_STR;
	} else {
		rc = MESS_LOG_STR;
	}
	return (rc);
}

static mm_msg_who_t
mm_msg_str2who(char *who)
{
	mm_msg_who_t rc;

	if (strcmp(who, MESS_OPER_STR) == 0) {
		rc = MESS_OPER;
	} else if (strcmp(who, MESS_ADMIN_STR) == 0) {
		rc = MESS_ADMIN;
	} else {
		rc = MESS_LOG;
	}
	return (rc);
}

/* Convert mms protocol language enum to message component string. */
char *
mm_msg_lang2component(mm_lang_t lang)
{
	char *rc;

	if (lang == MM_LANG_DMP) {
		rc = MESS_DM_STR;
	} else if (lang == MM_LANG_LMP) {
		rc = MESS_LM_STR;
	} else {
		rc = MESS_AI_STR;
	}
	return (rc);
}

static void
mm_get_timestamp(mm_db_t *db, char *timestamp)
{
	int		rc = 1;
	char		date[100];
	time_t		tm;
	struct tm	ltime;
	int		i;
	char		*p;

	/*
	 * Get timestamp with 3 digit millisecond
	 */

	if (db != NULL) {
		if (mm_db_exec(HERE, db, "select cast(current_timestamp as "
		    "timestamp(3)) as ts;") != MM_DB_DATA) {
			rc = 1;
		} else if (PQntuples(db->mm_db_results) != 1) {
			rc = 1;
		} else {
			memset(timestamp, 0, MM_TIMESTAMP);
			snprintf(timestamp, MM_TIMESTAMP, "%s",
			    PQgetvalue(db->mm_db_results, 0, 0));

			/* pad milliseconds with zeros */
			if (p = strrchr(timestamp, '.')) {
				for (i = 1; i <= 3; i++) {
					if (!isdigit(*(p+i))) {
						*(p+i) = '0';
					}
				}
			} else {
				/* zero milliseconds */
				strlcat(timestamp, ".000", MM_TIMESTAMP);
			}
			rc = 0;
		}
		mm_clear_db(&db->mm_db_results);
	}

	if (rc) {
		/* failed to get time from db so use system time */
		(void) time(&tm);
		(void) localtime_r(&tm, &ltime);
		(void) strftime(date, 100, "%Y-%m-%d %H:%M:%S.000", &ltime);
		strlcpy(timestamp, date, MM_TIMESTAMP);
	}
}
