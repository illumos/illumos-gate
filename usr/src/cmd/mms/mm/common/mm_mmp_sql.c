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
#include <unistd.h>
#include <libscf.h>
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
#include "mms_sock.h"
#include "net_cfg_service.h"
#include "mms_cfg.h"
#include "mms_cat.h"

static char *_SrcFile = __FILE__;

/*
 * Macros with a %s that create a function
 * need to be dropped before each use
 */

/* Need to drop GET_TYPE_SQL */
#define	GET_TYPE_SQL "CREATE FUNCTION gettype() RETURNS "	\
	"SETOF \"%s\" AS $$ SELECT * FROM \"%s\" %s; "		\
	"$$ LANGUAGE SQL;"

#define	GET_ID_SQL "select distinct \"CartridgeID\" "		\
	"from getcart() where \"CartridgeGroupName\" in "	\
	"(select distinct \"CartridgeGroupName\" "		\
	"from \"CARTRIDGEGROUPAPPLICATION\" "			\
	"where \"ApplicationName\" = '%s');"

#define	SELECT_CAP_GROUP "select distinct "	\
	"\"DMCapabilityGroupName\" from "	\
	"\"DMCAPABILITYGROUPTOKEN\" where "	\
	"\"DriveName\" = '%s';"

#define	SELECT_CAP_TOK "select \"DMCapabilityToken\" "			\
	"from \"DMCAPABILITYGROUPTOKEN\" where "			\
	"\"DMCapabilityGroupName\" = '%s' and "				\
	"\"DriveName\" = '%s' and \"DMCapabilityToken\" = '%s' "	\
	"and \"DMName\" "						\
	"in (select \"DMName\" from \"DM\" "				\
	"where pg_host_ident(\"DMTargetHost\") = pg_host_ident('%s'));"

#define	SELECT_DEFAULT_TOK "select \"DMCapabilityGroupDefaultName\" "	\
	"from \"DMCAPABILITYGROUP\" "					\
	"where \"DriveName\" = '%s' "					\
	"and \"DMCapabilityGroupName\" = '%s';"

extern int mm_attribute_match(mm_command_t *cmd);
extern void mm_print_char_list(mms_list_t *list);
extern int mm_add_char(char *str, mms_list_t *list);
extern int mm_sql_report_func_attr(mm_command_t *cmd);
extern int mm_sql_report_func(mm_command_t *cmd, mm_db_t *db);
extern int mm_get_set_clause(mm_command_t *cmd, mms_list_t *set_list,
    mms_list_t *obj_list);
extern int mm_notify_delete(mm_db_t *db, mm_command_t *cmd, char *objname,
    int match_off);
static int mm_change_attendance_mode(mm_wka_t *mm_wka);
extern void mm_cancel_cmd_buf(mm_command_t *cmd);
extern int mm_exiting;

void
mm_write_success(mm_command_t *cmd, char *fmt, ...) {
	va_list		args;
	char		*text;
	va_start(args, fmt);
	text = mms_vstrapp(NULL, fmt, args);
	va_end(args);
	if (text == NULL) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
		free(text);
		return;
	}
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_SUCCESS_TEXT_DQ) +
	    strlen(cmd->cmd_task) +
	    strlen(text) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_SUCCESS_TEXT_DQ, cmd->cmd_task, text);
	free(text);
	return;
no_mem:
	MM_ABORT_NO_MEM();
}


int
mm_add_lib_lm_activate(mm_command_t *parent, mm_wka_t *lm_wka, int type) {

	mm_command_t		*cmd;
	uuid_text_t		uuid;

	if (type == 1) {
		/* activate enable */
		mms_trace(MMS_DEVP, "add activate enable");
	} else if (type == 2) {
		/* activate disable */
		mms_trace(MMS_DEVP, "add activate disable");
	} else {
		mms_trace(MMS_ERR, "unknown type passed");
		return (1);
	}


	if ((cmd = mm_alloc_cmd(lm_wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		return (1);
	}
	mm_add_depend(cmd, parent);
	mm_get_uuid(uuid);
	cmd->cmd_root = NULL;
	cmd->cmd_task = NULL;
	cmd->cmd_task = strdup(uuid);
	if (cmd->cmd_task == NULL) {
		mms_trace(MMS_ERR, "Error malloc cmd_task in add cmd");
		return (1);
	}
	if (type == 1) {
		/* activate enable */
		cmd->cmd_textcmd = mms_strnew(ACTIVATE_ENABLE, cmd->cmd_task);
		cmd->cmd_name = strdup("lmp activate");
		if (cmd->cmd_name == NULL) {
			mms_trace(MMS_ERR, "Error malloc cmd->name "
			    "in add cmd");
			return (1);
		}
	} else if (type == 2) {
		/* activate disable */
		cmd->cmd_textcmd = mms_strnew(ACTIVATE_DISABLE, cmd->cmd_task);
		cmd->cmd_name = strdup("lmp activate");
		if (cmd->cmd_name == NULL) {
			mms_trace(MMS_ERR, "Error malloc cmd->name "
			    "in add cmd");
			return (1);
		}
	}
	cmd->cmd_func = mm_lmp_activate_cmd_func;
	cmd->cmd_root = mm_text_to_par_node(cmd->cmd_textcmd, mms_lmpm_parse);

	pthread_mutex_lock(&lm_wka->mm_data->mm_queue_mutex);
	mms_list_insert_tail(&lm_wka->mm_data->mm_cmd_queue, cmd);
	pthread_mutex_unlock(&lm_wka->mm_data->mm_queue_mutex);
	mms_trace(MMS_INFO,
	    "LM activate added, %s", lm_wka->wka_conn.cci_instance);

	return (0);
}

int
mm_libonline_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	mms_par_node_t		*arg;
	mms_par_node_t		*value;
	mms_par_node_t		*work;
	mms_par_node_t		*item;
	int			print_message = 1;
	int			rc;

	char			*lib_name = NULL;
	char			*lm_name = NULL;
	int			online = 0;
	int			offline = 0;
	int			lib_broken = 0;
	char			*cmd_buf = NULL;

	char			*response_message = NULL;

	mm_data_t	*mm_data = mm_wka->mm_data;
	mm_wka_t	*next;
	mm_wka_t	*cur_wka;
	int		found = 0;


	mms_trace(MMS_DEBUG, "mm_libonline_cmd_func");


	if (cmd->cmd_state == 2) {
		/* An activate command has completed */
		/* Check for errors */
		mms_trace(MMS_DEVP, "    cmd_state == 2");
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_ERR, "LM activate failed");
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    MM_5055_MSG,
			    "msg_rsp", response_message,
			    NULL);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		/* The sql command should still be cmd->cmd_buf */
		/* send it to the data base */

		if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_OK) {
			goto db_error;
		}

		/* Send Success */
		mm_path_match_report(cmd, db);
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		rc = MM_CMD_DONE;
		goto end;
	}



	/* Online clause */
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "online",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		if (print_message)
			mms_trace(MMS_DEVP, "online clause");
		item = NULL;

		/* Get Library Name */
		if ((value =
		    mms_pn_lookup(arg, NULL,
		    MMS_PN_STRING,
		    &item)) == NULL) {
			/* Missing a Library Name */
			mms_trace(MMS_ERR, "Missing a library Name");
			goto not_found;
		} else {
			/* Have a library Name */
			online = 1;
			lib_name = mms_strapp(lib_name,
			    value->pn_string);
			if (print_message)
				mms_trace(MMS_DEVP, "    %s",
				    value->pn_string);
		}
		/* Try to get LMName */
		if ((value =
		    mms_pn_lookup(arg, NULL,
		    MMS_PN_STRING,
		    &item)) == NULL) {
			/* Should never hit here... */
			/* Missing a LM Name */
			mms_trace(MMS_ERR, "Missing a LM Name");
			goto not_found;
		} else {
			/* Have a lm Name */
			lm_name = mms_strapp(lm_name,
			    value->pn_string);
			if (print_message)
				mms_trace(MMS_DEVP, "    %s",
				    value->pn_string);
		}

	} else {
		/* Didn't find a online clause */
		if (print_message)
			mms_trace(MMS_DEVP, "Didn't find a online clause");
	}

	/* Offline clause */
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "offline",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		if (print_message)
			mms_trace(MMS_DEVP, "offline clause");
		/* Get Drive Name */
		item = NULL;

		if ((value =
		    mms_pn_lookup(arg, NULL,
		    MMS_PN_STRING,
		    &item)) == NULL) {
			mms_trace(MMS_ERR, "Missing a library name");
			goto not_found;

		} else {
			/* Have the library name */
			offline = 1;
			lib_name = mms_strapp(lib_name,
			    value->pn_string);
			if (print_message)
				mms_trace(MMS_DEVP, "    %s",
				    value->pn_string);
		}

	} else {
		/* Didn't find a offline clause */
		if (print_message)
			mms_trace(MMS_DEVP, "Didn't find a offline clause");
	}

	if (online && offline) {
		/* Shouldn't ever get here */
		mms_trace(MMS_ERR, "Cannot have both an "
		    "online and offline clause");
		/*  ECLASS_LANGUAGE, ELIBRARYNOEXIST */
		mm_response_error(cmd,
		    ECLASS_LANGUAGE,
		    ETOOMANYCLAUSES,
		    MM_5057_MSG,
		    NULL);
		/* Create new error codes */
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto not_found;
	}

	/* Check Priv, library ownership */

	/* Check if library exists */
	/* Determine if the library is broken or not */
	if (mm_db_exec(HERE, db,
	    "select \"LibraryName\",\"LibraryBroken\" "
	    "from \"LIBRARY\" where "
	    "\"LibraryName\" = '%s';",
	    lib_name) != MM_DB_DATA) {
		goto db_error;
	} else {
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR, "Library does not exist");
			/* No library exists */
			/*  ECLASS_EXIST, ELIBRARYNOEXIST */
			mm_response_error(cmd,
			    ECLASS_EXIST,
			    ELIBRARYNOEXIST,
			    MM_5058_MSG,
			    NULL);
			/* Create new error codes */
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;

		} else {
			if (strcmp(PQgetvalue(db->mm_db_results,
			    0, 1), "t") == 0) {
				mms_trace(MMS_INFO, "Library %s is broken",
				    lib_name);
				lib_broken = 1;
			}
		}
	}


	mm_clear_db(&db->mm_db_results);
	if (online) {
		/* If library is broken, error */
		if (lib_broken) {
			/* Library is broken */
			mms_trace(MMS_ERR, "Library broken");
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    "ELIBBROKEN",
			    MM_5044_MSG,
			    NULL);
			/* Create new error codes */
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		/* Is the library already online */

		if (mm_db_exec(HERE, db,
		    "select \"LibraryName\" "
		    "from \"LIBRARY\" where "
		    "\"LibraryName\" = '%s'"
		    "and \"LibraryOnline\" = 'true';",
		    lib_name) != MM_DB_DATA) {
			goto db_error;
		} else {
			if (PQntuples(db->mm_db_results) == 1) {
				mms_trace(MMS_ERR, "Library already online");
				/* Library already online */
				/*  ECLASS_PREMPRIV, ELIBALREADYONLINE */
				mm_response_error(cmd,
				    ECLASS_PERMPRIV,
				    "ELIBALREADYONLINE",
				    MM_5059_MSG,
				    "lib",
				    lib_name,
				    NULL);
				/* Create new error codes */
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;

			}
		}
		mm_clear_db(&db->mm_db_results);
		/* Check if LM exists */
		if (mm_db_exec(HERE, db,
		    "select \"LMName\" "
		    "from \"LM\" where "
		    "\"LMName\" = '%s';",
		    lm_name) != MM_DB_DATA) {
			goto db_error;
		} else {
			if (PQntuples(db->mm_db_results) != 1) {
				mms_trace(MMS_ERR, "LM does not exist");
				/* No lm exists */
				/*  ECLASS_EXIST, ELMNOEXIST */
				mm_response_error(cmd,
				    ECLASS_EXIST,
				    ELMNOEXIST,
				    MM_5060_MSG,
				    NULL);
				/* Create new error codes */
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;

			}
		}

		/* Do online specific checks */

		/* Do online */
		cmd_buf = mms_strapp(cmd_buf,
		    "update \"LIBRARY\" set "
		    "\"LMName\" = '%s', "
		    "\"LibraryOnline\" = 'true', "
		    "\"LibraryDisabled\" = 'false', "
		    "\"LibraryBroken\" = 'f' "
		    "where \"LibraryName\" = '%s';",
		    lm_name,
		    lib_name);
	} else if (offline) {

		/* Do offline specific checks */
		/* Is the library already offline */

		if (mm_db_exec(HERE, db,
		    "select \"LibraryName\" "
		    "from \"LIBRARY\" where "
		    "\"LibraryName\" = '%s'"
		    "and \"LibraryOnline\" = 'false';",
		    lib_name) != MM_DB_DATA) {
			goto db_error;
		} else {
			if (PQntuples(db->mm_db_results) == 1) {
				mms_trace(MMS_ERR, "Library already offline");
				/* Library already offline */
				/*  ECLASS_PREMPRIV, ELIBALREADYOFFLINE */
				mm_response_error(cmd,
				    ECLASS_PERMPRIV,
				    "ELIBALREADYOFFLINE",
				    MM_5061_MSG,
				    "lib",
				    lib_name,
				    NULL);
				/* Create new error codes */
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;

			}
		}
		mm_clear_db(&db->mm_db_results);
		/* Find the controlling LM's name */
		if (mm_db_exec(HERE, db,
		    "select \"LMName\" "
		    "from \"LIBRARY\" where "
		    "\"LibraryName\" = '%s';",
		    lib_name) != MM_DB_DATA) {
			goto db_error;
		} else {
			lm_name =
			    mms_strapp(lm_name, PQgetvalue(db->mm_db_results,
			    0, 0));
		}
		/* Do offline */
		cmd_buf = mms_strapp(cmd_buf,
		    "update \"LIBRARY\" set "
		    "\"LMName\" = NULL, "
		    "\"LibraryOnline\" = 'false', "
		    "\"LibraryBroken\" = 'false' "
		    "where \"LibraryName\" = '%s';",
		    lib_name);
		/* Update states */
		cmd_buf = mms_strapp(cmd_buf,
		    " delete from \"SLOT\" where"
		    "\"LMName\" = '%s'; "
		    " delete from \"BAY\" where"
		    "\"LMName\" = '%s'; "
		    " delete from \"SLOTGROUP\" where"
		    "\"LMName\" = '%s'; "
		    "update \"DRIVE\" "
		    "set \"BayName\" = DEFAULT "
		    "where \"LibraryName\" = '%s';",
		    lm_name,
		    lm_name,
		    lm_name,
		    lib_name);
	} else {
		/* Shouldn't ever get here */
		mms_trace(MMS_ERR, "Missing an online or offline clause");
		goto not_found;
	}

	/* Send cmd_buf to data base */
	if (print_message)
		mms_trace(MMS_DEVP, "\n%s\n",
		    cmd_buf);


	/* Create activate enable/disable commands to dispatch */
	/* if no lm is connected, return success */

	for (cur_wka = mms_list_head(&mm_data->mm_wka_list);
	    cur_wka != NULL;
	    cur_wka = next) {
		next = mms_list_next(&mm_data->
		    mm_wka_list, cur_wka);
		if ((strcmp(cur_wka->wka_conn.cci_client,
		    lib_name) == 0) &&
		    (strcmp(cur_wka->wka_conn.cci_instance,
		    lm_name) == 0)) {
			found = 1;
			break;
		}
	}
	/* If this is an offline and the library is broken */
	/* skip the activate disable */
	if (!found) {
		mms_trace(MMS_DEVP, "LM is not connected");
	} else if (!lib_broken) {
		mms_trace(MMS_DEVP, "LM is connected");
		if (online) {
			mms_trace(MMS_DEVP, "Adding activate enable");

			if (mm_add_lib_lm_activate(cmd, cur_wka, 1)) {
				mms_trace(MMS_ERR,
				    "mm_libonline_cmd_func: "
				    "could not add "
				    "lm activate enable");
				mm_system_error(cmd,
				    "could not add "
				    "lm activate enable");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			cmd->cmd_state = 2;
			rc = MM_DISPATCH_DEPEND;
			/* Copy local cmd_buf into cmd->cmd_buf */
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(cmd_buf) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    "%s", cmd_buf);
			goto end;
		} else if (offline) {
			mms_trace(MMS_DEVP, "Adding activate disable");
			if (mm_add_lib_lm_activate(cmd, cur_wka, 2)) {
				mms_trace(MMS_ERR,
				    "mm_libonline_cmd_func: "
				    "could not add "
				    "lm activate disable");
				mm_system_error(cmd,
				    "could not add "
				    "lm activate disable");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			cmd->cmd_state = 2;
			rc = MM_DISPATCH_DEPEND;
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(cmd_buf) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    "%s", cmd_buf);
			goto end;
		}
	} else {
		mms_trace(MMS_DEVP, "LM connected and library broken, "
		    "skipping activate");
	}
	/* Send success for non-connected LM's */
	mm_clear_db(&db->mm_db_results);
	if (mm_db_exec(HERE, db, cmd_buf) != MM_DB_OK) {
		goto db_error;
	}
	/* Send Success */
	mm_path_match_report(cmd, db);
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	rc = MM_CMD_DONE;
	goto end;

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;

	goto end;
end:
	mm_clear_db(&db->mm_db_results);
	if (cmd_buf)
		free(cmd_buf);
	if (lib_name)
		free(lib_name);
	if (lm_name)
		free(lm_name);
	return (rc);

}

int
mm_drvonline_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	mms_par_node_t		*arg;
	mms_par_node_t		*value;
	mms_par_node_t		*work;
	mms_par_node_t		*item;
	int			print_message = 1;
	int			rc;

	char			*drive_name = NULL;
	int			online = 0;
	int			offline = 0;

	char			*cmd_buf = NULL;

	mm_wka_t		*dm_wka;

	mms_trace(MMS_DEBUG, "mm_drvonline_cmd_func");

	/*
	 * NOTES:  May need to issue a scan command to LM to
	 * determine the current state of the drive.
	 * What to do in error cases?
	 */

	/* Online clause */
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "online",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		if (print_message)
			mms_trace(MMS_DEVP, "online clause");
		/* Get Drive Name */
		item = NULL;

		if ((value =
		    mms_pn_lookup(arg, NULL,
		    MMS_PN_STRING,
		    &item)) == NULL) {
			mms_trace(MMS_ERR, "Missing a drive name");
			goto not_found;

		} else {
			/* Have the drive name */
			online = 1;
			drive_name = mms_strapp(drive_name,
			    value->pn_string);
			if (print_message)
				mms_trace(MMS_DEVP, "    %s",
				    value->pn_string);
		}

	} else {
		/* Didn't find a online clause */
		if (print_message)
			mms_trace(MMS_DEVP, "Didn't find a online clause");
	}

	/* Offline clause */
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "offline",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		if (print_message)
			mms_trace(MMS_DEVP, "offline clause");
		/* Get Drive Name */
		item = NULL;

		if ((value =
		    mms_pn_lookup(arg, NULL,
		    MMS_PN_STRING,
		    &item)) == NULL) {
			mms_trace(MMS_ERR, "Missing a drive name");
			goto not_found;

		} else {
			/* Have the drive name */
			offline = 1;
			drive_name = mms_strapp(drive_name,
			    value->pn_string);
			if (print_message)
				mms_trace(MMS_DEVP, "    %s",
				    value->pn_string);
		}

	} else {
		/* Didn't find a offline clause */
		if (print_message)
			mms_trace(MMS_DEVP, "Didn't find a offline clause");
	}

	if (online && offline) {
		/* Shouldn't ever get here */
		mms_trace(MMS_ERR, "Cannot have both an "
		    "online and offline clause");
		goto not_found;
	}

	/* Check if drive exists */
	if (mm_db_exec(HERE, db,
	    "select \"DriveName\" "
	    "from \"DRIVE\" where "
	    "\"DriveName\" = '%s';",
	    drive_name) != MM_DB_DATA) {
		goto db_error;
	} else {
		if (PQntuples(db->mm_db_results) != 1) {
			/* No drive exists */
			mms_trace(MMS_ERR, "Drive does not exist");
			/*  ECLASS_EXIST, EDRIVENOEXIST */
			mm_response_error(cmd,
			    ECLASS_EXIST,
			    EDRIVENOEXIST,
			    MM_5063_MSG,
			    NULL);
			/* Create new error codes */
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			mm_clear_db(&db->mm_db_results);
			goto end;
		}
	}
	mm_clear_db(&db->mm_db_results);

	/* Check Priv, drive group ownership */


	if (online) {
		/* Do online specific checks */
		/* Is drive already online? */
		if (mm_db_exec(HERE, db,
		    "select \"DriveName\" "
		    "from \"DRIVE\" where "
		    "\"DriveName\" = '%s'"
		    " and \"DriveOnline\" = 'true';",
		    drive_name) != MM_DB_DATA) {
			goto db_error;
		} else {
			if (PQntuples(db->mm_db_results) == 1) {
				mms_trace(MMS_ERR, "Drive already on line");
				/* Drive Already online */
				/*  ECLASS_PREMPRIV, EDRIVEONLINE */

				mm_response_error(cmd,
				    ECLASS_PERMPRIV,
				    "EDRIVEALREADYONLINE",
				    MM_5064_MSG,
				    "drive",
				    drive_name,
				    NULL);
				/* Create new error codes */
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;

			}
		}
		mm_clear_db(&db->mm_db_results);
		/* Do online */
		/* clear DriveDisabled DriveBroken */
		/* don't clear DriveLibraryAccess or DriveNeedsCleaning */
		cmd_buf = mms_strapp(cmd_buf,
		    "update \"DRIVE\" set "
		    "\"DriveOnline\" = 't', "
		    "\"DriveDisabled\" = 'false', "
		    "\"DriveBroken\" = 'f' where "
		    "\"DriveName\" = '%s';",
		    drive_name);
	} else if (offline) {
		/* Do offline specific checks */

		/* Check if drive has a tape currently mounted */
		if (mm_db_exec(HERE, db,
		    " select \"DriveName\" "
		    "from \"DRIVE\" where "
		    "\"CartridgePCL\" ISNULL "
		    "and  \"DriveStateHard\" "
		    "= 'unloaded' and "
		    "\"DriveName\" = '%s';",
		    drive_name) != MM_DB_DATA) {
			goto db_error;
		} else {
			if (PQntuples(db->mm_db_results) != 1) {
				mms_trace(MMS_ERR, "Drive has tape loaded");
				/* Drive Already online */
				mm_response_error(cmd,
				    ECLASS_INTERNAL,
				    "EMNTCARTPRES",
				    MM_5065_MSG,
				    "drive",
				    drive_name,
				    NULL);
				/* Create new error codes */
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;

			}
		}
		mm_clear_db(&db->mm_db_results);
		if (mm_db_exec(HERE, db,
		    "select \"DriveName\" "
		    "from \"DRIVE\" where "
		    "\"DriveName\" = '%s'"
		    " and \"DriveOnline\" = 'false';",
		    drive_name) != MM_DB_DATA) {
			goto db_error;
		} else {
			if (PQntuples(db->mm_db_results) == 1) {
				mms_trace(MMS_ERR, "Drive already off line");
				/* Drive Already offline */
				/*  ECLASS_PREMPRIV, EDRIVEOFFLINE */
				mm_response_error(cmd,
				    ECLASS_PERMPRIV,
				    "EDRIVEALREADYOFFLINE",
				    MM_5066_MSG,
				    "drive",
				    drive_name,
				    NULL);
				/* Create new error codes */
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;

			}
		}
		mm_clear_db(&db->mm_db_results);
		/*
		 * Don't allow offline if drive
		 * has cartridge mounted?
		 */

		/* Do offline */
		cmd_buf = mms_strapp(cmd_buf,
		    "update \"DRIVE\" set \"DriveOnline\" = "
		    "'false' where \"DRIVE\".\"DriveName\" = '%s';",
		    drive_name);
	} else {
		/* Shouldn't ever get here */
		mms_trace(MMS_ERR, "Missing an online or offline clause");
		goto not_found;
	}

	/* Send cmd_buf to data base */
	if (print_message)
		mms_trace(MMS_DEVP, "\n%s\n",
		    cmd_buf);

	/* Add events */
	if (online) {
		if (mm_notify_add_driveonline(mm_wka, cmd, drive_name)) {
			mms_trace(MMS_ERR,
			    "mm_drvonline_cmd_func: "
			    "error adding drive online event");
		}
	}

	if (offline) {
		if (mm_notify_add_driveoffline(mm_wka, cmd, drive_name)) {
			mms_trace(MMS_ERR,
			    "mm_drvonline_cmd_func: "
			    "error adding drive offline event");
		}
	}


	if (mm_db_exec(HERE, db, cmd_buf) != MM_DB_OK) {
		goto db_error;
	}
	/* Add any activate enables for DM's */
	/* These will run as independent commands */
	dm_wka = NULL;
	mms_list_foreach(&mm_wka->mm_data->mm_wka_list, dm_wka) {
		if (strcmp(dm_wka->wka_conn.cci_client,
		    drive_name) == 0) {
			if (online) {
				/* Found the wka of dm for this drive */
				if (mm_drive_dm_activate_enable(dm_wka)
				    == NULL) {
					mms_trace(MMS_DEVP,
					    "Failed to add activate enable");
				} else {
					mms_trace(MMS_DEVP,
					    "added activate enable for %s %s",
					    dm_wka->wka_conn.cci_instance,
					    dm_wka->wka_conn.cci_client);
				}
			} else {
				if (mm_drive_dm_activate_disable(dm_wka)) {
					mms_trace(MMS_DEVP,
					    "Failed to add activate enable");
				} else {
					mms_trace(MMS_DEVP,
					    "added activate enable for %s %s",
					    dm_wka->wka_conn.cci_instance,
					    dm_wka->wka_conn.cci_client);
				}

			}
		}

	}
	/* Send Success */

	mm_path_match_report(cmd, db);
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	rc = MM_CMD_DONE;
	goto end;

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;
end:
	mm_clear_db(&db->mm_db_results);
	if (cmd_buf)
		free(cmd_buf);
	if (drive_name)
		free(drive_name);
	return (rc);
}
#define	NOTIFY_NEW "INSERT"
#define	NOTIFY_DELETE "DELETE"
#define	NOTIFY_CHANGE "UPDATE"
#define	NOTIFY_NEW_OBJ "NEW"
#define	NOTIFY_DELETE_OBJ "OLD"

int
mm_build_event_rule(mm_command_t *cmd, mm_db_t *db, uuid_text_t *notify_uuid,
    char *action, mms_par_node_t *data_clause) {
	char *buf = NULL;
	char *rule_buf = NULL;
	mm_path_t *path = NULL;
	char *joined[100];
	int joined_count = 0;
	int skip = 0;
	int wrote_one = 0;
	int y;
	int j;
	int k;
	int x;
	int l;
	int p;

	char *source_buf;
	char *dest_buf;

	int print_message = 0;

	mm_pkey_t *source_pkey;

	char	*sql_action;
	char	*sql_object;

	mms_par_node_t		*data_string = NULL;
	mms_par_node_t		*work = NULL;

	mms_trace(MMS_DEBUG, "mm_build_event_rule");

	/* map action string to the correct sql thingys */
	if (strcmp(action, "add") == 0) {
		sql_action = NOTIFY_NEW;
		sql_object = NOTIFY_NEW_OBJ;
	}
	if (strcmp(action, "change") == 0) {
		sql_action = NOTIFY_CHANGE;
		sql_object = NOTIFY_NEW_OBJ;
	}
	if (strcmp(action, "delete") == 0) {
		sql_action = NOTIFY_DELETE;
		sql_object = NOTIFY_DELETE_OBJ;
	}


	for (y = 0; y < 100; y ++) {
		joined[y] = NULL;
	}

	source_buf =
	    (char *)mm_return_char(&cmd->cmd_source_list, 0);
	/* sohuld be only 1 source */
	buf = mms_strapp(buf,
	    "from \"%s\" ",
	    source_buf);
	joined_count = 0;
	joined[0] = NULL;
	joined[0] = mms_strapp(joined[0], source_buf);

	joined_count ++;
	for (j = 0; j < cmd->cmd_dest_num; j ++) {
		dest_buf =
		    (char *)mm_return_char(&cmd->cmd_dest_list, j);

		if (print_message) {
			mms_trace(MMS_DEVP, "    1) Dest %d -> %s",
			    j, dest_buf);

			mms_trace(MMS_DEVP, "mm_get_path(%s, %s)",
			    dest_buf,
			    source_buf);
		}


		if ((path = mm_get_path(dest_buf,
		    source_buf)) == NULL) {
			mms_trace(MMS_DEVP, "Path is NULL, %s to %s",
			    dest_buf,
			    source_buf);

		} else {
			for (k = 0; k < path->mm_node_num; k++) {
				skip = 0;
				for (x = 0; x < joined_count; x++) {

					if (strcmp(joined[x],
					    path->mm_node[k]->mm_obj) == 0) {
						/* same so skip */
						skip = 1;
					}
				}
				if (!skip) {
					buf = mms_strapp(buf,
					    "\ncross join \"%s\" ",
					    path->mm_node[k]->mm_obj);

					joined[joined_count] = NULL;
					joined[joined_count] =
					    mms_strapp(joined[joined_count],
					    path->mm_node[k]->mm_obj);
					joined_count ++;
				}
			}
		}

	}


	for (j = 0; j < cmd->cmd_dest_num; j ++) {
		/* j cmd_dest_num */
		if (j == 0) {
			buf = mms_strapp(buf,
			    "\nwhere \n(\n");
		}
		dest_buf =
		    (char *)mm_return_char(&cmd->cmd_dest_list, j);
		if (print_message) {
			mms_trace(MMS_DEVP, "    2) Dest %d -> %s",
			    j, dest_buf);
			mms_trace(MMS_DEVP, "mm_get_path(%s, %s)",
			    dest_buf,
			    source_buf);
		}

		if ((path = mm_get_path(dest_buf,
		    source_buf)) == NULL) {

			if (strcmp(dest_buf,
			    source_buf) == 0) {
				/* same object */
				buf = mms_strapp(buf, "(true)\n");
				wrote_one = 1;
			} else {
				/* no path between */
				buf = mms_strapp(buf, "(false)\n");
				wrote_one = 1;
			}

		} else {


			for (k = path->mm_node_num - 1; k >= 0; k--) {

				/* node[%d] has %d edges, k, */
				/* path->mm_node[k]->mm_edge_num */
				for (l = 0;
				    l < path->mm_node[k]->mm_edge_num;
				    l++) {
					/*
					 * if (path->mm_node[k]->
					 *   mm_edge[l]->mm_ref_att != NULL) {
					 *
					 * }
					 */

					/* add this edge constraint */
					wrote_one = 1;
					if (k == path->mm_node_num - 1) {
						buf = mms_strapp(buf,
						    "(\"%s\".",
						    source_buf);
					} else {
						buf = mms_strapp(buf,
						    "(\"%s\".",
						    path->mm_node
						    [k+1]->mm_obj);
					}
					if (path->mm_node[k]->
					    mm_edge[l]->mm_ref_att == NULL) {
						buf = mms_strapp(buf,
						    "\"%s\" = ",
						    path->mm_node[k]->
						    mm_edge[l]->mm_att);
					} else {
						buf = mms_strapp(buf,
						    "\"%s\" = ",
						    path->mm_node[k]->
						    mm_edge[l]->mm_ref_att);
					}
					buf = mms_strapp(buf,
					    "\"%s\".\"%s\")\n",
					    path->mm_node[k]->mm_obj,
					    path->mm_node[k]->
					    mm_edge[l]->mm_att);

					if (l+1 < path->mm_node[k]->
					    mm_edge_num) {
						buf = mms_strapp(buf, "and\n");
					}

				}


				if (k - 1 >= 0) {
					buf = mms_strapp(buf, "and\n");
				}

			}

		}
		if (j + 1 < cmd->cmd_dest_num) {
			buf = mms_strapp(buf, "and\n");
		}



		if (j + 1 == cmd->cmd_dest_num) {
			/* Add all constraints here */

			for (p = 0;
			    p < cmd->cmd_const_num;
			    p ++) {
				if (p == 0) {
					if (wrote_one)
						buf = mms_strapp(buf,
						    "and\n(\n");
				}
				buf = mms_strapp(buf,
				    (char *)
				    mm_return_char(&cmd->
				    cmd_const_list, p));
				if (p+1 < cmd->cmd_const_num) {
					buf =
					    mms_strapp(buf,
					    "and\n");
				}
				if (p + 1 ==
				    cmd->cmd_const_num) {
					/* parenn for constraints */
					buf = mms_strapp(buf, ")\n");
				}
			}
			/* paren for where ( */
			if (wrote_one) {
				buf = mms_strapp(buf,
				    ")\n");
			} else {
				buf = mms_strapp(buf,
				    "\n");
			}
		}

	}

	for (y = 0; y < joined_count; y ++) {
		free(joined[y]);
		joined[y] = NULL;
	}

	/* now build the ru1le buf, we use buf for each pkey in source */
	rule_buf = mms_strapp(rule_buf,
	    "CREATE RULE \"%s\" AS ON %s TO \"%s\" "
	    "WHERE ( ", notify_uuid, sql_action, source_buf);

	source_pkey = mm_get_pkey(source_buf);
	for (j = 0; j < source_pkey->mm_att_num; j ++) {
		/* p_key->mm_att[j] */
		if (j != 0) {
			rule_buf = mms_strapp(rule_buf, "and\n");

		}
		rule_buf = mms_strapp(rule_buf,
		    "(%s.\"%s\" in "
		    "(select distinct \"%s\".\"%s\" %s))",
		    sql_object,
		    source_pkey->mm_att[j],
		    source_buf,
		    source_pkey->mm_att[j],
		    buf);

	}
	if (data_clause == NULL) {
		rule_buf = mms_strapp(rule_buf,
		    ") DO INSERT INTO \"EVENTRULES\" VALUES ('%s', '%s');",
		    notify_uuid, source_buf);
	} else {
		rule_buf = mms_strapp(rule_buf,
		    ") DO INSERT INTO \"EVENTRULES\" VALUES ('%s', '%s'",
		    notify_uuid, source_buf);
		while ((data_string = mms_pn_lookup(data_clause,
		    NULL, MMS_PN_STRING, &work)) != NULL) {
			/* Determine if data needs to be cast */
			if (mm_db_exec(HERE, db,
			    "select \"%s\""
			    " from \"%s\" limit 1;",
			    data_string->pn_string,
			    source_buf) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "error checking type "
				    "of data attribute");
				mm_sql_db_err_rsp_new(cmd, db);
				free(buf);
				free(rule_buf);
				return (1);
			}
			if (PQftype(db->mm_db_results, 0) ==
			    db->mm_db_cfg->mm_db_bool_oid) {
				/* column is a bool */
				rule_buf = mms_strapp(rule_buf,
				    ", bool_to_text(%s.\"%s\")",
				    sql_object,
				    data_string->pn_string);
			} else {
				/* Column is not a bool */
				/* int, timestamp etc work w/o cast */
				rule_buf = mms_strapp(rule_buf,
				    ", %s.\"%s\"",
				    sql_object,
				    data_string->pn_string);
			}
			mm_clear_db(&db->mm_db_results);
		}
		rule_buf = mms_strapp(rule_buf, ");");
	}


	if (mm_db_exec(HERE, db, rule_buf) != MM_DB_OK) {
		mms_trace(MMS_ERR, "Error adding rule");
		mm_sql_db_err_rsp_new(cmd, db);
		free(buf);
		free(rule_buf);
		return (1);
	}


	/* Free char buf */
	free(buf);
	free(rule_buf);
	return (0);

}

int
mm_notify_chg_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	cci_t			*conn = &mm_wka->wka_conn;
	char			*db_buf = NULL;

	mms_par_node_t		*cmd_root;

	char			*object = NULL;
	char			*tag = NULL;



	/* Receive clause */
	uuid_text_t		notify_uuid;

	mms_par_node_t		*receive_work = NULL;
	mms_par_node_t		*receive_node = NULL;
	mms_par_node_t		*receive_clause = NULL;
	mms_par_node_t		*receive_to_clause = NULL;
	mms_par_node_t		*receive_from_clause = NULL;
	mms_par_node_t		*receive_string = NULL;

	mms_par_node_t		*data_clause = NULL;
	mms_par_node_t		*data_string = NULL;
	int			data_count = 0;
	int			i;

	char			*action = NULL;
	char			*scope = NULL;

	mms_par_node_t		*work;
	char			*attr_buf;

	/* Cancel clause */
	mms_par_node_t		*cancel_work = NULL;
	mms_par_node_t		*cancel_node = NULL;
	mms_par_node_t		*cancel_clause = NULL;
	mms_par_node_t		*cancel_string = NULL;
	PGresult		*notifyid_results;



	mms_trace(MMS_DEBUG, "mm_notify_chg_cmd_func");
	/* Parse cmd */
	/* Check to see if this is a new or old format notfiy cmd */
	/* every new format notify cmd has either a tag or object clause */

	if ((receive_clause = mms_pn_lookup(cmd->cmd_root, "object",
	    MMS_PN_CLAUSE, 0)) == NULL) {
		/* check for tag clause */
		if ((receive_clause = mms_pn_lookup(cmd->cmd_root, "tag",
		    MMS_PN_CLAUSE, 0)) == NULL) {
			mms_trace(MMS_DEVP, "No tag/object clause found,"
			    " Try processing as old notify cmd");
			return (mm_notify_chg_cmd_func_old(mm_wka, cmd));
		}
	}

	/* Recieve clause */
	receive_work = NULL;
	while ((receive_node = mms_pn_lookup(cmd->cmd_root, "receive",
	    MMS_PN_CLAUSE, &receive_work)) != NULL) {
		if (db_buf)
			free(db_buf);
		db_buf = NULL;
		object = NULL;
		tag = NULL;
		action = NULL;
		mm_clear_source(cmd);
		mm_clear_dest(cmd);
		mm_clear_const(cmd);
		mms_trace(MMS_DEVP, "receive clause");

		/* Get object */
		if ((receive_clause = mms_pn_lookup(receive_node, "object",
		    MMS_PN_CLAUSE, 0)) == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing"
			    " object clause");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing"
			    " object clause",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		receive_string = mms_pn_lookup(receive_clause,
		    NULL, MMS_PN_OBJ, 0);
		if (receive_string == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing"
			    " object string");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing"
			    " object string",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		object = receive_string->pn_string;

		receive_string = NULL;
		mms_trace(MMS_DEVP,
		    "object -> %s", object);
		if (mm_add_char(object,
		    &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_notify_chg_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_source_num = 1;
		if (mm_add_char(object,
		    &cmd->cmd_dest_list)) {
			mms_trace(MMS_ERR,
			    "mm_notify_chg_cmd_func: "
			    "out of mem creating dest list");
			mm_system_error(cmd,
			    "out of mem creating dest list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_dest_num = 1;
		cmd->cmd_const_num = 0;
		/* Add the constrants in the attribute clause */
		work = NULL;
		while ((receive_string = mms_pn_lookup(receive_clause,
		    NULL, MMS_PN_STRING, &work)) != NULL) {
			/* Check that this is actally an attribute */
			if (mm_db_exec(HERE, db,
			    "select \"%s\" from "
			    "\"%s\" limit 1;",
			    receive_string->pn_string,
			    object) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "attribute %s in object clause "
				    "is not in object %s",
				    receive_string->pn_string,
				    object);
				mm_system_error(cmd,
				    "attribute %s in object clause "
				    "is not in object %s",
				    receive_string->pn_string,
				    object);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				mm_clear_db(&db->mm_db_results);
				return (MM_CMD_ERROR);
			}
			mm_clear_db(&db->mm_db_results);

			attr_buf = NULL;
			attr_buf = mms_strapp(attr_buf,
			    "(\"%s\".\"%s\" != NEW.\"%s\")",
			    object, receive_string->pn_string,
			    receive_string->pn_string);
			if (mm_add_char(attr_buf, &cmd->cmd_const_list)) {
				mms_trace(MMS_ERR,
				    "mm_notify_chg_cmd_func: "
				    "out of mem creating const list");
				mm_system_error(cmd,
				    "out of mem creating const list");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			cmd->cmd_const_num ++;
			free(attr_buf);
			receive_string = NULL;
		}
		receive_clause = NULL;
		mms_trace(MMS_DEVP,
		    "const list after additions, %d",
		    cmd->cmd_const_num);
		mm_print_char_list(&cmd->cmd_const_list);

		/* Get tag */
		if ((receive_clause = mms_pn_lookup(receive_node, "tag",
		    MMS_PN_CLAUSE, 0)) == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing"
			    " tag clause");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing"
			    " tag clause",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		receive_string = mms_pn_lookup(receive_clause,
		    NULL, MMS_PN_STRING, 0);
		if (receive_string == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing"
			    " tag string");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing"
			    " tag string",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		tag = receive_string->pn_string;
		receive_clause = NULL;
		receive_string = NULL;

		/* Confirm tag does not exist for this client */
		mms_trace(MMS_DEVP,
		    "tag -> %s", tag);
		if (mm_db_exec(HERE, db,
		    "select \"NotifyID\" from "
		    "\"NOTIFYRULES\" where \"ConnectionID\" = "
		    "'%s' and "
		    "\"NotifyTag\" = '%s';",
		    conn->cci_uuid,
		    tag) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) > 0) {
			mms_trace(MMS_ERR,
			    "Tag %s already in use",
			    tag);
			mm_system_error(cmd,
			    "Tag %s already in use",
			    tag);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);

		/* Get action */
		if ((receive_clause = mms_pn_lookup(receive_node, "action",
		    MMS_PN_CLAUSE, 0)) == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing"
			    " action clause");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing"
			    " action clause",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		receive_string = mms_pn_lookup(receive_clause,
		    NULL, MMS_PN_KEYWORD, 0);
		if (receive_string == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing"
			    " action string");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing"
			    " action string",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		action = receive_string->pn_string;
		receive_clause = NULL;
		receive_string = NULL;
		mms_trace(MMS_DEVP,
		    "action -> %s", action);
		/* Match clause */
		/* If this action is add or delete */
		/* Look up match in receive */
		/* if this is change need to look for to/from */
		if (strcmp(action, "change") == 0) {
			/* set cmd->cmd_notify_to = 1 */
			/* before calling add_const */
			/* reset to 0 after */
			/* Get to clause and add constrants to const list */
			receive_to_clause = mms_pn_lookup(receive_node, "to",
			    MMS_PN_CLAUSE, 0);
			if (receive_to_clause != NULL) {
				receive_clause =
				    mms_pn_lookup(receive_to_clause,
				    "match",
				    MMS_PN_CLAUSE, 0);
				cmd_root = cmd->cmd_root;
				cmd->cmd_root = receive_clause;
				cmd->cmd_notify_to = 1;
				(void) mm_get_const(mm_wka, cmd);
				cmd->cmd_root = cmd_root;
				cmd->cmd_notify_to = 0;
			} else {
				mms_trace(MMS_DEVP,
				    "didn't see a to clause");
			}
			receive_clause = NULL;

			/* set receive clause to match inside from */
			receive_clause =
			    mms_pn_lookup_arg(receive_node, "match",
			    MMS_PN_CLAUSE, 0);
			if (receive_from_clause == NULL) {
					mms_trace(MMS_ERR,
					    "found from clause but "
					    "could not find match");
			} else {
				mms_trace(MMS_DEVP,
				    "didn't see a match clause");
			}
		} else {
			receive_clause = mms_pn_lookup(receive_node, "match",
			    MMS_PN_CLAUSE, 0);
		}
		if (receive_clause != NULL) {
			scope = mms_pn_build_cmd_text(receive_clause);
			if (scope == NULL) {
				mms_trace(MMS_ERR,
				    "Unable build match clause "
				    "from receive clause");
				mm_system_error(cmd,
				    "Unable build match clause "
				    "from receive clause");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			/* Get notifyID */
			mm_get_uuid(notify_uuid);
			/* insert this into notify */
			db_buf = mms_strapp(db_buf,
			    "insert into \"NOTIFYRULES\" (\"ConnectionID\","
			    "\"NotifyTag\",\"NotifyObject\","
			    "\"NotifyAction\",\"NotifyScope\","
			    "\"NotifyID\")"
			    "VALUES('%s', '%s',"
			    "'%s', '%s', $$%s$$, '%s');",
			    conn->cci_uuid, tag, object,
			    action, scope, notify_uuid);
			cmd_root = cmd->cmd_root;
			cmd->cmd_root = receive_clause;
			(void) mm_get_dest(mm_wka, cmd);
			(void) mm_get_const(mm_wka, cmd);
			cmd->cmd_root = cmd_root;

		} else {
			/* Get notifyID */
			mm_get_uuid(notify_uuid);
			/* insert this into notify */
			db_buf = mms_strapp(db_buf,
			    "insert into \"NOTIFYRULES\" (\"ConnectionID\","
			    "\"NotifyTag\",\"NotifyObject\","
			    "\"NotifyAction\", \"NotifyID\")"
			    "VALUES('%s', '%s',"
			    "'%s', '%s', '%s');",
			    conn->cci_uuid, tag, object, action, notify_uuid);
		}
		if (mm_db_exec(HERE, db, db_buf) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (cmd->wka_ptr->wka_privilege == MM_PRIV_STANDARD) {
			mms_trace(MMS_DEVP,
			    "add non-priv constraints");
			/* Need to check source list and */
			/* add constraints as necessary */
			if (mm_non_priv_const(mm_wka, cmd)) {
				mms_trace(MMS_ERR,
				    "error adding non-priv "
				    "client constraints");
			}
			mms_trace(MMS_DEVP,
			    "const list after additions, %d",
			    cmd->cmd_const_num);
			mm_print_char_list(&cmd->cmd_const_list);
		} else {
			mms_trace(MMS_DEVP,
			    "skip constraints forpriv client");
		}

		/* Data clause */
		if ((data_clause = mms_pn_lookup(receive_node, "data",
		    MMS_PN_CLAUSE, 0)) == NULL) {
			mms_trace(MMS_DEVP, "No data clause found");
		} else {
			/* Verify these attributes */
			mms_trace(MMS_DEVP, "Found a data clause");
			work = NULL;
			while ((data_string = mms_pn_lookup(data_clause,
			    NULL, MMS_PN_STRING, &work)) != NULL) {
				data_count ++;
				if (data_count > 5) {
					/* 6th data string */
					/* only 5 allowed */
					mms_trace(MMS_ERR,
					    "only 5 attributes are allowed in"
					    "a data clause");
					mm_system_error(cmd,
					    "only 5 attributes are allowed in"
					    "a data clause");
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					return (MM_CMD_ERROR);

				}
				/* Verify that this data string is */
				/* an attribute of object */
				if (mm_db_exec(HERE, db,
				    "select \"%s\" from "
				    "\"%s\" limit 1;",
				    data_string->pn_string,
				    object) != MM_DB_DATA) {
					mms_trace(MMS_ERR,
					    "attribute %s in data clause"
					    " is not in object %s",
					    data_string->pn_string,
					    object);
					mm_system_error(cmd,
					    "attribute %s in data clause"
					    " is not in object %s",
					    data_string->pn_string,
					    object);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&db->mm_db_results);
					return (MM_CMD_ERROR);
				}
				mm_clear_db(&db->mm_db_results);
			}
		}

		/* create rule */
		/* insert rule into rule table */
		/* write new func based on mm_sql_report_func( */
		/* to generate the path matching part of the event rule */
		if (mm_build_event_rule(cmd, db, &notify_uuid,
		    action, data_clause)) {
			mms_trace(MMS_ERR,
			    "Unable build event rule from receive clause");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		if (db_buf)
			free(db_buf);
		db_buf = NULL;

		/* end of recieve clause */
	}


	/* Cancel clause */
	cancel_work = NULL;
	while ((cancel_node = mms_pn_lookup(cmd->cmd_root, "cancel",
	    MMS_PN_CLAUSE, &cancel_work)) != NULL) {
		object = NULL;
		tag = NULL;
		if (db_buf)
			free(db_buf);
		db_buf = NULL;
		mms_trace(MMS_DEVP, "cancel clause");
		cancel_string = NULL;
		/* Get object */
		if ((cancel_clause = mms_pn_lookup(cancel_node, "object",
		    MMS_PN_CLAUSE, 0)) != NULL) {
			cancel_string = mms_pn_lookup(cancel_clause,
			    NULL, MMS_PN_OBJ, 0);
			if (cancel_string == NULL) {
				mms_trace(MMS_ERR, "Cancel clause missing"
				    " object string");
				mm_response_error(cmd,
				    ECLASS_LANGUAGE,
				    "ECLAUSENEEDSARG",
				    MM_5067_MSG,
				    "text",
				    "reveive clause missing"
				    " object string",
				    NULL);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			object = cancel_string->pn_string;
			cancel_clause = NULL;
			cancel_string = NULL;
			mms_trace(MMS_DEVP,
			    "drop all event rules for obj %s, conn %s",
			    object, conn->cci_uuid);
			if (mm_db_exec(HERE, db,
			    "select \"NotifyID\" from \"NOTIFYRULES\" where "
			    "\"ConnectionID\" = '%s' "
			    "and \"NotifyObject\" = '%s';",
			    conn->cci_uuid, object) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			notifyid_results = db->mm_db_results;
			for (i = 0; i < PQntuples(notifyid_results); i ++) {
				/* Drop event rules for these id's */
				if (mm_db_exec(HERE, db,
				    "drop rule \"%s\" on \"%s\";",
				    PQgetvalue(notifyid_results, i, 0),
				    object) != MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&notifyid_results);
					return (MM_CMD_ERROR);
				}
				/* Delete rules for this tag from NOTIFYRULES */
				if (mm_db_exec(HERE, db,
				    "delete "
				    " from \"NOTIFYRULES\" where "
				    "\"ConnectionID\" = '%s' and "
				    "\"NotifyObject\" = '%s';",
				    conn->cci_uuid, object) != MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					return (MM_CMD_ERROR);
				}
			}
			/* Go to next cancel clause */
			mm_clear_db(&notifyid_results);
			continue;
		} else {
			mms_trace(MMS_DEVP, "cancel clause missing"
			    " object clause");
		}

		/* Get tag */
		if ((cancel_clause = mms_pn_lookup(cancel_node, "tag",
		    MMS_PN_CLAUSE, 0)) != NULL) {
			cancel_string = mms_pn_lookup(cancel_clause,
			    NULL, MMS_PN_STRING, 0);
			if (cancel_string == NULL) {
				mms_trace(MMS_ERR, "Cancel clause missing"
				    " tag string");
				mm_response_error(cmd,
				    ECLASS_LANGUAGE,
				    "ECLAUSENEEDSARG",
				    MM_5067_MSG,
				    "text",
				    "reveive clause missing"
				    " tag string",
				    NULL);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			tag = cancel_string->pn_string;
			cancel_clause = NULL;
			cancel_string = NULL;
			mms_trace(MMS_DEVP,
			    "drop all event rules for tag %s, conn %s",
			    tag, conn->cci_uuid);
			if (mm_db_exec(HERE, db,
			    "select \"NotifyID\",\"NotifyObject\""
			    " from \"NOTIFYRULES\" where "
			    "\"ConnectionID\" = '%s' and \"NotifyTag\" = '%s';",
			    conn->cci_uuid, tag) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			notifyid_results = db->mm_db_results;
			for (i = 0; i < PQntuples(notifyid_results); i ++) {
				/* Drop event rules for these id's */
				if (mm_db_exec(HERE, db,
				    "drop rule \"%s\" on \"%s\";",
				    PQgetvalue(notifyid_results, i, 0),
				    PQgetvalue(notifyid_results, i, 1)) !=
				    MM_DB_OK) {
					mm_sql_db_err_rsp_new(cmd, db);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					mm_clear_db(&notifyid_results);
					return (MM_CMD_ERROR);
				}
			}
			mm_clear_db(&notifyid_results);
			/* Delete rules for this tag from NOTIFYRULES */
			if (mm_db_exec(HERE, db,
			    "delete "
			    " from \"NOTIFYRULES\" where "
			    "\"ConnectionID\" = '%s' and \"NotifyTag\" = '%s';",
			    conn->cci_uuid, tag) != MM_DB_OK) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

		} else {
			/* Missing tag and obj clause */
			/* parser should prevent this situation */
			mms_trace(MMS_ERR,
			    "cancel clause missing tag/object clause");
			mm_system_error(cmd,
			    "cancel clause missing tag/object clause");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);

		}


	}

	if (db_buf)
		free(db_buf);
	db_buf = NULL;
	mm_write_success(cmd, NULL);
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_DONE);

}


int
mm_notify_chg_cmd_func_old(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	cci_t			*conn = &mm_wka->wka_conn;
	mms_par_node_t		*arg;

	mms_par_node_t		*value;

	int			print_message = 1;

	int			go;
	mms_par_node_t		*item;

	char			*cmd_buf = NULL;

	int			wrote_one = 0;
	mms_par_node_t		*work;
	mms_par_node_t		*receive_work;
	mms_par_node_t		*receive_node;
	mms_par_node_t		*receive_event;
	mms_par_node_t		*receive_scope;
	/* This is the function to process the */
	/* old format notfiy commands */

	mms_trace(MMS_DEBUG, "mm_notify_chg_cmd_func");

	cmd_buf = mms_strapp(cmd_buf,
	    "update \"NOTIFY\" set ");

	/* Recieve clause */
	receive_work = NULL;
	while ((receive_node = mms_pn_lookup(cmd->cmd_root, "receive",
	    MMS_PN_CLAUSE, &receive_work)) != NULL) {
		if (print_message)
			mms_trace(MMS_DEVP, "receive clause");

		work = NULL;
		if ((receive_event = mms_pn_lookup(receive_node, NULL,
		    MMS_PN_STRING, &work)) == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing event");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing event arg",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if ((receive_scope = mms_pn_lookup(receive_node, NULL,
		    MMS_PN_STRING, &work)) == NULL) {
			mms_trace(MMS_ERR, "Receive clause missing scope");
			mm_response_error(cmd,
			    ECLASS_LANGUAGE,
			    "ECLAUSENEEDSARG",
			    MM_5067_MSG,
			    "text",
			    "reveive clause missing scope arg",
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (wrote_one)
			cmd_buf = mms_strapp(cmd_buf,
			    ",");
		cmd_buf = mms_strapp(cmd_buf,
		    " \"%s\" = '%s'",
		    receive_event->pn_string,
		    receive_scope->pn_string);
		wrote_one = 1;
		mms_trace(MMS_DEVP,
		    "Receive %s, scope, %s",
		    receive_event->pn_string,
		    receive_scope->pn_string);
	}


	/* Cancel clause */
	work = NULL;
	arg = mms_pn_lookup(cmd->cmd_root, "cancel",
	    MMS_PN_CLAUSE, &work);
	if (arg != NULL) {
		if (print_message)
			mms_trace(MMS_DEVP, "cancel clause");
		/* Set each value to 'yes' */
		item = NULL;
		go = 1;
		while (go) {
			if ((value =
			    mms_pn_lookup(arg, NULL,
			    MMS_PN_STRING,
			    &item)) == NULL) {
				go = 0;
			} else {
				if (wrote_one)
					cmd_buf = mms_strapp(cmd_buf,
					    ",");
				cmd_buf = mms_strapp(cmd_buf,
				    " \"%s\" = 'off'",
				    value->pn_string);
				wrote_one = 1;

				if (print_message)
					mms_trace(MMS_DEVP, "    %s",
					    value->pn_string);
			}
		}
	} else {
		/* Didn't find a cancel clause */
		if (print_message)
			mms_trace(MMS_DEVP, "Didn't find a cancel clause");
	}

	/* add where clause */
	if (conn->cci_uuid == NULL) {
		if (print_message)
			mms_trace(MMS_DEVP, "uuid is NULL");
	} else {
		if (print_message)
			mms_trace(MMS_DEVP, "uuid is %s", conn->cci_uuid);
	}

	cmd_buf = mms_strapp(cmd_buf, " where \"ConnectionID\" = '%s';",
	    conn->cci_uuid);


	/* Send cmd_buf to data base */
	if (print_message)
		mms_trace(MMS_DEVP, "\n%s\n",
		    cmd_buf);


	if (mm_db_exec(HERE, db, cmd_buf) != MM_DB_OK) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}

	/* Send Success */

	if (cmd_buf)
		free(cmd_buf);

	mm_path_match_report(cmd, db);
	mm_send_response(mm_wka->mm_wka_conn, cmd);

	return (MM_CMD_DONE);


no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:

	if (cmd_buf)
		free(cmd_buf);
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
}


int
mm_inject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	char		*slotgroup = NULL;
	int		 rows;
	char		*query;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*lmp_inject_cmd;
	mm_wka_t	*lm_wka;
	uuid_text_t	 new_task;
	char		*library;
	char		*lm;
	PGresult	*lib_results;
	char		*constraint;


	mms_trace(MMS_DEVP, "mm inject state %d", cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
			return (MM_CMD_ERROR);
		}

		(void) mm_get_dest(mm_wka, cmd);
		(void) mm_get_const(mm_wka, cmd); /* constraints */
		if (mm_add_char("LM", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_inject_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_source_num = 1;
		if (mm_add_char("LIBRARY", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_inject_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		cmd->cmd_source_num = 2;
		query = "select distinct "
		    "\"LM\".\"LibraryName\",\"LM\".\"LMName\" from ";
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(query) + 1);
		(void) strlcpy(cmd->cmd_buf, query, cmd->cmd_bufsize);

		if (mm_sql_from_where(cmd, db)) {
			mms_trace(MMS_ERR,
			    "mm_inject_cmd_func: "
			    "db error creating helper functions");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		constraint = "and ((\"LIBRARY\".\"LibraryName\" = "
		    "\"LM\".\"LibraryName\") and "
		    "(\"LIBRARY\".\"LibraryOnline\" = 'true'))";
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(constraint) + 1);
		strcat(cmd->cmd_buf, constraint);
		mm_sql_order(cmd);
		mm_sql_number(cmd);
		if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		lib_results = db->mm_db_results;
		rows = PQntuples(lib_results);
		if (rows == 0) {
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
			    strlen(ECLASS_EXIST) + strlen(ENOMATCH) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_EXIST, ENOMATCH);
			mm_clear_db(&lib_results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		} else if (rows > 1) {
			mms_trace(MMS_DEVP,
			    "user constaints selected more than "
			    "one library");
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
			    strlen(ECLASS_EXPLICIT) + strlen(ETOOMANY) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_EXPLICIT, ETOOMANY);
			mm_clear_db(&lib_results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		library = PQgetvalue(lib_results, 0, 0);
		lm = PQgetvalue(lib_results, 0, 1);

		/* find cap */
		if (arg = mms_pn_lookup(cmd->cmd_root, "slotgroup",
		    MMS_PN_CLAUSE, NULL)) {
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			slotgroup = strdup(value->pn_string);
		} else if ((slotgroup = mm_library_lm_get_cap(cmd,
		    library, lm)) == NULL) {
			mm_clear_db(&lib_results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mms_trace(MMS_DEVP, "cap %s", slotgroup);

		/*
		 * Report clause, query before data model changed.
		 * Actually, this should be about the context of command
		 * and report what was injected.
		 */
		mm_path_match_report(cmd, db);
		cmd->cmd_report = strdup(cmd->cmd_buf);

		/*
		 * LMP inject command
		 */
		mms_trace(MMS_INFO, "Sending Inject to %s", library);
		lm_wka = mm_library_lm_wka(cmd->wka_ptr->mm_data,
		    library, NULL);
		if ((lmp_inject_cmd = mm_alloc_cmd(lm_wka)) == NULL) {
			mms_trace(MMS_ERR,
			    "Unable to malloc mm_command_t: %s",
			    strerror(errno));
			mm_system_error(cmd,
			    "unable to allocate memory for lmp inject");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		lmp_inject_cmd->cmd_name = strdup("lmp inject");
		lmp_inject_cmd->cmd_func = mm_lmp_inject_cmd_func;
		mm_get_uuid(new_task);
		lmp_inject_cmd->cmd_textcmd = mms_strnew(LMP_INJECT, new_task,
		    slotgroup);
		lmp_inject_cmd->cmd_root =
		    mm_text_to_par_node(lmp_inject_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		lmp_inject_cmd->cmd_task =
		    mm_get_task(lmp_inject_cmd->cmd_root);
		mm_add_depend(lmp_inject_cmd, cmd);
		/* create task */
		if (mm_new_tm_task(db, cmd, "dispatched") != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_inject_cmd_func: "
			    "error inserting new task");
			mm_system_error(cmd,
			    "error inserting new task");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_set_tm_library(db,
		    cmd->cmd_uuid, library) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_inject_cmd_func: "
			    "error updating TASKLIBRARY");
			mm_system_error(cmd,
			    "error updating TASKLIBRARY");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		mm_clear_db(&lib_results);
		free(slotgroup);

		cmd->cmd_state = 1;

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue,
		    lmp_inject_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		return (MM_DISPATCH_DEPEND);

	} else if (cmd->cmd_state == 1) {
		char *response_message = NULL;
		/* remove completed task */
		(void) mm_del_tm_cmd(db, cmd->cmd_uuid);

		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "lm inject failed");
			response_message = mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    MM_5055_MSG,
			    "msg_rsp", response_message,
			    NULL);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		/*
		 * Report clause (previously generated).
		 */
		cmd->cmd_remove = 1;
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		mms_trace(MMS_INFO, "Injected Cartridge(s) Successfully");
		return (MM_CMD_DONE);
	}

no_mem:
	MM_ABORT_NO_MEM();
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


int
mm_eject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	int		 rows;
	int		 row;
	int		 rc;
	uuid_text_t	 new_task;
	mms_par_node_t	*work;
	char		*cartid;
	char		*cartpcl;
	char		*slottype;
	mms_par_node_t	*cart;
	mms_par_node_t	*id;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*lmp_eject_cmd;
	eject_cart_t	*eject_cart;
	PGresult	*taskcart_results;
	mm_wka_t	*lm_wka;
	mms_par_node_t	*index;
	char		*query;


	mms_trace(MMS_DEVP, "mm eject state %d", cmd->cmd_state);

	if (cmd->cmd_state == 0) {
		if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
			return (MM_CMD_ERROR);
		}

		mms_trace(MMS_DEVP, "cartridge eject list");
		if ((cmd->cmd_eject = (cmd_eject_t *)calloc(1,
		    sizeof (cmd_eject_t))) == NULL) {
			MM_ABORT_NO_MEM();
		}
		mms_list_create(&cmd->cmd_eject->eject_list,
		    sizeof (eject_cart_t),
		    offsetof(eject_cart_t, cart_next));

		/* get cart(s) by id */
		work = NULL;
		for (id = mms_pn_lookup(cmd->cmd_root, "cartid",
		    MMS_PN_CLAUSE, &work);
		    id != NULL;
		    id = mms_pn_lookup(cmd->cmd_root, "cartid",
		    MMS_PN_CLAUSE, &work)) {

			mms_trace(MMS_DEVP, "get cartridge by id");

			MMS_PN_LOOKUP(value, id, NULL, MMS_PN_STRING, NULL);
			cartid = value->pn_string;

			mms_trace(MMS_DEVP, "cartid %s", cartid);

			if (mm_db_exec(HERE, db, "SELECT \"CartridgePCL\","
			    "\"SlotTypeName\","
			    "\"LibraryName\","
			    "\"SlotName\" "
			    "FROM \"SLOT\" "
			    "WHERE \"CartridgeID\" = '%s';",
			    cartid) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			if (PQntuples(db->mm_db_results) == 0) {
				mms_trace(MMS_DEVP,
				    "cartid %s not found", cartid);
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    ENOSUCHCART,
				    MM_5004_MSG, "cartid", cartid,
				    NULL);
				mm_clear_db(&db->mm_db_results);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			/* add cartridge to list of ejectable cartridges */
			if ((eject_cart = (eject_cart_t *)calloc(1,
			    sizeof (eject_cart_t))) == NULL) {
				MM_ABORT_NO_MEM();
			}
			eject_cart->cart_cartid = strdup(cartid);
			eject_cart->cart_cartpcl =
			    strdup(PQgetvalue(db->mm_db_results, 0, 0));
			eject_cart->cart_slottype =
			    strdup(PQgetvalue(db->mm_db_results, 0, 1));
			eject_cart->cart_library =
			    strdup(PQgetvalue(db->mm_db_results, 0, 2));
			eject_cart->cart_slotname =
			    strdup(PQgetvalue(db->mm_db_results, 0, 3));
			mm_clear_db(&db->mm_db_results);
			mms_list_insert_tail(&cmd->cmd_eject->eject_list,
			    eject_cart);
		}

		/* get cart(s) by pcl and slottype */
		work = NULL;
		for (cart = mms_pn_lookup(cmd->cmd_root, "cart",
		    MMS_PN_CLAUSE, &work);
		    cart != NULL;
		    cart = mms_pn_lookup(cmd->cmd_root, "cart",
		    MMS_PN_CLAUSE, &work)) {

			mms_trace(MMS_DEVP,
			    "get cartridge by pcl and slottype");

			index = 0;
			MMS_PN_LOOKUP(value, cart, NULL,
			    MMS_PN_STRING, &index);
			cartpcl = value->pn_string;

			MMS_PN_LOOKUP(value, cart, NULL,
			    MMS_PN_STRING, &index);
			slottype = value->pn_string;

			mms_trace(MMS_DEVP, "cartpcl %s, slottype %s",
			    cartpcl, slottype);

			if (mm_db_exec(HERE, db, "SELECT \"CartridgeID\","
			    "\"LibraryName\","
			    "\"SlotName\" "
			    "FROM \"SLOT\" "
			    "WHERE (\"CartridgePCL\" = '%s') "
			    "AND (\"SlotTypeName\" = '%s');",
			    cartpcl, slottype) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			if (PQntuples(db->mm_db_results) == 0) {
				mms_trace(MMS_DEVP, "cartpcl %s slottype %s "
				    "not found", cartpcl, slottype);
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    ENOSUCHPCL,
				    MM_5005_MSG, "cartpcl", cartpcl,
				    NULL);
				mm_clear_db(&db->mm_db_results);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			if ((eject_cart = (eject_cart_t *)calloc(1,
			    sizeof (eject_cart_t))) == NULL) {
				MM_ABORT_NO_MEM();
			}
			eject_cart->cart_cartid =
			    strdup(PQgetvalue(db->mm_db_results, 0, 0));
			eject_cart->cart_cartpcl = strdup(cartpcl);
			eject_cart->cart_slottype = strdup(slottype);
			eject_cart->cart_library =
			    strdup(PQgetvalue(db->mm_db_results, 0, 1));
			eject_cart->cart_slotname =
			    strdup(PQgetvalue(db->mm_db_results, 0, 2));
			mm_clear_db(&db->mm_db_results);
			mms_list_insert_tail(&cmd->cmd_eject->eject_list,
			    eject_cart);
		}

		/* get cart(s) by match */
		if (mms_pn_lookup(cmd->cmd_root, "match",
		    MMS_PN_CLAUSE, NULL)) {
			mms_trace(MMS_DEVP, "find carts using match");
			(void) mm_get_dest(mm_wka, cmd);
			(void) mm_get_const(mm_wka, cmd); /* constraints */
			if (mm_add_char("CARTRIDGE", &cmd->cmd_source_list)) {
				mms_trace(MMS_ERR,
				    "mm_eject_cmd_func: "
				    "out of mem creating source list");
				mm_system_error(cmd,
				    "out of mem creating source list");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			cmd->cmd_source_num = 1;
			if (mm_add_char("SLOT", &cmd->cmd_source_list)) {
				mms_trace(MMS_ERR,
				    "mm_eject_cmd_func: "
				    "out of mem creating source list");
				mm_system_error(cmd,
				    "out of mem creating source list");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			cmd->cmd_source_num = 2;
			query = "select distinct "
			    "\"CARTRIDGE\".\"CartridgeID\","
			    "\"CARTRIDGE\".\"CartridgePCL\","
			    "\"SLOT\".\"SlotTypeName\","
			    "\"CARTRIDGE\".\"LibraryName\","
			    "\"SLOT\".\"SlotName\" "
			    "from ";
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(query) + 1);
			(void) strlcpy(cmd->cmd_buf, query, cmd->cmd_bufsize);
			if (mm_sql_from_where(cmd, db)) {
				mms_trace(MMS_ERR,
				    "mm_eject_cmd_func: "
				    "db error creating helper functions");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			mm_sql_order(cmd);
			mm_sql_number(cmd);
			if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			if ((rows = PQntuples(db->mm_db_results)) == 0) {
				mms_trace(MMS_DEVP, "no match");
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    ENOMATCH,
				    MM_5068_MSG,
				    NULL);
				mm_clear_db(&db->mm_db_results);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			mms_trace(MMS_DEVP, "%d cartridge matches",
			    rows);
			for (row = 0; row < rows; row++) {

				if ((eject_cart = (eject_cart_t *)calloc(1,
				    sizeof (eject_cart_t))) == NULL) {
					MM_ABORT_NO_MEM();
				}
				mms_trace(MMS_DEVP, "    cart, %s",
				    PQgetvalue(db->mm_db_results, row, 0));
				eject_cart->cart_cartid =
				    strdup(PQgetvalue(db->mm_db_results,
				    row, 0));
				eject_cart->cart_cartpcl =
				    strdup(PQgetvalue(db->mm_db_results,
				    row, 1));
				eject_cart->cart_slottype =
				    strdup(PQgetvalue(db->mm_db_results,
				    row, 2));
				eject_cart->cart_library =
				    strdup(PQgetvalue(db->mm_db_results,
				    row, 3));
				eject_cart->cart_slotname =
				    strdup(PQgetvalue(db->mm_db_results,
				    row, 4));
				mms_list_insert_tail(&cmd->
				    cmd_eject->eject_list,
				    eject_cart);
			}
			mm_clear_db(&db->mm_db_results);
		}

		/* check for at least one cart */
		if (mms_list_head(&cmd->cmd_eject->eject_list) == NULL) {
			mms_trace(MMS_DEVP, "no carts found to eject");
			mm_response_error(cmd,
			    ECLASS_EXPLICIT,
			    ENOMATCH,
			    MM_5068_MSG,
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		/* check cartridge state */
		mms_list_foreach(&cmd->cmd_eject->eject_list, eject_cart) {
			mms_trace(MMS_DEVP,
			    "check cartridge state for %s",
			    eject_cart->cart_cartid);

			/* cartridge is not mount candidate */
			if (mm_db_exec(HERE, db, "SELECT \"CartridgeID\","
			    "\"TaskID\" "
			    "FROM \"TASKCARTRIDGE\" "
			    "WHERE (\"CartridgeID\" = '%s');",
			    eject_cart->cart_cartid) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			taskcart_results = db->mm_db_results;
			rows = PQntuples(taskcart_results);
			for (row = 0; row < rows; row++) {
				if (mm_db_exec(HERE, db, "SELECT \"TaskType\" "
				    "FROM \"TASK\" "
				    "WHERE (\"TaskID\" = '%s');",
				    PQgetvalue(taskcart_results, row, 0))
				    != MM_DB_DATA) {
					mm_sql_db_err_rsp_new(cmd, db);
					mm_clear_db(&taskcart_results);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					return (MM_CMD_ERROR);
				}
				if (PQntuples(db->mm_db_results) == 1) {
					rc = strcmp("mount",
					    PQgetvalue(taskcart_results, 0, 0));
					if (rc == 0) {
						mm_clear_db(&taskcart_results);
						mm_clear_db(&db->mm_db_results);
						mms_trace(MMS_DEVP, "cart is "
						    "mount candidate");
						mm_response_error(cmd,
						    ECLASS_RETRY,
						    ECARTINUSE,
						    MM_5006_MSG, "cartid",
						    eject_cart->cart_cartid,
						    NULL);
						cmd->cmd_remove = 1;
						mm_send_text(mm_wka->
						    mm_wka_conn,
						    cmd->cmd_buf);
						return (MM_CMD_ERROR);
					}
				}
				mm_clear_db(&db->mm_db_results);
			}
			mm_clear_db(&taskcart_results);

			/* check for cart in slot */
			if (mm_db_exec(HERE, db, "select \"SlotOccupied\" "
			    "from \"SLOT\" where \"CartridgeID\" = '%s';",
			    eject_cart->cart_cartid) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			if (PQntuples(db->mm_db_results) != 1) {
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    ENOSLOT,
				    MM_5010_MSG, "cartid",
				    eject_cart->cart_cartid,
				    NULL);
				mm_clear_db(&db->mm_db_results);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
			    "true") != 0 &&
			    strcmp(PQgetvalue(db->mm_db_results, 0, 0),
			    "t") != 0) {
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    ESLOTNOTOCCUPIED,
				    MM_5011_MSG, "cartid",
				    eject_cart->cart_cartid,
				    NULL);
				mm_clear_db(&db->mm_db_results);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
			mm_clear_db(&db->mm_db_results);

			/* check for carts in same library */
			if (cmd->cmd_eject->eject_library == NULL) {
				cmd->cmd_eject->eject_library =
				    strdup(eject_cart->cart_library);
			} else if (strcmp(cmd->cmd_eject->eject_library,
			    eject_cart->cart_library) != 0) {
				mms_trace(MMS_DEVP, "cart not in same library");
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    ETOOMANY,
				    MM_5007_MSG,
				    "cartid1", eject_cart->cart_cartid,
				    "lib1", eject_cart->cart_library,
				    "lib2", cmd->cmd_eject->eject_library,
				    NULL);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
		}

		/* get lm */
		if (mm_db_exec(HERE, db, "SELECT \"LMName\" FROM \"LM\" "
		    "WHERE \"LibraryName\" = '%s'",
		    cmd->cmd_eject->eject_library) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mm_response_error(cmd,
			    ECLASS_CONFIG,
			    ELIBNOLMCONFIGURED,
			    MM_5008_MSG, "lib", cmd->cmd_eject->eject_library,
			    NULL);
			mm_clear_db(&db->mm_db_results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_response_error(cmd,
			    ECLASS_EXPLICIT,
			    ETOOMANY,
			    MM_5009_MSG, "lib", cmd->cmd_eject->eject_library,
			    NULL);
			mm_clear_db(&db->mm_db_results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cmd->cmd_eject->eject_lm =
		    strdup(PQgetvalue(db->mm_db_results, 0, 0));
		mm_clear_db(&db->mm_db_results);

		/* check for configured, connected, and ready library */
		if (mm_library_lm_cfg_conn_rdy(cmd,
		    cmd->cmd_eject->eject_library,
		    cmd->cmd_eject->eject_lm) != 0) {
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		/* find cap */
		if (arg = mms_pn_lookup(cmd->cmd_root, "slotgroup",
		    MMS_PN_CLAUSE, NULL)) {
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			cmd->cmd_eject->eject_slotgroup =
			    strdup(value->pn_string);
		} else if ((cmd->cmd_eject->eject_slotgroup =
		    mm_library_lm_get_cap(cmd,
		    cmd->cmd_eject->eject_library,
		    cmd->cmd_eject->eject_lm)) == NULL) {
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mms_trace(MMS_DEVP, "cap %s", cmd->cmd_eject->eject_slotgroup);

		/*
		 * Report clause, get before data model changes.
		 */
		mm_path_match_report(cmd, db);
		cmd->cmd_report = strdup(cmd->cmd_buf);

		/*
		 * LMP eject command
		 */
		mms_trace(MMS_INFO, "Sending Eject to %s",
		    cmd->cmd_eject->eject_library);

		lm_wka = mm_library_lm_wka(cmd->wka_ptr->mm_data,
		    cmd->cmd_eject->eject_library, NULL);
		if ((lmp_eject_cmd = mm_alloc_cmd(lm_wka)) == NULL) {
			mms_trace(MMS_ERR,
			    "Unable to malloc mm_command_t: %s",
			    strerror(errno));
			mm_system_error(cmd,
			    "unable to allocate memory "
			    "for eject cmd");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		lmp_eject_cmd->cmd_func = mm_lmp_eject_cmd_func;
		mm_get_uuid(new_task);
		lmp_eject_cmd->cmd_textcmd = mms_strnew(LMP_EJECT, new_task,
		    cmd->cmd_eject->eject_slotgroup);
		if (mm_new_tm_task(db, cmd, "dispatched") != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_eject_cmd_func: "
			    "error inserting new task");
			mm_system_error(cmd,
			    "error inserting new task");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		if (mm_set_tm_library(db, cmd->cmd_uuid,
		    cmd->cmd_eject->eject_library) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_eject_cmd_func: "
			    "error updating TASKLIBRARY");
			mm_system_error(cmd,
			    "error updating TASKLIBRARY");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}


		mms_list_foreach(&cmd->cmd_eject->eject_list, eject_cart) {
			lmp_eject_cmd->cmd_textcmd =
			    mms_strapp(lmp_eject_cmd->cmd_textcmd,
			    LMP_EJECT_SLOT,
			    eject_cart->cart_slotname,
			    eject_cart->cart_cartpcl);
			if (mm_set_tm_cartridge(db, cmd->cmd_uuid,
			    eject_cart->cart_cartid) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_eject_cmd_func: "
				    "db error inserting TASKCARTRIDGE");
			}
		}
		lmp_eject_cmd->cmd_textcmd =
		    mms_strapp(lmp_eject_cmd->cmd_textcmd, LMP_EJECT_END);
		lmp_eject_cmd->cmd_name = strdup("lmp eject");
		lmp_eject_cmd->cmd_root =
		    mm_text_to_par_node(lmp_eject_cmd->cmd_textcmd,
		    mms_lmpm_parse);
		lmp_eject_cmd->cmd_task = mm_get_task(lmp_eject_cmd->cmd_root);
		mm_add_depend(lmp_eject_cmd, cmd);
		cmd->cmd_state = 1;

		pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
		mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue,
		    lmp_eject_cmd);
		pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

		return (MM_DISPATCH_DEPEND);

	} else if (cmd->cmd_state == 1) {
		char *response_message = NULL;
		/* remove completed task */
		(void) mm_del_tm_cmd(db, cmd->cmd_uuid);

		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_DEVP, "lm eject failed");
			response_message =
			    mm_ret_response_msg(cmd);
			mm_response_error(cmd,
			    ECLASS_SUBOP,
			    ELMDMCOMMUNICATION,
			    MM_5055_MSG,
			    "msg_rsp", response_message,
			    NULL);
			free(response_message);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		/*
		 * Report clause (previously generated).
		 */
		cmd->cmd_remove = 1;
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		mms_trace(MMS_INFO, "Ejected Cartridge(s) Successfully");
		return (MM_CMD_DONE);
	}

no_mem:
	MM_ABORT_NO_MEM();
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


int
mm_private_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	int		 off;
	mms_par_node_t	*work;
	mms_par_node_t	*item;
	mms_par_node_t	*itemcnt;
	mms_par_node_t	*object;
	mms_par_node_t	*attr;
	mms_par_node_t	*value;
	mms_par_node_t	*get;
	mms_par_node_t	*set;
	mms_par_node_t	*unset;
	char		*objname;
	int		 get_once = 0;
	int		 rc;
	int		 error = 0;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*notify_obj = NULL;
	int		 col;
	int		 cols;
	char		 date[24];
	char		*data = NULL;
	int		 datasize = 0;
	char		*id;
	char		*name;
	char		*val;
	Oid		 oid;
	char		*seen_id[2] = {NULL, NULL};
	char		*seen_name[2] = {NULL, NULL};
	char		*query;
	char		*response = NULL;
	int		 responsesize = 0;
	mm_lang_t	 lang = cmd->cmd_language;
	cci_t		*conn = &mm_wka->wka_conn;
	int		 i;
	int		 len;


	mms_trace(MMS_DEVP, "sql trans dmp/d or lmp/l private cmd");

	/*
	 * Get all values in a single query
	 */
	off = 0;
	work = NULL;
	for (get = mms_pn_lookup(cmd->cmd_root, "get",
	    MMS_PN_CLAUSE, &work);
	    get != NULL;
	    get = mms_pn_lookup(cmd->cmd_root, "get",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		itemcnt = NULL;
		for (object = mms_pn_lookup(get, NULL,
		    MMS_PN_OBJ, &item);
		    object != NULL;
		    object = mms_pn_lookup(get, NULL,
		    MMS_PN_OBJ, &item)) {
			objname = object->pn_string;

			/* gather sql query constraints */
			if (strcmp(objname, "DRIVE") == 0 &&
			    lang == MM_LANG_DMP) {
				seen_id[0] = "DRIVE";
				seen_name[0] = "DriveName";
			} else if (strcmp(objname, "DM") == 0 &&
			    lang == MM_LANG_DMP) {
				seen_id[1] = "DM";
				seen_name[1] = "DMName";
			} else if (strcmp(objname, "LIBRARY") == 0 &&
			    lang == MM_LANG_LMP) {
				seen_id[0] = "LIBRARY";
				seen_name[0] = "LibraryName";
			} else if (strcmp(objname, "LM") == 0 &&
			    lang == MM_LANG_LMP) {
				seen_id[1] = "LM";
				seen_name[1] = "LMName";
			} else {
				/* invalid object */
				SQL_CHK_LEN(&cmd->cmd_buf, 0,
				    &cmd->cmd_bufsize,
				    strlen(ECLASS_LANGUAGE) +
				    strlen(cmd->cmd_task) +
				    strlen(ESYNTAX) + 1);
				(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
				    RESPONSE_ERROR, cmd->cmd_task,
				    ECLASS_LANGUAGE, ESYNTAX);
				free(data);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			/* initialize query buffer */
			if (!get_once) {
				SQL_CHK_LEN(&data, 0, &datasize, 8);
				off = snprintf(data, datasize, "SELECT ");
				get_once = 1;
			}

			/* add which sql query table and field */
			MMS_PN_LOOKUP(attr, get, NULL, MMS_PN_STRING,
			    &itemcnt);
			SQL_CHK_LEN(&data, off, &datasize, strlen(objname) +
			    strlen(attr->pn_string) + 7);
			off += snprintf(data + off, datasize - off,
			    "\"%s\".\"%s\",", objname, attr->pn_string);
		}
	}
	if (get_once) {
		off--;	  /* overwrite the last comma */
		data[off] = '\0';

		/* add query constraints */
		if (seen_id[0] && seen_id[1]) {
			query = mms_strnew("%s FROM \"%s\",\"%s\" WHERE "
			    "\"%s\".\"%s\" = '%s' AND "
			    "\"%s\".\"%s\" = '%s'",
			    data, seen_id[0], seen_id[1],
			    seen_id[0], seen_name[0],
			    conn->cci_client,
			    seen_id[1], seen_name[1],
			    conn->cci_instance);
		} else if (seen_id[0] && strcmp(seen_id[0], "DRIVE") == 0) {
			query = mms_strnew("%s FROM \"%s\" WHERE "
			    "\"%s\".\"DriveName\" = '%s'",
			    data, seen_id[0], seen_id[0],
			    conn->cci_client);
		} else if (seen_id[0] && strcmp(seen_id[0], "LIBRARY") == 0) {
			query = mms_strnew("%s FROM \"%s\" WHERE "
			    "\"%s\".\"LibraryName\" = '%s'",
			    data, seen_id[0], seen_id[0],
			    conn->cci_client);
		} else {
			query = mms_strnew("%s FROM \"%s\" WHERE "
			    "\"%s\" = '%s'",
			    data, seen_id[1], seen_name[1],
			    conn->cci_instance);
		}
		free(data);
		data = NULL;
		datasize = 0;
		if (query == NULL) {
			MM_ABORT_NO_MEM();
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		/* query the database */
		rc = mm_db_exec(HERE, db, query);
		free(query);
		if (rc != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INTERNAL) +
			    strlen(EDATABASE) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_INTERNAL, EDATABASE);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		cols = PQnfields(db->mm_db_results);


		/* convert strings from postgres to mms */
		off = 0;
		for (col = 0; col < cols; col++) {
			name = PQfname(db->mm_db_results, col);
			val = PQgetvalue(db->mm_db_results, 0, col);
			if (val[0] == '\0') {
				/* empty object attribute string */
				val = "none";
			}

			/* database data types to mms string conversions */
			oid = PQftype(db->mm_db_results, col);
			if (oid == db->mm_db_cfg->mm_db_bool_oid) {
				if (strcmp(val, "t") == 0) {
					val = "true";
				} else if (strcmp(val, "f") == 0) {
					val = "false";
				}
			} else if (oid == db->mm_db_cfg->mm_db_timestamp_oid) {
				if (strcmp(val, "-infinity") == 0) {
					/* mms time not set */
					val = "0000 00 00 00 00 00 000";
				} else {
					(void) strlcpy(date, val,
					    sizeof (date));
					val = date;
					/* mms localtime format */
					val[4] = ' '; /* - */
					val[7] = ' '; /* - */
					val[13] = ' '; /* : */
					val[16] = ' '; /* : */
					if (val[19] == '\0') {
						val[20] = '\0';
					}
					val[19] = ' '; /* . */

					len = strlen(val);
					for (i = len; i < 23; i++) {
						val[i] = '0';
					}
					val[23] = '\0';
				}
			}

			SQL_CHK_LEN(&data, off, &datasize, strlen(name) +
			    strlen(val) + 7);
			off += snprintf(data + off, datasize - off,
			    "\"%s\" \"%s\" ", name, val);
		}
		mm_clear_db(&db->mm_db_results);

		if (data) {
			/* build successful response with text */
			SQL_CHK_LEN(&response, 0, &responsesize,
			    strlen(RESPONSE_SUCCESS_TEXT) +
			    strlen(cmd->cmd_task) +
			    strlen(data) + 1);
			(void) snprintf(response, responsesize,
			    RESPONSE_SUCCESS_TEXT, cmd->cmd_task, data);
			free(data);
			data = NULL;
			datasize = 0;
		}
	}
	if (response == NULL) { /* nothing to report */
		SQL_CHK_LEN(&response, 0, &responsesize,
		    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
		(void) snprintf(response, responsesize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
	}

	/*
	 * Set values one at a time
	 */
	work = NULL;
	for (set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work);
	    set != NULL;
	    set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		itemcnt = NULL;
		for (object = mms_pn_lookup(set, NULL, MMS_PN_OBJ, &item);
		    object != NULL;
		    object = mms_pn_lookup(set, NULL, MMS_PN_OBJ, &item)) {
			objname = object->pn_string;
			MMS_PN_LOOKUP(attr, set, NULL,
			    MMS_PN_STRING, &itemcnt);
			MMS_PN_LOOKUP(value, set, NULL,
			    MMS_PN_STRING, &itemcnt);

			/* check for name changes and flag change event */
			if (strcmp(objname, "DRIVE") == 0 &&
			    lang == MM_LANG_DMP) {
				id = "DriveName";
				name = conn->cci_client;
			} else if (strcmp(objname, "DM") == 0 &&
			    lang == MM_LANG_DMP) {
				id = "DMName";
				name = conn->cci_instance;
				notify_obj = "DM";
			} else if (strcmp(objname, "LIBRARY") == 0 &&
			    lang == MM_LANG_LMP) {
				id = "LibraryName";
				name = conn->cci_client;
			} else if (strcmp(objname, "LM") == 0 &&
			    lang == MM_LANG_LMP) {
				id = "LMName";
				name = conn->cci_instance;
				notify_obj = "LM";
			} else {
				error = 1; /* invalid object */
			}
			if (strcmp(attr->pn_string, id) == 0 || error) {
				/* name change not allowed or invalid object */
				SQL_CHK_LEN(&cmd->cmd_buf, 0,
				    &cmd->cmd_bufsize,
				    strlen(ECLASS_LANGUAGE) +
				    strlen(cmd->cmd_task) +
				    strlen(ESYNTAX) + 1);
				(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
				    RESPONSE_ERROR, cmd->cmd_task,
				    ECLASS_LANGUAGE, ESYNTAX);
				free(response);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(objname) + 14);
			off = snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    "UPDATE \"%s\" SET ", objname);

			if (value->pn_type & MMS_PN_NULLSTR) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize,
				    strlen(attr->pn_string) +
				    strlen(id) + strlen(name) + 8);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    "\"%s\" = default "
				    "WHERE \"%s\" = '%s'",
				    attr->pn_string,
				    id, name);
			} else {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize,
				    strlen(attr->pn_string) +
				    strlen(value->pn_string) +
				    strlen(id) + strlen(name) + 8);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    "\"%s\" = '%s' "
				    "WHERE \"%s\" = '%s'",
				    attr->pn_string,
				    value->pn_string, id, name);
			}

			/* create the attribute if needed */
			if (mm_db_create_attribute(db, objname,
			    attr->pn_string) != MM_DB_OK) {
				mm_sql_db_err_rsp_new(cmd, db);
				free(response);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			/* change the attribute value */
			if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_OK) {
				mm_sql_db_err_rsp_new(cmd, db);
				free(response);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
		}
	}

	/*
	 * Unset values one at a time
	 */
	for (unset = mms_pn_lookup(cmd->cmd_root, "unset",
	    MMS_PN_CLAUSE, &work);
	    unset != NULL;
	    unset = mms_pn_lookup(cmd->cmd_root, "unset",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		itemcnt = NULL;
		for (object = mms_pn_lookup(unset, NULL, MMS_PN_OBJ, &item);
		    object != NULL;
		    object = mms_pn_lookup(unset, NULL, MMS_PN_OBJ,
		    &item)) {
			objname = object->pn_string;
			MMS_PN_LOOKUP(attr, unset, NULL,
			    MMS_PN_STRING, &itemcnt);

			/* check for name changes and flag change event */
			if (strcmp(objname, "DRIVE") == 0 &&
			    lang == MM_LANG_DMP) {
				id = "DriveName";
				name = conn->cci_client;
			} else if (strcmp(objname, "DM") == 0 &&
			    lang == MM_LANG_DMP) {
				id = "DMName";
				name = conn->cci_instance;
				notify_obj = "DM";
			} else if (strcmp(objname, "LIBRARY") == 0 &&
			    lang == MM_LANG_LMP) {
				id = "LibraryName";
				name = conn->cci_client;
			} else if (strcmp(objname, "LM") == 0 &&
			    lang == MM_LANG_LMP) {
				id = "LMName";
				name = conn->cci_instance;
				notify_obj = "LM";
			} else {
				error = 1; /* invalid object */
			}
			if (strcmp(attr->pn_string, id) == 0 || error) {
				/* name change not allowed or invalid object */
				SQL_CHK_LEN(&cmd->cmd_buf, 0,
				    &cmd->cmd_bufsize,
				    strlen(ECLASS_LANGUAGE) +
				    strlen(cmd->cmd_task) +
				    strlen(ESYNTAX) + 1);
				(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
				    RESPONSE_ERROR, cmd->cmd_task,
				    ECLASS_LANGUAGE, ESYNTAX);
				free(response);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			/* remove device manager created attributes */
			if ((rc = mm_db_delete_attribute(db, objname,
			    attr->pn_string)) == MM_DB_DROPPED) {
				continue;	/* object attribute removed */
			} else if (rc == MM_DB_ERROR) {
				mm_sql_db_err_rsp_new(cmd, db);
				free(response);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}

			/* set the attribute to its default */
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(objname) + 15);
			off = snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    "UPDATE \"%s\" SET ", objname);

			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    strlen(attr->pn_string) + 14);
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    "\"%s\" = DEFAULT WHERE \"%s\" = '%s'",
			    attr->pn_string, id, name);

			/* set attribute to default */
			if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_OK) {
				mm_sql_db_err_rsp_new(cmd, db);
				free(response);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
		}
	}

	/*
	 * Notify clients
	 */
	if (notify_obj) {
		if (mm_notify_add_config(mm_wka,
		    cmd,
		    "change", notify_obj,
		    cmd->wka_ptr->wka_conn.cci_instance,
		    cmd->wka_ptr->wka_conn.cci_host)) {
			mms_trace(MMS_ERR,
			    "mm_private_cmd_func: "
			    "error adding config change event");
		}
	}

	/*
	 * Return the get report
	 */
	if (cmd->cmd_buf) {
		free(cmd->cmd_buf);
		cmd->cmd_buf = NULL;
		cmd->cmd_bufsize = 0;
	}
	cmd->cmd_buf = response;
	cmd->cmd_bufsize = strlen(response) + 1;
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	free(data);
	free(response);
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);

}

int
mm_startup_private(mm_wka_t *mm_wka) {
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	uuid_text_t	task;
	char		*buf;
	mm_command_t	*pvt_cmd;

	PGresult		*system_results;

	/*
	 * Add change tracing private command to command queue
	 */

	if (mm_db_exec(HERE, db,
	    "select \"SystemDiskMountTimeout\" "
	    "from \"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR,
		    "error getting SystemDiskMountTimeout");
		return (1);
	}

	system_results = db->mm_db_results;

	if (mm_wka->mm_wka_mm_lang == MM_LANG_LMP) {

		mms_trace(MMS_DEVP, "Set lmp tracing");

		if (mm_db_exec(HERE, db, "select \"LMMessageLevel\","
		    "\"TraceLevel\",\"TraceFileSize\" from \"LM\" where "
		    "\"LMName\" = '%s';", conn->cci_instance) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&system_results);
			return (1);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&system_results);
			return (1);
		}

		mm_get_uuid(task);

		buf = mms_strnew("private task[\"%s\"] "
		    "set[\"LMMessageLevel\" \"%s\" "
		    "\"TraceLevel\" \"%s\" "
		    "\"TraceFileSize\" \"%s\" "
		    "\"SystemDiskMountTimeout\" \"%s\"];",
		    task,
		    PQgetvalue(db->mm_db_results, 0, 0),
		    PQgetvalue(db->mm_db_results, 0, 1),
		    PQgetvalue(db->mm_db_results, 0, 2),
		    PQgetvalue(system_results, 0, 0));
		mm_clear_db(&system_results);

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
			mm_clear_db(&system_results);
			return (1);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&system_results);
			return (1);
		}

		mm_get_uuid(task);

		buf = mms_strnew("private task[\"%s\"] "
		    "set[\"DMMessageLevel\" \"%s\" "
		    "\"TraceLevel\" \"%s\" "
		    "\"TraceFileSize\" \"%s\" "
		    "\"SystemDiskMountTimeout\" \"%s\"];",
		    task,
		    PQgetvalue(db->mm_db_results, 0, 0),
		    PQgetvalue(db->mm_db_results, 0, 1),
		    PQgetvalue(db->mm_db_results, 0, 2),
		    PQgetvalue(system_results, 0, 0));

		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&system_results);

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

int
mm_hello_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	int		 row = 0;
	int		 rows = 0;
	mms_par_node_t	*clause = NULL;
	mms_par_node_t	*value = NULL;

	int		 error = 0;
	int		 found = 0;
	mms_par_node_t	*work = NULL;
	char		*tag = NULL;

	char		*password = NULL;
	char		*mm_password = NULL;

#ifdef	MMS_OPENSSL
	char		*certificate = NULL;
	char		*auth_message = NULL;
	mms_err_t	err;
	char		ebuf[MMS_EBUF_LEN];
#endif	/* MMS_OPENSSL */

	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;

	int		 configured;
	int		 rc;

	mms_trace(MMS_DEVP, "mm hello command");
	if (cmd->cmd_state == 0) {
		if (mm_wka->wka_hello_needed == B_FALSE) {
			mms_trace(MMS_DEVP, "No hello Necessary...");
			goto unsupported;

		}
		/* get client connection info */
		clause = mms_pn_lookup_arg(cmd->cmd_root, "client",
		    MMS_PN_CLAUSE, NULL);
		if (clause == NULL) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "missing client clause");
			goto unsupported;
		}
		/* client clause is present */
		value = mms_pn_lookup_arg(clause, NULL,
		    MMS_PN_STRING, NULL);
		if ((value == NULL) ||
		    (value->pn_string == NULL)) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "missing client clause string");
			goto unsupported;
		}
		conn->cci_client = mms_strapp(conn->cci_client,
		    value->pn_string);
		if (conn->cci_client == NULL) {
			mms_trace(MMS_ERR, "null connection client");
			goto unsupported;
		}

		mms_trace(MMS_DEBUG, "client %s", conn->cci_client);
		clause = NULL;
		value = NULL;
		/* get instance info */
		clause = mms_pn_lookup_arg(cmd->cmd_root, "instance",
		    MMS_PN_CLAUSE, NULL);
		if (clause == NULL) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "missing instance clause");
			goto unsupported;
		}
		/* instance clause is present */
		value = mms_pn_lookup_arg(clause, NULL,
		    MMS_PN_STRING, NULL);
		if ((value == NULL) ||
		    (value->pn_string == NULL)) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "missing instance clause string");
			goto unsupported;
		}
		conn->cci_instance = mms_strapp(conn->cci_instance,
		    value->pn_string);
		if (conn->cci_instance == NULL) {
			mms_trace(MMS_ERR, "null connection instance");
			goto unsupported;
		}
		mms_trace(MMS_DEBUG, "instance %s", conn->cci_instance);

		/* Get optional tag arg */
		clause = mms_pn_lookup_arg(cmd->cmd_root, "tag",
		    MMS_PN_CLAUSE, NULL);
		if (clause != NULL) {
			/* tag clause is present */
			value = mms_pn_lookup_arg(clause, NULL,
			    MMS_PN_STRING, NULL);
			tag = value->pn_string;
			mms_trace(MMS_DEVP,
			    "session tag will be %s",
			    tag);
		}

		clause = NULL;
		value = NULL;
		/* get language info */
		clause = mms_pn_lookup_arg(cmd->cmd_root, "language",
		    MMS_PN_CLAUSE, NULL);
		if (clause == NULL) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "missing language clause");
			goto unsupported;
		}
		/* language clause is present */
		value = mms_pn_lookup_arg(clause, NULL,
		    MMS_PN_KEYWORD, NULL);
		if ((value == NULL) ||
		    (value->pn_string == NULL)) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "missing language clause keyword");
			goto unsupported;
		}
		mm_wka->wka_privilege = MM_PRIV_STANDARD;
		if (strcmp(value->pn_string, "MMP") == 0) {
			cmd->cmd_language = MM_LANG_MMP;
			mm_wka->mm_wka_mm_lang = MM_LANG_MMP;
			if (strcmp(conn->cci_client, MM_APP) == 0 &&
			    (strcmp(conn->cci_instance, MM_ADMIN) == 0 ||
			    strcmp(conn->cci_instance, MM_OPER) == 0)) {
				mm_wka->wka_privilege = MM_PRIV_ADMIN;
			}
		} else if (strcmp(value->pn_string, "DMP") == 0) {
			cmd->cmd_language = MM_LANG_DMP;
			mm_wka->mm_wka_mm_lang = MM_LANG_DMP;
			mm_wka->wka_privilege = MM_PRIV_SYSTEM;
		} else if (strcmp(value->pn_string, "LMP") == 0) {
			cmd->cmd_language = MM_LANG_LMP;
			mm_wka->mm_wka_mm_lang = MM_LANG_LMP;
			mm_wka->wka_privilege = MM_PRIV_SYSTEM;
		} else {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "unknown language in hello");
			mm_wka->wka_unwelcome = 1;
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(UNWELCOME_LANG) + 1);

			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    UNWELCOME_LANG);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_DONE);
		}
		conn->cci_language = mms_strapp(conn->cci_language,
		    value->pn_string);
		if (conn->cci_language == NULL) {
			mms_trace(MMS_ERR, "null connection language");
			goto unsupported;
		}
		mms_trace(MMS_DEBUG, "language %s", conn->cci_language);

		clause = NULL;
		value = NULL;
		clause = mms_pn_lookup_arg(cmd->cmd_root, "version",
		    MMS_PN_CLAUSE, NULL);
		if (clause == NULL) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "missing version clause");
			goto unsupported;
		}

		found = 0;
		work = NULL;
		while (!found && (value = mms_pn_lookup(clause, NULL,
		    MMS_PN_STRING,
		    &work)) != NULL) {
			mms_trace(MMS_DEBUG, "version %s", value->pn_string);
			if (strcmp(value->pn_string, "1.0") == 0) {
				conn->cci_version =
				    mms_strapp(conn->cci_version,
				    value->pn_string);
				if (conn->cci_version == NULL) {
					mms_trace(MMS_ERR,
					    "null connection version");
					goto unsupported;
				}
				found = 1;
			}
		}

		if (!found) {
			mms_trace(MMS_DEVP, "version not found");
			goto unsupported;
		}

		switch (cmd->cmd_language) {
		case MM_LANG_MMP:
			rc = mm_db_exec_si(HERE, db,
			    "select \"Password\" "
			    "from \"MMPASSWORD\" "
			    "where \"ApplicationName\" = '%s';",
			    conn->cci_client);
			break;
		case MM_LANG_LMP:
		case MM_LANG_DMP:
			/* lm and dm use watcher's password */
			rc = mm_db_exec_si(HERE, db,
			    "select \"Password\" "
			    "from \"MMPASSWORD\" "
			    "where \"ApplicationName\" = '%s';",
			    MM_APP);
			break;
		}
		if (rc != MM_DB_DATA ||
		    PQntuples(db->mm_db_results) != 1 ||
		    (password = PQgetvalue(db->mm_db_results, 0, 0)) == NULL) {
			mm_clear_db(&db->mm_db_results);
			mms_trace(MMS_ERR, "expected password retrieval");
			goto denied;
		}

		free(conn->cci_password);
		conn->cci_password = strdup(password);
		mm_clear_db(&db->mm_db_results);
		password = NULL;

		/* verify hello password or cert clause */
		if ((clause = mms_pn_lookup_arg(cmd->cmd_root, "password",
		    MMS_PN_CLAUSE, NULL)) != NULL) {
			value = mms_pn_lookup_arg(clause, NULL,
			    MMS_PN_STRING, NULL);
			password = strdup(value->pn_string);
		}
#ifdef	MMS_OPENSSL
		if ((clause = mms_pn_lookup_arg(cmd->cmd_root, "certificate",
		    MMS_PN_CLAUSE, NULL)) != NULL) {
			mms_par_node_t	*index = NULL;

			value = mms_pn_lookup_arg(clause, NULL,
			    MMS_PN_STRING, &index);
			certificate = value->pn_string;

			value = mms_pn_lookup_arg(clause, NULL,
			    MMS_PN_STRING, &index);
			auth_message = value->pn_string;

			mms_trace(MMS_DEBUG,
			    "certificate/auth\n%s\n%s",
			    certificate,
			    auth_message);

			/* get password from encrypted data */
			if (mms_ssl_verify_cert_clause(
			    mm_wka->mm_data->mm_ssl_data,
			    mm_wka->mm_wka_conn,
			    certificate,
			    auth_message,
			    &password)) {
				mms_get_error_string(&err,
				    ebuf, MMS_EBUF_LEN);
				mms_trace(MMS_ERR,
				    "invalid cert clause %s", ebuf);
				goto denied;
			}
		}
#endif	/* MMS_OPENSSL */
		if (password == NULL) {
			mms_trace(MMS_ERR, "no password");
			goto denied;
		}
		/* get password hash */
		rc = mm_db_exec_si(HERE, db,
		    "select mm_func_getpassword('%s');",
		    password);
		free(password);
		if (rc != MM_DB_DATA || PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR, "get password hash");
			mm_clear_db(&db->mm_db_results);
			goto denied;
		}
		/* compare password hashes */
		rc = strcmp(conn->cci_password,
		    PQgetvalue(db->mm_db_results, 0, 0));
		mm_clear_db(&db->mm_db_results);
		if (rc == 0) {
			mms_trace(MMS_DEVP, "password ok");
		} else {
			mms_trace(MMS_ERR, "invalid password");
			goto denied;
		}


		error = 0;
		configured = 0;
		switch (cmd->cmd_language) {
		case MM_LANG_MMP:
			if (mm_db_exec(HERE, db,
			    "SELECT "\
			    "\"APPLICATION\".\"ApplicationName\","
			    "\"AI\".\"AIName\", "\
			    "\"AI\".\"ApplicationName\","
			    "\"AI\".\"SessionsAllowed\" FROM "
			    "\"APPLICATION\",\"AI\" WHERE "
			    "(\"APPLICATION\".\"ApplicationName\" "\
			    "= '%s' AND "
			    "\"AI\".\"AIName\" = '%s') AND "
			    "\"AI\".\"ApplicationName\" = '%s'",
			    conn->cci_client,
			    conn->cci_instance,
			    conn->cci_client) != MM_DB_DATA) {
				error = 1;
			} else if (PQntuples(db->mm_db_results) == 1) {
				if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
				    conn->cci_client) == 0 &&
				    strcmp(PQgetvalue(db->mm_db_results, 0, 1),
				    conn->cci_instance) == 0 &&
				    strcmp(PQgetvalue(db->mm_db_results, 0, 2),
				    conn->cci_client) == 0) {
					configured = 1;
				}
			}
			mm_clear_db(&db->mm_db_results);
			break;
		case MM_LANG_DMP:
			/*
			 * Drive.DMName is only set when DM is activate enable.
			 */
			if (mm_db_exec(HERE, db,
			    "SELECT \"DRIVE\".\"DriveName\","
			    "\"DM\".\"DMName\",\"DM\"."\
			    "\"DriveName\" "
			    "FROM \"DRIVE\",\"DM\" WHERE "
			    "(\"DRIVE\".\"DriveName\" = '%s' AND "
			    "\"DM\".\"DMName\" = '%s' AND "
			    "\"DM\".\"DriveName\" = '%s')",
			    conn->cci_client, conn->cci_instance,
			    conn->cci_client) != MM_DB_DATA) {
				error = 1;
			} else if (PQntuples(db->mm_db_results) == 1) {
				if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
				    conn->cci_client) == 0 &&

				    strcmp(PQgetvalue(db->mm_db_results, 0, 1),
				    conn->cci_instance) == 0 &&

				    strcmp(PQgetvalue(db->mm_db_results, 0, 2),
				    conn->cci_client) == 0) {

					configured = 1;
				}
			}
			mm_clear_db(&db->mm_db_results);
			break;
		case MM_LANG_LMP:
			/*
			 * LIBRARY.LMName is set by the user.
			 */
			if (mm_db_exec(HERE, db,
			    "SELECT \"LIBRARY\".\"LibraryName\","
			    "\"LM\".\"LMName\",\"LM\"."\
			    "\"LibraryName\" "
			    "FROM \"LIBRARY\",\"LM\" WHERE "
			    "(\"LIBRARY\".\"LibraryName\" "\
			    "= '%s' AND "
			    "\"LM\".\"LMName\" = '%s' AND "
			    "\"LM\".\"LibraryName\" = '%s')",
			    conn->cci_client, conn->cci_instance,
			    conn->cci_client) != MM_DB_DATA) {
				error = 1;
			} else if (PQntuples(db->mm_db_results) == 1) {
				if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
				    conn->cci_client) == 0 &&

				    strcmp(PQgetvalue(db->mm_db_results, 0, 1),
				    conn->cci_instance) == 0 &&

				    strcmp(PQgetvalue(db->mm_db_results, 0, 2),
				    conn->cci_client) == 0) {

					configured = 1;
				}
			}
			mm_clear_db(&db->mm_db_results);
			break;
		}
		if (error == 1 || configured == 0) {
			if (error)
				mms_trace(MMS_ERR, "unable to validate config");
			if (!configured)
				mms_trace(MMS_INFO, "HINT: %s %s (%s) "
				    "not configured",
				    conn->cci_client,
				    conn->cci_instance,
				    mm_cci_host_ident(conn));
			goto denied;
		}
		/* check for duplicate device managers on same host */
		if (mm_db_exec(HERE, db, "SELECT \"ConnectionClientName\","
		    "\"ConnectionClientInstance\", "\
		    "\"ConnectionClientHost\" "
		    "FROM \"CONNECTION\"") != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "mm_hello_cmd_func: "
			    "db error getting connection info,"
			    "return unwelcome");
			goto denied;
		}
		rows = PQntuples(db->mm_db_results);
		for (row = 0; row < rows; row++) {
			switch (cmd->cmd_language) {
			case MM_LANG_DMP:
			case MM_LANG_LMP:
				if (strcmp(PQgetvalue(db->mm_db_results,
				    row, 0),
				    conn->cci_client) == 0 &&
				    strcmp(PQgetvalue(db->mm_db_results,
				    row, 1),
				    conn->cci_instance) == 0 &&
				    strcmp(PQgetvalue(db->mm_db_results,
				    row, 2),
				    mm_cci_host_ident(conn)) == 0) {

					mm_clear_db(&db->mm_db_results);

					mms_trace(MMS_ERR,
					    "mm_hello_cmd_func: "
					    "duplicate session found, "
					    "return unwelcome");
					mm_wka->wka_unwelcome = 1;
					SQL_CHK_LEN(&cmd->cmd_buf, 0,
					    &cmd->cmd_bufsize,
					    strlen(UNWELCOME_DUP) + 1);

					(void) snprintf(cmd->cmd_buf,
					    cmd->cmd_bufsize, UNWELCOME_DUP);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					return (MM_CMD_DONE);
				}
				break;
			}
		}
		mm_clear_db(&db->mm_db_results);

		/* For MMP clients, check that Ai.SessionsAllowed */
		/* allows them to conect */
		if (cmd->cmd_language == MM_LANG_MMP) {
			if (mm_db_exec(HERE, db,
			    "SELECT \"CONNECTION\".\"ConnectionID\","
			    "\"AI\".\"SessionsAllowed\" FROM"
			    "\"CONNECTION\" cross join \"AI\""
			    "where"
			    "("
			    "(\"CONNECTION\"."
			    "\"ConnectionClientInstance\" = "
			    "\"AI\".\"AIName\")"
			    "and"
			    "(\"CONNECTION\"."
			    "\"ConnectionClientName\" = "
			    "\"AI\".\"ApplicationName\")"
			    "and"
			    "(\"AI\".\"AIName\" = '%s')"
			    "and"
			    "(\"AI\".\"ApplicationName\" = '%s')"
			    ");",
			    conn->cci_instance,
			    conn->cci_client) != MM_DB_DATA) {
				goto denied;
			}
			if ((PQntuples(db->mm_db_results) != 0) &&
			    (strcmp(PQgetvalue(db->mm_db_results, 0, 1),
			    "single") == 0)) {
				/* This is a duplicate session */
				/* with single session allowed */
				mms_trace(MMS_ERR,
				    "multiple sessions not allowed for %s, %s",
				    conn->cci_client,
				    conn->cci_instance);
				mm_clear_db(&db->mm_db_results);
				mm_wka->wka_unwelcome = 1;
				SQL_CHK_LEN(&cmd->cmd_buf, 0,
				    &cmd->cmd_bufsize,
				    strlen(UNWELCOME_DUP) + 1);

				(void) snprintf(cmd->cmd_buf,
				    cmd->cmd_bufsize, UNWELCOME_DUP);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_DONE);
			}
			mm_clear_db(&db->mm_db_results);
		}


		if (mm_db_exec(HERE, db, "INSERT INTO \"CONNECTION\" "
		    "(\"Language\",\"ConnectionClientName\","
		    "\"ConnectionClientInstance\", "\
		    "\"ConnectionClientHost\","
		    "\"ConnectionClientPort\", "\
		    "\"ConnectionID\") "
		    "VALUES('%s','%s','%s','%s','%d','%s')",
		    conn->cci_language,
		    conn->cci_client,
		    conn->cci_instance,
		    mm_cci_host_ident(conn),
		    conn->cci_port,
		    mm_wka->wka_conn.cci_uuid)
		    != MM_DB_OK) {
			goto denied;
		}

		if (mm_db_exec(HERE, db, "INSERT INTO \"NOTIFY\" "
		    "(\"ConnectionClientName\", "
		    "\"ConnectionClientInstance\","
		    "\"ConnectionID\") "
		    "VALUES ('%s','%s','%s')",
		    conn->cci_client,
		    conn->cci_instance,
		    mm_wka->wka_conn.cci_uuid) != MM_DB_OK) {
			goto denied;
		}

		/* add session */
		if (cmd->cmd_language == MM_LANG_MMP) {
			mm_get_uuid(mm_wka->session_uuid);
			if (mm_db_exec(HERE, db,
			    "INSERT INTO \"SESSION\" "
			    "(\"SessionID\", "
			    "\"ApplicationName\", "
			    "\"AIName\","
			    "\"SessionClientHost\", "
			    "\"SessionClientPort\", "
			    "\"ConnectionID\") "
			    "VALUES ('%s','%s','%s',"
			    "'%s','%d','%s')",
			    mm_wka->session_uuid,
			    conn->cci_client,
			    conn->cci_instance,
			    mm_cci_host_ident(conn),
			    conn->cci_port,
			    mm_wka->wka_conn.cci_uuid)
			    != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "db error inserting session obj");
				goto denied;
			}
			if (tag != NULL) {
				/* Set the session tag */
				if (mm_db_exec(HERE, db,
				    "update \"SESSION\" set "
				    "\"SessionTag\" = '%s'"
				    " where \"SessionID\" = '%s';",
				    tag, mm_wka->session_uuid) != MM_DB_OK) {
					mms_trace(MMS_ERR,
					    "db error setting session tag");
					goto denied;
				}
			}

		} else if (cmd->cmd_language == MM_LANG_DMP) {
			/* update dm host */
			if (mm_db_exec(HERE, db, "update \"DM\" "
			    "set \"DMHost\" = '%s' "
			    "where \"DriveName\" = '%s' "
			    "and \"DMName\" = '%s';",
			    mm_cci_host_ident(conn),
			    conn->cci_client,
			    conn->cci_instance) != MM_DB_OK) {
				goto denied;
			}
		} else if (cmd->cmd_language == MM_LANG_LMP) {
			/* update lm host */
			if (mm_db_exec(HERE, db, "update \"LM\" "
			    "set \"LMHost\" = '%s' "
			    "where \"LibraryName\" = '%s' "
			    "and \"LMName\" = '%s';",
			    mm_cci_host_ident(conn),
			    conn->cci_client,
			    conn->cci_instance) != MM_DB_OK) {
				goto denied;
			}
		}

		/* welcome new client */
		mm_password = mm_wka->mm_data->mm_cfg.mm_network_cfg.mm_pass;
		if (mm_password == NULL) {
			SQL_CHK_LEN(&cmd->cmd_buf, 0,
			    &cmd->cmd_bufsize, strlen(MMS_WELCOME) +
			    strlen(conn->cci_version) +
			    strlen(mm_wka->mm_data->mm_cfg.
			    mm_network_cfg.cli_name) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    MMS_WELCOME, conn->cci_version,
			    mm_wka->mm_data->mm_cfg.mm_network_cfg.cli_name);
#ifdef	MMS_OPENSSL
		} else if (mms_ssl_has_cert_clause(mm_wka->
		    mm_data->mm_ssl_data,
		    mm_wka->mm_wka_conn)) {
			if (mms_ssl_build_cert_clause(mm_wka->mm_data->
			    mm_ssl_data,
			    mm_wka->mm_wka_conn,
			    mm_password,
			    &certificate,
			    &auth_message)) {
				mms_get_error_string(&err, ebuf,
				    MMS_EBUF_LEN);
				mms_trace(MMS_ERR, "welcome cert clause - %s",
				    ebuf);
				goto denied;

			}
			SQL_CHK_LEN(&cmd->cmd_buf, 0,
			    &cmd->cmd_bufsize, strlen(WELCOME_CERT) +
			    strlen(conn->cci_version) +
			    strlen(mm_wka->mm_data->mm_cfg.
			    mm_network_cfg.cli_name) +
			    strlen(certificate) +
			    strlen(auth_message) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    WELCOME_CERT, conn->cci_version,
			    mm_wka->mm_data->mm_cfg.mm_network_cfg.cli_name,
			    certificate,
			    auth_message);
			mms_trace(MMS_DEBUG,
			    "certificate/auth\n%s\n%s",
			    certificate,
			    auth_message);
			free(certificate);
			free(auth_message);
#endif	/* MMS_OPENSSL */
		} else {
			SQL_CHK_LEN(&cmd->cmd_buf, 0,
			    &cmd->cmd_bufsize, strlen(WELCOME_PASS) +
			    strlen(conn->cci_version) +
			    strlen(mm_wka->mm_data->mm_cfg.
			    mm_network_cfg.cli_name) +
			    strlen(mm_password) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    WELCOME_PASS, conn->cci_version,
			    mm_wka->mm_data->mm_cfg.mm_network_cfg.cli_name,
			    mm_password);
			mms_trace(MMS_DEBUG, "adding password");
		}
		mm_wka->wka_hello_needed = B_FALSE;
		cmd->cmd_remove = 1;

		mms_trace(MMS_INFO, "Welcome, %s, %s, %s",
		    conn->cci_client,
		    conn->cci_instance,
		    conn->cci_language);

		if ((strcmp(conn->cci_client, "MMS") == 0) &&
		    (strcmp(conn->cci_instance, "watcher") == 0)) {
			mm_wka->wka_privilege = MM_PRIV_ADMIN;
		}

		mm_send_text_si(mm_wka->mm_wka_conn, cmd->cmd_buf);

		if (cmd->cmd_language != MM_LANG_MMP) {
			/* Send device manager private cmd */
			if (mm_startup_private(mm_wka)) {
				mms_trace(MMS_ERR,
				    "error sending "
				    "private command");
			}
		}

		/* Add LM Activate */

		if (rc == 0 && cmd->cmd_language == MM_LANG_LMP) {
			/* activate enable library lm */
			if (mm_library_lm_connect(mm_wka)) {
				mms_trace(MMS_ERR, "library lm access");
				return (MM_CMD_ERROR);
			} else if (mm_library_lm_activate_enable(mm_wka) == 0) {
				mms_trace(MMS_INFO, "Added LM Activate Enable"
				    "for %s",
				    mm_wka->wka_conn.cci_instance);
				return (MM_DISPATCH_AGAIN);
			}
		}

		/* Add DM Activate */

		if (rc == 0 && cmd->cmd_language == MM_LANG_DMP) {
			/* activate enable */
			mm_sql_update_state(mm_wka->mm_data, "DM",
			    "DMStateSoft",
			    "present", "DMName",
			    mm_wka->wka_conn.cci_instance);
			if (mm_drive_dm_activate_enable(mm_wka) != NULL) {
				mms_trace(MMS_INFO, "Added DM Activate Enable"
				    "for %s",
				    mm_wka->wka_conn.cci_instance);
				return (MM_DISPATCH_AGAIN);
			}
		}

		/* hello complete */
		return (MM_CMD_DONE);
	}


no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);


not_found:
	mms_trace(MMS_ERR, "not_found in hello cmd func");
	mm_wka->wka_unwelcome = 1;
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(UNWELCOME_PROTO) + 1);

	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, UNWELCOME_PROTO);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);


unsupported:
	mms_trace(MMS_ERR, "unsupported in hello cmd func");
	mm_wka->wka_unwelcome = 1;
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(UNWELCOME_UNSUP) + 1);

	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, UNWELCOME_UNSUP);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);

	return (MM_CMD_DONE);


denied:
	mms_trace(MMS_ERR, "denied in hello cmd func");
	mm_wka->wka_unwelcome = 1;
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(UNWELCOME_DENIED) + 1);

	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, UNWELCOME_DENIED);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);

	return (MM_CMD_DONE);
}



int
mm_move_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t		*arg;
	mms_par_node_t		*value;
	char			*toslot;
	int			rows;
	PGresult		*cart_results;
	PGresult		*lm_results;
	int			rc;
	char			taskid[UUID_PRINTF_SIZE];
	char			*libname;
	char			*lmname;
	mms_par_node_t		*work = NULL;
	mms_par_node_t		*next;
	char			*cartid;
	char			*sidename;
	char			*cartpcl;
	char			*slottype;
	const char		*query;
	mms_par_node_t		*cart;
	char			*slotname;
	char			*state;
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	char			*const_buf = NULL;


	mms_trace(MMS_DEVP, "mm move command");
	if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
		rc = MM_CMD_ERROR;
		goto end;
	}

	/* slot */
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "toslot", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, NULL);
	toslot = value->pn_string;


	/* constraints */
	if (cart = mms_pn_lookup(cmd->cmd_root, "cartid",
	    MMS_PN_CLAUSE, &work)) {

		mms_trace(MMS_DEVP,
		    "move command cartid clause");

		if (const_buf != NULL) {
			free(const_buf);
			const_buf = NULL;
		}

		if (mm_add_match_list("SIDE", &cmd->cmd_dest_list)) {
			mms_trace(MMS_DEVP, "SIDE  "
			    "already in dest list");
		} else {
			cmd->cmd_dest_num ++;
		}


		mms_trace(MMS_DEVP, "    lookup cartid");
		work = NULL;
		MMS_PN_LOOKUP(value, cart, NULL, MMS_PN_STRING, &work);
		cartid = value->pn_string;

		const_buf = mms_strapp(const_buf,
		    "(\"SIDE\".\"CartridgeID\" = '%s' AND ",
		    cartid);

		mms_trace(MMS_DEVP, "    lookup sidename");

		MMS_PN_LOOKUP(value, cart, NULL, MMS_PN_STRING, &work);
		sidename = value->pn_string;
		const_buf = mms_strapp(const_buf,
		    "\"SIDE\".\"SideName\" = '%s') ",
		    sidename);
		if (mm_add_match_list(const_buf, &cmd->cmd_const_list)) {
			mms_trace(MMS_DEVP, "SIDE constraint "
			    "already in const list");
		} else {
			cmd->cmd_const_num ++;
		}
		if (const_buf != NULL) {
			free(const_buf);
			const_buf = NULL;
		}


	} else if (cart = mms_pn_lookup(cmd->cmd_root, "cart",
	    MMS_PN_CLAUSE, &work)) {
		mms_trace(MMS_DEVP,
		    "move command cart clause");
		mms_trace(MMS_DEVP, "    lookup cartpcl");
		MMS_PN_LOOKUP(value, cart, NULL, MMS_PN_STRING, NULL);
		cartpcl = value->pn_string;

		mms_trace(MMS_DEVP, "    lookup slottype");
		MMS_PN_LOOKUP(next, cart, "cart", MMS_PN_CLAUSE, &work);
		MMS_PN_LOOKUP(value, next, NULL, MMS_PN_STRING, NULL);
		slottype = value->pn_string;

		mms_trace(MMS_DEVP, "    lookup sidename");
		MMS_PN_LOOKUP(next, cart, "cart", MMS_PN_CLAUSE, &work);
		MMS_PN_LOOKUP(value, next, NULL, MMS_PN_STRING, NULL);
		sidename = value->pn_string;

		if (const_buf != NULL) {
			free(const_buf);
			const_buf = NULL;
		}
		if (mm_add_match_list("SIDE",
		    &cmd->cmd_dest_list)) {
			mms_trace(MMS_DEVP, "SIDE  "
			    "already in dest list");
		} else {
			cmd->cmd_dest_num ++;
		}
		if (mm_add_match_list("CARTRIDGE",
		    &cmd->cmd_dest_list)) {
			mms_trace(MMS_DEVP, "CARTRIDGE  "
			    "already in dest list");
		} else {
			cmd->cmd_dest_num ++;
		}
		if (mm_add_match_list("SLOTTYPE",
		    &cmd->cmd_dest_list)) {
			mms_trace(MMS_DEVP, "SLOTTYPE  "
			    "already in dest list");
		} else {
			cmd->cmd_dest_num ++;
		}
		const_buf = mms_strapp(const_buf,
		    "(\"CARTRIDGE\".\"CartridgePCL\" = '%s' AND "
		    "\"SLOTTYPE\".\"SlotTypeName\" = '%s' AND "
		    "\"SIDE\".\"SideName\" = '%s') ",
		    cartpcl,
		    slottype, sidename);
		if (mm_add_match_list(const_buf, &cmd->cmd_const_list)) {
			mms_trace(MMS_DEVP, "cart constraint "
			    "already in const list");
		} else {
			cmd->cmd_const_num ++;
		}

	} else {
		mms_trace(MMS_DEVP,
		    "move command match clause");

		if (mm_get_dest(mm_wka, cmd)) {
			/* Command does not have a match/volname clause */
			mms_trace(MMS_DEVP, "No match/volname Clause???");
		} else {
			/* TEMP - Trace out our dest info */
			mms_trace(MMS_DEVP,
			    "Dest count is %d", cmd->cmd_dest_num);
			mm_print_char_list(&cmd->cmd_dest_list);
		}
		if (mm_get_const(mm_wka, cmd)) {
			/* Command does not have a match/volname clause */
			mms_trace(MMS_DEVP, "No match/volname Clause???");
		} else {
			/* TEMP - Trace out our const info */
			mms_trace(MMS_DEVP,
			    "Const count is %d", cmd->cmd_const_num);
			mm_print_char_list(&cmd->cmd_const_list);
		}

	}

	/* cartridge */
	query = "SELECT \"SLOT\".\"SlotName\",\"CARTRIDGE\".\"CartridgePCL\","
	    "\"SIDE\".\"SideName\",\"CARTRIDGE\".\"LibraryName\","
	    "\"CARTRIDGE\".\"CartridgeState\" FROM ";
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) + 1);

	if (mm_add_match_list("SLOT", &cmd->cmd_source_list)) {
		mms_trace(MMS_DEVP, "SLOT already in source list");
	} else {
		cmd->cmd_source_num ++;
	}
	if (mm_add_match_list("CARTRIDGE", &cmd->cmd_source_list)) {
		mms_trace(MMS_DEVP, "CARTRIDGE already in source list");
	} else {
		cmd->cmd_source_num ++;
	}
	if (mm_add_match_list("SIDE", &cmd->cmd_source_list)) {
		mms_trace(MMS_DEVP, "SIDE already in source list");
	} else {
		cmd->cmd_source_num ++;
	}

	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_move_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}
	mm_sql_order(cmd);
	mm_sql_number(cmd);



	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		goto db_error;
	}
	rows = PQntuples(db->mm_db_results);
	if (rows == 0) {
		mm_clear_db(&db->mm_db_results);
		if (cart) {
			mm_response_error(cmd,
			    ECLASS_EXIST,
			    ENOSUCHCART,
			    MM_5069_MSG,
			    NULL);

		} else {
			mm_response_error(cmd,
			    ECLASS_EXIST,
			    ENOMATCH,
			    MM_5069_MSG,
			    NULL);
		}
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	} else if (rows > 1) {
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_EXPLICIT,
		    ETOOMANY,
		    MM_5070_MSG,
		    NULL);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}
	cart_results = db->mm_db_results;

	slotname = PQgetvalue(cart_results, 0, 0);
	cartpcl = PQgetvalue(cart_results, 0, 1);
	sidename = PQgetvalue(cart_results, 0, 2);
	libname = PQgetvalue(cart_results, 0, 3);
	state = PQgetvalue(cart_results, 0, 4);

	if (strcmp(state, "identified") == 0) {
		mm_clear_db(&cart_results);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    ECARTNOTLOCATED,
		    MM_5071_MSG,
		    "pcl",
		    cartpcl,
		    NULL);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}
	if (mm_db_exec(HERE, db, "SELECT \"LMName\" FROM \"LM\" WHERE "
	    "\"LibraryName\" = '%s'", libname) != MM_DB_DATA) {
		mm_clear_db(&cart_results);
		goto db_error;
	}
	rows = PQntuples(db->mm_db_results);
	if (rows == 0) {
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&cart_results);
		mm_response_error(cmd,
		    ECLASS_CONFIG,
		    ELIBNOLMCONFIGURED,
		    MM_5072_MSG,
		    "lib",
		    libname,
		    NULL);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	} else if (rows > 1) {
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&cart_results);
		mm_system_error(cmd,
		    "row number mismatch, "
		    "to many device manager rows returned");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}
	lm_results = db->mm_db_results;
	lmname = PQgetvalue(lm_results, 0, 0);

	/* check for online library */
	if (mm_db_exec(HERE, db, "SELECT "
	    "\"LIBRARY\".\"LibraryStateSoft\",\"LM\".\"LMStateSoft\" "
	    "FROM \"LIBRARY\",\"LM\" "
	    "WHERE (\"LIBRARY\".\"LibraryName\" = '%s' AND "
	    "\"LIBRARY\".\"LMName\" = '%s') AND "
	    "(\"LM\".\"LibraryName\" = '%s' AND "
	    "\"LM\".\"LMName\" = '%s')",
	    libname, lmname, libname, lmname) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&lm_results);
		mm_clear_db(&cart_results);
		goto db_error;
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
	    "ready") != 0 ||
	    strcmp(PQgetvalue(db->mm_db_results, 0, 1),
	    "ready") != 0) {
		mm_response_error(cmd,
		    ECLASS_RETRY,
		    ELMNOTREADY,
		    MM_5073_MSG,
		    "lm",
		    lmname,
		    NULL);
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&lm_results);
		mm_clear_db(&cart_results);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}
	mm_clear_db(&db->mm_db_results);
	mm_clear_db(&lm_results);

	/* issue lm move command */
	mm_get_uuid(taskid);
	/* build lm scan cmd */
	query = "move task[\"%s\"] from[\"%s\" \"%s\" \"%s\"] "
	    "to[\"%s\" \"%s\"]";
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) +
	    strlen(taskid) + strlen(slotname) + strlen(cartpcl) +
	    strlen(sidename) + strlen(toslot) + strlen(sidename) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, query,
	    taskid, slotname, cartpcl, sidename, toslot, sidename);

	mms_trace(MMS_DEVP, "%s", cmd->cmd_buf);

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_SUCCESS, cmd->cmd_task);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_DONE;
	goto end;

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mms_trace(MMS_ERR,
	    "move command not_found");
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);

	rc = MM_CMD_ERROR;
	goto end;
end:

	return (rc);
}








int
mm_shutdown_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*clause;
	mms_par_node_t	*value;
	mms_par_node_t	*tw;
	char		*type = NULL;
	char		*restart = NULL;


	mms_trace(MMS_DEVP, "mm shutdown command %d", cmd->cmd_state);

	if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
		return (MM_CMD_ERROR);
	}

	tw = NULL;
	MMS_PN_LOOKUP(clause, cmd->cmd_root, "type", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_KEYWORD, &tw);
	if (strcmp(value->pn_string, "restart") == 0) {
		restart = value->pn_string;
	} else {
		type = value->pn_string;
	}
	if (value = mms_pn_lookup(clause, NULL, MMS_PN_KEYWORD, &tw)) {
		if (strcmp(value->pn_string, "restart") == 0) {
			restart = value->pn_string;
		} else {
			type = value->pn_string;
		}
	}

	if (value = mms_pn_lookup(cmd->cmd_root, "restart",
	    MMS_PN_KEYWORD, NULL)) {
		restart = value->pn_string;
	}

	if (type)
		mms_trace(MMS_DEVP, "type %s", type);
	if (restart)
		mms_trace(MMS_DEVP, "kw %s", restart);

	/*
	 * TBD: Args: nonewapps, nonewmounts, abortqueue, force, restart.
	 *	Send device managers activate disable
	 */

	mm_exiting = 1;
	close(mm_wka->mm_data->mm_service_fd);
	mm_wka->mm_data->mm_service_fd = -1;

	mms_trace(MMS_DEVP, "success");
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
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);


}


int
mm_rename_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	 *vol;
	mms_par_node_t	 *value;
	mms_par_node_t	*work;
	int		  row;
	int		  rows;
	int		  count;
	int		  index;
	char		**volname = NULL;
	PGresult	 *results;
	int		  i;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;

	char		*buf = NULL;
	char		*query = NULL;




	mms_trace(MMS_DEVP, "sql trans rename cmd");

	/*
	 * Get volume names.
	 */
	work = NULL;
	count = 0;
	MMS_PN_LOOKUP(vol, cmd->cmd_root, "newvolname",
	    MMS_PN_CLAUSE, NULL);
	while (mms_pn_lookup(vol, NULL, MMS_PN_STRING, &work) != NULL) {
		count++;
	}
	if ((volname = (char **) malloc(sizeof (char *) * count) + 1) == NULL) {
		MM_ABORT_NO_MEM();
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	work = NULL;
	index = 0;
	for (value = mms_pn_lookup(vol, NULL, MMS_PN_STRING, &work);
	    value != NULL && index < count;
	    value = mms_pn_lookup(vol, NULL, MMS_PN_STRING, &work)) {
		volname[index++] = value->pn_string;
	}
	for (index = 0; index < count; index++)
		mms_trace(MMS_DEVP, "newvolname[%d] %s", index, volname[index]);

	/* check for duplicate volumes */
	for (index = 0; index < count; index++) {
		for (i = 0; i < count; i++) {
			if (i != index &&
			    strcmp(volname[index], volname[i]) == 0) {
				SQL_CHK_LEN(&cmd->cmd_buf, 0,
				    &cmd->cmd_bufsize,
				    strlen(RESPONSE_ERROR) +
				    strlen(cmd->cmd_task) +
				    strlen(ECLASS_INVALID) +
				    strlen(EVOLNAMEREWRITE) + 1);
				(void) snprintf(cmd->cmd_buf,
				    cmd->cmd_bufsize, RESPONSE_ERROR,
				    cmd->cmd_task, ECLASS_INVALID,
				    EVOLNAMEREWRITE);
				free(volname);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
		}
	}

	/*
	 * Find distinct volumes to rename.
	 */
	mms_trace(MMS_DEVP, "find");

	mm_clear_source(cmd);
	mm_clear_dest(cmd);
	mm_clear_const(cmd);
	(void) mm_get_dest(mm_wka, cmd);
	(void) mm_get_const(mm_wka, cmd);

	/* Add the VOLUME constraint */
	buf = mms_strapp(buf,
	    "(\"VOLUME\".\"ApplicationName\" = '%s') ",
	    conn->cci_client);


	if (!mm_add_match_list(buf, &cmd->cmd_const_list)) {
		cmd->cmd_const_num ++;
	}

	free(buf);
	if (!mm_add_match_list("VOLUME", &cmd->cmd_dest_list)) {
		cmd->cmd_dest_num ++;
	}

	query = "SELECT DISTINCT \"VOLUME\".\"CartridgeID\", "
	    "\"VOLUME\".\"VolumeName\" FROM ";

	if (!mm_add_match_list("VOLUME", &cmd->cmd_source_list)) {
		cmd->cmd_source_num ++;
	}

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) + 1);

	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_rename_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_sql_order(cmd);
	mm_sql_number(cmd);

	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		free(volname);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	results = db->mm_db_results;
	rows = PQntuples(results);

	/*
	 * Check for mounted or stale volumes.
	 */
	for (row = 0; row < rows; row++) {

		if (mm_db_exec(HERE, db, "SELECT \"CartridgeID\","
		    "\"VolumeName\" FROM \"MOUNTLOGICAL\" WHERE "
		    "\"CartridgeID\" = '%s'",
		    PQgetvalue(results, row, 0)) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) > 0) {
			mm_clear_db(&results);
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(SIMPLE_RESPONSE_ERROR_TEXT) +
			    strlen(cmd->cmd_task) + strlen(ECLASS_EXIST) +
			    strlen(EVOLINUSE) +
			    strlen(PQgetvalue(results, row, 1)) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    SIMPLE_RESPONSE_ERROR_TEXT,
			    cmd->cmd_task, ECLASS_EXIST, EVOLINUSE,
			    PQgetvalue(results, row, 1));
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);

		if (mm_db_exec(HERE, db, "SELECT \"CartridgeID\","
		    "\"VolumeName\" FROM \"STALEHANDLE\" WHERE "
		    "\"CartridgeID\" = '%s'",
		    PQgetvalue(results, row, 0)) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			mm_clear_db(&db->mm_db_results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) > 0) {
			mm_clear_db(&results);
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(SIMPLE_RESPONSE_ERROR_TEXT) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_EXIST) +
			    strlen(EVOLINUSE) +
			    strlen(PQgetvalue(results, row, 1)) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    SIMPLE_RESPONSE_ERROR_TEXT,
			    cmd->cmd_task, ECLASS_EXIST, EVOLINUSE,
			    PQgetvalue(results, row, 1));
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);
	}

	/*
	 * Rename volumes.
	 */
	for (row = 0; row < rows; row++) {
		/* check for unique volume name in apps namespace. */
		if (mm_db_exec(HERE, db, "SELECT \"VolumeName\" FROM "
		    "\"VOLUME\" WHERE \"ApplicationName\" = '%s' AND "
		    "\"VolumeName\" = '%s'",
		    conn->cci_client,
		    volname[row]) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 0) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(SIMPLE_RESPONSE_ERROR_TEXT) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_EXIST) +
			    strlen(ERENAMEDVOLEXISTS) +
			    strlen(volname[row]) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    SIMPLE_RESPONSE_ERROR_TEXT,
			    cmd->cmd_task, ECLASS_EXIST,
			    ERENAMEDVOLEXISTS, volname[row]);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);

		if (mm_db_exec(HERE, db, "UPDATE \"VOLUME\" SET "
		    "\"VolumeName\" = '%s' WHERE \"CartridgeID\" = '%s'",
		    volname[row], PQgetvalue(results, row, 0)) != MM_DB_OK) {
			mm_clear_db(&results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INTERNAL) +
			    strlen(ETRANSACTIONFAILED) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_INTERNAL, ETRANSACTIONFAILED);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}
	mm_clear_db(&results);
	free(volname);

	/*
	 * Generate report.
	 */
	mm_path_match_report(cmd, db);

	cmd->cmd_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	return (MM_CMD_DONE);


no_mem:
	MM_ABORT_NO_MEM();
	free(volname);
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	free(volname);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
}




int
mm_deallocate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	 *vol;
	mms_par_node_t	 *arg;
	int		  row;
	int		  rows;
	int		  count;
	int		  index;
	char		**volname = NULL;
	char		 *report_buf = NULL;
	PGresult	 *results;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	char			*query;
	char		*buf = NULL;


	mms_trace(MMS_DEVP, "sql trans deallocate cmd");
	/*
	 * Generate report and save it before the delete.
	 */
	mms_trace(MMS_DEVP, "report clause");

	mm_path_match_report(cmd, db);


	report_buf = cmd->cmd_buf;
	cmd->cmd_bufsize = SQL_CMD_BUF_INCR;
	if ((cmd->cmd_buf = (char *)malloc(cmd->cmd_bufsize)) == NULL) {
		MM_ABORT_NO_MEM();
		free(report_buf);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	/*
	 * Get volume names from the command.
	 */
	mms_trace(MMS_DEVP, "volnames");
	count = 0;
	if (vol = mms_pn_lookup(cmd->cmd_root, "volname",
	    MMS_PN_CLAUSE, NULL)) {
		mms_list_foreach(&vol->pn_arglist, arg) {
			count++;
		}
		if (count && (volname = (char **) malloc(sizeof (char *) *
		    count)) == NULL) {
			MM_ABORT_NO_MEM();
			free(report_buf);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		index = 0;
		mms_list_foreach(&vol->pn_arglist, arg) {
			volname[index++] = arg->pn_string;
		}
		for (index = 0; index < count; index++) {
			mms_trace(MMS_DEVP,
			    "volname[%d] %s", index, volname[index]);
		}
	}
	/*
	 * Get the volumes cartridge ids.
	 */
	mms_trace(MMS_DEVP, "partition");

	mm_clear_source(cmd);
	mm_clear_dest(cmd);
	mm_clear_const(cmd);
	(void) mm_get_dest(mm_wka, cmd);
	(void) mm_get_const(mm_wka, cmd);

	/* Add the VOLUME constraint */
	buf = mms_strapp(buf,
	    "(\"VOLUME\".\"ApplicationName\" = '%s') ",
	    conn->cci_client);

	if (!mm_add_match_list(buf, &cmd->cmd_const_list)) {
		cmd->cmd_const_num ++;
	}

	free(buf);
	if (!mm_add_match_list("VOLUME", &cmd->cmd_dest_list)) {
		cmd->cmd_dest_num ++;
	}

	query = "SELECT DISTINCT \"VOLUME\".\"CartridgeID\" "
	    "FROM ";

	if (!mm_add_match_list("VOLUME", &cmd->cmd_source_list)) {
		cmd->cmd_source_num ++;
	}

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) + 1);

	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_deallocate_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_sql_order(cmd);
	mm_sql_number(cmd);

	/* delete volumes, mountlogical foreign key prevents mounted delete */
	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		free(volname);
		free(report_buf);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	/*
	 * Delete volumes.
	 */
	results = db->mm_db_results;
	rows = PQntuples(results);
	for (row = 0; row < rows; row++) {
		if (mm_db_exec(HERE, db, "DELETE FROM \"VOLUME\" "
		    "WHERE \"CartridgeID\" = '%s'",
		    PQgetvalue(results, row, 0)) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			free(report_buf);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_db_exec(HERE, db, "UPDATE \"PARTITION\" SET "
		    "\"PartitionAllocatable\" = 'true' WHERE "
		    "\"CartridgeID\" = '%s'",
		    PQgetvalue(results, row, 0)) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			free(report_buf);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}
	for (row = 0; row < rows; row++) {

		if (mm_notify_add_volumedelete(mm_wka,
		    cmd,
		    PQgetvalue(results, row, 0),
		    db)) {
			mms_trace(MMS_ERR,
			    "mm_deallocate_cmd_func: "
			    "error adding volume delete event");
		}
		mms_trace(MMS_INFO,
		    "VOLUME, %s deallocated by %s %s",
		    PQgetvalue(results, row, 0),
		    conn->cci_client,
		    conn->cci_instance);

	}


	mm_clear_db(&results);
	free(volname);

	free(cmd->cmd_buf);
	cmd->cmd_buf = NULL;
	cmd->cmd_bufsize = 0;

	cmd->cmd_buf = report_buf;
	cmd->cmd_bufsize = strlen(report_buf) + 1;
	cmd->cmd_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
	free(volname);
	free(report_buf);
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	free(volname);
	free(report_buf);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
}


int
mm_allocate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*vol;
	mms_par_node_t	*who;
	mms_par_node_t	*value;
	mms_par_node_t	*work;
	int		row;
	int		rows;
	int		count;
	int		index;
	char		**volname = NULL;
	PGresult	*results;
	int		num;
	int		i;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	mm_range_t	range;
	char		*query;
	char		*constraint;

	char		*app_name = NULL;
	char		*ai_name = NULL;

	char		*db_buf = NULL;


	mms_trace(MMS_DEVP, "mm allocate cmd");
	/* Get who clause */
	work = NULL;



	/* who clause */
	who = mms_pn_lookup(cmd->cmd_root, "who",
	    MMS_PN_CLAUSE, NULL);
	if (who != NULL) {

		if ((value = mms_pn_lookup(who,
		    NULL,
		    MMS_PN_STRING,
		    &work)) != NULL) {
			app_name = value->pn_string;
			mms_trace(MMS_DEVP, "Use %s as application name",
			    app_name);
			if (cmd->wka_ptr->wka_privilege == MM_PRIV_STANDARD) {
				/* for standard priv, */
				/* check that app_name is the client's */
				if (strcmp(app_name, conn->cci_client) != 0) {
					mms_trace(MMS_DEVP,
					    "appcliation name in who does"
					    " not match client application");
					mm_response_error(cmd,
					    ECLASS_LANGUAGE,
					    "ECLAUSENOPRIVILEGE",
					    MM_5082_MSG,
					    NULL);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					return (MM_CMD_ERROR);
				}
			}
		}
		if ((value = mms_pn_lookup(who,
		    NULL,
		    MMS_PN_STRING,
		    &work)) != NULL) {
			ai_name = value->pn_string;
			mms_trace(MMS_DEVP, "Use %s as ai name",
			    ai_name);
			if (cmd->wka_ptr->wka_privilege == MM_PRIV_STANDARD) {
				/* for standard priv, */
				/* check that app_name is the client's */
				if (strcmp(ai_name, conn->cci_instance) != 0) {
					mms_trace(MMS_DEVP,
					    "instace name in who does"
					    " not match client instance'");
					mm_response_error(cmd,
					    ECLASS_LANGUAGE,
					    "ECLAUSENOPRIVILEGE",
					    MM_5082_MSG,
					    NULL);
					cmd->cmd_remove = 1;
					mm_send_text(mm_wka->mm_wka_conn,
					    cmd->cmd_buf);
					return (MM_CMD_ERROR);
				}
			}
		} else {
			ai_name = NULL;
			mms_trace(MMS_DEVP, "'any' instance");
		}
	} else {
		app_name = conn->cci_client;
		ai_name = NULL;
		mms_trace(MMS_DEVP, "Use %s as application name, any instance",
		    app_name);
	}

	/*
	 * Get volume names.
	 */
	work = NULL;
	count = 0;
	MMS_PN_LOOKUP(vol, cmd->cmd_root, "newvolname",
	    MMS_PN_CLAUSE, NULL);
	while (mms_pn_lookup(vol, NULL, MMS_PN_STRING, &work) != NULL) {
		count++;
	}
	if ((volname = (char **) malloc(sizeof (char *) * count)) == NULL) {
		MM_ABORT_NO_MEM();
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	work = NULL;
	index = 0;
	for (value = mms_pn_lookup(vol, NULL, MMS_PN_STRING, &work);
	    value != NULL && index < count;
	    value = mms_pn_lookup(vol, NULL, MMS_PN_STRING, &work)) {
		volname[index++] = value->pn_string;
	}
	for (index = 0; index < count; index++) {
		mms_trace(MMS_DEVP, "newvolname[%d] %s", index, volname[index]);

		/* check command for unique volnames */
		for (i = 0; i < count; i++) {
			if (i != index &&
			    strcmp(volname[index], volname[i]) == 0) {
				SQL_CHK_LEN(&cmd->cmd_buf, 0,
				    &cmd->cmd_bufsize,
				    strlen(RESPONSE_ERROR) +
				    strlen(cmd->cmd_task) +
				    strlen(ECLASS_LANGUAGE) +
				    strlen(EINVALCLAUSEARG) + 1);
				(void) snprintf(cmd->cmd_buf,
				    cmd->cmd_bufsize,
				    RESPONSE_ERROR,
				    cmd->cmd_task,
				    ECLASS_LANGUAGE,
				    EINVALCLAUSEARG);
				free(volname);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				return (MM_CMD_ERROR);
			}
		}
	}

	/* check number-clause and newvolname-clause counts */
	if (mm_get_range(cmd, &range)) {
		mms_trace(MMS_DEVP, "number-clause range parse error");
		mm_response_error(cmd,
		    ECLASS_LANGUAGE,
		    ESYNTAX,
		    MM_5083_MSG,
		    NULL);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	if ((range.mm_range_type == MM_RANGE_NUMS &&
	    (range.mm_range_last - range.mm_range_first + 1) != count) ||
	    (range.mm_range_type == MM_RANGE_A_NUM && count != 1)) {

		mms_trace(MMS_DEVP, "number-clause error, "
		    "type %d range %d %d count %d error",
		    range.mm_range_type,
		    range.mm_range_first,
		    range.mm_range_last,
		    count);
		mm_response_error(cmd,
		    ECLASS_INVALID,
		    ENEWVOLNAMECOUNT,
		    MM_5084_MSG,
		    NULL);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}

	/*
	 * Find distinct suitable volume partitions.
	 */

	mms_trace(MMS_DEVP, "Find Partitions");

	if (mm_get_dest(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match Clause???");
	} else {
		/* TEMP - Trace out our dest info */
		mms_trace(MMS_DEVP, "Dest count is %d", cmd->cmd_dest_num);
		mm_print_char_list(&cmd->cmd_dest_list);
	}

	if (mm_get_const(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match Clause???");
	} else {
		/* TEMP - Trace out our const info */
		mms_trace(MMS_DEVP, "Const count is %d", cmd->cmd_const_num);
		mm_print_char_list(&cmd->cmd_const_list);
	}

	if (mm_add_match_list("PARTITION", &cmd->cmd_dest_list)) {
		mms_trace(MMS_DEVP, "PARTITION already in dest list");
	} else {
		cmd->cmd_dest_num ++;
	}
	constraint = "(\"PARTITION\".\"PartitionAllocatable\" = 'true')";
	if (mm_add_match_list(constraint, &cmd->cmd_const_list)) {
		mms_trace(MMS_DEVP, "PARTITION allocatable "
		    "already in constraint list");
	} else {
		cmd->cmd_const_num ++;
	}

	if (cmd->wka_ptr->wka_privilege != MM_PRIV_STANDARD) {
		mms_trace(MMS_DEVP,
		    "Privileged app, skip "
		    "CARTRIDGEGROUPAPPLICATION constraint");
	} else {
		/* if this is not a privilaged app */
		/* Enforce CARTRIDGEGROUPAPPLICATION */
		mms_trace(MMS_DEVP,
		    "Non-Privileged app, add CARTRIDGEGROUPAPPLICATION");

		if (mm_add_match_list("CARTRIDGEGROUPAPPLICATION",
		    &cmd->cmd_dest_list)) {
			mms_trace(MMS_DEVP, "CARTRIDGEGROUPAPPLICATION already "
			    "in dest list");
		} else {
			cmd->cmd_dest_num ++;
		}

		constraint = mms_strnew("(\"CARTRIDGEGROUPAPPLICATION\"."
		    "\"ApplicationName\" = '%s')", conn->cci_client);

		if (mm_add_match_list(constraint, &cmd->cmd_const_list)) {
			mms_trace(MMS_DEVP, "CARTRIDGEGROUPAPPLICATION appname "
			    "already in constraint list");
		} else {
			cmd->cmd_const_num ++;
		}
		free(constraint);
	}


	if (mm_add_char("PARTITION", &cmd->cmd_source_list)) {
		mms_trace(MMS_ERR,
		    "mm_allocate_cmd_func: "
		    "out of mem creating source list");
		mm_system_error(cmd,
		    "out of mem creating source list");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		free(volname);
		return (MM_CMD_ERROR);
	}


	query = "select distinct \"PARTITION\".\"CartridgeID\","
	    "\"PARTITION\".\"SideName\","
	    "\"PARTITION\".\"PartitionName\" from ";
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(query) + 1);
	(void) strlcpy(cmd->cmd_buf, query, cmd->cmd_bufsize);
	cmd->cmd_source_num = 1;

	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_allocate_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		free(volname);
		return (MM_CMD_ERROR);
	}
	mm_sql_order(cmd);

	mm_sql_number(cmd);

	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mm_clear_db(&db->mm_db_results);
		free(volname);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	rows = PQntuples(db->mm_db_results);
	results = db->mm_db_results;

	/* each volname needs a partition */
	if (rows < count) {
		/* general error, this means the resource is already used */
		mms_trace(MMS_DEVP,
		    "partitions found %d, partitions needed %d",
		    rows, count);
		mm_response_error(cmd,
		    ECLASS_EXPLICIT,
		    ENOTENOUGHPARTITIONS,
		    MM_5085_MSG,
		    NULL);
		mm_clear_db(&results);
		free(volname);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/*
	 * Allocate one volume per partition.
	 */
	for (row = 0; row < rows && row < count; row++) {

		/* check for unique volume name in apps namespace. */
		if (mm_db_exec(HERE, db, "SELECT \"VolumeName\" FROM "
		    "\"VOLUME\" WHERE \"ApplicationName\" = '%s' AND "
		    "\"VolumeName\" = '%s';",
		    app_name,
		    volname[row]) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if ((num = PQntuples(db->mm_db_results)) != 0) {
			mms_trace(MMS_DEVP, "volume count %d", num);
			for (i = 0; i < num; i++) {
				mms_trace(MMS_DEVP, "volume[%d] %s", i,
				    PQgetvalue(db->mm_db_results, i, 0));
			}
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(SIMPLE_RESPONSE_ERROR_TEXT) +
			    strlen(cmd->cmd_task) + strlen(ECLASS_EXIST) +
			    strlen(ENEWVOLEXISTS) +
			    strlen(volname[row]) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    SIMPLE_RESPONSE_ERROR_TEXT,
			    cmd->cmd_task, ECLASS_EXIST, ENEWVOLEXISTS,
			    volname[row]);
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);




		if (ai_name == NULL) {
			db_buf = mms_strapp(db_buf,
			    "INSERT INTO \"VOLUME\" "
			    "(\"ApplicationName\", "
			    "\"VolumeName\", \"CartridgeID\", "
			    "\"SideName\", "
			    "\"PartitionName\") VALUES "
			    "('%s', '%s', '%s', '%s', '%s')",
			    app_name,
			    volname[row],
			    PQgetvalue(results, row, 0),
			    PQgetvalue(results, row, 1),
			    PQgetvalue(results, row, 2));
		} else {
			db_buf = mms_strapp(db_buf,
			    "INSERT INTO \"VOLUME\" "
			    "(\"ApplicationName\", "
			    "\"VolumeName\", \"CartridgeID\", "
			    "\"SideName\", \"PartitionName\", "
			    "\"AIName\") VALUES "
			    "('%s', '%s', '%s', '%s', '%s', '%s')",
			    app_name,
			    volname[row],
			    PQgetvalue(results, row, 0),
			    PQgetvalue(results, row, 1),
			    PQgetvalue(results, row, 2),
			    ai_name);
		}
		if (mm_db_exec(HERE, db, db_buf) != MM_DB_OK) {
			free(db_buf);
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		free(db_buf);
		db_buf = NULL;

		if (mm_db_exec(HERE, db, "UPDATE \"PARTITION\" SET "
		    "\"PartitionAllocatable\" = 'false' WHERE "
		    "\"CartridgeID\" = '%s' and "
		    "\"PARTITION\".\"PartitionName\" = '%s';",
		    PQgetvalue(results, row, 0),
		    PQgetvalue(results, row, 2)) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (db->mm_db_count != 1) {
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(SIMPLE_RESPONSE_ERROR_TEXT) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_SUBOP) +
			    strlen(EPARTITIONSTATECHANGE) +
			    strlen(PQgetvalue(results, row, 0)) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    SIMPLE_RESPONSE_ERROR_TEXT,
			    cmd->cmd_task,
			    ECLASS_SUBOP,
			    EPARTITIONSTATECHANGE,
			    PQgetvalue(results, row, 0));
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_db_exec(HERE, db, "UPDATE \"CARTRIDGE\" SET "
		    "\"ApplicationName\" = '%s' WHERE "
		    "\"CARTRIDGE\".\"CartridgeID\" = '%s';",
		    app_name,
		    PQgetvalue(results, row, 0)) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (db->mm_db_count != 1) {
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(SIMPLE_RESPONSE_ERROR_TEXT) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_SUBOP) +
			    strlen(ECARTRIDGESTATECHANGE) +
			    strlen(PQgetvalue(results, row, 0)) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    SIMPLE_RESPONSE_ERROR_TEXT,
			    cmd->cmd_task,
			    ECLASS_SUBOP,
			    ECARTRIDGESTATECHANGE,
			    PQgetvalue(results, row, 0));
			mm_clear_db(&results);
			free(volname);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}

	for (row = 0; row < rows && row < count; row++) {

		if (mm_notify_add_volumeadd(mm_wka, cmd, volname[row],
		    PQgetvalue(results, row, 0),
		    db)) {
			mms_trace(MMS_ERR,
			    "mm_allocate_cmd_func: "
			    "error adding volume add event");
		}
		mms_trace(MMS_INFO,
		    "VOLUME, %s allocated by %s %s",
		    volname[row],
		    conn->cci_client,
		    conn->cci_instance);

	}
	mm_clear_db(&results);
	free(volname);



	/*
	 * Generate report.
	 */
	mm_path_match_report(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
	free(volname);
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	free(volname);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
}

int
mm_privilege_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*level;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;


	mms_trace(MMS_DEVP, "mm_privilege_cmd_func");
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "level", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(level, arg, NULL, MMS_PN_KEYWORD, NULL);

	if (mm_db_exec(HERE, db, "SELECT \"PrivilegeChangeable\" "
	    "FROM \"AI\" WHERE \"ApplicationName\" = '%s' AND "
	    "\"AIName\" = '%s';", conn->cci_client,
	    conn->cci_instance) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INTERNAL) + strlen(EDATABASE) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INTERNAL, EDATABASE);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0), "t") != 0) {
		mm_clear_db(&db->mm_db_results);
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_PERMPRIV) +
		    strlen(EPRIVCHANGEDISALLOWED) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_PERMPRIV, EPRIVCHANGEDISALLOWED);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_clear_db(&db->mm_db_results);

	if (strcmp(level->pn_string, SYSTEM_PRIV) == 0) {
		/* only mms admin can become system level privileged */
		if (strcmp(mm_wka->wka_conn.cci_client, MM_APP) != 0 &&
		    strcmp(mm_wka->wka_conn.cci_instance, MM_ADMIN) != 0) {
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_PERMPRIV) +
			    strlen(EPRIVNOTMMSADMIN) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_PERMPRIV,
			    EPRIVNOTMMSADMIN);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mm_wka->wka_privilege = MM_PRIV_SYSTEM;
	} else if (strcmp(level->pn_string, ADMINISTRATOR) == 0) {
		mm_wka->wka_privilege = MM_PRIV_ADMIN;
	} else {
		mm_wka->wka_privilege = MM_PRIV_STANDARD;
	}
	mms_trace(MMS_DEVP, "privilege level changed to %s",
	    level->pn_string);

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
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
}


int
mm_locale_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*lang;
	mms_par_node_t	*flavor;
	mms_par_node_t	*value;
	mms_par_node_t	*work = NULL;

	mms_trace(MMS_DEVP, "sql trans locale cmd");
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "protocol", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(lang, arg, NULL, MMS_PN_STRING, &work);
	if (strcmp(lang->pn_string, LANG_EN) != 0) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INVALID) +
		    strlen(ELANGNOTSUPPORTED) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INVALID, ELANGNOTSUPPORTED);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	if ((flavor = mms_pn_lookup(arg, NULL,
	    MMS_PN_STRING, &work)) != NULL &&
	    strcmp(flavor->pn_string, LANG_EN_US) != 0) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INVALID) +
		    strlen(ELANGNOTSUPPORTED) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INVALID, ELANGNOTSUPPORTED);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	work = NULL;
	for (arg = mms_pn_lookup(cmd->cmd_root, "sort",
	    MMS_PN_CLAUSE, &work);
	    arg != NULL;
	    arg = mms_pn_lookup(cmd->cmd_root, "sort",
	    MMS_PN_CLAUSE, &work)) {
		MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_STRING, NULL);
		if (strcmp(LANG_EN_US, value->pn_string) != 0) {
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INVALID) +
			    strlen(ESORTNOTSUPPORTED) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_INVALID,
			    ESORTNOTSUPPORTED);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
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

int
mm_attribute_check_helper(mm_command_t *cmd, char *object, char *attribute) {
	char *buf = NULL;
	int priv = 0;
	char *err_buf = NULL;
	mm_attribute_info_t *attr_info;
	int i;

	mms_trace(MMS_DEVP, "Check value -> %s.%s", object, attribute);

	attr_info = &cmd->wka_ptr->mm_data->mm_attr_info;
	buf = mms_strapp(buf, "%s.%s", object, attribute);

	/*
	 * Find the prvilege of this client
	 * system -> priv = 2
	 * administrator -> priv = 1
	 * standard -> priv = 0
	 */

	if (cmd->wka_ptr->wka_privilege == MM_PRIV_SYSTEM) {
		/* level is system */
		priv = 2;
	} else if (cmd->wka_ptr->wka_privilege == MM_PRIV_ADMIN) {
		/* level is administrator */
		priv = 1;
	} else {
		/* level is standard */
		priv = 0;
	}


	/* Check Status Objects if not system priv */
	if (priv < 2) {
		for (i = 0; i < MM_NUM_STATUS_OBJS; i ++) {
			if (strcmp(object, attr_info->status_objs[i]) == 0) {
				mms_trace(MMS_ERR, "Cannot modify "\
				    "status object, %s", object);
				mm_response_error(cmd,
				    ECLASS_PERMPRIV,
				    EOBJSYSATTRMODNOPRIV,
				    MM_5109_MSG,
				    "object", object,
				    "attribute", attribute,
				    NULL);
				goto return_error;
			}
		}

		/* Check Status Attributes if not system priv */
		for (i = 0; i < MM_NUM_STATUS_ATTS; i ++) {
			if (strcmp(buf, attr_info->status_atts[i]) == 0) {
				mms_trace(MMS_ERR, "Cannot modify "\
				    "status attribute, %s", buf);
				mm_response_error(cmd,
				    ECLASS_PERMPRIV,
				    EOBJSYSATTRMODNOPRIV,
				    MM_5109_MSG,
				    "object", object,
				    "attribute", attribute,
				    NULL);
				goto return_error;
			}
		}
	}

	/* Restrict control attributes if this is non-privileged */
	if (priv < 1) {
		if (strcmp(object, "SYSTEM") == 0) {
			mms_trace(MMS_ERR, "Standard privilege client "
			    "may not modify the SYSTEM object");
			mm_response_error(cmd,
			    ECLASS_PERMPRIV,
			    EOBJSYSATTRMODNOPRIV,
			    MM_5108_MSG,
			    "object", object,
			    "attribute", attribute,
			    NULL);
			goto return_error;
		}

		for (i = 0; i < MM_NUM_CONTROL_ATTS; i ++) {
			if (strcmp(buf, attr_info->control_atts[i]) == 0) {
				mms_trace(MMS_ERR, "Cannot modify "\
				    "control attribute, %s", buf);
				mm_response_error(cmd,
				    ECLASS_PERMPRIV,
				    EOBJSYSATTRMODNOPRIV,
				    MM_5108_MSG,
				    "object", object,
				    "attribute", attribute,
				    NULL);
				goto return_error;
			}
		}
	}


	goto return_ok;


no_mem:
	mms_trace_flush();
	MM_ABORT_NO_MEM();
	return (1);

return_ok:

	if (err_buf != NULL)
		free(err_buf);
	if (buf != NULL)
		free(buf);
	return (0);


return_error:

	if (err_buf != NULL)
		free(err_buf);
	if (buf != NULL)
		free(buf);
	return (1);

}




int
mm_add_set_list(mms_list_t *list, int type,
    char *obj, char *attr, char *value) {
	cmd_set_t	*mm_set_struct;

	mm_set_struct = (cmd_set_t *)calloc(1, sizeof (cmd_set_t));
	if (mm_set_struct == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc cmd_set_t: %s",
		    strerror(errno));
		return (1);
	}
	mm_set_struct->cmd_set_type = type;
	switch (type) {
	case MM_SET:
		mm_set_struct->cmd_set_obj = strdup(obj);
		mm_set_struct->cmd_set_attr = strdup(attr);
		mm_set_struct->cmd_set_value = strdup(value);
		break;
	case MM_UNSET:
		mm_set_struct->cmd_set_obj = strdup(obj);
		mm_set_struct->cmd_set_attr = strdup(attr);
		mm_set_struct->cmd_set_value = NULL;
		break;
	}

	mms_list_insert_tail(list, mm_set_struct);

	return (0);
}

void
mm_print_set_list(mms_list_t *list) {
	cmd_set_t	*cur_set;
	cmd_set_t	*next;

	for (cur_set = mms_list_head(list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(list, cur_set);
		switch (cur_set->cmd_set_type) {
		case MM_SET:
			/* This node is for a set clause */
			mms_trace(MMS_DEBUG, "    SET %s.%s = %s",
			    cur_set->cmd_set_obj,
			    cur_set->cmd_set_attr,
			    cur_set->cmd_set_value);
			break;
		case MM_UNSET:
			/* This node is for an unset clause */
			mms_trace(MMS_DEBUG, "    UNSET %s.%s",
			    cur_set->cmd_set_obj,
			    cur_set->cmd_set_attr);
			break;
		}
	}
}

int
mm_in_set_list(mms_list_t *list, char *obj, char *attr) {
	cmd_set_t	*cur_set;
	cmd_set_t	*next;
	for (cur_set = mms_list_head(list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(list, cur_set);
		if ((strcmp(cur_set->cmd_set_obj, obj) == 0) &&
		    (strcmp(cur_set->cmd_set_attr, attr) == 0)) {
			return (1);
		}
	}
	return (0);
}


int
mm_attribute_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*cmd_buf = NULL;
	int		rc;
	int		error;
	char		*info = NULL;

	/* For Set and Unset Lists */
	mms_list_t		set_list;
	cmd_set_t	*cur_set;
	cmd_set_t	*next;

	/* Char list for OBJECT types */
	mms_list_t		obj_list;
	mm_char_list_t	*cur_obj;
	mm_char_list_t	*next_obj;

	mms_trace(MMS_DEBUG, "mm_attribute_cmd_func");

	/* Create the Set and Unset Struct Lists */

	mms_list_create(&set_list, sizeof (cmd_set_t),
	    offsetof(cmd_set_t, cmd_set_next));
	mms_list_create(&obj_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));

	/* Build the lists after parsing the clauses */

	if (mm_get_set_clause(cmd,
	    &set_list, &obj_list)) {
		mms_trace(MMS_ERR,
		    "mm_attribute_cmd_func: "
		    "error building structs from set clause");
		mm_system_error(cmd,
		    "error building structs from set clause");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}


	/* Get Dest Objects */
	if (mm_get_dest(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our dest info */
		mms_trace(MMS_DEVP, "Dest count is %d", cmd->cmd_dest_num);
		mm_print_char_list(&cmd->cmd_dest_list);
	}
	/* Get constraint Objects */
	if (mm_get_const(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our const info */
		mms_trace(MMS_DEVP, "Const count is %d", cmd->cmd_const_num);
		mm_print_char_list(&cmd->cmd_const_list);
	}

	/* Do attribute check */
	/* Only for MMP clients */
	if (cmd->cmd_language == MM_LANG_MMP) {
		/* Check if the creating attribtues is allowed */
		mms_trace(MMS_DEBUG, "Checking objects and attribtues");
		for (cur_set = mms_list_head(&set_list);
		    cur_set != NULL;
		    cur_set = next) {
			next = mms_list_next(&set_list, cur_set);
			/* Check if the attributes may be created */
			if (mm_db_create_attribute(db,
			    cur_set->cmd_set_obj,
			    cur_set->cmd_set_attr) !=
			    MM_DB_OK) {
				mms_trace(MMS_ERR, "Create attribute check "
				    "failed for %s.%s",
				    cur_set->cmd_set_obj,
				    cur_set->cmd_set_attr);
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;
			}
			/* Check if the attributes may be modified */
			if (mm_attribute_check_helper(cmd, cur_set->cmd_set_obj,
			    cur_set->cmd_set_attr)) {
				/* check_helper sets the correct error */
				/* Send and remove */
				mms_trace(MMS_ERR, "Attribute check failed");
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;
			}
		}
		mms_trace(MMS_DEVP, "Done checking objects and attribtes");
	} else {
		mms_trace(MMS_DEBUG,
		    "Skipping attribute check for non-MMP client");
	}

	/*
	 * All attributes have passed attribute restricted
	 * check and creation check
	 * For each MM object construct the sql command
	 * to perform the set operation
	 * unset's are simply a set using DEFAULT as value
	 */

	for (cur_obj = mms_list_head(&obj_list);
	    cur_obj != NULL;
	    cur_obj = next_obj) {
		int first = 1;
		next_obj = mms_list_next(&obj_list, cur_obj);
		if (cmd_buf) {
			free(cmd_buf);
			cmd_buf = NULL;
		}
		mms_trace(MMS_DEVP, "Current object -> %s", cur_obj->text);
		/* Clear the source list, and add cur_obj as the only source */
		mm_clear_source(cmd);

		if (mm_add_char(cur_obj->text, &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_attribute_cmd_func: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}

		cmd->cmd_source_num = 1;
		/* Begin constructin the SQL command */
		cmd_buf = mms_strapp(cmd_buf, "UPDATE \"%s\" SET ",
		    cur_obj->text);
		/* For every set where obj = cur_obj */
		/* add to the sql command */
		for (cur_set = mms_list_head(&set_list);
		    cur_set != NULL;
		    cur_set = next) {
			next = mms_list_next(&set_list, cur_set);
			if (strcmp(cur_obj->text, cur_set->cmd_set_obj) == 0) {
				/* Obj matches */
				if (first) {
					/* Frist attr doesn't need a comma */
					first = 0;
				} else {
					/* add a comma */
					cmd_buf = mms_strapp(cmd_buf, ", ");
				}
				switch (cur_set->cmd_set_type) {
				case (MM_SET):
					cmd_buf = mms_strapp(cmd_buf,
					    "\"%s\" = '%s'",
					    cur_set->cmd_set_attr,
					    cur_set->cmd_set_value);
					break;
				case (MM_UNSET):
					cmd_buf = mms_strapp(cmd_buf,
					    "\"%s\" = DEFAULT",
					    cur_set->cmd_set_attr);
					break;
				}
			}
		}
		/* Copy local cmd_buf into cmd->cmd_buf */
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(cmd_buf) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, "%s", cmd_buf);
		if (cmd_buf) {
			mms_trace(MMS_DEVP, "    %s", cmd_buf);
		}
		if (mm_sql_report_func_attr(cmd)) {
			mms_trace(MMS_ERR,
			    "mm_attribute_cmd_func: "
			    "error creating helper sql functions");
			mm_system_error(cmd,
			    "error creating helper sql functions");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		if ((rc = mm_attribute_match(cmd)) != INTRP_OK) {
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		mms_trace(MMS_DEVP, "cmd->cmd_buf constructed");

		/* Function has been created */
		/* cmd->cmd_buf contains the command */
		/* Send cmd->cmd_buf to the data base */
		if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		mms_trace(MMS_DEBUG, "Number of rows modified is %d",
		    db->mm_db_count);
	}

	/* Triggers */
	error = 0;
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "SystemLogFile")) {
		if (error = mm_slog_set_fname(db)) {
			info = strdup("system log file name");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "SystemSyncLimit")) {
		if (error = mm_slog_set_sync(db)) {
			info = strdup("system log sync limit");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "SystemLogLevel")) {
		if (error = mm_slog_set_level(db)) {
			info = strdup("system log level");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "SystemLogFileSize")) {
		if (error = mm_slog_set_size(db)) {
			info = strdup("system log file size");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "SystemMessageLimit")) {
		if (error = mm_msg_set_limit(db)) {
			info = strdup("system message limit");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "SystemRequestLimit")) {
		if (error = mm_request_history_limit(db)) {
			info = strdup("system request history limit");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "AttendanceMode")) {
		if (error = mm_change_attendance_mode(mm_wka)) {
			info = strdup("system attendance mode");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "DM", "DMMessageLevel")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, DM)) {
			info = strdup("dm messsage level");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "DM", "TraceLevel")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, DM)) {
			info = strdup("dm mms_trace level");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "DM", "TraceFileSize")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, DM)) {
			info = strdup("dm mms_trace file size");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "LM", "LMMessageLevel")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, LM)) {
			info = strdup("lm message level");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "LM", "TraceLevel")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, LM)) {
			info = strdup("lm mms_trace level");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "LM", "TraceFileSize")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, LM)) {
			info = strdup("lm mms_trace file size");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "MessageLevel")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, MM)) {
			info = strdup("mm message level");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "TraceLevel")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, MM)) {
			info = strdup("mm mms_trace level");
		}
	}
	if (error == 0 &&
	    mm_in_set_list(&set_list, "SYSTEM", "TraceFileSize")) {
		if (error = mm_msg_set_tracing(mm_wka, cmd, MM)) {
			info = strdup("mm mms_trace file size");
		}
	}
	if (error) {
		mm_response_error(cmd,
		    ECLASS_SUBOP,
		    ESYSTEMCONFIGCHANGE,
		    MM_5099_MSG,
		    "info", info,
		    NULL);
		free(info);
		info = NULL;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		rc = MM_CMD_ERROR;
		goto end;
	}

	/* Create the report and send success */
	mm_path_match_report(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	rc = MM_CMD_DONE;
	goto end;
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

end:

	/* Destroy the lists */
	/* Set List */
	for (cur_set = mms_list_head(&set_list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(&set_list, cur_set);
		if (cur_set->cmd_set_obj)
			free(cur_set->cmd_set_obj);
		if (cur_set->cmd_set_attr)
			free(cur_set->cmd_set_attr);
		if (cur_set->cmd_set_value)
			free(cur_set->cmd_set_value);
		mms_list_remove(&set_list,
		    cur_set);
		free(cur_set);
	}
	mms_list_destroy(&set_list);

	/* Destroy the Object list */
	for (cur_obj = mms_list_head(&obj_list);
	    cur_obj != NULL;
	    cur_obj = next_obj) {
		next_obj = mms_list_next(&obj_list, cur_obj);
		if (cur_obj->text)
			free(cur_obj->text);
		mms_list_remove(&obj_list,
		    cur_obj);
		free(cur_obj);
	}
	if (cmd_buf != NULL)
		free(cmd_buf);
	if (info != NULL)
		free(info);
	return (rc);
}


char *
mm_return_set_value(mms_list_t *set_list, char *obj, char *attr) {
	cmd_set_t	*cur_set;
	cmd_set_t	*next;
	for (cur_set = mms_list_head(set_list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(set_list, cur_set);
		if ((strcmp(cur_set->cmd_set_obj, obj) == 0) &&
		    (strcmp(cur_set->cmd_set_attr, attr) == 0)) {
			return (cur_set->cmd_set_value);
		}
	}
	return (NULL);
}

/*
 * mm_get_set_clause:
 *     Parses commands with set/unset clauses
 *     and creates lists that hold all the relevant information
 *     Can be used in any command that includes set/unset clauses
 *     obj_list is the list of MM objects used in the set/unset clauses
 */
int
mm_get_set_clause(mm_command_t *cmd, mms_list_t *set_list, mms_list_t *obj_list)
{
	int		rc;

	/* For Set and Unset Lists */


	/* For the Parse */
	mms_par_node_t	*work = NULL;
	mms_par_node_t	*set;
	mms_par_node_t	*unset;

	mms_par_node_t	*object;
	mms_par_node_t	*attr;
	mms_par_node_t	*value;

	mms_trace(MMS_DEVP, "mm_get_set_clause");

	/* TEMP create the lists within this function */
	/* and destroy them when we are finished */


	work = NULL;
	for (set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work);
	    set != NULL;
	    set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work)) {
		mms_trace(MMS_DEVP, "    Set Clause");
		/* Get the Object */
		MMS_PN_LOOKUP(object, set, NULL, MMS_PN_OBJ, NULL);
		mms_trace(MMS_DEVP, "        Object name-> %s",
		    object->pn_string);
		/* Get the Attribute */
		MMS_PN_LOOKUP(attr, set, NULL, MMS_PN_ATTR, NULL);
		mms_trace(MMS_DEVP, "        Attribute name-> %s",
		    attr->pn_string);
		/* Get the Value */
		MMS_PN_LOOKUP(value, set, NULL, MMS_PN_STRING, NULL);
		if (value->pn_type & MMS_PN_NULLSTR) {
			mms_trace(MMS_DEVP, "        Value name-> NULL");
			/* Add this to the set list */
			if (mm_add_set_list(set_list,
			    MM_SET,
			    object->pn_string,
			    attr->pn_string,
			    "DEFAULT")) {
				mms_trace(MMS_ERR,
				    "mm_get_set_clause: "
				    "unable to allocate "
				    "memory for this set");
				return (MM_CMD_ERROR);
			}

		} else {
			mms_trace(MMS_DEVP, "        Value name-> %s",
			    value->pn_string);
			/* Add this to the set list */


			if (mm_add_set_list(set_list,
			    MM_SET,
			    object->pn_string,
			    attr->pn_string,
			    value->pn_string)) {
				mms_trace(MMS_ERR,
				    "mm_get_set_clause: "
				    "unable to allocate "
				    "memory for this set");
				return (MM_CMD_ERROR);
			}
		}

		/* Add this to the obj list */
		if (obj_list != NULL) {
			(void) mm_add_obj_list(obj_list,
			    object->pn_string);
		}
	}

	work = NULL;
	for (unset = mms_pn_lookup(cmd->cmd_root, "unset",
	    MMS_PN_CLAUSE, &work);
	    unset != NULL;
	    unset = mms_pn_lookup(cmd->cmd_root, "unset",
	    MMS_PN_CLAUSE, &work)) {
		mms_trace(MMS_DEVP, "    Unset Clause");
		/* Get the Object */
		MMS_PN_LOOKUP(object, unset, NULL, MMS_PN_OBJ, NULL);
		mms_trace(MMS_DEVP, "        Object name-> %s",
		    object->pn_string);
		/* Get the Attribute */
		MMS_PN_LOOKUP(attr, unset, NULL, MMS_PN_ATTR, NULL);
		mms_trace(MMS_DEVP, "        Attribute name-> %s",
		    attr->pn_string);
		/* Add this to the set list */
		if (mm_add_set_list(set_list,
		    MM_UNSET,
		    object->pn_string,
		    attr->pn_string,
		    NULL)) {
			mms_trace(MMS_ERR,
			    "mm_get_set_clause: "
			    "unable to allocate "
			    "memory for this set");
			return (MM_CMD_ERROR);
		}
		/* Add this to the obj list */
		if (obj_list != NULL) {
			(void) mm_add_obj_list(obj_list,
			    object->pn_string);
		}

	}


	/* Print both the Set and Unset lists */
	mms_trace(MMS_DEVP, "Printing Set list");
	mm_print_set_list(set_list);
	rc = 0;
	goto end;

not_found:
	mms_trace(MMS_ERR, "Not found in mm_get_set_clause");
	rc = 1;
	goto end;

end:

	return (rc);


}



int
mm_show_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;

	cmd->cmd_source_num = 0;
	cmd->cmd_dest_num = 0;

	mms_trace(MMS_DEVP, "sql trans show cmd");

	mm_path_match_report(cmd, db);

	cmd->cmd_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	return (MM_CMD_DONE);
}


int
mm_delete_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	char		*objname;
	mms_par_node_t	*object;
	mms_par_node_t	*type;
	int		 rc;
	int		 row;
	int		 rows;
	int		j;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*notify_obj = NULL;
	int		 match_off;
	char		*path_buf = NULL;
	mm_pkey_t *p_key = NULL;
	PGresult	*results;
	char *source_buf_0;

	mms_trace(MMS_DEVP, "sql trans delete cmd");

	/* Get Dest and Constraints */
	if (mm_get_dest(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our dest info */
		mms_trace(MMS_DEVP, "Dest count is %d", cmd->cmd_dest_num);
		mm_print_char_list(&cmd->cmd_dest_list);
	}

	if (mm_get_const(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our const info */
		mms_trace(MMS_DEVP, "Const count is %d", cmd->cmd_const_num);
		mm_print_char_list(&cmd->cmd_const_list);
	}

	/* Look up the type */
	MMS_PN_LOOKUP(type, cmd->cmd_root, "type", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(object, type, NULL, MMS_PN_OBJ, NULL);
	objname = object->pn_string;

	/* Set notify object */
	if (strcmp(objname, "DM") == 0 || strcmp(objname, "LM") == 0) {
		notify_obj = objname;
	}

	/* Prepare source[0] */

	if (mm_add_char(objname,
	    &cmd->cmd_source_list)) {
		mms_trace(MMS_ERR,
		    "mm_delete_cmd_func: "
		    "out of mem creating source list");
		mm_system_error(cmd,
		    "out of mem creating source list");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}


	cmd->cmd_source_num = 1;

	/* Clear cmd_buf */
	if (cmd->cmd_buf != NULL) {
		free(cmd->cmd_buf);
		cmd->cmd_buf = NULL;
		cmd->cmd_bufsize = 0;
	}

	/* Generate the final report where sql */
	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_delete_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	/* Make path sql for delete */

	source_buf_0 = (char *)mm_return_char(&cmd->cmd_source_list, 0);

	path_buf = mms_strapp(path_buf, "delete from \"%s\" ",
	    source_buf_0);
	match_off = strlen(path_buf);
	path_buf = mms_strapp(path_buf, "where");

	p_key = mm_get_pkey(source_buf_0);

	for (j = 0; j < p_key->mm_att_num; j ++) {
		path_buf = mms_strapp(path_buf,
		    "(\"%s\".\"%s\" in "
		    "( select \"%s\".\"%s\" from ",
		    source_buf_0,
		    p_key->mm_att[j],
		    source_buf_0,
		    p_key->mm_att[j]);
		path_buf = mms_strapp(path_buf, cmd->cmd_buf);
		path_buf = mms_strapp(path_buf, "))");
		if (j + 1 < p_key->mm_att_num) {
			path_buf = mms_strapp(path_buf, "and ");
		}
	}

	SQL_CHK_LEN(&cmd->cmd_buf, NULL,
	    &cmd->cmd_bufsize, strlen(path_buf) + 1);
	(void) strlcpy(cmd->cmd_buf, path_buf, cmd->cmd_bufsize);

	free(path_buf);
	path_buf = NULL;




	if (strcmp(objname, "CARTRIDGE") == 0) {
		/* Delete SIDE and SLOT before deleteing CARTRIDGE */
		path_buf = mms_strapp(path_buf, "SELECT \"CartridgeID\" "
		    "FROM \"CARTRIDGE\" %s",
		    &cmd->cmd_buf[match_off]);
		if (mm_db_exec(HERE, db, path_buf) != MM_DB_DATA) {
			goto db_error;
		}
		free(path_buf);
		path_buf = NULL;

		rows = PQntuples(db->mm_db_results);
		results = db->mm_db_results;
		for (row = 0; row < rows; row++) {
			path_buf = mms_strapp(path_buf, "DELETE FROM \"SIDE\" "
			    "WHERE \"CartridgeID\" = '%s'",
			    PQgetvalue(results, row, 0));

			if (mm_db_exec(HERE, db, path_buf) != MM_DB_OK) {
				if (path_buf)
					free(path_buf);
				goto db_error;
			}
			free(path_buf);
			path_buf = NULL;
			path_buf = mms_strapp(path_buf, "DELETE FROM \"SLOT\" "
			    "WHERE \"CartridgeID\" = '%s'",
			    PQgetvalue(results, row, 0));

			if (mm_db_exec(HERE, db, path_buf) != MM_DB_OK) {
				if (path_buf)
					free(path_buf);
				goto db_error;
			}
			free(path_buf);
			path_buf = NULL;

		}
		mm_clear_db(&db->mm_db_results);
	}


	/* Do the notification */
	if (notify_obj) {
		mms_trace(MMS_DEVP, "delete %s", notify_obj);
		if ((rc = mm_notify_delete(db, cmd, notify_obj,
		    match_off)) != INTRP_OK) {
			mms_trace(MMS_DEVP, "rc %d delete %s", rc, notify_obj);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}
	if (strcmp(objname, "LIBRARY") == 0) {
		/* Get the lirbarynames for delete before */
		/* the sql is run */
		mm_notify_add_librarydelete(db, mm_wka,
		    cmd, match_off);
	} else if (strcmp(objname, "DRIVE") == 0) {
		mm_notify_add_drivedelete(db, mm_wka,
		    cmd, match_off);
	}

	/* do delete in sql */
	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_OK) {
		goto db_error;
	}

	/* Finish */
	if (strcmp(objname, "MESSAGE") == 0) {
		int count;
		if (mm_db_exec(HERE, db, "select \"MessageID\" from "
		    "\"MESSAGE\";") != MM_DB_DATA) {
			goto db_error;
		}
		count = PQntuples(db->mm_db_results);
		mm_clear_db(&db->mm_db_results);
		if (mm_db_exec(HERE, db, "update \"SYSTEM\" set "
		    "\"SystemMessageCount\" = '%d';", count) != MM_DB_OK) {
			goto db_error;
		}
	} else if (strcmp(objname, "REQUEST") == 0) {
		int count;
		if (mm_db_exec(HERE, db, "select \"RequestID\" from "
		    "\"REQUEST\" where \"RequestState\" = 'responded';")
		    != MM_DB_DATA) {
			goto db_error;
		}
		count = PQntuples(db->mm_db_results);
		mm_clear_db(&db->mm_db_results);
		if (mm_db_exec(HERE, db, "update \"SYSTEM\" set "
		    "\"SystemRequestCount\" = '%d';", count) != MM_DB_OK) {
			goto db_error;
		}
	}

	/* Clear cmd_buf */
	if (cmd->cmd_buf != NULL) {
		free(cmd->cmd_buf);
		cmd->cmd_buf = NULL;
		cmd->cmd_bufsize = 0;
	}

	mm_path_match_report(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
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

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	free(path_buf);
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	return (MM_CMD_ERROR);
}




/* Check the command's accessmode vs drive capability */

int
mm_mount_union(mm_command_t *cmd, char *mode_toks[CMI_NUM_ACCESSMODE],
    cmi_mode_list_t *mode)
{
	int count = 0;
	int number = 0;
	int i;
	/* copy accessmodes over */
	number = 0;
	for (i = 0; i < mode->cmi_num_accessmode; i ++) {
		mode_toks[i] = strdup(mode->cmi_accessmode[i]);
		count ++;
		number ++;
	}
	/* append with  first mount */
	for (i = 0; i < cmd->cmd_mount_info.
	    cmi_num_firstmount; i ++) {
		mode_toks[count+i] = strdup(cmd->cmd_mount_info.
		    cmi_firstmount[i]);
		number ++;
	}
	return (number);
}

char *
/* LINTED: mm_wka may be used in the future */
mm_check_mode(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *drive, cmi_mode_list_t *mode, char *cart_id,
    mm_db_t *db) {


	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	int			number_toks = 0;
	char			*tok_union[CMI_NUM_ACCESSMODE];
	char			*send_buf = NULL;
	PGresult		*default_toks;
	int			num_default_toks;
	int			total_toks;
	char			*check_buf = NULL;
	char			*tok_group[CMI_NUM_ACCESSMODE];
	int			tok_group_count = 0;
	int			i;
	int			j;

	char			*return_ptr = NULL;

	mms_trace(MMS_DEVP,
	    "mm_check_mode");

	if (mode == NULL) {
		number_toks = 0;
	} else {
		number_toks = mm_mount_union(cmd,
		    tok_union,
		    mode);
	}
	total_toks = number_toks;
	/* Add the bit format tokens to tok_union */
	/* If the token already exists, skip */

	if (mm_db_exec(HERE, db,
	    "select distinct \"DMBITFORMATTOKEN\"."
	    "\"DMCapabilityToken\" from \"DMBITFORMATTOKEN\" "
	    "cross join \"DM\" "
	    "cross join \"PARTITION\" "
	    "where ("
	    "(\"DMBITFORMATTOKEN\".\"DriveName\" "
	    "= \"DM\".\"DriveName\") and "
	    "(\"DMBITFORMATTOKEN\".\"DMName\" "
	    "= \"DM\".\"DMName\") and "
	    "(\"DMBITFORMATTOKEN\".\"DMBitFormatName\" "
	    "= \"PARTITION\".\"PartitionBitFormat\") and "
	    "((\"DMBITFORMATTOKEN\".\"DriveName\" = '%s') "
	    "AND (pg_host_ident(\"DM\".\"DMTargetHost\")"
	    " = pg_host_ident('%s')) "
	    "and (\"PARTITION\".\"CartridgeID\" = '%s')));",
	    drive,
	    mount_info->cmi_where,
	    cart_id) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mms_trace(MMS_ERR, "mm_check_mode: "
		    "error getting tokens from db");
		return_ptr = NULL;
		goto end;
	}

	for (j = 0; j < PQntuples(db->mm_db_results); j ++) {
		int write = 1;
		for (i = 0; i < number_toks; i ++) {
			if (strcmp(tok_union[i],
			    PQgetvalue(db->mm_db_results, j, 0)) == 0) {
				write = 0;
			}
		}
		if (write) {
			tok_union[number_toks] = NULL;
			tok_union[number_toks] =
			    mms_strapp(tok_union[number_toks],
			    PQgetvalue(db->mm_db_results, j, 0));
			number_toks ++;
			total_toks ++;
		}
	}
	mm_clear_db(&db->mm_db_results);

	/* Validate that this drive contains the given tokens */

	for (i = 0; i < number_toks; i ++) {
		check_buf = mms_strapp(check_buf,
		    "select distinct \"DMCapabilityToken\" " \
		    "from good_tok('%s', '%s', '%s');",
		    drive, tok_union[i], mount_info->cmi_where);
		if (mm_db_exec(HERE, db, check_buf) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mms_trace(MMS_ERR, "Error Checking Access mode Tokens");
			return_ptr = NULL;
			goto end;
		}
		if (check_buf)
			free(check_buf);
		check_buf = NULL;
		if (PQntuples(db->mm_db_results) == 0) {
			/* Drive doesn't support this token */
			return_ptr = NULL;
			mm_clear_db(&db->mm_db_results);
			goto end;
		}
		/* Validate that there are not 2 tokens from the same group */
		mm_clear_db(&db->mm_db_results);
		if (mm_db_exec(HERE, db,
		    "select distinct \"DMCAPABILITYGROUP\"."
		    "\"DMCapabilityGroupName\" "
		    "from \"DMCAPABILITYGROUP\" "
		    "cross join \"DM\" "
		    "cross join \"DMCAPABILITYGROUPTOKEN\" "
		    "cross join \"DRIVE\" "
		    "where ( "
		    "(\"DMCAPABILITYGROUP\".\"DMName\" = "
		    "\"DM\".\"DMName\") "
		    "and "
		    "(\"DMCAPABILITYGROUP\".\"DriveName\" = "
		    "\"DMCAPABILITYGROUPTOKEN\".\"DriveName\") "
		    "and "
		    "(\"DMCAPABILITYGROUP\".\"DMName\" = "
		    "\"DMCAPABILITYGROUPTOKEN\".\"DMName\") "
		    "and "
		    "(\"DMCAPABILITYGROUP\"."
		    "\"DMCapabilityGroupName\" = "
		    "\"DMCAPABILITYGROUPTOKEN\"."
		    "\"DMCapabilityGroupName\") "
		    "and "
		    "(\"DMCAPABILITYGROUP\".\"DMName\" = "
		    "\"DM\".\"DMName\") "
		    "and "
		    "(\"DM\".\"DriveName\" = \"DRIVE\".\"DriveName\") "
		    "and "
		    "( "
		    "(pg_host_ident(\"DM\".\"DMTargetHost\") "
		    "= pg_host_ident('%s')) "
		    "AND (\"DMCAPABILITYGROUPTOKEN\"."
		    "\"DMCapabilityToken\" = '%s') AND "
		    "(\"DRIVE\".\"DriveName\" = '%s')));",
		    mount_info->cmi_where,
		    tok_union[i],
		    drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR, "Error Checking Access mode Tokens");
			mm_sql_db_err_rsp_new(cmd, db);
			return_ptr = NULL;
			goto end;
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEBUG, "Couldn't find group for %s",
			    tok_union[i]);
			mm_clear_db(&db->mm_db_results);
			goto bad_group;
		}
		for (j = 0; j < tok_group_count; j ++) {
			if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
			    tok_group[j]) == 0) {
				/* already have this group */
				mms_trace(MMS_DEBUG,
				    "Duplication token %s for group %s",
				    tok_union[i],
				    tok_group[j]);
				mm_clear_db(&db->mm_db_results);
				goto bad_group;
			}
		}
		tok_group[tok_group_count] = NULL;
		tok_group[tok_group_count] =
		    mms_strapp(tok_group[tok_group_count],
		    PQgetvalue(db->mm_db_results, 0, 0));
		tok_group_count ++;
		mm_clear_db(&db->mm_db_results);
	}

	for (j = 0; j < tok_group_count; j ++) {
		if (tok_group[j])
			free(tok_group[j]);
	}
	tok_group_count = 0;


	send_buf = mms_strapp(send_buf,
	    "select distinct \"DMCapabilityGroupDefaultName\" "\
	    "from \"DMCAPABILITYGROUP\" "\
	    "where \"DriveName\" = '%s'",
	    drive);


	for (i = 0; i < number_toks; i ++) {
		send_buf = mms_strapp(send_buf,
		    "and \"DMCapabilityGroupName\" not in " \
		    "(select \"DMCapabilityGroupName\" "	\
		    "from \"DMCAPABILITYGROUPTOKEN\" "	\
		    " where \"DriveName\" = '%s' and "	\
		    "\"DMCapabilityToken\" = '%s')",
		    drive, tok_union[i]);
	}

	send_buf = mms_strapp(send_buf, ";");
	mm_clear_db(&db->mm_db_results);
	if (mm_db_exec(HERE, db, send_buf) != MM_DB_DATA) {
		/* Error */
		mms_trace(MMS_ERR, "Error Getting Default Tokens");
		mm_sql_db_err_rsp_new(cmd, db);
		free(send_buf);
		return_ptr = NULL;
		goto end;
	}
	default_toks = db->mm_db_results;
	db->mm_db_results = NULL;
	num_default_toks = PQntuples(default_toks);

	free(send_buf);
	send_buf = NULL;
	total_toks = number_toks;


	for (i = 0; i < num_default_toks; i++) {
		tok_union[total_toks] = strdup(PQgetvalue(default_toks, i, 0));
		total_toks ++;
	}

	/* Now Check the access mode */

	send_buf = mms_strapp(send_buf,
	    "select distinct \"DMCapabilityName\" "
	    "from \"DMCAPABILITYTOKEN\" "
	    "where \"DriveName\" "
	    "in (select \"DriveName\" from \"DM\" where "
	    "pg_host_ident(\"DMTargetHost\") = "
	    "pg_host_ident('%s') and \"DriveName\" = '%s') "
	    "and \"DMCapabilityName\" in ",
	    mount_info->cmi_where,
	    drive);
	for (i = 0; i < total_toks - 2; i ++) {
		send_buf = mms_strapp(send_buf,
		    "(select \"DMCapabilityName\" "\
		    "from \"DMCAPABILITYTOKEN\" "	 \
		    " where \"DMCapabilityName\" in ");
	}
	send_buf = mms_strapp(send_buf,
	    "(select \"DMCapabilityName\" "\
	    "from \"DMCAPABILITYTOKEN\" where "\
	    "\"DMCapabilityToken\" = '%s')",
	    tok_union[0]);
	for (i = 1; i < total_toks - 1; i ++) {
		send_buf = mms_strapp(send_buf,
		    "and \"DMCapabilityToken\" = '%s')",
		    tok_union[i]);
	}
	send_buf = mms_strapp(send_buf,
	    "and \"DMCapabilityToken\" = '%s';",
	    tok_union[total_toks - 1]);

	if (mm_db_exec(HERE, db, send_buf) != MM_DB_DATA) {
		/* Error */
		mms_trace(MMS_ERR, "Error Getting Cap name Tokens");
		mm_sql_db_err_rsp_new(cmd, db);
		return_ptr = NULL;
		free(send_buf);
		mm_clear_db(&default_toks);
		goto end;
	}

	free(send_buf);
	send_buf = NULL;

	if (PQntuples(db->mm_db_results) == 0) {
		if (mode == NULL) {
			mms_trace(MMS_ERR,
			    "GET DEFAULT TOKENS FAILED!! "
			    "BAD/CORRUPT DM CONFIG");
		}

		/* Drive Doesn't support this mode */
		mm_clear_db(&db->mm_db_results);
		return_ptr = NULL;
		goto end;
	} else if (PQntuples(db->mm_db_results) > 1) {
		/* Bad DMConfig */
		mm_clear_db(&db->mm_db_results);
		return_ptr = NULL;
		goto end;
	}
	/* Set cmid_capability */
	if (mount_info->cmi_capability != NULL) {
		free(mount_info->cmi_capability);
		mount_info->cmi_capability = NULL;
	}
	mount_info->cmi_capability = strdup(PQgetvalue(db->
	    mm_db_results, 0, 0));
	for (i = 0; i < total_toks; i ++) {
		send_buf = mms_strapp(send_buf, "%s:", tok_union[i]);
	}

	mms_trace(MMS_DEVP, "cmi_capability is %s, Cap Token string is %s",
	    mount_info->cmi_capability, send_buf);
	mms_trace_flush();
	mm_clear_db(&db->mm_db_results);
	mm_clear_db(&default_toks);
	return_ptr = send_buf;
	goto end;
no_mem:
	MM_ABORT_NO_MEM();
	return (NULL);
bad_group:

	for (j = 0; j < tok_group_count; j ++) {
		if (tok_group[j])
			free(tok_group[j]);
	}
	for (int j = 0; j < tok_group_count; j ++) {
		if (tok_group[j])
			free(tok_group[j]);
	}
	return (NULL);
end:
	for (int j = 0; j < tok_group_count; j ++) {
		if (tok_group[j])
			free(tok_group[j]);
	}
	for (int j = 0; j < total_toks; j ++) {
		if (tok_union[j])
			free(tok_union[j]);
	}
	return (return_ptr);
}


int
mm_goodbye_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	mm_command_t	*cur_cmd;
	PGresult	*task_results;

	/* Make sure there are no outstanding commands */
	/* If the command is ablocked mount, cancel the mount */
	/* Delay dispatch of the final success until all commands */
	/* have completed */

	/* Dont accept any more commands from this wka */
	mm_wka->wka_goodbye = 1;

	/* lock queue and run thorugh the list */
	/* 1st Cancel any outstanding mount/unmounts that are blocked */

	mms_trace(MMS_DEVP,
	    "check for blocked mount/unmounts");
	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_wka->mm_data->mm_cmd_queue, cur_cmd) {
		if ((cur_cmd->wka_ptr == mm_wka) &&
		    (cur_cmd != cmd) &&
		    (cur_cmd->cmd_remove == 0)) {
			/* If this command is a blocked mount, then cancel */
			if ((cur_cmd->cmd_func == mm_mount_cmd_func) ||
			    (cur_cmd->cmd_func == mm_unmount_cmd_func)) {
				/* If this unmount/mount */
				/* is blocked, cancel it */
				/* If not, wait for it to finish */
				if (mm_db_exec(HERE, db,
				    "select \"TaskState\" from \"TASK\" where"
				    " \"TaskID\" = '%s';",
				    cur_cmd->cmd_uuid) != MM_DB_DATA) {
					mms_trace(MMS_ERR,
					    "Error determining "
					    "mount/unmount taskstate");
					mm_sql_db_err_rsp_new(cmd, db);
					continue;
				}
				task_results = db->mm_db_results;
				if (PQntuples(task_results) != 1) {
					mms_trace(MMS_ERR,
					    "row mismatch getting task info");
					mm_clear_db(&task_results);
					continue;
				}
				/* If this mount/unmount is blocked */
				/* send a cancel and set this */
				/* command for remove */
				if (strcmp(PQgetvalue(task_results, 0, 0),
				    "blocked") == 0) {
					/* This task is blocked, */
					/* cancel it now */
					mms_trace(MMS_DEVP,
					    "this task is blocked, "
					    "sending cancel");
					mm_cancel_cmd_buf(cur_cmd);
					mm_send_text(cur_cmd->
					    wka_ptr->mm_wka_conn,
					    cur_cmd->cmd_buf);
					cur_cmd->cmd_remove = 1;
					if (mm_db_exec(HERE, db,
					    "delete from \"TASK\" where"
					    "\"TaskID\" = '%s';",
					    cur_cmd->cmd_uuid) != MM_DB_OK) {
						mms_trace(MMS_ERR,
						    "Error removing "
						    "TASK object");
					}
				}
				mm_clear_db(&task_results);
			}
		}
	}
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

	mms_trace(MMS_DEVP,
	    "Check outstanding commands");
	/* All mounts/unmounts are cancelled */
	/* lock queue and run thorugh the list */
	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_wka->mm_data->mm_cmd_queue, cur_cmd) {
		if ((cur_cmd->wka_ptr == mm_wka) &&
		    (cur_cmd != cmd) &&
		    (cur_cmd->cmd_remove == 0)) {
			/* Same wka && */
			/* not this command  && */
			/* The command is not being removed */
			mm_add_depend(cur_cmd, cmd);
			mms_trace(MMS_DEVP,
			    "this client has outstanding commands "
			    "which must finish before goodbye");
			pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);
			return (MM_WORK_TODO);
		}
	}
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);


	/* Send Success */
	mm_path_match_report(cmd, db);

	cmd->cmd_remove = 1;
	mm_wka->wka_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	return (MM_CMD_DONE);
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}

mm_privilege_t
mm_privileged(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	if (mm_wka->wka_privilege == MM_PRIV_STANDARD) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_PERMPRIV) +
		    strlen(ECOMMANDNOPRIVILEGE) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_PERMPRIV, ECOMMANDNOPRIVILEGE);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	}
	return (mm_wka->wka_privilege);

no_mem:
	MM_ABORT_NO_MEM();
	return (mm_wka->wka_privilege);
}

int
mm_create_side(mm_wka_t *mm_wka, mm_command_t *cmd, char *cartridge_id) {
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*cartridge_type;
	PGresult	*results;
	int		 side;
	int		 sides;

	if (cartridge_id == NULL) {
		mms_trace(MMS_ERR,
		    "mm_create_side passed null cartridge_id");
		return (MM_CMD_ERROR);
	}

	if (mm_db_exec(HERE, db, "SELECT "
	    "\"CartridgeTypeName\" FROM "\
	    "\"CARTRIDGE\" WHERE "
	    "\"CartridgeID\" = '%s'",
	    cartridge_id) != MM_DB_DATA ||
	    PQntuples(db->mm_db_results) != 1 ||
	    (cartridge_type =
	    strdup(PQgetvalue(db->mm_db_results, 0, 0))) ==
	    NULL) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_clear_db(&db->mm_db_results);
	if (mm_db_exec(HERE, db, "SELECT "
	    "\"CartridgeTypeNumberSides\" "
	    "FROM \"CARTRIDGETYPE\" WHERE "\
	    "\"CartridgeTypeName\" = '%s'",
	    cartridge_type) != MM_DB_DATA ||
	    PQntuples(db->mm_db_results) != 1) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		free(cartridge_type);
		return (MM_CMD_ERROR);
	}
	sides = atoi(PQgetvalue(db->mm_db_results, 0, 0));
	mm_clear_db(&db->mm_db_results);
	for (side = 0; side < sides; side++) {
		if (mm_db_exec(HERE, db, "SELECT "
		    "\"Side%dName\" FROM "
		    "\"CARTRIDGETYPE\" WHERE "
		    "\"CartridgeTypeName\" = '%s'",
		    side + 1, cartridge_type) !=
		    MM_DB_DATA &&
		    PQntuples(db->mm_db_results) != 1) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			free(cartridge_type);
			return (MM_CMD_ERROR);
		}
		results = db->mm_db_results;
		if (mm_db_exec(HERE, db, "INSERT INTO "
		    "\"SIDE\" (\"CartridgeID\", "
		    "\"SideName\") VALUES "
		    "('%s', '%s')", cartridge_id,
		    PQgetvalue(results, 0, 0)) !=
		    MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			free(cartridge_type);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&results);
	}
	free(cartridge_type);
	return (MM_CMD_DONE);

}


int
mm_create_slot_type(mm_wka_t *mm_wka, mm_command_t *cmd, char *library_type)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;

	if (mm_db_exec(HERE, db,
	    "select \"SlotTypeName\" "
	    "from \"SLOTTYPE\" where "
	    "\"SlotTypeName\" = '%s';",
	    library_type) != MM_DB_DATA) {
		goto db_error;
	}
	if (PQntuples(db->mm_db_results) != 0) {
		/* A slot type for this library already exists */
		return (MM_CMD_DONE);
	}

	if (mm_db_exec(HERE, db,
	    "insert into \"SLOTTYPE\" "
	    "(\"SlotTypeName\", "
	    "\"CartridgeShapeName\") "
	    "values('%s', '%s%s');",
	    library_type,
	    library_type,
	    "-generic") != MM_DB_OK) {
		goto db_error;
	}
	return (MM_CMD_DONE);

db_error:
	mm_sql_db_err_rsp_new(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn,
	    cmd->cmd_buf);
	return (MM_CMD_ERROR);
}

int
mm_update_side(mm_wka_t *mm_wka, mm_command_t *cmd, char *cartridge_type)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	int		 side;
	int		 sides;
	char		 sidename[20];

	if (mm_db_exec(HERE, db,
	    "SELECT \"CartridgeTypeNumberSides\" " \
	    "FROM "
	    "\"CARTRIDGETYPE\" WHERE "	\
	    "\"CartridgeTypeName\" = '%s'",
	    cartridge_type) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	sides = atoi(PQgetvalue(db->mm_db_results, 0, 0));
	mm_clear_db(&db->mm_db_results);
	for (side = 0; side < sides; side++) {
		(void) snprintf(sidename, sizeof (sidename),
		    "Side%dName", side + 1);
		if (mm_db_create_attribute(db, "CARTRIDGETYPE",
		    sidename) !=
		    MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (mm_db_exec(HERE, db, "UPDATE \"CARTRIDGETYPE\" "
		    "SET \"%s\" = 'side %d' WHERE "
		    "\"CartridgeTypeName\" = '%s'",
		    sidename,
		    side + 1, cartridge_type) !=
		    MM_DB_OK) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}
	return (MM_CMD_DONE);
}

int
mm_create_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*cmd_buf = NULL;
	int		rc;
	uuid_text_t	cartridge_id;
	char		*part_cart_id = NULL;

	/* Type Clause */
	mms_par_node_t	*object;
	mms_par_node_t	*type;

	/* For Set and Unset Lists */
	mms_list_t		set_list;
	cmd_set_t	*cur_set;
	cmd_set_t	*next;

	int		command_added = 0;
	int first = 1;


	mms_trace(MMS_DEBUG, "mm_create_cmd_func");

	/* First get the type clause */
	MMS_PN_LOOKUP(type, cmd->cmd_root, "type",
	    MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(object, type, NULL, MMS_PN_OBJ, NULL);
	mms_trace(MMS_DEVP, "type clause, %s",
	    object->pn_string);

	/* Create the Set and Unset Struct Lists */

	mms_list_create(&set_list, sizeof (cmd_set_t),
	    offsetof(cmd_set_t, cmd_set_next));
	/* Build the lists after parsing the clauses */

	if (mm_get_set_clause(cmd, &set_list, NULL)) {
		mms_trace(MMS_ERR,
		    "mm_create_cmd_func: "
		    "error building structs from set clause");
		mm_system_error(cmd,
		    "error building structs from set clause");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}


	/* Check if the creating attribtues is allowed */
	mms_trace(MMS_DEBUG, "Checking objects and attribtues");
	for (cur_set = mms_list_head(&set_list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(&set_list, cur_set);
		/* Check if the attributes may be created */
		if (mm_db_create_attribute(db,
		    cur_set->cmd_set_obj,
		    cur_set->cmd_set_attr) !=
		    MM_DB_OK) {
			mms_trace(MMS_ERR, "Create attribute check "
			    "failed for %s.%s",
			    cur_set->cmd_set_obj,
			    cur_set->cmd_set_attr);
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}

		/* Check if the attributes may be modified */
		if (mm_attribute_check_helper(cmd, cur_set->cmd_set_obj,
		    cur_set->cmd_set_attr)) {
			/* check_helper sets the correct error */
			/* Send and remove */
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
	}


	/* Do any special permission checks here */
	if ((strcmp(object->pn_string, "PARTITION") == 0)) {
		char *LibraryName = NULL;
		/* For PARTITION get CartridgeID using libname and pcl */

		char *CartridgePCL = NULL;
		CartridgePCL = mm_return_set_value(&set_list, "PARTITION",
		    "CartridgePCL");
		if (CartridgePCL == NULL) {
			mms_trace(MMS_ERR, "Create PARTITION requires "
			    "a CartridgePCL");
			mm_response_error(cmd,
			    "invalid",
			    "EOBJCREATESYSATTRREQUIRED",
			    MM_5086_MSG,
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		LibraryName = mm_return_set_value(&set_list, "PARTITION",
		    "LibraryName");
		if (LibraryName == NULL) {
			mms_trace(MMS_ERR, "Create PARTITION requires "
			    "a LibraryName");
			mm_response_error(cmd,
			    "invalid",
			    "EOBJCREATESYSATTRREQUIRED",
			    MM_5087_MSG,
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		if (mm_wka->wka_privilege == MM_PRIV_STANDARD) {
			/* For a non-priv client, */
			/* check the user's CARTRIDGEGROUPAPPLICATION */
			if (mm_db_exec(HERE, db,
			    "select distinct "
			    "\"CARTRIDGEGROUPAPPLICATION\".* "
			    "from \"CARTRIDGEGROUPAPPLICATION\" "
			    "cross join \"CARTRIDGE\" where ("
			    "(\"CARTRIDGEGROUPAPPLICATION\"."
			    "\"CartridgeGroupName\" = "
			    "\"CARTRIDGE\".\"CartridgeGroupName\") "
			    "and ("
			    "(\"CARTRIDGE\".\"CartridgePCL\" "
			    "= '%s') AND "
			    "(\"CARTRIDGEGROUPAPPLICATION\"."
			    "\"ApplicationName\" = '%s') AND "
			    "(\"CARTRIDGE\".\"LibraryName\" = '%s')));",
			    CartridgePCL,
			    mm_wka->
			    wka_conn.cci_client,
			    LibraryName) != MM_DB_DATA) {
				mm_sql_db_err_rsp_new(cmd, db);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				goto end;
			}

			if (PQntuples(db->mm_db_results) == 0) {
				mms_trace(MMS_ERR,
				    "Missing a CARTRIDGEGROUPAPPLICATION, "
				    "%s",
				    mm_wka->
				    wka_conn.cci_client);
				mm_response_error(cmd,
				    "explicit",
				    "EAPPCARTNOACC",
				    MM_5088_MSG,
				    "client",
				    mm_wka->wka_conn.cci_client,
				    "pcl",
				    CartridgePCL,
				    NULL);
				cmd->cmd_remove = 1;
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				rc = MM_CMD_ERROR;
				mm_clear_db(&db->mm_db_results);
				goto end;
			}
		}
		/* Either a priv app, or std app w/cart access */
		/* Get the cartridgeID */
		mm_clear_db(&db->mm_db_results);
		if (mm_db_exec(HERE, db,
		    "select \"CartridgeID\" from "
		    "\"CARTRIDGE\" where "
		    "(\"CARTRIDGE\".\"CartridgePCL\" "
		    " = '%s') and "
		    "(\"CARTRIDGE\".\"LibraryName\" "
		    " = '%s');",
		    CartridgePCL,
		    LibraryName) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR,
			    "Error getting CartridgeID from DB");
			mm_system_error(cmd,
			    "Error getting CartridgeID from DB");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			mm_clear_db(&db->mm_db_results);
			goto end;
		}
		part_cart_id = strdup(PQgetvalue(db->mm_db_results, 0, 0));
		mms_trace(MMS_DEVP, "Cartridge ID is %s", part_cart_id);
	}
	mm_clear_db(&db->mm_db_results);

	mms_trace(MMS_DEVP, "Done checking objects and attribtes");




	/* Construct the SQL command */
	cmd_buf = mms_strapp(cmd_buf, "INSERT INTO \"%s\" (",
	    object->pn_string);

	/* List the attributes */
	for (cur_set = mms_list_head(&set_list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(&set_list, cur_set);
		if (first) {
			/* Skip comma on first */
			first = 0;
		} else {
			/* need commma */
			cmd_buf = mms_strapp(cmd_buf, ", ");
		}
		cmd_buf = mms_strapp(cmd_buf,
		    "\"%s\"", cur_set->cmd_set_attr);
	}
	if ((strcmp(object->pn_string,
	    "CARTRIDGE") == 0) ||
	    (strcmp(object->pn_string,
	    "PARTITION") == 0)) {
		/* Obj is cartridge, add CartridgeID */
		cmd_buf = mms_strapp(cmd_buf, ", \"CartridgeID\"");
	}

	/* List the values */
	cmd_buf = mms_strapp(cmd_buf, ") VALUES (");
	first = 1;
	for (cur_set = mms_list_head(&set_list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(&set_list, cur_set);
		if (first) {
			/* Skip comma on first */
			first = 0;
		} else {
			/* need commma */
			cmd_buf = mms_strapp(cmd_buf, ", ");
		}
		cmd_buf = mms_strapp(cmd_buf,
		    "'%s'", cur_set->cmd_set_value);
	}
	if (strcmp(object->pn_string,
	    "CARTRIDGE") == 0) {
		/* Obj is cartridge, add CartridgeID */
		mm_get_uuid(cartridge_id);
		cmd_buf = mms_strapp(cmd_buf, ", \'%s'", cartridge_id);
	} else if (strcmp(object->pn_string,
	    "PARTITION") == 0) {
		/* cartridge_id should be set above */
		if (part_cart_id != NULL) {
			cmd_buf = mms_strapp(cmd_buf,
			    ", \'%s'", part_cart_id);
		} else {
			mms_trace(MMS_ERR,
			    "Error finding part_cart_id");
			mm_system_error(cmd,
			    "Error finding part_cart_id");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			rc = MM_CMD_ERROR;
			goto end;
		}
	}

	cmd_buf = mms_strapp(cmd_buf, ")");

	/* Copy local cmd_buf into cmd->cmd_buf */
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(cmd_buf) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, "%s", cmd_buf);
	if (cmd_buf) {
		mms_trace(MMS_DEVP, "    %s", cmd_buf);
	}
	/* Send cmd->cmd_buf to the data base */

	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_OK) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		rc = MM_CMD_ERROR;
		goto end;
	}


	/* Create any additional objects */
	if (strcmp(object->pn_string, "CARTRIDGE") == 0) {
		/* New Cartridge */
		if (mm_create_side(mm_wka, cmd,
		    cartridge_id) == MM_CMD_ERROR) {
			rc = MM_CMD_ERROR;
			goto end;
		}

	} else if (strcmp(object->pn_string,
	    "CARTRIDGETYPE") == 0) {
		char *cartridge_type = NULL;
		/* New Cartridge Type */
		cartridge_type = mm_return_set_value(&set_list, "CARTRIDGETYPE",
		    "CartridgeTypeName");
		if (cartridge_type == NULL) {
			mms_trace(MMS_ERR, "Couldn't find CartridgeTypeName");
			rc = MM_CMD_ERROR;
			goto end;
		}
		if (mm_update_side(mm_wka, cmd,
		    cartridge_type) == MM_CMD_ERROR) {
			rc = MM_CMD_ERROR;
			goto end;
		}
	}

	/* Do event notification */
	if (strcmp(object->pn_string, "DM") == 0) {
		char *DMTargetHost = NULL;
		/* Notification for new DM */
		char *DMName = NULL;
		DMName = mm_return_set_value(&set_list, "DM",
		    "DMName");
		if (DMName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find DMName");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		DMTargetHost = mm_return_set_value(&set_list, "DM",
		    "DMTargetHost");
		if (DMName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find DMTargetHost");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		if (mm_notify_add_config(mm_wka, cmd,
		    EVENT_CFG_NEW,
		    "DM",
		    DMName,
		    DMTargetHost)) {
			mms_trace(MMS_ERR,
			    "mm_create_cmd_func: "
			    "error adding config event");
		}

	} else if (strcmp(object->pn_string, "LM") == 0) {
		char *LMTargetHost = NULL;
		/* Notification for new LM */
		char *LMName = NULL;
		LMName = mm_return_set_value(&set_list, "LM",
		    "LMName");
		if (LMName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find LMName");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		LMTargetHost = mm_return_set_value(&set_list, "LM",
		    "LMTargetHost");
		if (LMName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find LMTargetHost");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}

		if (mm_notify_add_config(mm_wka, cmd,
		    EVENT_CFG_NEW,
		    "LM",
		    LMName,
		    LMTargetHost)) {
			mms_trace(MMS_ERR,
			    "mm_create_cmd_func: "
			    "error adding config event");
		}

	} else if (strcmp(object->pn_string, "DRIVE") == 0) {

		char *DriveName = NULL;
		char *LibraryName = NULL;
		DriveName = mm_return_set_value(&set_list, "DRIVE",
		    "DriveName");
		if (DriveName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find DriveName");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		LibraryName = mm_return_set_value(&set_list, "DRIVE",
		    "LibraryName");
		if (LibraryName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find Library Name");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		/* Notification for new DRIVE */
		mm_notify_add_newdrive(cmd->wka_ptr,
		    cmd,
		    DriveName,
		    LibraryName);

		/* Add LMP scan command for this drive */
		if (mm_add_lmp_scan(mm_wka->mm_data, NULL, DriveName,
		    NULL, LibraryName)) {
			mms_trace(MMS_DEBUG,
			    "Error adding LMP scan, LM may not be connected");
		} else {
			mms_trace(MMS_DEVP,
			    "Added a LMP scan");
			command_added = 1;
		}


	} else if (strcmp(object->pn_string, "CARTRIDGE") == 0) {
		char *CartridgePCL = NULL;
		char *LibraryName = NULL;
		CartridgePCL = mm_return_set_value(&set_list, "CARTRIDGE",
		    "CartridgePCL");
		if (CartridgePCL == NULL) {
			mms_trace(MMS_ERR, "Couldn't find CartridgePCL");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		LibraryName = mm_return_set_value(&set_list, "CARTRIDGE",
		    "LibraryName");
		if (LibraryName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find Library Name");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		/* Notification for new CARTRIDGE */

		mm_notify_add_newcartridge(cmd->wka_ptr,
		    cmd,
		    CartridgePCL,
		    LibraryName);

		/* Add LMP scan command for this cartridge */
		if (mm_add_lmp_scan(mm_wka->mm_data, NULL, NULL,
		    CartridgePCL, LibraryName)) {
			mms_trace(MMS_DEBUG,
			    "Error adding LMP scan");
		} else {
			mms_trace(MMS_DEVP,
			    "Added a LMP scan");
			command_added = 1;
		}
	} else if (strcmp(object->pn_string, "LIBRARY") == 0) {
		char *LibraryName = NULL;
		LibraryName = mm_return_set_value(&set_list, "LIBRARY",
		    "LibraryName");
		if (LibraryName == NULL) {
			mms_trace(MMS_ERR, "Couldn't find Library Name");
			rc = MM_CMD_ERROR;
			/* New Error codes for this?? */
			goto not_found;
		}
		mm_notify_add_librarycreate(cmd->wka_ptr,
		    cmd,
		    LibraryName);
	}

	/* Trace a info summary */

	mms_trace(MMS_INFO,
	    "%s created by %s %s",
	    object->pn_string,
	    conn->cci_client,
	    conn->cci_instance);
	for (cur_set = mms_list_head(&set_list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(&set_list, cur_set);
		mms_trace(MMS_INFO, "    %s.%s=%s",
		    cur_set->cmd_set_obj,
		    cur_set->cmd_set_attr,
		    cur_set->cmd_set_value);
	}

	/* Create the report and send success */
	mm_path_match_report(cmd, db);
	cmd->cmd_remove = 1;
	mm_send_response(mm_wka->mm_wka_conn, cmd);

	if (command_added) {
		rc = MM_DISPATCH_AGAIN;
	} else {
		rc = MM_CMD_DONE;
	}
	goto end;

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	rc = MM_CMD_ERROR;
	goto end;

end:
	/* Destroy the lists */
	/* Set List */
	for (cur_set = mms_list_head(&set_list);
	    cur_set != NULL;
	    cur_set = next) {
		next = mms_list_next(&set_list, cur_set);
		if (cur_set->cmd_set_obj)
			free(cur_set->cmd_set_obj);
		if (cur_set->cmd_set_attr)
			free(cur_set->cmd_set_attr);
		if (cur_set->cmd_set_value)
			free(cur_set->cmd_set_value);
		mms_list_remove(&set_list,
		    cur_set);
		free(cur_set);
	}
	mms_list_destroy(&set_list);
	free(cmd_buf);

	if (part_cart_id != NULL)
		free(part_cart_id);

	return (rc);
}



/*
 * mm_get_task:
 * returns allocated char*, caller must free
 */
char *
mm_get_task(mms_par_node_t *root)
{
	mms_par_node_t	*node;
	mms_par_node_t	*tasknode;
	char		*task;

	node = mms_pn_lookup(root, "task", MMS_PN_CLAUSE, NULL);
	if (node == NULL) {
		mms_trace(MMS_DEBUG,
		    "mm_get_task couldn't find a task clause");
		return (NULL);
	}
	tasknode = mms_pn_lookup(node, NULL, MMS_PN_STRING, NULL);
	if (tasknode == NULL) {
		mms_trace(MMS_DEBUG,
		    "mm_get_task couldn't find the task string");
		return (NULL);
	}
	if (mms_pn_token(tasknode) == NULL) {
		mms_trace(MMS_DEBUG,
		    "mm_get_task, task sting is null");
		return (NULL);
	}
	task = strdup(mms_pn_token(tasknode));
	return (task);
}

int
mm_change_attendance_mode(mm_wka_t *mm_wka)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	PGresult	*results;
	char		*reqid;
	int		messageid = 1001;
	char		*text = "unattened";
	char		*buf;
	int		rc;
	mm_command_t	*cmd_p;
	mm_data_t	*data = mm_wka->mm_data;
	int		i;

	mms_trace(MMS_DEVP, "mm_change_attendance_mode");

	/*
	 * SYSTEM.AttendanceMode was changed, respond to requests
	 * if unattended mode.
	 */

	/* get mm operator attandance mode */
	if (mm_db_exec(HERE, db, "select \"AttendanceMode\" "
	    "from \"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	rc = strcmp(PQgetvalue(db->mm_db_results, 0, 0), "attended");
	mm_clear_db(&db->mm_db_results);
	if (rc == 0) {
		mms_trace(MMS_DEVP, "mm is operator attened");
		return (0);
	}

	mms_trace(MMS_DEVP, "mm is operator unattened");

	/* respond to all outstanding requests */

	if (mm_db_exec(HERE, db, "select \"RequestID\" from \"REQUEST\" "
	    "where \"RequestState\" != 'responded';") != MM_DB_DATA) {
		return (1);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		mm_clear_db(&db->mm_db_results);
		return (0); /* zero unfinished requests */
	}
	results = db->mm_db_results;

	for (i = 0; i < PQntuples(results); i++) {
		reqid = PQgetvalue(results, i, 0);

		/* set requests to responded */
		if (mm_db_exec(HERE, db, "update \"REQUEST\" set "
		    "\"RequestState\" = 'responded',"
		    "\"RequestTimeResponded\" = now(),"
		    "\"ResponseManufacturer\" = '%s',"
		    "\"ResponseModel\" = '%s',"
		    "\"ResponseNumber\" = '%d',"
		    "\"ResponseText\" = $$%s$$,"
		    "\"AcceptingClient\" = '%s',"
		    "\"AcceptingInstance\" = '%s',"
		    "\"AcceptingSessionID\" = default,"
		    "\"RequestTimeAccepted\" = now() "
		    "where \"RequestID\" = '%s';",
		    MESS_MANUFACTURER, MESS_MODEL, messageid, text,
		    data->mm_cfg.mm_network_cfg.cli_name,
		    data->mm_cfg.mm_network_cfg.cli_inst,
		    reqid) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&results);
			return (1);
		}

		if (db->mm_db_count != 1) {
			continue;
		}

		/* respond to request commands with unattended */
		pthread_mutex_lock(&data->mm_queue_mutex);
		mms_list_foreach(&data->mm_cmd_queue, cmd_p) {
			if (strcmp(cmd_p->cmd_reqid, reqid) == 0) {
				break;
			}
		}
		if (cmd_p == NULL) {
			/* mm will clean this req up at client disconnect */
			pthread_mutex_unlock(&data->mm_queue_mutex);
			continue;
		}

		buf = mms_strnew("response task[\"%s\"] success "
		    "text[\"%d\" \"reply\" \"%s\"];",
		    cmd_p->cmd_task, messageid, text);
		SQL_CHK_LEN(&cmd_p->cmd_buf, 0, &cmd_p->cmd_bufsize,
		    strlen(buf) + 1);
		(void) strlcpy(cmd_p->cmd_buf, buf, cmd_p->cmd_bufsize);
		free(buf);

		cmd_p->cmd_remove = 1;
		if (mm_has_depend(cmd_p)) {
			mm_command_t *cur_depend = NULL;
			mms_trace(MMS_DEVP, "internal mm request");
			mms_list_foreach(&cmd_p->cmd_depend_list, cur_depend) {
				cur_depend->cmd_response =
				    mm_text_to_par_node(cmd_p->cmd_buf,
				    mms_mmp_parse);
				cur_depend->cmd_flags |= MM_CMD_DISPATCHABLE;
			}

			/*
			 * Command queue tick so cmd_depend is valid.
			 */
			mms_list_remove(&data->mm_cmd_queue, cmd_p);
			mms_list_insert_head(&data->mm_cmd_queue, cmd_p);
			rc = 0;
		} else {
			mms_trace(MMS_DEVP, "device manager request");
			mm_send_text(cmd_p->wka_ptr->mm_wka_conn,
			    cmd_p->cmd_buf);
		}
		pthread_mutex_unlock(&data->mm_queue_mutex);

	}
	mm_clear_db(&results);

	/* resize request history */
	if (mm_request_history_limit(db)) {
		mms_trace(MMS_ERR, "unable to resize history");
		return (1);
	}

	return (0);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);
}

int
mm_attendance_mode_internal(mm_wka_t *mm_wka, mm_command_t *cmd,
    mm_command_t *req_cmd)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	int		messageid = 1001;
	char		*text = "unattened";
	char		*buf;
	int		rc;
	mm_data_t	*data = mm_wka->mm_data;

	mms_trace(MMS_DEVP, "mm_attendance_mode_internal");

	/*
	 * Attendance mode for mm request
	 */

	/* get mm operator attandance mode */
	if (mm_db_exec(HERE, db, "select \"AttendanceMode\" "
	    "from \"SYSTEM\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR, "unable to get attendance mode");
		mm_sql_db_err_rsp_new(req_cmd, db);
		cmd->cmd_response = mm_text_to_par_node(req_cmd->cmd_buf,
		    mms_mmp_parse);
		return (-1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR, "no results in attendance mode query");
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_INTERNAL,
		    MM_E_INTERNAL,
		    MM_5021_MSG,
		    "text",
		    "no results in attendance mode query",
		    NULL);
		cmd->cmd_response = mm_text_to_par_node(req_cmd->cmd_buf,
		    mms_mmp_parse);
		return (-1);
	}
	rc = strcmp(PQgetvalue(db->mm_db_results, 0, 0), "attended");
	mm_clear_db(&db->mm_db_results);
	if (rc == 0) {
		mms_trace(MMS_DEVP, "mm is operator attened");
		return (0);
	}


	mms_trace(MMS_DEVP, "mm is not attended by an operator");

	/* set request to responded */
	if (mm_db_exec(HERE, db, "update \"REQUEST\" set "
	    "\"RequestState\" = 'responded',"
	    "\"RequestTimeResponded\" = now(),"
	    "\"ResponseManufacturer\" = '%s',"
	    "\"ResponseModel\" = '%s',"
	    "\"ResponseNumber\" = '%d',"
	    "\"ResponseText\" = $$%s$$,"
	    "\"AcceptingClient\" = '%s',"
	    "\"AcceptingInstance\" = '%s',"
	    "\"AcceptingSessionID\" = default,"
	    "\"RequestTimeAccepted\" = now() "
	    "where \"RequestID\" = '%s';",
	    MESS_MANUFACTURER, MESS_MODEL, messageid, text,
	    data->mm_cfg.mm_network_cfg.cli_name,
	    data->mm_cfg.mm_network_cfg.cli_inst,
	    req_cmd->cmd_reqid) != MM_DB_OK) {
		mms_trace(MMS_ERR, "failed to set unattended request");
		mm_sql_db_err_rsp_new(req_cmd, db);
		mm_clear_db(&db->mm_db_results);
		cmd->cmd_response = mm_text_to_par_node(req_cmd->cmd_buf,
		    mms_mmp_parse);
		return (-1);
	}
	if (db->mm_db_count != 1) {
		mms_trace(MMS_ERR, "set request unattended count not 1");
		mm_response_error(cmd,
		    ECLASS_INTERNAL,
		    MM_E_INTERNAL,
		    MM_5021_MSG,
		    "text",
		    "set request unattended count not 1",
		    NULL);
		cmd->cmd_response = mm_text_to_par_node(req_cmd->cmd_buf,
		    mms_mmp_parse);
		return (-1);
	}

	/* resize request history */
	if (mm_request_history_limit(db)) {
		mm_response_error(cmd,
		    ECLASS_SUBOP,
		    EREQSTATECHANGEFAILED,
		    MM_5089_MSG,
		    NULL);
		cmd->cmd_response = mm_text_to_par_node(req_cmd->cmd_buf,
		    mms_mmp_parse);
		return (-1);
	}

	/* tell mm we're unattened */
	buf = mms_strnew("response task[\"%s\"] success "
	    "text[\"%d\" \"reply\" \"%s\"];",
	    cmd->cmd_task, messageid, text);
	SQL_CHK_LEN(&req_cmd->cmd_buf, 0, &req_cmd->cmd_bufsize,
	    strlen(buf) + 1);
	(void) strlcpy(req_cmd->cmd_buf, buf, req_cmd->cmd_bufsize);
	free(buf);
	cmd->cmd_response = mm_text_to_par_node(req_cmd->cmd_buf,
	    mms_mmp_parse);
	cmd->cmd_flags |= MM_CMD_DISPATCHABLE;
	return (1);

no_mem:
	MM_ABORT_NO_MEM();
	return (-1);
}

int
mm_make_request(mm_wka_t *mm_wka, mm_command_t *cmd, char *task, int priority,
    int messageid, ...)
{
	mm_command_t	*req_cmd;
	uuid_text_t	new_task;
	va_list		args;
	char		*text;
	uuid_text_t	reqid_uuid;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*task_taskid = NULL;
	int		rows;
	int		rc;
	mm_data_t	*data = mm_wka->mm_data;

	mms_trace(MMS_DEVP, "mm_internal_request for %s",
	    (cmd->cmd_name == NULL ? "??" : cmd->cmd_name));

	/*
	 * The mm is requesting operator intervention
	 */

	req_cmd = (mm_command_t *)calloc(1, sizeof (mm_command_t));
	req_cmd->wka_ptr = mm_wka;
	req_cmd->cmd_mm_data = mm_wka->mm_data;
	mm_get_uuid(new_task);
	va_start(args, messageid);
	text = mms_get_locstr(messageid, args);
	va_end(args);
	req_cmd->cmd_name = strdup("mm request");
	req_cmd->cmd_textcmd = mms_strnew("internal \"%s\" "
	    "\"task\" \"%s\" \"priority\" \"%d\" "
	    "\"messageid\" \"%d\" \"locstr\" \"%s\";",
	    req_cmd->cmd_name, new_task, priority, messageid, text);
	req_cmd->cmd_root = mm_text_to_par_node(req_cmd->cmd_textcmd,
	    mms_mmp_parse);
	req_cmd->cmd_task = strdup(new_task);
	mm_add_depend(req_cmd, cmd);
	(void) strlcpy(req_cmd->wka_uuid, mm_wka->wka_conn.cci_uuid,
	    sizeof (req_cmd->wka_uuid));

	/* get requestid */
	mm_get_uuid(reqid_uuid);

	/* set command reqid */
	strcpy(req_cmd->cmd_reqid, reqid_uuid);

	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, req_cmd);
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);


	/*
	 * Make internal mm request entry
	 */


	/* mm can have but does not need a valid task.taskid */
	if (task == MM_NO_TASK) {
		/* no task.taskid */
		task_taskid = strdup("default");
	} else {
		/* validate task.taskid */
		if (mm_db_exec(HERE, db, "select * from \"TASK\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_DATA) {
			free(text);
			mm_sql_db_err_rsp_new(req_cmd, db);
			mm_clear_db(&db->mm_db_results);
			cmd->cmd_response =
			    mm_text_to_par_node(req_cmd->cmd_buf,
			    mms_mmp_parse);
			req_cmd->cmd_remove = 1;
			return (1);
		}
		rows = PQntuples(db->mm_db_results);
		mm_clear_db(&db->mm_db_results);
		if (rows != 1) {
			free(text);
			if (rows == 0) {
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    MM_E_NOTASK,
				    MM_5090_MSG,
				    NULL);
			} else {
				mm_response_error(cmd,
				    ECLASS_EXPLICIT,
				    MM_E_TOOMANYTASKS,
				    MM_5091_MSG,
				    NULL);
			}
			cmd->cmd_response =
			    mm_text_to_par_node(req_cmd->cmd_buf,
			    mms_mmp_parse);
			req_cmd->cmd_remove = 1;
			return (1);
		}
		task_taskid = mms_strnew("'%s'", cmd->cmd_uuid);
	}

	rc = mm_db_exec(HERE, db, "insert into \"REQUEST\" "
	    "(\"RequestID\",\"RequestingTaskID\","
	    "\"RequestingClient\",\"RequestingInstance\","
	    "\"RequestingClientType\",\"RequestPriority\","
	    "\"RequestManufacturer\",\"RequestModel\","
	    "\"RequestNumber\",\"RequestText\",\"RequestHost\") "
	    "values ('%s',%s,'%s','%s','%s','%d',"
	    "'%s','%s','%d',$$%s$$,'%s');",
	    reqid_uuid,
	    task_taskid,
	    data->mm_cfg.mm_network_cfg.cli_name,
	    data->mm_cfg.mm_network_cfg.cli_inst,
	    MESS_MM_STR,
	    priority,
	    MESS_MANUFACTURER,
	    MESS_MODEL,
	    messageid,
	    text,
	    data->mm_host_name);
	free(task_taskid);
	free(text);
	if (rc != MM_DB_OK) {
		mm_sql_db_err_rsp_new(req_cmd, db);
		mm_clear_db(&db->mm_db_results);
		cmd->cmd_response = mm_text_to_par_node(req_cmd->cmd_buf,
		    mms_mmp_parse);
		req_cmd->cmd_remove = 1;
		return (1);
	}
	mms_trace(MMS_INFO, "Added internal mm request %s", reqid_uuid);

	/* mm operator attendance mode */
	if ((rc = mm_attendance_mode_internal(mm_wka, cmd, req_cmd)) != 0) {
		mms_trace(MMS_DEVP, "failed doing internal attendance mode");
		/*
		 * Command queue tick so cmd_depend is valid.
		 */
		pthread_mutex_lock(&data->mm_queue_mutex);
		req_cmd->cmd_remove = 1;
		mms_list_remove(&data->mm_cmd_queue, req_cmd);
		mms_list_insert_head(&data->mm_cmd_queue, req_cmd);
		pthread_mutex_unlock(&data->mm_queue_mutex);
		if (rc == 1) {
			rc = 0; /* unattended */
		} else {
			rc = 1; /* error */
		}
		return (rc);
	}

	return (0);
}

int
mm_cancel_request(mm_db_t *db, char *reqid)
{

	if (reqid[0] == (char)0) {
		return (0);		/* no request */
	}

	if (mm_db_exec(HERE, db, "delete from \"REQUEST\" where "
	    "\"RequestID\" = '%s' and \"RequestState\" != 'responded';",
	    reqid) != MM_DB_OK) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	mms_trace(MMS_DEVP, "deleted request %s - %d", reqid, db->mm_db_count);

	return (0);
}

int
mm_attendance_mode(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	int		messageid = 1001;
	char		*text = "unattened";
	char		*buf;
	mm_data_t	*data = mm_wka->mm_data;
	int		rc;

	mms_trace(MMS_DEVP, "mm_attendance_mode");

	/*
	 * Attendance mode for device manager request
	 */

	/* get mm operator attandance mode */
	if (mm_db_exec(HERE, db, "select \"AttendanceMode\" "
	    "from \"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		mm_system_error(cmd,
		    "too many rows returned "
		    "getting SYSTEM.AttendanveMode");
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	rc = strcmp(PQgetvalue(db->mm_db_results, 0, 0), "attended");
	mm_clear_db(&db->mm_db_results);
	if (rc == 0) {
		mms_trace(MMS_DEVP, "mm is operator attened");
		return (MM_WORK_TODO);
	}


	mms_trace(MMS_DEVP, "mm is not attended by an operator");

	/* set request to responded */
	if (mm_db_exec(HERE, db, "update \"REQUEST\" set "
	    "\"RequestState\" = 'responded',"
	    "\"RequestTimeResponded\" = now(),"
	    "\"ResponseManufacturer\" = '%s',"
	    "\"ResponseModel\" = '%s',"
	    "\"ResponseNumber\" = '%d',"
	    "\"ResponseText\" = $$%s$$,"
	    "\"AcceptingClient\" = '%s',"
	    "\"AcceptingInstance\" = '%s',"
	    "\"AcceptingSessionID\" = default,"
	    "\"RequestTimeAccepted\" = now() "
	    "where \"RequestID\" = '%s';",
	    MESS_MANUFACTURER, MESS_MODEL, messageid, text,
	    data->mm_cfg.mm_network_cfg.cli_name,
	    data->mm_cfg.mm_network_cfg.cli_inst,
	    cmd->cmd_reqid) != MM_DB_OK) {
		mm_clear_db(&db->mm_db_results);
		mm_sql_db_err_rsp_new(cmd, db);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	mm_clear_db(&db->mm_db_results);
	if (db->mm_db_count != 1) {
		mm_system_error(cmd,
		    "failed to correctly "
		    "update request object");
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* resize request history */
	if (mm_request_history_limit(db)) {
		mm_response_error(cmd,
		    ECLASS_SUBOP,
		    EREQSTATECHANGEFAILED,
		    MM_5089_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* tell device manager we're unattened */
	buf = mms_strnew("response task[\"%s\"] success "
	    "text[\"%d\" \"reply\" \"%s\"];",
	    cmd->cmd_task, messageid, text);
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, strlen(buf) + 1);
	strcpy(cmd->cmd_buf, buf);
	free(buf);
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}

void
mm_request_tasktaskid(mm_command_t *cmd, char *tasktaskid, char **taskid)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	mm_data_t	*data = cmd->cmd_mm_data;
	mm_command_t	*cmd_p;
	mm_command_t	*cmd_q;

	mms_trace(MMS_DEVP, "mm_request_tasktaskid %s", tasktaskid);

	*taskid = NULL;

	/*
	 * taskid is mm command which cause the request,
	 * find the mm command in the command queue which
	 * contains the mm task.taskid.
	 */

	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&data->mm_cmd_queue, cmd_p) {

		if (cmd_p->wka_ptr == NULL)
			continue;

		if (strcmp(tasktaskid, cmd_p->cmd_task) == 0) {

			/* find parent command */
			cmd_q = mm_top_parent(cmd_p);

			/* this maybe be our task.taskid */
			*taskid = strdup(cmd_q->cmd_uuid);
			if (*taskid == NULL) {
				MM_ABORT_NO_MEM();
			}
			break;
		}
	}
	pthread_mutex_unlock(&data->mm_queue_mutex);

	if (*taskid == NULL) {
		mms_trace(MMS_DEVP, "taskid not found");
		return;
	}

	if (mm_db_exec(HERE, db, "select \"TaskID\" from \"TASK\" where "
	    "\"TaskID\" = '%s';", *taskid) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		free(*taskid);
		*taskid = NULL;
		return;
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		free(*taskid);
		*taskid = NULL;
		return;
	}
	mm_clear_db(&db->mm_db_results);
}

int
mm_request_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*clause;
	mms_par_node_t	*name;
	mms_par_node_t	*value;
	mms_par_node_t	*arg;
	int		priority;
	char		*obj;
	char		*attr;
	int		rc;
	uuid_text_t	reqid_uuid;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	char		*taskid = NULL;
	char		taskid_buf[UUID_PRINTF_SIZE+3];

	mms_trace(MMS_DEVP, "mm_request_cmd_func");

	/*
	 * Device manager or mmp client is requesting operator intervention
	 */

	MMS_PN_LOOKUP(arg, cmd->cmd_root, "type", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_OBJ, NULL);


	MMS_PN_LOOKUP(clause, cmd->cmd_root, "priority",
	    MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, NULL);
	priority = atoi(value->pn_string);

	/*
	 * find optional task.taskid for device manager
	 */

	if (mm_msg_parse(cmd, cmd->cmd_root)) {
		free(taskid);
		mm_response_error(cmd,
		    ECLASS_INTERNAL, MM_E_CMDARGS,
		    MM_5067_MSG,
		    "text",
		    "mission task.taskid for device manager",
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* optional - find task by mm dmp/lmp command taskid */
	if (cmd->cmd_msg.msg_args) {

		mms_trace(MMS_DEVP,
		    "find task.taskid by message-clause argument");

		/*
		 * reserved request message-clause arg-key word:
		 *		tasktaskid - mm command taskid
		 */

		mms_list_pair_foreach(cmd->cmd_msg.msg_args, name, value) {

			if (strcmp(mms_pn_token(name), "tasktaskid") == 0) {
				mm_request_tasktaskid(cmd,
				    mms_pn_token(value),
				    &taskid);
				break;
			}
		}
	}

	if (taskid == NULL && mm_wka->mm_wka_mm_lang != MM_LANG_MMP) {

		/*
		 * If one and only one task for a device manager exists then
		 * assign it to the request object.
		 */

		if (mm_wka->mm_wka_mm_lang == MM_LANG_DMP) {
			obj = "TASKDRIVE";
			attr = "DriveName";
		} else {
			obj = "TASKLIBRARY";
			attr = "LibraryName";
		}

		if (mm_db_exec(HERE, db, "select \"TASK\".\"TaskID\" "
		    "from \"TASK\",\"%s\" where "
		    "\"TASK\".\"TaskID\" = \"%s\".\"TaskID\" and "
		    "\"%s\".\"%s\" = '%s';", obj, obj, obj, attr,
		    cmd->wka_ptr->wka_conn.cci_client) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) == 1) {
			taskid = strdup(PQgetvalue(db->mm_db_results, 0, 0));
			if (taskid == NULL) {
				MM_ABORT_NO_MEM();
			}
		}
		mm_clear_db(&db->mm_db_results);
	}

	if (taskid) {
		mms_trace(MMS_DEVP, "taskid %s found", taskid);
		(void) snprintf(taskid_buf, sizeof (taskid_buf),
		    "'%s'", taskid);
		free(taskid);
	} else {
		mms_trace(MMS_DEVP, "taskid not found");
		(void) strlcpy(taskid_buf, "default", sizeof (taskid_buf));
	}

	/*
	 * Make request entry
	 */

	mm_get_uuid(reqid_uuid);

	rc = mm_db_exec(HERE, db, "insert into \"REQUEST\" "
	    "(\"RequestID\",\"RequestingTaskID\","
	    "\"RequestingClient\",\"RequestingInstance\","
	    "\"RequestingConnectionID\",\"RequestingClientType\","
	    "\"RequestPriority\",\"RequestManufacturer\","
	    "\"RequestModel\",\"RequestNumber\","
	    "\"RequestText\",\"RequestHost\") "
	    "values ('%s',%s,'%s','%s','%s','%s','%d',"
	    "'%s','%s','%d',$$%s$$,'%s');",
	    reqid_uuid,
	    taskid_buf,
	    cmd->wka_ptr->wka_conn.cci_client,
	    cmd->wka_ptr->wka_conn.cci_instance,
	    cmd->wka_ptr->wka_conn.cci_uuid,
	    mm_msg_lang2component(cmd->wka_ptr->mm_wka_mm_lang),
	    priority,
	    cmd->cmd_msg.msg_manufacturer,
	    cmd->cmd_msg.msg_model,
	    cmd->cmd_msg.msg_messageid,
	    cmd->cmd_msg.msg_localized,
	    cmd->wka_ptr->wka_conn.cci_host);
	if (rc != MM_DB_OK) {
		mm_sql_db_err_rsp_new(cmd, db);
		mm_clear_db(&db->mm_db_results);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	mm_clear_db(&db->mm_db_results);

	/* set command reqid */
	strcpy(cmd->cmd_reqid, reqid_uuid);

	mms_trace(MMS_INFO, "Added request");

	/* mm operator attendance mode */
	if ((rc = mm_attendance_mode(mm_wka, cmd)) != MM_WORK_TODO) {
		mms_trace(MMS_DEVP, "unattened or error");
		return (rc);
	}

	mms_trace(MMS_DEVP, "operator has request");
	return (MM_WORK_TODO);

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
mm_request_disconnect(mm_db_t *db, mm_wka_t *mm_wka)
{
	/*
	 * Cleanup disconnected client requests
	 */

	if (mm_wka->mm_wka_mm_lang == MM_LANG_MMP) {

		/*
		 * Release all requests accepted by this operator
		 */
		if (mm_db_exec(HERE, db, "update \"REQUEST\" set "
		    "\"AcceptingClient\" = default,"
		    "\"AcceptingInstance\" = default,"
		    "\"AcceptingSessionID\" = default,"
		    "\"RequestTimeAccepted\" = default,"
		    "\"RequestState\" = 'pending' "
		    "where \"AcceptingSessionID\" = '%s' "
		    "and \"RequestState\" != 'responded';",
		    mm_wka->session_uuid) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			return (1);
		}

	}

	/*
	 * Remove all requests generated by this device manager
	 * or mmp client.
	 */
	if (mm_db_exec(HERE, db, "delete from \"REQUEST\" where "
	    "\"RequestingClient\" = '%s' and "
	    "\"RequestingInstance\" = '%s' and "
	    "\"RequestState\" != 'responded' and "
	    "\"RequestingConnectionID\" = '%s';",
	    mm_wka->wka_conn.cci_client,
	    mm_wka->wka_conn.cci_instance,
	    mm_wka->wka_conn.cci_uuid) != MM_DB_OK) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	return (0);
}

int
mm_get_requests(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	mms_par_node_t	*reqid;
	mms_par_node_t	*arg;
	char		*buf;
	const char	*query;

	mms_trace(MMS_DEVP, "mm_get_requests");

	/*
	 * Find requests state info for the accept and release commands
	 */

	/* get requests */
	if (mms_pn_lookup(cmd->cmd_root, "match", MMS_PN_CLAUSE, NULL)) {
		(void) mm_get_dest(mm_wka, cmd);
		(void) mm_get_const(mm_wka, cmd); /* constraints */
		if (mm_add_char("REQUEST", &cmd->cmd_source_list)) {
			mms_trace(MMS_ERR,
			    "mm_get_requests: "
			    "out of mem creating source list");
			mm_system_error(cmd,
			    "out of mem creating source list");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

		cmd->cmd_source_num = 1;
		query = "select \"REQUEST\".\"RequestID\","
		    "\"REQUEST\".\"RequestState\","
		    "\"REQUEST\".\"AcceptingSessionID\" from ";
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(query) + 1);
		strcpy(cmd->cmd_buf, query);
		if (mm_sql_from_where(cmd, db)) {
			mms_trace(MMS_ERR,
			    "mm_get_requests: "
			    "db error creating helper functions");
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn,
			    cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}

	} else if (reqid = mms_pn_lookup(cmd->cmd_root, "reqid",
	    MMS_PN_CLAUSE, NULL)) {
		buf = NULL;
		query = "(\"REQUEST\".\"RequestID\" = '%s')";
		mms_list_foreach(&reqid->pn_arglist, arg) {
			buf = mms_strapp(buf, query, arg->pn_string);
			if (arg != mms_list_tail(&reqid->pn_arglist)) {
				buf = mms_strapp(buf, " or ");
			}
		}
		query = "select \"REQUEST\".\"RequestID\","
		    "\"REQUEST\".\"RequestState\","
		    "\"REQUEST\".\"AcceptingSessionID\" from "
		    "\"REQUEST\" where (%s) ";
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(query) + strlen(buf) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, query, buf);
		free(buf);
	} else {
		mm_response_error(cmd,
		    ECLASS_EXIST, ENOMATCH,
		    MM_5092_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	mm_sql_order(cmd);
	mm_sql_number(cmd);
	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* check request count */
	if (PQntuples(db->mm_db_results) == 0) {
		mms_trace(MMS_DEVP, "no requests selected");
		mm_clear_db(&db->mm_db_results);
		if (mms_pn_lookup(cmd->cmd_root, "match",
		    MMS_PN_CLAUSE, NULL)) {
			mm_response_error(cmd,
			    ECLASS_EXIST, ENOMATCH,
			    MM_5092_MSG,
			    NULL);
		} else {
			mm_response_error(cmd,
			    ECLASS_EXIST, ENOSUCHREQ,
			    MM_5093_MSG,
			    NULL);
		}
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* caller frees tuples */
	return (0);

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
mm_accept_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	int		rc;
	int		error;
	int		i;
	char		*state;
	char		*buf;
	char		*more;

	mms_trace(MMS_DEVP, "mm_accept_cmd_func");

	if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
		return (MM_CMD_ERROR);
	}

	/*
	 * Operator wants to work on device manager or mm requests
	 */

	if (rc = mm_get_requests(mm_wka, cmd)) {
		return (rc);
	}

	/* check for pending requests */
	error = 0;
	for (i = 0; i < PQntuples(db->mm_db_results); i++) {
		PQgetvalue(db->mm_db_results, i, 0);
		state = PQgetvalue(db->mm_db_results, i, 1);
		if (strcmp(state, "accepted") == 0) {
			mm_set_cmd_err_buf(cmd,
			    ECLASS_INVALID,
			    EREQUESTALREADYACCEPTED);
			error = 1;
		} else if (strcmp(state, "responded") == 0) {
			mm_set_cmd_err_buf(cmd,
			    ECLASS_INVALID,
			    EREQUESTALREADYSATISFIED);
			error = 1;
		}
		if (error) {
			mm_clear_db(&db->mm_db_results);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	}

	/* accept selected requests */
	buf = mms_strnew("update \"REQUEST\" set "
	    "\"AcceptingClient\" = '%s',"
	    "\"AcceptingInstance\" = '%s',"
	    "\"AcceptingSessionID\" = '%s',"
	    "\"RequestState\" = 'accepted',"
	    "\"RequestTimeAccepted\" = now() where ",
	    cmd->wka_ptr->wka_conn.cci_client,
	    cmd->wka_ptr->wka_conn.cci_instance,
	    cmd->wka_ptr->session_uuid);
	more = "or ";
	for (i = 0; i < PQntuples(db->mm_db_results); i++) {
		mms_trace(MMS_DEVP, "selected request id -> %s",
		    PQgetvalue(db->mm_db_results, i, 0));
		if (i + 1 >= PQntuples(db->mm_db_results)) {
			more = ";";
		}
		buf = mms_strapp(buf, "(\"RequestID\" = '%s') %s",
		    PQgetvalue(db->mm_db_results, i, 0), more);
	}
	rc = mm_db_exec(HERE, db, buf);
	free(buf);
	if (rc != MM_DB_OK) {
		mm_response_error(cmd,
		    ECLASS_SUBOP,
		    EREQSTATECHANGEFAILED,
		    MM_5089_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* get report */
	mm_path_match_report(cmd, db);
	mm_send_response(mm_wka->mm_wka_conn, cmd);
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
mm_respond_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	mm_data_t	*data = mm_wka->mm_data;
	mms_par_node_t	*clause;
	mms_par_node_t	*value;
	char		*reqid;
	mm_command_t	*cmd_p;
	char		*state;
	char		*session;
	int		messageid = 1000;
	char		*buf;

	mms_trace(MMS_DEVP, "mm_respond_cmd_func");

	/*
	 * Operator finished device manager, mm or app request
	 */

	MMS_PN_LOOKUP(clause, cmd->cmd_root, "reqid", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, NULL);
	reqid = value->pn_string;

	/* get request response message */
	if (mm_msg_parse(cmd, cmd->cmd_root)) {
		mm_system_error(cmd,
		    "failed to parse request response");
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	mms_trace(MMS_DEVP, "reply message info: %d %s %s - %s",
	    cmd->cmd_msg.msg_messageid,
	    cmd->cmd_msg.msg_manufacturer,
	    cmd->cmd_msg.msg_model,
	    cmd->cmd_msg.msg_localized);

	/* validate client request response */
	if (mm_db_exec(HERE, db, "select \"RequestState\","
	    "\"AcceptingSessionID\" from \"REQUEST\" where "
	    "\"RequestID\" = '%s';", reqid) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	state = PQgetvalue(db->mm_db_results, 0, 0);
	session = PQgetvalue(db->mm_db_results, 0, 1);
	if (PQntuples(db->mm_db_results) == 0) {
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_EXIST, ENOSUCHREQ,
		    MM_5093_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	if (strcmp(state, "pending") == 0) {
		mm_clear_db(&db->mm_db_results);
		mm_set_cmd_err_buf(cmd, ECLASS_INVALID, EREQUESTNOTACCEPTED);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	if (strcmp(state, "responded") == 0) {
		mm_clear_db(&db->mm_db_results);
		mm_set_cmd_err_buf(cmd,
		    ECLASS_INVALID,
		    EREQUESTALREADYSATISFIED);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	if (strcmp(session, mm_wka->session_uuid) != 0) {
		mm_clear_db(&db->mm_db_results);
		mm_set_cmd_err_buf(cmd, ECLASS_INVALID, EREQACCEPTEDBYDIFFSESS);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	mm_clear_db(&db->mm_db_results);

	/* set request to responded */
	if (mm_db_exec(HERE, db, "update \"REQUEST\" set "
	    "\"RequestState\" = 'responded',"
	    "\"RequestTimeResponded\" = now(),"
	    "\"ResponseManufacturer\" = '%s',"
	    "\"ResponseModel\" = '%s',"
	    "\"ResponseNumber\" = '%d',"
	    "\"ResponseText\" = $$%s$$,"
	    "\"AcceptingSessionID\" = default where "
	    "\"RequestID\" = '%s' and "
	    "\"AcceptingSessionID\" = '%s';",
	    cmd->cmd_msg.msg_manufacturer,
	    cmd->cmd_msg.msg_model,
	    cmd->cmd_msg.msg_messageid,
	    cmd->cmd_msg.msg_localized,
	    reqid, mm_wka->session_uuid) != MM_DB_OK) {
		mm_clear_db(&db->mm_db_results);
		mm_response_error(cmd,
		    ECLASS_SUBOP,
		    EREQSTATECHANGEFAILED,
		    MM_5089_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* resize request history */
	if (mm_request_history_limit(db)) {
		mm_response_error(cmd,
		    ECLASS_SUBOP,
		    EREQSTATECHANGEFAILED,
		    MM_5089_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* find device manager command that generated request */
	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&data->mm_cmd_queue, cmd_p) {
		if (strcmp(cmd_p->cmd_reqid, reqid) == 0) {
			break;
		}
	}
	if (cmd_p) {
		/* send device manager, mm or app request response */
		buf = mms_strnew("response task[\"%s\"] success "
		    "text[\"%d\" \"reply\" \"%s\"];",
		    cmd_p->cmd_task, messageid,
		    cmd->cmd_msg.msg_localized);
		SQL_CHK_LEN(&cmd_p->cmd_buf, 0, &cmd_p->cmd_bufsize,
		    strlen(buf) + 1);
		strcpy(cmd_p->cmd_buf, buf);
		free(buf);
		cmd_p->cmd_remove = 1;
		if (mm_has_depend(cmd_p)) {
			mm_command_t *cur_depend = NULL;
			mms_trace(MMS_DEVP, "internal mm request");
			mms_list_foreach(&cmd_p->cmd_depend_list, cur_depend) {
				cur_depend->cmd_response =
				    mm_text_to_par_node(cmd_p->cmd_buf,
				    mms_mmp_parse);
				cur_depend->cmd_flags |= MM_CMD_DISPATCHABLE;
			}
			mms_list_remove(&data->mm_cmd_queue, cmd_p);
			mms_list_insert_head(&data->mm_cmd_queue, cmd_p);
		} else {
			mms_trace(MMS_DEVP, "device manager request");
			mm_send_text(cmd_p->wka_ptr->mm_wka_conn,
			    cmd_p->cmd_buf);
		}
	}
	pthread_mutex_unlock(&data->mm_queue_mutex);
	if (cmd_p == NULL) {
		mm_response_error(cmd,
		    ECLASS_EXIST, ENOSUCHREQ,
		    MM_5093_MSG,
		    NULL);
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

/* Change request history size and do repairs if required. */
int
mm_request_history_limit(mm_db_t *db)
{
	int limit;
	int count;
	int actual_count;

	mms_trace(MMS_DEVP, "mm_request_history_limit");

	if (mm_db_exec(HERE, db, "select \"SystemRequestLimit\","
	    "\"SystemRequestCount\" from \"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	limit = atoi(PQgetvalue(db->mm_db_results, 0, 0));
	count = atoi(PQgetvalue(db->mm_db_results, 0, 1));
	mm_clear_db(&db->mm_db_results);

	if (mm_db_exec(HERE, db, "select \"RequestID\" "
	    "from \"REQUEST\" "
	    "where \"RequestState\" = 'responded';") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	actual_count = PQntuples(db->mm_db_results);
	mm_clear_db(&db->mm_db_results);

	if (count != actual_count) {
		count = actual_count;
	}

	/* limit could be zero which means the request history is off */
	while (count > limit) {
		/* delete oldest responded to request from request history */
		if (mm_db_exec(HERE, db, "delete from \"REQUEST\" "
		    "where \"RequestID\" = (select \"RequestID\" "
		    "from \"REQUEST\" where \"RequestState\" = 'responded' "
		    "order by \"RequestTimeResponded\" "
		    "limit 1);") != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
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
	    "\"SystemRequestCount\" = '%d';", count) != MM_DB_OK) {
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	return (0);
}

int
mm_release_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;
	int		rc;
	int		error;
	int		i;
	char		*state;
	char		*session;
	char		*buf;
	char		*more;

	mms_trace(MMS_DEVP, "mm_release_cmd_func");

	/*
	 * Release requests accepted by this operator
	 */

	if (rc = mm_get_requests(mm_wka, cmd)) {
		return (rc);
	}

	/* check for this session's accepted requests */
	error = 0;
	for (i = 0; i < PQntuples(db->mm_db_results); i++) {
		PQgetvalue(db->mm_db_results, i, 0);
		state = PQgetvalue(db->mm_db_results, i, 1);
		session = PQgetvalue(db->mm_db_results, i, 2);
		if (strcmp(state, "accepted") == 0) {
			/*
			 * A system privileged client can release any
			 * request accepted by any client.
			 */
			if (mm_privileged(mm_wka, cmd) != MM_PRIV_SYSTEM) {
				/*
				 * An admin privileged client can only
				 * release their accepeted requests.
				 */
				if (strcmp(cmd->wka_ptr->session_uuid,
				    session) != 0) {
					mm_set_cmd_err_buf(cmd,
					    ECLASS_INVALID,
					    EREQACCEPTEDBYDIFFSESS);
					error = 1;
				}
			}
		} else {
			mm_set_cmd_err_buf(cmd,
			    ECLASS_INVALID,
			    EREQUESTNOTACCEPTED);
			error = 1;
		}
		if (error) {
			mm_clear_db(&db->mm_db_results);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	}

	/* set request state to pending */
	buf = mms_strnew("update \"REQUEST\" set "
	    "\"AcceptingClient\" = default,"
	    "\"AcceptingInstance\" = default,"
	    "\"AcceptingSessionID\" = default,"
	    "\"RequestState\" = 'pending',"
	    "\"RequestTimeAccepted\" = default where ");
	more = "or ";
	for (i = 0; i < PQntuples(db->mm_db_results); i++) {
		mms_trace(MMS_DEVP, "selected request id -> %s",
		    PQgetvalue(db->mm_db_results, i, 0));
		if (i + 1 >= PQntuples(db->mm_db_results)) {
			more = ";";
		}
		buf = mms_strapp(buf, "(\"RequestID\" = '%s') %s",
		    PQgetvalue(db->mm_db_results, i, 0), more);
	}
	mm_clear_db(&db->mm_db_results);
	rc = mm_db_exec(HERE, db, buf);
	free(buf);
	mm_clear_db(&db->mm_db_results);
	if (rc != MM_DB_OK) {
		mm_response_error(cmd,
		    ECLASS_SUBOP,
		    EREQSTATECHANGEFAILED,
		    MM_5089_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* get report */
	mm_path_match_report(cmd, db);
	mm_send_response(mm_wka->mm_wka_conn, cmd);
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
mm_cancel_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_data_t	*data = mm_wka->mm_data;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*cmd_p;
	mm_command_t	*cmd_q;
	char		*cmd_name = NULL;
	char		*reqid;
	char		*req_cid;
	char		*reqstate;
	PGresult	*results;
	char		*query;
	char		*constraint;

	mms_trace(MMS_DEVP, "mm_cancel_cmd_func");

	(void) mm_get_dest(mm_wka, cmd);
	(void) mm_get_const(mm_wka, cmd);
	if (mm_add_char("REQUEST", &cmd->cmd_source_list)) {
		mms_trace(MMS_ERR,
		    "mm_cancel_cmd_func: "
		    "out of mem creating source list");
		mm_system_error(cmd,
		    "out of mem creating source list");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	cmd->cmd_source_num = 1;
	query = "select distinct \"REQUEST\".\"RequestID\","
	    "\"REQUEST\".\"RequestingConnectionID\","
	    "\"REQUEST\".\"RequestState\" from ";
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(query) + 1);
	strcpy(cmd->cmd_buf, query);
	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_cancel_cmd_func: "
		    "db error creating helper functions");
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn,
		    cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	constraint = "and (\"REQUEST\".\"RequestingClientType\" = 'AI')";
	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(constraint) + 1);
	strcat(cmd->cmd_buf, constraint);
	mm_sql_order(cmd);
	mm_sql_number(cmd);
	if (mm_db_exec(HERE, db, cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		mm_set_cmd_err_buf(cmd, ECLASS_EXPLICIT, ENOMATCH);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	} else if (PQntuples(db->mm_db_results) > 1) {
		mm_set_cmd_err_buf(cmd, ECLASS_EXPLICIT, ETOOMANY);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	reqid = PQgetvalue(db->mm_db_results, 0, 0);
	req_cid = PQgetvalue(db->mm_db_results, 0, 1);
	reqstate = PQgetvalue(db->mm_db_results, 0, 2);
	results = db->mm_db_results;

	if (strcmp(reqstate, "responded") == 0) {
		mm_clear_db(&results);
		mm_set_cmd_err_buf(cmd, ECLASS_EXIST, ENOCANCELLABLETASKS);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	} else if (strcmp(req_cid, mm_wka->wka_conn.cci_uuid) != 0) {
		if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
			mm_clear_db(&results);
			return (MM_CMD_ERROR);
		}
	}

	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&data->mm_cmd_queue, cmd_p) {
		if (strcmp(reqid, cmd_p->cmd_reqid) == 0) {

			/* is this a command we know how to cancel */
			if (strcmp(mms_pn_token(cmd_p->cmd_root),
			    "request") == 0) {
				cmd_name = strdup("request");
			}
			break;
		}
	}
	pthread_mutex_unlock(&data->mm_queue_mutex);

	/* command not found */
	if (cmd_p == NULL) {
		mm_clear_db(&results);
		mm_set_cmd_err_buf(cmd, ECLASS_EXIST, ENOCANCELLABLETASKS);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	/* cancel command */
	if (strcmp(cmd_name, "request") == 0) {
		free(cmd_name);
		if (mm_cancel_request(db, reqid)) {
			mm_clear_db(&results);
			mm_set_cmd_err_buf(cmd, ECLASS_INTERNAL, EDATABASE);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else {
		free(cmd_name);
		mm_clear_db(&results);
		mm_set_cmd_err_buf(cmd, ECLASS_EXIST, ENOCANCELLABLETASKS);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
	mm_clear_db(&results);

	/* send cancelled command's final-command response */
	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&data->mm_cmd_queue, cmd_q) {
		if (cmd_q == cmd_p) {
			/* send cancelled command response */
			SQL_CHK_LEN(&cmd_p->cmd_buf, 0, &cmd_p->cmd_bufsize,
			    strlen(RESPONSE_CANCELLED) +
			    strlen(cmd_p->cmd_task) + 1);
			(void) snprintf(cmd_p->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_CANCELLED, cmd_p->cmd_task);
			mm_send_text(cmd_p->wka_ptr->mm_wka_conn,
			    cmd_p->cmd_buf);
			cmd_p->cmd_remove = 1;
			break;
		}
	}
	pthread_mutex_unlock(&data->mm_queue_mutex);

	/* same command not found or error sending cancelled response */
	if (cmd_q == NULL) {
		mm_system_error(cmd,
		    "same command not found or "
		    "error sending cancelled response");
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
mm_identity_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	const char	*response;

	mms_trace(MMS_DEVP, "mm_identity_cmd_func");

	response = "response task[\"%s\"] success "
	    "text [\"ConnectionID\" \"%s\" "
	    "\"SessionID\" \"%s\"];";

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(response) + strlen(cmd->cmd_task) +
	    strlen(mm_wka->wka_conn.cci_uuid) +
	    strlen(mm_wka->session_uuid) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize, response,
	    cmd->cmd_task, mm_wka->wka_conn.cci_uuid, mm_wka->session_uuid);

	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	cmd->cmd_remove = 1;
	return (MM_CMD_DONE);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}

int
mm_direct_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*clause;
	mms_par_node_t	*value;
	mms_par_node_t	*tw;
	char		*to;
	char		*event = NULL;
	mm_data_t	*data = mm_wka->mm_data;
	mm_wka_t	*wka;

	mms_trace(MMS_DEVP, "mm_direct_cmd_func");

	MMS_PN_LOOKUP(clause, cmd->cmd_root, "to", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, NULL);
	to = mms_pn_token(value);

	tw = NULL;
	MMS_PN_LOOKUP(clause, cmd->cmd_root, "data", MMS_PN_CLAUSE, NULL);
	event = mms_strnew("event direct['%s' ", mm_wka->wka_conn.cci_uuid);
	while ((value = mms_pn_lookup(clause, NULL,
	    MMS_PN_STRING, &tw)) != NULL) {
		event = mms_strapp(event, "'%s' ", mms_pn_token(value));
	}
	event = mms_strapp(event, "];");

	mms_list_foreach(&data->mm_wka_list, wka) {
		if (strcmp(wka->wka_conn.cci_uuid, to) == 0) {
			/* to wka found */
			break;
		}
	}
	if (wka == NULL) {
		free(event);
		mm_response_error(cmd,
		    ECLASS_EXIST,
		    ENOTCONNECTED,
		    MM_5100_MSG,
		    NULL);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

	mms_trace(MMS_DEVP, "direct command\n"
	    "     from %s - %s %s\n"
	    "       to %s - %s %s",
	    mm_wka->wka_conn.cci_uuid,
	    mm_wka->wka_conn.cci_client,
	    mm_wka->wka_conn.cci_instance,
	    wka->wka_conn.cci_uuid,
	    wka->wka_conn.cci_client,
	    wka->wka_conn.cci_instance);

	mm_send_text(wka->mm_wka_conn, event);
	free(event);


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
mm_setpassword_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*clause;
	mms_par_node_t	*value;
	char		*password = NULL;
	char		*oldpassword = NULL;
	char		*clientname = NULL;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	PGresult	*results;
	char		*pass;
	int		error;

	mms_trace(MMS_DEVP, "mm_setpassword_cmd_func");

	MMS_PN_LOOKUP(clause, cmd->cmd_root, "password",
	    MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, NULL);
	password = mms_pn_token(value);

	if (clause = mms_pn_lookup(cmd->cmd_root, "oldpassword",
	    MMS_PN_CLAUSE, NULL)) {

		mms_trace(MMS_DEBUG, "client changing own password");

		MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, NULL);
		oldpassword = mms_pn_token(value);

		clientname = mm_wka->wka_conn.cci_client;

		if (mm_db_exec_si(HERE, db,
		    "select \"Password\" from \"MMPASSWORD\" where "
		    "\"ApplicationName\" = '%s';",
		    clientname) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INTERNAL) +
			    strlen(EDATABASE) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_INTERNAL, EDATABASE);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		results = db->mm_db_results;
		if (mm_db_exec_si(HERE, db,
		    "select mm_func_getpassword('%s');",
		    oldpassword) != MM_DB_DATA) {
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&results);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&results);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_ERROR) +
			    strlen(cmd->cmd_task) +
			    strlen(ECLASS_INTERNAL) +
			    strlen(EDATABASE) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR, cmd->cmd_task,
			    ECLASS_INTERNAL, EDATABASE);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		/* compare password hashes */
		if (strcmp(PQgetvalue(results, 0, 0),
		    PQgetvalue(db->mm_db_results, 0, 0)) != 0) {
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&results);
			mm_response_error(cmd,
			    ECLASS_INVALID,
			    ENOMATCH,
			    MM_5106_MSG,
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);
		mm_clear_db(&results);

	} else if (clause = mms_pn_lookup(cmd->cmd_root, "name",
	    MMS_PN_CLAUSE, NULL)) {

		mms_trace(MMS_DEBUG, "admin changing client password");

		MMS_PN_LOOKUP(value, clause, NULL, MMS_PN_STRING, NULL);
		clientname = mms_pn_token(value);

		mms_trace(MMS_DEBUG, "client %s", clientname);

		if (mm_privileged(mm_wka, cmd) == MM_PRIV_STANDARD) {
			return (MM_CMD_ERROR);
		}
	} else {
		goto not_found;
	}

	if (mm_db_exec_si(HERE, db,
	    "update \"MMPASSWORD\" set \"Password\" = '%s' "
	    "where \"ApplicationName\" = '%s';",
	    password, clientname) != MM_DB_OK) {
		mm_sql_db_err_rsp_new(cmd, db);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	if (db->mm_db_count != 1) {
		mm_clear_db(&db->mm_db_results);
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) +
		    strlen(cmd->cmd_task) +
		    strlen(ECLASS_INTERNAL) +
		    strlen(EDATABASE) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INTERNAL, EDATABASE);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (MM_CMD_ERROR);
	}
	mm_clear_db(&db->mm_db_results);

	if (strcmp(clientname, MM_APP) == 0) {
		mms_trace(MMS_DEBUG, "update file %s", MMS_NET_CFG_HELLO_FILE);

		error = 0;
		pass = mms_net_cfg_read_pass_file(MMS_NET_CFG_HELLO_FILE);
		if (pass == NULL) {
			mms_trace(MMS_ERR, "read failed");
			error = 1;
		} else if (strcmp(pass, password) != 0) {
			if (mms_net_cfg_write_pass_file(MMS_NET_CFG_HELLO_FILE,
			    password)) {
				mms_trace(MMS_ERR, "write failed");
				error = 1;
			} else {
				mms_trace(MMS_DEBUG, "refresh watcher");
				(void) smf_refresh_instance(MMS_CFG_WCR_INST);
			}
		}
		if (pass)
			free(pass);
		if (error) {
			mm_response_error(cmd,
			    ECLASS_INTERNAL,
			    MM_E_INTERNAL,
			    MM_5107_MSG,
			    "file", MMS_NET_CFG_HELLO_FILE,
			    NULL);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (MM_CMD_ERROR);
		}
	}

	mms_trace(MMS_DEBUG, "updated password");

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
