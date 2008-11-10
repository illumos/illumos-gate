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

static char *_SrcFile = __FILE__;

#define	INS_DMCAPABILITYGROUP "INSERT INTO \"DMCAPABILITYGROUP\" "\
	"(\"DriveName\", \"DMName\", "\
	"\"DMCapabilityGroupName\", \"DMCapabilityGroupDefaultName\", "\
	"\"DMCapabilityGroupType\") "\
	"VALUES ('%s', '%s', '%s', '%s' , '%s');"


#define	INS_DMCAPABILITYGROUPTOKEN "INSERT INTO \"DMCAPABILITYGROUPTOKEN\" "\
	"(\"DriveName\", \"DMName\", "\
	"\"DMCapabilityGroupName\", \"DMCapabilityToken\") "\
	"VALUES ('%s', '%s', '%s', '%s'); "

#define	INS_DMCAPABILITY "INSERT INTO \"DMCAPABILITY\" (\"DriveName\", "\
	"\"DMName\", "\
	"\"DMCapabilityName\") "\
	"VALUES ('%s', '%s', '%s'); "

#define	INS_DMCAPABILITYTOKEN "INSERT INTO \"DMCAPABILITYTOKEN\" "\
	"(\"DriveName\", "\
	"\"DMName\", \"DMCapabilityName\", \"DMCapabilityToken\") "\
	"VALUES ('%s', '%s', '%s', '%s'); "

#define	INS_DMBITFORMAT "INSERT INTO \"DMBITFORMAT\" "\
	"(\"DriveName\", \"DMName\", \"DMBitFormatName\", "\
	"\"DMBitFormatDefaultToken\") "\
	"VALUES('%s', '%s', '%s', '%s');"

#define	INS_DMBITFORMATTOKEN "INSERT INTO \"DMBITFORMATTOKEN\" "\
	"(\"DriveName\", "\
	"\"DMName\", \"DMBitFormatName\", "\
	"\"DMCapabilityToken\") "\
	"VALUES('%s', '%s', '%s', '%s');"

#define	INS_BITFORMATDEFAULTTOKEN "UPDATE \"DMBITFORMAT\" SET "\
	"\"DMBitFormatDefaultToken\" = '%s' WHERE "\
	"( \"DriveName\" = '%s' AND \"DMName\" = '%s' AND "\
	"\"DMBitFormatName\" = '%s');"

#define	INS_ATTR "UPDATE \"DMCAPABILITY\" SET \"%s\" = '%s' WHERE "\
	"( \"DriveName\" = '%s' AND \"DMName\" = '%s' AND "\
	"\"DMCapabilityName\" = '%s');"

#define	DEL_DMCAPABILITYGROUPTOKEN "DELETE FROM \"DMCAPABILITYGROUPTOKEN\" "\
	"WHERE ((\"DMCAPABILITYGROUPTOKEN\".\"DriveName\" = '%s') AND "\
	"(\"DMCAPABILITYGROUPTOKEN\".\"DMName\" = '%s'));"

#define	DEL_DMCAPABILITYGROUP "DELETE FROM \"DMCAPABILITYGROUP\" "\
	"WHERE ((\"DMCAPABILITYGROUP\".\"DriveName\" = '%s') AND "\
	"(\"DMCAPABILITYGROUP\".\"DMName\" = '%s'));"

#define	DEL_DMCAPABILITYTOKEN "DELETE FROM \"DMCAPABILITYTOKEN\" "\
	"WHERE ((\"DMCAPABILITYTOKEN\".\"DriveName\" = '%s') "\
	"AND (\"DMCAPABILITYTOKEN\".\"DMName\" = '%s'));"

#define	DEL_DMCAPABILITY "DELETE FROM \"DMCAPABILITY\" WHERE "\
	"((\"DMCAPABILITY\".\"DriveName\" = '%s') AND "\
	"(\"DMCAPABILITY\".\"DMName\" = '%s'));"

#define	DEL_DMBITFORMATTOKEN "DELETE FROM \"DMBITFORMATTOKEN\" WHERE "\
	"((\"DMBITFORMATTOKEN\".\"DriveName\" = '%s') AND "\
	"(\"DMBITFORMATTOKEN\".\"DMName\" = '%s'));"

#define	DEL_DMBITFORMAT "DELETE FROM \"DMBITFORMAT\" WHERE "\
	"((\"DMBITFORMAT\".\"DriveName\" = '%s') AND "\
	"(\"DMBITFORMAT\".\"DMName\" = '%s'));"


int
mm_dmp_clear_at_enable(mm_wka_t *mm_wka) {
	/* Check if DM has a STALEHANDLE */
	/* Clear drive if the session for */
	/* stale handle is no longer connected */
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*DriveName = conn->cci_client;
	char		*DMName = conn->cci_instance;

	PGresult	 *cartid;
	char		*CartridgeID = NULL;

	PGresult	 *session;
	char		*AppName = NULL;
	char		*AIName = NULL;

	if (mm_db_exec(HERE, db,
		    "select \"CartridgeID\" from \"STALEHANDLE\" "
		    "where \"DMName\" = '%s' and"
		    "\"DriveName\" = '%s';",
		    DMName, DriveName) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error in mm_dmp_has_stalehandle");
		mm_clear_db(&db->mm_db_results);
		return (0);
	}
	cartid = db->mm_db_results;
	if (PQntuples(cartid) != 0) {
		CartridgeID = PQgetvalue(cartid, 0, 0);
		/* DM has a stale handle */
		mms_trace(MMS_DEBUG,
		    "%s %s, has STALEHANDLE for cart %s",
		    DMName, DriveName, CartridgeID);
		/* Check if mounting session is still connected */
		if (mm_db_exec(HERE, db,
			    "select \"SESSION\".\"ApplicationName\","
			    "\"SESSION\".\"AIName\" "
			    " from \"SESSION\",\"MOUNTPHYSICAL\" "
			    "where \"SESSION\".\"SessionID\" = "
			    "\"MOUNTPHYSICAL\".\"SessionID\" and "
			    "\"MOUNTPHYSICAL\".\"CartridgeID\" = '%s';",
			    CartridgeID) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error in mm_dmp_has_stalehandle");
			mm_clear_db(&db->mm_db_results);
			mm_clear_db(&cartid);
			return (0);
		}
		session = db->mm_db_results;
		if (PQntuples(session) != 0) {
			AppName = PQgetvalue(session, 0, 0);
			AIName = PQgetvalue(session, 0, 1);
			mms_trace(MMS_DEBUG,
			    "%s %s session still active, "
			    "skip clear and reserve DM, %s %s %s",
			    AppName, AIName,
			    DMName, DriveName, CartridgeID);

			/*  Add activate command */
			if (mm_dmp_add_cmd(mm_wka, NULL, DMName,
			    MM_DMP_RESERVE) == NULL) {
				mms_trace(MMS_ERR,
				    "mm_dmp_clear_at_enable: "
				    "error adding dmp reserve");
			}

			mm_clear_db(&session);
			mm_clear_db(&cartid);
			return (0);
		}
		mms_trace(MMS_DEBUG,
		    "no active client session "
		    "found, clear drive, %s %s",
		    DMName, DriveName);
		mm_clear_db(&session);
		mm_clear_db(&cartid);
		return (1);
	}
	mms_trace(MMS_DEBUG,
	    "no STALEHANDLE found, %s %s",
	    DMName, DriveName);
	mm_clear_db(&cartid);
	return (0);


}

int
inc_current(int current[100], int num_cap_groups, int num_group_tokens[100]) {
	int least_sig = num_cap_groups;
	current[least_sig-1] ++;
	if (current[least_sig-1] < num_group_tokens[least_sig-1]) {
		/* Ok */
		return (0);
	}
	if (least_sig == 1) {
		current[least_sig-1] --;
		return (1);
	}
	current[least_sig-1] = 0;
	least_sig --;
	return (inc_current(current, least_sig, num_group_tokens));
}


int
mm_drive_dm_activate_disable(mm_wka_t *mm_wka) {
	int		 rc;
	uuid_text_t	 task;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*cmd;

	char		*dmname = mm_wka->wka_conn.cci_instance;
	char		*drivename = mm_wka->wka_conn.cci_client;
	/*
	 * Determine if activate disable can be sent
	 * return 1 for fail, 0 for success
	 */
	rc = mm_db_exec(HERE, db,
			"select \"DM\".\"DMStateHard\","
			"\"DM\".\"DMStateSoft\","
			"\"DRIVE\".\"DriveBroken\","
			"\"DRIVE\".\"DriveStateSoft\","
			"\"DRIVE\".\"DriveDisabled\", "
			"\"DRIVE\".\"DriveOnline\" "
			"from \"DM\",\"DRIVE\" where "
			"\"DM\".\"DriveName\" = "
			"\"DRIVE\".\"DriveName\" and "
			"\"DM\".\"DMName\" = '%s';",
			dmname);
	if ((rc != MM_DB_DATA) ||
	    (PQntuples(db->mm_db_results) != 1)) {
		mms_trace(MMS_ERR,
		    "db error getting DM/DRIVE info, "
		    "skip DM disable");
		return (1);
	}


	mms_trace(MMS_DEVP,
	    "DM/DRIVE info:");
	mms_trace(MMS_DEVP,
	    "  DMStateHard = %s",
	    PQgetvalue(db->mm_db_results, 0, 0));
	mms_trace(MMS_DEVP,
	    "  DMStateSoft = %s",
	    PQgetvalue(db->mm_db_results, 0, 1));
	mms_trace(MMS_DEVP,
	    "  DriveBroken = %s",
	    PQgetvalue(db->mm_db_results, 0, 2));
	mms_trace(MMS_DEVP,
	    "  DriveStateSoft = %s",
	    PQgetvalue(db->mm_db_results, 0, 3));
	mms_trace(MMS_DEVP,
	    "  DriveDisabled = %s",
	    PQgetvalue(db->mm_db_results, 0, 4));
	mms_trace(MMS_DEVP,
	    "  DriveOnline = %s",
	    PQgetvalue(db->mm_db_results, 0, 5));

	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "DMStateHard != ready, skip disable");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 1),
		    "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "DMStateSoft != ready, skip disable");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 2),
		    "f") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveBroken != f, skip disable");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 3),
		    "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveStateSoft != f, skip disable");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 4),
		    "false") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveDisabled != false, skip disable");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	if (strcmp(PQgetvalue(db->mm_db_results, 0, 5),
		    "f") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveOnline != f, skip disable");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	mm_clear_db(&db->mm_db_results);

	mms_trace(MMS_DEBUG, "Add an activate disable for %s %s",
	    dmname, drivename);


	/* Allocate and add an activate command to the queue */
	/*
	 * Build an activate disable command
	 */
	if ((cmd = mm_alloc_cmd(mm_wka)) == NULL) {
		mms_trace(MMS_ERR,
			"Unable to malloc mm_command_t: %s",
			strerror(errno));
		return (1);
	}
	mm_get_uuid(task);
	cmd->cmd_textcmd = mms_strnew(ACTIVATE_DISABLE, task);
	cmd->cmd_root = mm_text_to_par_node(cmd->cmd_textcmd, mms_dmpm_parse);
	cmd->cmd_task = mm_get_task(cmd->cmd_root);
	cmd->cmd_func = mm_dmp_activate_cmd_func;
	cmd->cmd_name = strdup("dmp activate disable");

	if (cmd->cmd_textcmd == NULL || cmd->cmd_root == NULL) {
		MM_ABORT_NO_MEM();
		return (1);
	}

	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, cmd);
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

	/*
	 * Activate dm is inprogress.
	 */
	return (0);
}

mm_command_t *
mm_alloc_dm_enable(mm_wka_t *mm_wka) {
	uuid_text_t	 task;
	mm_command_t	*cmd;

	/* Allocate and add an activate command to the queue */
	/*
	 * Build an activate enable command
	 */
	if ((cmd = mm_alloc_cmd(mm_wka)) == NULL) {
		mms_trace(MMS_ERR,
			"Unable to malloc mm_command_t: %s",
			strerror(errno));
		return (NULL);
	}
	mm_get_uuid(task);
	cmd->cmd_textcmd = mms_strnew(ACTIVATE_ENABLE, task);
	cmd->cmd_root = mm_text_to_par_node(cmd->cmd_textcmd, mms_dmpm_parse);
	cmd->cmd_task = mm_get_task(cmd->cmd_root);
	cmd->cmd_func = mm_dmp_activate_cmd_func;
	cmd->cmd_name = strdup("dmp activate enable");

	if (cmd->cmd_textcmd == NULL || cmd->cmd_root == NULL) {
		MM_ABORT_NO_MEM();
		return (NULL);
	}

	pthread_mutex_lock(&mm_wka->mm_data->mm_queue_mutex);
	mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, cmd);
	pthread_mutex_unlock(&mm_wka->mm_data->mm_queue_mutex);

	/*
	 * Activate dm is inprogress.
	 */
	return (cmd);
}

mm_command_t *
mm_drive_dm_activate_enable(mm_wka_t *mm_wka) {
	int		 rc;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t	*cmd;

	char		*dmname = mm_wka->wka_conn.cci_instance;
	char		*drivename = mm_wka->wka_conn.cci_client;


	/*
	 * Determine if activate enable can be sent
	 * return NULL for fail, pointer to the enable command for success
	 */
	rc = mm_db_exec(HERE, db,
			"select \"DM\".\"DMStateHard\","
			"\"DM\".\"DMStateSoft\","
			"\"DRIVE\".\"DriveBroken\","
			"\"DRIVE\".\"DriveStateSoft\","
			"\"DRIVE\".\"DriveDisabled\", "
			"\"DRIVE\".\"DriveOnline\" "
			"from \"DM\",\"DRIVE\" where "
			"\"DM\".\"DriveName\" = "
			"\"DRIVE\".\"DriveName\" and "
			"\"DM\".\"DMName\" = '%s';",
			dmname);
	if ((rc != MM_DB_DATA) ||
	    (PQntuples(db->mm_db_results) != 1)) {
		mms_trace(MMS_ERR,
		    "db error getting DM/DRIVE info, "
		    "skip DM enable");
		return (NULL);
	}


	mms_trace(MMS_DEVP,
	    "DM/DRIVE info:");
	mms_trace(MMS_DEVP,
	    "  DMStateHard = %s",
	    PQgetvalue(db->mm_db_results, 0, 0));
	mms_trace(MMS_DEVP,
	    "  DMStateSoft = %s",
	    PQgetvalue(db->mm_db_results, 0, 1));
	mms_trace(MMS_DEVP,
	    "  DriveBroken = %s",
	    PQgetvalue(db->mm_db_results, 0, 2));
	mms_trace(MMS_DEVP,
	    "  DriveStateSoft = %s",
	    PQgetvalue(db->mm_db_results, 0, 3));
	mms_trace(MMS_DEVP,
	    "  DriveDisabled = %s",
	    PQgetvalue(db->mm_db_results, 0, 4));
	mms_trace(MMS_DEVP,
	    "  DriveOnline = %s",
	    PQgetvalue(db->mm_db_results, 0, 5));

	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "DMStateHard != ready, skip enable");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 1),
		    "present") != 0) {
		mms_trace(MMS_DEVP,
		    "DMStateSoft != present, skip enable");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 2),
		    "f") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveBroken != f, skip enable");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 3),
		    "unavailable") == 0) {
		mms_trace(MMS_DEVP,
		    "DriveStateSoft == unavailable, "
		    "wait on DM activate");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}

	if (strcmp(PQgetvalue(db->mm_db_results, 0, 3),
		    "ready") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveStateSoft != ready");
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 4),
		    "false") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveDisabled != false, skip enable");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 5),
		    "t") != 0) {
		mms_trace(MMS_DEVP,
		    "DriveOnline != t, skip enable");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	mm_clear_db(&db->mm_db_results);
	mms_trace(MMS_DEBUG, "Add an activate enable for %s %s",
	    dmname, drivename);

	cmd = mm_alloc_dm_enable(mm_wka);
	if (cmd == NULL) {
		mms_trace(MMS_ERR,
		    "unable to malloc dm enable cmd");
		return (NULL);
	}

	/*
	 * Activate dm is inprogress.
	 */
	return (cmd);
}

/*
 * This function deletes the config for a DM
 * who's wka is mm_wka
 * db should be the calling thread's
 * database pointer
 */

void
delete_dm_config(mm_wka_t *mm_wka, mm_db_t *db) {


	if (mm_db_exec(HERE, db,
		    "delete from "\
		    "\"DMSHAPEPRIORITY\" "	\
		    "where \"DMName\" = '%s'",
		    mm_wka->wka_conn.cci_instance)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error removing "\
		    "DMSHAPEPRIORITY");
	}
	if (mm_db_exec(HERE, db,
		    "delete from "\
		    "\"DMDENSITYPRIORITY\" "	\
		    "where \"DMName\" = '%s'",
		    mm_wka->wka_conn.cci_instance)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error removing "\
		    "DMDENSITYPRIORITY");
	}
	if (mm_db_exec(HERE, db,
		    "delete from "\
		    "\"DMCAPABILITYGROUP\" " \
		    "where \"DMName\" = '%s'",
		    mm_wka->wka_conn.cci_instance)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error removing "\
		    "DMCAPABILITYGROUP");
	}
	if (mm_db_exec(HERE, db,
		    "delete from "\
		    "\"DMCAPABILITY\" "	\
		    "where \"DMName\" = '%s'",
		    mm_wka->wka_conn.cci_instance)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error removing DMCAPABILITY");
	}
	if (mm_db_exec(HERE, db,
		    "delete from "\
		    "\"DMBITFORMAT\" "	\
		    "where \"DMName\" = '%s'",
		    mm_wka->wka_conn.cci_instance)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error removing DMBITFORMAT");
	}
	if (mm_db_exec(HERE, db,
		    "delete from "\
		    "\"DMBITFORMATTOKEN\" "	\
		    "where \"DMName\" = '%s'",
		    mm_wka->wka_conn.cci_instance)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error removing "\
		    "DMBITFORMATTOKEN");
	}
}

int
mm_dmp_config_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	int		 scope_full;
	mms_par_node_t	*work = NULL;
	mms_par_node_t	*item = NULL;
	int		go;
	int		count;
	mms_par_node_t	*cap_list_work;
	mms_par_node_t	*group;
	char		*group_name;
	char		*group_type;
	char		*default_cap_token;
	char		*group_cap_token[512];
	mms_par_node_t	*cap;
	char		*cap_name;
	mms_par_node_t	*cap_list;
	char		*cap_list_cap_token[512];
	mms_par_node_t	*attr;
	char		*attr_name;
	char		*attr_value;
	mms_par_node_t	*bitformat;
	char		*bit_name;
	char		*default_bit_token;
	char		*bit_cap_token[512];

	mms_par_node_t	*shapepriority;
	mms_par_node_t	*densitypriority;

	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*DriveName = conn->cci_client;
	char		*DMName = conn->cci_instance;
	char		*send_buf = NULL;

	int		shape_count = 1;
	int		density_count = 1;

	int i;


	/*
	 *		buf = mms_strapp(buf, DMP_PRIVATE_BLOCKSIZE,
	 *			    mount_info->cmi_blocksize);
	 */


	mms_trace(MMS_DEVP, "dmp sql trans config cmd");

	if (cmd->cmd_state == 100) {
		/* Response for DM debug Config Command */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			/*
			 * Error In Debug Config
			 * return MMS_ERROR response and
			 * delete config from DataBase
			 */
			delete_dm_config(mm_wka, &mm_wka->mm_data->mm_db);

			mms_trace(MMS_ERR, "DEBUG CONFIG "	\
			    "MMS_ERROR");
			/*
			 * cmd->cmd_remove = 1;
			 * mm_sql_db_err_rsp_new(cmd, db);
			 * mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			 */
			goto not_found;
		} else {
			/* Config is MMS_OK */
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_SUCCESS) +
			    strlen(cmd->cmd_task) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_SUCCESS,
			    cmd->cmd_task);
			cmd->cmd_remove = 1;
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);

			mms_trace(MMS_INFO, "DM Connected and Configured");
			return (MM_DISPATCH_AGAIN);
		}

	}

	/* Begin Parsing Config Command */
	MMS_PN_LOOKUP(arg, cmd->cmd_root, "scope", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(value, arg, NULL, MMS_PN_KEYWORD, NULL);
	if (strcmp(value->pn_string, "full") == 0) {
		scope_full = 1;
		mms_trace(MMS_DEVP, "scope: full");
	} else if (strcmp(value->pn_string, "partial") == 0) {
		scope_full = 0;
		mms_trace(MMS_DEVP, "scope: partial");
	} else {
		mm_response_error(cmd,
		    ECLASS_LANGUAGE,
		    ENOTFOUND,
		    MM_5062_MSG,
		    NULL);
		cmd->cmd_remove = 1;
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		goto error;
	}

	/*
	 * If scope is 'full' then remove all existing config entries
	 * in db for the current dm and drive
	 */

	if (scope_full) {

		/* Remove DMBITFORMATTOKEN from db */
		if (mm_db_exec(HERE, db, DEL_DMBITFORMATTOKEN, DriveName,
		    DMName) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error removing "
			    "DMBITFORMATTOKEN");
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}
		/* Remove DMBITFORMAT from db */
		if (mm_db_exec(HERE, db, DEL_DMBITFORMAT, DriveName,
		    DMName) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error removing "
			    "DMBITFORMAT");
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}
		/* Revomve DMCAPABILITYGROUPTOKEN from db */
		if (mm_db_exec(HERE, db, DEL_DMCAPABILITYGROUPTOKEN, DriveName,
		    DMName) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error removing "\
			    "DMCAPABILITYGROUPTOKEN");
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}
		/* Revomve DMCAPABILITYGROUP from db */
		if (mm_db_exec(HERE, db, DEL_DMCAPABILITYGROUP, DriveName,
		    DMName) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error removing "\
			    "DMCAPABILITYGROUP");
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}
		/* Revomve DMCAPABILITYTOKEN from db */
		if (mm_db_exec(HERE, db, DEL_DMCAPABILITYTOKEN, DriveName,
		    DMName) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error removing "\
			    "DMCAPABILITYTOKEN");
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}
		/* Revomve DMCAPABILITY from db */
		if (mm_db_exec(HERE, db, DEL_DMCAPABILITY, DriveName,
		    DMName) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error removing "\
			    "DMCAPABILITY");
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}

	}


	/* Get Group Config */

	/* mms_trace(MMS_DEVP, "group"); */
	work = NULL;
	for (group = mms_pn_lookup(cmd->cmd_root, "group",
	    MMS_PN_CLAUSE, &work);
	    group != NULL;
	    group = mms_pn_lookup(cmd->cmd_root, "group",
	    MMS_PN_CLAUSE, &work)) {
		int i;
		item = NULL;
		MMS_PN_LOOKUP(value, group, NULL, MMS_PN_STRING, &item);
		group_name = value->pn_string;

		MMS_PN_LOOKUP(value, group, NULL, MMS_PN_STRING, &item);
		group_type = value->pn_string;

		MMS_PN_LOOKUP(value, group, NULL, MMS_PN_STRING, &item);
		default_cap_token = value->pn_string;

		/* Insert DMCAPABILITYGROUP into db */
		if (mm_db_exec(HERE, db,
		    INS_DMCAPABILITYGROUP, DriveName,
		    DMName, group_name, default_cap_token,
		    group_type) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "Error adding cap group "
			    "%s %s %s %s %s",
			    DriveName,
			    DMName, group_name,
			    default_cap_token,
			    group_type);
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}


		/* Get the Other Group Cap Tokens */

		count = 0;
		go = 1;
		while (go) {
			if ((value = mms_pn_lookup(group, NULL,
			    MMS_PN_STRING,
			    &item)) == NULL) {
				go = 0;
			} else {
				group_cap_token[count] =
				    value->pn_string;
				count ++;
			}
		}

		/* Insert DMCAPABILITYGROUPTOKEN into db */
		/* Insert the default token */
		if (mm_db_exec(HERE, db,
		    INS_DMCAPABILITYGROUPTOKEN,
		    DriveName,
		    DMName, group_name,
		    default_cap_token) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "Error adding cap group token"
			    "%s %s %s %s",
			    DriveName,
			    DMName, group_name,
			    default_cap_token);
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}



		/* Insert the other tokens */
		for (i = 0; i < count; i++) {
			if (mm_db_exec(HERE, db,
			    INS_DMCAPABILITYGROUPTOKEN,
			    DriveName,
			    DMName, group_name,
			    group_cap_token[i]) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "Error adding cap group token"
				    "%s %s %s %s",
				    DriveName,
				    DMName, group_name,
				    group_cap_token[i]);
				cmd->cmd_remove = 1;
				mm_sql_db_err_rsp_new(cmd, db);
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				goto error;
			}
		}
	}

	/* Capabilities */

	mms_trace(MMS_DEVP, "Parsing cap clauses");
	work = NULL;
	for (cap = mms_pn_lookup(cmd->cmd_root, "cap",
	    MMS_PN_CLAUSE, &work);
	    cap != NULL;
	    cap = mms_pn_lookup(cmd->cmd_root, "cap",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		MMS_PN_LOOKUP(value, cap, NULL, MMS_PN_STRING, &item);
		cap_name = value->pn_string;

		/* Insert DMCAPABILITY into db */
		if (mm_db_exec(HERE, db,
		    INS_DMCAPABILITY, DriveName,
		    DMName, cap_name) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "Error adding cap "
			    "%s %s %s",
			    DriveName,
			    DMName, cap_name);
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}

		mms_trace(MMS_DEVP, "    cap: %s", cap_name);

		/* Get the tokens in the CapList */

		if ((cap_list = mms_pn_lookup(cap, "caplist",
		    MMS_PN_CLAUSE,
		    &item)) == NULL) {
			mms_trace(MMS_ERR, "No caplist found");
		}
		mms_trace(MMS_DEVP, "     caplist");
		value = NULL;
		count = 0;
		go = 1;
		cap_list_work = NULL;
		while (go) {
			if ((value = mms_pn_lookup(cap_list, NULL,
			    MMS_PN_STRING,
			    &cap_list_work)) == NULL) {
				go = 0;
			} else {
				cap_list_cap_token[count] =
				    value->pn_string;
				count ++;
			}
		}
		/* Insert DMCAPABILITYTOKEN into db */
		for (i = 0; i < count; i++) {
			if (mm_db_exec(HERE, db,
			    INS_DMCAPABILITYTOKEN, DriveName,
			    DMName, cap_name,
			    cap_list_cap_token[i]) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "Error adding cap "
				    "%s %s %s %s",
				    DriveName,
				    DMName, cap_name,
				    cap_list_cap_token[i]);
				cmd->cmd_remove = 1;
				mm_sql_db_err_rsp_new(cmd, db);
				mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
				goto error;
			}

		}

		/* Get the attribute name/value pairs */

		cap_list_work = NULL;
		for (attr = mms_pn_lookup(cap, "attr",
		    MMS_PN_CLAUSE, &cap_list_work);
		    attr != NULL;
		    attr = mms_pn_lookup(cap, "attr",
		    MMS_PN_CLAUSE, &cap_list_work)) {
			mms_trace(MMS_DEVP, "      attr");
			item = NULL;
			MMS_PN_LOOKUP(value, attr, NULL,
			    MMS_PN_STRING, &item);
			attr_name = value->pn_string;
			MMS_PN_LOOKUP(value, attr, NULL,
			    MMS_PN_STRING, &item);
			attr_value = value->pn_string;

			if (mm_db_create_attribute2(db, "DMCAPABILITY",
			    attr_name, &send_buf)
			    != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "Error creating new attribute");
				cmd->cmd_remove = 1;
				mm_sql_db_err_rsp_new(cmd, db);
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				goto error;
			}
			send_buf = mms_strapp(send_buf, INS_ATTR, attr_name,
			    attr_value, DriveName, DMName, cap_name);

			mms_trace(MMS_DEVP, "attr_name: %s , attr_value: %s",
			    attr_name, attr_value);

		}


	}


	if (send_buf != NULL) {
		if (mm_db_exec(HERE, db, send_buf) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error adding "	\
			    "config");
			cmd->cmd_remove = 1;
			mm_sql_db_err_rsp_new(cmd, db);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			goto error;
		}
		free(send_buf);
		send_buf = NULL;
	}


	mms_trace(MMS_DEVP, "bitformat");
	work = NULL;
	for (bitformat = mms_pn_lookup(cmd->cmd_root, "bitformat",
	    MMS_PN_CLAUSE, &work);
	    bitformat != NULL;
	    bitformat = mms_pn_lookup(cmd->cmd_root, "bitformat",
	    MMS_PN_CLAUSE, &work)) {
		item = NULL;
		MMS_PN_LOOKUP(value, bitformat, NULL,
		    MMS_PN_STRING, &item);
		bit_name = value->pn_string;

		MMS_PN_LOOKUP(value, bitformat, NULL,
		    MMS_PN_STRING, &item);
		default_bit_token = value->pn_string;

		/* Insert DMBITFORMAT into db */

		send_buf = mms_strapp(send_buf, INS_DMBITFORMAT, DriveName,
		    DMName, bit_name, default_bit_token);

		mms_trace(MMS_DEVP, "Bit name is %s, Default token is %s",
		    bit_name, default_bit_token);
		/* Get the remaining tokens */
		count = 0;
		go = 1;
		while (go) {
			if ((value = mms_pn_lookup(bitformat, NULL,
			    MMS_PN_STRING,
			    &item)) == NULL) {
				go = 0;
			} else {
				bit_cap_token[count] =
				    value->pn_string;
				count ++;
			}
		}
		/* Insert DMBITFORMATTOKEN into db */

		/* Insert the default token */

		send_buf = mms_strapp(send_buf, INS_DMBITFORMATTOKEN,
		    DriveName,
		    DMName, bit_name,
		    default_bit_token);


		/* Insert the rest */
		for (i = 0; i < count; i++) {
			send_buf = mms_strapp(send_buf, INS_DMBITFORMATTOKEN,
			    DriveName,
			    DMName, bit_name,
			    bit_cap_token[i]);
			mms_trace(MMS_DEVP,
			    "BitToken %d: %s", i, bit_cap_token[i]);
		}

	}

	/* Add the send_buf */
	if (mm_db_exec(HERE, db, send_buf) != MM_DB_OK) {
		mms_trace(MMS_ERR, "Error adding "	\
		"config");
		cmd->cmd_remove = 1;
		mm_sql_db_err_rsp_new(cmd, db);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		goto error;
	}

	free(send_buf);


	/* Cartridge Shape and Density Priority */
	/* Shape priority */


	mms_trace(MMS_DEVP, "shapepriority");
	work = NULL;
	if ((shapepriority = mms_pn_lookup(cmd->cmd_root,
	    "shapepriority",
	    MMS_PN_CLAUSE, NULL)) == NULL) {
		mms_trace(MMS_ERR,
		    "DM config is missing the shapepriority clause");
	} else {
		item = NULL;
		while ((item = mms_pn_lookup(shapepriority, NULL,
		    MMS_PN_STRING, &work)) != NULL) {
			if (mm_db_exec(HERE, db,
			    "insert into \"DMSHAPEPRIORITY\" "
			    "(\"DMName\", \"DMShapePriority\", "
			    "\"DMShapeName\") "
			    "values('%s', '%d', '%s');",
			    DMName, shape_count,
			    item->pn_string) != MM_DB_OK) {
				mms_trace(MMS_ERR, "Error adding "
				    "shapepriority");
				cmd->cmd_remove = 1;
				mm_sql_db_err_rsp_new(cmd, db);
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				goto error;
			}
			if (shape_count == 1) {
				/* set DriveShapeName */
				if (mm_db_exec(HERE, db,
				    "update \"DRIVE\" "
				    "set \"DriveShapeName\" = '%s'"
				    " where \"DriveName\" = '%s'",
				    item->pn_string,
				    DriveName) != MM_DB_OK) {
				mms_trace(MMS_ERR, "Error setting"
				    "DriveShapeName");
				cmd->cmd_remove = 1;
				mm_sql_db_err_rsp_new(cmd, db);
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				goto error;
			}
			}
			shape_count ++;
		}
	}
	/* Density priority */

	mms_trace(MMS_DEVP, "densitypriority");
	work = NULL;
	if ((densitypriority = mms_pn_lookup(cmd->cmd_root,
	    "densitypriority",
	    MMS_PN_CLAUSE, NULL)) == NULL) {
		mms_trace(MMS_ERR,
		    "DM config is missing the densitypriority clause");
	} else {
		item = NULL;
		while ((item = mms_pn_lookup(densitypriority, NULL,
		    MMS_PN_STRING, &work)) != NULL) {
			if (mm_db_exec(HERE, db,
			    "insert into \"DMDENSITYPRIORITY\" "
			    "(\"DMName\", \"DMDensityPriority\", "
			    "\"DMDensityName\") "
			    "values('%s', '%d', '%s');",
			    DMName, density_count,
			    item->pn_string) != MM_DB_OK) {
				mms_trace(MMS_ERR, "Error adding "
				    "densitypriority");
				cmd->cmd_remove = 1;
				mm_sql_db_err_rsp_new(cmd, db);
				mm_send_text(mm_wka->mm_wka_conn,
				    cmd->cmd_buf);
				goto error;
			}
			density_count ++;
		}
	}

	/* Done Parsing */

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
	    strlen(RESPONSE_SUCCESS) + strlen(cmd->cmd_task) + 1);
	(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
	    RESPONSE_SUCCESS, cmd->cmd_task);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	mms_trace(MMS_INFO, "DM Connected and Configured -> %s",
	    mm_wka->wka_conn.cci_instance);
	return (MM_DISPATCH_AGAIN);


no_mem:
	MM_ABORT_NO_MEM();
	goto error;

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	cmd->cmd_remove = 1;
	mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	goto error;
error:
	mm_sql_update_state(mm_wka->mm_data, "DM",
	    "DMStateSoft",
	    "not ready", "DMName",
	    DMName);
	return (MM_CMD_ERROR);

}
#define	DMP_SEND_ATTACH "attach task [\"%s\"] "	\
	"modename [\"%s\"];"

int
mm_dmp_attach_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	cci_t		*conn = &mm_wka->wka_conn;
	char		*DMName = conn->cci_instance;
	mms_par_node_t	*work = NULL;
	mms_par_node_t		*arg;
	mms_par_node_t		*value;
	char		*task = cmd->cmd_task;
	char		*buf = NULL;
	int		bufsize = 0;
	mm_response_t	 response;
	mm_command_t	*parent = NULL;
	cmd_mount_info_t *mount_info = NULL;


	mms_trace(MMS_DEVP, "mm_dmp_attach_cmd_func");
	parent = mm_first_parent(cmd);
	mount_info = &parent->cmd_mount_info;
	if (cmd->cmd_state == 0) {
		/* send the attach to DM */
		mms_trace(MMS_DEVP, "DM Name is %s, task id is %s",
		    DMName, task);
		if (mount_info->cmi_capability == NULL) {
			mms_trace(MMS_DEVP, "No capability found...");
			return (MM_CMD_ERROR);
		}

		SQL_CHK_LEN(&buf, 0, &bufsize,
		    strlen(DMP_SEND_ATTACH) +
		    strlen(task) +
		    strlen(mount_info->cmi_capability) + 1);
		(void) snprintf(buf, bufsize,
		    DMP_SEND_ATTACH, task,
		    mount_info->cmi_capability);
		mms_trace(MMS_DEVP, "send buf is '%s' to fd %d ", buf,
		    mm_wka->mm_wka_conn->mms_fd);

		mm_send_text(mm_wka->mm_wka_conn,
		    buf);
		cmd->cmd_state  = 1;
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
		free(buf);
		return (MM_ACCEPT_NEEDED);

	} else if (cmd->cmd_state == 1) {
		/* revieved accept */
		mms_trace(MMS_DEVP, "ATTACH STATE 1");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_ACCEPTED) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}

		mms_trace(MMS_DEVP, "PARSE RESPONSE DONE!!");
		cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
		cmd->cmd_flags |= MM_CMD_ACCEPTED;
		cmd->cmd_state = 2;
		mms_trace(MMS_DEVP, "ATTACH STATE 1 DONE!!");
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 2) {
		/* recieved success */
		mms_trace(MMS_DEVP, "ATTACH STATE 2!");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_SUCCESS) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		/* Get text */
		work = NULL;
		arg = mms_pn_lookup(cmd->cmd_response, "text",
		    MMS_PN_CLAUSE, &work);
		if (arg != NULL) {
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			if (value->pn_string != NULL) {
				mms_trace(MMS_DEVP, "Response text is %s",
				    value->pn_string);
			} else {
				mms_trace(MMS_DEVP, "Response text was NULL");
			}
		} else {
			mms_trace(MMS_DEVP, "Response text clause missing");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		mount_info->cmi_handle = strdup(value->pn_string);
		if (mount_info->cmi_handle == NULL) {
			mms_trace(MMS_ERR, "Error malloc cmi_handle");
			return (MM_CMD_ERROR);
		}
		cmd->cmd_remove = 1;
		return (MM_DEPEND_DONE);

	} else {
		mms_trace(MMS_DEVP, "Bad command state");
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
not_found:
	mms_trace(MMS_ERR, "Not Found!!");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

#define	DMP_SEND_IDENTIFY "identify task [\"%s\"] type [\"none\"];"

int
mm_dmp_identify_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	cci_t		*conn = &mm_wka->wka_conn;
	char		*DMName = conn->cci_instance;
	mms_par_node_t	*work = NULL;
	mms_par_node_t	*value;
	mms_par_node_t	*arg;
	char		*task = cmd->cmd_task;
	char		*buf = NULL;
	int		bufsize = 0;
	mm_response_t	 response;

	mms_trace(MMS_DEVP, "mm_dmp_identify_cmd_func");
	if (cmd->cmd_state == 0) {
		/* send the load to DM */
		mms_trace(MMS_DEVP, "DM Name is %s, task id is %s",
		    DMName, task);

		SQL_CHK_LEN(&buf, 0, &bufsize,
		    strlen(DMP_SEND_IDENTIFY) +
		    strlen(task) + 1);
		(void) snprintf(buf, bufsize,
		    DMP_SEND_IDENTIFY, task);
		mms_trace(MMS_DEVP, "send buf is '%s' to fd %d ", buf,
		    mm_wka->mm_wka_conn->mms_fd);
		mm_send_text(mm_wka->mm_wka_conn,
		    buf);
		cmd->cmd_state  = 1;
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
		free(buf);
		return (MM_ACCEPT_NEEDED);

	} else if (cmd->cmd_state == 1) {
		/* revieved accept */
		mms_trace(MMS_DEVP, "IDENTIFY STATE 1");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_ACCEPTED) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}

		mms_trace(MMS_DEVP, "PARSE RESPONSE DONE!!");
		cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
		cmd->cmd_flags |= MM_CMD_ACCEPTED;
		cmd->cmd_state = 2;
		mms_trace(MMS_DEVP, "IDENTIFY STATE 1 DONE!!");
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 2) {
		/* recieved success */
		mms_trace(MMS_DEVP, "IDENTIFY STATE 2!");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_SUCCESS) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		/* Get text */
		work = NULL;
		arg = mms_pn_lookup(cmd->cmd_response, "text",
		    MMS_PN_CLAUSE, &work);
		if (arg != NULL) {
			MMS_PN_LOOKUP(value, arg, NULL,
			    MMS_PN_STRING, NULL);
			if (value->pn_string != NULL) {
				mms_trace(MMS_DEVP, "Response text is %s",
				    value->pn_string);
			} else {
				mms_trace(MMS_DEVP, "Response text was NULL");
			}
		} else {
			mms_trace(MMS_DEVP, "Response text clause missing");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		cmd->cmd_remove = 1;
		return (MM_DEPEND_DONE);
	} else {
		mms_trace(MMS_DEVP, "Bad command state");
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
not_found:
	mms_trace(MMS_ERR, "Not Found!!");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}


#define	DMP_SEND_ACT "activate task[\"%s\"] enable;"

int
mm_dmp_activate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*DriveName = conn->cci_client;
	char		*DMName = conn->cci_instance;
	char		*task = cmd->cmd_task;
	mm_response_t	 response;



	mms_trace(MMS_DEVP, "dmp activate cmd");

	if (cmd->cmd_state == 0) {
		mms_trace(MMS_DEVP, "DM Name is %s, task id is %s",
		    DMName, task);

		/* set "DMStateSoft" to notready */
		mm_sql_update_state(mm_wka->mm_data, "DM",
		    "DMStateSoft",
		    "not ready", "DMName",
		    DMName);

		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_textcmd);
		cmd->cmd_state  = 1;
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
		return (MM_ACCEPT_NEEDED);
	}
	if (cmd->cmd_state == 1) {
		mms_trace(MMS_DEVP, "ACTIVATE STATE 1");

		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_ACCEPTED) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}

		cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
		cmd->cmd_flags |= MM_CMD_ACCEPTED;
		cmd->cmd_state = 2;
		mms_trace(MMS_DEVP, "End of activate state = 1");
		return (MM_NO_DISPATCH);


	}
	if (cmd->cmd_state == 2) {
		mms_trace(MMS_DEVP, "ACTIVATE STATE 2!");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_SUCCESS) {
			if (mm_errorcode_eq(cmd->cmd_response,
			    "DM_E_ENABLED")) {
				/* DM has aleady been enabled */
				mms_trace(MMS_DEBUG,
				    "%s %s already enabled",
				    DMName, DriveName);
				mm_sql_update_state(mm_wka->mm_data, "DM",
				    "DMStateSoft",
				    "ready", "DMName",
				    DMName);
				/* Add a DMUP event */
				mm_notify_add_dmup(mm_wka, cmd);

				/* Check if this DM has any handles */
				mms_trace(MMS_DEVP,
				    "check if %s has any STALEHANDLE",
				    DMName);

				if (mm_dmp_clear_at_enable(mm_wka)) {
					/* DM has a stale handle */
					/* The client session is */
					/* not connected */
					/* Need to clear the drive */
					mms_trace(MMS_DEBUG,
					    "Adding clear drive for %s %s",
					    DMName, DriveName);
					if (mm_add_clear_drive(DriveName,
					    mm_wka->mm_data,
					    db,
					    NULL,
					    NULL, 1, 0) == NULL) {
						mms_trace(MMS_ERR,
						    "mm_dmp_activate_cmd_func: "
						    "unable to add a "
						    "clear drive cmd");
					}
				}
			} else {
				mms_trace(MMS_ERR,
				    "DM activate command error");
				cmd->cmd_remove = 1;
				return (MM_CMD_ERROR);
			}
		}

		/* Set the correct DMSoftState */
		if ((mms_pn_lookup(cmd->cmd_root, "enable",
		    MMS_PN_KEYWORD, NULL)) != NULL) {
			mms_trace(MMS_DEBUG,
			    "%s %s enabled",
			    DMName, DriveName);
			mm_sql_update_state(mm_wka->mm_data, "DM",
			    "DMStateSoft",
			    "ready", "DMName",
			    DMName);
			/* Add a DMUP event */
			mm_notify_add_dmup(mm_wka, cmd);
			if (mm_dmp_clear_at_enable(mm_wka)) {
				/* DM has a stale handle */
				/* The client session is not connected */
				/* Need to clear the drive */
				mms_trace(MMS_DEBUG,
				    "Adding clear drive for %s %s",
				    DMName, DriveName);
				if (mm_add_clear_drive(DriveName,
				    mm_wka->mm_data,
				    db,
				    NULL,
				    NULL, 1, 0) == NULL) {
					mms_trace(MMS_ERR,
					    "mm_dmp_activate_cmd_func: "
					    "unable to add a clear drive cmd");
				}
			}
		} else if ((mms_pn_lookup(cmd->cmd_root, "disable",
		    MMS_PN_KEYWORD, NULL)) != NULL) {
			mms_trace(MMS_DEBUG,
			    "%s %s disabled",
			    DMName, DriveName);
			mm_sql_update_state(mm_wka->mm_data, "DM",
			    "DMStateSoft",
			    "present", "DMName",
			    DMName);
			delete_dm_config(mm_wka, &mm_wka->mm_data->mm_db);
			/* Add a DMDOWN event */
			mm_notify_add_dmdown(mm_wka, cmd);

		} else if ((mms_pn_lookup(cmd->cmd_root, "reserve",
		    MMS_PN_KEYWORD, NULL)) != NULL) {
			mms_trace(MMS_DEBUG,
			    "%s reserved %s",
			    DMName, DriveName);
			mm_sql_update_state(mm_wka->mm_data, "DM",
			    "DMStateSoft",
			    "reserved", "DMName",
			    DMName);
		} else if ((mms_pn_lookup(cmd->cmd_root, "release",
		    MMS_PN_KEYWORD, NULL)) != NULL) {
			mms_trace(MMS_DEBUG,
			    "%s released %s",
			    DMName, DriveName);
			mm_sql_update_state(mm_wka->mm_data, "DM",
			    "DMStateSoft",
			    "ready", "DMName",
			    DMName);
			if (mm_db_exec(HERE, db,
			    "update \"DRIVE\" set "
			    "\"DMName\" = DEFAULT "
			    "where \"DMName\" = '%s';",
			    DMName) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "Error udating DRIVE.DMName");
			}
		} else {
			mms_trace(MMS_ERR,
			    "Unknown type - %s",
			    cmd->cmd_textcmd);
			return (MM_CMD_ERROR);
		}


		cmd->cmd_remove = 1;
		if (mm_has_depend(cmd)) {
			return (MM_DEPEND_DONE);
		}
		return (MM_CMD_DONE);
	}
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}


#define	DMP_PRIVATE "private task['%s'] "		\
	"set['cap'		     '%s' "		\
	"'filename'                  '%s' "		\
	"'volumeid'                  '%s' "		\
	"'CartridgePCL'		     '%s' "		\
	"'VolumeName'		     '%s' "

#define	DMP_PRIVATE_PRIVILEGE "'privileged' '%s' "
#define	DMP_PRIVATE_BLOCKSIZE "'blocksize' '%s' "
#define	DMP_PRIVATE_FSEQ "'filesequence' '%s'"
#define	DMP_PRIVATE_USER "'user' '%s'"
#define	DMP_PRIVATE_RETENTION "'retention' '%s'"
#define	DMP_RESERVE_DRIVE "select \"ReserveDrive\" "\
	"from \"DRIVE\" where \"DriveName\" = '%s';"
#define	DMP_DEFAULT_FILENAME "select \"VolumeName\" "\
	"from \"VOLUME\" where "\
	"\"CartridgeID\" = '%s';"
#define	DMP_DEFAULT_VOLID "select \"CartridgePCL\" "\
	"from \"CARTRIDGE\" where "				\
	"\"CartridgeID\" = '%s';"

int
mm_dmp_private_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*DriveName = conn->cci_client;
	char		*DMName = conn->cci_instance;
	char		*task = cmd->cmd_task;
	char		*buf = NULL;
	int		bufsize = 0;
	mm_response_t	 response;
	mm_command_t	*parent = NULL;
	mm_wka_t	*parent_wka = NULL;
	cmi_mode_list_t		*mode;
	cmd_mount_info_t	*mount_info = NULL;
	char			*cap_tokens = NULL;
	int			rc;
	PGresult	 *reserve_drive;
	PGresult	 *default_filename;
	PGresult	 *default_volumeid;
	int		a_mode = 0;
	char		*VolumeName = NULL;

	/* Send a DM mount information */
	mms_trace(MMS_DEVP, "mm_dmp_private_cmd_func");

	parent = mm_first_parent(cmd);
	parent_wka = parent->wka_ptr;
	mount_info = &parent->cmd_mount_info;

	mms_trace(MMS_DEVP, "DM PRIVATE CMD FUNC STATE IS %d", cmd->cmd_state);
	if (MM_IS_SET(cmd->cmd_flags, MM_CMD_NEED_ACCEPT)) {
		mms_trace(MMS_DEVP, "MM_CMD_NEED_ACCEPT is set!");
	} else {
		mms_trace(MMS_DEVP, "MM_CMD_NEED_ACCEPT not set!");
	}

	if (cmd->cmd_state == 0) {
		mms_trace(MMS_DEVP, "DM Name is %s, task id is %s",
		    DMName, task);
		mms_list_foreach(&mount_info->cmi_mode_list, mode) {
			a_mode = 1;
			cap_tokens = (char *)mm_check_mode(parent_wka,
			    parent, DriveName,
			    mode,
			    mount_info->cmi_cartridge, db);
			if (cap_tokens != NULL) {
				/* mode is ok */
				break;
			}
		}
		if (!a_mode) {
			cap_tokens = (char *)mm_check_mode(parent_wka,
			    parent, DriveName,
			    NULL,
			    mount_info->cmi_cartridge, db);
		}

		if (cap_tokens == NULL) {
			mms_trace(MMS_ERR,
			    "couldn't create capability token string,"
			    " verify DM connected/configured");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		mms_trace(MMS_DEVP, "cap tokens are %s",
		    cap_tokens);

		/* quert DRIVE for reserve drive */
		rc = mm_db_exec(HERE, db, DMP_RESERVE_DRIVE,
		    DriveName);
		if (rc != MM_DB_DATA) {
			mms_trace(MMS_DEVP, "Exec returned with no Data");
			cmd->cmd_remove = 1;
			free(cap_tokens);
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		reserve_drive = db->mm_db_results;

		/*
		 * file name not specified use default
		 * 1st 17 chars of VolumeName
		 */
		rc = mm_db_exec(HERE, db, DMP_DEFAULT_FILENAME,
		    mount_info->cmi_cartridge);
		if (rc != MM_DB_DATA) {
			mms_trace(MMS_DEVP, "Exec returned with no Data");
			cmd->cmd_remove = 1;
			mm_clear_db(&reserve_drive);
			mm_clear_db(&db->mm_db_results);
			free(cap_tokens);
			return (MM_CMD_ERROR);
		}
		default_filename = db->mm_db_results;
		VolumeName =
		    strdup(PQgetvalue(default_filename, 0, 0));

		if (mount_info->cmi_filename == NULL) {
			mount_info->cmi_filename =
			    strdup(PQgetvalue(default_filename, 0, 0));
		}


		rc = mm_db_exec(HERE, db, DMP_DEFAULT_VOLID,
		    mount_info->cmi_cartridge);
		if (rc != MM_DB_DATA) {
			mms_trace(MMS_DEVP, "Exec returned with no Data");
			cmd->cmd_remove = 1;
			mm_clear_db(&reserve_drive);
			mm_clear_db(&default_filename);
			mm_clear_db(&db->mm_db_results);
			free(cap_tokens);
			free(VolumeName);
			return (MM_CMD_ERROR);
		}
		default_volumeid = db->mm_db_results;
		if (mount_info->cmi_volumeid == NULL) {
			/*
			 * volumeid not specifed use default
			 * CartridgePCL
			 */
			mount_info->cmi_volumeid =
			    strdup(PQgetvalue(default_volumeid, 0, 0));
		}

		/* ***************************** */
		SQL_CHK_LEN(&buf, 0, &bufsize,
		    strlen(DMP_PRIVATE) +
		    strlen(task) +
		    strlen(cap_tokens) +
		    strlen(mount_info->cmi_filename) +
		    strlen(mount_info->cmi_volumeid) +
		    strlen(PQgetvalue(default_volumeid,
		    0, 0)) +
		    strlen(VolumeName) + 1);
		(void) snprintf(buf, bufsize,
		    DMP_PRIVATE,
		    task,
		    cap_tokens,
		    mount_info->cmi_filename,
		    mount_info->cmi_volumeid,
		    PQgetvalue(default_volumeid,
		    0, 0),
		    VolumeName);

		free(VolumeName);

		if (mount_info->cmi_blocksize != NULL) {
			/* if we were passed a blocksize, include it */
			buf = mms_strapp(buf, DMP_PRIVATE_BLOCKSIZE,
			    mount_info->cmi_blocksize);
		}

		if (mount_info->cmi_retention != NULL) {
			/* if we were passed a retention, include it */
			buf = mms_strapp(buf, DMP_PRIVATE_RETENTION,
			    mount_info->cmi_retention);
		}
		/* Add the new privleged name/value pair */
		if (parent_wka->wka_privilege == MM_PRIV_STANDARD) {
			buf = mms_strapp(buf, DMP_PRIVATE_PRIVILEGE,
			    "false");
		} else {
			buf = mms_strapp(buf, DMP_PRIVATE_PRIVILEGE,
			    "true");
		}
		/* Always include the default blocksize */
		/* find default blocksize for this drive */
		rc = mm_db_exec(HERE, db,
		    "select \"DefaultBlocksize\" "
		    "from \"DRIVE\" where "
		    "\"DriveName\" = '%s';",
		    DriveName);
		if (rc != MM_DB_DATA) {
			mms_trace(MMS_DEVP, "Exec returned with no Data");
			cmd->cmd_remove = 1;
			mm_clear_db(&reserve_drive);
			mm_clear_db(&default_filename);
			mm_clear_db(&default_volumeid);
			mm_clear_db(&db->mm_db_results);
			free(cap_tokens);
			return (MM_CMD_ERROR);
		}

		if (mount_info->cmi_filesequence != NULL) {
			buf = mms_strapp(buf, DMP_PRIVATE_FSEQ,
			    mount_info->cmi_filesequence);
		}
		if (mount_info->cmi_user != NULL) {
			buf = mms_strapp(buf, DMP_PRIVATE_USER,
			    mount_info->cmi_user);
		}
		buf = mms_strapp(buf, " ];");
			/*
			 * mms_trace(MMS_DEVP, "send buf is '%s' to
			 * fd %d ", buf,  mm_wka->mm_wka_conn->mms_fd);
			 */
		mm_send_text(mm_wka->mm_wka_conn,
		    buf);
		/* ***************************** */
		cmd->cmd_state  = 1;
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
		free(buf);
		free(cap_tokens);
		mm_clear_db(&reserve_drive);
		mm_clear_db(&default_filename);
		mm_clear_db(&default_volumeid);
		mm_clear_db(&db->mm_db_results);
		return (MM_ACCEPT_NEEDED);
	}
	if (cmd->cmd_state == 1) {
		mms_trace(MMS_DEVP, "PRIVATE STATE 1");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_ACCEPTED) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}

		mms_trace(MMS_DEVP, "PARSE RESPONSE DONE!!");
		cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
		cmd->cmd_flags |= MM_CMD_ACCEPTED;
		cmd->cmd_state = 2;
		mms_trace(MMS_DEVP, "PRIVATE STATE 1 DONE!!");
		return (MM_DISPATCH_DEPEND);


	}
	if (cmd->cmd_state == 2) {
		mms_trace(MMS_DEVP, "PRIVATE STATE 2!");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_SUCCESS) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		cmd->cmd_remove = 1;
		return (MM_DEPEND_DONE);
	}
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}

#define	DMP_SEND_LOAD "load task[\"%s\"];"

int
mm_dmp_load_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	cci_t		*conn = &mm_wka->wka_conn;
	char		*DMName = conn->cci_instance;
	char		*task = cmd->cmd_task;
	char		*buf = NULL;
	int		bufsize = 0;
	mm_response_t	 response;
	mm_command_t	*parent = NULL;
	cmd_mount_info_t	*mount_info = NULL;

	mms_trace(MMS_DEVP, "mm_dmp_load_cmd_func");
	parent = mm_first_parent(cmd);
	mount_info = &parent->cmd_mount_info;
	if (cmd->cmd_state == 0) {
		/* send the load to DM */
		mms_trace(MMS_DEVP, "DM Name is %s, task id is %s",
		    DMName, task);

		SQL_CHK_LEN(&buf, 0, &bufsize,
		    strlen(DMP_SEND_LOAD) +
		    strlen(task) + 1);
		(void) snprintf(buf, bufsize,
		    DMP_SEND_LOAD, task);
		mms_trace(MMS_DEVP, "send buf is '%s' to fd %d ", buf,
		    mm_wka->mm_wka_conn->mms_fd);
		mm_send_text(mm_wka->mm_wka_conn,
		    buf);
		cmd->cmd_state  = 1;
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
		free(buf);
		return (MM_ACCEPT_NEEDED);

	} else if (cmd->cmd_state == 1) {
		/* revieved accept */
		mms_trace(MMS_DEVP, "LOAD STATE 1");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_ACCEPTED) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		/* set "DriveStateHard" to loading */
		mm_sql_update_state(mm_wka->mm_data, "DRIVE",
		    "DriveStateHard",
		    "loading", "DriveName",
		    mount_info->cmi_drive);

		mms_trace(MMS_DEVP, "PARSE RESPONSE DONE!!");
		cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
		cmd->cmd_flags |= MM_CMD_ACCEPTED;
		cmd->cmd_state = 2;
		mms_trace(MMS_DEVP, "LOAD STATE 1 DONE!!");
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 2) {
		/* recieved success */
		mms_trace(MMS_DEVP, "LOAD STATE 2!");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_SUCCESS) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		/* set "DriveStateHard" to loaded */
		mm_sql_update_state(mm_wka->mm_data, "DRIVE",
		    "DriveStateHard",
		    "loaded", "DriveName",
		    mount_info->cmi_drive);

		cmd->cmd_remove = 1;
		return (MM_DEPEND_DONE);
	} else {
		mms_trace(MMS_DEVP, "Bad command state");
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}
no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}


int
mm_dmp_ready_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*message;
	mms_par_node_t	*work = NULL;
	mms_par_node_t	*text_work = NULL;
	int		go;
	int		name;
	mms_par_node_t	*value;
	mms_par_node_t	*id;
	mms_par_node_t	*args;
	mms_par_node_t	*text;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*DMName = conn->cci_instance;
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;

	mms_trace(MMS_DEVP, "mm_dmp_ready_cmd_func");
	if ((value = mms_pn_lookup(cmd->cmd_root, "broken",
	    MMS_PN_KEYWORD, NULL)) != NULL) {
		mms_trace(MMS_DEVP, "ready broken");
		mm_sql_update_state(mm_wka->mm_data, "DM",
		    "DMStateSoft",
		    "not ready", "DMName",
		    DMName);
		mm_sql_update_state(mm_wka->mm_data, "DM",
		    "DMStateHard",
		    "broken", "DMName",
		    DMName);

	} else if ((value = mms_pn_lookup(cmd->cmd_root, "not",
	    MMS_PN_KEYWORD, NULL)) != NULL) {
		mms_trace(MMS_DEVP, "ready not");
		mm_sql_update_state(mm_wka->mm_data, "DM",
		    "DMStateSoft",
		    "not ready", "DMName",
		    DMName);
	} else if ((value = mms_pn_lookup(cmd->cmd_root, "disconnected",
	    MMS_PN_KEYWORD, NULL)) != NULL) {
		mms_trace(MMS_DEVP, "ready disconnected");
		mm_sql_update_state(mm_wka->mm_data, "DM",
		    "DMStateSoft",
		    "disconnected", "DMName",
		    DMName);
	} else {
		/* Drive is READY! */
		mm_sql_update_state(mm_wka->mm_data, "DM",
		    "DMStateSoft",
		    "ready", "DMName",
		    DMName);
		mm_path_match_report(cmd, db);
		mm_send_response(mm_wka->mm_wka_conn, cmd);
		cmd->cmd_remove = 1;
		return (MM_CMD_DONE);
	}

	message = mms_pn_lookup(cmd->cmd_root, "message",
	    MMS_PN_CLAUSE, &work);
	if (message != NULL) {
		work = NULL;
		id = mms_pn_lookup(message, "id",
		    MMS_PN_CLAUSE, &work);
		if (id != NULL) {
			work = NULL;
			MMS_PN_LOOKUP(value, id, NULL,
			    MMS_PN_STRING, &work);
			mms_trace(MMS_DEVP, "Manufacturer identifer -> %s",
			    value->pn_string);
			MMS_PN_LOOKUP(value, id, NULL,
			    MMS_PN_STRING, &work);
			mms_trace(MMS_DEVP, "Catalog -> %s",
			    value->pn_string);
			MMS_PN_LOOKUP(value, id, NULL,
			    MMS_PN_STRING, &work);
			mms_trace(MMS_DEVP, "Message ID -> %s",
			    value->pn_string);
		} else {
			mms_trace(MMS_DEVP, "Missing an id clause");
		}

		work = NULL;
		args = mms_pn_lookup(message, "arguments",
		    MMS_PN_CLAUSE, &work);
		if (args != NULL) {
			mms_trace(MMS_DEVP, "Name, Value");
			work = NULL;
			go = 1;
			name = 0;
			while (go) {
				if ((value = mms_pn_lookup(args, NULL,
				    MMS_PN_STRING,
				    &work)) == NULL) {
					go = 0;
				} else {
					if (name == 0) {
						/* got name */
						name = 1;
						mms_trace(MMS_DEVP,
						    "Name -> %s",
						    value->pn_string);
					} else {
						name = 0;
						mms_trace(MMS_DEVP,
						    " Value -> %s",
						    value->pn_string);
					}
				}
			}
			if (name == 1) {
				/* got name and are missing a value */
				mms_trace(MMS_DEVP, "Missing value "\
				"in argument clause");
				goto not_found;
			}

		} else {
			mms_trace(MMS_DEVP, "Missing an arguements clause");
		}
		text_work = NULL;
		text = mms_pn_lookup(message, "loctext",
		    MMS_PN_CLAUSE, &text_work);
		while (text != NULL) {
			work = NULL;
			MMS_PN_LOOKUP(value, text, NULL,
			    MMS_PN_STRING, &work);
			mms_trace(MMS_DEVP, "Language -> %s",
			    value->pn_string);
			MMS_PN_LOOKUP(value, text, NULL,
			    MMS_PN_STRING, &work);
			mms_trace(MMS_DEVP, "Format -> %s",
			    value->pn_string);
			text = mms_pn_lookup(message, "loctext",
			    MMS_PN_CLAUSE, &text_work);
		}
	} else {
		mms_trace(MMS_DEVP, "Didn't find a message...");
	}

	mm_path_match_report(cmd, db);
	mm_send_response(mm_wka->mm_wka_conn, cmd);
	cmd->cmd_remove = 1;
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

#define	DMP_SEND_UNLOAD "unload task [\"%s\"];"



int
mm_dmp_unload_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	cci_t			*conn = &mm_wka->wka_conn;
	char			*DriveName = conn->cci_client;
	char			*DMName = conn->cci_instance;
	char			*task = cmd->cmd_task;
	char			*buf = NULL;
	int			bufsize = 0;
	mm_response_t		response;
	mms_par_node_t		*work = NULL;
	int			go;
	int			name;
	mms_par_node_t		*value;
	mms_par_node_t		*text;

	mms_trace(MMS_DEVP, "mm_dmp_unload_cmd_func");
	if (cmd->cmd_state == 0) {
		/* send the unload to DM */
		mms_trace(MMS_DEVP, "DM Name is %s, task id is %s",
		    DMName, task);

		SQL_CHK_LEN(&buf, 0, &bufsize,
		    strlen(DMP_SEND_UNLOAD) +
		    strlen(task) + 1);
		(void) snprintf(buf, bufsize,
		    DMP_SEND_UNLOAD, task);
		mms_trace(MMS_DEVP, "send buf is '%s' to fd %d ", buf,
		    mm_wka->mm_wka_conn->mms_fd);

		/* Set DriveStateHard to UNLOADING */
		mm_sql_update_state(mm_wka->mm_data,
		    "DRIVE", "DriveStateHard",
		    "unloading", "DriveName",
		    DriveName);

		mm_send_text(mm_wka->mm_wka_conn,
		    buf);
		cmd->cmd_state  = 1;
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
		free(buf);
		return (MM_ACCEPT_NEEDED);

	} else if (cmd->cmd_state == 1) {
		/* revieved accept */
		mms_trace(MMS_DEVP, "UNLOAD STATE 1");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_ACCEPTED) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}

		cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
		cmd->cmd_flags |= MM_CMD_ACCEPTED;
		cmd->cmd_state = 2;
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 2) {
		/* recieved success */
		mms_trace(MMS_DEVP, "UNLOAD STATE 2!");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_SUCCESS) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
		work = NULL;
		text = mms_pn_lookup(cmd->cmd_response, "text",
		    MMS_PN_CLAUSE, &work);
		if (text != NULL) {
			mms_trace(MMS_DEVP, "Name, Value");
			work = NULL;
			go = 1;
			name = 0;
			while (go) {
				if ((value = mms_pn_lookup(text, NULL,
				    MMS_PN_STRING,
				    &work)) == NULL) {
					go = 0;
				} else {
					if (name == 0) {
						/* got name */
						name = 1;
						mms_trace(MMS_DEVP,
						    "Name -> %s",
						    value->pn_string);
					} else {
						name = 0;
						mms_trace(MMS_DEVP,
						    " Value -> %s",
						    value->pn_string);
					}
				}
			}
			if (name == 1) {
				/* got name and are missing a value */
				mms_trace(MMS_DEVP, "Missing value "\
				    "in text clause");
				goto not_found;
			}

		} else {
			mms_trace(MMS_DEVP, "Missing an text clause");
		}

		cmd->cmd_remove = 1;
		return (MM_DEPEND_DONE);

	} else {
		mms_trace(MMS_DEVP, "Bad command state");
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mms_trace(MMS_ERR, "Not Found!!");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

#define	DMP_SEND_DETACH "detach task [\"%s\"] "\
	"drivehandle [\"%s\"] stale [\"%s\"];"
int
mm_dmp_detach_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mm_db_t			*db = &mm_wka->mm_data->mm_db;
	cci_t			*conn = &mm_wka->wka_conn;
	char			*DriveName = conn->cci_client;
	char			*DMName = conn->cci_instance;
	char			*task = cmd->cmd_task;
	char			*buf = NULL;
	int			bufsize = 0;
	mm_response_t		response;
	mm_command_t		*parent = NULL;
	cmd_mount_info_t	*mount_info = NULL;
	int			rc;
	PGresult		*handle;
	int			stale = 0;

	mms_trace(MMS_DEVP, "mm_dmp_detach_cmd_func");
	parent = mm_first_parent(cmd);
	mount_info = &parent->cmd_mount_info;
	if (cmd->cmd_state == 0) {
		/* send the detach to DM */
		mms_trace(MMS_DEVP, "DM Name is %s, task id is %s",
		    DMName, task);

		/* Get the handle from MOUNTLOGICAL */

		rc = mm_db_exec(HERE, db, "select \"MountLogicalHandle\" "\
		    "from \"MOUNTLOGICAL\" where "\
		    "\"DriveName\" = '%s' and \"DMName\" = '%s';",
		    DriveName, DMName);
		if (rc != MM_DB_DATA) {
			mms_trace(MMS_ERR, "Exec returned with no Data");
			return (MM_CMD_ERROR);
		}
		handle = db->mm_db_results;
		if (PQntuples(handle) == 0) {
			/* NO handle found */
			mms_trace(MMS_NOTICE,
			    "No MOUNTLOGICAL handle found...");
			/* No MOUNLOGICAL handle, check for STALEHANDLE */
			rc = mm_db_exec(HERE, db,
			    "select \"MountLogicalHandle\" "
			    "from \"STALEHANDLE\" where "
			    "\"DriveName\" = '%s' "
			    "and \"DMName\" = '%s';",
			    DriveName, DMName);
			if (rc != MM_DB_DATA) {
				mms_trace(MMS_DEVP,
				    "Exec returned with no Data");
				mm_clear_db(&handle);
				return (MM_CMD_ERROR);
			}
			mm_clear_db(&handle);
			handle = db->mm_db_results;
			if (PQntuples(handle) == 0) {
				/* NO handle found */
				mms_trace(MMS_NOTICE, "No STALEHANDLE or "\
				    "MOUNTLOGICAL found, skipping detach");
				mm_clear_db(&handle);
				return (MM_DEPEND_DONE);
			} else {
				stale = 1;
			}
		}

		mount_info->cmi_handle = strdup(PQgetvalue(handle, 0, 0));
		if (stale) {
			SQL_CHK_LEN(&buf, 0, &bufsize,
			    strlen(DMP_SEND_DETACH) +
			    strlen(task) +
			    strlen(mount_info->cmi_handle) + 4 + 1);
			(void) snprintf(buf, bufsize,
			    DMP_SEND_DETACH, task,
			    mount_info->cmi_handle, "true");
		} else {
			SQL_CHK_LEN(&buf, 0, &bufsize,
			    strlen(DMP_SEND_DETACH) +
			    strlen(task) +
			    strlen(mount_info->cmi_handle) + 5 + 1);
			(void) snprintf(buf, bufsize,
			    DMP_SEND_DETACH, task,
			    mount_info->cmi_handle, "false");
		}
		mms_trace(MMS_DEVP, "send buf is '%s' to fd %d ", buf,
		    mm_wka->mm_wka_conn->mms_fd);

		mm_send_text(mm_wka->mm_wka_conn,
		    buf);
		cmd->cmd_state  = 1;
		MM_SET_FLAG(cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
		free(buf);
		mm_clear_db(&handle);
		return (MM_ACCEPT_NEEDED);

	} else if (cmd->cmd_state == 1) {
		/* revieved accept */
		mms_trace(MMS_DEVP, "DETACH STATE 1");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_ACCEPTED) {
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}

		cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
		cmd->cmd_flags |= MM_CMD_ACCEPTED;
		cmd->cmd_state = 2;
		return (MM_DISPATCH_DEPEND);
	} else if (cmd->cmd_state == 2) {
		/* recieved success */
		mms_trace(MMS_DEVP, "DETACH STATE 2!");
		if (mm_parse_response(cmd->cmd_response, &response) != 0 ||
		    response.response_type != MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_ERR, "DM Detach - %s %s",
			    response.error_class,
			    response.error_code);
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);

		}
		cmd->cmd_remove = 1;
		return (MM_DEPEND_DONE);

	} else {
		mms_trace(MMS_DEVP, "Bad command state");
		cmd->cmd_remove = 1;
		return (MM_CMD_ERROR);
	}

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:
	mms_trace(MMS_ERR, "Not Found!!");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

mm_command_t *
mm_dmp_add_cmd(mm_wka_t *mm_wka, mm_command_t *mnt_cmd, char *dm_name, int type)
{
	mm_command_t		*cmd;
	mm_data_t		*mm_data = mm_wka->mm_data;
	mm_wka_t		*dm_wka;
	uuid_text_t		uuid;
	int			recover = 0;

	mms_trace(MMS_DEVP, "mm_dmp_add_cmd");
	switch (type) {
	case MM_DMP_RESERVE:
		mms_trace(MMS_DEVP, "About to add activate reserve command ");
		break;
	case MM_DMP_PRIV:
		mms_trace(MMS_DEVP, "About to add private command ");
		break;
	case MM_DMP_LOAD:
		mms_trace(MMS_DEVP, "About to add load command ");
		break;
	case MM_DMP_ATTACH:
		mms_trace(MMS_DEVP, "About to add attach command ");
		break;
	case MM_DMP_IDENTIFY:
		mms_trace(MMS_DEVP, "About to add identify command ");
		break;
	case MM_DMP_DETACH:
		mms_trace(MMS_DEVP, "About to add detach command ");
		break;
	case MM_DMP_UNLOAD:
		mms_trace(MMS_DEVP, "About to add unload command ");
		break;
	case MM_DMP_RELEASE:
		mms_trace(MMS_DEVP, "About to add activate release command ");
		break;
	}

	/* Set cmd->wka_ptr to point to the dm's wka */
	dm_wka = NULL;
	if (!recover) {
		mms_list_foreach(&mm_data->mm_wka_list, dm_wka) {
			if (strcmp(dm_wka->wka_conn.cci_instance,
			    dm_name) == 0) {
				/* Found the wka of dm */
				break;
			}

		}
		if ((dm_wka == NULL) || (strcmp(dm_wka->wka_conn.cci_instance,
		    dm_name) != 0)) {
			/* bad wka */
			mms_trace(MMS_DEVP, "DM not connected!!");
			return (NULL);
		}
	} else {
		dm_wka = mm_wka;
	}
	if ((cmd = mm_alloc_cmd(dm_wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		return (NULL);
	}

	mm_get_uuid(uuid);
	mm_add_depend(cmd, mnt_cmd);
	cmd->cmd_task = NULL;
	cmd->cmd_task = strdup(uuid);
	if (cmd->cmd_task == NULL) {
		mms_trace(MMS_ERR, "Error malloc cmd_task in add cmd");
		return (NULL);
	}

	switch (type) {
	case MM_DMP_RESERVE:
		cmd->cmd_func = mm_dmp_activate_cmd_func;
		cmd->cmd_name = strdup("dmp activate reserve");
		cmd->cmd_textcmd = mms_strnew(ACTIVATE_RESERVE, cmd->cmd_task);
		cmd->cmd_root = mm_text_to_par_node(cmd->cmd_textcmd,
		    mms_dmpm_parse);
		break;
	case MM_DMP_PRIV:
		cmd->cmd_func = mm_dmp_private_cmd_func;
		cmd->cmd_name = strdup("dmp private");
		break;
	case MM_DMP_LOAD:
		cmd->cmd_func = mm_dmp_load_cmd_func;
		cmd->cmd_name = strdup("dmp load");
		break;
	case MM_DMP_ATTACH:
		cmd->cmd_func = mm_dmp_attach_cmd_func;
		cmd->cmd_name = strdup("dmp attach");
		break;
	case MM_DMP_IDENTIFY:
		cmd->cmd_func = mm_dmp_identify_cmd_func;
		cmd->cmd_name = strdup("dmp identify");
		break;
	case MM_DMP_DETACH:
		cmd->cmd_func = mm_dmp_detach_cmd_func;
		cmd->cmd_name = strdup("dmp detach");
		break;
	case MM_DMP_UNLOAD:
		cmd->cmd_func = mm_dmp_unload_cmd_func;
		cmd->cmd_name = strdup("dmp unload");
		break;
	case MM_DMP_RELEASE:
		cmd->cmd_func = mm_dmp_activate_cmd_func;
		cmd->cmd_name = strdup("dmp activate release");
		cmd->cmd_textcmd = mms_strnew(ACTIVATE_RELEASE, cmd->cmd_task);
		cmd->cmd_root = mm_text_to_par_node(cmd->cmd_textcmd,
		    mms_dmpm_parse);
		break;
	}
	pthread_mutex_lock(&mm_data->
	    mm_queue_mutex);
	mms_list_insert_tail(&mm_wka->mm_data->mm_cmd_queue, cmd);
	pthread_mutex_unlock(&mm_data->
	    mm_queue_mutex);
	mms_trace(MMS_DEVP, "DMP Command Added to Queue - %d",
	    mm_wka->mm_wka_conn);
	return (cmd);
}

int
mm_dmp_cancel_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	mms_par_node_t	*value;
	mms_par_node_t	*arg;
	mm_data_t	*data = mm_wka->mm_data;
	char		*taskid;
	mm_db_t		*db = &mm_wka->mm_data->mm_db;
	mm_command_t    *cmd_p;
	mm_command_t    *cmd_q;
	char		*cmd_name = NULL;
	uuid_text_t	cmd_reqid;

	mms_trace(MMS_DEVP, "mm_dmp_cancel_cmd_func");

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
		    strlen(ECLASS_INVALID) + strlen(EDM_E_NOTASK) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INVALID, EDM_E_NOTASK);
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
			    strlen(EDM_E_NOCANC) + 1);
			(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
			    RESPONSE_ERROR,
			    cmd->cmd_task,
			    ECLASS_INVALID, EDM_E_NOCANC);
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
		    strlen(ECLASS_INVALID) + strlen(EDM_E_NOCANC) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INVALID, EDM_E_NOCANC);
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
mm_dmp_reset_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	cci_t		*conn = &mm_wka->wka_conn;
	mm_response_t	 response;


	mms_trace(MMS_DEBUG,
	    "dmp reset, state %d, %s",
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
			mms_trace(MMS_DEVP, "dmp reset accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "dmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "dmp reset success");
			cmd->cmd_remove = 1;
			return (MM_DEPEND_DONE);
		}
	}

	mms_trace(MMS_DEVP, "dmp reset failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}

int
mm_dmp_exit_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	cci_t		*conn = &mm_wka->wka_conn;
	mm_response_t	 response;


	mms_trace(MMS_DEBUG,
	    "dmp exit, state %d, %s",
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
			mms_trace(MMS_DEVP, "dmp exit accepted");
			cmd->cmd_flags &= ~MM_CMD_NEED_ACCEPT;
			cmd->cmd_flags |= MM_CMD_ACCEPTED;
			cmd->cmd_state = 2;
			return (MM_NO_DISPATCH);
		} else {
			mms_trace(MMS_ERR, "dmp cmd not accepted");
			cmd->cmd_remove = 1;
			return (MM_CMD_ERROR);
		}
	} else if (cmd->cmd_state == 2) {
		if (mm_parse_response(cmd->cmd_response, &response) == 0 &&
		    response.response_type == MM_RESPONSE_SUCCESS) {
			mms_trace(MMS_DEVP, "dmp exit success");
			cmd->cmd_remove = 1;
			return (MM_DEPEND_DONE);
		}
	}

	mms_trace(MMS_DEVP, "dmp exit failed");
	cmd->cmd_remove = 1;
	return (MM_CMD_ERROR);
}
