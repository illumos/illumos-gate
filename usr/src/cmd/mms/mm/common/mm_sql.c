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
#include <syslog.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <libpq-fe.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include <pthread.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_commands.h"
#include "mm_sql.h"
#include "mm_sql_impl.h"
#include "mm_path.h"


static char *_SrcFile = __FILE__;

extern mm_pkey_t *mm_get_pkey(char *obj);

char *mm_sql_number_buf(mm_command_t *cmd);
char *mm_sql_order_buf(mm_command_t *cmd);
static sql_ops_tab_t opstab[] = {
	"strlohi", "ASC",
	"strhilo", "DESC",
	"numlohi", "ASC",
	"numhilo", "DESC",
	"regex", "~",
	"streq", "=",
	"strne", "<>",
	"strlt", "<",
	"strle", "<=",
	"strgt", ">",
	"strge", ">=",
	"numeq", "=",
	"numne", "<>",
	"numlt", "<",
	"numle", "<=",
	"numgt", ">",
	"numge", ">=",
	"and", "AND",
	"or", "OR",
	"not", "NOT",
	"hosteq", "=",
	"hostne", "<>"
};
static int	num_ops = sizeof (opstab) / sizeof (sql_ops_tab_t);


char *
mm_get_cart_pcl(mm_command_t *cmd, char *cart_id, mm_db_t *db)
{
	char		*value;
	char		*cart_pcl;

	/*
	 * Get cartridge pcl from cartridge id
	 */
	if (cart_id == NULL) {
		mms_trace(MMS_DEVP, "cartridge id is null");
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_EXPLICIT) + strlen(ENOMATCH) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_EXPLICIT, ENOMATCH);
		return (NULL);
	}
	if (mm_db_exec(HERE, db, "select \"CartridgePCL\" from \"CARTRIDGE\" "
	    "where \"CartridgeID\" = '%s'", cart_id) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_INTERNAL) + strlen(EDATABASE) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INTERNAL, EDATABASE);
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_DEVP, "cartridge pcl failed");
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ERROR) + strlen(cmd->cmd_task) +
		    strlen(ECLASS_EXPLICIT) + strlen(ENOMATCH) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_EXPLICIT, ENOMATCH);
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	value = PQgetvalue(db->mm_db_results, 0, 0);
	if (value[0] == '\0') {
		value = "none";
	}
	cart_pcl = strdup(value);
	mm_clear_db(&db->mm_db_results);
	if (cart_pcl == NULL) {
	no_mem:
		MM_ABORT_NO_MEM();
	}
	return (cart_pcl);
}


int
mm_set_cartridge_status(char *id, char *status, mm_db_t *db) {
	if ((id == NULL) ||
	    (status == NULL)) {
		mms_trace(MMS_ERR,
		    "id and/or status cannot be null");
		return (1);
	}
	/* Allowed values for status are : */
	/* in use */
	/* unavailable */
	/* available */
	if (mm_db_exec(HERE, db,
		    "update \"CARTRIDGE\" "
		    "set \"CartridgeStatus\" = '%s' "
		    "where \"CartridgeID\" = '%s';",
		    status, id) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error updateing cartridge state, %s, %s",
		    id, status);
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (1);
	}
	return (0);
}

int
mm_set_drive_statesoft(char *drive, char *state, mm_db_t *db) {
	if ((drive == NULL) ||
	    (state == NULL)) {
		mms_trace(MMS_ERR,
		    "drive and/or state cannot be null");
		return (1);
	}
	/* Allowed values for status are : */
	/* in use */
	/* ready */
	if (mm_db_exec(HERE, db,
		    "update \"DRIVE\" "
		    "set \"DriveStateSoft\" = '%s' "
		    "where \"DriveName\" = '%s';",
		    state, drive) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error updateing drive state, %s, %s",
		    drive, state);
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (1);
	}
	return (0);
}



void
mm_set_mount_info_cart(char *cart_id,
		    cmd_mount_info_t *mount_info) {
	if (mount_info->cmi_cartridge)
		free(mount_info->cmi_cartridge);
	mount_info->cmi_cartridge = NULL;
	mount_info->cmi_cartridge =
		mms_strapp(mount_info->cmi_cartridge,
		    cart_id);
}
void
mm_set_mount_info_drive(char *drive,
			cmd_mount_info_t *mount_info) {
	if (mount_info->cmi_drive)
		free(mount_info->cmi_drive);
	mount_info->cmi_drive = NULL;
	mount_info->cmi_drive =
		mms_strapp(mount_info->cmi_drive,
		    drive);
}
void
mm_set_mount_info_library(char *library,
			cmd_mount_info_t *mount_info) {
	if (mount_info->cmi_library)
		free(mount_info->cmi_library);
	mount_info->cmi_library = NULL;
	mount_info->cmi_library =
		mms_strapp(mount_info->cmi_library,
		    library);
}
void
mm_set_mount_info_dm(char *dm,
		    cmd_mount_info_t *mount_info) {
	if (mount_info->cmi_dm)
		free(mount_info->cmi_dm);
	mount_info->cmi_dm = NULL;
	mount_info->cmi_dm =
		mms_strapp(mount_info->cmi_dm,
		    dm);
}
void
mm_set_mount_info_pcl(char *pcl,
		    cmd_mount_info_t *mount_info) {
	if (mount_info->cmi_pcl)
		free(mount_info->cmi_pcl);
	mount_info->cmi_pcl = NULL;
	mount_info->cmi_pcl =
		mms_strapp(mount_info->cmi_pcl,
		    pcl);
}


void
mm_free_mount_info(cmd_mount_info_t *mount_info) {
	if (mount_info->cmi_cartridge)
		free(mount_info->cmi_cartridge);
	if (mount_info->cmi_drive)
		free(mount_info->cmi_drive);
	if (mount_info->cmi_library)
		free(mount_info->cmi_library);
	if (mount_info->cmi_dm)
		free(mount_info->cmi_dm);
	if (mount_info->cmi_pcl)
		free(mount_info->cmi_pcl);
	mount_info->cmi_cartridge = NULL;
	mount_info->cmi_pcl = NULL;
	mount_info->cmi_drive = NULL;
	mount_info->cmi_library = NULL;
	mount_info->cmi_dm = NULL;
}



void
mm_print_dm_status(mm_dm_stat_t *dm_stat) {
	mms_trace(MMS_DEVP,
	    "DM, %s, Status for Drive, %s, host, %s",
	    dm_stat->dm_stat_name,
	    dm_stat->dm_stat_drive,
	    dm_stat->dm_stat_host);
	mms_trace(MMS_DEVP,
	    "     DMStateHard = %s",
	    dm_stat->dm_stat_hard);
	mms_trace(MMS_DEVP,
	    "     DMStateSoft = %s",
	    dm_stat->dm_stat_soft);
	mms_trace(MMS_DEVP,
	    "     DMDisabled = %s",
	    dm_stat->dm_stat_disabled);
}

void
mm_free_dm_status(mm_dm_stat_t *dm_stat) {
	if (dm_stat == NULL) {
		return;
	}
	if (dm_stat->dm_stat_name)
		free(dm_stat->dm_stat_name);
	if (dm_stat->dm_stat_hard)
		free(dm_stat->dm_stat_hard);
	if (dm_stat->dm_stat_disabled)
		free(dm_stat->dm_stat_disabled);
	if (dm_stat->dm_stat_soft)
		free(dm_stat->dm_stat_soft);
	if (dm_stat->dm_stat_host)
		free(dm_stat->dm_stat_host);
	if (dm_stat->dm_stat_drive)
		free(dm_stat->dm_stat_drive);

	free(dm_stat);
}

mm_dm_stat_t *
mm_get_dm_status(char *dm_name, char *drive_name, char *host, mm_db_t *db) {
	mm_dm_stat_t *dm_status = NULL;

	char		*cmd_buf = NULL;
	/* when dm name is null, use drive and host to return the dm status */
	cmd_buf = mms_strapp(cmd_buf,
		    "select "
		    "\"DM\".\"DMStateHard\", "
		    "\"DM\".\"DMStateSoft\", "
		    "\"DM\".\"DriveName\", "
		    "\"DM\".\"DMDisabled\", "
		    "\"DM\".\"DMTargetHost\", "
		    "\"DM\".\"DMName\" "
		    "from \"DM\" ");

	if (dm_name == NULL) {
		if ((drive_name == NULL) ||
		    (host == NULL)) {
			mms_trace(MMS_ERR,
			    "need drive and host if dm namd is null",
			    ", mm_get_dm_status");
			free(cmd_buf);
			return (NULL);
		}
		/* use drive/host constraint */
		cmd_buf = mms_strapp(cmd_buf,
				"where \"DriveName\" = '%s' "
				"and pg_host_ident(\"DMTargetHost\") "
				"= pg_host_ident('%s');",
				drive_name,
				host);
	} else {
		/* use dm name constrant */
		cmd_buf = mms_strapp(cmd_buf,
				"where \"DM\".\"DMName\" = '%s'",
				dm_name);
	}
	if (mm_db_exec(HERE, db, cmd_buf) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error, mm_get_dm_status");
		free(cmd_buf);
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (NULL);
	}
	free(cmd_buf);
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR,
		    "row num mismatch, "
		    "mm_get_drive_status");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	dm_status = (mm_dm_stat_t *)calloc(1, sizeof (mm_dm_stat_t));
	if (dm_status == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc dm_status");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}

	dm_status->dm_stat_hard = mms_strapp(dm_status->dm_stat_hard,
					PQgetvalue(db->mm_db_results, 0, 0));
	dm_status->dm_stat_soft = mms_strapp(dm_status->dm_stat_soft,
					PQgetvalue(db->mm_db_results, 0, 1));
	dm_status->dm_stat_drive = mms_strapp(dm_status->dm_stat_drive,
					PQgetvalue(db->mm_db_results, 0, 2));
	dm_status->dm_stat_disabled = mms_strapp(dm_status->dm_stat_disabled,
					PQgetvalue(db->mm_db_results, 0, 3));
	dm_status->dm_stat_host = mms_strapp(dm_status->dm_stat_host,
					PQgetvalue(db->mm_db_results, 0, 4));
	dm_status->dm_stat_name = mms_strapp(dm_status->dm_stat_name,
					PQgetvalue(db->mm_db_results, 0, 5));
	mm_clear_db(&db->mm_db_results);
	return (dm_status);

}

void
mm_print_drive_status(mm_drive_stat_t *drive_stat) {
	mms_trace(MMS_DEVP,
	    "Drive Status for Drive, %s",
	    drive_stat->drive_stat_name);
	mms_trace(MMS_DEVP,
	    "    DriveDisabled  = %s",
	    drive_stat->drive_stat_disabled);
	mms_trace(MMS_DEVP,
	    "    DriveBroken = %s",
	    drive_stat->drive_stat_broken);
	mms_trace(MMS_DEVP,
	    "    DriveStateSoft = %s",
	    drive_stat->drive_stat_soft);
	mms_trace(MMS_DEVP,
	    "    DriveStateHard = %s",
	    drive_stat->drive_stat_hard);
	mms_trace(MMS_DEVP,
	    "    DriveLibraryAccessible = %s",
	    drive_stat->drive_stat_lib_acc);
	mms_trace(MMS_DEVP,
	    "    ExclusiveAppName = %s",
	    drive_stat->drive_stat_excl_app);
	mms_trace(MMS_DEVP,
	    "    DriveOnline = %s",
	    drive_stat->drive_stat_online);
	mms_trace(MMS_DEVP,
	    "    DriveGroupName = %s",
	    drive_stat->drive_stat_group);
	mms_trace(MMS_DEVP,
	    "    LibraryName = %s",
	    drive_stat->drive_stat_library);
	mms_trace(MMS_DEVP,
	    "    DrivePriority = %s",
	    drive_stat->drive_stat_priority);
	mms_trace(MMS_DEVP,
	    "    DMName = %s",
	    drive_stat->drive_stat_dm);
	mms_trace(MMS_DEVP,
	    "    DriveGeometry = %s",
	    drive_stat->drive_stat_geometry);
	mms_trace(MMS_DEVP,
	    "    DriveSerialNum = %s",
	    drive_stat->drive_stat_serial);
	mms_trace(MMS_DEVP,
	    "    CartridgePCL = %s",
	    drive_stat->drive_stat_pcl);
	mms_trace(MMS_DEVP,
	    "    DriveLibraryOccupied = %s",
	    drive_stat->drive_stat_drvlib_occ);
}
void
mm_free_drive_status(mm_drive_stat_t *drive_stat) {
	if (drive_stat == NULL) {
		return;
	}
	if (drive_stat->drive_stat_name)
		free(drive_stat->drive_stat_name);
	if (drive_stat->drive_stat_hard)
		free(drive_stat->drive_stat_hard);
	if (drive_stat->drive_stat_disabled)
		free(drive_stat->drive_stat_disabled);
	if (drive_stat->drive_stat_soft)
		free(drive_stat->drive_stat_soft);
	if (drive_stat->drive_stat_library)
		free(drive_stat->drive_stat_library);
	if (drive_stat->drive_stat_lib_acc)
		free(drive_stat->drive_stat_lib_acc);
	if (drive_stat->drive_stat_group)
		free(drive_stat->drive_stat_group);
	if (drive_stat->drive_stat_excl_app)
		free(drive_stat->drive_stat_excl_app);
	if (drive_stat->drive_stat_broken)
		free(drive_stat->drive_stat_broken);
	if (drive_stat->drive_stat_online)
		free(drive_stat->drive_stat_online);
	if (drive_stat->drive_stat_priority)
		free(drive_stat->drive_stat_priority);
	if (drive_stat->drive_stat_dm)
		free(drive_stat->drive_stat_dm);
	if (drive_stat->drive_stat_geometry)
		free(drive_stat->drive_stat_geometry);
	if (drive_stat->drive_stat_serial)
		free(drive_stat->drive_stat_serial);
	if (drive_stat->drive_stat_pcl)
		free(drive_stat->drive_stat_pcl);
	if (drive_stat->drive_stat_drvlib_occ)
		free(drive_stat->drive_stat_drvlib_occ);
	free(drive_stat);
}

mm_drive_stat_t *
mm_get_drive_status(char *drive_name, mm_db_t *db) {
	mm_drive_stat_t *drive_status = NULL;
	if (mm_db_exec(HERE, db,
		    "select "
		    "\"DRIVE\".\"DriveDisabled\", "
		    "\"DRIVE\".\"DriveBroken\", "
		    "\"DRIVE\".\"DriveStateSoft\", "
		    "\"DRIVE\".\"DriveLibraryAccessible\", "
		    "\"DRIVE\".\"ExclusiveAppName\", "
		    "\"DRIVE\".\"DriveOnline\", "
		    "\"DRIVE\".\"DriveGroupName\", "
		    "\"DRIVE\".\"DriveStateHard\", "
		    "\"DRIVE\".\"LibraryName\", "
		    "\"DRIVE\".\"DrivePriority\", "
		    "\"DRIVE\".\"DMName\", "
		    "\"DRIVE\".\"DriveGeometry\", "
		    "\"DRIVE\".\"DriveSerialNum\", "
		    "\"DRIVE\".\"CartridgePCL\", "
		    "\"DRIVE\".\"DriveLibraryOccupied\" "
		    "from \"DRIVE\" "
		    "where \"DriveName\" = '%s';",
		    drive_name) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error, mm_get_drive_status");
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR,
		    "row num mismatch, "
		    "mm_get_drive_status");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	drive_status = (mm_drive_stat_t *)calloc(1, sizeof (mm_drive_stat_t));
	if (drive_status == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc drive_status");
		return (NULL);
	}
	drive_status->drive_stat_name =
		mms_strapp(drive_status->drive_stat_name,
		    drive_name);
	drive_status->drive_stat_disabled =
		mms_strapp(drive_status->drive_stat_disabled,
		    PQgetvalue(db->mm_db_results, 0, 0));
	drive_status->drive_stat_broken =
		mms_strapp(drive_status->drive_stat_broken,
		    PQgetvalue(db->mm_db_results, 0, 1));
	drive_status->drive_stat_soft =
		mms_strapp(drive_status->drive_stat_soft,
		    PQgetvalue(db->mm_db_results, 0, 2));
	drive_status->drive_stat_lib_acc =
		mms_strapp(drive_status->drive_stat_lib_acc,
		    PQgetvalue(db->mm_db_results, 0, 3));
	drive_status->drive_stat_excl_app =
		mms_strapp(drive_status->drive_stat_excl_app,
		    PQgetvalue(db->mm_db_results, 0, 4));
	drive_status->drive_stat_online =
		mms_strapp(drive_status->drive_stat_online,
		    PQgetvalue(db->mm_db_results, 0, 5));
	drive_status->drive_stat_group =
		mms_strapp(drive_status->drive_stat_group,
		    PQgetvalue(db->mm_db_results, 0, 6));
	drive_status->drive_stat_hard =
		mms_strapp(drive_status->drive_stat_hard,
		    PQgetvalue(db->mm_db_results, 0, 7));
	drive_status->drive_stat_library =
		mms_strapp(drive_status->drive_stat_library,
		    PQgetvalue(db->mm_db_results, 0, 8));
	drive_status->drive_stat_priority =
		mms_strapp(drive_status->drive_stat_priority,
		    PQgetvalue(db->mm_db_results, 0, 9));
	drive_status->drive_stat_dm =
		mms_strapp(drive_status->drive_stat_dm,
		    PQgetvalue(db->mm_db_results, 0, 10));
	drive_status->drive_stat_geometry =
		mms_strapp(drive_status->drive_stat_geometry,
		    PQgetvalue(db->mm_db_results, 0, 11));
	drive_status->drive_stat_serial =
		mms_strapp(drive_status->drive_stat_serial,
		    PQgetvalue(db->mm_db_results, 0, 12));
	drive_status->drive_stat_pcl =
		mms_strapp(drive_status->drive_stat_pcl,
		    PQgetvalue(db->mm_db_results, 0, 13));
	drive_status->drive_stat_drvlib_occ =
		mms_strapp(drive_status->drive_stat_drvlib_occ,
		    PQgetvalue(db->mm_db_results, 0, 14));

	mm_clear_db(&db->mm_db_results);
	return (drive_status);

}

void
mm_print_lm_status(mm_lm_stat_t *lm_stat) {
	mms_trace(MMS_DEVP,
	    "LM Status for LM, %s",
	    lm_stat->lm_stat_name);
	mms_trace(MMS_DEVP,
	    "    LibraryName = %s",
	    lm_stat->lm_stat_library);
	mms_trace(MMS_DEVP,
	    "    LMStateHard = %s",
	    lm_stat->lm_stat_hard);
	mms_trace(MMS_DEVP,
	    "    LMStateSoft = %s",
	    lm_stat->lm_stat_soft);
	mms_trace(MMS_DEVP,
	    "    LMDisabled = %s",
	    lm_stat->lm_stat_disabled);
}

void
mm_free_lm_status(mm_lm_stat_t *lm_stat) {
	if (lm_stat == NULL) {
		return;
	}
	if (lm_stat->lm_stat_name)
		free(lm_stat->lm_stat_name);
	if (lm_stat->lm_stat_hard)
		free(lm_stat->lm_stat_hard);
	if (lm_stat->lm_stat_disabled)
		free(lm_stat->lm_stat_disabled);
	if (lm_stat->lm_stat_soft)
		free(lm_stat->lm_stat_soft);
	if (lm_stat->lm_stat_library)
		free(lm_stat->lm_stat_library);
	free(lm_stat);
}
mm_lm_stat_t *
mm_get_lm_status(char *lm_name, mm_db_t *db) {
	mm_lm_stat_t *lm_status = NULL;
	if (mm_db_exec(HERE, db,
		"select "
		"\"LM\".\"LMStateHard\", "
		"\"LM\".\"LMStateSoft\", "
		"\"LM\".\"LMDisabled\", "
		"\"LM\".\"LibraryName\" "
		"from \"LM\" "
		"where \"LMName\" = '%s';",
		lm_name) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error, mm_get_lm_status");
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR,
		    "row num mismatch, "
		    "mm_get_lm_status");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	lm_status = (mm_lm_stat_t *)calloc(1, sizeof (mm_lm_stat_t));
	if (lm_status == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc lm_status");
		return (NULL);
	}
	lm_status->lm_stat_name =
		mms_strapp(lm_status->lm_stat_name,
		    lm_name);
	lm_status->lm_stat_hard =
		mms_strapp(lm_status->lm_stat_hard,
		    PQgetvalue(db->mm_db_results, 0, 0));
	lm_status->lm_stat_soft =
		mms_strapp(lm_status->lm_stat_soft,
		    PQgetvalue(db->mm_db_results, 0, 1));
	lm_status->lm_stat_disabled =
		mms_strapp(lm_status->lm_stat_disabled,
		    PQgetvalue(db->mm_db_results, 0, 2));
	lm_status->lm_stat_library =
		mms_strapp(lm_status->lm_stat_library,
		    PQgetvalue(db->mm_db_results, 0, 3));
	mm_clear_db(&db->mm_db_results);
	return (lm_status);
}
void
mm_print_library_status(mm_lib_stat_t *lib_stat) {
	mms_trace(MMS_DEVP,
	    "Library Status for Library, %s",
	    lib_stat->lib_stat_name);
	mms_trace(MMS_DEVP,
	    "    LibraryOnline = %s",
	    lib_stat->lib_stat_online);
	mms_trace(MMS_DEVP,
	    "    LibraryDisabled = %s",
	    lib_stat->lib_stat_disabled);
	mms_trace(MMS_DEVP,
	    "    LibraryBroken = %s",
	    lib_stat->lib_stat_broken);
	mms_trace(MMS_DEVP,
	    "    LMName = %s",
	    lib_stat->lib_stat_lm);
}


void
mm_free_library_status(mm_lib_stat_t *lib_stat) {
	if (lib_stat == NULL) {
		return;
	}
	if (lib_stat->lib_stat_name)
		free(lib_stat->lib_stat_name);
	if (lib_stat->lib_stat_online)
		free(lib_stat->lib_stat_online);
	if (lib_stat->lib_stat_disabled)
		free(lib_stat->lib_stat_disabled);
	if (lib_stat->lib_stat_broken)
		free(lib_stat->lib_stat_broken);
	if (lib_stat->lib_stat_lm)
		free(lib_stat->lib_stat_lm);
	free(lib_stat);
}
mm_lib_stat_t *
mm_get_library_status(char *library_name, mm_db_t *db) {
	mm_lib_stat_t *library_status = NULL;

	if (mm_db_exec(HERE, db,
		"select "
		"\"LIBRARY\".\"LibraryOnline\", "
		"\"LIBRARY\".\"LibraryDisabled\", "
		"\"LIBRARY\".\"LibraryBroken\", "
		"\"LIBRARY\".\"LMName\" "
		"from \"LIBRARY\" "
		"where \"LibraryName\" = '%s';",
		library_name) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error, mm_get_library_status");
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (NULL);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR,
		    "row num mismatch, "
		    "mm_get_library_status");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}

	library_status = (mm_lib_stat_t *)calloc(1, sizeof (mm_lib_stat_t));
	if (library_status == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc library_status");
		return (NULL);
	}
	library_status->lib_stat_name =
		mms_strapp(library_status->lib_stat_name,
		    library_name);
	library_status->lib_stat_online =
		mms_strapp(library_status->lib_stat_online,
		    PQgetvalue(db->mm_db_results, 0, 0));
	library_status->lib_stat_disabled =
		mms_strapp(library_status->lib_stat_disabled,
		    PQgetvalue(db->mm_db_results, 0, 1));
	library_status->lib_stat_broken =
		mms_strapp(library_status->lib_stat_broken,
		    PQgetvalue(db->mm_db_results, 0, 2));
	library_status->lib_stat_lm =
		mms_strapp(library_status->lib_stat_lm,
		    PQgetvalue(db->mm_db_results, 0, 3));
	mm_clear_db(&db->mm_db_results);
	return (library_status);
}


static char *
mm_sql_get_ops(char *op)
{
	int		x;

	for (x = 0; x < num_ops; x++) {
		if (strcmp(opstab[x].sql_mmp_ops, op) == 0) {
			return (opstab[x].sql_ops);
		}
	}
	/* Not in table */
	return ("??UNKNOWN??");
}

int
mm_sql_chk_len(char **line, int off, int *bufsize, int len)
{
	char		*new;
	int		 new_bufsize;


	if (off + len < *bufsize) {
		return (0);
	}
	while (off + len > *bufsize) {
		new_bufsize = *bufsize + SQL_CMD_BUF_INCR;
		new = realloc(*line, new_bufsize);
		if (new == NULL) {
			return (-1);
		}
		*line = new;
		*bufsize = new_bufsize;
	}
	return (0);
}


int
mm_notify_delete(mm_db_t *db, mm_command_t *cmd, char *objname,
	int match_off)
{
	PGresult	*results;

	int		rows;
	int		row;


	mms_trace(MMS_DEVP, "mm_notify_delete, object %s", objname);

	/* get object instance */
	if (mm_db_exec(HERE, db, "SELECT \"%sName\", \"%sTargetHost\""
	    " FROM \"%s\" %s", objname, objname,
	    objname, &cmd->cmd_buf[match_off]) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (MM_CMD_ERROR);
	}

	results = db->mm_db_results;
	rows = PQntuples(results);

	if (rows == 0) {
		mms_trace(MMS_DEVP,
		    "Didn't match any %s's for delete", objname);
		mm_clear_db(&db->mm_db_results);
		return (INTRP_OK);
	}
	for (row = 0; row < rows; row ++) {
		mms_trace(MMS_DEVP,
		    "notify object %s instance %s",
		    objname,
		    PQgetvalue(results, row, 0));

		if (mm_notify_add_config(cmd->wka_ptr, cmd,
		    EVENT_CFG_DELETE,
		    objname,
		    PQgetvalue(results, row, 0),
		    PQgetvalue(results, row, 1))) {
			mms_trace(MMS_ERR,
			    "mm_notify_delete: "
			    "error adding config event");
		}

	}

	mm_clear_db(&db->mm_db_results);
	return (INTRP_OK);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}



int
mm_sql_notify_inst(mm_db_t *db, mm_command_t *cmd, char *objname,
	int match_off, char **objinst)
{
	PGresult	*results = db->mm_db_results;
	char		*value;



	mms_trace(MMS_DEVP, "sql notify inst, object %s", objname);

	*objinst = NULL;

	/* get object instance */
	if (mm_db_exec(HERE, db, "SELECT \"%sName\" FROM \"%s\" %s", objname,
	    objname, &cmd->cmd_buf[match_off]) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		db->mm_db_results = results;
		return (MM_CMD_ERROR);
	}

	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = results;
		return (INTRP_OK);
	}
	value = PQgetvalue(db->mm_db_results, 0, 0);
	if (value[0] == '\0') {
		*objinst = strdup("none"); /* none used for empty string */
	} else {
		*objinst = strdup(value);
	}
	mm_clear_db(&db->mm_db_results);
	db->mm_db_results = results;
	if (objinst == NULL) {
		MM_ABORT("object instance");
		return (MM_CMD_ERROR);
	}
	mms_trace(MMS_DEVP, "notify object %s instance %s", objname, *objinst);
	return (INTRP_OK);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}

void
mm_sql_report_write_value(char **buf, PGresult *results,
			int row, int col, mm_command_t *cmd,
			int reportmode) {

	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;

	/* 3 possible reportmode formatting */
	int			name_rt = 1;
	int			value_rt = 2;
	int			namevalue_rt = 3;

	Oid		 oid;
	char		*value;
	char		*name;

	char		 date[24];
	int		 i;
	int		 len;

	name = PQfname(results, col);
	value = PQgetvalue(results, row, col);
	oid = PQftype(results, col);

	/* database data types to mms string conversions */
	oid = PQftype(results, col);
	if (oid == db->mm_db_cfg->mm_db_bool_oid) {
		if (strcmp(value, "t") == 0) {
			value = "true";
		} else if (strcmp(value, "f") == 0) {
			value = "false";
		}
	} else if (oid == db->mm_db_cfg->mm_db_timestamp_oid) {
		if (strcmp(value, "-infinity") == 0) {
			/* mms time not set */
			value = "0000 00 00 00 00 00 000";
		} else {
			strcpy(date, value);
			value = date;
			/* mms UTC time format */
			value[4] = ' '; /* - */
			value[7] = ' '; /* - */
			value[13] = ' '; /* : */
			value[16] = ' '; /* : */
			if (value[19] == '\0') {
				value[20] = '\0';
			}
			value[19] = ' '; /* . */


			len = strlen(value);
			for (i = len; i < 23; i++) {
				value[i] = '0';
			}
			value[23] = '\0';
		}
	}
	if ((reportmode == name_rt) ||
	    (reportmode == namevalue_rt)) {
		/* add name */
		*(buf) = mms_strapp(*(buf),
				" \"%s\"",
				name);
	}
	if ((reportmode == value_rt) ||
	    (reportmode == namevalue_rt)) {
		*(buf) = mms_strapp(*(buf), " \"%s\"", value);
	}
	return;

}


char *
mm_sql_report_attr(mm_command_t *cmd,
		int row, int *col_count,
		int num_atts, int reportmode,
		PGresult *results) {

	int		col = *(col_count);
	int		start_col = *(col_count);

	char		*attr_buf = NULL;
	int			print = 0;

	if (print)
		mms_trace(MMS_DEVP,
		    "create attlist clause for row %d",
		    row);
	/* print the attr list for row starting with col_count */
	attr_buf = mms_strapp(attr_buf,
			"attrlist[");
	/* LINTED: */
	for (col; col < (start_col + num_atts); col ++) {
			mm_sql_report_write_value(&attr_buf,
						results, row,
						col, cmd,
						reportmode);
	}
	attr_buf = mms_strapp(attr_buf,
			"]");
	*(col_count) = col;
	return (attr_buf);

}

char *
mm_sql_report_text_row(mm_command_t *cmd,
		    int row, PGresult *results, int reportmode,
		    mms_list_t *format) {

	mm_char_list_t *cur;
	mm_char_list_t *next;

	char			*text_buf = NULL;
	char			*attr_buf = NULL;
	int			col_count = 0;

	int			print = 0;

	/* Create the text clause for the report in cmd */
	if (print)
		mms_trace(MMS_DEVP,
		    "create text clause for row %d",
		    row);

	/* First bracket for this text clause */
	text_buf = mms_strapp(text_buf, "text[");
	for (cur = mms_list_head(format);
	    cur != NULL;
	    cur = next) {
		next = mms_list_next(format, cur);
		if (cur->number == 0) {
			/* Do data base format conversion */
			/* The function will write into text buf */
			mm_sql_report_write_value(&text_buf,
						results, row,
						col_count, cmd,
						reportmode);
			col_count ++;
		} else {
			/* This is an attrlist clause */
			if ((attr_buf = mm_sql_report_attr(cmd,
							row, &col_count,
							cur->number, reportmode,
							results)) == NULL) {
				mms_trace(MMS_ERR,
				    "error setting atr_buf");
				if (text_buf)
					free(text_buf);
				return (NULL);
			}
			text_buf = mms_strapp(text_buf, "%s",
					attr_buf);
			free(attr_buf);


		}
	}

	/* Trailing bracket for this text text */
	text_buf = mms_strapp(text_buf, "]");

	return (text_buf);


}



int
mm_sql_format_report(mm_command_t *cmd, mms_par_node_t *report,
		mms_list_t *format) {

	mms_par_node_t		*report_work;
	mms_par_node_t		*report_work_next;
	mms_par_node_t		*object;
	mms_par_node_t		*object_next;


	/* 2 possible data types in report */
	int			data_type;
	int			obj_att = 1;
	int			att_list = 2;

	char			*cur_obj;
	char			*cur_attr;

	int			print = 0;
	int			num_atts = 0;
	mm_db_t		*db = &cmd->wka_ptr->mm_data->mm_db;

	/* Create the text clause for the report in cmd */
	if (print)
		mms_trace(MMS_DEVP,
		    "determine formatting for this report");

	data_type = 0;
	/* Need to use attr list for OBJECTS */
	report_work = NULL;
	for (object = mms_pn_lookup(report, NULL, NULL, &report_work);
	    object != NULL;
	    object = mms_pn_lookup(report, NULL, NULL, &report_work)) {
		if (object->pn_string != NULL) {
			if (print)
				mms_trace(MMS_DEVP,
				    "cur object is %s",
				    object->pn_string);
		}

		if (object->pn_type == MMS_PN_OBJ) {
			/* determine if attr list is needed */
			report_work_next = NULL;
			report_work_next = report_work;
			object_next = NULL;
			object_next =
				mms_pn_lookup(report, NULL, NULL,
						&report_work_next);

			if ((object_next != NULL) &&
			    (object_next->pn_type == MMS_PN_ATTR)) {
				/* don't need an attrlist */
				/* set the obj name */
				/* The next object will be an attribute */
				if (print)
					mms_trace(MMS_DEVP,
					    "set obj for obj.attr, %s",
					    object->pn_string);
				cur_obj = object->pn_string;
			} else {
				/* Need attr list */
				/* Write all name/values for this obj */
				if (print)
					mms_trace(MMS_DEVP,
					    "set obj for attr list, %s",
					    object->pn_string);
				cur_obj = object->pn_string;
				data_type = att_list;
			}
		}
		if (object->pn_type == MMS_PN_ATTR) {
			/* Write the name/value for this obj.att */
			if (print)
				mms_trace(MMS_DEVP,
				    "set attr for obj.attr, %s",
				    object->pn_string);
			cur_attr = object->pn_string;
			data_type = obj_att;
		}

		if (data_type == obj_att) {
			data_type = 0;
			/* This is an obj_att */
			(void) mm_add_int(0, format);
			if (print)
				mms_trace(MMS_DEVP,
				    "add 0 to int list %s.\"%s\"",
				    cur_obj, cur_attr);

		}
		if (data_type == att_list) {
			data_type = 0;
			/* This is an attr list */
			/* Determine the number of attributes */
			if (print)
				mms_trace(MMS_DEVP,
				    "set attr num for %s",
				    cur_obj);

			if (mm_db_exec(HERE, db,
				    "select * from \"%s\" limit 1;",
				    cur_obj) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "db error getting attribute number");
				mm_clear_db(&db->mm_db_results);
				db->mm_db_results = NULL;
				return (1);
			}
			num_atts = PQnfields(db->mm_db_results);
			if (print)
				mms_trace(MMS_DEVP,
				    "attr num is %d for %s",
				    num_atts,
				    cur_obj);
			(void) mm_add_int(num_atts, format);
			mm_clear_db(&db->mm_db_results);

		}



	}

	/* done */
	return (0);



}
int
mm_check_cmd_size(int header_length, char *text_clause, char *text_buf) {

	int buf_len;
	int clause_len;
	int char_size = sizeof (char);

	if (text_clause == NULL) {
		/* is the 1st text clause, this must fit */
		return (0);
	}
	if (text_buf == NULL) {
		return (0);
	}

	buf_len = strlen(text_buf);
	clause_len = strlen(text_clause);

	if ((char_size * (header_length + buf_len + clause_len)) >
	    MM_CMD_SIZE_LIMIT) {
		mms_trace(MMS_DEVP,
		    "header len == %d, buf len == %d, "
		    "clause len == %d, total == %d, "
		    "LIMIT == %d",
		    header_length, buf_len, clause_len,
		    header_length + buf_len + clause_len,
		    MM_CMD_SIZE_LIMIT);
		return (1);
	} else {
		return (0);
	}
}

static int
mm_sql_report(mm_command_t *cmd)
{
	mm_db_t			*db = &cmd->wka_ptr->mm_data->mm_db;
	mms_par_node_t		*report;
	mms_par_node_t		*reportmode;
	PGresult		*results;

	int			report_type = 2;
	int			name_rt = 1;
	int			namevalue_rt = 3;

	/* buf for whole response */
	char			*resp_buf = NULL;
	/* buf for multiple text clauses */
	char			*text_buf = NULL;
	/* buf for a single text clause */
	char			*text_clause = NULL;

	int			number_of_rows = 0;
	int			row;

	/* Report format */
	mms_list_t			format;

	/* CMD size limit */
	int			header_length;


	mms_trace(MMS_DEVP, "sql report");

	mms_list_create(&format, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));

	if (mm_db_exec(HERE, db, "%s;", cmd->cmd_buf) != MM_DB_DATA) {
		mm_sql_db_err_rsp_new(cmd, db);
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (1);
	}
	if (PQresultStatus(db->mm_db_results) != PGRES_TUPLES_OK) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(ECLASS_INTERNAL) + strlen(EDATABASE) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ERROR, cmd->cmd_task,
		    ECLASS_INTERNAL, EDATABASE);
		return (1);
	}

	number_of_rows = PQntuples(db->mm_db_results);
	mms_trace(MMS_DEVP, "number of rows is %d", number_of_rows);

	/* Only return info user wants. The default is value only. */
	reportmode = mms_pn_lookup(cmd->cmd_root, "reportmode",
	    MMS_PN_CLAUSE, NULL);

	if (reportmode && mms_pn_lookup(reportmode, "name",
	    MMS_PN_KEYWORD, NULL)) {
		report_type = name_rt;
	} else if (reportmode && mms_pn_lookup(reportmode, "namevalue",
	    MMS_PN_KEYWORD, NULL)) {
		report_type = namevalue_rt;
	} else if (reportmode && mms_pn_lookup(reportmode, "number",
	    MMS_PN_KEYWORD, NULL)) {
		/* Generate a the number report and return */
		text_buf = mms_strapp(text_buf,
		    "text[\"%d\"]",
		    number_of_rows);
		if (cmd->cmd_buf != NULL) {
			free(cmd->cmd_buf);
			cmd->cmd_buf = NULL;
		}
		cmd->cmd_buf = mms_strapp(cmd->cmd_buf,
		    RESPONSE_SUCCESS_STR,
		    cmd->cmd_task,
		    text_buf);
		free(text_buf);
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_DEVP, "\n\n%s\n", cmd->cmd_buf);
		return (0);

	}

	/* Build the text report */
	/* there will be a text clause for each of the rows */
	results = db->mm_db_results;

	report = mms_pn_lookup(cmd->cmd_root, "report",
	    MMS_PN_CLAUSE, NULL);
	if (report == NULL) {
		/* no report clause */
		/* there will be no text clause in response */
		number_of_rows = 0;
	} else {
		/* Determine the formatting for the entire report */
		if (mm_sql_format_report(cmd, report, &format)) {
			mms_trace(MMS_ERR,
			    "error determineing report format");
			mm_system_error(cmd,
			    "error determineing report format");
			mm_clear_db(&results);
			return (1);
		}
	}
	if (number_of_rows != 0) {
		/* There will be text clauses */
		header_length = strlen(RESPONSE_INTERMEDIATE) +
		    strlen(cmd->cmd_task);
		mms_trace(MMS_DEVP,
		    "response header size is %d",
		    header_length);
	}

	for (row = 0; row < number_of_rows; row++) {
		text_clause = NULL;

		if ((text_clause = mm_sql_report_text_row(cmd, row, results,
		    report_type,
		    &format)) == NULL) {
			mms_trace(MMS_ERR,
			    "error generating text clause");
			mm_system_error(cmd,
			    "error generating text clause");
			mm_clear_db(&results);
			return (1);

		}

		/* Check the MM_CMD_SIZE_LIMIT */
		/* before appending the next text clause */
		/* this command may need intermediate packets */
		if (mm_check_cmd_size(header_length, text_clause, text_buf)) {

			mm_char_list_t *node;

			/* This text clause will push response over limit */
			mms_trace(MMS_DEVP,
			    "command size over the limit");
			/* add the curr text buf to the response list */
			if (resp_buf)
				free(resp_buf);
			resp_buf = NULL;
			resp_buf = mms_strapp(resp_buf, RESPONSE_INTERMEDIATE,
			    cmd->cmd_task,
			    text_buf);

			node =
			    (mm_char_list_t *)malloc(sizeof (mm_char_list_t));
			if (node == NULL) {
				mms_trace(MMS_ERR,
				    "Error malloc response object");
				mm_clear_db(&results);
				return (1);
			} else {
				memset(node, 0, sizeof (mm_char_list_t));
				node->text = NULL;
				node->text = resp_buf;
				mms_list_insert_tail(&cmd->cmd_resp_list, node);
				resp_buf = NULL;
			}

			if (text_buf)
				free(text_buf);
			text_buf = NULL;
		}
		text_buf = mms_strapp(text_buf,
		    text_clause);
		if (text_clause)
			free(text_clause);
		text_clause = NULL;

	}

	/* clean up formatting */
	mm_free_list(&format);
	mms_list_destroy(&format);

	if (number_of_rows == 0) {
		mm_char_list_t	*node;

		/* add the curr text buf to the response list */
		if (resp_buf)
			free(resp_buf);
		resp_buf = NULL;
		resp_buf = mms_strapp(resp_buf, RESPONSE_SUCCESS,
		    cmd->cmd_task);

		node =
		    (mm_char_list_t *)malloc(sizeof (mm_char_list_t));
		if (node == NULL) {
			mms_trace(MMS_ERR, "Error malloc response object");
			mm_clear_db(&results);
			return (1);
		} else {
			memset(node, 0, sizeof (mm_char_list_t));
			node->text = NULL;
			node->text = resp_buf;
			mms_list_insert_tail(&cmd->cmd_resp_list, node);
			resp_buf = NULL;
		}

		/* Set the success response  with no text */
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS) +
		    strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
	} else {
		mm_char_list_t *node;
		/* add the curr text buf to the response list */
		if (resp_buf)
			free(resp_buf);
		resp_buf = NULL;
		resp_buf = mms_strapp(resp_buf, RESPONSE_SUCCESS_STR,
		    cmd->cmd_task,
		    text_buf);

		node = (mm_char_list_t *)malloc(sizeof (mm_char_list_t));
		if (node == NULL) {
			mms_trace(MMS_ERR, "Error malloc response object");
			mm_clear_db(&results);
			return (1);
		} else {
			memset(node, 0, sizeof (mm_char_list_t));
			node->text = NULL;
			node->text = resp_buf;
			mms_list_insert_tail(&cmd->cmd_resp_list, node);
			resp_buf = NULL;
		}

		/* Set the success response  with a text */
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS_STR) + strlen(cmd->cmd_task) +
		    strlen(text_buf) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS_STR, cmd->cmd_task, text_buf);
	}

	if (text_buf)
		free(text_buf);
	mm_clear_db(&results);
	return (0);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);

}


static void
mm_sql_trans_volname(mm_command_t *cmd, int *offset)
{
	mms_par_node_t	*volname;
	mms_par_node_t	*arg;
	int		 off = *offset;


	mms_trace(MMS_DEVP, "sql trans volname");
	MMS_PN_LOOKUP(volname, cmd->cmd_root, "volname",
	    MMS_PN_CLAUSE, NULL);

	SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize, 1);
	off += snprintf(cmd->cmd_buf + off, cmd->cmd_bufsize - off, "(");

	mms_list_foreach(&volname->pn_arglist, arg) {
		SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
		    28 + strlen(arg->pn_string));
		off += snprintf(cmd->cmd_buf + off, cmd->cmd_bufsize - off,
		    "(\"VOLUME\".\"VolumeName\" = '%s')",
		    arg->pn_string);
		if (arg != mms_list_tail(&volname->pn_arglist)) {
			SQL_CHK_LEN(&cmd->cmd_buf, off,
			    &cmd->cmd_bufsize, 4);
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off, " OR ");
		}
	}
	SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize, 1);
	off += snprintf(cmd->cmd_buf + off, cmd->cmd_bufsize - off, ")");

	*offset = off;
	return;

no_mem:
	MM_ABORT_NO_MEM();
	return;

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	return;

}

int
mm_make_constraint_helper(mms_par_node_t *node, mm_command_t *cmd,
			    int num, char **buf, int *offset,
			    int *bufsize, int current, int reg_ex) {

	mms_par_node_t	*arg;
	mms_par_node_t	*next_arg;
	int		 off = *offset;
	int		b_size = *bufsize;
	char		*sql_ops;
	const char	*att_test;
	char 		*att_cond;
	char		*obj;
	char		*att;
	int cur = current;
	int regex = reg_ex;
	int twice = 0;



	mms_trace(MMS_DEVP, "constraint helper -> num -> %d "	\
	    " current -> %d", num, current);

	if (node->pn_string != NULL) {
		mms_trace(MMS_DEVP, "1 Object is %s", node->pn_string);
		if (strcmp(node->pn_string, "regex") ==  0) {
			regex = 1;
		}
	}

	if (*buf != NULL) {
		mms_trace(MMS_DEVP, "1)%s", *buf);

	}


	if (node->pn_type & MMS_PN_STRING) {
		if (cur == num) {

		/* Could be numeric or null string or string. */
		if (node->pn_type == MMS_PN_NUMERIC) {

			SQL_CHK_LEN(buf, off, &b_size,
				    1 + strlen(node->pn_string));
			off += snprintf(*buf + off, b_size - off,
				    "%s", node->pn_string);


		} else if (node->pn_type & MMS_PN_NULLSTR) {
		    if (strcmp(*buf + off - 3, " = ") == 0) {

			off -= 2; /* backup over operator */
			SQL_CHK_LEN(buf, off, &b_size, 7);
			off += snprintf(*buf + off, b_size - off, "ISNULL");

		    } else if (strcmp(*buf + off - 4, " <= ") == 0 ||
				strcmp(*buf + off - 4, " >= ") == 0) {

			off -= 3; /* backup over operator */
			SQL_CHK_LEN(buf, off, &b_size, 7);
			off += snprintf(*buf + off, b_size - off, "ISNULL");

		    } else if (strcmp(*buf + off - 4, " <> ") == 0) {

			off -= 3; /* backup over operator */
			SQL_CHK_LEN(buf, off, &b_size, 8);
			off += snprintf(*buf + off, b_size - off, "NOTNULL");
		    } else {
			SQL_CHK_LEN(buf, off, &b_size,
				    1 + strlen(node->pn_string));
			off += snprintf(*buf + off, b_size - off,
				    "%s", node->pn_string);
		    }
		} else {
			SQL_CHK_LEN(buf, off, &b_size,
				    3 + strlen(node->pn_string));
			off += snprintf(*buf + off, b_size - off,
				    "'%s'", node->pn_string);
		}
		}
		if (!regex)
			cur ++;
			/* Just Worte a constraint value */
	}


	if (node->pn_type == MMS_PN_OBJ) {

		/* An object-attribute */
		twice = 0;
	if (cur == num) {
		if (*buf != NULL) {
			twice = 1;
		}
		SQL_CHK_LEN(buf, off, &b_size,
			    4 + strlen(node->pn_string));
		off += snprintf(*buf + off, b_size - off,
			    "\"%s\".", node->pn_string);
	}
		arg = mms_list_head(&node->pn_arglist);
	if (cur == num) {
		SQL_CHK_LEN(buf, off, &b_size,
			    3 + strlen(arg->pn_string));
		off += snprintf(*buf + off, b_size - off,
			    "\"%s\"", arg->pn_string);
		if (regex)
			cur ++;
		if (twice)
			cur ++;
	}

	} else if (node->pn_flags & MMS_PN_MULTIOPS) {

		/*
		 * A multiops has two or more args hanging off the arglist.
		 * Insert the ops between the args by adding an arg, then add
		 * the ops and repeat until the last arg.
		 */
		if (node->pn_flags & MMS_PN_REGEX) {

			/* sql regular expression is at end of list */
			arg = mms_list_head(&node->pn_arglist);
			mms_list_remove(&node->pn_arglist, arg);
			mms_list_insert_tail(&node->pn_arglist, arg);
		}
		mms_list_foreach(&node->pn_arglist, arg) {
			cur = mm_make_constraint_helper(arg, cmd,
							num, buf, &off,
							&b_size, cur, regex);

			if (arg != mms_list_tail(&node->pn_arglist)) {

				sql_ops = mm_sql_get_ops(node->pn_string);
				if ((strcmp(sql_ops, "AND") == 0) ||
				    (strcmp(sql_ops, "OR") == 0) ||
				    (strcmp(sql_ops, "NOT") == 0) ||
				    (strcmp(sql_ops, "ASC") == 0) ||
				    /* LINTED: dont change */
				    (strcmp(sql_ops, "DESC") == 0)) {
				} else {
					if (cur == num) {
				SQL_CHK_LEN(buf, off,
					    &b_size,
					    3 + strlen(sql_ops));
				off += snprintf(*buf + off, b_size - off,
					    " %s ", sql_ops);
					}
				}
			}

		}
		if (node->pn_flags & MMS_PN_REGEX) {
			/* restore list to original order */
			arg = mms_list_tail(&node->pn_arglist);
			mms_list_remove(&node->pn_arglist, arg);
			mms_list_insert_head(&node->pn_arglist, arg);
		}
	} else if (node->pn_flags & MMS_PN_UNARYOPS) {

		/* Unary ops has only one arg */
		if (strcmp(node->pn_string, "isattr") == 0 ||
		    strcmp(node->pn_string, "noattr") == 0) {

			att_test = "mm_obj_has_att('%s','%s') = '%s'";

			if (strcmp(node->pn_string, "isattr") == 0) {
				att_cond = "true";
			} else {
				att_cond = "false";
			}

			arg = mms_list_head(&node->pn_arglist);
			obj = arg->pn_string;

			next_arg = mms_list_head(&arg->pn_arglist);
			att = next_arg->pn_string;
	if (cur == num) {
			SQL_CHK_LEN(buf, off, &b_size,
				strlen(att_test) + 1);
			off += snprintf(*buf + off, b_size - off,
				att_test, obj, att, att_cond);
	}
		} else {
			sql_ops = mm_sql_get_ops(node->pn_string);
	if (cur == num) {
			SQL_CHK_LEN(buf, off, &b_size,
				    strlen(sql_ops) + 3);
			off += snprintf(*buf + off, b_size - off,
				    " %s ", sql_ops);
	}
			arg = mms_list_head(&node->pn_arglist);
			cur = mm_make_constraint_helper(arg, cmd,
							num, buf, &off,
							&b_size, cur, regex);
		}
	}
	*offset = off;
	*bufsize = b_size;

	return (cur);

no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

not_found:

	return (MM_CMD_ERROR);
}

char *
mm_make_constraint(mm_command_t *cmd, int num) {
	char *object;
	char *buf = NULL;
	mms_par_node_t	*match;
	mms_par_node_t	*node;
	int off = 0;
	int bufsize = 0;
	int cur = 0;


	mms_trace(MMS_DEBUG, "mm_make_constraint");

	object = (char *)mm_return_char(&cmd->cmd_dest_list, num);


	match = mms_pn_lookup(cmd->cmd_root, "match",
				MMS_PN_CLAUSE, NULL);
	if (match == NULL) {
		return (NULL);
	}


	mms_list_foreach(&match->pn_arglist, node) {

		mms_trace(MMS_DEVP, "examing a node...");

		off = 0;
		bufsize = 0;
		cur = mm_make_constraint_helper(node, cmd, num, &buf, &off,
						&bufsize, cur, 0);

		mms_trace(MMS_DEVP, "After helper...");

	}
	if (buf != NULL) {
		mms_trace(MMS_DEVP, "Final Constraint for %s -> %s",
		    object, buf);
	} else {
		mms_trace(MMS_DEVP, "Final for %s is NULL",
		    object);
		return (NULL);
	}

	return (buf);
}
int
mm_use_and_or(mm_command_t *cmd) {
	/*
	 * return 1 if the operator is 'and'
	 * between constraints with indexes 'idx1' and 'idx2'
	 * return 0 if the operator is 'or'
	 */
	mms_par_node_t	*match;
	mms_par_node_t	*node;
	int oper = 1;

	match = mms_pn_lookup(cmd->cmd_root, "match",
				MMS_PN_CLAUSE, NULL);
	if (match == NULL) {
		return (NULL);
	}


	mms_list_foreach(&match->pn_arglist, node) {

		mms_trace(MMS_DEVP, "examing a node...");
		if (node->pn_string != NULL) {
			mms_trace(MMS_DEVP, " Node is %s", node->pn_string);
			if (strcmp(node->pn_string, "and") ==  0) {
				oper = 1;
			}
			if (strcmp(node->pn_string, "or") ==  0) {
				oper = 0;
			}
		}

	}
	return (oper);
}

int
mm_sql_report_func(mm_command_t *cmd, mm_db_t *db) {
	char *buf = NULL;
	mm_path_t *path = NULL;
	char *joined[100];
	int joined_count = 0;
	int skip = 0;
	int wrote_one = 0;

	char *source_buf;
	char *dest_buf;
	char *savepoint = NULL;

	int print_message = 0;
	int i;
	int y;
	int j;
	int k;
	int x;
	int l;

	mms_trace(MMS_DEBUG, "mm_sql_make_sql_func");

	for (y = 0; y < 100; y ++) {
		joined[y] = NULL;
	}

	/* create report functins for each report onject */
	for (i = 0; i < cmd->cmd_source_num; i ++) { /* source */
		joined_count = 0;
		/* Make report_n() for this source */

		source_buf =
			(char *)mm_return_char(&cmd->cmd_source_list, i);
		buf = mms_strapp(buf,
			    "CREATE OR REPLACE FUNCTION "\
			    "report_%d_%d() RETURNS SETOF \"%s\" AS $$\n",
			    i, db->mm_db_fd, source_buf);
		buf = mms_strapp(buf,
			    "select distinct \"%s\".* from \"%s\" ",
			    source_buf,
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

		if (cmd->cmd_dest_num == 0) {
			buf = mms_strapp(buf,
				    ";\n");
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
					int p;
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
							    ");\n");
					} else {
						buf = mms_strapp(buf,
							    ";\n");
					}
				}

		}


		buf = mms_strapp(buf,
			    "$$ LANGUAGE SQL;\n");

		savepoint = mms_strnew("report_%d_%d", i, db->mm_db_fd);
		if (mm_db_txn_savepoint(db, savepoint) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_sql_report_func: "
			    "db error setting savepoint");
		}
		if (mm_db_exec(HERE, db, "drop function report_%d_%d();", i,
			    db->mm_db_fd) !=
		    MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			if (mm_db_txn_savepoint_rollback(db,
			    savepoint) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_sql_report_func: "
				    "db error rollingback savepoint");
			}
		}
		if (mm_db_txn_release_savepoint(db,
		    savepoint) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_sql_report_func: "
			    "db error releaseing savepoint");
		}
		free(savepoint);

		if (mm_db_exec(HERE, db, buf) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error adding path match function");
			mm_sql_db_err_rsp_new(cmd, db);
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			free(buf);
			return (1);
		}
		free(buf);
		buf = NULL;

		for (y = 0; y < joined_count; y ++) {
			free(joined[y]);
			joined[y] = NULL;
		}


	}
	return (0);

}

int
mm_sql_report_func_attr(mm_command_t *cmd) {
	char *buf = NULL;
	char *order_buf = NULL;
	mm_path_t *path = NULL;
	char *joined[100];
	int joined_count = 0;
	int skip = 0;
	mm_db_t	*db = &cmd->cmd_mm_data->mm_db;
	int wrote_one = 0;
	char *temp_buf = NULL;
	char *savepoint = NULL;

	char *source_buf;
	char *dest_buf;
	int y;
	int j;
	int k;
	int x;
	int l;
	int p;
	int i;

	mms_trace(MMS_DEBUG, "mm_sql_make_sql_func_attr");

	for (y = 0; y < 100; y ++) {
		joined[y] = NULL;
	}

	/* create report functins for each report onject */
	for (i = 0; i < cmd->cmd_source_num; i ++) { /* source */
		joined_count = 0;

		/* Make report_n() for this source */

		source_buf =
			(char *)mm_return_char(&cmd->cmd_source_list, i);
		buf = mms_strapp(buf,
			    "CREATE OR REPLACE FUNCTION "\
			    "report_%d_%d() RETURNS SETOF \"%s\" AS $$\n",
			    i, db->mm_db_fd, source_buf);
		buf = mms_strapp(buf,
			    "select distinct \"%s\".* from \"%s\" ",
			    source_buf,
			    source_buf);
		joined_count = 0;
		joined[0] = NULL;
		joined[0] = mms_strapp(joined[0], source_buf);


		joined_count ++;
		for (j = 0; j < cmd->cmd_dest_num; j ++) {
			dest_buf =
				(char *)mm_return_char(&cmd->cmd_dest_list, j);

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

		order_buf = mm_sql_order_buf(cmd);
		buf = mms_strapp(buf, order_buf);
		if (order_buf != NULL)
			free(order_buf);

		for (j = 0; j < cmd->cmd_dest_num; j ++) {
			dest_buf =
				(char *)mm_return_char(&cmd->cmd_dest_list, j);
			/* j cmd_dest_num */
			if (j == 0) {
				buf = mms_strapp(buf,
					    "\nwhere \n(\n");

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

		temp_buf = mms_strapp(temp_buf, mm_sql_number_buf(cmd));
		if (temp_buf != NULL) {
			buf = mms_strapp(buf, temp_buf);
			free(temp_buf);
		}

		buf = mms_strapp(buf,
			    " ; $$ LANGUAGE SQL;\n");


		savepoint = mms_strnew("report_%d_%d", i, db->mm_db_fd);
		if (mm_db_txn_savepoint(db,
		    savepoint) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_sql_report_func_attr: "
			    "db error setting savepoint");
		}
		if (mm_db_exec(HERE, db, "drop function report_%d_%d();", i,
			    db->mm_db_fd) !=
		    MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			if (mm_db_txn_savepoint_rollback(db,
			    savepoint) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_sql_report_func_attr: "
				    "db error setting savepoint");
			}
		}
		if (mm_db_txn_release_savepoint(db,
		    savepoint) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_sql_report_func_attr: "
			    "db error releaseing savepoint");
		}
		free(savepoint);

		if (mm_db_exec(HERE, db, buf) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			mms_trace(MMS_ERR, "Error adding path match function");
			return (1);
		}
		free(buf);
		buf = NULL;

		for (y = 0; y < joined_count; y ++) {
			free(joined[y]);
			joined[y] = NULL;
		}


	}
	return (0);
}


int
mm_sql_from_where(mm_command_t *cmd, mm_db_t *db)
{
	char *buf = NULL;
	char *final_buf = NULL;
	mm_path_t *path = NULL;
	char *joined[100];
	int joined_count = 0;
	int skip = 0;
	mm_pkey_t *p_key = NULL;

	char *source_buf_i;
	char *source_buf_j;
	int y;
	int i;
	int j;
	int k;
	int x;
	int l;

	mms_trace(MMS_DEVP, "mm_sql_from_where");

	for (y = 0; y < 100; y ++) {
		joined[y] = NULL;
	}
	/* Generate all report_n() for this command */

	if (mm_sql_report_func(cmd, db)) {
		mms_trace(MMS_ERR,
		    "error creating report funcs");
		return (1);
	}

	joined_count = 0;

	for (i = 0; i < cmd->cmd_source_num; i ++) {

		/*
		 * ex, i = 0
		 * report_0() t0, "DM"
		 * t0 is arbitrary table alias
		 */
		source_buf_i = (char *)mm_return_char(&cmd->cmd_source_list, i);
		buf = mms_strapp(buf,
		    "\nreport_%d_%d() t%d, \"%s\" ",
		    i, db->mm_db_fd, i, source_buf_i);
		joined[i] = NULL;
		joined[i] = mms_strapp(joined[i],
		    source_buf_i);
		joined_count ++;

		if (i+1 < cmd->cmd_source_num) {
			buf = mms_strapp(buf,
			    "cross join ");
		}
	}

	/* Add objects to FROM clause */
	/* add implied constraints between source objects */


	for (i = 0; i < cmd->cmd_source_num; i ++) {
		source_buf_i = (char *)mm_return_char(&cmd->cmd_source_list, i);
		for (j = i+1; j < cmd->cmd_source_num; j ++) {
			source_buf_j = (char *)
			    mm_return_char(&cmd->cmd_source_list, j);
			if ((path = mm_get_path(source_buf_j,
			    source_buf_i)) != NULL) {

				for (k = 0; k < path->mm_node_num; k++) {
					skip = 0;
					for (x = 0; x < joined_count; x++) {

						if (strcmp(joined[x],
						    path->mm_node[k]->
						    mm_obj) == 0) {
							/* same so skip */
							skip = 1;
						}
					}
				if (!skip) {
					buf = mms_strapp(buf,
					    "\ncross join \n\"%s\" ",
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
	}

	buf = mms_strapp(buf, "\nwhere \n(\n");

	for (i = 0; i < cmd->cmd_source_num; i ++) {
		source_buf_i = (char *)mm_return_char(&cmd->cmd_source_list, i);
		p_key = mm_get_pkey(source_buf_i);
		for (j = 0; j < p_key->mm_att_num; j ++) {
			buf = mms_strapp(buf,
			    "(t%d.\"%s\" = \"%s\".\"%s\")\n",
			    i, p_key->mm_att[j], source_buf_i,
			    p_key->mm_att[j]);
			if (j+1 < p_key->mm_att_num) {
				buf = mms_strapp(buf, "and\n");
			}
		}
		if (i+1 < cmd->cmd_source_num) {
			buf = mms_strapp(buf, "and\n");
		}
	}


	/* Now add the implied path constraints */

	for (i = 0; i < cmd->cmd_source_num; i ++) {
		source_buf_i = (char *)mm_return_char(&cmd->cmd_source_list, i);
		for (j = i+1; j < cmd->cmd_source_num; j ++) {
			source_buf_j = (char *)
			    mm_return_char(&cmd->cmd_source_list, j);
			if ((path = mm_get_path(source_buf_j,
			    source_buf_i)) != NULL) {
			for (k = path->mm_node_num - 1; k >= 0; k--) {
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
					/* will always need an 'and' */
					buf = mms_strapp(buf, "and\n");
					if (k == path->mm_node_num - 1) {
						buf = mms_strapp(buf,
						    "(\"%s\".",
						    source_buf_i);
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
				}
			}
			}
		}
	}

	buf = mms_strapp(buf, ")\n");

	final_buf = mms_strapp(final_buf, cmd->cmd_buf);
	final_buf = mms_strapp(final_buf, buf);

	SQL_CHK_LEN(&cmd->cmd_buf, NULL,
	    &cmd->cmd_bufsize, strlen(final_buf) + 1);
	strcpy(cmd->cmd_buf, final_buf);


	for (y = 0; y < joined_count; y ++) {
		free(joined[y]);
		joined[y] = NULL;
	}
	free(buf);
	free(final_buf);
	return (0);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);


}



int
mm_attribute_match(mm_command_t *cmd) {

	char *buf = NULL;
	mm_db_t	*db = &cmd->cmd_mm_data->mm_db;
	mm_pkey_t *p_key = NULL;

	int j;
	int i;

	char *source_buf_0;

	mms_trace(MMS_DEBUG, "mm_attribute_match");
	buf = mms_strapp(buf, cmd->cmd_buf);
	mms_trace(MMS_DEVP, "buf is %s",
	    buf);

	buf = mms_strapp(buf, "\nwhere\n");
	/* get pkey for this source */
	source_buf_0 = (char *)mm_return_char(&cmd->cmd_source_list, 0);
	p_key = mm_get_pkey(source_buf_0);
	buf = mms_strapp(buf, "(\n");

	for (j = 0; j < p_key->mm_att_num; j ++) {
		buf = mms_strapp(buf,
			    "(\"%s\".\"%s\" in \n",
			    source_buf_0,
			    p_key->mm_att[j]);
		buf = mms_strapp(buf,
			    "(select \"%s\".\"%s\" from "\
			    "report_0_%d() t%d, \"%s\" where\n",
			    source_buf_0,
			    p_key->mm_att[j],
			    db->mm_db_fd,
			    j,
			    source_buf_0);

		buf = mms_strapp(buf, "(\n");
		for (i = 0; i < p_key->mm_att_num; i ++) {

			buf = mms_strapp(buf,
				    "(t%d.\"%s\" = \"%s\".\"%s\") ",
				    j,
				    p_key->mm_att[i],
				    source_buf_0,
				    p_key->mm_att[i]);

			if (i+1 < p_key->mm_att_num) {
				buf = mms_strapp(buf, "and\n");
			}
		}
		buf = mms_strapp(buf, ")\n");
		buf = mms_strapp(buf, ")\n");
		buf = mms_strapp(buf, ")\n");
		if (j+1 < p_key->mm_att_num) {
			buf = mms_strapp(buf, "and\n");
		}
	}

	buf = mms_strapp(buf, ")\n");


	SQL_CHK_LEN(&cmd->cmd_buf, NULL,
		    &cmd->cmd_bufsize, strlen(buf) + 1);
	strcpy(cmd->cmd_buf, buf);

	free(buf);

	return (INTRP_OK);



no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);

}

static int
mm_sql_trans_match_exp(mms_par_node_t *node, mm_command_t *cmd,
    int *offset, int host_ident)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*next_arg;
	int		 off = *offset;
	char		*sql_ops;
	const char	*att_test;
	char		*att_cond;
	char		*obj;
	char		*att;

	int		need_int_cast = 0;
	int		need_host_ident = 0;

	int		print_message = 0;

	mms_trace(MMS_DEVP, "sql trans match exp");
	if (cmd->cmd_buf != NULL) {
		if (print_message)
		mms_trace(MMS_DEVP,
		    "    cmdbuf == %s",
		    cmd->cmd_buf);
	} else {
		if (print_message)
			mms_trace(MMS_DEVP,
			    "    cmd_buf is NULL");
	}

	if (node->pn_type & MMS_PN_STRING) {
		if (print_message)
			mms_trace(MMS_DEVP,
			    " (node->pn_type & MMS_PN_STRING)");

		/* Could be numeric or null string or string. */
		if (node->pn_type == MMS_PN_NUMERIC) {
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    1 + strlen(node->pn_string));
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    "%s", node->pn_string);
		} else if (node->pn_type & MMS_PN_NULLSTR) {
			/* Still support NULLSTR ?? */
			if (strcmp(&cmd->cmd_buf[off - 3], " = ") == 0) {
				off -= 2; /* backup over operator */
				SQL_CHK_LEN(&cmd->cmd_buf,
				    off, &cmd->cmd_bufsize, 7);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, "ISNULL");
			} else if (strcmp(&cmd->cmd_buf[off - 4],
			    " <= ") == 0 ||
			    strcmp(&cmd->cmd_buf[off - 4],
			    " >= ") == 0) {
				off -= 3; /* backup over operator */
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 7);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, "ISNULL");
			} else if (strcmp(&cmd->cmd_buf[off - 4],
			    " <> ") == 0) {
				off -= 3; /* backup over operator */
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 8);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, "NOTNULL");
			} else {
				SQL_CHK_LEN(&cmd->cmd_buf,
				    off, &cmd->cmd_bufsize,
				    1 + strlen(node->pn_string));
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    "%s", node->pn_string);
			}
		} else {
			if (host_ident) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 15);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    "pg_host_ident(");
			}
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    3 + strlen(node->pn_string));
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    "'%s'", node->pn_string);
			if (host_ident) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 2);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, ")");
			}
		}

	}

	if (node->pn_type == MMS_PN_OBJ) {
		if (print_message)
			mms_trace(MMS_DEVP,
			    " node->pn_type == MMS_PN_OBJ");

		/* An object-attribute */
		if (cmd->cmd_notify_to == 1) {
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    2 + strlen("NEW"));
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off, "%s.", "NEW");
		} else {
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    4 + strlen(node->pn_string));
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    "\"%s\".", node->pn_string);
		}
		arg = mms_list_head(&node->pn_arglist);
		SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
		    3 + strlen(arg->pn_string));
		off += snprintf(cmd->cmd_buf + off,
		    cmd->cmd_bufsize - off,
		    "\"%s\"", arg->pn_string);
	} else if (node->pn_flags & MMS_PN_MULTIOPS) {

		if (print_message)
			mms_trace(MMS_DEVP,
			    "(node->pn_flags & MMS_PN_MULTIOPS)");
		if (node->pn_string != NULL) {
			if ((strcmp(node->pn_string,
			    "numeq") == 0) ||
			    (strcmp(node->pn_string,
			    "numne") == 0) ||
			    (strcmp(node->pn_string,
			    "numlt") == 0) ||
			    (strcmp(node->pn_string,
			    "numle") == 0) ||
			    (strcmp(node->pn_string,
			    "numgt") == 0) ||
			    (strcmp(node->pn_string,
			    "numge") == 0)) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 6);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, "int4(");
				need_int_cast = 1;
			}
			if (print_message)
				mms_trace(MMS_DEVP,
				    "    %s",
				    node->pn_string);
			if ((strcmp(node->pn_string,
			    "hosteq") == 0) ||
			    (strcmp(node->pn_string,
			    "hostne") == 0)) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 15);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    "pg_host_ident(");
				need_int_cast = 1;
				need_host_ident = 1;
			}
		}

		/*
		 * A multiops has two or more args hanging off the arglist.
		 * Insert the ops between the args by adding an arg, then add
		 * the ops and repeat until the last arg.
		 */
		if (node->pn_flags & MMS_PN_REGEX) {
			/* sql regular expression is at end of list */
			arg = mms_list_head(&node->pn_arglist);
			mms_list_remove(&node->pn_arglist, arg);
			mms_list_insert_tail(&node->pn_arglist, arg);
		}
		mms_list_foreach(&node->pn_arglist, arg) {
			if (arg->pn_type == MMS_PN_OPS) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 2);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, "(");
			}

			if (mm_sql_trans_match_exp(arg, cmd,
			    &off, need_host_ident)) {
				mms_trace(MMS_ERR,
				    "mm_sql_trans_match_exp: "
				    "error translating match expression");
				return (1);
			}
			if (arg->pn_type == MMS_PN_OPS) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 2);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, ")");
			}
			if (need_int_cast) {
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize, 2);
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off, ")");
				need_int_cast = 0;
			}
			if (arg != mms_list_tail(&node->pn_arglist)) {
				sql_ops = mm_sql_get_ops(node->pn_string);
				SQL_CHK_LEN(&cmd->cmd_buf, off,
				    &cmd->cmd_bufsize,
				    3 + strlen(sql_ops));
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    " %s ", sql_ops);
			}
		}

		if (node->pn_flags & MMS_PN_REGEX) {
			/* restore list to original order */
			arg = mms_list_tail(&node->pn_arglist);
			mms_list_remove(&node->pn_arglist, arg);
			mms_list_insert_head(&node->pn_arglist, arg);
		}
	} else if (node->pn_flags & MMS_PN_UNARYOPS) {
		if (print_message)
			mms_trace(MMS_DEVP,
			    "(node->pn_flags & MMS_PN_UNARYOPS)");

		/* Unary ops has only one arg */
		if (strcmp(node->pn_string, "isset") == 0 ||
		    strcmp(node->pn_string, "notset") == 0) {
			arg = mms_list_head(&node->pn_arglist);

			if (mm_sql_trans_match_exp(arg, cmd,
			    &off, need_host_ident)) {
				mms_trace(MMS_ERR,
				    "mm_sql_trans_match_exp: "
				    "error translating match expression");
				return (1);
			}
			if (strcmp(node->pn_string, "isset") == 0) {
				/* isset */
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    " IS NOT NULL");
			} else {
				/* notnot */
				off += snprintf(cmd->cmd_buf + off,
				    cmd->cmd_bufsize - off,
				    " ISNULL");
			}


		} else if (strcmp(node->pn_string, "isattr") == 0 ||
		    strcmp(node->pn_string, "noattr") == 0) {

			att_test = "mm_obj_has_att('%s','%s') = '%s'";

			if (strcmp(node->pn_string, "isattr") == 0) {
				att_cond = "true";
			} else {
				att_cond = "false";
			}

			arg = mms_list_head(&node->pn_arglist);
			obj = arg->pn_string;

			next_arg = mms_list_head(&arg->pn_arglist);
			att = next_arg->pn_string;

			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    strlen(att_test) + 1);
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    att_test, obj, att, att_cond);

		} else {
			sql_ops = mm_sql_get_ops(node->pn_string);
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    strlen(sql_ops) + 3);
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    " %s ", sql_ops);
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize, 2);
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off, "(");
			arg = mms_list_head(&node->pn_arglist);

			if (mm_sql_trans_match_exp(arg, cmd,
			    &off, need_host_ident)) {
				mms_trace(MMS_ERR,
				    "mm_sql_trans_match_exp: "
				    "error translating match expression");
				return (1);
			}
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize, 2);
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off, ")");
		}
	}
	*offset = off;
	return (0);

no_mem:
	MM_ABORT_NO_MEM();
	return (1);

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	return (1);

}


void
mm_sql_number(mm_command_t *cmd)
{


	char		*buf = NULL;
	char		*final_buf = NULL;
	char		*number_buf = NULL;

	mms_trace(MMS_DEVP, "mm_sql_number");
	/* This function will append the number buf to cmd_buf */

	number_buf = mm_sql_number_buf(cmd);

	buf = mms_strapp(buf, number_buf);

	if (number_buf != NULL)
		free(number_buf);

	if (buf == NULL) {
		return;
	}

	final_buf = mms_strapp(final_buf, cmd->cmd_buf);
	final_buf = mms_strapp(final_buf, buf);

	SQL_CHK_LEN(&cmd->cmd_buf, NULL,
	    &cmd->cmd_bufsize, strlen(final_buf) + 1);
	strcpy(cmd->cmd_buf, final_buf);

	if (buf)
		free(buf);
	if (final_buf)
		free(final_buf);

	return;

no_mem:
	MM_ABORT_NO_MEM();
}



char *
mm_sql_number_buf(mm_command_t *cmd)
{
	/* This function returns a buf of the number clause */
	mms_par_node_t	*number;
	mms_par_node_t	*range;
	mms_par_node_t	*node;
	mms_par_node_t	*arg1;
	mms_par_node_t	*arg2;
	int		 range1 = 0;
	int		 range2 = 0;

	int		 val;

	char		*buf = NULL;
	mms_par_node_t	*work;



	mms_trace(MMS_DEVP, "mm_sql_number_buf");
	number = mms_pn_lookup(cmd->cmd_root, "number",
	    MMS_PN_CLAUSE, NULL);
	if (number == NULL) {
		mms_trace(MMS_DEVP, "didn't find a number clause");
		return (NULL);
	}
	/*
	 * Subtract one from the number because the postgres data index
	 * starts at zero and the mmp command number starts at one.
	 */
	node = mms_list_head(&number->pn_arglist);



	if ((range = mms_pn_lookup(number, NULL,
	    MMS_PN_RANGE, NULL)) != NULL) {
		mms_trace(MMS_DEVP, "inside range..");

		work = NULL;
		/* Have a range */
		/* get the 1st and last arg */
		arg1 = mms_pn_lookup(range, NULL,
		    MMS_PN_STRING, &work);
		arg2 = mms_pn_lookup(range, NULL,
		    MMS_PN_STRING, &work);

		if ((arg1->pn_string == NULL) ||
		    (arg2->pn_string == NULL)) {
			mms_trace(MMS_ERR,
			    "an arg in range cannot be NULL");
			return (buf);
		}

		if (strcmp(arg1->pn_string, "FIRST") == 0) {
			if (arg2->pn_type & MMS_PN_NUMERIC) {
				range1 = 1;
				sscanf(arg2->pn_string, "%d", &range2);
			} else {
				return (buf);
			}
		} else if (strcmp(arg2->pn_string, "LAST") == 0) {
			if (arg1->pn_type & MMS_PN_NUMERIC) {
				sscanf(arg1->pn_string, "%d", &val);
				val -= 1;
				buf = mms_strapp(buf, " OFFSET %d ", val);

				return (buf);
			} else {
				return (buf);
			}
		} else if (arg1->pn_type & MMS_PN_NUMERIC &&
		    arg2->pn_type & MMS_PN_NUMERIC) {
			sscanf(arg1->pn_string, "%d", &range1);
			sscanf(arg2->pn_string, "%d", &range2);
		} else {
			return (buf);
		}
		range1 -= 1;
		range2 -= 1;
		buf = mms_strapp(buf, " LIMIT %d OFFSET %d ",
		    range2 - range1 + 1, range1);

	} else if (strcmp(node->pn_string, "FIRST") == 0) {
		buf = mms_strapp(buf, " LIMIT 1 OFFSET 0 ");

	} else if (node->pn_type & MMS_PN_NUMERIC) {
		sscanf(node->pn_string, "%d", &val);
		val -= 1;
		buf = mms_strapp(buf, " LIMIT 1 OFFSET %d ", val);

	}

	if (buf == NULL) {
		mms_trace(MMS_ERR,
		    "found a number clause, "
		    "but didn't write any sql");
		mms_trace(MMS_DEVP, "Number buf is NULL");
		return (buf);
	}




	return (buf);


no_mem:
	MM_ABORT_NO_MEM();
	return (NULL);

not_found:
	return (NULL);

}



int
mm_get_range(mm_command_t *cmd, mm_range_t *range)
{
	mms_par_node_t	*number;
	mms_par_node_t	*node;
	mms_par_node_t	*arg1;
	mms_par_node_t	*arg2;

	/*
	 * Get number clause range, number[a..b] or number[a]
	 */

	memset(range, 0, sizeof (mm_range_t));

	if ((number = mms_pn_lookup(cmd->cmd_root, "number",
	    MMS_PN_CLAUSE, NULL)) == NULL) {
		/* no number */
		range->mm_range_type = MM_RANGE_NONE;
		return (0);
	}

	node = mms_list_head(&number->pn_arglist);
	if (node->pn_type == MMS_PN_RANGE) {

		/* number range */
		arg1 = mms_list_head(&node->pn_arglist);
		arg2 = mms_list_tail(&node->pn_arglist);

		if (strcmp(arg1->pn_string, "FIRST") == 0 &&
		    strcmp(arg2->pn_string, "LAST") == 0) {
			mms_trace(MMS_DEVP, "number-clause range first-last");
			range->mm_range_type = MM_RANGE_FIRST_LAST;
			range->mm_range_first = 1;
			return (0);
		} else if (strcmp(arg1->pn_string, "FIRST") == 0) {
			range->mm_range_type = MM_RANGE_FIRST;
			range->mm_range_first = 1;
			if (arg2->pn_type & MMS_PN_NUMERIC) {
				range->mm_range_last =
				    atoi(arg2->pn_string);
				mms_trace(MMS_DEVP,
				    "number-clause range first-%d",
				    range->mm_range_last);
				return (0);
			}
		} else if (strcmp(arg2->pn_string, "LAST") == 0) {
			range->mm_range_type = MM_RANGE_LAST;
			if (arg1->pn_type & MMS_PN_NUMERIC) {
				range->mm_range_first =
				    atoi(arg1->pn_string);
				mms_trace(MMS_DEVP, "number-clause "
				    "range %d-last",
				    range->mm_range_first);
				return (0);
			}
		} else if (arg1->pn_type & MMS_PN_NUMERIC &&
		    arg2->pn_type & MMS_PN_NUMERIC) {
			range->mm_range_type = MM_RANGE_NUMS;
			range->mm_range_first = atoi(arg1->pn_string);
			range->mm_range_last = atoi(arg2->pn_string);
			mms_trace(MMS_DEVP, "number-clause range %d-%d",
			    range->mm_range_first, range->mm_range_last);
			return (0);
		}

		mms_trace(MMS_DEVP, "number-clause range lookup failed");
		return (1);

	}

	/* single number */
	range->mm_range_type = MM_RANGE_A_NUM;
	range->mm_range_first = atoi(node->pn_string);
	mms_trace(MMS_DEVP, "number-clause number %d",
	    range->mm_range_first);
	return (0);
}

void
mm_sql_order(mm_command_t *cmd)
{
	char		*buf = NULL;
	char		*final_buf = NULL;
	char		*order_buf = NULL;

	mms_trace(MMS_DEVP, "mm_sql_order");

	order_buf = mm_sql_order_buf(cmd);

	buf = mms_strapp(buf, order_buf);
	if (order_buf != NULL)
		free(order_buf);
	if (buf == NULL) {
		return;
	}

	final_buf = mms_strapp(final_buf, cmd->cmd_buf);
	final_buf = mms_strapp(final_buf, buf);

	SQL_CHK_LEN(&cmd->cmd_buf, NULL,
	    &cmd->cmd_bufsize, strlen(final_buf) + 1);


	strcpy(cmd->cmd_buf, final_buf);


	if (buf)
		free(buf);
	if (final_buf)
		free(final_buf);

	return;

no_mem:
	MM_ABORT_NO_MEM();
}

char *
mm_sql_order_buf(mm_command_t *cmd)
{
	mms_par_node_t	*order;
	mms_par_node_t	*ops;
	mms_par_node_t	*object;
	mms_par_node_t	*attr;

	mms_par_node_t	*work = NULL;
	int		 ordercnt = 0;
	char		*sql_ops;

	char		*buf = NULL;

	int		need_int_cast = 0;

	mms_trace(MMS_DEVP, "mm_sql_order_buf");

	for (order = mms_pn_lookup(cmd->cmd_root, "order",
	    MMS_PN_CLAUSE, &work);
	    order != NULL;
	    ordercnt++,
	    order = mms_pn_lookup(cmd->cmd_root, "order",
	    MMS_PN_CLAUSE, &work)) {
		if (ordercnt == 0) {
			buf = mms_strapp(buf, "ORDER BY ");
		} else {
			buf = mms_strapp(buf, ", ");
		}
		ops = mms_list_head(&order->pn_arglist);
		sql_ops = mm_sql_get_ops(ops->pn_string);
		mms_trace(MMS_DEVP,
		    "op == %s",
		    ops->pn_string);

		if ((strcmp(ops->pn_string,
		    "numhilo") == 0) ||
		    (strcmp(ops->pn_string,
		    "numlohi") == 0)) {
			need_int_cast = 1;
			buf = mms_strapp(buf,
			    "int4(");
		}

		object = mms_list_head(&ops->pn_arglist);
		buf = mms_strapp(buf, "\"%s\".",
		    object->pn_string);

		attr = mms_list_head(&object->pn_arglist);
		buf = mms_strapp(buf, "\"%s\" ",
		    attr->pn_string);
		if (need_int_cast) {
			buf = mms_strapp(buf, ") ");
		}

		buf = mms_strapp(buf, "%s", sql_ops);

	}
	if (buf == NULL) {
		mms_trace(MMS_DEVP, "Order buf is NULL");
		buf = mms_strapp(buf, " ");
		return (buf);
	}

	return (buf);

no_mem:
	MM_ABORT_NO_MEM();
	return (NULL);

}


void
mm_sql_db_err_rsp_new(mm_command_t *cmd, mm_db_t *db)
{
	int		 dbstatus;
	char		*dbmessage;

	dbstatus = PQresultStatus(db->mm_db_results);
	dbmessage = PQresultErrorMessage(db->
	    mm_db_results);

	free(cmd->cmd_buf);
	if ((cmd->cmd_buf = mm_db_sql_err_rsp(dbstatus, dbmessage,
	    cmd->wka_ptr->wka_conn.cci_language, cmd->cmd_task)) == NULL) {
		MM_ABORT_NO_MEM();
		return;
	}
	mm_clear_db(&db->mm_db_results);

}

int
mm_add_match_list(char *str, mms_list_t *list) {
	/* Checks is str is already in list */
	/* If str exists, do nothing */
	/* Else add to list and inc num */
	if (mm_in_char_list(list, str)) {
		return (1);
	}
	if (mm_add_char(str, list)) {
		mms_trace(MMS_ERR,
		    "mm_add_match_list: "
		    "error adding char");
		return (1);
	}
	return (0);
}

int
/* LINTED: mm_wka may be used in the future */
mm_get_const(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	*match;
	mms_par_node_t	*node;
	int		  off = 0;
	mms_par_node_t	*vol_name;

	mms_trace(MMS_DEVP, "mm_get_const");

	if (cmd->cmd_buf != NULL) {
		free(cmd->cmd_buf);
		cmd->cmd_buf = NULL;
		cmd->cmd_bufsize = 0;
	}

	/* Look up the match clause */
	match = mms_pn_lookup(cmd->cmd_root, "match",
	    MMS_PN_CLAUSE, NULL);
	if (match == NULL) {
		/* No match clause, chek for volname */
		vol_name = mms_pn_lookup(cmd->cmd_root, "volname",
		    MMS_PN_CLAUSE, NULL);
		if (vol_name != NULL) {
			/* Found a volname */
			mm_sql_trans_volname(cmd, &off);
		} else {
			/* No match and no volname */
			return (1);
		}
		if (cmd->cmd_buf != NULL) {
			mms_trace(MMS_DEVP, "cmd_buf is \n%s\n", cmd->cmd_buf);
		}
		mms_trace(MMS_DEVP, "cmd_const_num = %d", cmd->cmd_const_num);

		if (mm_add_char(cmd->cmd_buf,
		    &cmd->cmd_const_list)) {
			mms_trace(MMS_ERR, "Error adding char to const list"
			    "- out of memory");
			return (1);
		}

		cmd->cmd_const_num ++;
		return (0);
	}
	/* We have a match clause */
	node = mms_list_head(&match->pn_arglist);
	if (node == NULL) {
		mms_trace(MMS_ERR, "Error translating match expression");
		return (1);
	}
	if (mm_sql_trans_match_exp(node, cmd, &off, 0)) {
		mms_trace(MMS_ERR, "Error translating match expression");
		return (1);
	}

	/* List way */
	if (mm_add_char(cmd->cmd_buf,
	    &cmd->cmd_const_list)) {
		mms_trace(MMS_ERR, "Error adding char to source list");
		return (1);
	}

	/* Array Way */

	cmd->cmd_const_num ++;

	/* List TEST */
	mms_trace(MMS_DEVP, "Printing char_list const...");
	mm_print_char_list(&cmd->cmd_const_list);
	return (0);



no_mem:
	MM_ABORT_NO_MEM();
	return (MM_CMD_ERROR);
}





int
/* LINTED: mm_wka may be used in the future */
mm_get_source(mm_wka_t *mm_wka, mm_command_t *cmd)
{
	mms_par_node_t	 *report;
	mms_par_node_t	 *object;
	mms_par_node_t	*work;
	int		source_count = 0;
	int skip = 0;

	mms_trace(MMS_DEBUG, "mm_get_source");

	report = mms_pn_lookup(cmd->cmd_root, "report",
	    MMS_PN_CLAUSE, NULL);
	if (report == NULL) {
		cmd->cmd_source_num = 0;
		return (1);
	}
	work = NULL;
	for (object = mms_pn_lookup(report, NULL, MMS_PN_OBJ, &work);
	    object != NULL;
	    object = mms_pn_lookup(report, NULL, MMS_PN_OBJ, &work)) {
		skip = 0;
		if (mm_in_char_list(&cmd->cmd_source_list,
		    object->pn_string)) {
			/* already have this as a source */
			skip = 1;
		}

		if (!skip) {
			/* List way */
			if (mm_add_char(object->pn_string,
			    &cmd->cmd_source_list)) {
				mms_trace(MMS_ERR, "Error adding "
				    "char to source list");
				return (1);
			}

			/* Array Way */

			source_count ++;
		}

	}
	cmd->cmd_source_num = source_count;
	/* List TEST */
	mms_trace(MMS_DEVP, "Printing char_list source...");
	mm_print_char_list(&cmd->cmd_source_list);
	return (0);

}

void
mm_get_dest_helper(mms_par_node_t *node, mm_command_t *cmd)
{
	mms_par_node_t	*arg;
	int skip = 0;

	if (node->pn_type == MMS_PN_OBJ) {
		if (node->pn_string != NULL) {

		skip = 0;
		if (mm_in_char_list(&cmd->cmd_dest_list,
		    node->pn_string)) {
			/* already have this as a dest */
			skip = 1;
		}
		if (!skip) {
			/* List way */
			if (mm_add_char(node->pn_string,
			    &cmd->cmd_dest_list)) {
				mms_trace(MMS_ERR, "Error adding "
				    "char to source list");
			}

			/* Array Way */

		cmd->cmd_dest_num ++;
		}

		}
		arg = mms_list_head(&node->pn_arglist);
	} else if (node->pn_flags & MMS_PN_MULTIOPS) {
		if (node->pn_flags & MMS_PN_REGEX) {
			/* sql regular expression is at end of list */
			arg = mms_list_head(&node->pn_arglist);
			mms_list_remove(&node->pn_arglist, arg);
			mms_list_insert_tail(&node->pn_arglist, arg);
		}
		mms_list_foreach(&node->pn_arglist, arg) {
			mm_get_dest_helper(arg, cmd);

		}
		if (node->pn_flags & MMS_PN_REGEX) {
			/* restore list to original order */
			arg = mms_list_tail(&node->pn_arglist);
			mms_list_remove(&node->pn_arglist, arg);
			mms_list_insert_head(&node->pn_arglist, arg);
		}
	} else if (node->pn_flags & MMS_PN_UNARYOPS) {
		if (strcmp(node->pn_string, "isattr") == 0 ||
		    strcmp(node->pn_string, "noattr") == 0) {
			arg = mms_list_head(&node->pn_arglist);

		} else {
			arg = mms_list_head(&node->pn_arglist);
			mm_get_dest_helper(arg, cmd);
		}
	}
}

void
mm_clear_const(mm_command_t *cmd) {
	mm_free_list(&cmd->cmd_const_list);
	cmd->cmd_const_num = 0;
}

void
mm_clear_dest(mm_command_t *cmd) {
	mm_free_list(&cmd->cmd_dest_list);
	cmd->cmd_dest_num = 0;
}
void
mm_clear_source(mm_command_t *cmd) {
	mm_free_list(&cmd->cmd_source_list);
	cmd->cmd_source_num = 0;
}



int
/* LINTED: mm_wka may be used in the future */
mm_get_dest(mm_wka_t *mm_wka, mm_command_t *cmd)
{

	mms_par_node_t	*match;
	mms_par_node_t	*node;
	mms_par_node_t	*vol_name;

	mms_trace(MMS_DEVP, "mm_get_dest");

	match = mms_pn_lookup(cmd->cmd_root, "match",
	    MMS_PN_CLAUSE, NULL);
	if (match == NULL) {
		vol_name = mms_pn_lookup(cmd->cmd_root, "volname",
		    MMS_PN_CLAUSE, NULL);
		if (vol_name != NULL) {
			/* List way */
			if (mm_add_char("VOLUME",
			    &cmd->cmd_dest_list)) {
				mms_trace(MMS_ERR, "Error adding "
				    "char to source list");
			}

			/* Array Way */

			cmd->cmd_dest_num ++;
			return (0);
		}
		return (1);

	}
	mms_list_foreach(&match->pn_arglist, node) {
		mm_get_dest_helper(node, cmd);
	}
	/* List TEST */
	mms_trace(MMS_DEVP, "Printing char_list dest...");
	mm_print_char_list(&cmd->cmd_dest_list);
	return (0);

}

int
mm_non_priv_const(mm_wka_t *mm_wka, mm_command_t *cmd) {

	char		*const_buf = NULL;
	mms_list_t		*source_list = &cmd->cmd_source_list;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*app_name = conn->cci_client;


	/*
	 * Cartridge/volume constriants
	 */
	/* Check for the objects in the source list */
	if (mm_in_char_list(source_list, "CARTRIDGE") ||
	    mm_in_char_list(source_list, "PARTITION") ||
	    mm_in_char_list(source_list, "SIDE") ||
	    mm_in_char_list(source_list, "SLOT") ||
	    mm_in_char_list(source_list, "CARTRIDGEGROUP") ||
	    mm_in_char_list(source_list, "CARTRIDGEGROUPAPPLICATION")) {
		/* Add constraint for CARTRIDGE */
		(void) mm_add_to_dest(cmd,
			"CARTRIDGEGROUPAPPLICATION");
		if (const_buf)
			free(const_buf);
		const_buf = NULL;
		const_buf = mms_strapp(const_buf,
			"\"CARTRIDGEGROUPAPPLICATION\"."
			"\"ApplicationName\" = '%s'",
			app_name);
		(void) mm_add_to_const(cmd, const_buf);
	}
	if (mm_in_char_list(source_list, "VOLUME")) {
		/* Add constraint for VOLUME */
		(void) mm_add_to_dest(cmd,
			"VOLUME");
		if (const_buf)
			free(const_buf);
		const_buf = NULL;
		const_buf = mms_strapp(const_buf,
			"\"VOLUME\"."
			"\"ApplicationName\" = '%s'",
			app_name);
		(void) mm_add_to_const(cmd, const_buf);
	}


	/*
	 * Drive/Mount constraints
	 */
	if (mm_in_char_list(source_list, "DRIVE") ||
	    mm_in_char_list(source_list, "DRIVEGROUP") ||
	    mm_in_char_list(source_list, "DRIVEGROUPAPPLICATION") ||
	    mm_in_char_list(source_list, "DM") ||
	    mm_in_char_list(source_list, "DMCAPABILITY") ||
	    mm_in_char_list(source_list, "DMCAPABILITYTOKEN") ||
	    mm_in_char_list(source_list, "DMCAPABILITYDEFAULTTOKEN") ||
	    mm_in_char_list(source_list, "DMCAPABILITYGROUP") ||
	    mm_in_char_list(source_list, "DMCAPABILITYGROUPTOKEN") ||
	    mm_in_char_list(source_list, "DMBITFORMAT") ||
	    mm_in_char_list(source_list, "DMBITFORMATTOKEN")) {
		/* Add constraint for DRIVE */
		(void) mm_add_to_dest(cmd,
			"DRIVEGROUPAPPLICATION");
		if (const_buf)
			free(const_buf);
		const_buf = NULL;
		const_buf = mms_strapp(const_buf,
			"\"DRIVEGROUPAPPLICATION\"."
			"\"ApplicationName\" = '%s'",
			app_name);
		(void) mm_add_to_const(cmd, const_buf);
	}
	if (mm_in_char_list(source_list, "MOUNTPHYSICAL") ||
	    mm_in_char_list(source_list, "MOUNTLOGICAL") ||
	    mm_in_char_list(source_list, "STALEHANDLE")) {
		/* Add constraint for MOUNTPHYSICAL */
		(void) mm_add_to_dest(cmd,
			"MOUNTPHYSICAL");
		if (const_buf)
			free(const_buf);
		const_buf = NULL;
		const_buf = mms_strapp(const_buf,
			"\"MOUNTPHYSICAL\"."
			"\"ApplicationName\" = '%s'",
			app_name);
		(void) mm_add_to_const(cmd, const_buf);
	}
	/*
	 * System/connection constraints
	 */

	if (mm_in_char_list(source_list, "APPLICATION") ||
	    mm_in_char_list(source_list, "AI")) {
		/* Add constraint for APPLICATION */
		(void) mm_add_to_dest(cmd,
			"APPLICATION");
		if (const_buf)
			free(const_buf);
		const_buf = NULL;
		const_buf = mms_strapp(const_buf,
			"\"APPLICATION\"."
			"\"ApplicationName\" = '%s'",
			app_name);
		(void) mm_add_to_const(cmd, const_buf);
	}

	if (mm_in_char_list(source_list, "CONNECTION") ||
	    mm_in_char_list(source_list, "SESSION") ||
	    mm_in_char_list(source_list, "NOTIFY")) {
		/* Add constraint for DRIVE */
		(void) mm_add_to_dest(cmd,
			"CONNECTION");
		if (const_buf)
			free(const_buf);
		const_buf = NULL;
		const_buf = mms_strapp(const_buf,
			"\"CONNECTION\"."
			"\"ConnectionClientName\" = '%s'",
			app_name);
		(void) mm_add_to_const(cmd, const_buf);
	}
	if (const_buf)
		free(const_buf);
	const_buf = NULL;
	return (0);
}

void
mm_path_match_report(mm_command_t *cmd, mm_db_t *db)
{

	int		  off;
	mms_par_node_t	 *report;
	mms_par_node_t	 *reportmode;
	mms_par_node_t	 *object;
	mms_par_node_t	 *attr;
	mms_par_node_t	*work;
	mm_wka_t *mm_wka = cmd->wka_ptr;

	mms_trace(MMS_DEVP, "mm_path_match_report");

	report = mms_pn_lookup(cmd->cmd_root, "report",
	    MMS_PN_CLAUSE, NULL);
	if (report == NULL) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_SUCCESS) +
		    strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_SUCCESS, cmd->cmd_task);
		return;
	}

	mm_clear_source(cmd);
	if (mm_get_source(mm_wka, cmd)) {
		/* Command does not have a report clause */
		mms_trace(MMS_DEVP, "No report clause");
	} else {
		/* TEMP - Trace out our source info */
		mms_trace(MMS_DEVP, "Source count is %d", cmd->cmd_source_num);
		mm_print_char_list(&cmd->cmd_source_list);
	}

	mm_clear_dest(cmd);
	if (mm_get_dest(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause");
	} else {
		/* TEMP - Trace out our dest info */
		mms_trace(MMS_DEVP, "Dest count is %d", cmd->cmd_dest_num);
		mm_print_char_list(&cmd->cmd_dest_list);
	}

	/* Build Constraint List */
	mm_clear_const(cmd);
	if (mm_get_const(mm_wka, cmd)) {
		/* Command does not have a match/volname clause */
		mms_trace(MMS_DEVP, "No match/volname Clause???");
	} else {
		/* TEMP - Trace out our const info */
		mms_trace(MMS_DEVP, "Const count is %d", cmd->cmd_const_num);
		mm_print_char_list(&cmd->cmd_const_list);
	}

	/* For non priv-clients, check the source list */
	/* Add any additional constraits necessary */
	/* ie. VOLUME.ApplicationName = cci_client */
	/* both source + dest may need adds */
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

	SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize, 7);
	off = snprintf(cmd->cmd_buf, cmd->cmd_bufsize, "SELECT ");

	/* If unique is specified in the reportmode clause, insert DISTINCT */
	reportmode = mms_pn_lookup(cmd->cmd_root, "reportmode",
	    MMS_PN_CLAUSE, NULL);
	if (reportmode && mms_pn_lookup(reportmode, "unique",
	    MMS_PN_KEYWORD, NULL)) {
		SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize, 9);
		off += snprintf(cmd->cmd_buf + off, cmd->cmd_bufsize - off,
		    "DISTINCT ");
	}
	work = NULL;
	for (object = mms_pn_lookup(report, NULL, MMS_PN_OBJ, &work);
	    object != NULL;
	    object = mms_pn_lookup(report, NULL, MMS_PN_OBJ, &work)) {
		attr = mms_pn_lookup(object, NULL, MMS_PN_ATTR, NULL);
		if (attr == NULL) {
			/* show all attributes */
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    4 + strlen(object->pn_string));
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    "\"%s\".*,", object->pn_string);
		} else {
			/*
			 * More than one object column reference can't be be
			 * ambiguous, specify object and attribute.
			 */
			SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize,
			    6 + strlen(object->pn_string) +
			    strlen(object->pn_string) +
			    strlen(attr->pn_string));
			off += snprintf(cmd->cmd_buf + off,
			    cmd->cmd_bufsize - off,
			    "\"%s\".\"%s\",",
			    object->pn_string,
			    attr->pn_string);
		}
	}
	off--;			/* overwrite the last comma */
	SQL_CHK_LEN(&cmd->cmd_buf, off, &cmd->cmd_bufsize, 6);
	off += snprintf(cmd->cmd_buf + off, cmd->cmd_bufsize - off, " FROM ");

	if (mm_sql_from_where(cmd, db)) {
		mms_trace(MMS_ERR,
		    "mm_path_match_report: "
		    "db error creating helper functions");
		return;
	}

	mm_sql_order(cmd);
	mm_sql_number(cmd);


	if (mm_sql_report(cmd)) {
		mms_trace(MMS_ERR,
		    "mm_path_match_report: "
		    "error generating final response");
	}
	return;

no_mem:
	MM_ABORT_NO_MEM();
	return;

not_found:
	mm_response_error(cmd,
	    ECLASS_LANGUAGE,
	    ENOTFOUND,
	    MM_5062_MSG,
	    NULL);
	return;

}

/*
 * function to set a LM/DM/DRIVE/LIBRARY state
 * uses its own db connection
 * to set drive 1, DRIVE.DriveStateHard to 'loaded' :
 * mm_sql_update_state(&mm_data, "DRIVE", "DriveStateHard", "loaded",
 *		"DriveName", "drive1");
 */
#define	MM_SQL_UPDATE_STATE "update \"%s\" "\
	"set \"%s\" = '%s' "\
	"where \"%s\" = '%s';"
void
mm_sql_update_state(mm_data_t *data, char *object, char *attribute,
		    char *value, char *instance, char *name)
{

	mm_db_t		*db = &data->mm_db;
	if (mm_db_exec(HERE, db, MM_SQL_UPDATE_STATE,
	    object, attribute, value,
	    instance, name) != MM_DB_OK) {
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		mms_trace(MMS_ERR,
		    "mm_sql_update_state: "
		    "db error updating db states");
	}
	return;

}


int
/* LINTED: db is used by this function */
mm_system_settings(mm_db_t *db, int *request_oper, int *auto_clear) {


#if 1
	/* TEMP - dont request, always clear */
	*auto_clear = 1;
	*request_oper = 0;
	return (0);
#else
	rc = mm_db_exec(HERE, db,
			"select "
			"\"AskClearDriveAtLMConfig\","
			"\"ClearDriveAtLMConfig\" "
			"from \"SYSTEM\";");
	if (rc != MM_DB_DATA) {
		mms_trace(MMS_ERR, "Db error in mm_clear_unknown_tape");
		mm_clear_db(&db->mm_db_results);
		db->mm_db_results = NULL;
		return (1);
	}
	if (PQntuples(db->mm_db_results) < 1) {
		mms_trace(MMS_ERR, "Missing SYSTEM object");
		return (1);

	}
	mms_trace(MMS_DEVP, "AskClearDrive = %s, ClearDrive = %s",
	    PQgetvalue(db->mm_db_results, 0, 0),
	    PQgetvalue(db->mm_db_results, 0, 1));
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "yes") == 0) {
		*request_oper = 1;

	}
	/* Don't ask the oper */
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 1),
		    "yes") == 0) {
		*auto_clear = 1;
	}
	return (0);
#endif
}

int
/* LINTED: a mm_wka arg is required by all cmd functions */
mm_req_test_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	mms_trace(MMS_DEVP, "mm_req_test_cmd_func");
	mms_trace(MMS_DEVP, "request clear for %s, %s",
	    mount_info->cmi_drive, mount_info->cmi_cartridge);
	return (MM_DEPEND_DONE);

}



int
mm_add_clear_request(mm_wka_t *mm_wka, mm_command_t *cmd) {
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	mm_command_t		*req_cmd;
	mm_wka_t		*oper_wka;
	mm_data_t		*mm_data = mm_wka->mm_data;
	uuid_text_t		uuid;

	mms_trace(MMS_DEVP, "adding clear drive request,"
	    "drive %s, cartridge %s",
	    mount_info->cmi_drive, mount_info->cmi_cartridge);


	oper_wka = NULL;
	mms_list_foreach(&mm_data->mm_wka_list, oper_wka) {
		if ((strcmp(oper_wka->wka_conn.cci_instance,
			    "oper") == 0) &&
		    (strcmp(oper_wka->wka_conn.cci_client,
			    "MMS") == 0)) {
			/* Found the wka of oper */
			break;
		}
	}
	if (oper_wka == NULL) {
		mms_trace(MMS_DEBUG, "operator not connected");
		return (1);
	}

	if ((req_cmd = mm_alloc_cmd(oper_wka)) == NULL) {
		mms_trace(MMS_ERR,
			"Unable to malloc mm_command_t: %s",
			strerror(errno));
		return (1);
	}
	mm_add_depend(req_cmd, cmd);
	mm_get_uuid(uuid);
	req_cmd->cmd_root = NULL;
	req_cmd->cmd_task = NULL;
	req_cmd->cmd_task = strdup(uuid);
	if (req_cmd->cmd_task == NULL) {
		mms_trace(MMS_ERR, "Error malloc cmd_task in add cmd");
		return (MM_CMD_ERROR);
	}
	req_cmd->cmd_func = mm_req_test_cmd_func;
	req_cmd->cmd_name = strdup("clear drive oper request");

	req_cmd->cmd_mount_info.cmi_drive = strdup(mount_info->cmi_drive);
	req_cmd->cmd_mount_info.cmi_cartridge =
		strdup(mount_info->cmi_cartridge);
	mms_list_insert_tail(&mm_data->mm_cmd_queue, req_cmd);
	return (0);

}
extern int mm_errorcode_eq(mms_par_node_t *cmd_response, char *code) {

	/* This function takes an MMP/DMP/LMP */
	/* response and returns a pointer to the error code */

	mm_response_t		response;


	if (mm_parse_response(cmd_response, &response) == 1) {
		mms_trace(MMS_ERR,
		    "Error parsing command response");
		return (0);
	}
	if ((response.error_class == NULL) ||
	    (response.error_code == NULL)) {
		/* Might not be an error response */
		return (0);
	}
	if (strcmp(response.error_code, code) == 0) {
		return (1);
	}
	return (0);

}
int
mm_non_physical_clear_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd) {
	mm_db_t			*db = &cmd->cmd_mm_data->mm_db;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;

	/* 1. DMP detach */
	/* 2. DMP release */
	/* 3. Schedule delay unmount/unload */

	if (cmd->cmd_state == 0) {
		mms_trace(MMS_DEVP,
		    "non-physical clear, add detach");
		/* Need both drive and dm set */
		if ((mount_info->cmi_drive == NULL)) {
			mms_trace(MMS_ERR,
			    "cmi_drive/dm is NULL for "
			    "this non-physical clear");
			return (MM_CMD_ERROR);
		}
		/* Get DM Name */
		if (mm_db_exec(HERE, db,
		    "select \"DMName\" from \"DRIVE\" "
		    "where \"DRIVE\".\"DriveName\" = '%s';",
		    mount_info->cmi_drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error");
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR,
			    "row num mismatch");
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		if (strcmp(PQgetvalue(db->mm_db_results, 0, 0), "") == 0) {
			mms_trace(MMS_ERR,
			    "missing dm name");
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		mm_set_mount_info_dm(PQgetvalue(db->mm_db_results, 0, 0),
				mount_info);
		mm_clear_db(&db->mm_db_results);

		/* Send a detach */
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_DETACH) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "error adding dmp detach");
		}
		cmd->cmd_state = 1;
		return (MM_DISPATCH_DEPEND);

	}
	if (cmd->cmd_state == 1) {
		mms_trace(MMS_DEVP,
		    "non-physical clear, add release");
		/*
		 * Detach has returned
		 * check error, update states
		 * Add Unload command
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			if ((cmd->cmd_response != NULL) &&
			    mm_errorcode_eq(cmd->cmd_response,
					"DM_E_NOEXISTHANDLE")) {
				mms_trace(MMS_DEVP,
				    "DM doesn't know the handle, "
				    "skip DMP unload, "
				    "send LMP unmount");
				/* Clear depend error flags */
				MM_UNSET_FLAG(cmd->cmd_flags,
					MM_CMD_DEPEND_ERROR);
			} else {
				/* detach returned handle in use */
				mms_trace(MMS_ERR,
				    "non-physical clear_drive -> "
				    "DMP detach error, "
				    "handle may be inuse");
				return (MM_CMD_ERROR);
			}

		}
		mms_trace(MMS_DEVP,
		    "DM is not using handle, send DMP release");
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_RELEASE) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "error adding dmp release");
		}
		cmd->cmd_state = 2;
		return (MM_DISPATCH_DEPEND);
	}
	if (cmd->cmd_state == 2) {
		mms_trace(MMS_DEVP,
		    "non-physical clear, schedule unload");
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			/* unload returned an error */
			mms_trace(MMS_ERR, "clear_drive -> DMP release error");
		}
		if (mm_db_exec(HERE, db,
		    "select distinct \"CARTRIDGE\"."
		    "\"CartridgeID\" from \"CARTRIDGE\""
		    "cross join \"DRIVE\""
		    "where"
		    "((\"CARTRIDGE\".\"LibraryName\" "
		    "= \"DRIVE\".\"LibraryName\")"
		    "and"
		    "(\"DRIVE\".\"DriveName\" = '%s')"
		    "and"
		    "(\"CARTRIDGE\".\"CartridgePCL\" = "
		    "\"DRIVE\".\"CartridgePCL\"));",
		    mount_info->cmi_drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error");
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR,
			    "row num mismatch");
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		mm_set_mount_info_cart(PQgetvalue(db->mm_db_results, 0, 0),
				mount_info);
		mm_clear_db(&db->mm_db_results);

		if (mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\""
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "db error deleting TASKCARTRIDGE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKDRIVE\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "db error deleting TASKDRIVE");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "db error deleting TASKLIBRARY");
		}
		if (mm_db_exec(HERE, db, "delete from \"TASK\" "
		    "where \"TaskID\" = '%s';", cmd->cmd_uuid) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "db error deleting TASK");
		}
		if (mm_db_exec(HERE, db, "delete from \"MOUNTLOGICAL\" "
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "db error deleting MOUNTLOGICAL");
		}
		if (mm_db_exec(HERE, db, "delete from \"MOUNTPHYSICAL\" "
		    "where \"CartridgeID\" = '%s';",
		    mount_info->cmi_cartridge) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "db error deleting MOUNTPHYSICAL");
		}

		if (mm_schedule_unload(mm_wka, cmd)) {
			mms_trace(MMS_ERR,
			    "mm_non_physical_clear_cmd_func: "
			    "error scheduling delay unload");
		}
		cmd->cmd_remove = 1;
		mms_trace(MMS_DEVP,
		    "non-physical clear complete, delay unload scheduled");
		return (MM_DISPATCH_AGAIN);

	}
	mms_trace(MMS_ERR,
	    "mm_non_physical_clear_cmd_func: unknown cmd state");
	return (MM_CMD_ERROR);
}


#define	MM_CLEAR_START 0
#define	MM_CLEAR_SLOTSCAN 20
#define	MM_CLEAR_DETACH 21
#define	MM_CLEAR_RELEASE 22
#define	MM_CLEAR_UNLOAD 23
#define	MM_CLEAR_UNMOUNT 24
#define	MM_CLEAR_FINAL 25

int
mm_clear_drive_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd) {
	mm_db_t			*db = &cmd->cmd_mm_data->mm_db;
	cmd_mount_info_t	*mount_info = &cmd->cmd_mount_info;
	mm_data_t		*data = cmd->cmd_mm_data;
	int			rc;

	mm_command_t		*lmp_umnt_cmd;
	uuid_text_t		new_task;


	/* This is a physical unmount */
	/* detach, release, unload, unmount */
start:
	if (cmd->cmd_state == MM_CLEAR_START) {

		/* Clear depend error flags, */
		/* On the 1st cmd state of clear drive */
		/*  ignore any errors */
		/* This clear drive may be running after */
		/* A DMP activate which may have errored */
		/* Try to clear anyways */

		MM_UNSET_FLAG(cmd->cmd_flags,
		    MM_CMD_DEPEND_ERROR);

		if (mount_info->cmi_library == NULL) {
			mms_trace(MMS_ERR,
			    "library name not set for clear drive");
			return (MM_CMD_ERROR);
		}
		/* Confirm LM is connected and active */
		rc = mm_db_exec(HERE, db,
		    "select distinct "
		    "\"LM\".\"LMStateSoft\" from \"LM\""
		    "cross join \"LIBRARY\""
		    "where((\"LM\".\"LibraryName\" = "
		    "\"LIBRARY\".\"LibraryName\")"
		    "and(\"LIBRARY\".\"LibraryName\" = '%s'));",
		    mount_info->cmi_library);
		if (rc != MM_DB_DATA) {
			mms_trace(MMS_ERR, "Exec returned with no Data");
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_ERR,
			    "library, %s, has no lm assigned",
			    mount_info->cmi_library);
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}

		if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "not ready") == 0) {
			mms_trace(MMS_DEVP, "lm is not ready, wait");
			MM_SET_FLAG(cmd->cmd_flags, MM_CMD_DISPATCHABLE);
			mm_clear_db(&db->mm_db_results);
			return (MM_NO_DISPATCH);
		}
		if (strcmp(PQgetvalue(db->mm_db_results, 0, 0), "ready") == 0) {
			mms_trace(MMS_DEVP, "lm ready, continue");
		} else {
			mms_trace(MMS_ERR,
			    "lm state = %s, cancel clear drive",
			    PQgetvalue(db->mm_db_results, 0, 0));
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		mm_clear_db(&db->mm_db_results);

		mms_trace(MMS_DEBUG, "LM Ready, try to clear "
		    "drive -> %s, send scan",
		    mount_info->cmi_drive);

		/* Add LMP scan command for this drive */
		if (mm_add_lmp_scan(mm_wka->mm_data, cmd,
				    mount_info->cmi_drive,
				    NULL, mount_info->cmi_library)) {
			mms_trace(MMS_ERR,
			    "Error adding LMP scan");
			return (MM_CMD_ERROR);
		} else {
			mms_trace(MMS_DEBUG,
			    "Added LMP scan");
			cmd->cmd_state = MM_CLEAR_DETACH;

		}
		/* If DRIVE is occupied and has pcl set */
		/* MM will need to send lmp scan for the */
		/* cartridge as well */

		if (mount_info->cmi_pcl != NULL) {
			mms_trace(MMS_DEVP,
			    "cmi_pcl already set, %s",
			    mount_info->cmi_pcl);
			cmd->cmd_state = MM_CLEAR_SLOTSCAN;
			return (MM_DISPATCH_DEPEND);
		}

		/* set mount_info->cmi_pcl */
		if (mm_db_exec(HERE, db,
		    "select distinct "
		    "\"DRIVE\".\"CartridgePCL\""
		    "from \"DRIVE\" "
		    "where"
		    " \"DRIVE\".\"DriveName\" = '%s'; ",
		    mount_info->cmi_drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR, "Couldn't get Cartridge_PCL -> "
			    "mm_clear_drive_cmd_func");
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_ERR,
			    "error getting pcl from drive");
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		if (strcmp(PQgetvalue(db->mm_db_results,
		    0, 0), MM_NON_MMS_CART) == 0) {
			mms_trace(MMS_DEVP,
			    "drive loaded with non-mms cart");
			/* If non-mms cart return */
			/* since this is not part of MMS */
			/* MM does not need a cart scan */
			mm_clear_db(&db->mm_db_results);
			return (MM_DISPATCH_DEPEND);
		}
		if (strcmp(PQgetvalue(db->mm_db_results,
		    0, 0), "") != 0) {
			/* DRIVE.pcl was set */
			cmd->cmd_state = MM_CLEAR_SLOTSCAN;
			mm_set_mount_info_pcl(PQgetvalue(db->
			    mm_db_results, 0, 0),
			    mount_info);
		}
		mm_clear_db(&db->mm_db_results);

		return (MM_DISPATCH_DEPEND);
	}

	if (cmd->cmd_state == MM_CLEAR_SLOTSCAN) {
		/* Command state when a lmp scan for slot is needed */
		/* Drive scan has completed */
		mms_trace(MMS_DEVP,
		    "drive scan complete, send scan of PCL");

		/* Add LMP scan command for this drive */
		if (mm_add_lmp_scan(mm_wka->mm_data, cmd,
		    NULL, mount_info->cmi_pcl,
		    mount_info->cmi_library)) {
			mms_trace(MMS_ERR,
			    "Error adding LMP scan");
			return (MM_CMD_ERROR);
		} else {
			mms_trace(MMS_DEBUG,
			    "Added LMP scan");
			cmd->cmd_state = MM_CLEAR_DETACH;

		}
		if (mount_info->cmi_pcl != NULL) {
			free(mount_info->cmi_pcl);
			mount_info->cmi_pcl = NULL;
		}
		return (MM_DISPATCH_DEPEND);
	}

	if (cmd->cmd_state == MM_CLEAR_DETACH) {
		/* Send the DMP detach command */
		mms_trace(MMS_DEVP,
		    "physical clear, add detach");
		/* Need drive set */
		if ((mount_info->cmi_drive == NULL)) {
			mms_trace(MMS_ERR,
			    "cmi_drive is NULL for "
			    "this physical clear");
			return (MM_CMD_ERROR);
		}

		/* set mount_info->cmi_pcl */
		if (mm_db_exec(HERE, db,
		    "select distinct "
		    "\"DRIVE\".\"CartridgePCL\""
		    "from \"DRIVE\" "
		    "where"
		    " \"DRIVE\".\"DriveName\" = '%s'; ",
		    mount_info->cmi_drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR, "Couldn't get Cartridge_PCL -> "
			    "mm_clear_drive_cmd_func");
			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			return (MM_CMD_ERROR);
		}

		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_ERR,
			    "error getting pcl from drive");
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}

		if (strcmp(PQgetvalue(db->mm_db_results,
		    0, 0), "") == 0) {
			mms_trace(MMS_DEVP,
			    "LMP scan of drive shows %s is clear",
			    mount_info->cmi_drive);

			mms_trace(MMS_INFO, "%s Cleared Successfully",
			    mount_info->cmi_drive);

			/* Set States For a Clear Drive */
			if (mm_db_exec(HERE, db,
			    "update \"DRIVE\" set "
			    "\"DriveStateHard\" = 'unloaded', "
			    "\"DMName\" = DEFAULT, "
			    "\"DriveLibraryOccupied\" = 'f' "
			    "where \"DriveName\" = '%s';",
			    mount_info->cmi_drive) != MM_DB_OK) {
				mm_clear_db(&db->mm_db_results);
				db->mm_db_results = NULL;
				mms_trace(MMS_ERR,
				    "mm_clear_drive_cmd_func: "
				    "db error updating DRIVE");
			}

			/* Delete any mountphysical, mountlogical, */
			/* or stalehandle */
			if (mm_db_exec(HERE, db,
			    "delete from \"MOUNTLOGICAL\" "
			    "where \"DriveName\" = '%s';",
			    mount_info->cmi_drive) != MM_DB_OK) {
				mm_clear_db(&db->mm_db_results);
				db->mm_db_results = NULL;
				mms_trace(MMS_ERR,
				    "mm_clear_drive_cmd_func: "
				    "db error deleting MOUNTLOGICAL");
			}
			if (mm_db_exec(HERE, db,
			    "delete from \"STALEHANDLE\" "
			    "where \"DriveName\" = '%s';",
			    mount_info->cmi_drive) != MM_DB_OK) {
				mm_clear_db(&db->mm_db_results);
				db->mm_db_results = NULL;
				mms_trace(MMS_ERR,
				    "mm_clear_drive_cmd_func: "
				    "db error deleting STALEHANDLE");
			}
			if (mm_db_exec(HERE, db,
			    "delete from \"MOUNTPHYSICAL\" "
			    "where \"DriveName\" = '%s';",
			    mount_info->cmi_drive) != MM_DB_OK) {
				mm_clear_db(&db->mm_db_results);
				db->mm_db_results = NULL;
				mms_trace(MMS_ERR,
				    "mm_clear_drive_cmd_func: "
				    "db error deleting MOUNTPHYSICAL");
			}

			mm_clear_db(&db->mm_db_results);
			db->mm_db_results = NULL;
			if (mm_has_depend(cmd)) {
				return (MM_DEPEND_DONE);
			}
			return (MM_CMD_DONE);

		}

		if (strcmp(PQgetvalue(db->mm_db_results,
		    0, 0), MM_NON_MMS_CART) == 0) {
			mms_trace(MMS_DEVP,
			    "this is a clear drive for a non-mms cartridge");
			/* Look in the response to the scan to */
			/* find the pcl in this drive */
			if (mount_info->cmi_pcl != NULL) {
				mms_trace(MMS_DEVP,
				    "pcl already set to %s",
				    mount_info->cmi_pcl);
			} else {
				mms_trace(MMS_ERR,
				    "pcl is NULL for a non-MMS cart");
				mm_clear_db(&db->mm_db_results);
				return (MM_CMD_ERROR);
			}
		} else {
			mm_set_mount_info_pcl(PQgetvalue(db->
			    mm_db_results, 0, 0),
			    mount_info);
		}
		mm_clear_db(&db->mm_db_results);
		if (mount_info->cmi_pcl == NULL) {
			mms_trace(MMS_ERR,
			    "pcl is NULL ");
			return (MM_CMD_ERROR);
		}
		mms_trace(MMS_DEVP,
		    "pcl set to %s",
		    mount_info->cmi_pcl);
		/* Get DM Name */
		if (mm_db_exec(HERE, db,
		    "select \"DMName\" from \"DRIVE\" "
		    "where \"DRIVE\".\"DriveName\" = '%s';",
		    mount_info->cmi_drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error");
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR,
			    "row num mismatch");
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		if (strcmp(PQgetvalue(db->mm_db_results, 0, 0), "") == 0) {
			mms_trace(MMS_ERR,
			    "missing dm name in DRIVE, "
			    "dm may already be detached, check STALEHANDLE");
			mm_clear_db(&db->mm_db_results);
			/* Try getting DMName from STALEHANDLE */
			if (mm_db_exec(HERE, db,
			    "select \"DMName\" from \"STALEHANDLE\" "
			    "where \"STALEHANDLE\".\"DriveName\" = '%s';",
			    mount_info->cmi_drive) != MM_DB_DATA) {
				mms_trace(MMS_ERR,
				    "db error");
				return (MM_CMD_ERROR);
			}
			if (PQntuples(db->mm_db_results) != 1) {
				mms_trace(MMS_ERR,
				    "Can't find STALEHANDLE, continue unmount");
				mm_clear_db(&db->mm_db_results);
				cmd->cmd_state = MM_CLEAR_UNLOAD;
				goto start;
			}
		}
		mm_set_mount_info_dm(PQgetvalue(db->mm_db_results, 0, 0),
				mount_info);
		mm_clear_db(&db->mm_db_results);

		/* Send a detach */
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_DETACH) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_clear_drive_cmd_func: "
			    "error adding dmp detach");
		}
		cmd->cmd_state = MM_CLEAR_RELEASE;
		return (MM_DISPATCH_DEPEND);
	}

	if (cmd->cmd_state == MM_CLEAR_RELEASE) {
		/* Send the DMP release command */
		mms_trace(MMS_DEVP,
		    "physical clear, add release");
		/*
		 * Detach has returned
		 * check error, update states
		 * Add Unload command
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			if ((cmd->cmd_response != NULL) &&
			    mm_errorcode_eq(cmd->cmd_response,
					"DM_E_NOEXISTHANDLE")) {
				mms_trace(MMS_DEVP,
				    "DM doesn't know the handle, "
				    "skip DMP unload, "
				    "send LMP unmount");
				/* Clear depend error flags */
				MM_UNSET_FLAG(cmd->cmd_flags,
					MM_CMD_DEPEND_ERROR);
			} else {
				/* detach returned handle in use */
				mms_trace(MMS_ERR, "physical clear_drive -> "
				    "DMP detach error, "
				    "handle may be inuse");
				return (MM_CMD_ERROR);
			}

		}
		mms_trace(MMS_DEVP,
		    "DM is not using handle, send DMP release if dm is ready");

		/* Check, if DM is not activated, don't send a release */
		if (mm_db_exec(HERE, db,
		    "select \"DMStateSoft\" from \"DM\" "
		    "where \"DM\".\"DMName\" = '%s';",
		    mount_info->cmi_dm) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error");
			return (MM_CMD_ERROR);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR,
			    "Can't find DM, continue unmount");
			mm_clear_db(&db->mm_db_results);
			return (MM_CMD_ERROR);
		}
		if ((strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "present") == 0) ||
		    (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "absent") == 0) ||
		    (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
		    "disconnected") == 0)) {
			/* DM cannot process release */
			/* Continue to unmount */
			mms_trace(MMS_DEVP,
			    "DMStateSoft = %s, don't send release, "
			    "continue with unmount",
			    PQgetvalue(db->mm_db_results, 0, 0));
			    mm_clear_db(&db->mm_db_results);
			    cmd->cmd_state = MM_CLEAR_UNLOAD;
			    goto start;
		}
		mms_trace(MMS_DEVP,
		    "DMStateSoft = %s, about to send release",
		    PQgetvalue(db->mm_db_results, 0, 0));
		mm_clear_db(&db->mm_db_results);
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_RELEASE) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_clear_drive_cmd_func: "
			    "error adding dmp release");
		}
		cmd->cmd_state = MM_CLEAR_UNLOAD;
		return (MM_DISPATCH_DEPEND);
	}
	if (cmd->cmd_state == MM_CLEAR_UNLOAD) {

		/* Always send a DMP unload before the physicalunmount */
		/* If MM knows what DM to send to */

		/* Try to send an unload now */
		MM_UNSET_FLAG(cmd->cmd_flags,
		    MM_CMD_DEPEND_ERROR);

		if (mount_info->cmi_dm == NULL) {
			mms_trace(MMS_ERR,
			    "didn't find DM Name, "
			    "skip DMP unload");
			cmd->cmd_state = MM_CLEAR_UNMOUNT;
			goto start;
		}
		mms_trace(MMS_DEVP,
		    "sending %s DMP unload",
		    mount_info->cmi_dm);
		if (mm_dmp_add_cmd(mm_wka, cmd, mount_info->cmi_dm,
		    MM_DMP_UNLOAD) == NULL) {
			mms_trace(MMS_ERR,
			    "mm_clear_drive_func: "
			    "error adding dmp unload");
		}
		cmd->cmd_state = MM_CLEAR_UNMOUNT;
		return (MM_DISPATCH_DEPEND);
	}

	if (cmd->cmd_state == MM_CLEAR_UNMOUNT) {
		/* DMP unload has completed, ignore any errors */
		/* and continue with the LMP unmount */

		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			mms_trace(MMS_ERR,
			    "error during DMP unload, "
			    "continue with LMP unmount");
			/* Clear depend error flags */
			MM_UNSET_FLAG(cmd->cmd_flags,
			    MM_CMD_DEPEND_ERROR);
		}
		mms_trace(MMS_DEVP,
		    "physical clear, add unmount");
		mms_trace(MMS_INFO, "Unmounting %s from %s",
		    mount_info->cmi_pcl,
		    mount_info->cmi_drive);

		/*
		 * LMP unmount command
		 */

		/* ********************* */
		/* TODO: FIX SIDE NAME!! */
		if ((lmp_umnt_cmd = mm_alloc_cmd(mm_wka)) == NULL) {
			mms_trace(MMS_ERR,
			    "Unable to malloc mm_command_t: %s",
			    strerror(errno));
			return (MM_CMD_ERROR);
		}
		lmp_umnt_cmd->cmd_func = mm_lmp_unmount_cmd_func;
		mm_get_uuid(new_task);
		lmp_umnt_cmd->cmd_textcmd = mms_strnew(LMP_UNMOUNT, new_task,
						mount_info->cmi_pcl,
						mount_info->cmi_pcl,
						"side 1",
						mount_info->cmi_drive,
						mount_info->cmi_pcl,
						mount_info->cmi_pcl,
						"side 1");
		mm_set_mount_info_drive(cmd->cmd_mount_info.cmi_drive,
		    &lmp_umnt_cmd->cmd_mount_info);
		lmp_umnt_cmd->cmd_root =
			mm_text_to_par_node(lmp_umnt_cmd->cmd_textcmd,
					    mms_lmpm_parse);
		lmp_umnt_cmd->cmd_task = mm_get_task(lmp_umnt_cmd->cmd_root);
		mm_add_depend(lmp_umnt_cmd, cmd);
		lmp_umnt_cmd->cmd_name = strdup("lmp unmount");

		pthread_mutex_lock(&data->mm_queue_mutex);
		mms_list_insert_tail(&data->mm_cmd_queue, lmp_umnt_cmd);
		pthread_mutex_unlock(&data->mm_queue_mutex);

		cmd->cmd_state = MM_CLEAR_FINAL;
		return (MM_DISPATCH_DEPEND);
	}
	if (cmd->cmd_state == MM_CLEAR_FINAL) {
		/*
		 * LMP mount has returned
		 * check for error,
		 * Return MM_DEPEND_DONE on success
		 */
		if (cmd->cmd_flags & MM_CMD_DEPEND_ERROR) {
			return (MM_CMD_ERROR);
		}
		mms_trace(MMS_INFO, "%s Cleared Successfully",
		    mount_info->cmi_drive);

		/* Set States For a Clear Drive */
		if (mm_db_exec(HERE, db,
			    "update \"DRIVE\" set "
			    "\"DriveStateHard\" = 'unloaded', "
			    "\"DMName\" = DEFAULT, "
			    "\"DriveLibraryOccupied\" = 'f' "
			    "where \"DriveName\" = '%s';",
		    mount_info->cmi_drive) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_clear_drive_cmd_func: "
			    "db error updating DRIVE");
		}


		/* Delete any mountphysical, mountlogical, or stalehandle */
		if (mm_db_exec(HERE, db, "delete from \"MOUNTLOGICAL\" "\
			"where \"DriveName\" = '%s';",
			mount_info->cmi_drive) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_clear_drive_cmd_func: "
			    "db error deleting MOUNTLOGICAL");
		}
		if (mm_db_exec(HERE, db, "delete from \"STALEHANDLE\" "\
			"where \"DriveName\" = '%s';",
			mount_info->cmi_drive) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_clear_drive_cmd_func: "
			    "db error deleting STALEHANDLE");
		}
		if (mm_db_exec(HERE, db, "delete from \"MOUNTPHYSICAL\" "\
			"where \"DriveName\" = '%s';",
			mount_info->cmi_drive) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_clear_drive_cmd_func: "
			    "db error deleting MOUNTPHYSICAL");
		}

		if (mm_has_depend(cmd)) {
			return (MM_DEPEND_DONE);
		}
		return (MM_CMD_DONE);
	}
	mms_trace(MMS_ERR,
	    "mm_clear_drive_cmd_func: unknown cmd state");
	return (MM_CMD_ERROR);
}

mm_command_t *
mm_add_clear_drive(char *drive_name, mm_data_t *mm_data,
		mm_db_t *db,
		mm_command_t *parent_cmd, char *cart_pcl, int force,
		int nonphysical) {

	mm_command_t		*cmd;
	mm_wka_t		*lm_wka;
	PGresult		*lm_name;
	uuid_text_t		uuid;

	mm_command_t *cur_cmd;

	mms_trace(MMS_DEVP, "Adding mm_clear_drive_cmd_func");

	if (drive_name == NULL) {
		mms_trace(MMS_DEBUG,
		    "mm_add_clear_drive passed null drive_name");
		return (NULL);
	}
	if (mm_data == NULL) {
		mms_trace(MMS_DEBUG,
		    "mm_add_clear_drive passed null mm_data");
		return (NULL);
	}
	if (db == NULL) {
		mms_trace(MMS_DEBUG,
		    "mm_add_clear_drive passed null db pointer");
		return (NULL);
	}


	if (mm_db_exec(HERE, db,
		    "select \"LMName\", \"LibraryName\" "\
		    "from \"LM\" "			    \
		    "where \"LibraryName\" in "\
		    "(select \"LibraryName\" from "\
		    "\"DRIVE\" where \"DriveName\" = '%s');",
		    drive_name) != MM_DB_DATA) {
		mms_trace(MMS_ERR, "Couldn't get LM Name -> "	\
		    "mm_add_clear_drive");
		mm_clear_db(&db->mm_db_results);
		return (NULL);
	}
	lm_name = db->mm_db_results;
	if (PQntuples(lm_name) == 0) {
		mms_trace(MMS_ERR, "Couldn't get LM Name -> "	\
		    "mm_add_clear_drive");
		mm_clear_db(&lm_name);
		return (NULL);
	}

	/* Check the queue, if there is already a clear drive, */
	/* do not add another */
	/* If other is found, return a pointer to that clear drive */
	pthread_mutex_lock(&mm_data->mm_queue_mutex);
		mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
			if ((cur_cmd->cmd_func == mm_clear_drive_cmd_func) ||
			    (cur_cmd->cmd_func ==
			    mm_non_physical_clear_cmd_func)) {
				if ((strcmp(cur_cmd->cmd_mount_info.cmi_drive,
				    drive_name) == 0) &&
				    (strcmp(cur_cmd->cmd_mount_info.cmi_library,
				    PQgetvalue(lm_name, 0, 1)) == 0)) {
					mms_trace(MMS_ERR,
					    "already have a clear "
					    "drive for %s , %s",
					    drive_name,
					    PQgetvalue(lm_name, 0, 1));
					pthread_mutex_unlock(&mm_data->
					    mm_queue_mutex);
					mm_clear_db(&lm_name);
					return (cur_cmd);
				}

			}
		}
	pthread_mutex_unlock(&mm_data->mm_queue_mutex);



	lm_wka = NULL;
	mms_list_foreach(&mm_data->mm_wka_list, lm_wka) {
		if (strcmp(lm_wka->wka_conn.cci_instance,
			    PQgetvalue(lm_name, 0, 0)) == 0) {
			/* Found the wka of lm */
			break;
		}
	}
	if ((lm_wka == NULL) || (strcmp(lm_wka->wka_conn.cci_instance,
					PQgetvalue(lm_name, 0, 0)) != 0)) {
		/* bad wka */
		mms_trace(MMS_DEBUG, "Could not find a connected LM");
		mm_clear_db(&lm_name);
		return (NULL);
	}
	if ((cmd = mm_alloc_cmd(lm_wka)) == NULL) {
		mms_trace(MMS_ERR,
			"Unable to malloc mm_command_t: %s",
			strerror(errno));
		mm_clear_db(&lm_name);
		return (NULL);
	}
	if (parent_cmd != NULL) {
		mm_add_depend(cmd, parent_cmd);
	}
	mm_get_uuid(uuid);
	cmd->cmd_root = NULL;
	cmd->cmd_task = NULL;
	cmd->cmd_task = strdup(uuid);
	if (cmd->cmd_task == NULL) {
		mms_trace(MMS_ERR, "Error malloc cmd_task in add cmd");
		mm_clear_db(&lm_name);
		return (NULL);
	}
	if (nonphysical) {
		cmd->cmd_func = mm_non_physical_clear_cmd_func;
	} else {
		cmd->cmd_func = mm_clear_drive_cmd_func;
	}
	cmd->cmd_name = strdup("clear drive");

	cmd->cmd_mount_info.cmi_drive = strdup(drive_name);
	cmd->cmd_mount_info.cmi_library = strdup(PQgetvalue(lm_name, 0, 1));

	/* Force or not */
	cmd->cmd_mount_info.cui_force = force;

	/* Cart_pcl */
	if (cart_pcl != NULL) {
		mm_set_mount_info_pcl(cart_pcl,
		    &cmd->cmd_mount_info);
	}
	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_insert_tail(&mm_data->mm_cmd_queue, cmd);
	pthread_mutex_unlock(&mm_data->mm_queue_mutex);
	mm_clear_db(&lm_name);
	return (cmd);

}
