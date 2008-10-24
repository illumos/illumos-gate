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
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/wait.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <libgen.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include <netdb.h>
#include <mms_cores.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <time.h>
#include <libscf.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_commands.h"
#include "mm_sql.h"
#include "mm_sql_impl.h"
#include "mm_task.h"
#include "mm_path.h"
#include "mm_db_version.h"
#include "mms_sock.h"
#include "mms_cfg.h"

static char *_SrcFile = __FILE__;

/*
 * MM data
 */
int			mm_exiting = 0;
int			mm_refresh = 0;
static mm_data_t	mm_data;
static mm_data_t	*data = &mm_data;

/*
 * mm_signal_handler
 *
 * Parameters:
 *	-int signo
 *
 * This is the routine used to handle various signals
 *
 * Return Values:
 *	None
 *
 */
static void
mm_signal_handler(int signo)
{
	switch (signo) {
	case SIGINT:
		mms_trace(MMS_DEVP, "SIGINT received");
		mm_exiting = 1;
		break;
	case SIGTERM:
		mms_trace(MMS_DEVP, "SIGTERM received");
		mm_exiting = 1;
		break;
	case SIGHUP:
		mms_trace(MMS_DEVP, "SIGHUP received");
		mm_refresh = 1;
		break;
	case SIGPIPE:
		mms_trace(MMS_DEVP, "SIGPIPE received");
		break;
	}
}

/*
 * mm_init_mm
 *
 * Parameters:
 *	- mm_data :	Pointer to mm_data_t structure
 *
 * This function initialzes the various elements of mm_data
 *
 * Return Values:
 *	None
 *
 */
void
mm_init_mm(mm_data_t *mm_data)
{
	memset(mm_data, 0, sizeof (mm_data_t));

	mms_list_create(&mm_data->mm_cmd_queue, sizeof (mm_command_t),
	    offsetof(mm_command_t, cmd_next));
	mms_list_create(&mm_data->mm_wka_list, sizeof (mm_wka_t),
	    offsetof(mm_wka_t, wka_next));
	(void) mms_host_info(mm_data->mm_host_name, mm_data->mm_host_ip);

	/* list mutex */
	pthread_mutex_init(&mm_data->mm_queue_mutex, NULL);
	pthread_mutex_init(&mm_data->mm_wka_mutex, NULL);

	/* worker */
	pthread_mutex_init(&mm_data->mm_worker_mutex, NULL);
	pthread_cond_init(&mm_data->mm_work_cv, NULL);
	pthread_cond_init(&mm_data->mm_accept_cv, NULL);

	/* Task Manager */
	pthread_mutex_init(&mm_data->mm_task_man_mutex, NULL);
	pthread_cond_init(&mm_data->mm_task_cv, NULL);
	pthread_mutex_init(&mm_data->mm_command_mutex, NULL);

	/* Notify */
	pthread_mutex_init(&mm_data->mm_notify_mutex, NULL);
	pthread_cond_init(&mm_data->mm_notify_cv, NULL);

}



/*
 * mm_init_attribute_info
 *
 * Parameters:
 *	- mm_data: 	Pointer to mm_data_t structure
 *
 * This function intializes the attr_info struct
 *
 * Return Values:
 *	0 for success
 *
 */
int
mm_init_attribute_info(mm_data_t *mm_data) {
	mm_attribute_info_t *attr_info = &mm_data->mm_attr_info;

	/* Restricted Status OBJECTS */
	/* modifiable by 'system' */
	/* MM_NUM_STATUS_OBJS */
	attr_info->status_objs[0] = strdup("MOUNTLOGICAL");
	attr_info->status_objs[1] = strdup("MOUNTPHYSICAL");
	attr_info->status_objs[2] = strdup("DRIVECARTRIDGEACCESS");
	attr_info->status_objs[3] = strdup("CONNECTION");
	attr_info->status_objs[4] = strdup("SESSION");
	attr_info->status_objs[5] = strdup("TASK");
	attr_info->status_objs[6] = strdup("TASKCARTRIDGE");
	attr_info->status_objs[7] = strdup("TASKDRIVE");
	attr_info->status_objs[8] = strdup("TASKLIBRARY");
	attr_info->status_objs[9] = strdup("MESSAGE");
	attr_info->status_objs[10] = strdup("REQUEST");
	attr_info->status_objs[11] = strdup("STALEHANDLE");
	attr_info->status_objs[12] = strdup("SLOTCONFIG");
	attr_info->status_objs[13] = strdup("NOTIFY");

	/* Restricted Status Attributes */
	/* modifiable by 'system' */
	/* MM_NUM_STATUS_ATTS */
	attr_info->status_atts[0] = strdup("LIBRARY.LibraryBroken");
	attr_info->status_atts[1] = strdup("LIBRARY.LibraryStateHard");
	attr_info->status_atts[2] = strdup("LIBRARY.LibraryStateSoft");
	attr_info->status_atts[3] = strdup("LM.LMHost");
	attr_info->status_atts[4] = strdup("LM.LMStateHard");
	attr_info->status_atts[5] = strdup("LM.LMStateSoft");
	attr_info->status_atts[6] = strdup("BAY.BayAccessible");
	attr_info->status_atts[7] = strdup("SLOT.CartridgeID");
	attr_info->status_atts[8] = strdup("SLOT.CartridgePCL");
	attr_info->status_atts[9] = strdup("SLOT.SlotAccessible");
	attr_info->status_atts[10] = strdup("SLOT.SlotOccupied");
	attr_info->status_atts[11] = strdup("DRIVE.DriveBroken");
	attr_info->status_atts[12] = strdup("DRIVE.DriveStateSoft");
	attr_info->status_atts[13] = strdup("DRIVE.DriveStateHard");
	attr_info->status_atts[14] = strdup("DRIVE.DriveTimeCreated");
	attr_info->status_atts[15] = strdup("DRIVE.DriveTimeMountedLast");
	attr_info->status_atts[16] = strdup("DRIVE.DriveTimeMountedTotal");
	attr_info->status_atts[17] = strdup("DRIVE.DriveNumberMounts");
	attr_info->status_atts[18] =
		strdup("DRIVE.DriveNumberMountsSinceCleaning");
	attr_info->status_atts[19] = strdup("DRIVE.DriveLibraryAccessible");
	attr_info->status_atts[20] = strdup("DRIVE.DriveLibraryOccupied");
	attr_info->status_atts[21] = strdup("DRIVE.CartridgePCL");
	attr_info->status_atts[22] = strdup("DRIVE.DriveNeedsCleaning");
	attr_info->status_atts[23] = strdup("DRIVE.MaxMounts");
	attr_info->status_atts[24] = strdup("DM.DMHost");
	attr_info->status_atts[25] = strdup("DM.DMStateHard");
	attr_info->status_atts[26] = strdup("DM.DMStateSoft");
	attr_info->status_atts[27] = strdup("CARTRIDGE.CartridgeState");
	attr_info->status_atts[28] = strdup("CARTRIDGE.CartridgeTimeCreated");
	attr_info->status_atts[29] =
		strdup("CARTRIDGE.CartridgeTimeMountedLast");
	attr_info->status_atts[30] =
		strdup("CARTRIDGE.CartridgeTimeMountedTotal");
	attr_info->status_atts[31] = strdup("CARTRIDGE.CartridgeNumberMounts");
	attr_info->status_atts[32] = strdup("CARTRIDGE.CartridgeNumberVolumes");
	attr_info->status_atts[33] = strdup("SIDE.SideTimeCreated");
	attr_info->status_atts[34] = strdup("SIDE.SideTimeMountedLast");
	attr_info->status_atts[35] = strdup("SIDE.SideTimeMountedTotal");
	attr_info->status_atts[36] = strdup("PARTITION.PartitionAllocatable");
	attr_info->status_atts[37] = strdup("PARTITION.PartitionNumberMounts");
	attr_info->status_atts[38] = strdup("PARTITION.PartitionTimeCreated");
	attr_info->status_atts[39] =
		strdup("PARTITION.PartitionTimeMountedTotal");
	attr_info->status_atts[40] =
		strdup("PARTITION.PartitionTimeMountedLast");
	attr_info->status_atts[41] = strdup("VOLUME.VolumeNumberMounts");
	attr_info->status_atts[42] = strdup("VOLUME.VolumeTimeCreated");
	attr_info->status_atts[43] = strdup("VOLUME.VolumeTimeMountedLast");
	attr_info->status_atts[44] = strdup("VOLUME.VolumeTimeMountedTotal");
	attr_info->status_atts[45] = strdup("LIBRARY.LibraryOnline");
	attr_info->status_atts[46] = strdup("DRIVE.DriveOnline");
	attr_info->status_atts[47] = strdup("LIBRARY.LMName");
	attr_info->status_atts[48] = strdup("PARTITION.CartridgeID");
	attr_info->status_atts[49] =
		strdup("CARTRIDGE.CartridgeWriteProtected");

	/* Restricted Control Attributes */
	/* modifiable by 'administrator' */
	/* MM_NUM_CONTROL_ATTS */
	attr_info->control_atts[0] = strdup("LIBRARY.LibraryDisabled");
	attr_info->control_atts[1] = strdup("CARTRIDGE.LibraryName");
	attr_info->control_atts[2] = strdup("LM.LMMessageLevel");
	attr_info->control_atts[3] = strdup("DRIVE.DriveGroupName");
	attr_info->control_atts[4] = strdup("DRIVE.DrivePriority");
	attr_info->control_atts[5] = strdup("DRIVE.DMName");
	attr_info->control_atts[6] = strdup("DRIVE.DriveDisabled");
	attr_info->control_atts[7] = strdup("DRIVEGROUP.DriveGroupUnloadTime");
	attr_info->control_atts[8] =
	strdup("DRIVEGROUPAPPLICATION.DriveGroupApplicationUnloadTime");
	attr_info->control_atts[9] = strdup("DM.DMMessageLevel");
	attr_info->control_atts[10] = strdup("CARTRIDGE.CartridgeGroupName");
	attr_info->control_atts[11] =
		strdup("CARTRIDGEGROUP.CartridgeGroupPriority");
	attr_info->control_atts[12] =
	strdup("CARTRIDGEGROUPAPPLICATION.CartridgeGroupApplicationPriority");

	attr_info->control_atts[13] = strdup("CARTRIDGE.ApplicationName");

	attr_info->control_atts[14] = strdup("LM.LMDisabled");
	attr_info->control_atts[15] = strdup("DM.DMDisabled");
	return (0);
}


/*
 * mm_signal
 *
 * Parameters:
 *	- sig : signal
 *	- handler : function to handle sig
 *
 * Sets up a handler function for a given signal
 *
 * Return Values:
 *	None:
 *
 */
static void
mm_signal(int sig, void (*handler) ())
{
	/*
	 * Setup to catch signals
	 */
	struct  sigaction act, oact;

	mms_trace(MMS_DEVP, "Setting signal handler for signal %d", sig);
	memset(&act, 0, sizeof (act));
	act.sa_sigaction = handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sig != SIGALRM) {
		/*
		 * Allow alarm signal to interrupt
		 */
		act.sa_flags |= SA_RESTART;
	}
	if (sigaction(sig, &act, &oact) < 0) {
		mms_trace(MMS_ERR, "Can't set signal handler for "
		    "signal %d: %s", sig, strerror(errno));
		exit(SMF_EXIT_ERR_FATAL);
	}
}


/*
 * mm_initialize
 *
 * Parameters:
 *	- mm_data : pointer to mm_data_t
 *
 * Initialzes structures, creates threads and starts db connections
 *
 * Return Values:
 *	None
 *
 */
static void
mm_initialize(mm_data_t *mm_data, int daemon_mode)
{
	mms_err_t	err;
	char		ebuf[MMS_EBUF_LEN];
	int		i;
	int		fd_limit;
	pid_t		pid;
	char		*corename;


	/*
	 * Initialize
	 */

	/*
	 * Start tracing
	 */
	openlog("mm", LOG_PID, LOG_DAEMON);


	/*
	 * Decome a daemon
	 */
	if (daemon_mode) {
		if (pid = fork()) {
			/*
			 * Parent process
			 */
			if (pid == (pid_t)(-1)) {
				syslog(LOG_ERR, "%s:%d fork error", MMS_HERE);
				exit(SMF_EXIT_ERR_FATAL);
			} else {
				/* Successfully forked, parent exits */
				exit(0);
			}
		}
	}

	/*
	 * Direct stdin, stdout and stderr to /dev/null
	 */
	fopen("/dev/null", "r");
	fopen("/dev/null", "w");
	fopen("/dev/null", "w");

	setsid();
	chdir("/");
	umask(0);
	syslog(LOG_INFO, "%s:%d MM Starting", MMS_HERE);

	if (mms_set_core(MMS_CORES_DIR, NULL)) {
		syslog(LOG_ERR, "%s:%d core setup %s", MMS_HERE,
		    strerror(errno));
		exit(SMF_EXIT_ERR_FATAL);
	}

	corename = mms_strapp(NULL, "core.mmsmm");
	/* Check to see how many core files exist */
	if (mms_man_cores(MMS_CORES_DIR, corename)) {
		syslog(LOG_ERR,
		    "%s:%d core management %s", MMS_HERE,
		    strerror(errno));
	}
	free(corename);

	/*
	 * Close unused file descriptors
	 */
	for (i = 0; i < OPEN_MAX; i++) {
		close(i);
	}

	/* Initialize mm */

	mm_init_mm(mm_data);
	mm_data->mm_service_fd = -1;
	mm_data->mm_work_todo = 0;

	/*
	 * Start tracing
	 */
	if (mms_trace_open(MM_TRACE_FN, MMS_ID_MM, -1, -1, 1, 1)) {
		syslog(LOG_NOTICE, "%s:d MM mms_trace open failed", MMS_HERE);
	}
	(void) mms_trace_filter(mm_read_trace_level());

	/* Use devp as default if debug build */
#ifdef MMSDEBUG
	(void) mms_trace_filter(MMS_SEV_DEVP);
#endif
	mms_trace(MMS_INFO, "MM Starting");

	/*
	 * Read config
	 */
	if (mm_cfg_read(&mm_data->mm_cfg)) {
		syslog(LOG_NOTICE, "%s:%d MM read config failed", MMS_HERE);
		mms_trace(MMS_ERR, "MM cfg read failed");
		exit(SMF_EXIT_ERR_CONFIG);
	}
	mm_data->mm_db.mm_db_cfg = &mm_data->mm_cfg.mm_db_cfg;
	mm_data->mm_db_main.mm_db_cfg = &mm_data->mm_cfg.mm_db_cfg;
	mm_data->mm_db_tm.mm_db_cfg = &mm_data->mm_cfg.mm_db_cfg;

	/*
	 * Load mms data model object pathing
	 */
	if (mm_init_paths(MM_PATHS_FN)) {
		mms_trace(MMS_ERR, "MM failed to load object paths");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	if (mm_init_attribute_info(mm_data)) {
		mms_trace(MMS_ERR, "MM failed to load attribute info");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Start and initialize database server
	 */
	if (mm_db_init(&mm_data->mm_db) != MM_DB_OK) {
		mms_trace(MMS_ERR, "unable to load or check db schema");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Database
	 */
	mm_data->mm_db.mm_db_has_list = 0;
	mm_data->mm_db.mm_db_resending = 0;
	if (mm_db_connect(&mm_data->mm_db) != MM_DB_OK) {
		mms_trace(MMS_ERR, "MM db connect failed");
		exit(SMF_EXIT_ERR_FATAL);
	}
	/* get system settings from database */
	mm_reconcile_trace_level(&mm_data->mm_db);
	fd_limit = mm_get_fd_limit(&mm_data->mm_db);
	if (mm_message_init(&mm_data->mm_db, mm_data)) {
		mms_trace(MMS_ERR, "MM messages failed");
		exit(SMF_EXIT_ERR_FATAL);
	}
	if (mm_db_exec(HERE, &mm_data->mm_db, "update \"SYSTEM\" set "
	    "\"SystemName\" = '%s',\"SystemInstance\" = '%s';",
	    mm_data->mm_cfg.mm_network_cfg.cli_name,
	    mm_data->mm_cfg.mm_network_cfg.cli_inst) != MM_DB_OK) {
		mms_trace(MMS_ERR, "MM system object update failed");
		exit(SMF_EXIT_ERR_FATAL);
	}
	/* cleanup database */
	if (mm_db_exec(HERE, &mm_data->mm_db,
	    "VACUUM VERBOSE ANALYZE;") != MM_DB_OK) {
		mms_trace(MMS_ERR, "MM vacuum failed");
		exit(SMF_EXIT_ERR_FATAL);
	}
	if (mm_db_exec(HERE, &mm_data->mm_db,
	    "REINDEX DATABASE %s;",
	    mm_data->mm_db.mm_db_cfg->mm_db_name) != MM_DB_OK) {
		mms_trace(MMS_ERR, "MM reindex failed");
		exit(SMF_EXIT_ERR_FATAL);
	}

	mms_trace(MMS_DEVP, "Verify of supported device types");
	if (mm_init_types(mm_data, MM_TYPES_FN)) {
		mms_trace(MMS_ERR, "MM failed to verify supported types");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Set MMS password
	 */
	if (mm_db_exec_si(HERE, &mm_data->mm_db,
	    "update \"MMPASSWORD\" set \"Password\" = '%s' "
	    "where \"ApplicationName\" = '%s';",
	    mm_data->mm_cfg.mm_network_cfg.cli_pass,
	    MM_APP) != MM_DB_OK) {
		mms_trace(MMS_ERR, "MM failed to update password");
		exit(SMF_EXIT_ERR_FATAL);
	}

	mm_db_disconnect(&mm_data->mm_db);

	/*
	 * Setup open file descriptor limit
	 */
	if (mm_set_fd_limit(fd_limit)) {
		mms_trace(MMS_DEVP, "MM failed to set fd limit %d", fd_limit);
	}

	if (mms_listen(mm_data->mm_cfg.mm_network_cfg.cli_host,
	    mm_data->mm_cfg.mm_network_cfg.cli_port,
	    &mm_data->mm_service_fd, &err)) {
		mms_get_error_string(&err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "mm listen - %s", ebuf);
		exit(SMF_EXIT_ERR_FATAL);
	}
	mms_trace(MMS_DEVP, "Server - fd %d", mm_data->mm_service_fd);

#ifdef	MMS_OPENSSL
	if (mms_ssl_server(&mm_data->mm_cfg.mm_network_cfg,
	    mm_data->mm_cfg.mm_ssl_dh_file,
	    mm_data->mm_cfg.mm_ssl_verify_peer,
	    &mm_data->mm_ssl_data, &err)) {
		mms_get_error_string(&err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "ssl init - %s", ebuf);
		exit(SMF_EXIT_ERR_CONFIG);
	}
#endif	/* MMS_OPENSSL */

	/*
	 * Ready for mm clients to connect
	 */
	mms_trace(MMS_INFO, "MM initialized");
}

/*
 * mm_char_list_destroy
 *
 * Parameters:
 *	- list: pointer to mm_list_t
 *
 * Free's memory for an entire mm_list_t
 * caller must do a list_destroy
 *
 * Return Values:
 *	None
 *
 */
void
mm_char_list_destroy(mms_list_t *list) {
	mm_char_list_t *char_list;
	mm_char_list_t *next_char_list;

	for (char_list = mms_list_head(list);
	    char_list != NULL;
	    char_list = next_char_list) {
		free(char_list->text);
		next_char_list =
			mms_list_next(list,
				char_list);
		mms_list_remove(list,
			    char_list);
		free(char_list);
	}
}

/*
 * mm_free_cmi_drive
 *
 * Parameters:
 *	- drive: pointer to a cmd_dirve_list_t list
 *
 * free memory for an entire cmi_drive_list_t
 * caller must do a list_destroy
 *
 * Return Values:
 *	None
 *
 */
void
mm_free_cmi_drive(cmi_drive_list_t *drive) {
	/* Drive */
	if (drive->cmi_drive_name)
		free(drive->cmi_drive_name);
	if (drive->cmi_dm_name)
		free(drive->cmi_dm_name);
	if (drive->cmi_loaded_pcl)
		free(drive->cmi_loaded_pcl);

	free(drive);
}

/*
 * mm_free_cmi_cart
 *
 * Parameters:
 *	- cart :
 *
 * Free memory for a single cmi_cart_list_t
 *
 * Return Values:
 *	None
 *
 */
void
mm_free_cmi_cart(cmi_cart_list_t *cart) {

	cmi_drive_list_t *drive;
	cmi_drive_list_t *next_drive;


	/* Cartridge */
	if (cart->cmi_library)
		free(cart->cmi_library);
	if (cart->cmi_side_name)
		free(cart->cmi_side_name);
	if (cart->cmi_cart_pcl)
		free(cart->cmi_cart_pcl);
	if (cart->cmi_cart_type)
		free(cart->cmi_cart_type);
	if (cart->cmi_bit_format)
		free(cart->cmi_bit_format);
	for (drive = mms_list_head(&cart->
			cmi_drive_list);
	    drive != NULL;
	    drive = next_drive) {
		next_drive =
			mms_list_next(&cart->
				cmi_drive_list,
				drive);
		mms_list_remove(&cart->
			cmi_drive_list,
			drive);
		mm_free_cmi_drive(drive);
	}
	mms_list_destroy(&cart->cmi_drive_list);

	free(cart);
}


/*
 * mm_free_cmi_cart_list
 *
 * Parameters:
 *	- cart_list : mms_list_t of cmi_cart_list_t
 *
 * Free memory for an entire list of cmi_cart_list_t
 * caller must do a list_destroy
 *
 * Return Values:
 *	None
 *
 */
void
mm_free_cmi_cart_list(mms_list_t *cart_list) {
	/* This function frees the cart list, */
	/* but does not destroy it */
	cmi_cart_list_t		*next_cart = NULL;
	cmi_cart_list_t		*cart = NULL;

	for (cart = mms_list_head(cart_list);
	    cart != NULL;
	    cart = next_cart) {
		next_cart =
			mms_list_next(cart_list,
				cart);
		mms_list_remove(cart_list,
			cart);
		mm_free_cmi_cart(cart);
	}
}

/*
 * mm_remove_from_depend
 *
 * Parameters:
 *	- cmd : cmd to remove from other commands depend list
 *
 * This function will remove cmd from the dependent command lists
 * of all other commands.  This should be called for every command
 * when the command is being destroyed
 *
 * if not removed from all other commands, then next list
 * access of the depend list containning this cmd will hit list_head
 * assert since the memory has already been free'd
 *
 * Return Values:
 *	None
 *
 */
void
mm_remove_from_depend(mm_command_t *cmd) {
	mm_command_t		*cur_cmd;
	mm_command_t *depend_list;
	mm_command_t *next_depend_list;

	pthread_mutex_lock(&data->
			mm_queue_mutex);
	mms_list_foreach(&data->mm_cmd_queue, cur_cmd) {
		if (cur_cmd == cmd) {
			/* this is the command to remove */
			continue;
		}
		for (depend_list = mms_list_head(&cur_cmd->cmd_depend_list);
		    depend_list != NULL;
		    depend_list = next_depend_list) {
			next_depend_list =
				mms_list_next(&cur_cmd->cmd_depend_list,
					depend_list);
			if (depend_list == cmd) {
				mms_list_remove(&cur_cmd->cmd_depend_list,
					depend_list);
			}
		}
	}

	pthread_mutex_unlock(&data->
			mm_queue_mutex);
}



/*
 * mm_destroy_cmd
 *
 * Parameters:
 *	- cmd : pointer to a command
 *
 * Does all cleanup necessary for the command
 * and free's all memory associated with this command
 * This includes reseting any data base states used
 * by the command
 *
 * Return Values:
 *	0 for success
 *
 */
int
mm_destroy_cmd(mm_command_t *cmd)
{

	cmd_mount_info_t *mount_info = &cmd->cmd_mount_info;
	cmi_mode_list_t *mode;
	cmi_mode_list_t *next_mode;
	cmi_cart_list_t *cart;
	cmi_cart_list_t *next_cart;
	mm_db_t		*db = &cmd->cmd_mm_data->mm_db;
	eject_cart_t	*eject_cart;
	eject_cart_t	*next_eject_cart;

	/* begin end command list */
	mm_command_t *cur_cmd;
	mm_command_t *next_cmd;


	if (cmd->cmd_name == NULL) {
		cmd->cmd_name = strdup("UNKNOWN COMMAND");
	}
	mms_trace(MMS_DEVP,
	    "mm_destroy_cmd, %s (%p)",
	    cmd->cmd_name,
	    cmd);


	if (cmd->cmd_func == mm_mount_cmd_func) {
		if (mm_db_exec(HERE, db,
		    "delete from \"TASK\" where " \
		    "\"TaskID\" = '%s';",
		    cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error Removing task objects...");
		}
		if (mm_db_exec(HERE, db,
		    "delete from \"REQUEST\" where "
		    "\"RequestingTaskID\" = '%s' and "
		    "\"RequestState\" != 'responded';",
		    cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error Removing request objects...");
		}
		if (cmd->cmd_mount_info.cmi_need_clear) {
			if (cmd->cmd_mount_info.cmi_drive != NULL) {
				mms_trace(MMS_DEBUG, "cmi_need_clear == true");
				(void) mm_add_clear_drive(cmd->
				    cmd_mount_info.cmi_drive,
				    data, db, NULL, NULL, 1, 0);
			}
		}
	} else if (cmd->cmd_func == mm_unmount_cmd_func) {
		if (mm_db_exec(HERE, db,
		    "delete from \"TASK\" where " \
		    "\"TaskID\" = '%s';",
		    cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error Removing task objects...");
		}
		if (mm_db_exec(HERE, db,
		    "delete from \"REQUEST\" where "
		    "\"RequestingTaskID\" = '%s' and "
		    "\"RequestState\" != 'responded';",
		    cmd->cmd_uuid) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error Removing request objects...");
		}
		if (cmd->cmd_mount_info.cmi_need_clear) {
			if (cmd->cmd_mount_info.cmi_drive != NULL) {
				mms_trace(MMS_DEBUG, "cmi_need_clear == true");
				(void) mm_add_clear_drive(cmd->
				    cmd_mount_info.cmi_drive,
				    data, db, NULL, NULL, 1, 0);
			}
		}
	}
	if ((cmd->cmd_func == mm_begin_cmd_func) ||
	    (cmd->cmd_func == mm_end_cmd_func)) {
		/* Free a begin end list */
		for (cur_cmd = mms_list_head(&cmd->cmd_beginend_list);
		    cur_cmd != NULL;
		    cur_cmd = next_cmd) {
			next_cmd =
			    mms_list_next(&cmd->cmd_beginend_list, cur_cmd);
			mms_list_remove(&cmd->cmd_beginend_list,
			    cur_cmd);
			(void) mm_destroy_cmd(cur_cmd);
		}
		mms_list_destroy(&cmd->cmd_beginend_list);
	}

	/* clean depend_list */
	mms_trace(MMS_DEVP,
	    "remove this cmd from all other cmd depend lists");
	mm_remove_from_depend(cmd);
	for (cur_cmd = mms_list_head(&cmd->cmd_depend_list);
	    cur_cmd != NULL;
	    cur_cmd = next_cmd) {
		next_cmd =
		    mms_list_next(&cmd->cmd_depend_list,
		    cur_cmd);
		mms_list_remove(&cmd->cmd_depend_list,
		    cur_cmd);
	}
	mms_list_destroy(&cmd->cmd_depend_list);

	for (cart = mms_list_head(&mount_info->
	    cmi_cart_list);
	    cart != NULL;
	    cart = next_cart) {
		next_cart =
		    mms_list_next(&mount_info->
		    cmi_cart_list,
		    cart);
		mms_list_remove(&mount_info->
		    cmi_cart_list,
		    cart);
		mm_free_cmi_cart(cart);
	}
	mms_list_destroy(&mount_info->cmi_cart_list);

	for (mode =
	    mms_list_head(&mount_info->
	    cmi_mode_list);
	    mode != NULL;
	    mode = next_mode) {
		next_mode =
		    mms_list_next(&mount_info->
		    cmi_mode_list,
		    mode);
		mms_list_remove(&mount_info->
		    cmi_mode_list,
		    mode);
		free(mode);
	}
	mms_list_destroy(&mount_info->cmi_mode_list);

	if (cmd->cmd_root != NULL) {
		mms_pn_destroy(cmd->cmd_root);
	}

	(void) mm_cancel_request(db, cmd->cmd_reqid);

	if (cmd->cmd_response) {
		mms_pn_destroy(cmd->cmd_response);
	}
	if (cmd->cmd_name)
		free(cmd->cmd_name);
	if (cmd->cmd_task)
		free(cmd->cmd_task);
	if (cmd->cmd_textcmd)
		free(cmd->cmd_textcmd);
	if (cmd->cmd_buf)
		free(cmd->cmd_buf);
	if (cmd->cmd_report)
		free(cmd->cmd_report);


	/* Free mount_info */
	if (mount_info->cmi_dm)
		free(mount_info->cmi_dm);
	if (mount_info->cmi_drive)
		free(mount_info->cmi_drive);
	if (mount_info->cmi_library)
		free(mount_info->cmi_library);
	if (mount_info->cmi_cartridge)
		free(mount_info->cmi_cartridge);
	if (mount_info->cmi_pcl)
		free(mount_info->cmi_pcl);
	if (mount_info->cmi_side_name)
		free(mount_info->cmi_side_name);
	if (mount_info->cmi_where)
		free(mount_info->cmi_where);
	if (mount_info->cmi_filename)
		free(mount_info->cmi_filename);
	if (mount_info->cmi_blocksize)
		free(mount_info->cmi_blocksize);
	if (mount_info->cmi_filesequence)
		free(mount_info->cmi_filesequence);
	if (mount_info->cmi_volumeid)
		free(mount_info->cmi_volumeid);
	if (mount_info->cmi_capability)
		free(mount_info->cmi_capability);
	if (mount_info->cmi_retention)
		free(mount_info->cmi_retention);
	if (mount_info->cmi_handle)
		free(mount_info->cmi_handle);
	if (mount_info->cmi_user)
		free(mount_info->cmi_user);
	/* Un mount */
	if (mount_info->cui_signature_type)
		free(mount_info->cui_signature_type);
	if (mount_info->cui_signature)
		free(mount_info->cui_signature);

	if (mount_info->cmi_first_lib)
		free(mount_info->cmi_first_lib);
	if (mount_info->cmi_first_drive)
		free(mount_info->cmi_first_drive);
	if (mount_info->cmi_second_lib)
		free(mount_info->cmi_second_lib);
	if (mount_info->cmi_second_drive)
		free(mount_info->cmi_second_drive);

	if (cmd->cmd_eclass)
		free(cmd->cmd_eclass);
	if (cmd->cmd_ecode)
		free(cmd->cmd_ecode);

	/* Eject cartridge */
	if (cmd->cmd_eject) {
		for (eject_cart = mms_list_head(&cmd->cmd_eject->eject_list);
		    eject_cart != NULL;
		    eject_cart = next_eject_cart) {
			next_eject_cart =
			    mms_list_next(&cmd->cmd_eject->eject_list,
			    eject_cart);

			mms_list_remove(&cmd->cmd_eject->eject_list,
			    eject_cart);

			free(eject_cart->cart_cartid);
			free(eject_cart->cart_cartpcl);
			free(eject_cart->cart_slottype);
			free(eject_cart->cart_slotname);
			free(eject_cart->cart_library);
			free(eject_cart);
		}
		mms_list_destroy(&cmd->cmd_eject->eject_list);
		free(cmd->cmd_eject->eject_library);
		free(cmd->cmd_eject->eject_lm);
		free(cmd->cmd_eject->eject_slotgroup);
		free(cmd->cmd_eject);
	}

	/* Path Matching */
	if (cmd->cmd_has_list) {
		mm_clear_source(cmd);
		mm_clear_dest(cmd);
		mm_clear_const(cmd);
		mms_list_destroy(&cmd->cmd_source_list);
		mms_list_destroy(&cmd->cmd_dest_list);
		mms_list_destroy(&cmd->cmd_const_list);
		mm_free_list(&cmd->cmd_resp_list);
		mms_list_destroy(&cmd->cmd_resp_list);
		mm_free_err_list(cmd);
		mms_list_destroy(&cmd->cmd_err_list);
	}

	/* Message */
	if (cmd->cmd_msg.msg_localized) {
		free(cmd->cmd_msg.msg_localized);
	}

	free(cmd);
	return (0);
}

/*
 * mm_destroy_wka
 *
 * Parameters:
 *	- wka : pointer to a mm_wka_t
 *
 * Free's all memory associated with this client workarea
 *
 * Return Values:
 *	None
 *
 */
void
mm_destroy_wka(mm_wka_t	*wka) {
	if (wka->wka_conn.cci_client)
		free(wka->wka_conn.cci_client);
	if (wka->wka_conn.cci_instance)
		free(wka->wka_conn.cci_instance);
	if (wka->wka_conn.cci_language)
		free(wka->wka_conn.cci_language);
	if (wka->wka_conn.cci_version)
		free(wka->wka_conn.cci_version);
	if (wka->wka_conn.cci_password)
		free(wka->wka_conn.cci_password);
	if (wka->wka_conn.cci_certificate)
		free(wka->wka_conn.cci_certificate);
	if (wka->wka_conn.cci_authentication)
		free(wka->wka_conn.cci_authentication);
	if (wka->mm_wka_conn)
		free(wka->mm_wka_conn);
	free(wka);
}

/*
 * mm_return_unload
 *
 * Parameters:
 *	- library : ptr to string of library name
 *	- drive : ptr to string of drive name
 *	- mm_data : pointer to mm_data_t
 *
 * For a given library and drive, search the command
 * queue and return a pointer to the delay unload
 * command for his library and drive
 *
 * Return Values:
 *	mm_command_t* : if the function finds a
 *			delay unload for this library
 *			and drive, it will return
 *			a ptr to that command
 *	NULL:		If no unload is found
 *			the function will return NULL
 *
 */
mm_command_t *
mm_return_unload(char *library, char *drive,
		mm_data_t *mm_data) {

	cmd_mount_info_t	*mount_info = NULL;
	mm_command_t		*cur_cmd;
	mm_command_t		*unload_cmd = NULL;

	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if (cur_cmd->cmd_func == mm_delay_unmount_cmd_func) {
			mount_info = &cur_cmd->cmd_mount_info;
			if ((strcmp(library, mount_info->cmi_library) == 0) &&
			    (strcmp(drive, mount_info->cmi_drive) == 0)) {
				unload_cmd = cur_cmd;
				break;
			}
		}
	}
	pthread_mutex_unlock(&mm_data->
			mm_queue_mutex);
	return (unload_cmd);
}

/*
 * mm_set_depend_response
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Copy the response to for this command to each command
 * dependent on this command (in this cmd's depend list)
 *
 * Return Values:
 *	1 : if responses were copied
 *	0 : if no responses were copied
 *
 */
int
mm_set_depend_response(mm_command_t *cmd) {
	mm_command_t *cur_depend = NULL;
	int			set_one = 0;
	char			*rsp_text = NULL;

	if (mm_has_depend(cmd) == 0) {
		return (0);
	}
	/* Generate text cmd from cmd response */
	rsp_text = mms_pn_build_cmd_text(cmd->cmd_response);
	if (rsp_text == NULL) {
		mms_trace(MMS_ERR,
		    "error getting response text");
		return (0);
	}
	mms_list_foreach(&cmd->cmd_depend_list, cur_depend) {
		set_one = 1;
		mms_trace(MMS_DEVP,
		    "%s has parent, %s",
		    cmd->cmd_name,
		    cur_depend->
		    cmd_name);
		if (cur_depend->
		    cmd_response != NULL)
			free(cur_depend->
			    cmd_response);
		/* Rebuild parnode */
		switch (cmd->cmd_language) {
		case MM_LANG_MMP:
			cur_depend->cmd_response =
				mm_text_to_par_node(rsp_text,
						mms_mmp_parse);
			break;
		case MM_LANG_DMP:
			cur_depend->cmd_response =
				mm_text_to_par_node(rsp_text,
						mms_dmpm_parse);
			break;
		case MM_LANG_LMP:
			cur_depend->cmd_response =
				mm_text_to_par_node(rsp_text,
						mms_lmpm_parse);
			break;
		}
	}
	free(rsp_text);
	mms_pn_destroy(cmd->cmd_response);
	cmd->cmd_response = NULL;
	return (set_one);
}

/*
 * mm_set_depend_error
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Copy the error response to for this command to each command
 * dependent on this command (in this cmd's depend list)
 * Set error flags for each dependent command
 *
 * Return Values:
 *	1 : if responses were copied
 *	0 : if no responses were copied
 *
 */
int
mm_set_depend_error(mm_command_t *cmd) {
	mm_command_t *cur_depend = NULL;
	int			set_one = 0;
	char			*rsp_text = NULL;

	/* this cmd had an error, */
	/* set error buf for every command */
	/* depending on this one */

	/*
	 * Command has a parent
	 * Set error flags,
	 * and dispatch
	 * parent command func can
	 * handle the error
	 * Save the child's error
	 * response for the parent
	 */
	if (mm_has_depend(cmd) == 0) {
		return (0);
	}

	/* Generate text cmd from cmd response */
	rsp_text = mms_pn_build_cmd_text(cmd->cmd_response);
	if (rsp_text == NULL) {
		mms_trace(MMS_ERR,
		    "error getting response text");
		return (0);
	}

	mms_list_foreach(&cmd->cmd_depend_list, cur_depend) {
		set_one = 1;
		mms_trace(MMS_DEVP,
		    "%s has parent, %s",
		    cmd->cmd_name,
		    cur_depend->
		    cmd_name);
		if (cur_depend->
		    cmd_response != NULL)
			free(cur_depend->
			    cmd_response);
		/* Rebuild parnode */
		switch (cmd->cmd_language) {
		case MM_LANG_MMP:
			cur_depend->cmd_response =
				mm_text_to_par_node(rsp_text,
						mms_mmp_parse);
			break;
		case MM_LANG_DMP:
			cur_depend->cmd_response =
				mm_text_to_par_node(rsp_text,
						mms_dmpm_parse);
			break;
		case MM_LANG_LMP:
			cur_depend->cmd_response =
				mm_text_to_par_node(rsp_text,
						mms_lmpm_parse);
			break;
		}
		cur_depend->cmd_flags |=
			MM_CMD_DEPEND_ERROR;
		cur_depend->cmd_flags |=
			MM_CMD_DISPATCHABLE;

	}
	free(rsp_text);
	mms_pn_destroy(cmd->cmd_response);
	cmd->cmd_response = NULL;
	return (set_one);
}

/*
 * mm_dispatch_all_depend
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Set every command dependent on this command
 * ready for dispatch
 *
 * Return Values:
 *	None
 *
 */
void
mm_dispatch_all_depend(mm_command_t *cmd) {
	/* set every depend for this cmd for dispatch */
	mm_command_t *cur_depend = NULL;
	mms_list_foreach(&cmd->cmd_depend_list, cur_depend) {
		cur_depend->cmd_flags |=
			MM_CMD_DISPATCHABLE;
	}
}

/*
 * mm_remove_this_depend
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *	- remove : ptr to mm_command_t
 *
 * Removes the command 'remove' from the depend list in 'cmd'
 *
 * Return Values:
 *	none
 *
 */
void
mm_remove_this_depend(mm_command_t *cmd, mm_command_t *remove) {
	/* remove remove from cmd's depend list */
	mm_command_t *depend_list;
	mm_command_t *next_depend_list;
	for (depend_list = mms_list_head(&cmd->cmd_depend_list);
	    depend_list != NULL;
	    depend_list = next_depend_list) {
		next_depend_list =
			mms_list_next(&cmd->cmd_depend_list,
				depend_list);
		if (depend_list == remove) {
			mms_list_remove(&cmd->cmd_depend_list,
				depend_list);
		}
	}
}

/*
 * mm_remove_all_depend
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Removes all depedent commands from cmd's depend list
 *
 * Return Values:
 *	None
 *
 */
void
mm_remove_all_depend(mm_command_t *cmd) {
	/* remove and free all */
	mm_command_t *depend_list;
	mm_command_t *next_depend_list;
	for (depend_list = mms_list_head(&cmd->cmd_depend_list);
	    depend_list != NULL;
	    depend_list = next_depend_list) {
		next_depend_list =
			mms_list_next(&cmd->cmd_depend_list,
				depend_list);
		mms_list_remove(&cmd->cmd_depend_list,
			    depend_list);
	}
}

/*
 * mm_is_parent
 *
 * Parameters:
 *	- parent : ptr to mm_command_t
 *	- child : ptr to mm_command_t
 *
 * Determines if parent is in the depend list of child
 *
 * Return Values:
 *	1 :	if parent is in the depend list
 *		of child
 *	0 :	if parent is not in the depend list
 *		of child
 *
 */
int
mm_is_parent(mm_command_t *parent, mm_command_t *child) {
	/* is parent, the parent of child? */
	mm_command_t *cur_depend = NULL;
	mms_list_foreach(&child->cmd_depend_list, cur_depend) {
		if (cur_depend == parent) {
			return (1);
		}
	}
	return (0);
}


/*
 * mm_first_parent
 *
 * Parameters:
 *	- child : ptr to mm_command_t
 *
 * Returns the first command dependent on child
 *
 * Return Values:
 *	mm_command_t* :	returns a pointer to the
 *			first parent of child
 *	NULL :		returns NULL if there are
 *			no parents of child
 *
 */
mm_command_t *
mm_first_parent(mm_command_t *child) {
	mm_command_t *cur_depend = NULL;

	cur_depend = mms_list_head(&child->cmd_depend_list);
	return (cur_depend);
}

/*
 * mm_top_parent
 *
 * Parameters:
 *	- child : ptr to mm_command_t
 *
 * Finds the 1st command to set child as a dependent
 *
 * Return Values:
 *	mm_command_t* : ptr to the 1st parent of child
 *	NULL :		return NULL if child had no
 *			commands in its depend list
 */
mm_command_t *
mm_top_parent(mm_command_t *child) {
	/* return parent of this child */
	mm_command_t *cur_depend = NULL;
	if (mm_has_depend(child) == 0) {
		/* No parent */
		return (NULL);
	}
	cur_depend = mms_list_head(&child->cmd_depend_list);
	if (cur_depend == NULL) {
		return (NULL);
	}
	if (mm_has_depend(cur_depend) == 0) {
		return (cur_depend);
	}
	return (mm_top_parent(cur_depend));
}


/*
 * mm_has_depend
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Determine if cmd has any commands in its depend list
 *
 * Return Values:
 *	0 :	for no commands in its depend list
 *	1 :	for any command in its depend list
 *
 */
int
mm_has_depend(mm_command_t *cmd) {
	/* does this command have a depend in the list */
	if (mms_list_head(&cmd->cmd_depend_list) != NULL) {
		return (1);
	}
	return (0);
}

/*
 * mm_add_depend
 *
 * Parameters:
 *	- child : ptr to mm_command_t
 *	- parent : ptr to mm_command_t
 *
 * Adds command pointed to by parent to the depend list
 * of command pointed to by child
 *
 * Return Values:
 *	None
 *
 */
void
mm_add_depend(mm_command_t *child, mm_command_t *parent) {
	/* this function adds parent to the child */
	/* allows multiple parents per child */
	mms_trace(MMS_DEVP,
	    "mm_add_depend");
	if (parent == NULL) {
		mms_trace(MMS_DEVP,
		    "passed a NULL parent");
		return;
	}

	if (mm_is_parent(parent, child)) {
		mms_trace(MMS_DEVP,
		    "%p is already a parent of %p",
		    parent, child);
		return;
	}

	mms_list_insert_tail(&child->cmd_depend_list, parent);

	mms_trace(MMS_DEVP,
	    "added %p as parent of %p",
	    parent,
	    child);
	return;


}

/*
 * mm_set_unload_dispatch
 *
 * Parameters:
 *	- unmnt_cmd : ptr to mm_command_t
 *	- parent : ptr to mm_command_t
 *
 * set the command pointed to by unmnt_cmd ready for dispatch
 * if parent is pointing to a command, add that command to
 * unmnt_cmd's depend list
 *
 * Return Values:
 *	None
 *
 */
void
mm_set_unload_dispatch(mm_command_t *unmnt_cmd, mm_command_t *parent) {
	/* This sets the unmnt_cmd for dispatch */
	/* if parent != NULL */
	/* it will be added to this commands parents */
	time_t			tm;
	cmd_mount_info_t	*mount_info = NULL;

	mount_info = &unmnt_cmd->cmd_mount_info;

	(void) time(&tm);
	if (((mount_info->unload_tm - tm) <= 0) &&
	    (unmnt_cmd->cmd_state >= 2)) {
		/* this delay unload is */
		/* already running */
		mms_trace(MMS_DEVP,
		    "this delay unmout is "
		    "already running");
	} else {
		MM_SET_FLAG(unmnt_cmd->cmd_flags,
			    MM_CMD_DISPATCHABLE);
		mount_info->unload_tm = tm;
	}
	/* Need to set cmd */
	/* as part of cur_cmd */
	/* depend list */
	if (parent != NULL)
		(void) mm_add_depend(unmnt_cmd, parent);

}

/*
 * mm_dispatch_unload
 *
 * Parameters:
 *	- library : ptr to library name string
 *	- drive : ptr to drive name string
 *	- cmd : ptr to mm_command_t
 *	- mm_data : ptr to mm_data_t
 *
 * Find's the unload command the give library and drive
 * and sets that ready for dispatch
 * then add cmd to that unload command's depend list
 *
 * Return Values:
 *	mm_command_t :	if an unload is found for library
 *			and drive, a ptr to that command
 *			is returned
 *	NULL :		if an unload for library and drive
 *			cannot be found, NULL is returned
 *
 */
mm_command_t *
mm_dispatch_unload(char *library, char *drive, mm_command_t *cmd,
	mm_data_t *mm_data) {
	/* searches the cmd_queue for a delay unmount cmd function */
	/* if the library and drive match, the cmd is set for dispatch */
	/* if cmd != NULL, then cmd will be set */
	/* as parent of the delay unmount */

	cmd_mount_info_t	*mount_info = NULL;
	mm_command_t		*cur_cmd;

	mm_command_t		*unmnt_cmd = NULL;

	mms_trace(MMS_DEVP, "dispatching delay unmounts for %s %s",
	    library, drive);

	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if (cur_cmd->cmd_func == mm_delay_unmount_cmd_func) {
			mount_info = &cur_cmd->cmd_mount_info;
			if ((strcmp(library, mount_info->cmi_library) == 0) &&
			    (strcmp(drive, mount_info->cmi_drive) == 0)) {
				mms_trace(MMS_DEVP,
				    "dispatch delay unmount, %s %s",
				    library,
				    drive);
				mm_set_unload_dispatch(cur_cmd, cmd);
				unmnt_cmd = cur_cmd;
			}
		}
	}
	pthread_mutex_unlock(&mm_data->
			mm_queue_mutex);
	if (unmnt_cmd != NULL)
		return (unmnt_cmd);
	/* We did not find a delay unload */
	/* Search the list for a clear drive function */
	/* This cmd may be following an error recovery situation */
	/* where the delay was not correctly added */
	/* search for a clear drive instead */
	/* do not dispatch the clear drive */
	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if (cur_cmd->cmd_func == mm_clear_drive_cmd_func) {
			mount_info = &cur_cmd->cmd_mount_info;
			if ((mount_info->cmi_library == NULL) ||
			    (mount_info->cmi_drive == NULL)) {
				continue;
			}
			if ((strcmp(library, mount_info->cmi_library) == 0) &&
			    (strcmp(drive, mount_info->cmi_drive) == 0)) {
				mms_trace(MMS_DEVP,
				    "found clear drive for, %s %s",
				    library,
				    drive);
				if (cmd != NULL)
					(void) mm_add_depend(cur_cmd, cmd);
				unmnt_cmd = cur_cmd;
			}
		}

	}
	pthread_mutex_unlock(&mm_data->
			mm_queue_mutex);
	return (unmnt_cmd);
}


/*
 * mm_remove_unload
 *
 * Parameters:
 *	- library : ptr to library name string
 *	- drive : ptr to drive name string
 *	- mm_data : ptr to mm_data_t
 *
 * Find the unload command for the given library and drive,
 * then set that unload command for removal
 *
 * Return Values:
 *	1 :	return 1 if a command was set for removal
 *	0 :	return 0 if a command was not set for removal
 *
 */
int
mm_remove_unload(char *library, char *drive, mm_data_t *mm_data) {
	/* searches the cmd_queue for a delay unmount cmd function */
	/* if the library and drive match, the cmd is set for removal */
	cmd_mount_info_t	*mount_info = NULL;
	mm_command_t		*cur_cmd;
	int			removed_one = 0;

	mms_trace(MMS_DEVP, "removeing delay unmounts for %s %s",
	    library, drive);

	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if (cur_cmd->cmd_func == mm_delay_unmount_cmd_func) {
			mount_info = &cur_cmd->cmd_mount_info;
			if ((strcmp(library, mount_info->cmi_library) == 0) &&
			    (strcmp(drive, mount_info->cmi_drive) == 0)) {
				mms_trace(MMS_DEVP,
				    "remove delay unmount, %s %s",
				    library,
				    drive);
				cur_cmd->cmd_remove = 1;
				removed_one = 1;
			}
		}
	}
	pthread_mutex_unlock(&mm_data->
			mm_queue_mutex);
	return (removed_one);
}

/*
 * mm_remove_commands
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *	- db_main : ptr to valid db connection, mm_db_t
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *
 * For the client workarea mm_wka points to, remove
 * and clean up all commands associated with it.
 * this may require updating states in the db
 *
 * Return Values:
 *	0 :	for success
 *	1 :	for errors
 *
 */
int
mm_remove_commands(mm_data_t *mm_data, mm_db_t *db_main, mm_wka_t *mm_wka) {

	mm_command_t	*cur_cmd;

	mms_trace(MMS_DEVP, "Removing client with uuid %s",
	    mm_wka->wka_conn.cci_uuid);
	/* Set outstanding commands for remove */
	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {

		/*
		 * If this command is a mount command,
		 * set flag for clearing the drive
		 */
		if (cur_cmd->cmd_name == NULL) {
			cur_cmd->cmd_name = strdup("**UNKNOWN CMD**");
		}

		if (strcmp(cur_cmd->wka_uuid,
			mm_wka->wka_conn.cci_uuid) != 0) {
			/* This is not a command from this wka */
			continue;
		}
		/* This IS a command from this client's wka */
		mms_trace(MMS_DEVP, "Matched client, "
		    "set for remove, %s",
		    cur_cmd->cmd_name);
		if (cur_cmd->cmd_func ==
		    mm_mount_cmd_func) {
			mms_trace(MMS_DEVP,
			    "client has an outstanding "
			    "mount command");
			mms_trace(MMS_DEBUG,
			    "Mark a mount_cmd for "
			    "clear and reset states");
			/* Call mm_rm_mount */
			/* to clear resources */
			/* and reset manager states */
			cur_cmd->cmd_mount_info.
				cmi_reset_states = 1;
			(void) mm_rm_mount(cur_cmd);
			cur_cmd->cmd_mount_info.
				cmi_need_clear = 1;
			/* Could optimize this clear */
			/* ie dont physical clear unless necessary */
			pthread_mutex_unlock(&data->mm_queue_mutex);
			(void) mm_add_clear_drive(cur_cmd->
				cmd_mount_info.cmi_drive,
				data, db_main, NULL, NULL, 1, 0);
			pthread_mutex_lock(&data->mm_queue_mutex);

		}
		if (cur_cmd->cmd_func ==
		    mm_unmount_cmd_func) {
			/* TODO fix manager states, */
			/* clear resources */
			mms_trace(MMS_DEVP,
			    "client has an outstanding "
			    "unmount command");
			(void) mm_rm_unmount(cur_cmd);
			cur_cmd->cmd_mount_info.
				cmi_need_clear = 1;
			cur_cmd->cmd_mount_info.
				cmi_reset_states = 1;
			if (cur_cmd->
			    cmd_mount_info.cui_physical == 1) {
				pthread_mutex_unlock(&data->mm_queue_mutex);
				(void) mm_add_clear_drive(cur_cmd->
					cmd_mount_info.cmi_drive,
					data, db_main, NULL, NULL, 1, 0);
				pthread_mutex_lock(&data->mm_queue_mutex);
			}
		}

		cur_cmd->cmd_remove = 1;
		cur_cmd->wka_ptr = NULL;

		/*
		 * If this command is a depend,
		 * mark its parent
		 */
		mm_command_t *cur_depend = NULL;
		if (mm_has_depend(cur_cmd)) {
			mms_trace(MMS_DEVP,
			    "this command has depend's in list "
			    "mark each with MMS_ERROR and do not dispatch");
			mms_list_foreach(&cur_cmd->cmd_depend_list,
				    cur_depend) {
				MM_SET_FLAG(cur_depend->
					    cmd_flags,
					    MM_CMD_DEPEND_ERROR);
				MM_SET_FLAG(cur_depend->
					    cmd_flags,
					    MM_CMD_DISPATCHABLE);
			}
			/* Clear depend list so that the parents may be */
			/* used by other commands */
			mm_remove_all_depend(cur_cmd);
		}

		/*
		 * If this command is a parent,
		 * Mark its children
		 */
		mm_command_t	*child;
		mms_list_foreach(&mm_data->mm_cmd_queue,
			    child) {
			if (mm_is_parent(cur_cmd, child) == 0) {
				/* not a parent of this child */
				continue;
			}
			if (child->cmd_name == NULL) {
				child->cmd_name =
					strdup("**UNKNOWN CMD**");
			}

			mms_trace(MMS_DEBUG,
			    "    %s is child "
			    "of %s, set cmd "
			    "for remove",
			    child->cmd_name,
			    cur_cmd->cmd_name);

			/* TODO */
			/*
			 * What to do with outstanding
			 * commands?
			 *
			 * Cancel child commands in a mount
			 * Ensure that states are correct
			 * and drives are clear
			 *
			 * TEMP
			 * Remove all dependent commands
			 * If lmp munt is a child
			 * Allow it to complete, then
			 * clear the drive
			 */
			mm_remove_this_depend(child, cur_cmd);
			if (strcmp(child->cmd_name,
			    "lmp mount") == 0) {
				mms_trace(MMS_DEVP, "setting lmp "
				    "mount for clear_drive");
				/* Need clear for lmp mount */
				child->cmd_mount_info.
				    cmi_need_clear = 1;
			} else if (strcmp(child->cmd_name,
			    "delay unmount") == 0) {
				mms_trace(MMS_DEVP,
				    "do not remove "
				    "this delay unmount");
			} else {
				child->cmd_remove = 1;
			}
		}

	}
	pthread_mutex_unlock(&data->mm_queue_mutex);
	mms_trace(MMS_DEVP, "Done removing commands");
	return (0);
}



/*
 * mm_remove_mmp_client
 *
 * Parameters:
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *	- db_main : ptr to valid db connection, mm_db_t
 *
 * Does clean up for an MMP client, reset any states that need
 * to be reset. If the client has a tape mounted, add commands
 * to free that resource
 *
 * Return Values:
 *	0 :	for successful cleanup
 *	1 :	for errors
 *
 */
int
mm_remove_mmp_client(mm_wka_t *mm_wka, mm_db_t *db_main) {
	char *drive_name = NULL;
	char *cartridge_pcl = NULL;
	char *library_name = NULL;

	PGresult *mount_results;
	int physical = 0;

	mm_data_t *mm_data = mm_wka->mm_data;

	int i = 0;
	int num_mounts = 0;

	mm_command_t *cur_cmd;

	/* Do any MMP specific tasks here */

	/* If this is a MMP client, check the MOUNTPHYSICAL */
	/* schedule a clear drive */
	if (mm_db_exec(HERE, db_main,
		    "select distinct "
		    "\"MOUNTPHYSICAL\".\"DriveName\","
		    "\"MOUNTPHYSICAL\".\"CartridgePCL\", "
		    "\"MOUNTPHYSICAL\".\"LibraryName\" "
		    "from \"MOUNTPHYSICAL\""
		    "where"
		    "("
		    "\"MOUNTPHYSICAL\".\"SessionID\" = '%s');",
		    mm_wka->session_uuid)
	    != MM_DB_DATA) {
		mms_trace(MMS_ERR, "Error getting MOUNTPHYSICAL");
		mm_clear_db(&db_main->mm_db_results);
		return (1);
	}
	mount_results = db_main->mm_db_results;
	num_mounts = PQntuples(mount_results);
	mms_trace(MMS_DEVP,
	    "client has %d tapes mounted",
	    num_mounts);
	for (i = 0; i < num_mounts; i++) {
		drive_name = PQgetvalue(mount_results,
					i, 0);
		cartridge_pcl = PQgetvalue(mount_results,
					i, 1);
		library_name = PQgetvalue(mount_results,
					i, 2);

		mms_trace(MMS_INFO,
		    "%s %s has tape mounted, %s %s %s, clear drive",
		    mm_wka->wka_conn.cci_client,
		    mm_wka->wka_conn.cci_instance,
		    cartridge_pcl, drive_name,
		    library_name);
		/* Reset resources */

		/* Set States For a Clear Drive */
		(void) mm_db_exec(HERE, db_main,
			    "update \"DRIVE\" set "
			    "\"DriveStateSoft\" = 'ready' "
			    "where \"DriveName\" = '%s';",
			    drive_name);

		(void) mm_db_exec(HERE, db_main,
			    "update \"CARTRIDGE\" set "
			    "\"CartridgeStatus\" = 'available' "
			    "where \"CartridgePCL\" = "
			    "'%s' and \"LibraryName\" = '%s';",
			    cartridge_pcl,
			    library_name);

		/* If this client does not have an outstanding */
		/* physical unmount, add a non-physical clear */
		pthread_mutex_lock(&data->mm_queue_mutex);
		mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
			/* wka is the same, cmd is unmount */
			/* unmount is physical, and drive are the same */
			if ((cur_cmd->wka_ptr == mm_wka) &&
			    (cur_cmd->cmd_func == mm_unmount_cmd_func) &&
			    (cur_cmd->cmd_mount_info.cui_physical == 1) &&
			    (strcmp(cur_cmd->cmd_mount_info.cmi_drive,
				    drive_name) == 0)) {
				physical = 1;
			}
		}
		pthread_mutex_unlock(&data->mm_queue_mutex);

		if (physical) {
			mms_trace(MMS_DEVP,
			    "adding a physical force unmount");
			(void) mm_add_clear_drive(drive_name,
					mm_wka->mm_data,
					db_main,
					NULL,
					cartridge_pcl, 1, 0);
		} else {
			mms_trace(MMS_DEVP,
			    "adding a non-physical unmount ");
			(void) mm_add_clear_drive(drive_name,
					mm_wka->mm_data,
					db_main,
					NULL,
					cartridge_pcl, 0, 1);
		}
	}
	mm_clear_db(&mount_results);

	return (0);



}


/*
 * mm_remove_dmp_client
 *
 * Parameters:
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *	- db_main : ptr to valid db connection, mm_db_t
 *
 * Does clean up for an DMP client, reset any states that need
 * to be reset. Copy any existing handle information for this DM
 * from MOUNTLOGICAL to STALEHANDLE
 *
 * If this DM recieved an unwelcome response, return without altering
 * any state information
 *
 * Return Values:
 *	None
 *
 */
void
mm_remove_dmp_client(mm_wka_t *mm_wka, mm_db_t *db_main) {
	PGresult	 *mount_logical;
	int		rows;
	int		rc;
	/* try to add dmdown event */
	/* copy mountlogical to stalehandle */
	/* delete the config for this dm */

	if (mm_wka->wka_unwelcome) {
		mms_trace(MMS_DEVP,
		    "mm_remove_dmp_client: "
		    "DM was unwelcome, skip clean up");
		return;
	}

	(void) mm_notify_add_dmdown_dc(mm_wka,
				db_main);
	/* Move MOUNTLOGICAL to STALEHANDLE */
	rc = mm_db_exec(HERE, db_main,
			"select  \"ApplicationName\", "	\
			"\"VolumeName\", \"PartitionName\", "\
			"\"SideName\", \"CartridgeID\", "\
			"\"DriveName\", \"DMName\", "\
			"\"MountLogicalHandle\" "\
			"from\"MOUNTLOGICAL\" "	\
			"where \"DMName\" = '%s';",
			mm_wka->wka_conn.cci_instance);
	if (rc != MM_DB_DATA) {
		/* error */
		mms_trace(MMS_ERR, "Error getting "\
		    "MOUNTLOGICAL handles");
		mm_clear_db(&db_main->mm_db_results);
		(void) mm_db_txn_rollback(db_main);
		return;
	}

	mount_logical = db_main->mm_db_results;
	rows = PQntuples(mount_logical);
	for (int i = 0; i < rows; i ++) {
		/* Move 1 MOUNTLOGICAL to STALEHANDLE */
		if (mm_db_exec(HERE, db_main,
				"insert into \"STALEHANDLE\" "\
				"(\"ApplicationName\", "\
				"\"VolumeName\", " \
				"\"PartitionName\", "\
				"\"SideName\", "\
				"\"CartridgeID\", " \
				"\"DriveName\", \"DMName\", "\
				"\"MountLogicalHandle\") "\
				"values "	\
				"('%s', '%s', '%s', '%s', "\
				"'%s', '%s', '%s', '%s');",
				PQgetvalue(mount_logical, i, 0),
				PQgetvalue(mount_logical, i, 1),
				PQgetvalue(mount_logical, i, 2),
				PQgetvalue(mount_logical, i, 3),
				PQgetvalue(mount_logical, i, 4),
				PQgetvalue(mount_logical, i, 5),
				PQgetvalue(mount_logical, i, 6),
				PQgetvalue(mount_logical,
				    i, 7)) != MM_DB_OK) {
			mms_trace(MMS_ERR, "Error moving "
			    "MOUNTLOGICAL to STALEHANDLE");
			mm_clear_db(&db_main->mm_db_results);
		}
	}
	mm_clear_db(&mount_logical);
	if (mm_db_exec(HERE, db_main,
		    "delete from \"MOUNTLOGICAL\" where "\
		    "\"DMName\" = '%s';",
		    mm_wka->wka_conn.cci_instance) !=
	    MM_DB_OK) {
		mms_trace(MMS_ERR, "Error removeing "\
		    "MOUNTLOGICAL");
		mm_clear_db(&db_main->mm_db_results);
	}


	if (mm_db_exec(HERE, db_main,
		    "update \"DM\" set "\
		    "\"DMStateSoft\" = "	\
		    "'absent' where \"DMName\" = '%s';",
		    mm_wka->wka_conn.cci_instance) !=
	    MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error updating "\
		    "DMStateSoft");
		mm_clear_db(&db_main->mm_db_results);
	}

	(void) delete_dm_config(mm_wka, db_main);

}



/*
 * mm_remove_dmp_client
 *
 * Parameters:
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *	- db_main : ptr to valid db connection, mm_db_t
 *
 * Does clean up for an LMP client, reset any states that need
 * to be reset.
 *
 * If this LM recieved an unwelcome response, return without altering
 * any state information
 *
 * Return Values:
 *	None
 *
 */
void
mm_remove_lmp_client(mm_wka_t *mm_wka, mm_db_t *db_main) {
	/* Try to add an lmdown event */
	/* Set LMStateSoft == 'absent' */

	if (mm_wka->wka_unwelcome) {
		mms_trace(MMS_DEVP,
		    "mm_remove_lmp_client: "
		    "LM was unwelcome, skip clean up");
		return;
	}

	(void) mm_notify_add_lmdown_dc(mm_wka,
				db_main);
	if (mm_db_exec(HERE, db_main, "UPDATE \"LM\" SET "
		    "\"LMStateSoft\" = 'absent' WHERE \"LibraryName\" = '%s' "
		    "AND \"LMName\" = '%s';", mm_wka->wka_conn.cci_client,
		    mm_wka->wka_conn.cci_instance) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "Error removing LIBRARY LM");
	}
}

/*
 * mm_remove_connection
 *
 * Parameters:
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *	- db_main : ptr to valid db connection, mm_db_t
 *
 * Do general clean up for all connections (MMP, DMP, LMP)
 * Cancel any notficitaions for the client, reset connection
 * object states
 *
 * Return Values:
 *	None
 *
 */
void
mm_remove_connection(mm_wka_t *mm_wka, mm_db_t *db_main) {
	char *savepoint = NULL;
	PGresult	*results;

	(void) mm_db_txn_begin(db_main);
	if (mm_request_disconnect(db_main, mm_wka)) {
		mms_trace(MMS_ERR, "Error updating REQUESTs");
	}
	if (mm_db_exec(HERE, db_main, MM_DELETE_NOTIFY,
		    mm_wka->wka_conn.cci_uuid)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR, "Error removing NOTIFY");
	}
	/* Get all NotifyId's and drop the rules */
	if (mm_db_exec(HERE, db_main,
	    "select \"NotifyID\",\"NotifyObject\""
	    " from \"NOTIFYRULES\" where "
	    "\"ConnectionID\" = '%s';",
	    mm_wka->wka_conn.cci_uuid) == MM_DB_DATA) {
		results = db_main->mm_db_results;
		for (int i = 0; i < PQntuples(results); i++) {
			savepoint = mms_strnew("\"%s\"",
			    PQgetvalue(results, i, 0));
			if (mm_db_txn_savepoint(db_main,
			    savepoint) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_remove_connection: "
				    "db error setting savepoint");
			}
			if (mm_db_exec(HERE, db_main,
			    "drop rule \"%s\" on \"%s\";",
			    PQgetvalue(results, i, 0),
			    PQgetvalue(results, i, 1)) !=
			    MM_DB_OK) {
				if (mm_db_txn_savepoint_rollback(db_main,
				    savepoint) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_remove_connection: "
				    "db error rollingback savepoint");
			}
			}
			if (mm_db_txn_release_savepoint(db_main,
			    savepoint) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_remove_connection: "
				    "db error releasing savepoint");
			}
			free(savepoint);
			savepoint = NULL;
		}
		mm_clear_db(&results);
	} else {
		mms_trace(MMS_ERR,
		    "error reading notify id from table");
		mm_clear_db(&db_main->mm_db_results);
	}
	if (mm_db_exec(HERE, db_main, MM_DELETE_NOTIFYRULES,
		    mm_wka->wka_conn.cci_uuid)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR, "Error removing NOTIFYRULES");
	}
	if (mm_wka->mm_wka_mm_lang == MM_LANG_MMP &&
	    (mm_wka->session_uuid != NULL) &&
	    mm_db_exec(HERE, db_main, MM_DELETE_SESSION,
		    mm_wka->session_uuid)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR, "Error removing SESSION");
	}
	if (mm_db_exec(HERE, db_main, MM_DELETE_CONNECTION,
		    mm_wka->wka_conn.cci_uuid)
	    != MM_DB_OK) {
		mms_trace(MMS_ERR, "Error removing CONNECTION");
	}

	(void) mm_db_txn_commit(db_main);
}

/*
 * mm_remove_clients
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *	- db : ptr to valid db connection, mm_db_t
 *
 * Check all client work areas in the work area list for
 * connections that need removal. For each client that needs
 * to be removed, call the approperate clean up functions
 *
 * This function should cause the reset of the
 * approperate db states and free memory assocated with
 * the disconnected clients
 *
 * Return Values:
 *	0 :	return 0 for success
 *	1 :	return 1 for errors
 *
 */
static int
mm_remove_clients(mm_data_t *mm_data, mm_db_t *db)
{

	mm_wka_t	*mm_wka;
	int		 go = 1;
	int		 remove;

	mms_trace(MMS_DEVP,
	    "mm_remove_clients");

	/*
	 * Find bad file descriptors
	 *
	 * Also need to remove all commands from
	 * queue that are asscociated with
	 * the bad FD
	 */
	/* mms_trace(MMS_INFO, "Inside remove clients"); */
	if (mm_is_fd_valid(mm_data->mm_service_fd) != 0) {
		mms_trace(MMS_ERR, "mm service not valid FD -> %d",
		    mm_data->mm_service_fd);
		/* Service Not Valid */
		return (1);
	}

	while (go) {
		remove = 0;
		pthread_mutex_lock(&data->mm_wka_mutex);
		mms_list_foreach(&mm_data->mm_wka_list, mm_wka) {
			pthread_mutex_unlock(&data->mm_wka_mutex);

			/* mms_trace(MMS_INFO," Checking a wka"); */
			if (mm_wka->wka_remove) {
				remove = 1;
				break;
			}
			if (mm_is_fd_valid(mm_wka->mm_wka_conn->mms_fd) != 0) {
				/* Not Valid */
				mms_trace(MMS_ERR, "mm_is_fd_valid found "
				    "bad FD -> %d",
				    mm_wka->mm_wka_conn->mms_fd);

				remove = 1;
				pthread_mutex_lock(&data->mm_wka_mutex);
				break;
			}

			pthread_mutex_lock(&data->mm_wka_mutex);
		}

		pthread_mutex_unlock(&data->mm_wka_mutex);

		if (remove) {
			/* Destroy the wka */
			pthread_mutex_lock(&mm_wka->wka_local_lock);

			pthread_mutex_lock(&data->mm_wka_mutex);
			mms_list_remove(&mm_data->mm_wka_list, mm_wka);
			pthread_mutex_unlock(&data->mm_wka_mutex);


			/* Remove commands associated with this wka */
			if (mm_remove_commands(mm_data, db, mm_wka)) {
				mms_trace(MMS_ERR, "Error removing commands");
			}

			if (mm_wka->mm_wka_mm_lang == MM_LANG_MMP) {
				/* Clean up for MMP client */
				(void) mm_remove_mmp_client(mm_wka, db);
			}
			if (mm_wka->mm_wka_mm_lang == MM_LANG_DMP) {
				/* Clean up for DMP client */
				(void) mm_remove_dmp_client(mm_wka, db);
			}
			if (mm_wka->mm_wka_mm_lang == MM_LANG_LMP) {
				/* Clean up for LMP client */
				(void) mm_remove_lmp_client(mm_wka, db);
			}

			/* Clean up connections */
			mm_remove_connection(mm_wka, db);

			/* free(mm_wka); */
			mms_close(mm_wka->mm_wka_conn);
			mm_destroy_wka(mm_wka);
		} else {
			go = 0;
		}
	}

	return (0);
}


/*
 * mm_add_wka
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *	- conn : ptr to MMS connection struct, mms_t
 *
 * Allocate and intialize a new client work area (mm_wka_t)
 * using the connection information in conn
 *
 * Return Values:
 *	0 :	for success
 *	1 :	for errors
 *
 */
int
mm_add_wka(mm_data_t *mm_data, mms_t *conn)
{
	mm_wka_t	*mm_wka;

	mm_wka = (mm_wka_t *)calloc(1, sizeof (mm_wka_t));
	if (mm_wka == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_wka_t fd %d: %s",
		    conn->mms_fd, strerror(errno));
		mms_close(conn);
		return (1);
	}
	/*
	 * Allocate empty connection strings for
	 * access before a client says hello.
	 */
	mm_wka->wka_conn.cci_client = strdup("");
	mm_wka->wka_conn.cci_instance = strdup("");
	mm_wka->wka_conn.cci_language = strdup("");
	mm_wka->wka_conn.cci_version = strdup("");
	mm_wka->wka_conn.cci_password = strdup("");
	mm_wka->wka_conn.cci_certificate = strdup("");
	mm_wka->wka_conn.cci_authentication = strdup("");

	if (mm_connect_info(conn->mms_fd, &mm_wka->wka_conn)) {
		mms_trace(MMS_ERR, "Connect id failed fd %d", conn->mms_fd);
		free(mm_wka);
		mms_close(conn);
		return (1);
	}

	mms_trace(MMS_INFO,
	    "Added client, host = %s(%s)", mm_wka->wka_conn.cci_host,
	    mm_wka->wka_conn.cci_ip);

	mm_wka->mm_wka_conn = conn;
	mm_wka->mm_data = mm_data;
	mm_wka->wka_hello_needed = B_TRUE;
	mm_wka->wka_remove = 0;
	mm_wka->wka_need_accept = 0;
	mm_wka->wka_goodbye = 0;
	mm_wka->wka_unwelcome = 0;
	mm_get_uuid(mm_wka->wka_conn.cci_uuid);
	pthread_mutex_init(&mm_wka->wka_local_lock, NULL);

	pthread_mutex_lock(&data->mm_wka_mutex);
	mms_list_insert_tail(&mm_data->mm_wka_list, mm_wka);
	pthread_mutex_unlock(&data->mm_wka_mutex);
	mms_trace(MMS_DEVP, "Wka added Successfully- %d",
	    mm_wka->mm_wka_conn->mms_fd);
	return (0);
}

/*
 * mm_response_cmd_func
 *
 * Parameters:
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *	- rsp_cmd : ptr to mm_command_t
 *
 * command function for all responses, this function will
 * find the command matching this response and set the response
 * values for that command. it will also set the approperate
 * flags for the command based on the type of response
 * (error, accept, success)
 *
 * Return Values:
 *	One of the Dispatcher return codes, see mm.h
 *	(MM_CMD_DONE, MM_NO_DISPATCH etc...)
 *
 */
int
mm_response_cmd_func(mm_wka_t *mm_wka, mm_command_t *rsp_cmd)
{

	/*
	 *  A response has been recieved,
	 * Find the the matching command in the queue,
	 *
	 * check:
	 * mm_wka->cci_uuid matches rsp_uuid (same connection)
	 * command's task is the same
	 *
	 * Set the command's flag to dispatchable
	 * Save parsed response in cmd_response
	 * return MM_CMD_DONE
	 */

	char			*rsp_uuid = mm_wka->wka_conn.cci_uuid;
	char			*rsp_task;
	mm_command_t		*cur_cmd;
	mm_data_t		*mm_data = mm_wka->mm_data;
	char			*task;
	int skip = 0;


	mms_trace(MMS_DEVP, "mm_response_cmd_func");

	mms_trace(MMS_DEVP, "rsp_uuid %s", rsp_uuid);
	rsp_task = mm_get_task(rsp_cmd->cmd_root);
	if (rsp_task != NULL) {
		mms_trace(MMS_DEVP, "rsp_task %s", rsp_task);
	} else {
		mms_trace(MMS_ERR,
		    "No task clause in response");
		return (MM_CMD_ERROR);
	}
	pthread_mutex_lock(&data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if ((cur_cmd->cmd_remove == 1) ||
		    (cur_cmd->wka_ptr == NULL)) {
			mms_trace(MMS_ERR, "bad wka/cmd_remove "
			    "set for a cmd, continue");
			continue;
		}
		mms_trace(MMS_DEVP, "cur_cmd->wka_ptr->wka_conn.cci_uuid %s",
		    cur_cmd->wka_ptr->wka_conn.cci_uuid);
		skip = 0;
		if (cur_cmd != rsp_cmd) {
			if (cur_cmd->cmd_root != NULL) {
				if (strcmp(mms_pn_token(cur_cmd->cmd_root),
				    "response") == 0) {
					skip = 1;
				}
			}

			if (strcmp(rsp_uuid,
			    cur_cmd->wka_ptr->wka_conn.cci_uuid) == 0) {
				/* From the same connection */
				if ((task = cur_cmd->cmd_task) != NULL) {
					mms_trace(MMS_DEVP, "task %s", task);
				}
				if (strcmp(rsp_task, task) == 0) {
					mms_trace(MMS_DEVP, "same task");
					/* Same Task */
					if (!skip)
						break;
				}
			}
		}
	}
	pthread_mutex_unlock(&data->mm_queue_mutex);

	if (cur_cmd) {
		(void) mm_message_command(rsp_cmd);

		if (mms_pn_lookup(rsp_cmd->cmd_root,
		    "accepted",
		    MMS_PN_KEYWORD, NULL)) {
			mms_trace(MMS_DEBUG, "%s accepted",
			    cur_cmd->cmd_name);
			if (cur_cmd->cmd_response != NULL) {
				mms_pn_destroy(cur_cmd->cmd_response);
			}
			cur_cmd->cmd_response = rsp_cmd->cmd_root;
			rsp_cmd->cmd_root = NULL;
			cur_cmd->cmd_flags |= MM_CMD_DISPATCHABLE;
			free(rsp_task);
			return (MM_DISPATCH_AGAIN);
		} else {
			if (MM_IS_SET(cur_cmd->cmd_flags, MM_CMD_NEED_ACCEPT)) {
				mms_trace(MMS_DEVP, "CMD still needs acc");
				rsp_cmd->cmd_flags |= MM_CMD_DISPATCHABLE;
				free(rsp_task);
				return (MM_NO_DISPATCH);
			}
			mms_trace(MMS_DEBUG, "%s final command response",
			    cur_cmd->cmd_name);
			if (cur_cmd->cmd_response != NULL) {
				mms_pn_destroy(cur_cmd->cmd_response);
			}
			cur_cmd->cmd_response = rsp_cmd->cmd_root;
			rsp_cmd->cmd_root = NULL;
			cur_cmd->cmd_flags |= MM_CMD_DISPATCHABLE;
			if (cur_cmd->cmd_root != NULL) {
				mms_trace(MMS_DEVP, "set %s for dispatch, %p",
				    mms_pn_token(cur_cmd->cmd_root),
				    cur_cmd);
			} else {
				mms_trace(MMS_DEVP,
				    "set NULL root for dispatch, %p",
				    cur_cmd);
			}
			free(rsp_task);
			return (MM_DISPATCH_AGAIN);
		}
	}
	mms_trace(MMS_DEBUG, "mm_response_cmd_func end MM_CMD_ERROR");
	mms_trace(MMS_ERR, "Couldnt match response to outstanding command");
	free(rsp_task);
	return (MM_CMD_ERROR);
}

/*
 * mm_handle_parser_error
 *
 * Parameters:
 *	- cmd : ptf to mms_par_node_t of a MMP/DMP/LMP command
 *	- err_list : error list for this error, ptf to mms_list_t
 *
 * Attempt to parse the partial parse tree and determine what the cmd is
 * If it can be determined that the command is a hello return unwelcome,
 * if the command is an MMP/DMP/LMP command return unacceptable,
 * if the command is a response or unknown, don't send a response
 *
 * Return Values:
 *	MM_PAR_ERROR : if cmd is unknown
 *	MM_PAR_SEND_UNWEL : if cmd is hello command
 *	MM_PAR_IS_RESP : if command is a response
 *	MM_PAR_NO_MEM : parser is out of memory
 *	MM_PAR_SEND_UNACC : if cmd requres an unaccep response
 *
 */
int
mm_handle_parser_error(mms_par_node_t *cmd, mms_list_t *err_list) {
	mms_par_err_t	*err;		/* Used to step through error list */
	mms_par_node_t	*root;		/* Ptr to cmd node of parse tree */
	int		syntax = 0;	/* Number of syntax errors in cmd */

	/* Need unaccept list */
	int		num_unaccept = 34;
	char		*unaccept[34];

	int		ret_val;

	unaccept[0] = strdup("mount");
	unaccept[1] = strdup("create");
	unaccept[2] = strdup("goodbye");
	unaccept[3] = strdup("delete");
	unaccept[4] = strdup("show");
	unaccept[5] = strdup("locale");
	unaccept[6] = strdup("privilege");
	unaccept[7] = strdup("begin");
	unaccept[8] = strdup("unmount");
	unaccept[9] = strdup("end");
	unaccept[10] = strdup("allocate");
	unaccept[11] = strdup("deallocate");
	unaccept[12] = strdup("rename");
	unaccept[13] = strdup("shutdown");
	unaccept[14] = strdup("cpscan");
	unaccept[15] = strdup("cpreset");
	unaccept[16] = strdup("cpexit");
	unaccept[17] = strdup("cpstart");
	unaccept[18] = strdup("move");
	unaccept[19] = strdup("eject");
	unaccept[20] = strdup("inject");
	unaccept[21] = strdup("cancel");
	unaccept[22] = strdup("notify_chg");
	unaccept[23] = strdup("config");
	unaccept[24] = strdup("activate");
	unaccept[25] = strdup("ready");
	unaccept[26] = strdup("private");
	unaccept[27] = strdup("drive");
	unaccept[28] = strdup("library");
	unaccept[29] = strdup("identity");
	unaccept[30] = strdup("request");
	unaccept[31] = strdup("message");
	unaccept[32] = strdup("direct");
	unaccept[33] = strdup("setpassword");

	mms_list_foreach(err_list, err) {
		switch (err->pe_code) {
			case MMS_PE_NOMEM:
				mms_trace(MMS_ERR, "mm_handle_parser_error: "
					"Parser error detected no memory "
					"available");
				ret_val = MM_PAR_NO_MEM;
				goto end;
			case MMS_PE_SYNTAX:
				syntax++;
				break;
			case MMS_PE_MAX_LEVEL:
				mms_trace(MMS_ERR, "mm_handle_parser_error: "
					"Parser error detected max level "
					"reached");
				ret_val = MM_PAR_ERROR;
				goto end;
			default:
				mms_trace(MMS_ERR, "mm_handle_parser_error: "
					"Invalid parser err encountered - %d",
					err->pe_code);
				/* XXX DO MMS_ERROR RECOVERY IN THIS. SNO */
				/* SINCE ONLY 3 MMS_ERROR CONDITIONS EXIST */
				ret_val = MM_PAR_ERROR;
				goto end;
		}
		mms_trace(MMS_ERR,
		    "mm_handle_parser_error: error mms_mmp_parse, \n"
			"    line %d, col %d, near token \"%s\", "
			"err code %d, %s",
			err->pe_line,
			err->pe_col,
			err->pe_token,
			err->pe_code,
			err->pe_msg);
	}

	if (!syntax) {
		mms_trace(MMS_ERR,
		    "mm_handle_parser_error: Parse error was not "
			"a valid error condition for MM, Unable to process "
			"error");
		ret_val = MM_PAR_ERROR;
		goto end;
	}

	mms_trace(MMS_ERR,
	    "mm_handle_parser_error: Parse error was syntax error. "
		"Num of errors - %d", syntax);

	root = mms_pn_lookup(cmd, NULL, MMS_PN_CMD, NULL);
	if (root == NULL) {
		mms_trace(MMS_ERR, "mm_handle_parser_error: Input string was a "
			"complete mess, no cmd found");
		/* NEED TO HANDLE MMS_ERROR CASE, UNABLE DETERMINE IF MESSAGE */
		/* WAS A CMD, CMD RESPONSE, CMD ACCEPT, NOT ABLE TO DETERMINE */
		/* WHAT TYPE OF RESPONSE SHOULD BE SENT IF ONE SHOULD BE XXX */
		ret_val = MM_PAR_ERROR;
		goto end;
	}


	/* The command has a syntax error, but root != NULL */
	/* Check root, send unaccept for valid commands, */
	/* send unwelcome for hello, skip resoponses and */
	/* unrecognized commands */

	for (int i = 0; i < num_unaccept; i ++) {
		if (strcmp(root->pn_string,
			    unaccept[i]) == 0) {
			mms_trace(MMS_ERR, "    %s had a syntax error,"
			    " send unaccept", unaccept[i]);
			ret_val = MM_PAR_SEND_UNACC;
			goto end;
		}
	}

	if (strcmp(root->pn_string, "hello") == 0) {
		mms_trace(MMS_ERR, "    hello had a syntax error,"
		    " send unwelcome");
		/* send an unwelcome for hello */
		ret_val = MM_PAR_SEND_UNWEL;
		goto end;
	} else if (strcmp(root->pn_string,
			"response") == 0) {
		/* Don't send an unacceptable for response */
		mms_trace(MMS_ERR, "    response had a syntax error, "
		    "Don't send unacceptable");
		ret_val = MM_PAR_IS_RESP;
		goto end;
	}
	/* shouldn't ever get here */
	ret_val = MM_PAR_ERROR;

end:
	for (int i = 0; i < num_unaccept; i ++) {
		if (unaccept[i])
			free(unaccept[i]);
	}
	return (ret_val);
}


/*
 * mm_setup_cmd
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *	- buf : pointer to char string of cmd text
 *
 * Parses the string in buf and sets up the mm_command_t struct
 * Sets the cmd_function pointer for the command
 * if there is problem parsing the command, send the approperate
 * response to the client (unwelcome or unacceptable)
 *
 * Return Values:
 *	0 : for errors
 *	1 : for success
 *	2 : for success and cmd was a part of a begin-end group
 *
 */
int
mm_setup_cmd(mm_command_t *cmd, char *buf)
{
	mms_par_node_t	*root;
	int		 rc;
	mms_list_t		 err_list;
	mm_wka_t	*mm_wka = cmd->wka_ptr;
	int		send_acc = 1;
	int		parse_error = 0;

	/* Parse error */
	int		send_unwelcome = 0;
	int		send_unacceptable = 0;
	int		is_response = 0;
	int		p_err_rc;

	/* Begin-end */
	mm_command_t	*cur_cmd;

	root = mms_pn_lookup(cmd->cmd_root, NULL, MMS_PN_CMD, NULL);
	switch (cmd->cmd_language) {
	case MM_LANG_MMP:
		mms_trace(MMS_DEVP, "Parse MMP cmd");
		rc = mms_mmp_parse(&root, &err_list, buf);
		if (rc) {
			mms_trace(MMS_DEVP, "parse error fd -> %d",
			    cmd->wka_ptr->mm_wka_conn->mms_fd);
			p_err_rc = mm_handle_parser_error(root, &err_list);
			if (p_err_rc == MM_PAR_SEND_UNACC) {
				send_unacceptable = 1;
			}
			if (p_err_rc == MM_PAR_SEND_UNWEL) {
				send_unwelcome = 1;
			}
			if (p_err_rc == MM_PAR_IS_RESP) {
				is_response = 1;
			}
			mms_pe_destroy(&err_list);
			cmd->cmd_remove = 1;
			parse_error = 1;
			break;
		}
		mms_pe_destroy(&err_list);

		cmd->cmd_root = root;
		cmd->cmd_task = mm_get_task(cmd->cmd_root);

		if (strcmp(mms_pn_token(root), "hello") == 0) {
			cmd->cmd_func = mm_hello_cmd_func;
			send_acc = 0;
		} else if (strcmp(mms_pn_token(root),
		    "response") == 0) {
			cmd->cmd_func = mm_response_cmd_func;
			send_acc = 0;
		} else if (strcmp(mms_pn_token(root),
		    "mount") == 0) {
			cmd->cmd_func = mm_mount_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "create") == 0) {
			cmd->cmd_func = mm_create_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "goodbye") == 0) {
			cmd->cmd_func = mm_goodbye_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "delete") == 0) {
			cmd->cmd_func = mm_delete_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "show") == 0) {
			cmd->cmd_func = mm_show_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "attribute") == 0) {
			cmd->cmd_func = mm_attribute_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "locale") == 0) {
			cmd->cmd_func = mm_locale_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "privilege") == 0) {
			cmd->cmd_func = mm_privilege_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "begin") == 0) {
			cmd->cmd_func = mm_begin_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "unmount") == 0) {
			cmd->cmd_func = mm_unmount_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "end") == 0) {
			cmd->cmd_func = mm_end_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "allocate") == 0) {
			cmd->cmd_func = mm_allocate_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "deallocate") == 0) {
			cmd->cmd_func = mm_deallocate_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "rename") == 0) {
			cmd->cmd_func = mm_rename_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "shutdown") == 0) {
			cmd->cmd_func = mm_shutdown_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "cpscan") == 0) {
			cmd->cmd_func = mm_cpscan_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "cpreset") == 0) {
			cmd->cmd_func = mm_cpreset_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "cpexit") == 0) {
			cmd->cmd_func = mm_cpexit_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "cpstart") == 0) {
			cmd->cmd_func = mm_cpstart_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "move") == 0) {
			cmd->cmd_func = mm_move_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "eject") == 0) {
			cmd->cmd_func = mm_eject_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "inject") == 0) {
			cmd->cmd_func = mm_inject_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "notify") == 0) {
			cmd->cmd_func = mm_notify_chg_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "library") == 0) {
			cmd->cmd_func = mm_libonline_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "drive") == 0) {
			cmd->cmd_func = mm_drvonline_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "request") == 0) {
			cmd->cmd_func = mm_request_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "accept") == 0) {
			cmd->cmd_func = mm_accept_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "respond") == 0) {
			cmd->cmd_func = mm_respond_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "release") == 0) {
			cmd->cmd_func = mm_release_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "cancel") == 0) {
			cmd->cmd_func = mm_cancel_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "identity") == 0) {
			cmd->cmd_func = mm_identity_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "message") == 0) {
			cmd->cmd_func = mm_message_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "direct") == 0) {
			cmd->cmd_func = mm_direct_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "setpassword") == 0) {
			cmd->cmd_func = mm_setpassword_cmd_func;
		} else {
			mms_trace(MMS_DEBUG, "Command Not implemented yet");
		}
		break;
	case MM_LANG_DMP:
		mms_trace(MMS_DEVP, "Parse DMP cmd");
		rc = mms_dmpd_parse(&root, &err_list, buf);
		if (rc) {
			mms_trace(MMS_DEVP, "parse error fd -> %d",
			    cmd->wka_ptr->mm_wka_conn->mms_fd);
			p_err_rc = mm_handle_parser_error(root, &err_list);
			if (p_err_rc == MM_PAR_SEND_UNACC) {
				send_unacceptable = 1;
			}
			if (p_err_rc == MM_PAR_SEND_UNWEL) {
				send_unwelcome = 1;
			}
			if (p_err_rc == MM_PAR_IS_RESP) {
				is_response = 1;
			}
			mms_pe_destroy(&err_list);
			cmd->cmd_remove = 1;
			parse_error = 1;
			break;
		}
		mms_pe_destroy(&err_list);

		cmd->cmd_root = root;
		cmd->cmd_task = mm_get_task(cmd->cmd_root);

		if (strcmp(mms_pn_token(root), "hello") == 0) {
			cmd->cmd_func = mm_hello_cmd_func;
			send_acc = 0;
		} else if (strcmp(mms_pn_token(root),
		    "response") == 0) {
			cmd->cmd_func = mm_response_cmd_func;
			send_acc = 0;
		} else if (strcmp(mms_pn_token(root), "show") == 0) {
			cmd->cmd_func = mm_show_cmd_func;
		} else if (strcmp(mms_pn_token(root), "attribute") == 0) {
			cmd->cmd_func = mm_attribute_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "create") == 0) {
			cmd->cmd_func = mm_create_cmd_func;
		} else if (strcmp(mms_pn_token(root), "private") == 0) {
			cmd->cmd_func = mm_private_cmd_func;
		} else if (strcmp(mms_pn_token(root), "config") == 0) {
			cmd->cmd_func = mm_dmp_config_cmd_func;
		} else if (strcmp(mms_pn_token(root), "activate") == 0) {
			cmd->cmd_func = mm_dmp_activate_cmd_func;
		} else if (strcmp(mms_pn_token(root), "ready") == 0) {
			cmd->cmd_func = mm_dmp_ready_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "notify") == 0) {
			cmd->cmd_func = mm_notify_chg_cmd_func;
		} else if (strcmp(mms_pn_token(root), "message") == 0) {
			cmd->cmd_func = mm_message_cmd_func;
		} else if (strcmp(mms_pn_token(root), "request") == 0) {
			cmd->cmd_func = mm_request_cmd_func;
		} else if (strcmp(mms_pn_token(root), "cancel") == 0) {
			cmd->cmd_func = mm_dmp_cancel_cmd_func;
		} else {
			mms_trace(MMS_DEBUG, "Command Not implemented yet");
		}
		break;
	case MM_LANG_LMP:
		mms_trace(MMS_DEVP, "Parse LMP cmd");
		rc = mms_lmpl_parse(&root, &err_list, buf);
		if (rc) {
			mms_trace(MMS_DEVP, "parse error fd -> %d",
			    cmd->wka_ptr->mm_wka_conn->mms_fd);
			p_err_rc = mm_handle_parser_error(root, &err_list);
			if (p_err_rc == MM_PAR_SEND_UNACC) {
				send_unacceptable = 1;
			}
			if (p_err_rc == MM_PAR_SEND_UNWEL) {
				send_unwelcome = 1;
			}
			if (p_err_rc == MM_PAR_IS_RESP) {
				is_response = 1;
			}
			mms_pe_destroy(&err_list);
			cmd->cmd_remove = 1;
			parse_error = 1;
			break;
		}
		mms_pe_destroy(&err_list);

		cmd->cmd_root = root;
		cmd->cmd_task = mm_get_task(cmd->cmd_root);

		if (strcmp(mms_pn_token(root), "hello") == 0) {
			cmd->cmd_func = mm_hello_cmd_func;
			send_acc = 0;
		} else if (strcmp(mms_pn_token(root),
		    "response") == 0) {
			cmd->cmd_func = mm_response_cmd_func;
			send_acc = 0;
		} else if (strcmp(mms_pn_token(root), "show") == 0) {
			cmd->cmd_func = mm_show_cmd_func;
		} else if (strcmp(mms_pn_token(root), "attribute") == 0) {
			cmd->cmd_func = mm_attribute_cmd_func;
		} else if (strcmp(mms_pn_token(root), "private") == 0) {
			cmd->cmd_func = mm_private_cmd_func;
		} else if (strcmp(mms_pn_token(root), "config") == 0) {
			cmd->cmd_func = mm_lmp_config_cmd_func;
		} else if (strcmp(mms_pn_token(root), "ready") == 0) {
			cmd->cmd_func = mm_lmp_ready_cmd_func;
		} else if (strcmp(mms_pn_token(root), "activate") == 0) {
			cmd->cmd_func = mm_lmp_activate_cmd_func;
		} else if (strcmp(mms_pn_token(root), "mount") == 0) {
			cmd->cmd_func = mm_lmp_mount_cmd_func;
		} else if (strcmp(mms_pn_token(root), "unmount") == 0) {
			cmd->cmd_func = mm_lmp_unmount_cmd_func;
		} else if (strcmp(mms_pn_token(root),
		    "notify") == 0) {
			cmd->cmd_func = mm_notify_chg_cmd_func;
		} else if (strcmp(mms_pn_token(root), "message") == 0) {
			cmd->cmd_func = mm_message_cmd_func;
		} else if (strcmp(mms_pn_token(root), "request") == 0) {
			cmd->cmd_func = mm_request_cmd_func;
		} else if (strcmp(mms_pn_token(root), "cancel") == 0) {
			cmd->cmd_func = mm_lmp_cancel_cmd_func;
		} else {
			mms_trace(MMS_DEBUG, "Command Not implemented yet");
		}
		break;

	}

	if (parse_error == 0) {
		char *buf_ptr;

		if (cmd->cmd_func == mm_hello_cmd_func ||
		    cmd->cmd_func == mm_setpassword_cmd_func) {
			buf_ptr = mms_pn_token(root);
		} else {
			buf_ptr = buf;
		}
		mms_trace(MMS_DEBUG,
		    "command %s %s fd -> %d"
		    "\n\n%s\n",
		    mm_wka->wka_conn.cci_client,
		    mm_wka->wka_conn.cci_instance,
		    mm_wka->mm_wka_conn->mms_fd,
		    buf_ptr);
	}

	if (parse_error) {
		if (send_unwelcome) {
			/* Syntax error in a hello command */
			/* send unwelcome */
			mms_pn_destroy(root);
			mms_trace(MMS_ERR, "Parse error- response unwelcome");
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(UNWELCOME_PROTO) + 1);
			(void) sprintf(cmd->cmd_buf, UNWELCOME_PROTO);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (0);
		} else if (send_unacceptable) {
			/* Syntax error in valid MM command */
			/* send unacceptable */
			mms_pn_destroy(root);
			mms_trace(MMS_ERR,
			    "Parse error- response unacceptable");
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_UNACCEPTABLE) + 1);
			(void) sprintf(cmd->cmd_buf, RESPONSE_UNACCEPTABLE);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (0);
		} else if (is_response) {
			/* There was a syntax error in the response, */
			/* attempt to process anyways */
			mms_trace(MMS_ERR, "Parse error in response, "
			    "attempting anyways");
			cmd->cmd_root = root;
			cmd->cmd_task = mm_get_task(cmd->cmd_root);
			cmd->cmd_func = mm_response_cmd_func;
			send_acc = 0;
			cmd->cmd_name = strdup("response");
			cmd->cmd_remove = 0;
			return (1);

		} else {
			/* Unrecoverable error, syntax, no mem */
			/* What to do?? Print message and ignore for now */
			mms_pn_destroy(root);
			mms_trace(MMS_ERR, "Unable to parse command root");
			/* Close the connection so the client does not hang */
			mms_close(cmd->wka_ptr->mm_wka_conn);
			return (0);
		}

	}
	rc = 1;

	if (mm_wka->wka_goodbye) {
		mms_trace(MMS_DEBUG,
		    "this client has already "
		    "sent a goodbye, send unaccept");
		mms_pn_destroy(root);
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_UNACCEPTABLE) + 1);
		(void) sprintf(cmd->cmd_buf, RESPONSE_UNACCEPTABLE);
		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
		return (0);
	}

	/* If this wka is involved in a begin-end command group, */
	/* send unaccept for all commands execpt, end, mount, unmount */
	if (mm_wka->wka_begin_end.be_active == B_TRUE) {
		/* Client is in beg-end group */
		if ((strcmp(mms_pn_token(root), "mount") != 0) &&
		    (strcmp(mms_pn_token(root), "unmount") != 0) &&
		    (strcmp(mms_pn_token(root), "end") != 0)) {
			mms_trace(MMS_ERR,
			    "client in begin end group"
			    " may only send mount,unmount, or end");
			mms_pn_destroy(root);
			SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
			    strlen(RESPONSE_UNACCEPTABLE) + 1);
			(void) sprintf(cmd->cmd_buf, RESPONSE_UNACCEPTABLE);
			mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
			return (0);
		} else if ((strcmp(mms_pn_token(root), "mount") == 0) ||
		    (strcmp(mms_pn_token(root), "unmount") == 0)) {
			/* if this is mount or unmount and to begin cmd list */
			/* Return 2 for special rc code */
			rc = 2;
		}
	}


	/* Send an accept for all command that are not hello or response */

	if (send_acc) {
		SQL_CHK_LEN(&cmd->cmd_buf, 0, &cmd->cmd_bufsize,
		    strlen(RESPONSE_ACCEPTED) +
		    strlen(cmd->cmd_task) + 1);
		(void) snprintf(cmd->cmd_buf, cmd->cmd_bufsize,
		    RESPONSE_ACCEPTED, cmd->cmd_task);
		/* If this command is a begin command */
		/* set begin end mode before sending the accept */
		if (cmd->cmd_func == mm_begin_cmd_func) {
			mms_trace(MMS_INFO,
			    "begin-end mode active");
			mm_wka->wka_begin_end.be_active = B_TRUE;
		}
		/* If this command is a end command */
		/* set begin end mode off before sending the accept */
		if (cmd->cmd_func == mm_end_cmd_func) {
			mms_trace(MMS_INFO,
			    "begin-end mode disabled");
			mm_wka->wka_begin_end.be_active = B_FALSE;
			/* Match this end with a begin */
			pthread_mutex_lock(&data->mm_queue_mutex);
			mms_list_foreach(&data->mm_cmd_queue, cur_cmd) {
				if ((cur_cmd->wka_ptr == mm_wka) &&
				    (cur_cmd->cmd_func == mm_begin_cmd_func) &&
				    (cur_cmd->cmd_begin_has_end == 0)) {
					/* found the begin for this end */
					cmd->cmd_begin_cmd = cur_cmd;
					cur_cmd->cmd_begin_has_end = 1;
					mms_trace(MMS_DEVP,
					    "mm_setup_cmd: "
					    "matched this end (%s, %p) "
					    "with begin (%s, %p)",
					    cmd->cmd_task, cmd,
					    cur_cmd->cmd_task,
					    cur_cmd);
					break;
				}
			}
			pthread_mutex_unlock(&data->mm_queue_mutex);
		}


		mm_send_text(mm_wka->mm_wka_conn, cmd->cmd_buf);
	}
	/* Set this commands name */
	cmd->cmd_name = strdup(mms_pn_token(root));
	return (rc);
no_mem:
	MM_ABORT_NO_MEM();
	return (0);


}

/*
 * mm_add_beginend_cmd
 *
 * Parameters:
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *	- mm_cmd : ptr to mm_command_t
 *	- mm_data : ptr to mm_data_t
 *
 * For the workarea pointed to by mm_wka, add the command
 * mm_cmd to the currently active list of commands for the
 * begin-end group
 *
 * Return Values:
 *	0 :	if the command was succesfully added to a
 *		begin-end group
 *	1 :	if the command was not added to a begin-end group
 *
 */

int
mm_add_beginend_cmd(mm_wka_t *mm_wka, mm_command_t *mm_cmd,
		    mm_data_t *mm_data) {
	mm_command_t	*cur_cmd;

	/* add this mount/unmount to beginend command block */
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if (cur_cmd->wka_ptr == NULL)
			continue;
		if ((cur_cmd->wka_ptr == mm_wka) &&
		    (cur_cmd->cmd_func == mm_begin_cmd_func) &&
		    (cur_cmd->cmd_begin_has_end == 0)) {
			/* This clients begin cmd */
			mms_list_insert_tail(&cur_cmd->cmd_beginend_list,
				mm_cmd);
			return (0);
		}
	}
	return (1);
}


/*
 * mm_add_cmd
 *
 * Parameters:
 *	- mm_wka : ptr to cli work area, mm_wka_t
 *	- buf : ptr to char string of cmd text
 *	- mm_data : ptr to mm_data_t
 *
 * Adds command to mm's command queue
 * Update CONNECTION information
 * setup command and add the command to the approperate
 * list based on the return from mm_setup_cmd
 *
 * Return Values:
 *	None
 *
 */
void
mm_add_cmd(mm_wka_t *mm_wka, char *buf, mm_data_t *mm_data)
{
	mm_command_t	*mm_cmd;

	int		rc = 0;

	mms_trace(MMS_DEVP, "About to add command from fd -> %d",
	    mm_wka->mm_wka_conn->mms_fd);



	(void) mm_db_exec(HERE, &mm_wka->mm_data->mm_db_main,
	    "update \"CONNECTION\" "
	    "set \"ConnectionTimeLastActive\" = now() "
	    "where \"ConnectionID\" = '%s';",
	    mm_wka->wka_conn.cci_uuid);


	if ((mm_cmd = mm_alloc_cmd(mm_wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		mm_wka->wka_remove = 1;
		return;
	}
	mm_get_uuid(mm_cmd->cmd_uuid);


	rc = mm_setup_cmd(mm_cmd, buf);
	if (rc == 0) {
		mms_trace(MMS_ERR, "Parse error- couldnt add command");
		free(mm_cmd);
	} else if (rc == 1) {
		pthread_mutex_lock(&data->mm_queue_mutex);
		mms_list_insert_tail(&mm_data->mm_cmd_queue, mm_cmd);
		pthread_mutex_unlock(&data->mm_queue_mutex);
		mms_trace(MMS_DEVP, "Command Successfully Added to Queue - %d",
		    mm_cmd->wka_ptr->mm_wka_conn->mms_fd);
	} else if (rc == 2) {
		/* Add this command to begin-end block commands */
		pthread_mutex_lock(&data->mm_queue_mutex);
		if (mm_add_beginend_cmd(mm_wka, mm_cmd, mm_data)) {
			mms_trace(MMS_ERR,
			    "couldn't find a begin command in cmd queue");
			free(mm_cmd);
		} else {
			mms_trace(MMS_DEVP,
			    "mount/unmount added to "
			    "begin-end block");
		}
		pthread_mutex_unlock(&data->mm_queue_mutex);

	} else {
		mms_trace(MMS_ERR, "Unknown return from setup cmd");
		free(mm_cmd);
	}

}

/*
 * mm_cmd_dispatch
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Determines if the command is ready for dipatch,
 * if the command is ready, call the function in cmd's
 * command function pointer.
 *
 * This function will put a postgres txn block around the
 * command function so if the command function returns
 * error, parial changes to the db are not committed
 *
 * Return Values:
 *	One of the Dispatcher return codes, see mm.h
 *	(MM_CMD_DONE, MM_NO_DISPATCH etc...)
 *
 */
int
mm_cmd_dispatch(mm_command_t *cmd)
{
	int		 rc;
	int		 txn;

	if (cmd->cmd_flags & MM_CMD_DISPATCHABLE) {
		cmd->cmd_flags &= ~MM_CMD_DISPATCHABLE;
		/* Dispatch the Command */
		if (cmd->cmd_func != NULL) {

			/* Skip db txn for the following funtions */
			txn = 1;

			/* Check for a valid wka before running cmd */

			if (cmd->wka_ptr == NULL) {
				mms_trace(MMS_ERR,
				    "this commands wka is NULL");
				rc = MM_CMD_ERROR;
			} else if (cmd->wka_ptr->wka_remove == 1) {
				mms_trace(MMS_ERR,
				    "this commands wka is set for remove");
				rc = MM_DISPATCH_AGAIN;
			} else {
				if (txn) {
					(void) mm_db_txn_begin(&cmd->wka_ptr->
					    mm_data->mm_db);
				}
				/* Lock this wka's local lock */
				pthread_mutex_lock(&cmd->wka_ptr->
				    wka_local_lock);
				mms_trace(MMS_DEVP,
				    "dispatching %s %s (%p) fd -> %d",
				    cmd->wka_ptr->wka_conn.cci_client,
				    cmd->wka_ptr->wka_conn.cci_instance,
				    cmd,
				    cmd->wka_ptr->mm_wka_conn->mms_fd);
				rc = cmd->cmd_func(cmd->wka_ptr, cmd);
				/* Unlock this wka's local lock */
				pthread_mutex_unlock(&cmd->wka_ptr->
				    wka_local_lock);

				if (rc == MM_CMD_ERROR ||
				    rc == MM_DEPEND_ERROR) {
					if (txn) {
						(void) mm_db_txn_rollback(&cmd->
						    wka_ptr->
						    mm_data->mm_db);
					}
					/* Notify Commit/Roll back */
					mm_notify_rollback(cmd->cmd_uuid);

				} else {
					if (txn) {
						(void) mm_db_txn_commit(&cmd->
						    wka_ptr->
						    mm_data->mm_db);
					}
					/* Notify Commit/Roll back */
					mm_notify_commit(cmd->cmd_uuid);

				}
				if (rc == MM_CMD_DONE) {
					(void) mm_message_command(cmd);
				}
			}
		} else {
			mms_trace(MMS_DEVP, "Command func is NULL");
			return (MM_NO_DISPATCH);
		}
		return (rc);
	} else {
		return (MM_NO_DISPATCH);
	}
}

/*
 * mm_rm_unmount
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Do additional steps to clean up when the command
 * being removed is an unmount command
 * check what subcommands are active,
 * reset drive and cartridge states and add commands
 * to clear the drive
 *
 * Return Values:
 *	0 :	for success
 *	1 :	for error
 *
 */
int
mm_rm_unmount(mm_command_t *cmd) {
	mm_db_t		*db = &cmd->cmd_mm_data->mm_db_main;
	PGresult	 *drive_results;
	mm_command_t	*cur_cmd;

	if (cmd->cmd_root == NULL) {
		return (0);
	}

	/* Check this cmd's sub cmd's */
	/* Allow detach release unload /unmount to complete */
	/* if they have already been accepted */
	mms_list_foreach(&data->mm_cmd_queue, cur_cmd) {
		if (mm_is_parent(cmd, cur_cmd)) {
			if (!MM_IS_SET(cur_cmd->cmd_flags,
				    MM_CMD_NEED_ACCEPT)) {
				mm_remove_this_depend(cur_cmd, cmd);
			}
		}
	}

	if (cmd->cmd_mount_info.cmi_drive != NULL) {
		(void) mm_set_drive_statesoft(cmd->
		    cmd_mount_info.cmi_drive,
		    "ready", db);
	}
	if (cmd->cmd_mount_info.cmi_drive != NULL) {
		(void) mm_set_cartridge_status(cmd->
		    cmd_mount_info.cmi_cartridge,
		    "available", db);
	}

	if ((cmd->cmd_mount_info.cmi_drive != NULL) &&
	    cmd->cmd_mount_info.cui_physical == 1) {
		if (mm_db_exec(HERE, db,
			"select \"DriveStateHard\" from \"DRIVE\" where"
			"\"DRIVE\".\"DriveName\" = '%s';",
			cmd->cmd_mount_info.cmi_drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "error checking DRIVE state");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		drive_results = db->mm_db_results;
		if (PQntuples(drive_results) == 0) {
			mms_trace(MMS_ERR,
			    "DRIVE results returned 0");
			mm_clear_db(&drive_results);
			return (0);
		}
		if (strcmp(PQgetvalue(drive_results, 0, 0), "loaded") == 0) {
			mms_trace(MMS_DEVP,
			    "drive is loaded, set DriveStateHard == unloading");
			(void) mm_db_exec(HERE, db,
			"update \"DRIVE\" set "
			"\"DriveStateHard\" = 'unloading' "
			"where \"DriveName\" = '%s';",
			cmd->cmd_mount_info.cmi_drive);
		}
		mm_clear_db(&drive_results);
	}
	return (0);
}

/*
 * mm_rm_mount
 *
 * Parameters:
 *	- cmd : ptr to mm_command_t
 *
 * Do additional steps to clean up when the command
 * being removed is a mount command
 * check what subcommands are active,
 * reset drive and cartridge states and add commands
 * to clear the drive
 *
 * Return Values:
 *	0 :	for success
 *	1 :	for error
 *
 */
int
mm_rm_mount(mm_command_t *cmd)
{
	/* This function is called when a client has disconnected */
	/* with an outstanding mount command */
	/* need to deallocate the resources and reset device manager states */

	mm_db_t		*db = &cmd->cmd_mm_data->mm_db_main;
	PGresult	 *drive_results;

	if (cmd->cmd_root == NULL) {
		return (0);
	}
	if ((strcmp(mms_pn_token(cmd->cmd_root), "mount") != 0) ||
	    (cmd->cmd_language != MM_LANG_MMP)) {
		/* command is not a MMP mount */
		mms_trace(MMS_DEVP,
		    "this command is not a MMP mount command");
		return (0);
	}

	/* Do clean up for MMP mount command */
	mms_trace(MMS_DEVP, "removing a mount command state == %d",
	    cmd->cmd_state);
	/* Cartridge is not in the drive */
	/* Reset CARTRIDGE and DRIVE */
	if (cmd->cmd_mount_info.cmi_cartridge != NULL) {
		(void) mm_db_exec(HERE, db,
		    "update \"CARTRIDGE\" set "
		    "\"CartridgeStatus\" = 'available' "
		    "where \"CartridgeID\" = '%s';",
		    cmd->cmd_mount_info.cmi_cartridge);
	} else {
		mms_trace(MMS_DEVP,
		    "cmi_cartridge is NULL "
		    "cannot update state");
	}
	if (cmd->cmd_mount_info.cmi_drive != NULL) {
		(void) mm_db_exec(HERE, db,
		    "update \"DRIVE\" set "
		    "\"DriveStateSoft\" = 'ready' "
		    "where \"DriveName\" = '%s';",
		    cmd->cmd_mount_info.cmi_drive);

		if (mm_db_exec(HERE, db,
		    "select \"DriveStateHard\" from \"DRIVE\" where"
		    "\"DRIVE\".\"DriveName\" = '%s';",
		    cmd->cmd_mount_info.cmi_drive) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "error checking DRIVE state");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		drive_results = db->mm_db_results;
		if (PQntuples(drive_results) == 0) {
			mms_trace(MMS_ERR,
			    "DRIVE results returned 0");
			mm_clear_db(&drive_results);
			return (0);
		}
		if ((strcmp(PQgetvalue(drive_results, 0, 0),
		    "loaded") == 0) ||
		    (strcmp(PQgetvalue(drive_results, 0, 0),
		    "loadeding") == 0)) {
			mms_trace(MMS_DEVP,
			    "drive is loaded/ing, set "
			    "DriveStateHard == unloading");
			(void) mm_db_exec(HERE, db,
			    "update \"DRIVE\" set "
			    "\"DriveStateHard\" = 'unloading' "
			    "where \"DriveName\" = '%s';",
			    cmd->cmd_mount_info.cmi_drive);
		}
		mm_clear_db(&drive_results);


	} else {
		mms_trace(MMS_DEVP,
		    "cmi_drive is NULL "
		    "cannot update state");
	}
	return (0);
}


/*
 * mm_print_cmd_queue
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *
 * Traces the names of all commands in
 * the current command queue
 *
 * Return Values:
 *	None
 *
 */
void
mm_print_cmd_queue(mm_data_t *mm_data) {

	mm_command_t	*cur_cmd;
	mm_command_t	*next;

	int		print_one = 0;

	mm_command_t *cur_depend = NULL;

	char		*print_buf = NULL;

	mms_trace(MMS_DEBUG, "Current Commands:");
	for (cur_cmd = mms_list_head(&mm_data->mm_cmd_queue);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		print_one = 1;
		if (print_buf)
			free(print_buf);
		print_buf = NULL;

		next = mms_list_next(&mm_data->
				mm_cmd_queue, cur_cmd);

		if (cur_cmd->cmd_name != NULL) {
			if (strcmp(cur_cmd->cmd_name, "response") == 0) {
				switch (cur_cmd->cmd_language) {
				case MM_LANG_MMP:
					print_buf = mms_strapp(print_buf,
							"MMP ");
					break;
				case MM_LANG_DMP:
					print_buf = mms_strapp(print_buf,
							"DMP ");
					break;
				case MM_LANG_LMP:
					print_buf = mms_strapp(print_buf,
							"LMP ");
					break;
				}
			}
			print_buf = mms_strapp(print_buf,
					"%s",
					cur_cmd->cmd_name);
		} else {
			print_buf = mms_strapp(print_buf,
					"NULL command name");
		}
		print_buf = mms_strapp(print_buf,
				" (%p)",
				cur_cmd);

		cur_depend = NULL;
		if (cur_cmd->cmd_has_list) {
			mms_list_foreach(&cur_cmd->cmd_depend_list,
			    cur_depend) {
				/* Is a child command */
				print_buf = mms_strapp(print_buf,
				    " child of");

				if (cur_depend->cmd_name != NULL) {
					/* depend name has been set */
					print_buf =
					    mms_strapp(print_buf,
					    " %s",
					    cur_depend->
					    cmd_name);
				} else {
					print_buf = mms_strapp(print_buf,
					    "NULL command name");
				}
				print_buf = mms_strapp(print_buf,
				    " (%p)",
				    cur_depend);
			}
		} else {
			print_buf = mms_strapp(print_buf,
			    " (no depend list)");
		}

		if (cur_cmd->wka_ptr != NULL) {
			/* Has a valid wka */
			print_buf = mms_strapp(print_buf,
					", %s",
					cur_cmd->wka_ptr->
					wka_conn.cci_instance);

		}
		if (print_buf != NULL) {
			mms_trace(MMS_DEBUG,
			    "    %s",
			    print_buf);
		} else {
			mms_trace(MMS_ERR, "Error printing command queue");
		}

	}
	if (!print_one) {
		mms_trace(MMS_DEBUG,
		    "    none");
	}

	if (print_buf) {
		free(print_buf);
	}

}

/*
 * mm_dispatch_delay_unmount
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *
 * Check each delay unmount in the command queue
 * and test its timer to see if it is ready for dispatch
 * dispach any command whose timer has expired
 *
 * Return Values:
 *	None
 *
 */
void
mm_dispatch_delay_unmount(mm_data_t *mm_data) {
	mm_command_t		*cur_cmd;
	time_t			tm;
	cmd_mount_info_t	*mount_info;


	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		if (cur_cmd->cmd_func == mm_delay_unmount_cmd_func) {
			mount_info = &cur_cmd->cmd_mount_info;
			(void) time(&tm);
			if (((mount_info->unload_tm - tm) <= 0) &&
			    (cur_cmd->cmd_state < 2)) {
				mms_trace(MMS_DEVP,
				    "a delay unmount is ready for dispatch");
				/* Delay is over */
				/* command is in the 1st or 2nd state */
				MM_SET_FLAG(cur_cmd->cmd_flags,
					MM_CMD_DISPATCHABLE);
			}
		}
	}
}


/*
 * mm_order_cmd_queue
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *
 * Reorders the command queue to make processing more
 * efficient.  This will put all response first while maintaining
 * the original order. This allows MM to do more work each
 * pass through the command queue
 *
 * Return Values:
 *	None
 *
 */
void
mm_order_cmd_queue(mm_data_t *mm_data) {

	/*
	 * Re order the queue:
	 * 1) Responses
	 * 2) LMP/DMP commands
	 * 3) Privilenged Commands
	 * 4) Remaning
	 */

	/* Pull all DMP/LMP commands to the front of the list */

	int		print_message = 0;

	mms_list_t		front_list;
	mms_list_t		response_list;
	mms_list_t		lmp_dmp_list;

	mm_command_t	*cur_cmd;
	mm_command_t	*next;

	int bump = 0;
	int response = 0;
	int lmp_dmp = 0;

	char *bump_list[3];
	int num_bump_list = 3;
	bump_list[0] = strdup("hello");
	bump_list[1] = strdup("mount");
	bump_list[2] = strdup("unmount");


	mms_list_create(&front_list, sizeof (mm_command_t),
		    offsetof(mm_command_t, cmd_next));
	mms_list_create(&response_list, sizeof (mm_command_t),
		    offsetof(mm_command_t, cmd_next));
	mms_list_create(&lmp_dmp_list, sizeof (mm_command_t),
		    offsetof(mm_command_t, cmd_next));

	/* Test - print all the commands in the queue */

	if (print_message)
		mm_print_cmd_queue(mm_data);


	for (cur_cmd = mms_list_head(&mm_data->mm_cmd_queue);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		bump = 0;
		response = 0;
		lmp_dmp = 0;
		next = mms_list_next(&mm_data->
				mm_cmd_queue, cur_cmd);

		/*
		 * Find responses and privileged commands
		 */
		if ((cur_cmd->cmd_language == MM_LANG_LMP) ||
		    (cur_cmd->cmd_language == MM_LANG_DMP)) {
			lmp_dmp = 1;
		}
		if (cur_cmd->cmd_root != NULL) {
			if (strcmp(mms_pn_token(cur_cmd->
					cmd_root), "response") == 0) {
				response = 1;
			}
			for (int i = 0; i < num_bump_list; i ++) {
				if (strcmp(mms_pn_token(cur_cmd->cmd_root),
					bump_list[i]) == 0) {
					bump = 1;
				}
			}
		}
		/*
		 * Add responses to response list,
		 * priviled to front list
		 */
		if (response) {
			if (print_message)
				mms_trace(MMS_DEVP, "Bump response");

			mms_list_remove(&mm_data->mm_cmd_queue,
				cur_cmd);
			mms_list_insert_head(&response_list, cur_cmd);
		} else if (lmp_dmp) {
			if (print_message)
				mms_trace(MMS_DEVP, "Bump LMP/DMP cmd");

			mms_list_remove(&mm_data->mm_cmd_queue,
				cur_cmd);
			mms_list_insert_head(&lmp_dmp_list, cur_cmd);
		} else if (bump) {
			if (print_message)
				mms_trace(MMS_DEVP,
				    "Bump this command to front");
			mms_list_remove(&mm_data->mm_cmd_queue,
				    cur_cmd);
			mms_list_insert_head(&front_list, cur_cmd);
		} else {
			if (print_message)
				mms_trace(MMS_DEVP, "No Bump");

		}

	}

	/* Put commands back into the queue */

	for (cur_cmd = mms_list_head(&front_list);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		next = mms_list_next(&front_list, cur_cmd);
		mms_list_remove(&front_list,
			    cur_cmd);
		mms_list_insert_head(&mm_data->mm_cmd_queue, cur_cmd);

	}
	for (cur_cmd = mms_list_head(&lmp_dmp_list);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		next = mms_list_next(&lmp_dmp_list, cur_cmd);
		mms_list_remove(&lmp_dmp_list,
			    cur_cmd);
		mms_list_insert_head(&mm_data->mm_cmd_queue, cur_cmd);

	}
	for (cur_cmd = mms_list_head(&response_list);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		next = mms_list_next(&response_list, cur_cmd);
		mms_list_remove(&response_list,
			    cur_cmd);
		mms_list_insert_head(&mm_data->mm_cmd_queue, cur_cmd);

	}

	/* Test - print all the commands in the queue */
	/*
	 * if (print_message)
	 */
		mm_print_cmd_queue(mm_data);


	/* Clean up */
	mms_list_destroy(&front_list);
	mms_list_destroy(&response_list);
	mms_list_destroy(&lmp_dmp_list);

	for (int i = 0; i < num_bump_list; i ++) {
		free(bump_list[i]);
	}
}

/*
 * mm_notify
 *
 * Parameters:
 *	- arg : pointer to mm_data
 *
 * Main function for the notification thread
 *
 * This function will brodcast events to clients
 * It checks the event list and event tables and
 * sends the events to the approperate clients
 * When all events have been sent, the thread will wait
 * untill more events are generated
 *
 * Return Values:
 *	None
 *
 */
void *
mm_notify(void * arg) {
	mm_data_t	*mm_data = arg;

	notify_cmd_t	*event;
	notify_cmd_t	*next_event;

	pthread_mutex_t	*notify_lock = mm_data->mm_notify_list_mutex;
	mms_list_t		*notify_list = mm_data->mm_notify_list_ptr;

	int		done_one = 0;

	while (!mm_exiting) {
		/* Wait for Work */
		mms_trace_flush();		/* flush mms_trace buffer */
		pthread_mutex_lock(&mm_data->mm_notify_mutex);
		while (mm_data->mm_notify_work_todo == 0) {
			mms_trace(MMS_DEVP, "Notify Thread is waiting....");
			pthread_cond_wait(&mm_data->mm_notify_cv,
					&mm_data->mm_notify_mutex);
		}
		mm_data->mm_notify_work_todo = 0;
		pthread_mutex_unlock(&mm_data->mm_notify_mutex);

		if (mm_exiting)
			break;

		/* Do the notify work */
		mms_trace(MMS_DEVP,
		    "Notify Thread Processing Events...");
		pthread_mutex_lock(notify_lock);
		done_one = 0;
		for (event = mms_list_head(notify_list);
		    event != NULL;
		    event = next_event) {
			next_event = mms_list_next(notify_list, event);
			done_one = 1;
			if (event->evt_cmd_uuid == NULL) {
				/*
				 * This event is not
				 * associated with a command
				 * Set the event ready for dispatch
				 * This may already have been set
				 */
				event->evt_can_dispatch = 1;
			}
			if (event->evt_can_dispatch == 1) {
				mms_list_remove(notify_list, event);
				/* unlock to process event */
				/* This allows the worker to add events */
				/* while this thread proccess an event */
				pthread_mutex_unlock(notify_lock);
				mms_trace(MMS_DEVP, "process event, %s",
				    event->evt_cmd);
				/* brodcast the event */
				(void) notify_send(event);
				/* clean up */
				mm_notify_destroy(event);
				/* re lock */
				pthread_mutex_lock(notify_lock);
			} else {
				mms_trace(MMS_DEVP,
				    "event not dispatchable, %s",
				    event->evt_cmd);
			}
		}
		pthread_mutex_unlock(notify_lock);
		/* Send events in the event table */
		if (mm_notify_event_table(mm_data)) {
			mms_trace(MMS_ERR,
			    "error sending status table events");
		}
		if (mm_notify_event_rules(mm_data)) {
			mms_trace(MMS_ERR,
			    "error sending status table events");
		}
		if (!done_one) {
			mms_trace(MMS_DEVP,
			    "    No Events Found");
		}
	}
	return (NULL);
}

/*
 * mm_worker
 *
 * Parameters:
 *	- arg : ptr to mm_data
 *
 * Main function for the worker thread
 *
 * This function will loop through the command queue
 * and attempt to dispatch commands.  If no commands are dispatchable
 * it will wait to be signaled by the main thread.
 *
 * For dispatchable commands, it will call a function to execute
 * that commands specifc command function. mm_worker will use the return code
 * of that command function to take the approperate action
 * (see mm.h for return codes used by this function)
 *
 * After doing some work, this therad will wake the taskmanager thread
 * and notification thread
 *
 * Return Values:
 *	None
 *
 */
void *
mm_worker(void * arg) {
	mm_data_t	*mm_data = arg;
	mm_command_t *next;
	mm_command_t *cur_cmd;
	int rc;
	int command_count = 0;
	int get_next_cmd;

	while (!mm_exiting) {

		/* Wake the task manager thread */
		pthread_mutex_lock(&data->mm_task_man_mutex);
		data->mm_tm_work_todo = 1;
		pthread_cond_signal(&data->mm_task_cv);
		pthread_mutex_unlock(&data->mm_task_man_mutex);

		/* Wake the notify thread */
		pthread_mutex_lock(&data->mm_notify_mutex);
		data->mm_notify_work_todo = 1;
		pthread_cond_signal(&data->mm_notify_cv);
		pthread_mutex_unlock(&data->mm_notify_mutex);


		/* Wait for Work */
		mms_trace_flush();	  /* flush mms_trace buffer */
		pthread_mutex_lock(&mm_data->mm_worker_mutex);
		while (mm_data->mm_work_todo == 0) {
			mms_trace(MMS_DEVP, "Worker is waiting....");
			pthread_cond_wait(&mm_data->mm_work_cv,
					&mm_data->mm_worker_mutex);
		}

		/* Remove disconnected clients */
		mms_trace(MMS_DEVP,
		    "clean up clients");
		if (mm_remove_clients(mm_data, &mm_data->mm_db)) {
			/* Service fd is bad */
			mms_trace(MMS_ERR, "MM's service fd is bad, "
			    "setting mm_exiting");
			mm_exiting = 1;
		}

		mm_data->mm_work_todo = 0;
		pthread_mutex_unlock(&mm_data->mm_worker_mutex);

		if (mm_exiting)
			break;

		/* Lock and Dispatch */
		pthread_mutex_lock(&mm_data->mm_queue_mutex);
		mm_dispatch_delay_unmount(mm_data);

		/*
		 * Re order the queue:
		 * 1) Responses
		 * 2) Privilenged Commands
		 * 3) Remaning
		 */

		mm_order_cmd_queue(mm_data);

		command_count = 0;
		for (cur_cmd = mms_list_head(&mm_data->mm_cmd_queue);
			cur_cmd != NULL;
			cur_cmd = next) {

			pthread_mutex_unlock(&mm_data->
					    mm_queue_mutex);

			command_count ++;

			get_next_cmd = 0;

			if (command_count > 10) {
				mms_trace(MMS_DEVP, "done 10 commands, break");
				mm_data->mm_work_todo = 1;
				pthread_mutex_lock(&mm_data->
						mm_queue_mutex);
				break;
			}


			if (cur_cmd == NULL) {
				mms_trace(MMS_ERR, "cur_cmd == NULL");
				rc = -1;
			} else if (cur_cmd->cmd_remove) {
				rc = MM_NO_DISPATCH;
			} else {
				rc = mm_cmd_dispatch(cur_cmd);
			}
			switch (rc) {
			case MM_NO_DISPATCH:
				if (cur_cmd->cmd_root != NULL) {
					mms_trace(MMS_DEVP,
					    "A command "\
					    "was not dispatchable - %s",
					    mms_pn_token(cur_cmd->cmd_root));
				} else {
					mms_trace(MMS_DEVP,
					    "A command "		\
					    "was not dispatchable");
				}
				/* Command not dispatchable-return to queue */
				if (cur_cmd->cmd_remove) {
					if (cur_cmd->cmd_name == NULL) {
						cur_cmd->cmd_name =
						    strdup("UNKNOWN COMMAND");
					}
					mms_trace(MMS_DEVP,
					    "Removing cmd, %s %p",
					    cur_cmd->cmd_name, cur_cmd);
					pthread_mutex_lock(&mm_data->
							mm_queue_mutex);
					next = mms_list_next(&mm_data->
							mm_cmd_queue, cur_cmd);
					mms_list_remove(&mm_data->
						    mm_cmd_queue, cur_cmd);
					pthread_mutex_unlock(&mm_data->
							mm_queue_mutex);
					/* free(cur_cmd); */
					(void) mm_destroy_cmd(cur_cmd);

				} else {
					get_next_cmd = 1;
				}
				/*
				 * non-dispatchable commands
				 * don't count in the command count
				 */
				command_count --;
				break;
			case MM_DISPATCH_DEPEND:
				/*
				 * Parent Command has added
				 * a new command to the
				 * queue that is ready for dispatch,
				 * set todo = true;
				 */
				mm_data->mm_work_todo = 1;
				get_next_cmd = 1;
				break;
			case MM_DEPEND_ERROR:
				/*
				 * There was an error on a dependent command
				 * Recovery command has been added
				 */
				mm_data->mm_work_todo = 1;
				get_next_cmd = 1;
				break;
			case MM_DEPEND_DONE:
				/*
				 *  Command With Parent is done,
				 *  dispatch the parent and remove
				 *  the completed command
				 */
				mm_dispatch_all_depend(cur_cmd);

				pthread_mutex_lock(&mm_data->mm_queue_mutex);
				next = mms_list_next(&mm_data->
						mm_cmd_queue, cur_cmd);
				mms_list_remove(&mm_data->
				    mm_cmd_queue, cur_cmd);
				pthread_mutex_unlock(&mm_data->mm_queue_mutex);
				/* free(cur_cmd); */
				(void) mm_destroy_cmd(cur_cmd);
				mm_data->mm_work_todo = 1;
				break;
			case MM_CMD_DONE:
				/* The command has sucessfully completed */
				mms_trace(MMS_DEVP, "Command Completed!");
				if (mm_has_depend(cur_cmd)) {
					mm_dispatch_all_depend(cur_cmd);
				}

				pthread_mutex_lock(&mm_data->
						mm_queue_mutex);
				next = mms_list_next(&mm_data->
						mm_cmd_queue, cur_cmd);
				mms_list_remove(&mm_data->
						mm_cmd_queue, cur_cmd);
				pthread_mutex_unlock(&mm_data->
						mm_queue_mutex);
				/* free(cur_cmd); */
				(void) mm_destroy_cmd(cur_cmd);
				/*
				 * mms_trace(MMS_INFO, "command destroyed...");
				 */
				break;
			case MM_CMD_ERROR:
				mms_trace(MMS_DEBUG,
				    "Command Error - removing");
				if (mm_set_depend_error(cur_cmd)) {
					mm_data->mm_work_todo = 1;
				}

				/* If this is a failed mount */
				/* check if states need to be reset */
				if (cur_cmd->cmd_mount_info.cmi_reset_states) {
					(void) mm_set_cartridge_status(cur_cmd->
						cmd_mount_info.cmi_cartridge,
						"available", &mm_data->mm_db);
					(void) mm_set_drive_statesoft(cur_cmd->
						cmd_mount_info.cmi_drive,
						"ready", &mm_data->mm_db);
				}

				pthread_mutex_lock(&mm_data->
						mm_queue_mutex);
				next = mms_list_next(&mm_data->
						mm_cmd_queue, cur_cmd);
				mms_list_remove(&mm_data->
						mm_cmd_queue, cur_cmd);
				pthread_mutex_unlock(&mm_data->
						mm_queue_mutex);
				/* free(cur_cmd); */
				(void) mm_destroy_cmd(cur_cmd);
				break;
			case MM_DISPATCH_AGAIN:
				/*
				 * This RC means that the current
				 * command has finished,
				 * but has added another command to run
				 * Remove the first command and set todo = 1
				 */
				mms_trace(MMS_DEVP, "Dispatch Again");
				/* If this command has depends, dispatch them */
				if (mm_has_depend(cur_cmd)) {
					mm_dispatch_all_depend(cur_cmd);
				}
				pthread_mutex_lock(&mm_data->
						mm_queue_mutex);
				next = mms_list_next(&mm_data->
						mm_cmd_queue, cur_cmd);
				mms_list_remove(&mm_data->
						mm_cmd_queue, cur_cmd);
				pthread_mutex_unlock(&mm_data->
						mm_queue_mutex);
				/* free(cur_cmd); */
				(void) mm_destroy_cmd(cur_cmd);
				mm_data->mm_work_todo = 1;
				break;
			case MM_ACCEPT_NEEDED:
				/*
				 * A command has returned and needs an accept
				 * from an LM or DM,  MM_CMD_NEED_ACCEPT
				 * flag should
				 * be set and command is NOT dispatchable
				 * Leave the cmd in the queue,
				 * when accept is recieved, the cmd will
				 * be dispatched
				 */
				get_next_cmd = 1;
				break;
			case MM_WORK_TODO:
				/* A mount command state = 0 has finished */
				mm_data->mm_work_todo = 1;
				get_next_cmd = 1;
				break;
			case (-1):
				/* No commands left */
				get_next_cmd = 1;
				break;
			}
			/* Lock queue for the for loop */
			pthread_mutex_lock(&mm_data->
						mm_queue_mutex);
			if (get_next_cmd) {
				next = mms_list_next(&mm_data->
						mm_cmd_queue, cur_cmd);
			}
		}
		/* Check for responses */
		/* If all responses are not finished */
		/* set todo */
		for (cur_cmd = mms_list_head(&mm_data->mm_cmd_queue);
			cur_cmd != NULL;
			cur_cmd = next) {
			next = mms_list_next(&mm_data->
			    mm_cmd_queue, cur_cmd);
			if (cur_cmd->cmd_root != NULL) {
				if (strcmp(mms_pn_token(cur_cmd->cmd_root),
				    "response") == 0) {
					mm_data->mm_work_todo = 1;
				}
			}
		}

		pthread_mutex_unlock(&mm_data->
				mm_queue_mutex);
	}
	return (NULL);
}


/*
 * mm_task_man
 *
 * Parameters:
 *	- arg : ptr to mm_data_T
 *
 * Main function for the task manager thread
 *
 * This function will attempt to dispatch any outstanding tasks
 * by calling mm_get_tm_cmd
 * After all tasks have been evaluated, the thread will wait
 * untill signaled by the worker thread with new work.
 *
 * Return Values:
 *	None
 *
 */
void *
mm_task_man(void * arg)
{
	mm_data_t	*mm_data = arg;

	while (!mm_exiting) {

		/* Wait for Work */
		mms_trace_flush();	    /* flush mms_trace buffer */
		pthread_mutex_lock(&mm_data->mm_task_man_mutex);
		while (mm_data->mm_tm_work_todo == 0) {
			mms_trace(MMS_DEVP, "TaskManager is waiting....");
			pthread_cond_wait(&mm_data->mm_task_cv,
			    &mm_data->mm_task_man_mutex);
		}
		mm_data->mm_tm_work_todo = 0;
		pthread_mutex_unlock(&mm_data->mm_task_man_mutex);
		(void) mm_check_drive_records(mm_data, &mm_data->mm_db_tm);

		if (mm_exiting)
			break;

		/* Run TM algorithm */

		(void) mm_get_tm_cmd(mm_data);

	}
	return (NULL);
}

/*
 * mm_check_drive_records
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *	- db : ptr to valid db connection, mm_db_t
 *
 * Checks and cleans drive records
 *
 * Return Values:
 *	0 :	for success
 *
 */
int
mm_check_drive_records(mm_data_t *mm_data, mm_db_t *db) {
	time_t		tm;
	(void) time(&tm);
	if (tm >= mm_data->clean_drive_records_tm) {
		(void) mm_clean_drive_records(mm_data, db);
	}
	return (0);
}

/*
 * mm_clean_drive_records
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *	- db : ptr to valid db connection, mm_db_t
 *
 * Cleans drive records, records older than
 * DriveRecordRetention will be removed from the db
 *
 * Return Values:
 *	0 :	for success
 *	1 :	for error
 *
 */
int
mm_clean_drive_records(mm_data_t *mm_data, mm_db_t *db) {
	PGresult	*system_results;
	char		*wait;
	time_t		tm;

	if (mm_db_exec(HERE, db,
	    "select \"DriveRecordRetention\" "
	    "from \"SYSTEM\"") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "error reading system object");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	system_results = db->mm_db_results;
	if (PQntuples(system_results) != 1) {
		mms_trace(MMS_ERR,
		    "row number mismatch"
		    " reading system object");
		mm_clear_db(&system_results);
		return (1);
	}
	wait = PQgetvalue(system_results, 0, 0);

	/* wait is in days, so days * 24 * 60 * 60 == wait in seconds */

	if (mm_db_exec(HERE, db,
	    "delete from \"DRIVECARTRIDGEACCESS\" where "
	    "((extract(epoch from (\"DriveCartridgeAccessTimeUnmount\" - "
	    "\"DriveCartridgeAccessTimeMount\"))) + (%s * 24 * 60 * 60)) > 0",
	    wait) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "error removing drive records");
		mm_clear_db(&system_results);
		return (1);
	}
	mm_clear_db(&system_results);

	/* Schedule the next clean of drive records 24 hours from now */
	(void) time(&tm);
	mm_data->clean_drive_records_tm = tm + 24*60*60;
	return (0);
}


/*
 * mm_start_states
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *
 * Set the starting states for the db
 * this is called once when MM first starts
 *
 * Return Values:
 *	0 :	for success
 *
 */
int
mm_start_states(mm_data_t *mm_data)
{
	mm_db_t		*db = &mm_data->mm_db_main;
	PGresult	 *mount_logical;
	int		rows;
	int		rc;
	PGresult		*notifyid_results;

	/* Set StateSoft to 'absent' until DM/LM's connect */
	/* TEMPORARY set HardState = ready */

	(void) mm_db_exec(HERE, db, "update \"DM\" set "\
	    "\"DMStateSoft\" = 'absent',"\
	    "\"DMStateHard\" = 'ready';");
	(void) mm_db_exec(HERE, db, "update \"LM\" set "\
	    "\"LMStateSoft\" = 'absent', "\
	    "\"LMStateHard\" = 'ready';");
	(void) mm_db_exec(HERE, db,
	    "update \"CARTRIDGE\" set "
	    "\"CartridgeStatus\" = 'unavailable';");

	/* Move MOUNTLOGICAL to STALEHANDLE */
	rc = mm_db_exec(HERE, db, "select  \"ApplicationName\", "\
	    "\"VolumeName\", \"PartitionName\", "\
	    "\"SideName\", \"CartridgeID\", "\
	    "\"DriveName\", \"DMName\", "\
	    "\"MountLogicalHandle\" from\"MOUNTLOGICAL\";");
	if (rc != MM_DB_DATA) {
		/* error */
		mms_trace(MMS_ERR, "Error getting MOUNTLOGICAL handles");
		mm_clear_db(&db->mm_db_results);
		return (0);
	}

	mount_logical = db->mm_db_results;
	rows = PQntuples(mount_logical);
	for (int i = 0; i < rows; i ++) {
		/* Move 1 MOUNTLOGICAL to STALEHANDLE */
		if (mm_db_exec(HERE, db,
		    "insert into \"STALEHANDLE\" "\
		    "(\"ApplicationName\", \"VolumeName\", "\
		    "\"PartitionName\", "\
		    "\"SideName\", \"CartridgeID\", "\
		    "\"DriveName\", \"DMName\", "\
		    "\"MountLogicalHandle\") values "\
		    "('%s', '%s', '%s', '%s', "\
		    "'%s', '%s', '%s', '%s');",
		    PQgetvalue(mount_logical, i, 0),
		    PQgetvalue(mount_logical, i, 1),
		    PQgetvalue(mount_logical, i, 2),
		    PQgetvalue(mount_logical, i, 3),
		    PQgetvalue(mount_logical, i, 4),
		    PQgetvalue(mount_logical, i, 5),
		    PQgetvalue(mount_logical, i, 6),
		    PQgetvalue(mount_logical, i, 7)) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "DB error copying MOUNTLOGICAL to STALEHANDLE");
		}

		/* Delete the old mount logical */
		if (mm_db_exec(HERE, db,
		    "delete from \"MOUNTLOGICAL\" "
		    "where \"CartridgeID\" = '%s';",
		    PQgetvalue(mount_logical, i, 4)) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "DB error deleting MOUNTLOGICAL");
		}
	}
	mm_clear_db(&mount_logical);

	(void) mm_db_exec(HERE, db, "delete from \"SLOT\";");
	(void) mm_db_exec(HERE, db, "delete from \"BAY\";");
	(void) mm_db_exec(HERE, db, "delete from \"SLOTGROUP\";");


	if (mm_db_exec(HERE, db, "update \"DRIVE\" set "
	    "\"DriveStateSoft\" = 'unavailable', "
	    "\"DriveLibraryOccupied\" = 'f', "
	    "\"DriveStateHard\" = 'unloaded', "
	    "\"BayName\" = DEFAULT, "
	    "\"DriveShapeName\" = DEFAULT, "
	    "\"DMName\" = DEFAULT;") != MM_DB_OK) {
		MM_ABORT("drive set at init");
	}


	(void) mm_db_exec(HERE, db, "delete from \"REQUEST\" where "
	    "\"RequestState\" != 'responded';");
	(void) mm_db_exec(HERE, db, "delete from \"NOTIFY\";");

	(void) mm_db_exec(HERE, db, "delete from \"SESSION\";");
	(void) mm_db_exec(HERE, db, "delete from \"CONNECTION\";");
	(void) mm_db_exec(HERE, db, "delete from \"TASKCARTRIDGE\";");
	(void) mm_db_exec(HERE, db, "delete from \"TASKDRIVE\";");
	(void) mm_db_exec(HERE, db, "delete from \"TASKLIBRARY\";");
	(void) mm_db_exec(HERE, db, "delete from \"TASK\";");

	/* Get any rules and drop them */
	if (mm_db_exec(HERE, db,
	    "select \"NotifyID\",\"NotifyObject\""
	    " from \"NOTIFYRULES\";") == MM_DB_DATA) {
		notifyid_results = db->mm_db_results;
		for (int i = 0; i < PQntuples(notifyid_results); i ++) {
			(void) mm_db_exec(HERE, db,
			    "drop rule \"%s\" on \"%s\";",
			    PQgetvalue(notifyid_results, i, 0),
			    PQgetvalue(notifyid_results, i, 1));
		}
		mm_clear_db(&notifyid_results);
	} else {
		mms_trace(MMS_ERR,
		    "error getting notifyid's");
		mm_clear_db(&db->mm_db_results);
	}


	(void) mm_db_exec(HERE, db, "delete from \"NOTIFYRULES\";");
	(void) mm_db_exec(HERE, db, "delete from \"EVENTRULES\";");

	(void) mm_db_exec(HERE, db, "update \"LIBRARY\" set "\
	    "\"LibraryStateSoft\" = 'ready';");


	/* Delete all DM Configs */
	(void) mm_db_exec(HERE, db, "delete from \"DMSHAPEPRIORITY\";");
	(void) mm_db_exec(HERE, db, "delete from \"DMDENSITYPRIORITY\";");
	(void) mm_db_exec(HERE, db, "delete from \"DMMOUNTPOINT\";");
	(void) mm_db_exec(HERE, db, "delete from \"DMCAPABILITYTOKEN\";");
	(void) mm_db_exec(HERE, db, "delete from \"DMBITFORMAT\";");
	(void) mm_db_exec(HERE, db, "delete from \"DMBITFORMATTOKEN\";");
	(void) mm_db_exec(HERE, db, "delete from \"DMCAPABILITYGROUP\";");
	(void) mm_db_exec(HERE, db, "delete from \"DMCAPABILITYGROUPTOKEN\";");
	/* Clean the Event table */
	(void) mm_db_exec(HERE, db, "delete from \"EVENT\";");

	/* Clean the drive records */
	(void) mm_clean_drive_records(mm_data, db);

	return (0);
}

/*
 * mm_calculate_timeout
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *
 * Determines the correct timeout for MM's main thread pselect
 *
 * When there is a delay unload command present, MM will
 * need to break out of pselect inorder to do the unload
 * at the correct time.
 *
 * The timeout will be the time for the current delay
 * unload's drivegroup minus the time since the delay was
 * scheduled.
 *
 * There will only be a timeout if there is delay unload
 * command on the queue.  If the delay unload is not
 * present the function returns 0
 *
 * Return Values:
 *	timeout :	return the timeout in seconds
 *	0 :		return 0 for no timeout
 *
 */
int
mm_calculate_timout(mm_data_t *mm_data) {

	mm_db_t		*db = &mm_data->mm_db_main;

	mm_command_t		*cur_cmd;
	time_t			tm;
	cmd_mount_info_t	*mount_info;

	int			wait = 0;
	int			wait_set = 0;
	int			any_command = 0;
	/* Returns 0 for no timout */



	pthread_mutex_lock(&mm_data->mm_queue_mutex);
	mms_list_foreach(&mm_data->mm_cmd_queue, cur_cmd) {
		any_command = 1;
		if (cur_cmd->cmd_func == mm_delay_unmount_cmd_func) {
			/* is a delay unload command */
			mount_info = &cur_cmd->cmd_mount_info;
			(void) time(&tm);
			if ((wait_set == 0) &&
			    ((mount_info->unload_tm - tm) > 0)) {
				/* The 1st delay unload */
				wait = mount_info->unload_tm - tm;
				wait_set = 1;
			} else if ((wait > (mount_info->unload_tm - tm)) &&
				((mount_info->unload_tm - tm) > 0)) {
				/* A delay shorter than the 1st */
				wait = mount_info->unload_tm - tm;
			}

		}
	}
	pthread_mutex_unlock(&mm_data->
			mm_queue_mutex);
	if (!any_command) {
		mms_trace(MMS_DEVP, "no MM timeout");
		return (wait);
	}
	if (!wait_set) {
		if (mm_db_exec(HERE, db,
			    "select \"DriveGroupUnloadTime\" from "
			    "\"DRIVEGROUP\"  order by "
			    "\"DriveGroupUnloadTime\" asc limit 1;")
		    != MM_DB_DATA) {
			mms_trace(MMS_ERR, "Exec returned with no Data");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_DEVP, "No drivegorups exist");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		/* Timeout is in min, so mult by 60 for seconds */
		wait = 60*atoi(PQgetvalue(db->mm_db_results, 0, 0));
	}
	mms_trace(MMS_DEVP, "MM timeout is %d", wait);
	mm_clear_db(&db->mm_db_results);
	return (wait);
}

/*
 * mm_reconfig
 *
 * Parameters:
 *	- mm_data : ptr to mm_data_t
 *
 *
 * Referesh the MM's config information
 *
 * Return Values:
 *	0 :	for success
 *
 */
static int
mm_reconfig(mm_data_t *data)
{
	mm_cfg_t	mm_cfg;
#ifdef	MMS_OPENSSL
	mm_wka_t	*mm_wka;
	mms_err_t	err;
	char		ebuf[MMS_EBUF_LEN];
#endif

	/*
	 * Re-load configuration
	 */
	mm_refresh = 0;
	if (mm_cfg_read(&mm_cfg)) {
		mms_trace(MMS_ERR, "configuration refresh error");
		mm_cfg_free(&mm_cfg);
		exit(SMF_EXIT_ERR_CONFIG);
	}

	pthread_mutex_lock(&data->mm_wka_mutex);
	mm_cfg_free(&data->mm_cfg);
	(void) memcpy(&data->mm_cfg, &mm_cfg, sizeof (mm_cfg_t));
	pthread_mutex_unlock(&data->mm_wka_mutex);
	mms_trace(MMS_INFO, "configuration refreshed");

#ifdef	MMS_OPENSSL
	if (data->mm_ssl_data) {
		mms_ssl_server_set_verify_peer(data->mm_ssl_data,
		    mm_cfg.mm_ssl_verify_peer);

		/*
		 * Get updated CRL
		 */
		if (mms_ssl_reload_crl_file(data->mm_ssl_data,
		    data->mm_cfg.mm_network_cfg.ssl_crl_file, &err)) {
			mms_get_error_string(&err, ebuf, MMS_EBUF_LEN);
			mms_trace(MMS_ERR, "crl file reload failed %s", ebuf);
			return (1);
		}

		/*
		 * Check for revoked clients
		 */
		if (mms_ssl_has_crl(data->mm_ssl_data)) {
			mms_trace(MMS_DEVP, "check for revoked clients");

			pthread_mutex_lock(&data->mm_wka_mutex);
			mms_list_foreach(&data->mm_wka_list, mm_wka) {
				if (mms_ssl_check_conn_cert(data->mm_ssl_data,
				    mm_wka->mm_wka_conn)) {

					mms_get_error_string(
					    &err, ebuf, MMS_EBUF_LEN);
					mms_trace(MMS_INFO,
					    "client revoked %s %s - %s",
					    mm_wka->wka_conn.cci_client,
					    mm_wka->wka_conn.cci_instance,
					    ebuf);

					mm_wka->wka_remove = 1;
				}
			}
			pthread_mutex_unlock(&data->mm_wka_mutex);
		}
	}
#endif	/* MMS_OPENSSL */
	(void) smf_refresh_instance(MMS_CFG_WCR_INST);
	return (0);
}


/*
 * main
 *
 * Parameters:
 *	No args
 *
 * This is the main function for MM
 *
 * This function first initializes the MM's tracing,
 * db connections, core files, signal handleing, and
 * creates the worker, task manager, and notification threads.
 *
 * Once MM has been intialized, this thread acts as the reader thread
 * it will accept and proccess incomming command and clients.
 * It will signal the other threads when there is work to be done.
 * When commands/clients have completed/disconnected this thread will
 * do the clean up and free any associated memory
 *
 * Return Values:
 *	N/A
 *
 */
int
main(int argc, char **argv)
{
	fd_set		 rfds;
	int		 mfd;
	int		 rc;
	char		*buf = NULL;
	sigset_t	 new_mask;
	sigset_t	 old_mask;
	mm_wka_t	*mm_wka;
	pthread_t	 tid;
	pthread_t	 tm_tid;
	pthread_t	 notify_tid;
	mms_t		*cli_conn;
	char		 ebuf[MMS_EBUF_LEN];
	char		 c;
	void		*status;
	/* Time out */
	struct timespec timeout;
	int		err;
	int		daemon_mode = 1;

	/*
	 * Get debug DM config option
	 */
	while ((c = getopt(argc, argv, "v(version)n(nodaemon)")) != -1) {
		switch (c) {
		case 'v':
			printf("%d\n", MM_DB_VERSION);
			return (0);
		case 'n':
			daemon_mode = 0;
			break;
		default:
			break;
		}
	}


	/*
	 * Setup MM data and services
	 */
	mm_initialize(&mm_data, daemon_mode);

	/*
	 * Setup to block signals MM cares about.
	 * This is inherited by the threads so they will not
	 * be interrupted by signals.
	 */
	sigemptyset(&new_mask);
	sigaddset(&new_mask, SIGINT);
	sigaddset(&new_mask, SIGHUP);
	sigaddset(&new_mask, SIGTERM);
	sigaddset(&new_mask, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

	/*
	 * Get seperate database connections for worker and main threads
	 */
	mm_data.mm_db.mm_db_has_list = 0;
	mm_data.mm_db_main.mm_db_has_list = 0;
	mm_data.mm_db_tm.mm_db_has_list = 0;
	mm_data.mm_db.mm_db_resending = 0;
	mm_data.mm_db_main.mm_db_resending = 0;
	mm_data.mm_db_tm.mm_db_resending = 0;
	if (mm_db_connect(&mm_data.mm_db) != MM_DB_OK ||
	    mm_db_connect(&mm_data.mm_db_main) != MM_DB_OK ||
	    mm_db_connect(&mm_data.mm_db_tm) != MM_DB_OK) {
		mms_trace(MMS_ERR, "unable to connect to database");
		exit(SMF_EXIT_ERR_FATAL);
	}
	/* initialze the db cmd lists */
	mms_list_create(&mm_data.mm_db.mm_db_cmds, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&mm_data.mm_db_main.mm_db_cmds, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&mm_data.mm_db_tm.mm_db_cmds, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mm_data.mm_db.mm_db_has_list = 1;
	mm_data.mm_db_main.mm_db_has_list = 1;
	mm_data.mm_db_tm.mm_db_has_list = 1;


	(void) mm_start_states(data);
	/* create worker and task manager threads */

	pthread_create(&tid, NULL, mm_worker, data);

	pthread_create(&tm_tid, NULL, mm_task_man, data);

	if (mm_notify_init(&mm_data)) {
		mms_trace(MMS_ERR, "unable to init notification events");
		exit(SMF_EXIT_ERR_FATAL);
	}

	pthread_create(&notify_tid, NULL, mm_notify, data);

	/*
	 * Setup signal handlers
	 */
	mm_signal(SIGINT, mm_signal_handler);
	mm_signal(SIGHUP, mm_signal_handler);
	mm_signal(SIGTERM, mm_signal_handler);
	mm_signal(SIGPIPE, mm_signal_handler);

	(void) mm_message(&mm_data.mm_db_main,
	    MESS_LOG, MESS_INFO, MM_5013_MSG, NULL);

	/*
	 * Accept new clients, read client input
	 */
	mms_trace(MMS_DEBUG, "Waiting for Commands...");
	while (!mm_exiting) {

		/*
		 * Setup for pselect
		 */
		FD_ZERO(&rfds);
		FD_SET(mm_data.mm_service_fd, &rfds);
		mfd = mm_data.mm_service_fd;
		pthread_mutex_lock(&data->mm_wka_mutex);
		mms_list_foreach(&mm_data.mm_wka_list, mm_wka) {
			if (mm_wka->mm_wka_conn->mms_fd == -1) {
				mms_trace(MMS_ERR,
				    "mms_fd == -1 for client,"
				    "set wka_remove");
				mm_wka->wka_remove = 1;
				continue;
			}
			FD_SET(mm_wka->mm_wka_conn->mms_fd, &rfds);
			if (mfd < mm_wka->mm_wka_conn->mms_fd) {
				mfd = mm_wka->mm_wka_conn->mms_fd;
			}
		}
		pthread_mutex_unlock(&data->mm_wka_mutex);

		mms_trace(MMS_DEVP, "pselect");
		mms_trace_flush();		/* flush mms_trace buffer */

		/* Calculate the time out */
		timeout.tv_nsec = 0;
		if ((timeout.tv_sec = mm_calculate_timout(&mm_data)) == 0) {
			rc = pselect(mfd + 1, &rfds, NULL,
			    NULL, NULL, &old_mask);
		} else {
			rc = pselect(mfd + 1, &rfds, NULL,
			    NULL, &timeout, &old_mask);
		}
		err = errno;

		if (mm_exiting) {
			mms_trace(MMS_DEVP, "do exit");
			break;
		}
		if (mm_refresh) {
			mms_trace(MMS_DEVP, "do refresh");
			if (mm_reconfig(&mm_data)) {
				mms_trace(MMS_ERR, "mm reconfig");
				mm_exiting = 1;
				break;
			}
		}

		/* Check for interupt and bad file descriptor */
		if (rc == -1) {
			mms_trace(MMS_DEBUG, "errno = %d: %s",
			    err, strerror(err));
			if (err == EINTR) {
				mms_trace(MMS_DEVP, "Pselect INTERRUPTED!!");
				/* Take action */
				continue;
			} else if (err == EBADF) {
				mms_trace(MMS_DEVP, "BAD FD!");
				/* Take action */
			}

			if (mm_is_fd_valid(mm_data.mm_service_fd) != 0) {
				mms_trace(MMS_ERR,
				    "mm service not valid FD -> %d",
				    mm_data.mm_service_fd);
				/* Service Not Valid */
				break;
			}

			/* Get valid FD SET */
			continue;
		}

		/* A wka FD is ready to be read... */
		pthread_mutex_lock(&data->mm_wka_mutex);
		mms_list_foreach(&mm_data.mm_wka_list, mm_wka) {
			if (mm_wka->wka_remove ||
			    mm_wka->mm_wka_conn->mms_fd == -1) {
				mms_trace(MMS_DEBUG,
				    "wka should be removed"
				    ", dont read");
				mm_wka->wka_remove = 1;
			} else if (!mm_exiting &&
			    FD_ISSET(mm_wka->mm_wka_conn->mms_fd, &rfds)) {
				if (buf != NULL) {
					free(buf);
					buf = NULL;
				}
				rc = mms_reader(mm_wka->mm_wka_conn, &buf);
				if (rc > 0) {
					mms_trace(MMS_DEBUG,
					    "read %s %s fd -> %d",
					    mm_wka->wka_conn.cci_client,
					    mm_wka->wka_conn.cci_instance,
					    mm_wka->mm_wka_conn->mms_fd);
					mm_add_cmd(mm_wka, buf, &mm_data);
				} else if (mm_wka->wka_remove != 1) {
					mm_wka->wka_remove = 1;
					if (mm_wka->mm_wka_mm_lang ==
					    MM_LANG_DMP) {
						mms_trace(MMS_INFO,
						    "DM Disconnected "
						    "%s %s fd -> %d",
						    mm_wka->wka_conn.cci_client,
						    mm_wka->
						    wka_conn.cci_instance,
						    mm_wka->
						    mm_wka_conn->mms_fd);
					} else if (mm_wka->mm_wka_mm_lang ==
					    MM_LANG_LMP) {
						mms_trace(MMS_INFO,
						    "LM Disconnected "
						    "%s %s fd -> %d",
						    mm_wka->
						    wka_conn.cci_client,
						    mm_wka->
						    wka_conn.cci_instance,
						    mm_wka->
						    mm_wka_conn->mms_fd);
					} else if (mm_wka->mm_wka_mm_lang ==
					    MM_LANG_MMP) {
						mms_trace(MMS_INFO,
						    "MM Client Disconnected "
						    "%s %s fd -> %d",
						    mm_wka->
						    wka_conn.cci_client,
						    mm_wka->
						    wka_conn.cci_instance,
						    mm_wka->
						    mm_wka_conn->mms_fd);
					} else {
						mms_trace(MMS_INFO,
						    "bad read - "
						    "client disconnect "
						    "%s %s fd -> %d",
						    mm_wka->
						    wka_conn.cci_client,
						    mm_wka->
						    wka_conn.cci_instance,
						    mm_wka->
						    mm_wka_conn->mms_fd);
					}
				}
			}
		}
		pthread_mutex_unlock(&data->mm_wka_mutex);

		mms_trace_flush();
		if (FD_ISSET(mm_data.mm_service_fd, &rfds)) {
			/* A new client has been found */
			if (mm_exiting) {
				mms_trace(MMS_INFO, "mm exiting");
				break;
			}
			mms_trace(MMS_DEBUG, "Client connecting...");
			cli_conn = (mms_t *)calloc(1, sizeof (mms_t));
			if (cli_conn == NULL) {
				mms_trace(MMS_ERR, "add client alloc");
				break;
			}
			if (mms_accept(mm_data.mm_service_fd,
			    mm_data.mm_ssl_data,
			    cli_conn)) {
				mms_trace(MMS_ERR,
				    "Error accepting new client connection");
				mms_get_error_string(&cli_conn->mms_err,
				    ebuf, MMS_EBUF_LEN);
				mms_trace(MMS_ERR, "Client Accept - fd %d, %s",
				    mm_data.mm_service_fd, ebuf);
				free(cli_conn);
				/* continue processing */
			} else {
				if (mm_exiting) {
					mms_trace(MMS_INFO, "mm exiting");
					break;
				}
				if (mm_add_wka(&mm_data, cli_conn)) {
					free(cli_conn);
				}
			}
		}

		if (mm_is_fd_valid(mm_data.mm_service_fd) != 0) {
			mms_trace(MMS_ERR, "mm service not valid FD -> %d",
			    mm_data.mm_service_fd);
			/* Service Not Valid */
			break;
		}

		/* wakeup worker thread to do work */
		pthread_mutex_lock(&data->mm_worker_mutex);
		data->mm_work_todo = 1;
		pthread_cond_signal(&data->mm_work_cv);
		pthread_mutex_unlock(&data->mm_worker_mutex);

	}

	/*
	 * Cleanup and exit
	 */
	mm_exiting = 1;

	mms_trace(MMS_DEBUG, "signal task manager");
	pthread_mutex_lock(&data->mm_task_man_mutex);
	data->mm_tm_work_todo = 1;
	pthread_cond_signal(&data->mm_task_cv);
	pthread_mutex_unlock(&data->mm_task_man_mutex);

	mms_trace(MMS_DEBUG, "signal worker");
	pthread_mutex_lock(&data->mm_worker_mutex);
	data->mm_work_todo = 1;
	pthread_cond_signal(&data->mm_work_cv);
	pthread_mutex_unlock(&data->mm_worker_mutex);

	mms_trace(MMS_DEBUG, "signal notify");
	pthread_mutex_lock(&data->mm_notify_mutex);
	data->mm_notify_work_todo = 1;
	pthread_cond_signal(&data->mm_notify_cv);
	pthread_mutex_unlock(&data->mm_notify_mutex);

	mms_trace(MMS_INFO, "join task manager");
	pthread_join(tm_tid, &status);

	mms_trace(MMS_INFO, "join worker");
	pthread_join(tid, &status);

	mms_trace(MMS_INFO, "join notify");
	pthread_join(notify_tid, &status);

	mms_trace(MMS_DEBUG, "close connections");
	mm_notify_close();
	mm_message_close();
	mm_db_disconnect(&mm_data.mm_db);
	mm_db_disconnect(&mm_data.mm_db_main);
	mm_db_disconnect(&mm_data.mm_db_tm);
	close(mm_data.mm_service_fd);
#ifdef	MMS_OPENSSL
	mms_ssl_finish(mm_data.mm_ssl_data);
#endif

	mms_trace(MMS_INFO, "MM Shutdown");
	mms_trace_close();
	closelog();

	return (SMF_EXIT_OK);
}
