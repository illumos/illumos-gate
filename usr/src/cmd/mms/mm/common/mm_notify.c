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
#include <mms_trace.h>
#include <mms_strapp.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_sql.h"
#include "mm_commands.h"
#include "mm_sql.h"

static char *_SrcFile = __FILE__;

/* Event table notification types */
#define	ETABLE_STATUS 0
#define	ETABLE_REQUEST 1
#define	ETABLE_MESSAGE 2
#define	ETABLE_CARTRIDGE 3
#define	ETABLE_VOLUME 4


/* All possible Notification Levels */
#define	NOTIFY_OFF 0
#define	NOTIFY_GLOBAL 1
#define	NOTIFY_APPLICATION 2
#define	NOTIFY_INSTANCE 3
#define	NOTIFY_SESSION 4
#define	NOTIFY_HOST 5

typedef struct notify notify_t;	/* sql table notify object as a structure */
struct notify {
	char	*n_uuid;
	char	*n_client;
	char	*n_inst;
	char	*n_cfgchg;
	char	*n_newdrive;
	char	*n_newcartridge;
	char	*n_volumeinject;
	char	*n_volumeeject;
	char	*n_volumeadd;
	char	*n_volumedelete;
	char	*n_dmup;
	char	*n_dmdown;
	char	*n_driveonline;
	char	*n_driveoffline;
	char	*n_lmup;
	char	*n_lmdown;
	char	*n_librarycreate;
	char	*n_librarydelete;
	char	*n_drivedelete;
};


static pthread_mutex_t		notify_lock;
static mm_db_t			notify_db;
static mms_list_t			notify_list;
static mm_data_t		*notify_data;


static void notify_results(PGresult *results, int row, notify_t *notify);
static void notify_client(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event);
static int notify_etable(int etable);




/* Initialize notify. */
int
mm_notify_init(mm_data_t *data)
{
	mms_trace(MMS_DEVP, "mm_notify_init");

	mms_list_create(&notify_list, sizeof (notify_cmd_t),
	    offsetof(notify_cmd_t, evt_next));
	notify_data = data;
	memset(&notify_db, 0, sizeof (mm_db_t));
	notify_db.mm_db_cfg = data->mm_db.mm_db_cfg;
	notify_db.mm_db_has_list = 0;
	notify_db.mm_db_resending = 0;
	if (mm_db_connect(&notify_db) != MM_DB_OK) {
		mms_trace(MMS_ERR, "notify db connection failed");
		return (1);
	}
	mms_list_create(&notify_db.mm_db_cmds, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	notify_db.mm_db_has_list = 1;

	pthread_mutex_init(&notify_lock, NULL);
	data->mm_notify_list_mutex = &notify_lock;
	data->mm_notify_list_ptr = &notify_list;

	return (0);
}

/* Close notify. */
void
mm_notify_close(void)
{
	mms_trace(MMS_DEVP, "mm_notify_close");

	mm_db_disconnect(&notify_db);
}
void
notify_set_cli_uuid(notify_cmd_t *event, uuid_text_t uuid) {
	strncpy(event->evt_cli_uuid,
	    uuid,
	    UUID_PRINTF_SIZE);
}

void
notify_set_session_uuid(notify_cmd_t *event, uuid_text_t uuid) {
	strncpy(event->evt_session_uuid,
	    uuid,
	    UUID_PRINTF_SIZE);
}
void
notify_set_cmd_uuid(notify_cmd_t *event, uuid_text_t uuid) {
	strncpy(event->evt_cmd_uuid,
	    uuid,
	    UUID_PRINTF_SIZE);
}
void
notify_set_cli_name(notify_cmd_t *event, char *name) {
	event->evt_cli_name = mms_strapp(event->evt_cli_name,
	    name);
}
void
notify_set_cli_instance(notify_cmd_t *event, char *instance) {
	event->evt_cli_instance = mms_strapp(event->evt_cli_instance,
	    instance);
}
void
notify_set_evt_obj_name(notify_cmd_t *event, char *name) {
	event->evt_obj_name = mms_strapp(event->evt_obj_name,
	    name);
}
void
notify_set_evt_obj_instance(notify_cmd_t *event, char *instance) {
	event->evt_obj_instance = mms_strapp(event->evt_obj_instance,
	    instance);
}
void
notify_set_evt_obj_host(notify_cmd_t *event, char *host) {
	event->evt_obj_host = mms_strapp(event->evt_obj_host,
	    host);
}
void
notify_set_evt_obj_library(notify_cmd_t *event, char *library) {
	event->evt_obj_library = mms_strapp(event->evt_obj_library,
	    library);
}
void
notify_set_evt_obj_cartid(notify_cmd_t *event, char *cartid) {
	event->evt_obj_cartid = mms_strapp(event->evt_obj_cartid,
	    cartid);
}
void
notify_set_evt_obj_drive(notify_cmd_t *event, char *drive) {
	event->evt_obj_drive = mms_strapp(event->evt_obj_drive,
	    drive);
}


void
mm_notify_send_status(mm_wka_t *notify_wka, PGresult *results) {

	char		*event_buf = NULL;
	int		num_events = PQntuples(results);
	char		*obj_name;
	cci_t		*conn = &notify_wka->wka_conn;
	char		*info1;
	char		*info2;
	char		*info3;
	int		i;

	for (i = 0; i < num_events; i++) {
		obj_name = PQgetvalue(results, i, 0);
		info1 = NULL;

		/* This ordering depends on the */
		/* select statement in the funtion below */
		if (strcmp(obj_name, "LIBRARY") == 0) {
			/* library event */
			info1 = PQgetvalue(results, i, 1);
		} else if (strcmp(obj_name, "DRIVE") == 0) {
			/* drive event */
			info1 = PQgetvalue(results, i, 1);
		} if (strcmp(obj_name, "DM") == 0) {
			/* dm event */
			info1 = PQgetvalue(results, i, 1);
		} else if (strcmp(obj_name, "LM") == 0) {
			/* lm event */
			info1 = PQgetvalue(results, i, 1);
		} else if (strcmp(obj_name, "REQUEST") == 0) {
			/* request event */
			info1 = PQgetvalue(results, i, 1);
			info2 = PQgetvalue(results, i, 2);
			info3 = PQgetvalue(results, i, 3);
			if (info1 == NULL || info2 == NULL || info3 == NULL) {
				info1 = NULL;
			}
		} else if (strcmp(obj_name, "MESSAGE") == 0) {
			/* message event */
			info1 = PQgetvalue(results, i, 1);
			info2 = PQgetvalue(results, i, 2);
			info3 = PQgetvalue(results, i, 3);
			if (info1 == NULL || info2 == NULL || info3 == NULL) {
				info1 = NULL;
			}
		} else if (strcmp(obj_name, "CARTRIDGE") == 0) {
			/* cartridge event */
			info1 = PQgetvalue(results, i, 1);
			info2 = PQgetvalue(results, i, 2);
			if (info1 == NULL || info2 == NULL) {
				info1 = NULL;
			}
		} else if (strcmp(obj_name, "VOLUME") == 0) {
			/* message event */
			info1 = PQgetvalue(results, i, 1);
			info2 = PQgetvalue(results, i, 2);
			info3 = PQgetvalue(results, i, 3);
			if (info1 == NULL || info2 == NULL || info3 == NULL) {
				info1 = NULL;
			}
		}
		if (info1 != NULL) {
			if (strcmp(obj_name, "REQUEST") == 0) {
				event_buf = mms_strapp(event_buf,
				    "event request[\"%s\" \"%s\" \"%s\"];",
				    info1,
				    info2,
				    info3);
			} else if (strcmp(obj_name, "MESSAGE") == 0) {
				event_buf = mms_strapp(event_buf,
				    "event message[\"%s\" \"%s\" \"%s\"];",
				    info1,
				    info2,
				    info3);
			} else if (strcmp(obj_name, "CARTRIDGE") == 0) {
				event_buf = mms_strapp(event_buf,
				    "event cartridge[\"%s\" \"%s\"];",
				    info1,
				    info2);
			} else if (strcmp(obj_name, "VOLUME") == 0) {
				event_buf = mms_strapp(event_buf,
				    "event volume[\"%s\" \"%s\" \"%s\"];",
				    info1,
				    info2,
				    info3);
			} else {
				event_buf = mms_strapp(event_buf,
				    "event status[\"%s\" \"%s\"];",
				    obj_name,
				    info1);
			}
			mms_trace(MMS_INFO,
			    "Send event to %s %s, %s",
			    conn->cci_client,
			    conn->cci_instance,
			    event_buf);
			mm_send_text(notify_wka->mm_wka_conn,
			    event_buf);

		} else {
			mms_trace(MMS_ERR,
			    "bad status event");
		}
		if (event_buf) {
			free(event_buf);
			event_buf = NULL;
		}
	}


}

char *
mm_write_event(char *notify_obj, PGresult *notify_results,
    PGresult *event_results, int i) {
	char *event_buf = NULL;
	int wrote_data = 0;
	int j;

	/* same wka */
	event_buf = mms_strapp(event_buf,
	    "event tag[\"%s\"] "
	    "object[%s]",
	    PQgetvalue(notify_results, 0, 1),
	    notify_obj);
	for (j = 2; j < 7; j++) {
		if (j == 2 &&
		    strcmp(PQgetvalue(event_results,
		    i, j), "") == 0) {
			continue;
		} else if (j == 2) {
			wrote_data = 1;
			event_buf = mms_strapp(event_buf,
			    "data[\"%s\" ",
			    PQgetvalue(event_results,
			    i, j));
		} else if (strcmp(PQgetvalue(event_results,
		    i, j), "") != 0) {
			event_buf = mms_strapp(event_buf,
			    "\"%s\" ",
			    PQgetvalue(event_results,
			    i, j));
		}
	}
	if (wrote_data) {
		event_buf = mms_strapp(event_buf, "]");
	}
	event_buf = mms_strapp(event_buf, ";");
	return (event_buf);

}


int
/* LINTED:mm_data may be needed in the future */
mm_notify_event_rules(mm_data_t	*mm_data) {
	mm_db_t		*db = &notify_db;

	PGresult	 *event_results;
	int		num_events = 0;

	PGresult	 *notify_results;

	int		i;

	char		*notify_id;
	char		*notify_obj;

	char		*event_buf = NULL;

	mm_wka_t	*notify_wka;
	mm_wka_t	*next_notify_wka;

	/* Send all events in rule table */
	if (mm_db_exec(HERE, db,
	    "select distinct \"NotifyID\",\"NotifyObject\","
	    "\"Data1\",\"Data2\",\"Data3\",\"Data4\",\"Data5\" "
	    " from \"EVENTRULES\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "error getting events "
		    "from EVENTRULES");
		return (1);
	}
	event_results = db->mm_db_results;
	num_events = PQntuples(event_results);
	mms_trace(MMS_DEVP,
	    "%d events found",
	    num_events);

	if (num_events == 0) {
		mm_clear_db(&event_results);
		return (0);
	}

	for (i = 0; i < num_events; i ++) {
		notify_id = PQgetvalue(event_results, i, 0);
		notify_obj = PQgetvalue(event_results, i, 1);
		if (mm_db_exec(HERE, db,
		    "select \"ConnectionID\",\"NotifyTag\""
		    " from \"NOTIFYRULES\" where \"NotifyID\" = '%s';",
		    notify_id) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "error getting results "
			    "from NOTIFYRULES");
			mm_clear_db(&event_results);
			return (1);
		}
		notify_results = db->mm_db_results;
		if (PQntuples(notify_results) == 0) {
			/* no notify row for this */
			char *savepoint = NULL;
			savepoint = mms_strnew("\"%s\"", notify_id);
			if (mm_db_txn_savepoint(db,
			    savepoint) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_notify_event_rules: "
				    "db error setting savepoint");
			}
			if (mm_db_exec(HERE, db,
			    "drop rule \"%s\" on \"%s\";", notify_id,
			    notify_obj) !=
			    MM_DB_OK) {
				if (mm_db_txn_savepoint_rollback(db,
				    savepoint) != MM_DB_OK) {
					mms_trace(MMS_ERR,
					    "mm_notify_event_rules: "
					    "db error rollingback savepoint");
				}
			}
			if (mm_db_txn_release_savepoint(db,
			    savepoint) != MM_DB_OK) {
				mms_trace(MMS_ERR,
				    "mm_notify_event_rules: "
				    "db error releaseing savepoint");
			}
			free(savepoint);
		} else {
			mms_trace(MMS_DEVP,
			    "send event to %s, %s",
			    PQgetvalue(notify_results, 0, 0),
			    PQgetvalue(notify_results, 0, 1));


			pthread_mutex_lock(&notify_data->mm_wka_mutex);
			for (notify_wka =
			    mms_list_head(&notify_data->mm_wka_list);
			    notify_wka != NULL;
			    notify_wka = next_notify_wka) {
				pthread_mutex_lock(&notify_wka->wka_local_lock);
				if (strcmp(notify_wka->wka_conn.cci_uuid,
				    PQgetvalue(notify_results, 0, 0)) == 0) {

					/* same wka */
					if ((event_buf =
					    mm_write_event(notify_obj,
					    notify_results,
					    event_results, i)) == NULL) {
						mms_trace(MMS_ERR,
						    "error writing "
						    "event buffer");
					} else {
						mm_send_text(notify_wka->
						    mm_wka_conn,
						    event_buf);
						free(event_buf);
						event_buf = NULL;
					}
				}
				next_notify_wka =
				    mms_list_next(&notify_data->mm_wka_list,
				    notify_wka);
				pthread_mutex_unlock(&notify_wka->
				    wka_local_lock);
			}
			pthread_mutex_unlock(&notify_data->mm_wka_mutex);
		}

		if (mm_db_exec(HERE, db,
		    "delete from \"EVENTRULES\""
		    " where \"NotifyID\" = '%s';",
		    notify_id) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "error deleting "
			    "from NOTIFYRULES");
			mm_clear_db(&event_results);
			mm_clear_db(&notify_results);
			return (1);
		}
	}
	mm_clear_db(&event_results);
	mm_clear_db(&notify_results);
	return (0);
}

int
/* LINTED:mm_data maybe used in the future */
mm_notify_event_table(mm_data_t	*mm_data) {
	mm_db_t		*db = &notify_db;
	int		rc;

	rc = notify_etable(ETABLE_STATUS);
	if (rc == 0) {
		rc = notify_etable(ETABLE_REQUEST);
	}
	if (rc == 0) {
		rc = notify_etable(ETABLE_MESSAGE);
	}
	if (rc == 0) {
		rc = notify_etable(ETABLE_CARTRIDGE);
	}
	if (rc == 0) {
		rc = notify_etable(ETABLE_VOLUME);
	}
	mms_trace(MMS_DEVP,
	    "clear event table of processed events");
	if (mm_db_exec(HERE, db, "delete from \"EVENT\" "
	    "where \"Seen\" = 't';") != MM_DB_OK) {
		mms_trace(MMS_ERR, "clear event table");
		rc = 1;
	}
	return (rc);
}

static int
notify_etable(int etable) {
	mm_db_t		*db = &notify_db;

	/* Event results */
	PGresult	 *event_results;
	int		num_events = 0;

	/* Client results */
	PGresult	 *client_results;
	int		num_clients = 0;
	int		i;

	/* Wka lookup */
	mm_wka_t	*notify_wka;
	mm_wka_t	*next_notify_wka;
	char		*cur_uuid = NULL;

	/* Event specific */
	char		*where;
	char		*what;

	switch (etable) {
	case ETABLE_STATUS:
		where = "where (\"ObjectName\" = 'LIBRARY' or "
		    "\"ObjectName\" = 'LM' or "
		    "\"ObjectName\" = 'DRIVE' or "
		    "\"ObjectName\" = 'DM')";
		what = "NotifyStatus";
		break;
	case ETABLE_REQUEST:
		where = "where (\"ObjectName\" = 'REQUEST')";
		what = "NotifyRequest";
		break;
	case ETABLE_MESSAGE:
		where = "where (\"ObjectName\" = 'MESSAGE')";
		what = "NotifyMessage";
		break;
	case ETABLE_CARTRIDGE:
		where = "where (\"ObjectName\" = 'CARTRIDGE')";
		what = "NotifyCartridge";
		break;
	case ETABLE_VOLUME:
		where = "where (\"ObjectName\" = 'VOLUME')";
		what = "NotifyVolume";
		break;
	default:
		mms_trace(MMS_ERR,
		    "unknown event table type %d", etable);
		return (1);
	}

	/* flag events we're going to process */
	if (mm_db_exec(HERE, db,
	    "update \"EVENT\" set \"Seen\" = 't' %s;",
	    where) != MM_DB_OK) {
		mms_trace(MMS_ERR,
		    "error setting event seen");
		return (1);
	}

	/* Get all the events */
	/* send_status_event is dependent */
	/* on the ordering of the */
	/* attributes in this select */
	if (mm_db_exec(HERE, db,
	    "select distinct \"ObjectName\","
	    "\"Info1\",\"Info2\",\"Info3\",\"Info4\" from "
	    "\"EVENT\" %s and (\"Seen\" = 't');",
	    where) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "error getting event data from db");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	event_results = db->mm_db_results;
	num_events = PQntuples(event_results);
	if (num_events == 0) {
		mms_trace(MMS_DEVP,
		    "No events found in event table");
		mm_clear_db(&event_results);
		return (0);
	}
	mms_trace(MMS_DEVP, "num status events %d", num_events);
	/* Get all the subscribers */
	if (mm_db_exec(HERE, db,
	    "select \"ConnectionID\" from "
	    "\"NOTIFY\" where "
	    "\"%s\" != "
	    "'off';", what) != MM_DB_DATA) {
		mm_clear_db(&event_results);
		mms_trace(MMS_ERR,
		    "error getting client data from db");
		return (1);
	}
	client_results = db->mm_db_results;
	num_clients = PQntuples(client_results);
	if (num_clients == 0) {
		mms_trace(MMS_DEVP,
		    "No clients subscribed to status events");
		mm_clear_db(&event_results);
		mm_clear_db(&client_results);
		return (0);
	}
	mms_trace(MMS_DEVP, "num subscribed clients %d", num_clients);
	/* Send the events to the subscribers */
	pthread_mutex_lock(&notify_data->mm_wka_mutex);
	for (notify_wka = mms_list_head(&notify_data->mm_wka_list);
	    notify_wka != NULL;
	    notify_wka = next_notify_wka) {
		pthread_mutex_lock(&notify_wka->wka_local_lock);

		for (i = 0; i < num_clients; i ++) {
			cur_uuid = PQgetvalue(client_results, i, 0);
			if (strcmp(notify_wka->wka_conn.cci_uuid,
			    cur_uuid) == 0) {
				/* This client needs the events */
				mm_notify_send_status(notify_wka,
				    event_results);
			}
		}
		next_notify_wka = mms_list_next(&notify_data->mm_wka_list,
		    notify_wka);
		pthread_mutex_unlock(&notify_wka->wka_local_lock);
	}
	pthread_mutex_unlock(&notify_data->mm_wka_mutex);
	mm_clear_db(&event_results);
	mm_clear_db(&client_results);
	return (0);
}



int
mm_notify_add_driveonline(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *drivename) {
	notify_cmd_t	*event = NULL;

	if (drivename == NULL) {
		mms_trace(MMS_ERR,
		    "drivename cannot be NULL, "
		    "mm_notify_add_driveonline");
		return (1);
	}

	if ((event = mm_notify_add("event driveonline[\"%s\"];",
	    drivename)) == NULL) {
		mms_trace(MMS_ERR, "Error adding notify event");
		return (1);
	} else {
		mms_trace(MMS_DEBUG, "Added notify event event");
		notify_set_cli_uuid(event,
		    mm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    mm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    mm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "DRIVE");
		notify_set_evt_obj_instance(event, drivename);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
	}
	return (0);
}

int
mm_notify_add_driveoffline(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *drivename) {
	notify_cmd_t	*event = NULL;

	if (drivename == NULL) {
		mms_trace(MMS_ERR,
		    "drivename cannot be NULL, "
		    "mm_notify_add_driveoffline");
		return (1);
	}

	if ((event = mm_notify_add("event driveoffline[\"%s\"];",
	    drivename)) == NULL) {
		mms_trace(MMS_ERR, "Error adding notify event");
		return (1);
	} else {
		mms_trace(MMS_DEBUG, "Added notify event event");
		notify_set_cli_uuid(event,
		    mm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    mm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    mm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "DRIVE");
		notify_set_evt_obj_instance(event, drivename);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
	}
	return (0);


}

void
mm_notify_add_dmdown(mm_wka_t *dm_wka, mm_command_t *cmd) {

	notify_cmd_t	*event = NULL;

	char		*drivename = dm_wka->wka_conn.cci_client;
	char		*dmhost = dm_wka->wka_conn.cci_host;
	char		*dmname = dm_wka->wka_conn.cci_instance;

	if ((event = mm_notify_add("event dmdown[\"%s\" \"%s\" \"%s\"];",
	    dmname,
	    drivename,
	    dmhost)) == NULL) {
		mms_trace(MMS_ERR, "Error adding notify event");
	} else {
		mms_trace(MMS_DEBUG, "Added notify event event");
		notify_set_cli_uuid(event,
		    dm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    dm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    dm_wka->wka_conn.cci_instance);

		notify_set_evt_obj_name(event, "DM");
		notify_set_evt_obj_instance(event, dmname);
		notify_set_evt_obj_host(event, dmhost);
		notify_set_evt_obj_drive(event, drivename);
		if (cmd != NULL) {
			notify_set_cmd_uuid(event, cmd->cmd_uuid);
		} else {
			event->evt_can_dispatch = 1;
		}
	}
}


int
mm_notify_add_dmdown_dc(mm_wka_t *dm_wka, mm_db_t *db) {
	/* This function is called by the main thread, not the worker */
	/* So it will need to use the main thread's db connection */

	/* If dm is in a ready state, add an event */
	if (mm_db_exec(HERE, db,
	    "select \"DMName\" from "
	    "\"DMCAPABILITYGROUP\" where "
	    "\"DMName\" = '%s';",
	    dm_wka->wka_conn.cci_instance) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error, mm_notify_add_dmdown_dc");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (PQntuples(db->mm_db_results) == 0) {
		mms_trace(MMS_ERR,
		    "rows != 1, mm_notify_add_dmdown_dc");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	mm_notify_add_dmdown(dm_wka, NULL);
	mm_clear_db(&db->mm_db_results);
	return (0);

}




void
mm_notify_add_dmup(mm_wka_t *dm_wka, mm_command_t *cmd) {
	notify_cmd_t	*event = NULL;

	char		*drivename = dm_wka->wka_conn.cci_client;
	char		*dmhost = dm_wka->wka_conn.cci_host;
	char		*dmname = dm_wka->wka_conn.cci_instance;

	/* Get DMTargetHost and DriveName */

	if ((event = mm_notify_add("event dmup[\"%s\" \"%s\" \"%s\"];",
	    dmname,
	    drivename,
	    dmhost)) == NULL) {
		mms_trace(MMS_ERR, "Error adding notify event");
	} else {
		mms_trace(MMS_DEBUG, "Added notify event event");
		notify_set_cli_uuid(event,
		    dm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    dm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    dm_wka->wka_conn.cci_instance);

		notify_set_evt_obj_name(event, "DM");
		notify_set_evt_obj_instance(event, dmname);
		notify_set_evt_obj_host(event, dmhost);
		notify_set_evt_obj_drive(event, drivename);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
	}
}

void
mm_notify_add_librarycreate(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *libraryname) {
	notify_cmd_t	*event = NULL;
	if ((event = mm_notify_add("event librarycreate[\"%s\"];",
	    libraryname)) == NULL) {
		mms_trace(MMS_ERR, "Error adding notify event");
	} else {
		mms_trace(MMS_DEBUG, "Added notify event event");
		notify_set_cli_uuid(event,
		    mm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    mm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    mm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "LIBRARY");
		notify_set_evt_obj_library(event, libraryname);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
	}
}

void
mm_notify_add_librarydelete(mm_db_t *db, mm_wka_t *mm_wka,
    mm_command_t *cmd, int match_off) {

	notify_cmd_t	*event = NULL;
	PGresult	*results;
	int		rows;
	int		row;
	char		*libraryname = NULL;
	if (mm_db_exec(HERE, db, "SELECT \"LibraryName\""
	    " FROM \"LIBRARY\" %s",
	    &cmd->cmd_buf[match_off]) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "data base error getting library name");
		return;
	}
	results = db->mm_db_results;
	rows = PQntuples(results);
	if (rows == 0) {
		mms_trace(MMS_DEVP, "Didn't match any library for delete");
		mm_clear_db(&results);
		return;
	}

	for (row = 0; row < rows; row ++) {
		event = NULL;
		libraryname = PQgetvalue(results, row, 0);

		if ((event = mm_notify_add("event librarydelete[\"%s\"];",
		    libraryname)) == NULL) {
			mms_trace(MMS_ERR, "Error adding notify event");
		} else {
			mms_trace(MMS_DEBUG, "Added librarydelete event for %s",
			    libraryname);
			notify_set_cli_uuid(event,
			    mm_wka->wka_conn.cci_uuid);
			notify_set_cli_name(event,
			    mm_wka->wka_conn.cci_client);
			notify_set_cli_instance(event,
			    mm_wka->wka_conn.cci_instance);
			notify_set_evt_obj_name(event, "LIBRARY");
			notify_set_evt_obj_library(event, libraryname);
			notify_set_cmd_uuid(event, cmd->cmd_uuid);
		}
	}
	mm_clear_db(&results);
}


void
mm_notify_add_drivedelete(mm_db_t *db, mm_wka_t *mm_wka,
    mm_command_t *cmd, int match_off) {

	notify_cmd_t	*event = NULL;
	PGresult	*results;
	int		rows;
	int		row;
	char		*drivename = NULL;
	if (mm_db_exec(HERE, db, "SELECT \"DriveName\""
	    " FROM \"DRIVE\" %s",
	    &cmd->cmd_buf[match_off]) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "data base error getting drive name");
		return;
	}
	results = db->mm_db_results;
	rows = PQntuples(results);
	if (rows == 0) {
		mms_trace(MMS_DEVP, "Didn't match any drive for delete");
		mm_clear_db(&results);
		return;
	}

	for (row = 0; row < rows; row ++) {
		event = NULL;
		drivename = PQgetvalue(results, row, 0);

		if ((event = mm_notify_add("event drivedelete[\"%s\"];",
		    drivename)) == NULL) {
			mms_trace(MMS_ERR, "Error adding notify event");
		} else {
			mms_trace(MMS_DEBUG, "Added drivedelete event for %s",
			    drivename);
			notify_set_cli_uuid(event,
			    mm_wka->wka_conn.cci_uuid);
			notify_set_cli_name(event,
			    mm_wka->wka_conn.cci_client);
			notify_set_cli_instance(event,
			    mm_wka->wka_conn.cci_instance);
			notify_set_evt_obj_name(event, "DRIVE");
			notify_set_cmd_uuid(event, cmd->cmd_uuid);
		}
	}
	mm_clear_db(&results);
}


void
mm_notify_add_newcartridge(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *cartridgepcl,
    char *libraryname) {
	notify_cmd_t	*event = NULL;
	if ((event = mm_notify_add("event newcartridge[\"%s\" \"%s\"];",
	    cartridgepcl,
	    libraryname)) == NULL) {
		mms_trace(MMS_ERR, "Error adding notify event");
	} else {
		mms_trace(MMS_DEBUG, "Added notify event event");
		notify_set_cli_uuid(event,
		    mm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    mm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    mm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "CARTRIDGE");
		notify_set_evt_obj_instance(event, cartridgepcl);
		notify_set_evt_obj_library(event, libraryname);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
	}
}

void
mm_notify_add_newdrive(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *drivename, char *libraryname) {
	notify_cmd_t	*event = NULL;
	if ((event = mm_notify_add("event newdrive[\"%s\" \"%s\"];",
	    drivename,
	    libraryname)) == NULL) {
		mms_trace(MMS_ERR, "Error adding newdrive event");
	} else {
		mms_trace(MMS_DEBUG, "Added newdrive event");
		notify_set_cli_uuid(event,
		    mm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    mm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    mm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "DRIVE");
		notify_set_evt_obj_instance(event, drivename);
		notify_set_evt_obj_library(event, libraryname);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
	}
}

int
mm_notify_add_volumedelete(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *cartid, mm_db_t *db) {

	notify_cmd_t	*event = NULL;


	if (cartid == NULL) {
		mms_trace(MMS_ERR,
		    "cannot have null cartid"
		    ", mm_notify_add_volumedelete");
		return (1);
	}

	/* First find this cartridge type */

	if (mm_db_exec(HERE, db,
	    "select "
	    "\"CARTRIDGE\".\"CartridgeTypeName\","
	    "\"VOLUME\".\"VolumeName\" from "
	    "\"CARTRIDGE\",\"VOLUME\" where "
	    "\"VOLUME\".\"CartridgeID\" ="
	    "\"CARTRIDGE\".\"CartridgeID\" and "
	    "\"VOLUME\".\"CartridgeID\" = '%s';",
	    cartid) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR,
		    "db error getting cartridge "
		    "type for %s, volumedelete event",
		    cartid);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {

		mms_trace(MMS_ERR,
		    "db error getting cartridge type, "
		    "%d rows returned, volumedelete event",
		    PQntuples(db->mm_db_results));
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	if ((event = mm_notify_add("event "
	    "volumedelete[\"%s\" \"%s\"];",
	    PQgetvalue(db->mm_db_results, 0, 1),
	    PQgetvalue(db->mm_db_results, 0, 0))) == NULL) {
		mms_trace(MMS_ERR, "Error adding volumedelete event");
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {

		mms_trace(MMS_DEBUG, "Added volumedelete event event");
		notify_set_cli_uuid(event,
		    mm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    mm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    mm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "VOLUME");
		notify_set_evt_obj_instance(event,
		    PQgetvalue(db->mm_db_results, 0, 1));
		notify_set_evt_obj_cartid(event,
		    cartid);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
		mm_clear_db(&db->mm_db_results);

	}
	return (0);

}


int
mm_notify_add_volumeeject(mm_wka_t *lm_wka, mm_command_t *cmd,
    char *pcl, mm_db_t *db) {
	notify_cmd_t	*event = NULL;

	char		*library_name = lm_wka->wka_conn.cci_client;
	char		*volname = NULL;
	char		*carttype = NULL;
	char		*cartid = NULL;
	int		num_vols = 0;
	int		i;

	if (mm_db_exec(HERE, db,
	    "select "
	    "\"CARTRIDGE\".\"CartridgeTypeName\","
	    "\"VOLUME\".\"VolumeName\", "
	    "\"CARTRIDGE\".\"CartridgeID\" "
	    "from "
	    "\"CARTRIDGE\",\"VOLUME\" "
	    "where ( "
	    "(\"VOLUME\".\"CartridgeID\" = "
	    "\"CARTRIDGE\".\"CartridgeID\") "
	    "and "
	    "(\"CARTRIDGE\".\"LibraryName\" = '%s') "
	    "and "
	    "(\"CARTRIDGE\".\"CartridgePCL\" = '%s'));",
	    library_name,
	    pcl) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR,
		    "db error getting cartridge "
		    "type for %s, volumeeject event",
		    pcl);
		return (1);
	}

	num_vols = PQntuples(db->mm_db_results);

	mms_trace(MMS_DEBUG,
	    "%d volume(s) for cart, %s %s",
	    num_vols,
	    pcl,
	    library_name);

	for (i = 0; i < num_vols; i ++) {
		carttype = PQgetvalue(db->mm_db_results, i, 0);
		volname = PQgetvalue(db->mm_db_results, i, 1);
		cartid = PQgetvalue(db->mm_db_results, i, 2);
		event = NULL;
		if ((event = mm_notify_add("event "
		    "volumeeject[\"%s\" \"%s\"];",
		    volname,
		    carttype)) == NULL) {
			mms_trace(MMS_ERR, "Error adding volumeeject event");
			mm_clear_db(&db->mm_db_results);
			return (1);
		} else {
			mms_trace(MMS_DEBUG, "Added volumeeject event event");
			notify_set_cli_uuid(event,
			    lm_wka->wka_conn.cci_uuid);
			notify_set_cli_name(event,
			    lm_wka->wka_conn.cci_client);
			notify_set_cli_instance(event,
			    lm_wka->wka_conn.cci_instance);
			notify_set_evt_obj_name(event, "VOLUME");
			notify_set_evt_obj_cartid(event,
			    cartid);
			notify_set_evt_obj_instance(event,
			    volname);
			notify_set_cmd_uuid(event, cmd->cmd_uuid);
		}
	}
	mm_clear_db(&db->mm_db_results);
	return (0);

}
int
mm_notify_add_volumeinject(mm_wka_t *lm_wka, mm_command_t *cmd,
    char *pcl, mm_db_t *db) {
	notify_cmd_t	*event = NULL;

	char		*library_name = lm_wka->wka_conn.cci_client;
	char		*volname = NULL;
	char		*carttype = NULL;
	char		*cartid = NULL;
	int		num_vols = 0;
	int		i;

	if (mm_db_exec(HERE, db,
	    "select "
	    "\"CARTRIDGE\".\"CartridgeTypeName\","
	    "\"VOLUME\".\"VolumeName\", "
	    "\"CARTRIDGE\".\"CartridgeID\" "
	    "from "
	    "\"CARTRIDGE\",\"VOLUME\" "
	    "where ( "
	    "(\"VOLUME\".\"CartridgeID\" = "
	    "\"CARTRIDGE\".\"CartridgeID\") "
	    "and "
	    "(\"CARTRIDGE\".\"LibraryName\" = '%s') "
	    "and "
	    "(\"CARTRIDGE\".\"CartridgePCL\" = '%s'));",
	    library_name,
	    pcl) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR,
		    "db error getting cartridge "
		    "type for %s, volumeinject event",
		    pcl);
		return (1);
	}

	num_vols = PQntuples(db->mm_db_results);

	mms_trace(MMS_DEBUG,
	    "%d volume(s) for cart, %s %s",
	    num_vols,
	    pcl,
	    library_name);

	for (i = 0; i < num_vols; i ++) {
		carttype = PQgetvalue(db->mm_db_results, i, 0);
		volname = PQgetvalue(db->mm_db_results, i, 1);
		cartid = PQgetvalue(db->mm_db_results, i, 2);
		event = NULL;
		if ((event = mm_notify_add("event "
		    "volumeinject[\"%s\" \"%s\"];",
		    volname,
		    carttype)) == NULL) {
			mms_trace(MMS_ERR, "Error adding volumeinject event");
			mm_clear_db(&db->mm_db_results);
			return (1);
		} else {
			mms_trace(MMS_DEBUG, "Added volumeinject event event");
			notify_set_cli_uuid(event,
			    lm_wka->wka_conn.cci_uuid);
			notify_set_cli_name(event,
			    lm_wka->wka_conn.cci_client);
			notify_set_cli_instance(event,
			    lm_wka->wka_conn.cci_instance);
			notify_set_evt_obj_name(event, "VOLUME");
			notify_set_evt_obj_cartid(event,
			    cartid);
			notify_set_evt_obj_instance(event,
			    volname);
			notify_set_cmd_uuid(event, cmd->cmd_uuid);
		}
	}

	mm_clear_db(&db->mm_db_results);
	return (0);

}




int
mm_notify_add_volumeadd(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *volumename, char *cartid, mm_db_t *db) {

	notify_cmd_t	*event = NULL;

	if (volumename == NULL) {
		mms_trace(MMS_ERR,
		    "cannot have null volumename"
		    ", mm_notify_add_volumeadd");
		return (1);
	}
	if (cartid == NULL) {
		mms_trace(MMS_ERR,
		    "cannot have null cartid"
		    ", mm_notify_add_volumeadd");
		return (1);
	}

	/* First find this cartridge type */

	if (mm_db_exec(HERE, db,
	    "select "
	    "\"CARTRIDGE\".\"CartridgeTypeName\" "
	    "from \"CARTRIDGE\" "
	    "where "
	    "\"CARTRIDGE\".\"CartridgeID\" = '%s';",
	    cartid) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR,
		    "db error getting cartridge "
		    "type for %s, volumeadd event",
		    volumename);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {

		mms_trace(MMS_ERR,
		    "db error getting cartridge type, "
		    "%d rows returned, volumeadd event",
		    PQntuples(db->mm_db_results));
		mm_clear_db(&db->mm_db_results);
		return (1);
	}

	if ((event = mm_notify_add("event "
	    "volumeadd[\"%s\" \"%s\"];",
	    volumename,
	    PQgetvalue(db->mm_db_results, 0, 0))) == NULL) {
		mms_trace(MMS_ERR, "Error adding volumeadd event");
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_DEBUG, "Added volumeadd event event");
		notify_set_cli_uuid(event,
		    mm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    mm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    mm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "VOLUME");
		notify_set_evt_obj_instance(event,
		    volumename);
		notify_set_evt_obj_cartid(event,
		    cartid);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);

	}
	return (0);

}

int
mm_notify_add_lmup(mm_wka_t *lm_wka, mm_command_t *cmd) {
	/* This adds an lmready event to the event queue */
	/* lm_wka should be the wka of the lm who is ready */

	/* Library Ready event */
	notify_cmd_t	*event = NULL;
	if ((event = mm_notify_add("event "
	    "lmup[\"%s\" \"%s\"];",
	    lm_wka->wka_conn.cci_instance,
	    lm_wka->wka_conn.cci_client)) == NULL) {
		mms_trace(MMS_ERR, "Error adding lmready event");
		return (1);
	} else {
		mms_trace(MMS_DEBUG, "Added lmup event event");
		notify_set_cli_uuid(event,
		    lm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    lm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    lm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "LM");
		notify_set_evt_obj_instance(event,
		    lm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_library(event,
		    lm_wka->wka_conn.cci_client);
		notify_set_cmd_uuid(event, cmd->cmd_uuid);
	}
	return (0);
}
int
mm_notify_add_lmdown_dc(mm_wka_t *lm_wka, mm_db_t *db) {
	/* This function is called by the main thread, not the worker */
	/* So it will need to use the main thread's db connection */

	/* If lm is in a ready state, add an event */
	if (mm_db_exec(HERE, db,
	    "select \"LMStateSoft\" "
	    "from \"LM\" where "
	    "\"LMName\" = '%s';",
	    lm_wka->wka_conn.cci_instance) != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error, mm_notify_add_lmdown_dc");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR,
		    "rows != 1, mm_notify_add_lmdown_dc");
		mm_clear_db(&db->mm_db_results);
		return (1);
	}
	if (strcmp(PQgetvalue(db->mm_db_results, 0, 0),
	    "ready") == 0) {
		mms_trace(MMS_DEBUG,
		    "lm dissconnected in ready state, add event");
		if (mm_notify_add_lmdown(lm_wka, NULL)) {
			mms_trace(MMS_ERR,
			    "mm_notify_add_lmdown_dc: "
			    "error adding lm down event");
		}
	}
	mm_clear_db(&db->mm_db_results);
	return (0);

}

int
mm_notify_add_lmdown(mm_wka_t *lm_wka, mm_command_t *cmd) {
	/* This adds an lmready event to the event queue */
	/* lm_wka should be the wka of the lm who is ready */

	/* Library Ready event */
	notify_cmd_t	*event = NULL;
	if ((event = mm_notify_add("event "
	    "lmdown[\"%s\" \"%s\"];",
	    lm_wka->wka_conn.cci_instance,
	    lm_wka->wka_conn.cci_client)) == NULL) {
		mms_trace(MMS_ERR, "Error adding lmready event");
		return (1);
	} else {
		mms_trace(MMS_DEBUG, "Added lmup event event");
		notify_set_cli_uuid(event,
		    lm_wka->wka_conn.cci_uuid);
		notify_set_cli_name(event,
		    lm_wka->wka_conn.cci_client);
		notify_set_cli_instance(event,
		    lm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_name(event, "LM");
		notify_set_evt_obj_instance(event,
		    lm_wka->wka_conn.cci_instance);
		notify_set_evt_obj_library(event,
		    lm_wka->wka_conn.cci_client);
		if (cmd != NULL) {
			notify_set_cmd_uuid(event, cmd->cmd_uuid);
		} else {
			event->evt_can_dispatch = 1;
		}
	}
	return (0);

}


int
mm_notify_add_config(mm_wka_t *mm_wka, mm_command_t *cmd,
    char *type, char *name, char *instance,
    char *host) {
	notify_cmd_t	*event = NULL;

	if (strcmp(type, "change") == 0) {
		if ((event = mm_notify_add(NOTIFY_EVENT_CFG_CHG,
		    name,
		    instance,
		    instance)) == NULL) {
			mms_trace(MMS_ERR, "Error adding config event");
			return (1);
		}
	} else {
		if ((event = mm_notify_add(NOTIFY_EVENT_CFG, name,
		    type, instance)) == NULL) {
			mms_trace(MMS_ERR, "Error adding config event");
			return (1);
		}
	}
	mms_trace(MMS_DEBUG, "Added config event");
	notify_set_cli_uuid(event,
	    mm_wka->wka_conn.cci_uuid);
	notify_set_cli_name(event,
	    mm_wka->wka_conn.cci_client);
	notify_set_cli_instance(event,
	    mm_wka->wka_conn.cci_instance);
	notify_set_evt_obj_name(event, name);
	notify_set_evt_obj_instance(event, instance);
	notify_set_evt_obj_host(event, host);
	notify_set_cmd_uuid(event, cmd->cmd_uuid);

	return (0);
}


/* Add event to pending event list for client. */
notify_cmd_t *
mm_notify_add(char *event_fmt, ...)
{
	va_list		 args;

	notify_cmd_t	*event = NULL;


	mms_trace(MMS_DEVP, "mm_notify_add");

	if ((event = (notify_cmd_t *)calloc(1,
	    sizeof (notify_cmd_t))) == NULL) {
		return (NULL);
	}

	va_start(args, event_fmt);
	event->evt_cmd = mms_vstrapp(NULL, event_fmt, args);
	va_end(args);
	if (event->evt_cmd == NULL) {
		free(event);
		return (NULL);
	}
	event->evt_can_dispatch = 0;
	event->evt_cli_name = NULL;
	event->evt_cli_instance = NULL;
	event->evt_obj_name = NULL;
	event->evt_obj_host = NULL;
	event->evt_obj_library = NULL;
	event->evt_obj_cartid = NULL;
	event->evt_obj_drive = NULL;
	event->evt_obj_app = NULL;
	event->evt_obj_appinst = NULL;

	mms_trace(MMS_DEBUG,
	    "Added event, %s",
	    event->evt_cmd);
	pthread_mutex_lock(&notify_lock);
	mms_list_insert_tail(&notify_list, event);
	pthread_mutex_unlock(&notify_lock);

	return (event);
}

void
mm_notify_destroy(notify_cmd_t *event) {
	/* clean up the event */
	if (event->evt_cmd != NULL)
		free(event->evt_cmd);
	if (event->evt_cli_name != NULL)
		free(event->evt_cli_name);
	if (event->evt_obj_name != NULL)
		free(event->evt_obj_name);
	if (event->evt_obj_instance != NULL)
		free(event->evt_obj_instance);
	if (event->evt_obj_host != NULL)
		free(event->evt_obj_host);
	if (event->evt_obj_library != NULL)
		free(event->evt_obj_library);
	if (event->evt_obj_cartid != NULL)
		free(event->evt_obj_cartid);
	if (event->evt_obj_drive != NULL)
		free(event->evt_obj_drive);
	if (event->evt_obj_app != NULL)
		free(event->evt_obj_app);
	if (event->evt_obj_appinst != NULL)
		free(event->evt_obj_appinst);
	if (event->evt_cli_instance != NULL)
		free(event->evt_cli_instance);
	free(event);
}



/* Command or action was successful, send client events. */

void
mm_notify_commit(char *cmd_uuid) {
	notify_cmd_t	*event;

	mms_trace(MMS_DEVP,
	    "mm_notify_commit");


	pthread_mutex_lock(&notify_lock);
	mms_list_foreach(&notify_list, event) {
		if (strcmp(event->evt_cmd_uuid, cmd_uuid) == 0) {
			mms_trace(MMS_DEVP,
			    "commit event %s",
			    event->evt_cmd);
			event->evt_can_dispatch = 1;
		}

	}
	pthread_mutex_unlock(&notify_lock);
}




void
mm_notify_rollback(char *cmd_uuid) {
	notify_cmd_t	*event;
	notify_cmd_t	*next_event;

	mms_trace(MMS_DEVP,
	    "mm_notify_rollback");
	pthread_mutex_lock(&notify_lock);
	for (event = mms_list_head(&notify_list);
	    event != NULL;
	    event = next_event) {
		next_event = mms_list_next(&notify_list, event);
		if (strcmp(event->evt_cmd_uuid, cmd_uuid) == 0) {
			mms_list_remove(&notify_list, event);

			mms_trace(MMS_DEVP, "remove event, %s",
			    event->evt_cmd);
			mm_notify_destroy(event);
		}
	}
	pthread_mutex_unlock(&notify_lock);
}



/* Send event now. */
int
mm_notify_now(char *cli_uuid, char *event_fmt, ...)
{
	va_list		 args;
	notify_cmd_t	*event;

	mms_trace(MMS_DEVP, "mm_notify_now");

	if ((event = (notify_cmd_t *)calloc(1,
	    sizeof (notify_cmd_t))) == NULL) {
		return (1);
	}

	va_start(args, event_fmt);
	event->evt_cmd = mms_vstrapp(NULL, event_fmt, args);
	va_end(args);
	if (event->evt_cmd == NULL) {
		free(event);
		return (1);
	}
	if (cli_uuid) {
		/* not mm event */
		strncpy(event->evt_cli_uuid, cli_uuid, UUID_PRINTF_SIZE);
		/* Find session, application and instance for this client */
	}

	event->evt_can_dispatch = 1;
	mms_trace(MMS_DEVP,
	    "adding event for immediate dispatch, %s",
	    event->evt_cmd);
	pthread_mutex_lock(&notify_lock);
	mms_list_insert_tail(&notify_list, event);
	pthread_mutex_unlock(&notify_lock);
	return (0);
}

int
notify_send(notify_cmd_t *event)
{
	notify_t	 notify;
	int		 rows;
	mm_wka_t	*notify_wka;
	mm_wka_t	*next_notify_wka;
	int		 print_message = 0;
	mm_db_t		*db = &notify_db;

	char		*cli_name = event->evt_cli_name;
	char		*cli_instance = event->evt_cli_instance;
	char		*obj_name = event->evt_obj_name;
	char		*obj_instance = event->evt_obj_instance;
	char		*obj_host = event->evt_obj_host;
	char		*obj_library = event->evt_obj_library;
	char		*obj_cartid = event->evt_obj_cartid;
	char		*obj_drive = event->evt_obj_drive;
	PGresult	*results;

	mms_trace(MMS_DEBUG,
	    "notify_send");
	mms_trace(MMS_DEBUG,
	    "send event %s",
	    event->evt_cmd);
	if (cli_name)
		mms_trace(MMS_DEBUG,
		    "    client name, %s",
		    cli_name);
	if (cli_instance)
		mms_trace(MMS_DEBUG,
		    "    client instance, %s",
		    cli_instance);
	if (obj_name)
		mms_trace(MMS_DEBUG,
		    "    object name, %s",
		    obj_name);
	if (obj_instance)
		mms_trace(MMS_DEBUG,
		    "    object instance, %s",
		    obj_instance);
	if (obj_host)
		mms_trace(MMS_DEBUG,
		    "    object host, %s",
		    obj_host);
	if (obj_library)
		mms_trace(MMS_DEBUG,
		    "    object library, %s",
		    obj_library);
	if (obj_cartid)
		mms_trace(MMS_DEBUG,
		    "    object cartid, %s",
		    obj_cartid);
	if (obj_drive)
		mms_trace(MMS_DEBUG,
		    "    object drive, %s",
		    obj_drive);

	/*
	 * Send event to mm subsribers.
	 */

	pthread_mutex_lock(&notify_data->mm_wka_mutex);
	for (notify_wka = mms_list_head(&notify_data->mm_wka_list);
	    notify_wka != NULL;
	    notify_wka = next_notify_wka) {

		pthread_mutex_lock(&notify_wka->wka_local_lock);

		if (print_message)
			mms_trace(MMS_INFO, "examining a client, %s",
			    notify_wka->wka_conn.cci_uuid);

		if (mm_db_exec(HERE, db, "SELECT \"ConnectionID\","
		    "\"ConnectionClientName\","
		    "\"ConnectionClientInstance\","
		    "\"NotifyConfigChange\","
		    "\"NotifyNewDrive\", "
		    "\"NotifyNewCartridge\", "
		    "\"NotifyVolumeAdd\", "
		    "\"NotifyVolumeDelete\", "
		    "\"NotifyDMUp\", "
		    "\"NotifyDMDown\", "
		    "\"NotifyDriveOnline\", "
		    "\"NotifyDriveOffline\", "
		    "\"NotifyLMUp\", "
		    "\"NotifyLMDown\", "
		    "\"NotifyVolumeInject\", "
		    "\"NotifyVolumeEject\", "
		    "\"NotifyLibraryCreate\", "
		    "\"NotifyLibraryDelete\", "
		    "\"NotifyDriveDelete\" "
		    "FROM \"NOTIFY\""
		    "where \"ConnectionID\" = '%s';",
		    notify_wka->wka_conn.cci_uuid) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			mms_trace(MMS_DEBUG, "notify db select failed");
			return (1);
		}
		rows = PQntuples(db->mm_db_results);
		results = db->mm_db_results;
		if (rows != 0) {
			mms_trace(MMS_DEVP,
			    "notify a client");
			/* NOTIFY entry for this connection */
			/* Set up the notify struct */
			notify_results(results, 0, &notify);
			/* Notify the client */
			notify_client(notify_wka, &notify,
			    event);
		} else {
			mms_trace(MMS_DEVP,
			    "client has no notification settings");
		}
		next_notify_wka = mms_list_next(&notify_data->mm_wka_list,
		    notify_wka);
		pthread_mutex_unlock(&notify_wka->wka_local_lock);
		mm_clear_db(&results);
	}
	pthread_mutex_unlock(&notify_data->mm_wka_mutex);
	return (0);
}

static void
notify_results(PGresult *results, int row, notify_t *notify)
{
	notify->n_uuid = PQgetvalue(results, row, 0);
	notify->n_client = PQgetvalue(results, row, 1);
	notify->n_inst = PQgetvalue(results, row, 2);
	notify->n_cfgchg = PQgetvalue(results, row, 3);
	notify->n_newdrive = PQgetvalue(results, row, 4);
	notify->n_newcartridge = PQgetvalue(results, row, 5);
	notify->n_volumeadd = PQgetvalue(results, row, 6);
	notify->n_volumedelete = PQgetvalue(results, row, 7);
	notify->n_dmup = PQgetvalue(results, row, 8);
	notify->n_dmdown = PQgetvalue(results, row, 9);
	notify->n_driveonline = PQgetvalue(results, row, 10);
	notify->n_driveoffline = PQgetvalue(results, row, 11);
	notify->n_lmup = PQgetvalue(results, row, 12);
	notify->n_lmdown = PQgetvalue(results, row, 13);
	notify->n_volumeinject = PQgetvalue(results, row, 14);
	notify->n_volumeeject = PQgetvalue(results, row, 15);
	notify->n_librarycreate = PQgetvalue(results, row, 16);
	notify->n_librarydelete = PQgetvalue(results, row, 17);
	notify->n_drivedelete = PQgetvalue(results, row, 18);
}


int
notify_return_scope(char *scope) {
	if (scope == NULL) {
		mms_trace(MMS_ERR, "notify_return_scope "
		    "passed a NULL scope");
		return (NOTIFY_OFF);
	}
	if (strcmp(scope, "off") == 0) {
		mms_trace(MMS_DEVP, "    off scope");
		return (NOTIFY_OFF);
	} else if (strcmp(scope, "global") == 0) {
		mms_trace(MMS_DEVP, "    global scope");
		return (NOTIFY_GLOBAL);
	} else if (strcmp(scope, "application") == 0) {
		mms_trace(MMS_DEVP, "    application scope");
		return (NOTIFY_APPLICATION);
	} else if (strcmp(scope, "instance") == 0) {
		mms_trace(MMS_DEVP, "    instance scope");
		return (NOTIFY_INSTANCE);
	} else if (strcmp(scope, "session") == 0) {
		mms_trace(MMS_DEVP, "    session scope");
		return (NOTIFY_SESSION);
	} else if (strcmp(scope, "host") == 0) {
		mms_trace(MMS_DEVP, "    host scope");
		return (NOTIFY_HOST);
	} else {
		mms_trace(MMS_ERR, "notify_return_scope "
		    "passed an unknown scope, %s",
		    scope);
		return (NOTIFY_OFF);
	}
}
int
/* LINTED: notify may be needed in the future */
notify_check_session_event(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	char		*event_text = event_cmd->evt_cmd;

	mms_trace(MMS_DEBUG,
	    "notify_check_session_event");

	mms_trace(MMS_DEVP,
	    "%s",
	    event_text);

	/* Use this check for any event of this type */

	/* Allowed scope values for a session event */
	/* Global- all */
	/* Application- application == client app */
	/* Instance- app and inst == client app, inst */
	/* Session- session id == client session */


	/* Client does not have this event 'off' */
	/* Check scope */
	if (event_scope == NOTIFY_GLOBAL) {
		mms_trace(MMS_DEVP, "    global scope");
	} else if ((event_scope == NOTIFY_APPLICATION) &&
	    (event_cmd->evt_cli_name != NULL)) {
		mms_trace(MMS_DEVP, "    application scope");
		mms_trace(MMS_DEVP, "        event app is %s, "
		    "client app is %s",
		    event_cmd->evt_cli_name,
		    conn->cci_client);
		if (strcmp(event_cmd->evt_cli_name,
		    conn->cci_client) == 0) {
			/* App name matches */
			mms_trace(MMS_DEVP, "App name matches");
		} else {
			mms_trace(MMS_DEVP, "    skip event");
			return (0);
		}
	} else if ((event_scope == NOTIFY_INSTANCE) &&
	    (event_cmd->evt_cli_name != NULL) &&
	    (event_cmd->evt_cli_instance != NULL)) {
		mms_trace(MMS_DEVP, "    instance scope");
		mms_trace(MMS_DEVP, "        event app is %s %s, "
		    "client app is %s %s",
		    event_cmd->evt_cli_name,
		    event_cmd->evt_cli_instance,
		    conn->cci_client,
		    conn->cci_instance);
		if ((strcmp(event_cmd->evt_cli_name,
		    conn->cci_client) == 0) &&
		    (strcmp(event_cmd->evt_cli_instance,
		    conn->cci_instance) == 0)) {
			/* App and instance match */
			mms_trace(MMS_DEVP, "App and instance match");
		} else {
			mms_trace(MMS_DEVP, "    skip event");
			return (0);
		}


	} else if ((event_scope == NOTIFY_SESSION) &&
	    (event_cmd->evt_session_uuid != NULL)) {
		mms_trace(MMS_DEVP, "    session scope");
		mms_trace(MMS_DEVP,
		    "        event session is %s, ",
		    event_cmd->evt_session_uuid);
		mms_trace(MMS_DEVP,
		    "        client session is %s",
		    mm_wka->session_uuid);
		if (strcmp(event_cmd->evt_session_uuid,
		    mm_wka->session_uuid) != 0) {
			/* Session ID does not match */
			mms_trace(MMS_DEVP, "    skip event");
			return (0);
		}
		/* Session ID matches */
	} else {
		mms_trace(MMS_ERR,
		    "Passed an unsupported event "
		    "scope for this event type");
		mms_trace(MMS_DEVP, "    skip event");
		return (0);
	}


	return (1);


}


int
/* LINTED: notify may be needed in the future */
notify_check_dmup(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	mm_db_t		*db = &notify_db;

	char		*dmhost = event_cmd->evt_obj_host;

	/* Event has global and host scope */
	if (event_scope == NOTIFY_GLOBAL) {
		return (1);
	} else if (event_scope == NOTIFY_HOST) {
		/* Confirm hosts are the same */

		if (mm_db_exec(HERE, db,
		    "select * from "
		    "pg_host_ident('%s') "
		    "where pg_host_ident('%s') = "
		    "pg_host_ident('%s');",
		    dmhost,
		    dmhost,
		    conn->cci_host) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error, notify_check_dmup");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "client host != dm host");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		mm_clear_db(&db->mm_db_results);
		return (1);

	} else {
		mms_trace(MMS_ERR,
		    "unknown scope for dmup event");
		return (0);
	}
}
int
/* LINTED: notify may be needed in the future */
notify_check_dmdown(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	mm_db_t		*db = &notify_db;

	char		*dmhost = event_cmd->evt_obj_host;

	/* Event has global and host scope */
	if (event_scope == NOTIFY_GLOBAL) {
		return (1);
	} else if (event_scope == NOTIFY_HOST) {
		/* Confirm hosts are the same */

		if (mm_db_exec(HERE, db,
		    "select * from "
		    "pg_host_ident('%s') "
		    "where pg_host_ident('%s') = "
		    "pg_host_ident('%s');",
		    dmhost,
		    dmhost,
		    conn->cci_host) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error, notify_check_dmup");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "client host != dm host");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		mm_clear_db(&db->mm_db_results);
		return (1);

	} else {
		mms_trace(MMS_ERR,
		    "unknown scope for dmup event");
		return (0);
	}
}

int
/* LINTED: notify may be needed in the future */
notify_check_driveonline(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	mm_db_t		*db = &notify_db;

	char		*drivename = event_cmd->evt_obj_instance;

	/* driveonline event */
	/* global -all */
	/* application - client has DRIVEGROUP access */
	if (event_scope == NOTIFY_GLOBAL) {
		return (1);
	} else if (event_scope == NOTIFY_APPLICATION) {
		/* Check this client and drive group */
		if (mm_db_exec(HERE, db,
		    "select distinct \"DRIVE\".* from \"DRIVE\" "
		    "cross join \"DRIVEGROUPAPPLICATION\" "
		    "where "
		    "(\"DRIVE\".\"DriveGroupName\" = "
		    "\"DRIVEGROUPAPPLICATION\".\"DriveGroupName\") "
		    "and "
		    "(\"DRIVE\".\"DriveName\" = '%s') AND "
		    "(\"DRIVEGROUPAPPLICATION\"."
		    "\"ApplicationName\" = '%s');",
		    drivename,
		    conn->cci_client) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error, notify_check_driveonline");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "client does not have drive access");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		mms_trace(MMS_ERR,
		    "unknown scope for driveonline event");
		return (0);
	}
}

int
/* LINTED: notify may be needed in the future */
notify_check_driveoffline(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	mm_db_t		*db = &notify_db;
	char		*drivename = event_cmd->evt_obj_instance;

	/* driveoffline event */
	/* global -all */
	/* application - client has DRIVEGROUP access */
	if (event_scope == NOTIFY_GLOBAL) {
		return (1);
	} else if (event_scope == NOTIFY_APPLICATION) {
		/* Check this client and drive group */
		if (mm_db_exec(HERE, db,
		    "select distinct \"DRIVE\".* from \"DRIVE\" "
		    "cross join \"DRIVEGROUPAPPLICATION\" "
		    "where "
		    "(\"DRIVE\".\"DriveGroupName\" = "
		    "\"DRIVEGROUPAPPLICATION\".\"DriveGroupName\") "
		    "and "
		    "(\"DRIVE\".\"DriveName\" = '%s') AND "
		    "(\"DRIVEGROUPAPPLICATION\"."
		    "\"ApplicationName\" = '%s');",
		    drivename,
		    conn->cci_client) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error, notify_check_driveoffline");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "client does not have drive access");
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		mms_trace(MMS_ERR,
		    "unknown scope for driveoffline event");
		return (0);
	}
}


int
/* LINTED: notify may be needed in the future */
notify_check_volumeevent(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	char		*event_text = event_cmd->evt_cmd;


	mm_db_t		*db = &notify_db;

	char		*volumename = event_cmd->evt_obj_instance;
	char		*cartid = event_cmd->evt_obj_cartid;

	int		app_ok = 0;
	int		instance_ok = 0;
	mms_trace(MMS_DEBUG,
	    "notify_check_volumeevent");

	mms_trace(MMS_DEVP,
	    "%s",
	    event_text);

	/* Allowed scope values for SIA volume event */
	/* Global - all */
	/* Application - VOLUME.AppName = cci_client */
	/* Instance - VOLUME.AIName = cci_instance */
	if (event_scope == NOTIFY_GLOBAL) {
		mms_trace(MMS_DEVP, "    global scope");
	} else if ((event_scope == NOTIFY_APPLICATION) ||
	    (event_scope == NOTIFY_INSTANCE)) {
		mms_trace(MMS_DEVP, "    application or instance scope");
		/* This volume's application should match the clients app */

		if (mm_db_exec(HERE, db,
		    "select "
		    "\"VOLUME\".\"ApplicationName\", "
		    "\"VOLUME\".\"AIName\" "
		    "from \"VOLUME\" where "
		    "\"CartridgeID\" = '%s'",
		    cartid) != MM_DB_DATA) {
			mms_trace(MMS_ERR,
			    "db error getting app name for %s, "
			    "notify_check_volumeevent",
			    volumename);
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		if (PQntuples(db->mm_db_results) != 1) {
			mms_trace(MMS_ERR,
			    "db returned %d rows != 1 "
			    "notify_check_volumeevent",
			    PQntuples(db->mm_db_results));
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		/* compare the apps */
		if (strcmp(conn->cci_client,
		    PQgetvalue(db->mm_db_results, 0, 0)) == 0) {
			mms_trace(MMS_DEVP,
			    "app name matches");
			app_ok = 1;
		} else {
			mms_trace(MMS_DEVP,
			    "app name does not match");
		}
		/* compare the instance */
		if (strcmp(conn->cci_instance,
		    PQgetvalue(db->mm_db_results, 0, 1)) == 0) {
			mms_trace(MMS_DEVP,
			    "instance matches");
			instance_ok = 1;
		} else {
			mms_trace(MMS_DEVP,
			    "instance does not match");
		}
		mm_clear_db(&db->mm_db_results);
	} else {
		mms_trace(MMS_ERR,
		    "Passed an unsupported event "
		    "scope for volumeevent");
		mms_trace(MMS_DEVP, "    skip event");
		return (0);
	}
	if (event_scope == NOTIFY_APPLICATION) {
		if (app_ok) {
			return (1);
		} else {
			return (0);
		}
	}
	if (event_scope == NOTIFY_INSTANCE) {
		if (app_ok && instance_ok) {
			return (1);
		} else {
			return (0);
		}
	}
	return (1);
}



int
/* LINTED: notify may be needed in the future */
notify_check_lmup(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	char		*event_text = event_cmd->evt_cmd;

	/* Allowed scope for lmready */
	/* Global- all */

	mms_trace(MMS_DEBUG,
	    "notify_check_lmup");
	mms_trace(MMS_DEVP,
	    "%s",
	    event_text);
	if (event_scope == NOTIFY_GLOBAL) {
		/* Global is the only scope currently implemeneted, */
		return (1);
	} else {
		mms_trace(MMS_ERR,
		    "unknown scope, notify_check_lmup");
		return (0);
	}
}
int
/* LINTED: notify may be needed in the future */
notify_check_lmdown(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {
	char		*event_text = event_cmd->evt_cmd;

	/* Allowed scope for lmready */
	/* Global- all */

	mms_trace(MMS_DEBUG,
	    "notify_check_lmdown");
	mms_trace(MMS_DEVP,
	    "%s",
	    event_text);
	/* Global is the only scope currently implemeneted, */
	if (event_scope == NOTIFY_GLOBAL) {
		/* Global is the only scope currently implemeneted, */
		return (1);
	} else {
		mms_trace(MMS_ERR,
		    "unknown scope, notify_check_lmdown");
		return (0);
	}
}


int
/* LINTED: notify may be needed in the future */
notify_check_newdrive(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	char		*event_text = event_cmd->evt_cmd;

	char		*db_buf = NULL;
	mm_db_t		*db = &notify_db;

	char		*drivename = event_cmd->evt_obj_instance;
	char		*libraryname = event_cmd->evt_obj_library;

	mms_trace(MMS_DEBUG,
	    "notify_check_newdrive");

	mms_trace(MMS_DEVP,
	    "%s",
	    event_text);

	if ((drivename == NULL) || (libraryname == NULL)) {
		mms_trace(MMS_ERR,
		    "bad drivename or libraryname in event struct");
		return (0);
	}

	/* Allowed scope values for a config change event */
	/* Global- all */
	/* Application- client application has DRIVEGROUPAPPLICATION */
	if (event_scope == NOTIFY_GLOBAL) {
		mms_trace(MMS_DEVP, "    global scope");
	} else if (event_scope == NOTIFY_APPLICATION) {

		db_buf = mms_strapp(db_buf,
		    "select distinct "
		    "\"DRIVEGROUPAPPLICATION\".* from "
		    "\"DRIVEGROUPAPPLICATION\" "
		    "cross join \"DRIVE\" where ( "
		    "(\"DRIVEGROUPAPPLICATION\"."
		    "\"DriveGroupName\" = "
		    "\"DRIVE\".\"DriveGroupName\") "
		    "and ((\"DRIVE\".\"DriveName\" = "
		    "'%s') AND "
		    "(\"DRIVE\".\"LibraryName\" = '%s') AND "
		    "(\"DRIVEGROUPAPPLICATION\"."
		    "\"ApplicationName\" = '%s')) "
		    ");",
		    drivename,
		    libraryname,
		    conn->cci_client);
		if (mm_db_exec(HERE, db, db_buf) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			free(db_buf);
			mms_trace(MMS_ERR,
			    "error getting db info");
			return (0);
		}
		free(db_buf);
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "%s has no access to %s, skip event",
			    conn->cci_client,
			    drivename);
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		mm_clear_db(&db->mm_db_results);

	} else {
		mms_trace(MMS_ERR,
		    "Passed an unsupported event "
		    "scope for this event type");
		mms_trace(MMS_DEVP, "    skip event");
		return (0);
	}
	return (1);




}

int
/* LINTED: notify may be needed in the future */
notify_check_newcartridge(mm_wka_t *mm_wka, notify_t *notify,
    notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	char		*event_text = event_cmd->evt_cmd;

	char		*db_buf = NULL;

	mm_db_t		*db = &notify_db;
	char		*pcl = event_cmd->evt_obj_instance;
	char		*library = event_cmd->evt_obj_library;


	mms_trace(MMS_DEBUG,
	    "notify_check_newcartridge");

	mms_trace(MMS_DEVP,
	    "%s",
	    event_text);

	if ((pcl == NULL) || (library == NULL)) {
		mms_trace(MMS_ERR,
		    "bad pcl or library name in event struct");
		return (0);
	}


	/* Allowed scope values for a config change event */
	/* Global- all */
	/* Application- client application has CARTRIDGEGROUPAPPLICATION */

	if (event_scope == NOTIFY_GLOBAL) {
		mms_trace(MMS_DEVP, "    global scope");
	} else if (event_scope == NOTIFY_APPLICATION) {

		db_buf = mms_strapp(db_buf,
		    "select distinct "
		    "\"CARTRIDGEGROUPAPPLICATION\".* from "
		    "\"CARTRIDGEGROUPAPPLICATION\" "
		    "cross join \"CARTRIDGE\" where ( "
		    "(\"CARTRIDGEGROUPAPPLICATION\"."
		    "\"CartridgeGroupName\" = "
		    "\"CARTRIDGE\".\"CartridgeGroupName\") "
		    "and ((\"CARTRIDGE\".\"CartridgePCL\" = "
		    "'%s') AND "
		    "(\"CARTRIDGE\".\"LibraryName\" = '%s') AND "
		    "(\"CARTRIDGEGROUPAPPLICATION\"."
		    "\"ApplicationName\" = '%s')) "
		    ");",
		    pcl,
		    library,
		    conn->cci_client);
		if (mm_db_exec(HERE, db, db_buf) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			free(db_buf);
			mms_trace(MMS_ERR,
			    "error getting db info");
			return (0);
		}
		free(db_buf);
		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "%s has no access to %s, skip event",
			    conn->cci_client,
			    pcl);
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		mm_clear_db(&db->mm_db_results);


	} else {
		mms_trace(MMS_ERR,
		    "Passed an unsupported event "
		    "scope for this event type");
		mms_trace(MMS_DEVP, "    skip event");
		return (0);
	}
	return (1);

}

int
/* LINTED: notify may be needed in the future */
notify_check_cfgchg(mm_wka_t *mm_wka, notify_t *notify, notify_cmd_t *event_cmd,
    int event_scope) {

	cci_t		*conn = &mm_wka->wka_conn;
	char		*event_text = event_cmd->evt_cmd;

	char		*db_buf = NULL;
	mm_db_t		*db = &notify_db;

	mms_trace(MMS_DEBUG,
	    "notify_check_cfgchg");

	mms_trace(MMS_DEVP,
	    "%s",
	    event_text);

	/* Allowed scope values for a config change event */
	/* Global- all */
	/* Host- client host == DM/LM host */

	if (event_scope == NOTIFY_GLOBAL) {
		mms_trace(MMS_DEVP, "    global scope");
	} else if (event_scope == NOTIFY_HOST) {
		mms_trace(MMS_DEVP, "    host scope");
		/* Check that our event has the proper struct */
		if (event_cmd->evt_obj_name == NULL) {
			/* This would be LM or DM */
			mms_trace(MMS_ERR,
			    "bad evt_obj_name "
			    "in notify_check_cfgchg");
			return (0);
		}
		if (event_cmd->evt_obj_instance == NULL) {
			/* This is the LM/DM's name */
			mms_trace(MMS_ERR,
			    "bad evt_obj_instance "
			    "in notify_check_cfgchg");
			return (0);
		}
		if (event_cmd->evt_obj_host == NULL) {
			/* This is the LM/DM's host */
			mms_trace(MMS_ERR,
			    "bad evt_obj_host "
			    "in notify_check_cfgchg");
			return (0);
		}

		if (conn->cci_host == NULL) {
			/* Host of client we are */
			/* sending event to */
			mms_trace(MMS_ERR,
			    "bad cci_host "
			    "in notify_check_cfgchg");
			return (0);
		}


		/* For this event the LM/LM name */
		/* is stored in event client instance */
		/* Event type is in client name */
		db_buf = mms_strapp(db_buf,
		    "select * from "
		    "pg_host_ident('%s') "
		    "where pg_host_ident('%s') = "
		    "pg_host_ident('%s')",
		    conn->cci_host,
		    event_cmd->evt_obj_host,
		    conn->cci_host);

		if (mm_db_exec(HERE, db, db_buf) != MM_DB_DATA) {
			mm_clear_db(&db->mm_db_results);
			free(db_buf);
			mms_trace(MMS_ERR,
			    "error getting db info");
			return (0);
		}
		free(db_buf);

		if (PQntuples(db->mm_db_results) == 0) {
			mms_trace(MMS_DEVP,
			    "%s %s not configured of %s, skip event",
			    event_cmd->evt_obj_name,
			    event_cmd->evt_obj_instance,
			    conn->cci_host);
			mm_clear_db(&db->mm_db_results);
			return (0);
		}
		mm_clear_db(&db->mm_db_results);
	} else {
		mms_trace(MMS_ERR,
		    "Passed an unsupported event "
		    "scope for this event type");
		mms_trace(MMS_DEVP, "    skip event");
		return (0);
	}
	return (1);
}

static void
notify_client(mm_wka_t *mm_wka, notify_t *notify, notify_cmd_t *event_cmd)
{
	int		 do_notify = 0;
	mms_par_node_t	*event;
	cci_t		*conn = &mm_wka->wka_conn;
	char		*event_text = event_cmd->evt_cmd;

	int		event_scope = 0;

	mms_trace(MMS_DEVP, "notify_client %s %s",
	    conn->cci_client,
	    conn->cci_instance);


	if ((event = mm_text_to_par_node(event_text,
	    mms_mmp_parse)) == NULL) {
		if (event_text != NULL) {
			mms_trace(MMS_ERR, "cannot parse event, %s",
			    event_text);
		} else {
			mms_trace(MMS_ERR,
			    "event_text was NULL, cannot parse");
		}
		return;
	}



	/* Match the event up with this connection's notify setting */
	/* All working events must be listed here */

	if (mms_pn_lookup(event, "driveoffline", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_driveoffline)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for driveoffline event");
		if (notify_check_driveoffline(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "driveonline", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_driveonline)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for driveonline event");
		if (notify_check_driveonline(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "dmdown", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_dmdown)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for dmdown event");
		if (notify_check_dmdown(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "dmup", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_dmup)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for dmup event");
		if (notify_check_dmup(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "volumedelete", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_volumedelete)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for volumedelete event");
		if (notify_check_volumeevent(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "volumeadd", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_volumeadd)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for volumeadd event");
		if (notify_check_volumeevent(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "volumeinject", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_volumeinject)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for volumeinject event");
		if (notify_check_volumeevent(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "volumeeject", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_volumeeject)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for volumeeject event");
		if (notify_check_volumeevent(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "lmup", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_lmup)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for lmup event");
		if (notify_check_lmup(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "lmdown", MMS_PN_CLAUSE, 0) &&
	    ((event_scope =
	    notify_return_scope(notify->n_lmdown)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for lmdown event");
		if (notify_check_lmdown(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "newdrive", MMS_PN_CLAUSE, NULL) &&
	    ((event_scope =
	    notify_return_scope(notify->n_newdrive)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for newdrive event");
		if (notify_check_newdrive(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "newcartridge", MMS_PN_CLAUSE,
	    NULL) &&
	    ((event_scope =
	    notify_return_scope(notify->n_newcartridge)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for newcartridge event");
		if (notify_check_newcartridge(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "config", MMS_PN_CLAUSE, NULL) &&
	    ((event_scope =
	    notify_return_scope(notify->n_cfgchg)) != 0)) {
		mms_trace(MMS_DEVP, "Check scope for config event");
		if (notify_check_cfgchg(mm_wka, notify,
		    event_cmd, event_scope)) {
			do_notify = 1;
		}
	} else if (mms_pn_lookup(event, "librarycreate",
	    MMS_PN_CLAUSE, NULL) &&
	    ((event_scope =
	    notify_return_scope(notify->n_librarycreate)) != 0)) {
		mms_trace(MMS_DEVP, "Global scope for library create event");
		do_notify = 1;
	} else if (mms_pn_lookup(event, "librarydelete",
	    MMS_PN_CLAUSE, NULL) &&
	    ((event_scope =
	    notify_return_scope(notify->n_librarydelete)) != 0)) {
		mms_trace(MMS_DEVP, "Global scope for library delete event");
		do_notify = 1;
	} else if (mms_pn_lookup(event, "drivedelete",
	    MMS_PN_CLAUSE, NULL) &&
	    ((event_scope =
	    notify_return_scope(notify->n_drivedelete)) != 0)) {
		mms_trace(MMS_DEVP, "Global scope for drive delete event");
		do_notify = 1;
	}

	if (do_notify) {
		/*
		 * Forward event to client.
		 */
		mms_trace(MMS_INFO,
		    "Send event to %s %s, %s",
		    conn->cci_client,
		    conn->cci_instance,
		    event_text);
		mm_send_text(mm_wka->mm_wka_conn, event_text);
	} else {
		mms_trace(MMS_DEVP, "skip event %s %s, %s",
		    conn->cci_client,
		    conn->cci_instance,
		    event_text);
	}

not_found:
	mms_pn_destroy(event);
}
