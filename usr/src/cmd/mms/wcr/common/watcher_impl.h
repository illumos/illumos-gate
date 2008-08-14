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

#ifndef	__WATCHER_IMPL_H
#define	__WATCHER_IMPL_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	WCR_DEV_START		0x01


typedef struct wcr_net_LM {
	char		wcr_ssi_host[MAXHOSTNAMELEN];
	int		wcr_ssi_port;
	int		wcr_acsls_port;
	pid_t		wcr_dev_pid;
	mms_list_node_t	wcr_net_LM_next;
	char		*wcr_lm_name;
}	wcr_net_LM_t;

typedef struct wcr_MM {
	mms_list_node_t	wcr_MM_next;
	char		wcr_mm_host[MAXHOSTNAMELEN];
}	wcr_MM_t;

/* wka Watcher Work Area */
typedef	struct	wcr_wka {
	int		wcr_wka_next_ordinal;
	int		wcr_wka_sigchld;
	int		wcr_wka_sighup;
	mms_network_cfg_t	wcr_wka_net_cfg;
	mms_list_t		*wcr_wka_MM_list;
	mms_list_t		wcr_wka_DM_LM_list;
	mms_list_t		wcr_old_DM_LM_list;
	int		wcr_wka_fd;
	char 		wcr_host_name[MAXHOSTNAMELEN];
	char		wcr_mm_host[MAXHOSTNAMELEN];
	mms_list_t		wcr_net_LM_list;
	mms_list_t		wcr_events;
	mms_t		wcr_mms_conn;
	mms_err_t	wcr_mms_err;
	char		wcr_mms_ebuf[MMS_EBUF_LEN];
	int		wcr_cfd;
	int		wcr_time;
	int		wcr_starts;
	int		wcr_connected;
	void		*wcr_ssl_data;
}	wcr_wka_t;

typedef struct wcr_event {
	mms_list_node_t	wcr_event_next;
	char		wcr_type[1024];
	char		wcr_object[1024];
	char		wcr_inst_name[1024];
	char		wcr_new_inst_name[1024];
	char		wcr_old_inst_name[1024];
	int		wcr_done;
}	wcr_event_t;

typedef struct wcr_DM {
	char 		*wcr_DM_name;
	char 		*wcr_drive_name;
	char		*wcr_dev_tar_path;
	char		*wcr_dev_mgr_path;
	major_t		wcr_dev_major;
	minor_t		wcr_dev_minor;
	int		wcr_dev_ordinal;
	int		wcr_dev_number;
}	wcr_DM_t;

typedef struct wcr_LM {
	char 		*wcr_LM_name;
	char 		*wcr_library_name;

}	wcr_LM_t;

typedef struct wcr_DM_LM {
	mms_list_node_t	wcr_DM_LM_next;
	int 		wcr_DM_flag;
	char 		*wcr_host_name;
	char 		wcr_path[1024];
	char		*wcr_disabled;
	pid_t		wcr_dev_pid;
	int		wcr_del_pending;
	int		wcr_change_pending;
	union {
		struct wcr_DM wcr_DM;
		struct wcr_LM wcr_LM;
	}		wcr_DM_LM_union;
	time_t		wcr_time;
	int		wcr_starts;
}	wcr_DM_LM_t;


#define	WCR_WORK_TO_DO		0x01

#define	WCR_WATCHER		"/devices/pseudo/dmd@0:watcher"
#define	WCR_FIRST_DEV_ORDINAL	DMD_FIRST_DEV_ORDINAL

#define	MMS_ERROR		1
#define	ACCEPT		2
#define	UNACCEPTABLE	3
#define	SUCCESS		4
#define	CANCELLED	5
#define	MMS_WELCOME		6
#define	MMS_UNWELCOME	7

#define	SHOW_DM_CMD_STRING "show task [\"wcr show DMs\"] " \
	"match[ hosteq (DM.\"DMTargetHost\" \"%s\") ] " \
	"report[DM] reportmode[namevalue];"
#define	SHOW_LM_CMD_STRING "show task [\"wcr show LMs\"] " \
	"match[ hosteq (LM.\"LMTargetHost\" \"%s\") ] " \
	"report[LM] reportmode[namevalue];"
#define	SHOW_LM_SSI_STRING "show task [\"wcr show SSI\"] "\
	"match[ and(hosteq (LM.\"LMTargetHost\" \"%s\") "\
	"strne(LIBRARY.\"LibraryIP\" \"\")"\
	")] "\
	"report[LM.\"LMName\" LIBRARY.\"LibraryIP\" "\
	"LIBRARY.\"LibraryACSLSPort\" LM.\"LMSSIPort\" ] "\
	"reportmode[namevalue];"
#define	SHOW_LM_SSI_STRING_NAME "show task [\"wcr show SSI\"] "\
	"match[ and(hosteq (LM.\"LMTargetHost\" \"%s\") "\
	"strne(LIBRARY.\"LibraryIP\" \"\")"\
	"streq(LM.\"LMName\" \"%s\")"\
	")] "\
	"report[LM.\"LMName\" LIBRARY.\"LibraryIP\" "\
	"LIBRARY.\"LibraryACSLSPort\" LM.\"LMSSIPort\" ] "\
	"reportmode[namevalue];"
#define	SHOW_SYSTEM_CMD_STR "show task ['wcr show system settings'] " \
	"report[SYSTEM.'WatcherStartsLimit' SYSTEM.'WatcherTimeLimit'] " \
	"reportmode[namevalue];"
#define	PRIVILEGE_CMD_STR "privilege task['wcr set privilege'] level[%s];"
#define	ATTR_BROKEN_LM_CMD_STRING "attribute task['wcr set lm broken'] " \
	"match[and(streq(LM.'LMName' '%s') hosteq(LM.'LMTargetHost' '%s'))] " \
	"set[LM.'LMStateHard' 'broken'];"
#define	ATTR_BROKEN_DM_CMD_STRING "attribute task['wcr set dm broken'] " \
	"match[and(streq(DM.'DMName' '%s') hosteq(DM.'DMTargetHost' '%s'))] " \
	"set[DM.'DMStateHard' 'broken'];"

#define	WCR_DEV_MGR_PATH "/devices/pseudo/dmd@0:%ddrm"

#define	WCR_DEV_MGR_PROG "/usr/lib/%s"
#define	WCR_SSI_SH "/usr/bin/%s"
#define	WCR_SSI_SCRIPT "mmsssi.sh"

#if 0
#define	WCR_MM_PROG "/usr/bin/mms"
#endif
#define	WCR_DM_LM_CONFIG_NAME "/etc/mms/config/%s_cfg.xml"
#define	WCR_NOTIFY_EVENTS "\"NotifyConfigChange\""
#define	WCR_TRACE_FILE		"/var/log/mms/wcr/wcr.debug"


#define	WCR_SHOW_NEW_DM "show task [\"wcr show new dm\"] " \
	"match[ and (streq (DM.\"DMName\" \"%s\") " \
	"hosteq (DM.\"DMTargetHost\" \"%s\")) ] " \
	"report[DM] reportmode[namevalue];"

#define	WCR_SHOW_NEW_LM "show task [\"wcr show new lm\"] " \
	"match[ and (streq (LM.\"LMName\" \"%s\") " \
	"hosteq (LM.\"LMTargetHost\" \"%s\")) ] " \
	"report[LM] reportmode[namevalue];"

#define	WCR_SET_NOTIFY "notify task[\"watchernotify\"] "\
	"receive [\"NotifyConfigChange\" \"host\"]; "

#define	WCR_SSI_ERR_MSG "message task[\"wcr ssi config error\"] "\
	"who [ administrator ] severity [ error ] "\
	"message [ id ['SUNW' 'MMS' '8000' ]"\
	"arguments [ 'wcr_host' '%s' 'lmname1' '%s' "\
	"'ssiport1' '%d' 'ssihost1' '%s' 'lmname2' '%s' "\
	"'ssiport2' '%d' 'ssihost2' '%s']];"


#ifdef	__cplusplus
}
#endif

#endif	/* __WATCHER_IMPL_H */
