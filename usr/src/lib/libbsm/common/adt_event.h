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
 * adt_event.h
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * AUTOMATICALLY GENERATED CODE; DO NOT EDIT; CONTACT AUDIT PROJECT
 *
 * This is an evolving interface; additions will be made without
 * notice.  It is also part of a contract private interface and
 * any changes made that are not upward compatible are subject to
 * the contract's rules.
 */

#ifndef _ADT_EVENT_H
#define	_ADT_EVENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <bsm/adt.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * adt_put_event() status values.  Positive values are for kernel-generated
 * failure, -1 for user-space.  For ADT_SUCCESS, the adt_put_event() return_val
 * is not used; the convention is to set it to ADT_SUCCESS.
 */
#define	ADT_SUCCESS	0
#define	ADT_FAILURE	-1

#define	ADT_FAIL_PAM	2000
#define	ADT_FAIL_VALUE	1000
enum	adt_fail_value {
	ADT_FAIL_VALUE_PW_ATTR = 1000,	/* Attribute update */
	ADT_FAIL_VALUE_PW,		/* Password update */
	ADT_FAIL_VALUE_USERNAME,		/* bad username */
	ADT_FAIL_VALUE_AUTH,		/* authorization failed */
	ADT_FAIL_VALUE_UID,		/* bad uid */
	ADT_FAIL_VALUE_UNKNOWN,		/* unknown failure */
	ADT_FAIL_VALUE_EXPIRED,		/* password expired */
	ADT_FAIL_VALUE_ACCOUNT_LOCKED,		/* Account is locked */
	ADT_FAIL_VALUE_BAD_DIALUP,		/* Bad dial up */
	ADT_FAIL_VALUE_BAD_ID,		/* Invalid ID */
	ADT_FAIL_VALUE_BAD_PW,		/* Invalid password */
	ADT_FAIL_VALUE_CONSOLE,		/* Not on console */
	ADT_FAIL_VALUE_MAX_TRIES,		/* Too many failed attempts */
	ADT_FAIL_VALUE_PROTOCOL_FAILURE,		/* Protocol failure */
	ADT_FAIL_VALUE_EXCLUDED_USER,		/* Excluded user */
	ADT_FAIL_VALUE_ANON_USER,		/* No anonymous */
	ADT_FAIL_VALUE_BAD_CMD,		/* Invalid command */
	ADT_FAIL_VALUE_BAD_TTY,		/* Standard input not a tty line */
	ADT_FAIL_VALUE_PROGRAM,		/* Program failure */
	ADT_FAIL_VALUE_CHDIR_FAILED,		/* chdir to home directory */
	ADT_FAIL_VALUE_INPUT_OVERFLOW,		/* Input line too long. */
	ADT_FAIL_VALUE_DEVICE_PERM,		/* login device override */
	ADT_FAIL_VALUE_AUTH_BYPASS,		/* authorization bypass */
	ADT_FAIL_VALUE_LOGIN_DISABLED		/* login disabled */
};
/* Deprecated message list */
enum	adt_login_text {
	ADT_LOGIN_NO_MSG,		/* (no token will be generated) */
	ADT_LOGIN_ACCOUNT_LOCKED,		/* Account is locked */
	ADT_LOGIN_BAD_DIALUP,		/* Bad dial up */
	ADT_LOGIN_BAD_ID,		/* Invalid ID */
	ADT_LOGIN_BAD_PW,		/* Invalid password */
	ADT_LOGIN_CONSOLE,		/* Not on console */
	ADT_LOGIN_MAX_TRIES,		/* Too many failed attempts */
	ADT_LOGIN_PROTOCOL_FAILURE,		/* Protocol failure */
	ADT_LOGIN_EXCLUDED_USER,		/* Excluded user */
	ADT_LOGIN_ANON_USER		/* No anonymous */
};
#define	ADT_admin_authenticate	3
#define	ADT_attach		42
#define	ADT_detach		43
#define	ADT_dladm_create_secobj	47
#define	ADT_dladm_delete_secobj	48
#define	ADT_filesystem_add	4
#define	ADT_filesystem_delete	5
#define	ADT_filesystem_modify	6
#define	ADT_inetd_connect	34
#define	ADT_inetd_copylimit	36
#define	ADT_inetd_failrate	37
#define	ADT_inetd_ratelimit	35
#define	ADT_init_solaris	32
#define	ADT_login		25
#define	ADT_logout		1
#define	ADT_network_add		7
#define	ADT_network_delete	8
#define	ADT_network_modify	9
#define	ADT_newgrp_login	41
#define	ADT_passwd		27
#define	ADT_pool_export		46
#define	ADT_pool_import		45
#define	ADT_printer_add		10
#define	ADT_printer_delete	11
#define	ADT_printer_modify	12
#define	ADT_prof_cmd		24
#define	ADT_remove		44
#define	ADT_rlogin		28
#define	ADT_role_login		13
#define	ADT_role_logout		40
#define	ADT_scheduledjob_add	14
#define	ADT_scheduledjob_delete	15
#define	ADT_scheduledjob_modify	16
#define	ADT_screenlock		26
#define	ADT_screenunlock	31
#define	ADT_serialport_add	17
#define	ADT_serialport_delete	18
#define	ADT_serialport_modify	19
#define	ADT_ssh			2
#define	ADT_su			30
#define	ADT_su_logout		39
#define	ADT_telnet		29
#define	ADT_uauth		20
#define	ADT_usermgr_add		21
#define	ADT_usermgr_delete	22
#define	ADT_usermgr_modify	23
#define	ADT_zlogin		38
#define	ADT_zone_state		33


struct adt_admin_authenticate {	/* ADT_admin_authenticate */
	enum adt_login_text	message;	/*  optional  */
};
typedef struct adt_admin_authenticate adt_admin_authenticate_t;

struct adt_attach {	/* ADT_attach */
	char 	*auth_used;	/* required */
	char 	*mount_point;	/* required */
	char 	*device;	/* required */
	char 	*options;	/* optional */
};
typedef struct adt_attach adt_attach_t;

struct adt_detach {	/* ADT_detach */
	char 	*auth_used;	/* required */
	char 	*mount_point;	/* required */
	char 	*device;	/* required */
	char 	*options;	/* optional */
};
typedef struct adt_detach adt_detach_t;

struct adt_dladm_create_secobj {	/* ADT_dladm_create_secobj */
	char 	*auth_used;	/* required */
	char 	*obj_class;	/* required */
	char 	*obj_name;	/* required */
};
typedef struct adt_dladm_create_secobj adt_dladm_create_secobj_t;

struct adt_dladm_delete_secobj {	/* ADT_dladm_delete_secobj */
	char 	*auth_used;	/* required */
	char 	*obj_class;	/* required */
	char 	*obj_name;	/* required */
};
typedef struct adt_dladm_delete_secobj adt_dladm_delete_secobj_t;

struct adt_filesystem_add {	/* ADT_filesystem_add */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*initial_values;	/* required */
};
typedef struct adt_filesystem_add adt_filesystem_add_t;

struct adt_filesystem_delete {	/* ADT_filesystem_delete */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*delete_values;	/* required */
};
typedef struct adt_filesystem_delete adt_filesystem_delete_t;

struct adt_filesystem_modify {	/* ADT_filesystem_modify */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*changed_values;	/* required */
};
typedef struct adt_filesystem_modify adt_filesystem_modify_t;

struct adt_inetd_connect {	/* ADT_inetd_connect */
	char 	*service_name;	/* optional */
	uint32_t	ip_type;	/*  required  */
	uint16_t	ip_remote_port;	/*  required  */
	uint16_t	ip_local_port;	/*  required  */
	uint32_t	ip_adr[4];	/*  required  */
	char 	*cmd;	/* required */
	priv_set_t 	*privileges;	/* required */
};
typedef struct adt_inetd_connect adt_inetd_connect_t;

struct adt_inetd_copylimit {	/* ADT_inetd_copylimit */
	char 	*service_name;	/* optional */
	char 	*limit;	/* required */
};
typedef struct adt_inetd_copylimit adt_inetd_copylimit_t;

struct adt_inetd_failrate {	/* ADT_inetd_failrate */
	char 	*service_name;	/* optional */
	char 	*values;	/* required */
};
typedef struct adt_inetd_failrate adt_inetd_failrate_t;

struct adt_inetd_ratelimit {	/* ADT_inetd_ratelimit */
	char 	*service_name;	/* optional */
	char 	*limit;	/* required */
};
typedef struct adt_inetd_ratelimit adt_inetd_ratelimit_t;

struct adt_init_solaris {	/* ADT_init_solaris */
	char 	*info;	/* optional */
};
typedef struct adt_init_solaris adt_init_solaris_t;

struct adt_login {	/* ADT_login */
	enum adt_login_text	message;	/*  optional  */
};
typedef struct adt_login adt_login_t;

struct adt_logout {	/* ADT_logout */
	char 	*user_name;	/* optional (format: logout %s) */
};
typedef struct adt_logout adt_logout_t;

struct adt_network_add {	/* ADT_network_add */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*initial_values;	/* required */
};
typedef struct adt_network_add adt_network_add_t;

struct adt_network_delete {	/* ADT_network_delete */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*delete_values;	/* required */
};
typedef struct adt_network_delete adt_network_delete_t;

struct adt_network_modify {	/* ADT_network_modify */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*changed_values;	/* required */
};
typedef struct adt_network_modify adt_network_modify_t;

struct adt_newgrp_login {	/* ADT_newgrp_login */
	char 	*groupname;	/* required */
};
typedef struct adt_newgrp_login adt_newgrp_login_t;

struct adt_passwd {	/* ADT_passwd */
	char 	*username;	/* optional */
};
typedef struct adt_passwd adt_passwd_t;

struct adt_pool_export {	/* ADT_pool_export */
	char 	*auth_used;	/* required */
	char 	*pool;	/* required */
	char 	*device;	/* required */
};
typedef struct adt_pool_export adt_pool_export_t;

struct adt_pool_import {	/* ADT_pool_import */
	char 	*auth_used;	/* required */
	char 	*pool;	/* required */
	char 	*device;	/* required */
};
typedef struct adt_pool_import adt_pool_import_t;

struct adt_printer_add {	/* ADT_printer_add */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*initial_values;	/* required */
};
typedef struct adt_printer_add adt_printer_add_t;

struct adt_printer_delete {	/* ADT_printer_delete */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*delete_values;	/* required */
};
typedef struct adt_printer_delete adt_printer_delete_t;

struct adt_printer_modify {	/* ADT_printer_modify */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*changed_values;	/* required */
};
typedef struct adt_printer_modify adt_printer_modify_t;

struct adt_prof_cmd {	/* ADT_prof_cmd */
	char	*cwdpath;	/* required */
	char	*cmdpath;	/* required */
	int	argc;	/*  required  */
	char	**argv;	/*  required  */
	char	**envp;	/*  required  */
	uid_t	proc_auid;	/*  required  */
	uid_t	proc_euid;	/*  required  */
	gid_t	proc_egid;	/*  required  */
	uid_t	proc_ruid;	/*  required  */
	gid_t	proc_rgid;	/*  required  */
	pid_t	proc_pid;	/*  required  */
	au_asid_t	proc_sid;	/*  required  */
	adt_termid_t	*proc_termid;	/*  required  */
	priv_set_t	*limit_set;	/* optional */
	priv_set_t	*inherit_set;	/* optional */
};
typedef struct adt_prof_cmd adt_prof_cmd_t;

struct adt_remove {	/* ADT_remove */
	char 	*auth_used;	/* required */
	char 	*mount_point;	/* optional */
	char 	*device;	/* required */
};
typedef struct adt_remove adt_remove_t;

struct adt_rlogin {	/* ADT_rlogin */
	enum adt_login_text	message;	/*  optional  */
};
typedef struct adt_rlogin adt_rlogin_t;

struct adt_role_login {	/* ADT_role_login */
	enum adt_login_text	message;	/*  optional  */
};
typedef struct adt_role_login adt_role_login_t;

struct adt_role_logout {	/* ADT_role_logout */
	int	dummy;	/* not used */
};
typedef struct adt_role_logout adt_role_logout_t;

struct adt_scheduledjob_add {	/* ADT_scheduledjob_add */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*initial_values;	/* required */
};
typedef struct adt_scheduledjob_add adt_scheduledjob_add_t;

struct adt_scheduledjob_delete {	/* ADT_scheduledjob_delete */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*delete_values;	/* required */
};
typedef struct adt_scheduledjob_delete adt_scheduledjob_delete_t;

struct adt_scheduledjob_modify {	/* ADT_scheduledjob_modify */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*changed_values;	/* required */
};
typedef struct adt_scheduledjob_modify adt_scheduledjob_modify_t;

struct adt_screenlock {	/* ADT_screenlock */
	int	dummy;	/* not used */
};
typedef struct adt_screenlock adt_screenlock_t;

struct adt_screenunlock {	/* ADT_screenunlock */
	int	dummy;	/* not used */
};
typedef struct adt_screenunlock adt_screenunlock_t;

struct adt_serialport_add {	/* ADT_serialport_add */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*initial_values;	/* required */
};
typedef struct adt_serialport_add adt_serialport_add_t;

struct adt_serialport_delete {	/* ADT_serialport_delete */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*delete_values;	/* required */
};
typedef struct adt_serialport_delete adt_serialport_delete_t;

struct adt_serialport_modify {	/* ADT_serialport_modify */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*changed_values;	/* required */
};
typedef struct adt_serialport_modify adt_serialport_modify_t;

struct adt_ssh {	/* ADT_ssh */
	enum adt_login_text	message;	/*  optional  */
};
typedef struct adt_ssh adt_ssh_t;

struct adt_su {	/* ADT_su */
	char 	*message;	/* optional */
};
typedef struct adt_su adt_su_t;

struct adt_su_logout {	/* ADT_su_logout */
	int	dummy;	/* not used */
};
typedef struct adt_su_logout adt_su_logout_t;

struct adt_telnet {	/* ADT_telnet */
	enum adt_login_text	message;	/*  optional  */
};
typedef struct adt_telnet adt_telnet_t;

struct adt_uauth {	/* ADT_uauth */
	char 	*auth_used;	/* required */
	char 	*objectname;	/* required */
};
typedef struct adt_uauth adt_uauth_t;

struct adt_usermgr_add {	/* ADT_usermgr_add */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*initial_values;	/* required */
};
typedef struct adt_usermgr_add adt_usermgr_add_t;

struct adt_usermgr_delete {	/* ADT_usermgr_delete */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*delete_values;	/* required */
};
typedef struct adt_usermgr_delete adt_usermgr_delete_t;

struct adt_usermgr_modify {	/* ADT_usermgr_modify */
	char 	*object_name;	/* required */
	char 	*domain;	/* optional */
	char 	*name_service;	/* required */
	char 	*auth_used;	/* optional */
	char 	*changed_values;	/* required */
};
typedef struct adt_usermgr_modify adt_usermgr_modify_t;

struct adt_zlogin {	/* ADT_zlogin */
	char 	*message;	/* optional */
};
typedef struct adt_zlogin adt_zlogin_t;

struct adt_zone_state {	/* ADT_zone_state */
	char 	*new_state;	/* required */
	char 	*zonename;	/* required */
};
typedef struct adt_zone_state adt_zone_state_t;

union adt_event_data {
		adt_admin_authenticate_t	adt_admin_authenticate;
		adt_attach_t	adt_attach;
		adt_detach_t	adt_detach;
		adt_dladm_create_secobj_t	adt_dladm_create_secobj;
		adt_dladm_delete_secobj_t	adt_dladm_delete_secobj;
		adt_filesystem_add_t	adt_filesystem_add;
		adt_filesystem_delete_t	adt_filesystem_delete;
		adt_filesystem_modify_t	adt_filesystem_modify;
		adt_inetd_connect_t	adt_inetd_connect;
		adt_inetd_copylimit_t	adt_inetd_copylimit;
		adt_inetd_failrate_t	adt_inetd_failrate;
		adt_inetd_ratelimit_t	adt_inetd_ratelimit;
		adt_init_solaris_t	adt_init_solaris;
		adt_login_t	adt_login;
		adt_logout_t	adt_logout;
		adt_network_add_t	adt_network_add;
		adt_network_delete_t	adt_network_delete;
		adt_network_modify_t	adt_network_modify;
		adt_newgrp_login_t	adt_newgrp_login;
		adt_passwd_t	adt_passwd;
		adt_pool_export_t	adt_pool_export;
		adt_pool_import_t	adt_pool_import;
		adt_printer_add_t	adt_printer_add;
		adt_printer_delete_t	adt_printer_delete;
		adt_printer_modify_t	adt_printer_modify;
		adt_prof_cmd_t	adt_prof_cmd;
		adt_remove_t	adt_remove;
		adt_rlogin_t	adt_rlogin;
		adt_role_login_t	adt_role_login;
		adt_role_logout_t	adt_role_logout;
		adt_scheduledjob_add_t	adt_scheduledjob_add;
		adt_scheduledjob_delete_t	adt_scheduledjob_delete;
		adt_scheduledjob_modify_t	adt_scheduledjob_modify;
		adt_screenlock_t	adt_screenlock;
		adt_screenunlock_t	adt_screenunlock;
		adt_serialport_add_t	adt_serialport_add;
		adt_serialport_delete_t	adt_serialport_delete;
		adt_serialport_modify_t	adt_serialport_modify;
		adt_ssh_t	adt_ssh;
		adt_su_t	adt_su;
		adt_su_logout_t	adt_su_logout;
		adt_telnet_t	adt_telnet;
		adt_uauth_t	adt_uauth;
		adt_usermgr_add_t	adt_usermgr_add;
		adt_usermgr_delete_t	adt_usermgr_delete;
		adt_usermgr_modify_t	adt_usermgr_modify;
		adt_zlogin_t	adt_zlogin;
		adt_zone_state_t	adt_zone_state;
};


#ifndef	ADT_PRIVATE
#define	ADT_PRIVATE

/*
 * These interfaces are project private and will change without
 * notice as needed for the BSM API project.
 */

extern	void	adt_get_auid(const adt_session_data_t *, au_id_t *);
extern	void	adt_set_auid(const adt_session_data_t *, const au_id_t);

extern	void	adt_get_mask(const adt_session_data_t *, au_mask_t *);
extern	void	adt_set_mask(const adt_session_data_t *, const au_mask_t *);

extern	void	adt_get_termid(const adt_session_data_t *, au_tid_addr_t *);
extern	void	adt_set_termid(const adt_session_data_t *,
    const au_tid_addr_t *);

extern	void	adt_get_asid(const adt_session_data_t *, au_asid_t *);
extern	void	adt_set_asid(const adt_session_data_t *, const au_asid_t);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ADT_EVENT_H */
