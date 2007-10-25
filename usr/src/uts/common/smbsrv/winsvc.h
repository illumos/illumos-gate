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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_WINSVC_H
#define	_SMBSRV_WINSVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NT Service Control interface definition for the Service Control
 * Manager (SCM).
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Service types (Bit Mask).
 *
 * SERVICE_WIN32_OWN_PROCESS	The service runs in its own process.
 * SERVICE_WIN32_SHARE_PROCESS	The service shares a process with other
 *                              services.
 */
#define	SERVICE_KERNEL_DRIVER		0x00000001
#define	SERVICE_FILE_SYSTEM_DRIVER	0x00000002
#define	SERVICE_ADAPTER			0x00000004
#define	SERVICE_RECOGNIZER_DRIVER	0x00000008
#define	SERVICE_WIN32_OWN_PROCESS	0x00000010
#define	SERVICE_WIN32_SHARE_PROCESS	0x00000020
#define	SERVICE_INTERACTIVE_PROCESS	0x00000100

#define	SERVICE_DRIVER (SERVICE_KERNEL_DRIVER				\
	    | SERVICE_FILE_SYSTEM_DRIVER				\
	    | SERVICE_RECOGNIZER_DRIVER)

#define	SERVICE_WIN32 (SERVICE_WIN32_OWN_PROCESS			\
	    | SERVICE_WIN32_SHARE_PROCESS)

#define	SERVICE_TYPE_ALL (SERVICE_WIN32					\
	    | SERVICE_ADAPTER						\
	    | SERVICE_DRIVER						\
	    | SERVICE_INTERACTIVE_PROCESS)

/*
 * Start type.
 */
#define	SERVICE_BOOT_START		0x00000000
#define	SERVICE_SYSTEM_START		0x00000001
#define	SERVICE_AUTO_START		0x00000002
#define	SERVICE_DEMAND_START		0x00000003
#define	SERVICE_DISABLED		0x00000004

/*
 * Error control type.
 */
#define	SERVICE_ERROR_IGNORE		0x00000000
#define	SERVICE_ERROR_NORMAL		0x00000001
#define	SERVICE_ERROR_SEVERE		0x00000002
#define	SERVICE_ERROR_CRITICAL		0x00000003

/*
 * Value to indicate no change to an optional parameter.
 */
#define	SERVICE_NO_CHANGE		0xffffffff

/*
 * Service State - for Enum Requests (Bit Mask).
 */
#define	SERVICE_ACTIVE			0x00000001
#define	SERVICE_INACTIVE		0x00000002
#define	SERVICE_STATE_ALL		(SERVICE_ACTIVE | SERVICE_INACTIVE)

/*
 * Controls
 */
#define	SERVICE_CONTROL_STOP		0x00000001
#define	SERVICE_CONTROL_PAUSE		0x00000002
#define	SERVICE_CONTROL_CONTINUE	0x00000003
#define	SERVICE_CONTROL_INTERROGATE	0x00000004
#define	SERVICE_CONTROL_SHUTDOWN	0x00000005
#define	SERVICE_CONTROL_PARAMCHANGE	0x00000006
#define	SERVICE_CONTROL_NETBINDADD	0x00000007
#define	SERVICE_CONTROL_NETBINDREMOVE	0x00000008
#define	SERVICE_CONTROL_NETBINDENABLE	0x00000009
#define	SERVICE_CONTROL_NETBINDDISABLE	0x0000000A

/*
 * Service State -- for CurrentState
 */
#define	SERVICE_STOPPED			0x00000001
#define	SERVICE_START_PENDING		0x00000002
#define	SERVICE_STOP_PENDING		0x00000003
#define	SERVICE_RUNNING			0x00000004
#define	SERVICE_CONTINUE_PENDING	0x00000005
#define	SERVICE_PAUSE_PENDING		0x00000006
#define	SERVICE_PAUSED			0x00000007

/*
 * Controls Accepted  (Bit Mask)
 *
 * SERVICE_ACCEPT_NETBINDCHANGE
 * Windows 2000/XP: The service is a network component that
 * can accept changes in its binding without being stopped and restarted.
 * This control code allows the service to receive SERVICE_CONTROL_NETBINDADD,
 * SERVICE_CONTROL_NETBINDREMOVE, SERVICE_CONTROL_NETBINDENABLE, and
 * SERVICE_CONTROL_NETBINDDISABLE notifications.
 *
 * SERVICE_ACCEPT_PARAMCHANGE
 * Windows 2000/XP: The service can reread its startup parameters without
 * being stopped and restarted. This control code allows the service to
 * receive SERVICE_CONTROL_PARAMCHANGE notifications.
 *
 * SERVICE_ACCEPT_PAUSE_CONTINUE
 * The service can be paused and continued. This control code allows the
 * service to receive SERVICE_CONTROL_PAUSE and SERVICE_CONTROL_CONTINUE
 * notifications.
 *
 * SERVICE_ACCEPT_SHUTDOWN
 * The service is notified when system shutdown occurs. This control code
 * allows the service to receive SERVICE_CONTROL_SHUTDOWN notifications.
 * Note that ControlService cannot send this notification; only the system
 * can send it.
 *
 * SERVICE_ACCEPT_STOP
 * The service can be stopped. This control code allows the service to
 * receive SERVICE_CONTROL_STOP notifications.
 */
#define	SERVICE_ACCEPT_STOP		0x00000001
#define	SERVICE_ACCEPT_PAUSE_CONTINUE	0x00000002
#define	SERVICE_ACCEPT_SHUTDOWN		0x00000004
#define	SERVICE_ACCEPT_PARAMCHANGE	0x00000008
#define	SERVICE_ACCEPT_NETBINDCHANGE	0x00000010

/*
 * Service Control Manager object specific access types.
 */
#define	SC_MANAGER_CONNECT		0x0001
#define	SC_MANAGER_CREATE_SERVICE	0x0002
#define	SC_MANAGER_ENUMERATE_SERVICE	0x0004
#define	SC_MANAGER_LOCK			0x0008
#define	SC_MANAGER_QUERY_LOCK_STATUS	0x0010
#define	SC_MANAGER_MODIFY_BOOT_CONFIG	0x0020

#define	SC_MANAGER_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED		       \
	    | SC_MANAGER_CONNECT				       \
	    | SC_MANAGER_CREATE_SERVICE				       \
	    | SC_MANAGER_ENUMERATE_SERVICE			       \
	    | SC_MANAGER_LOCK					       \
	    | SC_MANAGER_QUERY_LOCK_STATUS			       \
	    | SC_MANAGER_MODIFY_BOOT_CONFIG)

/*
 * Service object specific access type.
 */
#define	SERVICE_QUERY_CONFIG		0x0001
#define	SERVICE_CHANGE_CONFIG		0x0002
#define	SERVICE_QUERY_STATUS		0x0004
#define	SERVICE_ENUMERATE_DEPENDENTS	0x0008
#define	SERVICE_START			0x0010
#define	SERVICE_STOP			0x0020
#define	SERVICE_PAUSE_CONTINUE		0x0040
#define	SERVICE_INTERROGATE		0x0080
#define	SERVICE_USER_DEFINED_CONTROL	0x0100

#define	SERVICE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED		       \
	    | SERVICE_QUERY_CONFIG				       \
	    | SERVICE_CHANGE_CONFIG				       \
	    | SERVICE_QUERY_STATUS				       \
	    | SERVICE_ENUMERATE_DEPENDENTS			       \
	    | SERVICE_START					       \
	    | SERVICE_STOP					       \
	    | SERVICE_PAUSE_CONTINUE				       \
	    | SERVICE_INTERROGATE				       \
	    | SERVICE_USER_DEFINED_CONTROL)

/*
 * Info levels for ChangeServiceConfig2 and QueryServiceConfig2.
 */
#define	SERVICE_CONFIG_DESCRIPTION	1
#define	SERVICE_CONFIG_FAILURE_ACTIONS	2

/*
 * Actions to take on service failure (SC_ACTION_TYPE).
 */
#define	SC_ACTION_NONE			0
#define	SC_ACTION_RESTART		1
#define	SC_ACTION_REBOOT		2
#define	SC_ACTION_RUN_COMMAND		3

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_WINSVC_H */
