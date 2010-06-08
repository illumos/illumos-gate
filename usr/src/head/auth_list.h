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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * This is an internal header file. Not to be shipped.
 */

#ifndef	_AUTH_LIST_H
#define	_AUTH_LIST_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Names of authorizations currently in use in the system
 */

#define	AUTOCONF_READ_AUTH	"solaris.network.autoconf.read"
#define	AUTOCONF_SELECT_AUTH	"solaris.network.autoconf.select"
#define	AUTOCONF_WLAN_AUTH	"solaris.network.autoconf.wlan"
#define	AUTOCONF_WRITE_AUTH	"solaris.network.autoconf.write"
#define	CDRW_AUTH		"solaris.device.cdrw"
#define	CRONADMIN_AUTH		"solaris.jobs.admin"
#define	CRONUSER_AUTH		"solaris.jobs.user"
#define	DEFAULT_DEV_ALLOC_AUTH	"solaris.device.allocate"
#define	DEVICE_REVOKE_AUTH	"solaris.device.revoke"
#define	LINK_SEC_AUTH		"solaris.network.link.security"
#define	MAILQ_AUTH		"solaris.mail.mailq"
#define	NET_ILB_CONFIG_AUTH	"solaris.network.ilb.config"
#define	NET_ILB_ENABLE_AUTH	"solaris.network.ilb.enable"
#define	SET_DATE_AUTH		"solaris.system.date"
#define	WIFI_CONFIG_AUTH	"solaris.network.wifi.config"
#define	WIFI_WEP_AUTH		"solaris.network.wifi.wep"
#define	HP_MODIFY_AUTH		"solaris.hotplug.modify"

/*
 * The following authorizations can be qualified by appending <zonename>
 */
#define	ZONE_CLONEFROM_AUTH	"solaris.zone.clonefrom"
#define	ZONE_LOGIN_AUTH		"solaris.zone.login"
#define	ZONE_MANAGE_AUTH	"solaris.zone.manage"

#define	ZONE_AUTH_PREFIX	"solaris.zone."

/*
 * Authorizations used by Trusted Extensions.
 */
#define	BYPASS_FILE_VIEW_AUTH	"solaris.label.win.noview"
#define	DEVICE_CONFIG_AUTH	"solaris.device.config"
#define	FILE_CHOWN_AUTH		"solaris.file.chown"
#define	FILE_DOWNGRADE_SL_AUTH	"solaris.label.file.downgrade"
#define	FILE_OWNER_AUTH		"solaris.file.owner"
#define	FILE_UPGRADE_SL_AUTH	"solaris.label.file.upgrade"
#define	MAINTENANCE_AUTH	"solaris.system.maintenance"
#define	PRINT_ADMIN_AUTH	"solaris.print.admin"
#define	PRINT_CANCEL_AUTH	"solaris.print.cancel"
#define	PRINT_LIST_AUTH		"solaris.print.list"
#define	PRINT_MAC_AUTH		"solaris.label.print"
#define	PRINT_NOBANNER_AUTH	"solaris.print.nobanner"
#define	PRINT_POSTSCRIPT_AUTH	"solaris.print.ps"
#define	PRINT_UNLABELED_AUTH	"solaris.print.unlabeled"
#define	SHUTDOWN_AUTH		"solaris.system.shutdown"
#define	SYS_ACCRED_SET_AUTH	"solaris.label.range"
#define	SYSEVENT_READ_AUTH	"solaris.system.sysevent.read"
#define	SYSEVENT_WRITE_AUTH	"solaris.system.sysevent.write"
#define	WIN_DOWNGRADE_SL_AUTH	"solaris.label.win.downgrade"
#define	WIN_UPGRADE_SL_AUTH	"solaris.label.win.upgrade"

#ifdef	__cplusplus
}
#endif

#endif	/* _AUTH_LIST_H */
