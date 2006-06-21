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
 * adt_xlate.c
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * AUTOMATICALLY GENERATED CODE; DO NOT EDIT; CONTACT AUDIT PROJECT
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <bsm/libbsm.h>
#include <adt_xlate.h>
#include <libintl.h>

#ifndef _PRAUDIT
/* Internal data type definitions */

static datadef	adr0[1] =	{{ADT_MSG, ADT_LIST_LOGIN_TEXT}};
static datadef	adr1[1] =	{{ADT_CHARSTAR, sizeof (char *)}};
static datadef	adr2[3] =	{{ADT_INT, sizeof (int)},
				{ADT_CHAR2STAR, sizeof (char **)},
				{ADT_CHAR2STAR, sizeof (char **)}};
static datadef	adr3[8] =	{{ADT_UID, sizeof (uid_t)},
				{ADT_UID, sizeof (uid_t)},
				{ADT_GID, sizeof (gid_t)},
				{ADT_UID, sizeof (uid_t)},
				{ADT_GID, sizeof (gid_t)},
				{ADT_PID, sizeof (pid_t)},
				{ADT_UINT32, sizeof (au_asid_t)},
				{ADT_TERMIDSTAR, sizeof (au_tid_addr_t *)}};
static datadef	adr4[1] =	{{ADT_PRIVSTAR, sizeof (priv_set_t *)}};
static datadef	adr5[4] =	{{ADT_UINT32, sizeof (uint32_t)},
				{ADT_UINT16, sizeof (uint16_t)},
				{ADT_UINT16, sizeof (uint16_t)},
				{ADT_UINT32ARRAY, 4 * sizeof (uint32_t)}};

/* External event structure to internal event structure */

static struct entry XX_admin_authenticate[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_admin_authenticate[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr0[0],	&(XX_admin_authenticate[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_admin_authenticate = {
	0,
	ADT_admin_authenticate,
	AUE_admin_authenticate,
	3,
	&XX_admin_authenticate[0],
	&XX_admin_authenticate[0]
};
static struct entry XX_filesystem_add[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_filesystem_add[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_add[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_add[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_add[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_filesystem_add[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_add[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_filesystem_add = {
	0,
	ADT_filesystem_add,
	AUE_filesystem_add,
	7,
	&XX_filesystem_add[0],
	&XX_filesystem_add[0]
};
static struct entry XX_filesystem_delete[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_filesystem_delete[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_delete[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_delete[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_delete[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_filesystem_delete[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_delete[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_filesystem_delete = {
	0,
	ADT_filesystem_delete,
	AUE_filesystem_delete,
	7,
	&XX_filesystem_delete[0],
	&XX_filesystem_delete[0]
};
static struct entry XX_filesystem_modify[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_filesystem_modify[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_modify[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_modify[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_modify[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_filesystem_modify[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_filesystem_modify[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_filesystem_modify = {
	0,
	ADT_filesystem_modify,
	AUE_filesystem_modify,
	7,
	&XX_filesystem_modify[0],
	&XX_filesystem_modify[0]
};
static struct entry XX_inetd_connect[6] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_inetd_connect[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_inetd_connect[2]),
		0,	0,	0,	NULL},
	{AUT_TID,	4,	&adr5[0],	&(XX_inetd_connect[3]),
		0,	1,	0,	NULL},
	{ADT_CMD_ALT,	1,	&adr1[0],	&(XX_inetd_connect[4]),
		0,	1,	0,	NULL},
	{ADT_AUT_PRIV_E,	1,	&adr4[0],	&(XX_inetd_connect[5]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_inetd_connect = {
	0,
	ADT_inetd_connect,
	AUE_inetd_connect,
	6,
	&XX_inetd_connect[0],
	&XX_inetd_connect[0]
};
static struct entry XX_inetd_copylimit[4] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_inetd_copylimit[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_inetd_copylimit[2]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_inetd_copylimit[3]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_inetd_copylimit = {
	0,
	ADT_inetd_copylimit,
	AUE_inetd_copylimit,
	4,
	&XX_inetd_copylimit[0],
	&XX_inetd_copylimit[0]
};
static struct entry XX_inetd_failrate[4] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_inetd_failrate[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_inetd_failrate[2]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_inetd_failrate[3]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_inetd_failrate = {
	0,
	ADT_inetd_failrate,
	AUE_inetd_failrate,
	4,
	&XX_inetd_failrate[0],
	&XX_inetd_failrate[0]
};
static struct entry XX_inetd_ratelimit[4] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_inetd_ratelimit[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_inetd_ratelimit[2]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_inetd_ratelimit[3]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_inetd_ratelimit = {
	0,
	ADT_inetd_ratelimit,
	AUE_inetd_ratelimit,
	4,
	&XX_inetd_ratelimit[0],
	&XX_inetd_ratelimit[0]
};
static struct entry XX_init_solaris[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_init_solaris[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_init_solaris[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_init_solaris = {
	0,
	ADT_init_solaris,
	AUE_init_solaris,
	3,
	&XX_init_solaris[0],
	&XX_init_solaris[0]
};
static struct entry XX_login[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_login[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr0[0],	&(XX_login[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_login = {
	0,
	ADT_login,
	AUE_login,
	3,
	&XX_login[0],
	&XX_login[0]
};
static struct entry XX_logout[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_logout[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_logout[2]),
		0,	0,	0,	"logout %s"},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_logout = {
	0,
	ADT_logout,
	AUE_logout,
	3,
	&XX_logout[0],
	&XX_logout[0]
};
static struct entry XX_network_add[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_network_add[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_add[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_add[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_add[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_network_add[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_add[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_network_add = {
	0,
	ADT_network_add,
	AUE_network_add,
	7,
	&XX_network_add[0],
	&XX_network_add[0]
};
static struct entry XX_network_delete[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_network_delete[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_delete[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_delete[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_delete[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_network_delete[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_delete[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_network_delete = {
	0,
	ADT_network_delete,
	AUE_network_delete,
	7,
	&XX_network_delete[0],
	&XX_network_delete[0]
};
static struct entry XX_network_modify[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_network_modify[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_modify[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_modify[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_modify[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_network_modify[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_network_modify[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_network_modify = {
	0,
	ADT_network_modify,
	AUE_network_modify,
	7,
	&XX_network_modify[0],
	&XX_network_modify[0]
};
static struct entry XX_passwd[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_passwd[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_passwd[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_passwd = {
	0,
	ADT_passwd,
	AUE_passwd,
	3,
	&XX_passwd[0],
	&XX_passwd[0]
};
static struct entry XX_printer_add[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_printer_add[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_add[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_add[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_add[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_printer_add[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_add[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_printer_add = {
	0,
	ADT_printer_add,
	AUE_printer_add,
	7,
	&XX_printer_add[0],
	&XX_printer_add[0]
};
static struct entry XX_printer_delete[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_printer_delete[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_delete[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_delete[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_delete[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_printer_delete[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_delete[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_printer_delete = {
	0,
	ADT_printer_delete,
	AUE_printer_delete,
	7,
	&XX_printer_delete[0],
	&XX_printer_delete[0]
};
static struct entry XX_printer_modify[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_printer_modify[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_modify[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_modify[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_modify[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_printer_modify[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_printer_modify[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_printer_modify = {
	0,
	ADT_printer_modify,
	AUE_printer_modify,
	7,
	&XX_printer_modify[0],
	&XX_printer_modify[0]
};
static struct entry XX_prof_cmd[8] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_prof_cmd[1]),
		0,	0,	0,	NULL},
	{AUT_PATH,	1,	&adr1[0],	&(XX_prof_cmd[2]),
		0,	1,	0,	NULL},
	{AUT_PATH,	1,	&adr1[0],	&(XX_prof_cmd[3]),
		0,	1,	0,	NULL},
	{AUT_CMD,	3,	&adr2[0],	&(XX_prof_cmd[4]),
		0,	1,	0,	NULL},
	{AUT_PROCESS,	8,	&adr3[0],	&(XX_prof_cmd[5]),
		0,	1,	0,	NULL},
	{ADT_AUT_PRIV_L,	1,	&adr4[0],	&(XX_prof_cmd[6]),
		0,	0,	0,	NULL},
	{ADT_AUT_PRIV_I,	1,	&adr4[0],	&(XX_prof_cmd[7]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_prof_cmd = {
	0,
	ADT_prof_cmd,
	AUE_prof_cmd,
	8,
	&XX_prof_cmd[0],
	&XX_prof_cmd[0]
};
static struct entry XX_rlogin[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_rlogin[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr0[0],	&(XX_rlogin[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_rlogin = {
	0,
	ADT_rlogin,
	AUE_rlogin,
	3,
	&XX_rlogin[0],
	&XX_rlogin[0]
};
static struct entry XX_role_login[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_role_login[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr0[0],	&(XX_role_login[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_role_login = {
	0,
	ADT_role_login,
	AUE_role_login,
	3,
	&XX_role_login[0],
	&XX_role_login[0]
};
static struct entry XX_role_logout[2] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_role_logout[1]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_role_logout = {
	0,
	ADT_role_logout,
	AUE_role_logout,
	2,
	&XX_role_logout[0],
	&XX_role_logout[0]
};
static struct entry XX_scheduledjob_add[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_scheduledjob_add[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_add[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_add[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_add[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_scheduledjob_add[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_add[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_scheduledjob_add = {
	0,
	ADT_scheduledjob_add,
	AUE_scheduledjob_add,
	7,
	&XX_scheduledjob_add[0],
	&XX_scheduledjob_add[0]
};
static struct entry XX_scheduledjob_delete[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_scheduledjob_delete[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_delete[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_delete[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_delete[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_scheduledjob_delete[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_delete[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_scheduledjob_delete = {
	0,
	ADT_scheduledjob_delete,
	AUE_scheduledjob_delete,
	7,
	&XX_scheduledjob_delete[0],
	&XX_scheduledjob_delete[0]
};
static struct entry XX_scheduledjob_modify[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_scheduledjob_modify[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_modify[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_modify[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_modify[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_scheduledjob_modify[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_scheduledjob_modify[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_scheduledjob_modify = {
	0,
	ADT_scheduledjob_modify,
	AUE_scheduledjob_modify,
	7,
	&XX_scheduledjob_modify[0],
	&XX_scheduledjob_modify[0]
};
static struct entry XX_screenlock[2] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_screenlock[1]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_screenlock = {
	0,
	ADT_screenlock,
	AUE_screenlock,
	2,
	&XX_screenlock[0],
	&XX_screenlock[0]
};
static struct entry XX_screenunlock[2] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_screenunlock[1]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_screenunlock = {
	0,
	ADT_screenunlock,
	AUE_screenunlock,
	2,
	&XX_screenunlock[0],
	&XX_screenunlock[0]
};
static struct entry XX_serialport_add[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_serialport_add[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_add[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_add[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_add[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_serialport_add[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_add[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_serialport_add = {
	0,
	ADT_serialport_add,
	AUE_serialport_add,
	7,
	&XX_serialport_add[0],
	&XX_serialport_add[0]
};
static struct entry XX_serialport_delete[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_serialport_delete[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_delete[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_delete[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_delete[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_serialport_delete[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_delete[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_serialport_delete = {
	0,
	ADT_serialport_delete,
	AUE_serialport_delete,
	7,
	&XX_serialport_delete[0],
	&XX_serialport_delete[0]
};
static struct entry XX_serialport_modify[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_serialport_modify[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_modify[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_modify[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_modify[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_serialport_modify[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_serialport_modify[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_serialport_modify = {
	0,
	ADT_serialport_modify,
	AUE_serialport_modify,
	7,
	&XX_serialport_modify[0],
	&XX_serialport_modify[0]
};
static struct entry XX_ssh[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_ssh[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr0[0],	&(XX_ssh[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_ssh = {
	0,
	ADT_ssh,
	AUE_ssh,
	3,
	&XX_ssh[0],
	&XX_ssh[0]
};
static struct entry XX_su[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_su[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_su[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_su = {
	0,
	ADT_su,
	AUE_su,
	3,
	&XX_su[0],
	&XX_su[0]
};
static struct entry XX_su_logout[2] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_su_logout[1]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_su_logout = {
	0,
	ADT_su_logout,
	AUE_su_logout,
	2,
	&XX_su_logout[0],
	&XX_su_logout[0]
};
static struct entry XX_telnet[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_telnet[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr0[0],	&(XX_telnet[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_telnet = {
	0,
	ADT_telnet,
	AUE_telnet,
	3,
	&XX_telnet[0],
	&XX_telnet[0]
};
static struct entry XX_uauth[4] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_uauth[1]),
		0,	0,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_uauth[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_uauth[3]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_uauth = {
	0,
	ADT_uauth,
	AUE_uauth,
	4,
	&XX_uauth[0],
	&XX_uauth[0]
};
static struct entry XX_usermgr_add[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_usermgr_add[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_add[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_add[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_add[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_usermgr_add[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_add[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_usermgr_add = {
	0,
	ADT_usermgr_add,
	AUE_usermgr_add,
	7,
	&XX_usermgr_add[0],
	&XX_usermgr_add[0]
};
static struct entry XX_usermgr_delete[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_usermgr_delete[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_delete[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_delete[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_delete[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_usermgr_delete[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_delete[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_usermgr_delete = {
	0,
	ADT_usermgr_delete,
	AUE_usermgr_delete,
	7,
	&XX_usermgr_delete[0],
	&XX_usermgr_delete[0]
};
static struct entry XX_usermgr_modify[7] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_usermgr_modify[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_modify[2]),
		0,	1,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_modify[3]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_modify[4]),
		0,	1,	0,	NULL},
	{AUT_UAUTH,	1,	&adr1[0],	&(XX_usermgr_modify[5]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_usermgr_modify[6]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_usermgr_modify = {
	0,
	ADT_usermgr_modify,
	AUE_usermgr_modify,
	7,
	&XX_usermgr_modify[0],
	&XX_usermgr_modify[0]
};
static struct entry XX_zlogin[3] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_zlogin[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_zlogin[2]),
		0,	0,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_zlogin = {
	0,
	ADT_zlogin,
	AUE_zlogin,
	3,
	&XX_zlogin[0],
	&XX_zlogin[0]
};
static struct entry XX_zone_state[4] = {
	{AUT_SUBJECT,	1,	NULL,	&(XX_zone_state[1]),
		0,	0,	0,	NULL},
	{AUT_TEXT,	1,	&adr1[0],	&(XX_zone_state[2]),
		0,	1,	0,	NULL},
	{AUT_ZONENAME,	1,	&adr1[0],	&(XX_zone_state[3]),
		0,	1,	0,	NULL},
	{AUT_RETURN,	1,	NULL,	NULL,
		0,	0,	0,	NULL}
};
static struct translation X_zone_state = {
	0,
	ADT_zone_state,
	AUE_zone_state,
	4,
	&XX_zone_state[0],
	&XX_zone_state[0]
};
struct translation *xlate_table[41] = {
	&X_admin_authenticate,
	&X_filesystem_add,
	&X_filesystem_delete,
	&X_filesystem_modify,
	&X_inetd_connect,
	&X_inetd_copylimit,
	&X_inetd_failrate,
	&X_inetd_ratelimit,
	&X_init_solaris,
	&X_login,
	&X_logout,
	&X_network_add,
	&X_network_delete,
	&X_network_modify,
	&X_passwd,
	&X_printer_add,
	&X_printer_delete,
	&X_printer_modify,
	&X_prof_cmd,
	&X_rlogin,
	&X_role_login,
	&X_role_logout,
	&X_scheduledjob_add,
	&X_scheduledjob_delete,
	&X_scheduledjob_modify,
	&X_screenlock,
	&X_screenunlock,
	&X_serialport_add,
	&X_serialport_delete,
	&X_serialport_modify,
	&X_ssh,
	&X_su,
	&X_su_logout,
	&X_telnet,
	&X_uauth,
	&X_usermgr_add,
	&X_usermgr_delete,
	&X_usermgr_modify,
	&X_zlogin,
	&X_zone_state,
	NULL
};

void
adt_preload(au_event_t event_id, adt_event_data_t *event_data)
{
	switch (event_id) {
	case ADT_prof_cmd:
		event_data->adt_prof_cmd.proc_auid = AU_NOAUDITID;
		event_data->adt_prof_cmd.proc_euid = AU_NOAUDITID;
		event_data->adt_prof_cmd.proc_egid = AU_NOAUDITID;
		event_data->adt_prof_cmd.proc_ruid = AU_NOAUDITID;
		event_data->adt_prof_cmd.proc_rgid = AU_NOAUDITID;
		break;
	default:
		break;
	}
}
#endif

/* message lists */

static char *msg_fail_value[24] = {
	"Attribute update",
	"Password update",
	"bad username",
	"authorization failed",
	"bad uid",
	"unknown failure",
	"password expired",
	"Account is locked",
	"Bad dial up",
	"Invalid ID",
	"Invalid password",
	"Not on console",
	"Too many failed attempts",
	"Protocol failure",
	"Excluded user",
	"No anonymous",
	"Invalid command",
	"Standard input not a tty line",
	"Program failure",
	"chdir to home directory",
	"Input line too long.",
	"login device override",
	"authorization bypass",
	"login disabled"
};
/* Deprecated message list */
static char *msg_login_text[10] = {
	NULL,
	"Account is locked",
	"Bad dial up",
	"Invalid ID",
	"Invalid password",
	"Not on console",
	"Too many failed attempts",
	"Protocol failure",
	"Excluded user",
	"No anonymous"
};

struct msg_text adt_msg_text[3] = {
	{0, -1, NULL, -2000},
	{0, 23, msg_fail_value, -1000},
	{0, 9, msg_login_text, 0}
};
