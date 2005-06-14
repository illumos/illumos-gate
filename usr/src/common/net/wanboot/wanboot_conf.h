/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_WANBOOT_CONF_H
#define	_WANBOOT_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>
#include <sys/nvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Valid wanboot.conf(4) names
 */
#define	BC_BOOT_FILE			"boot_file"
#define	BC_ROOT_SERVER			"root_server"
#define	BC_ROOT_FILE			"root_file"
#define	BC_ENCRYPTION_TYPE		"encryption_type"
#define	BC_SIGNATURE_TYPE		"signature_type"
#define	BC_CLIENT_AUTHENTICATION	"client_authentication"
#define	BC_SERVER_AUTHENTICATION	"server_authentication"
#define	BC_BOOT_LOGGER			"boot_logger"
#define	BC_RESOLVE_HOSTS		"resolve_hosts"
#define	BC_SYSTEM_CONF			"system_conf"

/*
 * Valid encryption types
 */
#define	BC_ENCRYPTION_3DES		"3des"
#define	BC_ENCRYPTION_AES		"aes"

/*
 * Valid signature types
 */
#define	BC_SIGNATURE_SHA1		"sha1"

/*
 * Valid yes/no options
 */
#define	BC_YES				"yes"
#define	BC_NO				"no"

/*
 * Define some maximum length for a line in wanboot.conf(4):
 */
#define	BC_MAX_LINE_LENGTH		4096

/*
 * Return codes from init_bootconf(); if BC_FAILURE, the 'bc_error_code'
 * field below gives the reason:
 */
#define	BC_SUCCESS			0
#define	BC_FAILURE			1

/*
 * Possible values of the 'bc_error_code' field below; refer to
 * bootconf_errmsg.c for a description of these codes:
 */
typedef enum {
	BC_E_NOERROR,
	BC_E_ACCESS,
	BC_E_NVLIST,
	BC_E_IOERR,
	BC_E_TOO_LONG,
	BC_E_SYNTAX,
	BC_E_UNKNOWN_NAME,
	BC_E_ENCRYPTION_ILLEGAL,
	BC_E_SIGNATURE_ILLEGAL,
	BC_E_CLIENT_AUTH_ILLEGAL,
	BC_E_SERVER_AUTH_ILLEGAL,
	BC_E_ROOT_SERVER_BAD,
	BC_E_ROOT_SERVER_ABSENT,
	BC_E_ROOT_FILE_ABSENT,
	BC_E_BOOT_LOGGER_BAD,
	BC_E_ENCRYPTED_NOT_SIGNED,
	BC_E_CLIENT_AUTH_NOT_ENCRYPTED,
	BC_E_CLIENT_AUTH_NOT_SERVER,
	BC_E_SERVER_AUTH_NOT_SIGNED,
	BC_E_SERVER_AUTH_NOT_HTTPS,
	BC_E_SERVER_AUTH_NOT_HTTP,
	BC_E_BOOTLOGGER_AUTH_NOT_HTTP
} bc_errcode_t;

/*
 * Structure defining the bootconf context:
 */
typedef struct bc_handle {
	nvlist_t	*bc_nvl;	/* The nvpair list representation */
	bc_errcode_t	bc_error_code;	/* On error, one of the above codes */
	int		bc_error_pos;	/* Line in error in wanboot.conf */
} bc_handle_t;

/*
 * The interfaces to be used when accessing the wanboot.conf file:
 */
extern int	bootconf_init(bc_handle_t *handle, const char *bootconf);
extern char	*bootconf_get(bc_handle_t *handle, const char *name);
extern void	bootconf_end(bc_handle_t *handle);
#if	!defined(_BOOT)
extern char	*bootconf_errmsg(bc_handle_t *handle);
#endif	/* !defined(_BOOT) */

#ifdef	__cplusplus
}
#endif

#endif	/* _WANBOOT_CONF_H */
