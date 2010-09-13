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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <stdio.h>
#include "wanboot_conf.h"

/*
 * This function maps an error code (one of those defined in wanboot_conf.h)
 * into an error message.
 *
 * Returns: the error message string.
 */
char *
bootconf_errmsg(bc_handle_t *handle)
{
	static char	errmsg[256];
	char		*errstr;
	int		chars;

	errstr = gettext("bootconf_errmsg: internal error");

	switch (handle->bc_error_code) {
	case BC_E_NOERROR:
		errstr = gettext("No error");
		break;
	case BC_E_ACCESS:
		errstr = gettext("Can't open configuration file");
		break;
	case BC_E_NVLIST:
		errstr = gettext("Error creating/adding to nvlist");
		break;
	case BC_E_IOERR:
		errstr = gettext("Error reading/closing configuration file");
		break;
	case BC_E_TOO_LONG:
		if ((chars = snprintf(errmsg, sizeof (errmsg),
		    gettext("Line %d of configuration file is too long"),
		    handle->bc_error_pos)) > 0 && chars < sizeof (errmsg)) {
			errstr = errmsg;
		}
		break;
	case BC_E_SYNTAX:
		if ((chars = snprintf(errmsg, sizeof (errmsg),
		    gettext("Syntax error on line %d of configuration file"),
		    handle->bc_error_pos)) > 0 && chars < sizeof (errmsg)) {
			errstr = errmsg;
		}
		break;
	case BC_E_UNKNOWN_NAME:
		if ((chars = snprintf(errmsg, sizeof (errmsg),
		    gettext("Unknown name on line %d of configuration file"),
		    handle->bc_error_pos)) > 0 && chars < sizeof (errmsg)) {
			errstr = errmsg;
		}
		break;
	case BC_E_ENCRYPTION_ILLEGAL:
		errstr = gettext("Illegal encryption_type");
		break;
	case BC_E_SIGNATURE_ILLEGAL:
		errstr = gettext("Illegal signature_type");
		break;
	case BC_E_CLIENT_AUTH_ILLEGAL:
		errstr = gettext("Illegal client_authentication");
		break;
	case BC_E_SERVER_AUTH_ILLEGAL:
		errstr = gettext("Illegal server_authentication");
		break;
	case BC_E_ROOT_SERVER_BAD:
		errstr = gettext("The root_server URL is malformed");
		break;
	case BC_E_ROOT_SERVER_ABSENT:
		errstr = gettext("A root_server must be provided");
		break;
	case BC_E_ROOT_FILE_ABSENT:
		errstr = gettext("The root_server URL is malformed");
		break;
	case BC_E_BOOT_LOGGER_BAD:
		errstr = gettext("The boot_logger URL is malformed");
		break;
	case BC_E_ENCRYPTED_NOT_SIGNED:
		errstr = gettext("When encryption_type is specified "
		    "signature_type must also be specified");
		break;
	case BC_E_CLIENT_AUTH_NOT_ENCRYPTED:
		errstr = gettext("When client_authentication is \"yes\" "
		    "encryption_type must also be specified");
		break;
	case BC_E_CLIENT_AUTH_NOT_SERVER:
		errstr = gettext("When client_authentication is \"yes\" "
		    "server_authentication must also be \"yes\"");
		break;
	case BC_E_SERVER_AUTH_NOT_SIGNED:
		errstr = gettext("When server_authentication is \"yes\" "
		    "signature_type must also be specified");
		break;
	case BC_E_SERVER_AUTH_NOT_HTTPS:
		errstr = gettext("When server_authentication is \"yes\" "
		    "root_server must specify a secure URL");
		break;
	case BC_E_SERVER_AUTH_NOT_HTTP:
		errstr = gettext("When server_authentication is \"no\" "
		    "root_server must not specify a secure URL");
		break;
	case BC_E_BOOTLOGGER_AUTH_NOT_HTTP:
		errstr = gettext("When server_authentication is \"no\" "
		    "boot_logger must not specify a secure URL");
		break;
	default:
		if ((chars = snprintf(errmsg, sizeof (errmsg),
		    gettext("Unknown error %d"),
		    handle->bc_error_code)) > 0 && chars < sizeof (errmsg)) {
			errstr = errmsg;
		}
	}

	return (errstr);
}
