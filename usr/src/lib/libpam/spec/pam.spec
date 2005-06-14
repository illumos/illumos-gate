#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libpam/spec/pam.spec

function	pam_acct_mgmt
include		<security/pam_appl.h>
declaration	int pam_acct_mgmt(pam_handle_t *pamh, int flags)
version		SUNW_1.1
exception	($return == PAM_USER_UNKNOWN	|| \
			$return == PAM_AUTH_ERR	|| \
			$return == PAM_NEW_AUTHTOK_REQD	|| \
			$return == PAM_ACCT_EXPIRED	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_authenticate
include		<security/pam_appl.h>
declaration	int pam_authenticate(pam_handle_t *pamh, int flags)
version		SUNW_1.1
exception	($return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR		|| \
			$return == PAM_SERVICE_ERR		|| \
			$return == PAM_SYSTEM_ERR		|| \
			$return == PAM_BUF_ERR		|| \
			$return == PAM_CONV_ERR		|| \
			$return == PAM_PERM_DENIED		|| \
			$return == PAM_AUTH_ERR		|| \
			$return == PAM_CRED_INSUFFICIENT	|| \
			$return == PAM_AUTHINFO_UNAVAIL	|| \
			$return == PAM_USER_UNKNOWN		|| \
			$return == PAM_MAXTRIES)
end		

function	pam_chauthtok
include		<security/pam_appl.h>
declaration	int pam_chauthtok(pam_handle_t *pamh, const int flags)
version		SUNW_1.1
exception	($return == PAM_PERM_DENIED		|| \
			$return == PAM_AUTHTOK_ERR		|| \
			$return == PAM_AUTHTOK_RECOVERY_ERR	|| \
			$return == PAM_AUTHTOK_LOCK_BUSY	|| \
			$return == PAM_AUTHTOK_DISABLE_AGING	|| \
			$return == PAM_USER_UNKNOWN		|| \
			$return == PAM_TRY_AGAIN		|| \
			$return == PAM_OPEN_ERR		|| \
			$return == PAM_SYMBOL_ERR		|| \
			$return == PAM_SERVICE_ERR		|| \
			$return == PAM_SYSTEM_ERR		|| \
			$return == PAM_BUF_ERR		|| \
			$return == PAM_CONV_ERR		|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_get_user
include		<security/pam_appl.h>
declaration	int pam_get_user(pam_handle_t *pamh, char **user, \
			const char *prompt)
version		SUNW_1.1
exception	($return == PAM_SUCCESS		|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_open_session
include		<security/pam_appl.h>
declaration	int pam_open_session(pam_handle_t *pamh, int flags)
version		SUNW_1.1
exception	($return == PAM_SESSION_ERR	|| \
			$return == PAM_SUCCESS	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_close_session
include		<security/pam_appl.h>
declaration	int pam_close_session(pam_handle_t *pamh, int flags)
version		SUNW_1.1
exception	($return == PAM_SESSION_ERR	|| \
			$return == PAM_SUCCESS	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_set_data
include		<security/pam_appl.h>
declaration	int pam_set_data(pam_handle_t *pamh, \
			const char *module_data_name, const void *data, \
			void *cleanup)
version		SUNW_1.1
exception	($return == PAM_NO_MODULE_DATA	|| \
			$return == PAM_SUCCESS	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_get_data
include		<security/pam_appl.h>
declaration	int pam_get_data(const pam_handle_t *pamh, \
			const	char *module_data_name, void **data)
version		SUNW_1.1
exception	($return == PAM_NO_MODULE_DATA	|| \
			$return == PAM_SUCCESS	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_set_item
include		<security/pam_appl.h>
declaration	int pam_set_item(pam_handle_t *pamh, int item_type, \
			const void *item)
version		SUNW_1.1
exception	($return == PAM_SUCCESS	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_get_item
include		<security/pam_appl.h>
declaration	int pam_get_item(const pam_handle_t  *pamh, \
			int item_type, void **item)
version		SUNW_1.1
exception	($return == PAM_SUCCESS	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return ==  PAM_PERM_DENIED)
end		

function	pam_setcred
include		<security/pam_appl.h>
declaration	int pam_setcred(pam_handle_t * pamh, int flags)
version		SUNW_1.1
exception	($return == PAM_SUCCESS	|| \
			$return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED	|| \
			$return == PAM_CRED_UNAVAIL	|| \
			$return == PAM_CRED_EXPIRED	|| \
			$return == PAM_USER_UNKNOWN	|| \
			$return == PAM_CRED_ERR)
end		

function	pam_start
include		<security/pam_appl.h>
declaration	int pam_start(const char *service, const char *user, \
			const struct pam_conv *pam_conv, pam_handle_t **pamh)
version		SUNW_1.1
exception	($return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_end
include		<security/pam_appl.h>
declaration	int pam_end(pam_handle_t *pamh, int status)
version		SUNW_1.1
exception	($return == PAM_OPEN_ERR	|| \
			$return == PAM_SYMBOL_ERR	|| \
			$return == PAM_SERVICE_ERR	|| \
			$return == PAM_SYSTEM_ERR	|| \
			$return == PAM_BUF_ERR	|| \
			$return == PAM_CONV_ERR	|| \
			$return == PAM_PERM_DENIED)
end		

function	pam_strerror
include		<security/pam_appl.h>
declaration	const char	*pam_strerror(pam_handle_t*pamh, int errnum)
version		SUNW_1.1
exception	($return == 0)
end		

function	pam_getenv
version		SUNW_1.1
end		

function	pam_getenvlist
version		SUNW_1.1
end		

function	pam_putenv
version		SUNW_1.1
end		

function	__pam_display_msg
version		SUNWprivate_1.1
end		

function	__pam_get_authtok
version		SUNWprivate_1.1
end		

function	__pam_log
version		SUNWprivate_1.1
end		
