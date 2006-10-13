/***************************************************************************
 *
 * libpolkit.h : Wraps a subset of methods on the PolicyKit daemon
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef LIBPOLKIT_H
#define LIBPOLKIT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <dbus/dbus.h>

typedef enum {
	LIBPOLKIT_RESULT_OK,
	LIBPOLKIT_RESULT_ERROR,
	LIBPOLKIT_RESULT_INVALID_CONTEXT,
	LIBPOLKIT_RESULT_NOT_PRIVILEGED,
	LIBPOLKIT_RESULT_NO_SUCH_PRIVILEGE,
	LIBPOLKIT_RESULT_NO_SUCH_USER
} LibPolKitResult;

struct LibPolKitContext_s;
typedef struct LibPolKitContext_s LibPolKitContext;

LibPolKitContext  *libpolkit_new_context                              (DBusConnection        *connection);

gboolean           libpolkit_free_context                             (LibPolKitContext      *ctx);

LibPolKitResult    libpolkit_get_privilege_list                       (LibPolKitContext      *ctx,
								       GList                **result);

LibPolKitResult    libpolkit_is_uid_allowed_for_privilege             (LibPolKitContext      *ctx,
								       const char            *system_bus_unique_name, 
								       const char            *user, 
								       const char            *privilege, 
								       const char            *resource,
								       gboolean              *out_is_allowed,
								       gboolean              *out_is_temporary,
								       char                 **out_is_privileged_but_restricted_to_system_bus_unique_name);

LibPolKitResult    libpolkit_revoke_temporary_privilege               (LibPolKitContext      *ctx,
								       const char            *user, 
								       const char            *privilege, 
								       const char            *resource,
								       gboolean              *result);

LibPolKitResult    libpolkit_get_allowed_resources_for_privilege_for_uid (LibPolKitContext      *ctx,
									  const char            *user, 
									  const char            *privilege, 
									  GList                **resources,
									  GList                **restrictions,
									  int                   *num_non_temporary);

#endif /* LIBPOLKIT_H */


