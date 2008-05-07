/***************************************************************************
 *
 * libpolkit-rbac.c : RBAC implementation of the libpolkit API
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <auth_attr.h>
#include <secdb.h>

#include <glib.h>
#include <dbus/dbus-glib.h>

#include "libpolkit.h"

#define LIBPOLKIT_MAGIC 0x3117beef

#ifdef __SUNPRO_C
#define __FUNCTION__ __func__
#endif

#define LIBPOLKIT_CHECK_CONTEXT(_ctx_, _ret_)				\
	do {									\
		if (_ctx_ == NULL) {						\
			g_warning ("%s: given LibPolKitContext is NULL",     \
				   __FUNCTION__);			        \
			return _ret_;					        \
		}								\
		if (_ctx_->magic != LIBPOLKIT_MAGIC) {			\
			g_warning ("%s: given LibPolKitContext is invalid (read magic 0x%08x, should be 0x%08x)",  \
				   __FUNCTION__, _ctx_->magic, LIBPOLKIT_MAGIC);	\
			return _ret_;					        \
		}								\
	} while(0)


struct LibPolKitContext_s
{
	guint32 magic;
};

/** Get a new context.
 *
 *  @return                     Pointer to new context or NULL if an error occured
 */
LibPolKitContext *
libpolkit_new_context (DBusConnection *connection)
{
	LibPolKitContext *ctx;

	ctx = g_new0 (LibPolKitContext, 1);
	ctx->magic = LIBPOLKIT_MAGIC;

	return ctx;
}

/** Free a context
 *
 *  @param  ctx                 The context obtained from libpolkit_new_context
 *  @return                     Pointer to new context or NULL if an error occured
 */
gboolean
libpolkit_free_context (LibPolKitContext *ctx)
{
	LIBPOLKIT_CHECK_CONTEXT (ctx, FALSE);

	ctx->magic = 0;
	g_free (ctx);
	return TRUE;		
}

LibPolKitResult 
libpolkit_get_allowed_resources_for_privilege_for_uid (LibPolKitContext    *ctx,
						       const char          *user, 
						       const char          *privilege, 
						       GList              **resources,
						       GList              **restrictions,
						       int                 *num_non_temporary)
{
	LibPolKitResult res;
	char **resource_list;
	int num_resources;
	char **restriction_list;
	int num_restrictions;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	res = LIBPOLKIT_RESULT_ERROR;
	*resources = NULL;
	*restrictions = NULL;

	res = LIBPOLKIT_RESULT_OK;

	return res;
}

LibPolKitResult 
libpolkit_is_uid_allowed_for_privilege (LibPolKitContext   *ctx,
					const char         *system_bus_unique_name, 
					const char         *user, 
					const char         *privilege, 
					const char         *resource,
					gboolean           *out_is_allowed,
					gboolean           *out_is_temporary,
					char              **out_is_privileged_but_restricted_to_system_bus_unique_name)
{
	LibPolKitResult res;
	const char *myresource = "";
	const char *mysystem_bus_unique_name = "";
	char *but_restricted_to = NULL;
	uid_t uid;
	struct passwd *pw;
	char *authname;
	int i;
	gboolean authname_free = FALSE;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	uid = (uid_t)atol (user);
	if ((pw = getpwuid (uid)) == NULL) {
		*out_is_allowed = FALSE;
		*out_is_temporary = FALSE;
		return LIBPOLKIT_RESULT_NO_SUCH_USER;
	}

	/* map PolicyKit privilege to RBAC authorization */
	if (strcmp (privilege, "hal-storage-removable-mount") == 0) {
		authname = "solaris.device.mount.removable";
	} else if (strcmp (privilege, "hal-storage-removable-mount-all-options") == 0) {
		authname = "solaris.device.mount.alloptions.removable";
	} else if (strcmp (privilege, "hal-storage-fixed-mount") == 0) {
		authname = "solaris.device.mount.fixed";
	} else if (strcmp (privilege, "hal-storage-fixed-mount-all-options") == 0) {
		authname = "solaris.device.mount.alloptions.fixed";
	} else if (strcmp(privilege, "hal-power-suspend") == 0) {
		authname = "solaris.system.power.suspend.ram";
	} else if (strcmp(privilege, "hal-power-hibernate") == 0) {
                authname = "solaris.system.power.suspend.disk";
	} else if ((strcmp(privilege, "hal-power-shutdown") == 0) ||
	    (strcmp(privilege, "hal-power-reboot") == 0)) {
                authname = "solaris.system.shutdown";
	} else if (strcmp(privilege, "hal-power-cpu") == 0) {
                authname = "solaris.system.power.cpu";
	} else if (strcmp(privilege, "hal-power-brightness") == 0) {
                authname = "solaris.system.power.brightness";
	} else {
		/* replace '-' with '.' */
		authname = g_strdup (privilege);
		authname_free = TRUE;
		for (i = 0; i < strlen (authname); i++) {
			if (authname[i] == '-') {
				authname[i] = '.';
			}
		}
	}

	*out_is_allowed = (chkauthattr(authname, pw->pw_name) != 0);
	*out_is_temporary = FALSE;

	if (authname_free) {
		g_free(authname);
	}

	return LIBPOLKIT_RESULT_OK;
}

LibPolKitResult
libpolkit_get_privilege_list (LibPolKitContext      *ctx,
			      GList                **result)
{
	LibPolKitResult res;
	char **privilege_list;
	int num_privileges = 0;
	int i;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	*result = NULL;

	for (i = 0; i < num_privileges; i++) {
		*result = g_list_append (*result, g_strdup (privilege_list[i]));
	}

	res = LIBPOLKIT_RESULT_OK;

	return res;
}

LibPolKitResult
libpolkit_revoke_temporary_privilege (LibPolKitContext      *ctx,
                                      const char            *user,
                                      const char            *privilege,
                                      const char            *resource,
                                      gboolean              *result)
{
	return LIBPOLKIT_RESULT_OK;
}
