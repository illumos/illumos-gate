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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

#include "libscf_impl.h"

#include <assert.h>
#include <dlfcn.h>
#include <libintl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/machelf.h>
#include <thread.h>

#include <ucontext.h>

extern int ndebug;

static struct scf_error_info {
	scf_error_t	ei_code;
	const char	*ei_desc;
} scf_errors[] = {
	{SCF_ERROR_NONE,		"no error"},
	{SCF_ERROR_NOT_BOUND,		"handle not bound"},
	{SCF_ERROR_NOT_SET,		"cannot use unset argument"},
	{SCF_ERROR_NOT_FOUND,		"entity not found"},
	{SCF_ERROR_TYPE_MISMATCH,	"type does not match value"},
	{SCF_ERROR_IN_USE,		"cannot modify while in-use"},
	{SCF_ERROR_CONNECTION_BROKEN,	"connection to repository broken"},
	{SCF_ERROR_INVALID_ARGUMENT,	"invalid argument"},
	{SCF_ERROR_NO_MEMORY,		"no memory available"},
	{SCF_ERROR_CONSTRAINT_VIOLATED,	"required constraint not met"},
	{SCF_ERROR_EXISTS,		"object already exists"},
	{SCF_ERROR_NO_SERVER,		"repository server unavailable"},
	{SCF_ERROR_NO_RESOURCES,	"server has insufficient resources"},
	{SCF_ERROR_PERMISSION_DENIED,	"insufficient privileges for action"},
	{SCF_ERROR_BACKEND_ACCESS,	"backend refused access"},
	{SCF_ERROR_BACKEND_READONLY,	"backend is read-only"},
	{SCF_ERROR_HANDLE_MISMATCH,	"mismatched SCF handles"},
	{SCF_ERROR_HANDLE_DESTROYED,	"object bound to destroyed handle"},
	{SCF_ERROR_VERSION_MISMATCH,	"incompatible SCF version"},
	{SCF_ERROR_DELETED,		"object has been deleted"},
	{SCF_ERROR_TEMPLATE_INVALID,	"template data is invalid"},

	{SCF_ERROR_CALLBACK_FAILED,	"user callback function failed"},

	{SCF_ERROR_INTERNAL,		"internal error"}
};
#define	SCF_NUM_ERRORS	(sizeof (scf_errors) / sizeof (*scf_errors))

/* a SWAG just in case things get out of sync, we can notice */
#define	LOOKS_VALID(e)	\
	((e) >= scf_errors[0].ei_code && \
	    (e) < scf_errors[SCF_NUM_ERRORS - 1].ei_code + 10)

static scf_error_t	_scf_fallback_error = SCF_ERROR_NONE;

#if defined(PTHREAD_ONCE_KEY_NP)

static pthread_key_t	scf_error_key = PTHREAD_ONCE_KEY_NP;

int
scf_setup_error(void)
{
	return (pthread_key_create_once_np(&scf_error_key, NULL) == 0);
}

#else	/* PTHREAD_ONCE_KEY_NP */

/*
 * This old code is here to enable the building of a native version
 * of libscf.so when the build machine has not yet been upgraded
 * to a version of libc that provides pthread_key_create_once_np().
 * It should be deleted when solaris_nevada ships.
 * This code is not MT-safe in a relaxed memory model.
 */

static pthread_key_t	scf_error_key = 0;

int
scf_setup_error(void)
{
	static pthread_mutex_t scf_key_lock = PTHREAD_MUTEX_INITIALIZER;
	static volatile int scf_error_key_setup = 0;

	if (scf_error_key_setup == 0) {
		(void) pthread_mutex_lock(&scf_key_lock);
		if (scf_error_key_setup == 0) {
			if (pthread_key_create(&scf_error_key, NULL) == 0)
				scf_error_key_setup = 1;
		}
		(void) pthread_mutex_unlock(&scf_key_lock);
	}

	return (scf_error_key_setup == 1);
}

#endif	/* PTHREAD_ONCE_KEY_NP */

int
scf_set_error(scf_error_t code)
{
	assert(LOOKS_VALID(code));

	if (scf_setup_error())
		(void) pthread_setspecific(scf_error_key, (void *)code);
	else
		_scf_fallback_error = code;
	return (-1);
}

scf_error_t
scf_error(void)
{
	scf_error_t ret;

	ret = (scf_error_t)pthread_getspecific(scf_error_key);
	if (ret == 0)
		return (_scf_fallback_error);
	assert(LOOKS_VALID(ret));
	return (ret);
}

const char *
scf_strerror(scf_error_t code)
{
	struct scf_error_info *cur, *end;

	cur = scf_errors;
	end = cur + SCF_NUM_ERRORS;

	for (; cur < end; cur++)
		if (code == cur->ei_code)
			return (dgettext(TEXT_DOMAIN, cur->ei_desc));

	return (dgettext(TEXT_DOMAIN, "unknown error"));
}

const char *
scf_get_msg(scf_msg_t msg)
{
	switch (msg) {
	case SCF_MSG_ARGTOOLONG:
		return (dgettext(TEXT_DOMAIN,
		    "Argument '%s' is too long, ignoring\n"));

	case SCF_MSG_PATTERN_NOINSTANCE:
		return (dgettext(TEXT_DOMAIN,
		    "Pattern '%s' doesn't match any instances\n"));

	case SCF_MSG_PATTERN_NOINSTSVC:
		return (dgettext(TEXT_DOMAIN,
		    "Pattern '%s' doesn't match any instances or services\n"));

	case SCF_MSG_PATTERN_NOSERVICE:
		return (dgettext(TEXT_DOMAIN,
		    "Pattern '%s' doesn't match any services\n"));

	case SCF_MSG_PATTERN_NOENTITY:
		return (dgettext(TEXT_DOMAIN,
		    "Pattern '%s' doesn't match any entities\n"));

	case SCF_MSG_PATTERN_MULTIMATCH:
		return (dgettext(TEXT_DOMAIN,
		    "Pattern '%s' matches multiple instances:\n"));

	case SCF_MSG_PATTERN_POSSIBLE:
		return (dgettext(TEXT_DOMAIN, "    %s\n"));

	case SCF_MSG_PATTERN_LEGACY:
		return (dgettext(TEXT_DOMAIN,
		    "Operation not supported for legacy service '%s'\n"));

	case SCF_MSG_PATTERN_MULTIPARTIAL:
		return (dgettext(TEXT_DOMAIN,
		    "Partial FMRI matches multiple instances\n"));

	default:
		abort();
		/* NOTREACHED */
	}

}
