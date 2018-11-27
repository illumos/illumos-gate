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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Functions for managing thread-local storage for LDAP, and in particular
 * for managing storage of the LDAP error state.
 */

#include <ldap.h>
#include <pthread.h>
#include <errno.h>
#include <note.h>
#include <syslog.h>
#include <string.h>
#include "solaris-int.h"	/* This is a libladp5 private include file */
				/* which has the defintion for */
				/* struct ldap_extra_thread_fns */
#include "adutils_impl.h"

struct adutils_lderrno {
	int le_errno;
	char *le_matched;
	char *le_errmsg;
};

static void *adutils_threadid(void);
static void *adutils_mutex_alloc(void);
static void adutils_mutex_free(void *mutexp);
static int adutils_get_errno(void);
static void adutils_set_errno(int err);
static void adutils_set_lderrno(int err, char *matched, char *errmsg,
    void *dummy);
static int adutils_get_lderrno(char **matched, char **errmsg, void *dummy);
static void adutils_lderrno_destructor(void *tsd);

static pthread_key_t adutils_lderrno_key = PTHREAD_ONCE_KEY_NP;

static struct ldap_thread_fns thread_fns = {
	.ltf_mutex_alloc = adutils_mutex_alloc,
	.ltf_mutex_free = adutils_mutex_free,
	.ltf_mutex_lock = (int (*)(void *)) pthread_mutex_lock,
	.ltf_mutex_unlock = (int (*)(void *)) pthread_mutex_unlock,
	.ltf_get_errno = adutils_get_errno,
	.ltf_set_errno = adutils_set_errno,
	.ltf_get_lderrno = adutils_get_lderrno,
	.ltf_set_lderrno = adutils_set_lderrno,
	.ltf_lderrno_arg = NULL
};

struct ldap_extra_thread_fns extra_thread_fns = {
	.ltf_threadid_fn = adutils_threadid
};

/*
 * Set up thread management functions for the specified LDAP session.
 * Returns either LDAP_SUCCESS or -1.
 */
int
adutils_set_thread_functions(LDAP *ld)
{
	int rc;

	if (adutils_lderrno_key == PTHREAD_ONCE_KEY_NP) {
		if ((rc = pthread_key_create_once_np(&adutils_lderrno_key,
		    adutils_lderrno_destructor)) != 0) {
			logger(LOG_ERR, "adutils_set_thread_functions() "
			    "pthread_key_create_once_np failed (%s)",
			    strerror(rc));
			rc = -1;
			return (rc);
		}
	}

	rc = ldap_set_option(ld, LDAP_OPT_THREAD_FN_PTRS,
	    &thread_fns);
	if (rc != LDAP_SUCCESS) {
		logger(LOG_ERR,
		    "ldap_set_option LDAP_OPT_THREAD_FN_PTRS failed");
		return (rc);
	}

	rc = ldap_set_option(ld, LDAP_OPT_EXTRA_THREAD_FN_PTRS,
	    &extra_thread_fns);
	if (rc != LDAP_SUCCESS) {
		logger(LOG_ERR,
		    "ldap_set_option LDAP_OPT_EXTRA_THREAD_FN_PTRS failed");
		return (rc);
	}
	return (rc);
}

static void *
adutils_threadid(void)
{
	return ((void *)(uintptr_t)pthread_self());
}

/*
 * Allocate a mutex.
 */
static
void *
adutils_mutex_alloc(void)
{
	pthread_mutex_t *mutexp;
	int rc;

	mutexp = malloc(sizeof (pthread_mutex_t));
	if (mutexp == NULL) {
		logger(LOG_ERR,
		    "adutils_mutex_alloc: malloc failed (%s)",
		    strerror(errno));
		return (NULL);
	}

	rc = pthread_mutex_init(mutexp, NULL);
	if (rc != 0) {
		logger(LOG_ERR,
		    "adutils_mutex_alloc: "
		    "pthread_mutex_init failed (%s)",
		    strerror(rc));
		free(mutexp);
		return (NULL);
	}
	return (mutexp);
}

/*
 * Free a mutex.
 */
static
void
adutils_mutex_free(void *mutexp)
{
	(void) pthread_mutex_destroy((pthread_mutex_t *)mutexp);
	free(mutexp);
}

/*
 * Get the thread's local errno.
 */
static
int
adutils_get_errno(void)
{
	return (errno);
}

/*
 * Set the thread's local errno.
 */
static
void
adutils_set_errno(int err)
{
	errno = err;
}

/*
 * Get a pointer to the thread's local LDAP error state structure.
 * Lazily allocate the thread-local storage, so that we don't need
 * initialization when each thread starts.
 */
static
struct adutils_lderrno *
adutils_get_lderrno_struct(void)
{
	struct adutils_lderrno *le;
	int rc;

	le = pthread_getspecific(adutils_lderrno_key);
	if (le == NULL) {
		le = calloc(1, sizeof (*le));
		if (le == NULL) {
			logger(LOG_ERR,
			    "adutils_get_lderrno_struct:  calloc failed (%s)",
			    strerror(errno));
			return (NULL);
		}
		rc = pthread_setspecific(adutils_lderrno_key, le);
		if (rc != 0) {
			logger(LOG_ERR,
			    "adutils_get_lderrno_struct:  "
			    "pthread_setspecific failed (%s)",
			    strerror(rc));
			free(le);
			return (NULL);
		}
	}

	return (le);
}

/*
 * Store an error report in the thread's local LDAP error state structure.
 */
static
void
adutils_set_lderrno(int err, char *matched, char *errmsg, void *dummy)
{
	NOTE(ARGUNUSED(dummy))
	struct adutils_lderrno *le;

	le = adutils_get_lderrno_struct();
	if (le != NULL) {
		le->le_errno = err;
		if (le->le_matched != NULL)
			ldap_memfree(le->le_matched);
		le->le_matched = matched;
		if (le->le_errmsg != NULL)
			ldap_memfree(le->le_errmsg);
		le->le_errmsg = errmsg;
	}
}

/*
 * Retrieve an error report from the thread's local LDAP error state structure.
 */
static
int
adutils_get_lderrno(char **matched, char **errmsg, void *dummy)
{
	NOTE(ARGUNUSED(dummy))
	struct adutils_lderrno *le;
	static struct adutils_lderrno empty = { LDAP_SUCCESS, NULL, NULL };

	le = adutils_get_lderrno_struct();
	if (le == NULL)
		le = &empty;

	if (matched != NULL)
		*matched = le->le_matched;
	if (errmsg != NULL)
		*errmsg = le->le_errmsg;
	return (le->le_errno);
}

/*
 * Free the thread's local LDAP error state structure.
 */
static
void
adutils_lderrno_destructor(void *tsd)
{
	struct adutils_lderrno *le = tsd;

	if (le == NULL)
		return;

	if (le->le_matched != NULL) {
		ldap_memfree(le->le_matched);
		le->le_matched = NULL;
	}
	if (le->le_errmsg != NULL) {
		ldap_memfree(le->le_errmsg);
		le->le_errmsg = NULL;
	}
	free(le);
}
