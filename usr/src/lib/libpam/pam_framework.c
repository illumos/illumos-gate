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
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <syslog.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <strings.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/mman.h>

#include <libintl.h>

#include "pam_impl.h"

static char *pam_snames [PAM_NUM_MODULE_TYPES] = {
	PAM_ACCOUNT_NAME,
	PAM_AUTH_NAME,
	PAM_PASSWORD_NAME,
	PAM_SESSION_NAME
};

static char *pam_inames [PAM_MAX_ITEMS] = {
/* NONE */		NULL,
/* PAM_SERVICE */	"service",
/* PAM_USER */		"user",
/* PAM_TTY */		"tty",
/* PAM_RHOST */		"rhost",
/* PAM_CONV */		"conv",
/* PAM_AUTHTOK */	"authtok",
/* PAM_OLDAUTHTOK */	"oldauthtok",
/* PAM_RUSER */		"ruser",
/* PAM_USER_PROMPT */	"user_prompt",
/* PAM_REPOSITORY */	"repository",
/* PAM_RESOURCE */	"resource",
/* PAM_AUSER */		"auser",
/* Undefined Items */
};

/*
 * This extra definition is needed in order to build this library
 * on pre-64-bit-aware systems.
 */
#if !defined(_LFS64_LARGEFILE)
#define	stat64	stat
#endif	/* !defined(_LFS64_LARGEFILE) */

/* functions to dynamically load modules */
static int	load_modules(pam_handle_t *, int, char *, pamtab_t *);
static void	*open_module(pam_handle_t *, char *);
static int	load_function(void *, char *, int (**func)());

/* functions to read and store the pam.conf configuration file */
static int	open_pam_conf(struct pam_fh **, pam_handle_t *, char *);
static void	close_pam_conf(struct pam_fh *);
static int	read_pam_conf(pam_handle_t *, char *);
static int	get_pam_conf_entry(struct pam_fh *, pam_handle_t *,
    pamtab_t **);
static char	*read_next_token(char **);
static char	*nextline(struct pam_fh *, pam_handle_t *, int *);
static int	verify_pam_conf(pamtab_t *, char *);

/* functions to clean up and free memory */
static void	clean_up(pam_handle_t *);
static void	free_pamconf(pamtab_t *);
static void	free_pam_conf_info(pam_handle_t *);
static void	free_env(env_list *);

/* convenience functions for I18N/L10N communication */

static void	free_resp(int, struct pam_response *);
static int	do_conv(pam_handle_t *, int, int,
    char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE], void *,
    struct pam_response **);

static int	log_priority;	/* pam_trace syslog priority & facility */
static int	pam_debug = 0;

static char *
pam_trace_iname(int item_type, char *iname_buf)
{
	char *name;

	if (item_type <= 0 ||
	    item_type >= PAM_MAX_ITEMS ||
	    (name = pam_inames[item_type]) == NULL) {
		(void) sprintf(iname_buf, "%d", item_type);
		return (iname_buf);
	}
	return (name);
}

static char *
pam_trace_fname(int flag)
{
	if (flag & PAM_BINDING)
		return (PAM_BINDING_NAME);
	if (flag & PAM_INCLUDE)
		return (PAM_INCLUDE_NAME);
	if (flag & PAM_OPTIONAL)
		return (PAM_OPTIONAL_NAME);
	if (flag & PAM_REQUIRED)
		return (PAM_REQUIRED_NAME);
	if (flag & PAM_REQUISITE)
		return (PAM_REQUISITE_NAME);
	if (flag & PAM_SUFFICIENT)
		return (PAM_SUFFICIENT_NAME);
	return ("bad flag name");
}

static char *
pam_trace_cname(pam_handle_t *pamh)
{
	if (pamh->pam_conf_name[pamh->include_depth] == NULL)
		return ("NULL");
	return (pamh->pam_conf_name[pamh->include_depth]);
}

#include <deflt.h>
#include <stdarg.h>
/*
 * pam_settrace - setup configuration for pam tracing
 *
 * turn on PAM debug if "magic" file exists
 * if exists (original), pam_debug = PAM_DEBUG_DEFAULT,
 * log_priority = LOG_DEBUG(7) and log_facility = LOG_AUTH(4).
 *
 * if has contents, keywork=value pairs:
 *
 *	"log_priority=" 0-7, the pam_trace syslog priority to use
 *		(see sys/syslog.h)
 *	"log_facility=" 0-23, the pam_trace syslog facility to use
 *		(see sys/syslog.h)
 *	"debug_flags=" PAM_DEBUG_DEFAULT (0x0001), log traditional
 *			(original) debugging.
 *		Plus the logical or of:
 *		    PAM_DEBUG_ITEM (0x0002), log item values and
 *			pam_get_item.
 *		    PAM_DEBUG_MODULE (0x0004), log module return status.
 *		    PAM_DEBUG_CONF (0x0008), log pam.conf parsing.
 *		    PAM_DEBUG_DATA (0x0010), get/set_data.
 *		    PAM_DEBUG_CONV (0x0020), conversation/response.
 *
 *		    If compiled with DEBUG:
 *		    PAM_DEBUG_AUTHTOK (0x8000), display AUTHTOK value if
 *				PAM_DEBUG_ITEM is set and results from
 *				PAM_PROMPT_ECHO_OFF responses.
 *		    USE CAREFULLY, THIS EXPOSES THE USER'S PASSWORDS.
 *
 *		or set to 0 and off even if PAM_DEBUG file exists.
 *
 * Output has the general form:
 * <whatever was set syslog> PAM[<pid>]: <interface>(<handle> and other info)
 * <whatever was set syslog> PAM[<pid>]: details requested for <interface> call
 *	Where:	<pid> is the process ID of the calling process.
 *		<handle> is the Hex value of the pam_handle associated with the
 *			call.
 */

static void
pam_settrace()
{
	void	*defp;

	if ((defp = defopen_r(PAM_DEBUG)) != NULL) {
		char	*arg;
		int	code;
		int	facility = LOG_AUTH;

		pam_debug = PAM_DEBUG_DEFAULT;
		log_priority = LOG_DEBUG;

		(void) defcntl_r(DC_SETFLAGS, DC_CASE, defp);
		if ((arg = defread_r(LOG_PRIORITY, defp)) != NULL) {
			code = (int)strtol(arg, NULL, 10);
			if ((code & ~LOG_PRIMASK) == 0) {
				log_priority = code;
			}
		}
		if ((arg = defread_r(LOG_FACILITY, defp)) != NULL) {
			code = (int)strtol(arg, NULL, 10);
			if (code < LOG_NFACILITIES) {
				facility = code << 3;
			}
		}
		if ((arg = defread_r(DEBUG_FLAGS, defp)) != NULL) {
			pam_debug = (int)strtol(arg, NULL, 0);
		}
		defclose_r(defp);

		log_priority |= facility;
	}
}

/*
 * pam_trace - logs tracing messages
 *
 *	flag = debug_flags from /etc/pam_debug
 *	format and args = message to print (PAM[<pid>]: is prepended).
 *
 *	global log_priority = pam_trace syslog (log_priority | log_facility)
 *		from /etc/pam_debug
 */
/*PRINTFLIKE2*/
static void
pam_trace(int flag, char *format, ...)
{
	va_list args;
	char message[1024];
	int savemask;

	if ((pam_debug & flag) == 0)
		return;

	savemask = setlogmask(LOG_MASK(log_priority & LOG_PRIMASK));
	(void) snprintf(message, sizeof (message), "PAM[%ld]: %s",
	    (long)getpid(), format);
	va_start(args, format);
	(void) vsyslog(log_priority, message, args);
	va_end(args);
	(void) setlogmask(savemask);
}

/*
 * __pam_log - logs PAM syslog messages
 *
 *	priority = message priority
 *	format and args = message to log
 */
/*PRINTFLIKE2*/
void
__pam_log(int priority, const char *format, ...)
{
	va_list args;
	int savemask = setlogmask(LOG_MASK(priority & LOG_PRIMASK));

	va_start(args, format);
	(void) vsyslog(priority, format, args);
	va_end(args);
	(void) setlogmask(savemask);
}


/*
 *			pam_XXXXX routines
 *
 *	These are the entry points to the authentication switch
 */

/*
 * pam_start		- initiate an authentication transaction and
 *			  set parameter values to be used during the
 *			  transaction
 */

int
pam_start(const char *service, const char *user,
    const struct pam_conv *pam_conv, pam_handle_t **pamh)
{
	int	err;

	*pamh = calloc(1, sizeof (struct pam_handle));

	pam_settrace();
	pam_trace(PAM_DEBUG_DEFAULT,
	    "pam_start(%s,%s,%p:%p) - debug = %x",
	    service ? service : "NULL", user ? user : "NULL", (void *)pam_conv,
	    (void *)*pamh, pam_debug);

	if (*pamh == NULL)
		return (PAM_BUF_ERR);

	(*pamh)->pam_inmodule = RO_OK;		/* OK to set RO items */
	if ((err = pam_set_item(*pamh, PAM_SERVICE, (void *)service))
	    != PAM_SUCCESS) {
		clean_up(*pamh);
		*pamh = NULL;
		return (err);
	}

	if ((err = pam_set_item(*pamh, PAM_USER, (void *)user))
	    != PAM_SUCCESS) {
		clean_up(*pamh);
		*pamh = NULL;
		return (err);
	}

	if ((err = pam_set_item(*pamh, PAM_CONV, (void *)pam_conv))
	    != PAM_SUCCESS) {
		clean_up(*pamh);
		*pamh = NULL;
		return (err);
	}

	(*pamh)->pam_inmodule = RW_OK;
	return (PAM_SUCCESS);
}

/*
 * pam_end - terminate an authentication transaction
 */

int
pam_end(pam_handle_t *pamh, int pam_status)
{
	struct pam_module_data *psd, *p;
	fd_list *expired;
	fd_list *traverse;
	env_list *env_expired;
	env_list *env_traverse;

	pam_trace(PAM_DEBUG_DEFAULT,
	    "pam_end(%p): status = %s", (void *)pamh,
	    pam_strerror(pamh, pam_status));

	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	/* call the cleanup routines for module specific data */

	psd = pamh->ssd;
	while (psd) {
		if (psd->cleanup) {
			psd->cleanup(pamh, psd->data, pam_status);
		}
		p = psd;
		psd = p->next;
		free(p->module_data_name);
		free(p);
	}
	pamh->ssd = NULL;

	/* dlclose all module fds */
	traverse = pamh->fd;
	while (traverse) {
		expired = traverse;
		traverse = traverse->next;
		(void) dlclose(expired->mh);
		free(expired);
	}
	pamh->fd = 0;

	/* remove all environment variables */
	env_traverse = pamh->pam_env;
	while (env_traverse) {
		env_expired = env_traverse;
		env_traverse = env_traverse->next;
		free_env(env_expired);
	}

	clean_up(pamh);
	return (PAM_SUCCESS);
}

/*
 * pam_set_item		- set the value of a parameter that can be
 *			  retrieved via a call to pam_get_item()
 */

int
pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
	struct pam_item *pip;
	int	size;
	char	iname_buf[PAM_MAX_MSG_SIZE];

	if (((pam_debug & PAM_DEBUG_ITEM) == 0) || (pamh == NULL)) {
		pam_trace(PAM_DEBUG_DEFAULT,
		    "pam_set_item(%p:%s)", (void *)pamh,
		    pam_trace_iname(item_type, iname_buf));
	}

	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	/* check read only items */
	if ((item_type == PAM_SERVICE) && (pamh->pam_inmodule != RO_OK))
		return (PAM_PERM_DENIED);

	/*
	 * Check that item_type is within valid range
	 */

	if (item_type <= 0 || item_type >= PAM_MAX_ITEMS)
		return (PAM_SYMBOL_ERR);

	pip = &(pamh->ps_item[item_type]);

	switch (item_type) {
	case PAM_AUTHTOK:
	case PAM_OLDAUTHTOK:
		if (pip->pi_addr != NULL)
			(void) memset(pip->pi_addr, 0, pip->pi_size);
		/*FALLTHROUGH*/
	case PAM_SERVICE:
	case PAM_USER:
	case PAM_TTY:
	case PAM_RHOST:
	case PAM_RUSER:
	case PAM_USER_PROMPT:
	case PAM_RESOURCE:
	case PAM_AUSER:
		if (pip->pi_addr != NULL) {
			free(pip->pi_addr);
		}

		if (item == NULL) {
			pip->pi_addr = NULL;
			pip->pi_size = 0;
		} else {
			pip->pi_addr = strdup((char *)item);
			if (pip->pi_addr == NULL) {
				pip->pi_size = 0;
				return (PAM_BUF_ERR);
			}
			pip->pi_size = strlen(pip->pi_addr);
		}
		break;
	case PAM_CONV:
		if (pip->pi_addr != NULL)
			free(pip->pi_addr);
		size = sizeof (struct pam_conv);
		if ((pip->pi_addr = calloc(1, size)) == NULL)
			return (PAM_BUF_ERR);
		if (item != NULL)
			(void) memcpy(pip->pi_addr, item, (unsigned int) size);
		else
			(void) memset(pip->pi_addr, 0, size);
		pip->pi_size = size;
		break;
	case PAM_REPOSITORY:
		if (pip->pi_addr != NULL) {
			pam_repository_t *auth_rep;

			auth_rep = (pam_repository_t *)pip->pi_addr;
			if (auth_rep->type != NULL)
				free(auth_rep->type);
			if (auth_rep->scope != NULL)
				free(auth_rep->scope);
			free(auth_rep);
		}
		if (item != NULL) {
			pam_repository_t *s, *d;

			size = sizeof (struct pam_repository);
			pip->pi_addr = calloc(1, size);
			if (pip->pi_addr == NULL)
				return (PAM_BUF_ERR);

			s = (struct pam_repository *)item;
			d = (struct pam_repository *)pip->pi_addr;

			d->type = strdup(s->type);
			if (d->type == NULL)
				return (PAM_BUF_ERR);
			d->scope = malloc(s->scope_len);
			if (d->scope == NULL)
				return (PAM_BUF_ERR);
			(void) memcpy(d->scope, s->scope, s->scope_len);
			d->scope_len = s->scope_len;
		}
		pip->pi_size = size;
		break;
	default:
		return (PAM_SYMBOL_ERR);
	}
	switch (item_type) {
	case PAM_CONV:
		pam_trace(PAM_DEBUG_ITEM, "pam_set_item(%p:%s)=%p",
		    (void *)pamh,
		    pam_trace_iname(item_type, iname_buf),
		    item ? (void *)((struct pam_conv *)item)->conv :
		    (void *)0);
		break;
	case PAM_REPOSITORY:
		pam_trace(PAM_DEBUG_ITEM, "pam_set_item(%p:%s)=%s",
		    (void *)pamh,
		    pam_trace_iname(item_type, iname_buf),
		    item ? (((struct pam_repository *)item)->type ?
		    ((struct pam_repository *)item)->type : "NULL") :
		    "NULL");
		break;
	case PAM_AUTHTOK:
	case PAM_OLDAUTHTOK:
#ifdef	DEBUG
		if (pam_debug & PAM_DEBUG_AUTHTOK)
			pam_trace(PAM_DEBUG_ITEM,
			    "pam_set_item(%p:%s)=%s", (void *)pamh,
			    pam_trace_iname(item_type, iname_buf),
			    item ? (char *)item : "NULL");
		else
#endif	/* DEBUG */
			pam_trace(PAM_DEBUG_ITEM,
			    "pam_set_item(%p:%s)=%s", (void *)pamh,
			    pam_trace_iname(item_type, iname_buf),
			    item ? "********" : "NULL");
		break;
	default:
		pam_trace(PAM_DEBUG_ITEM, "pam_set_item(%p:%s)=%s",
		    (void *)pamh,
		    pam_trace_iname(item_type, iname_buf),
		    item ? (char *)item : "NULL");
	}

	return (PAM_SUCCESS);
}

/*
 * pam_get_item		- read the value of a parameter specified in
 *			  the call to pam_set_item()
 */

int
pam_get_item(const pam_handle_t *pamh, int item_type, void **item)
{
	struct pam_item *pip;
	char	iname_buf[PAM_MAX_MSG_SIZE];

	if (((pam_debug & PAM_DEBUG_ITEM) == 0) || (pamh == NULL)) {
		pam_trace(PAM_DEBUG_ITEM, "pam_get_item(%p:%s)",
		    (void *)pamh, pam_trace_iname(item_type, iname_buf));
	}

	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	if (item_type <= 0 || item_type >= PAM_MAX_ITEMS)
		return (PAM_SYMBOL_ERR);

	if ((pamh->pam_inmodule != WO_OK) &&
	    ((item_type == PAM_AUTHTOK || item_type == PAM_OLDAUTHTOK))) {
		__pam_log(LOG_AUTH | LOG_NOTICE, "pam_get_item(%s) called from "
		    "a non module context",
		    pam_trace_iname(item_type, iname_buf));
		return (PAM_PERM_DENIED);
	}

	pip = (struct pam_item *)&(pamh->ps_item[item_type]);

	*item = pip->pi_addr;
	switch (item_type) {
	case PAM_CONV:
		pam_trace(PAM_DEBUG_ITEM, "pam_get_item(%p:%s)=%p",
		    (void *)pamh,
		    pam_trace_iname(item_type, iname_buf),
		    (void *)((struct pam_conv *)*item)->conv);
		break;
	case PAM_REPOSITORY:
		pam_trace(PAM_DEBUG_ITEM, "pam_get_item(%p:%s)=%s",
		    (void *)pamh,
		    pam_trace_iname(item_type, iname_buf),
		    *item ? (((struct pam_repository *)*item)->type ?
		    ((struct pam_repository *)*item)->type : "NULL") :
		    "NULL");
		break;
	case PAM_AUTHTOK:
	case PAM_OLDAUTHTOK:
#ifdef	DEBUG
		if (pam_debug & PAM_DEBUG_AUTHTOK)
			pam_trace(PAM_DEBUG_ITEM,
			    "pam_get_item(%p:%s)=%s", (void *)pamh,
			    pam_trace_iname(item_type, iname_buf),
			    *item ? *(char **)item : "NULL");
		else
#endif	/* DEBUG */
			pam_trace(PAM_DEBUG_ITEM,
			    "pam_get_item(%p:%s)=%s", (void *)pamh,
			    pam_trace_iname(item_type, iname_buf),
			    *item ? "********" : "NULL");
		break;
	default:
		pam_trace(PAM_DEBUG_ITEM, "pam_get_item(%p:%s)=%s",
		    (void *)pamh,
		    pam_trace_iname(item_type, iname_buf),
		    *item ? *(char **)item : "NULL");
	}

	return (PAM_SUCCESS);
}

/*
 * parse_user_name         - process the user response: ignore
 *                           '\t' or ' ' before or after a user name.
 *                           user_input is a null terminated string.
 *                           *ret_username will be the user name.
 */

static int
parse_user_name(char *user_input, char **ret_username)
{
	register char *ptr;
	register int index = 0;
	char username[PAM_MAX_RESP_SIZE];

	/* Set the default value for *ret_username */
	*ret_username = NULL;

	/*
	 * Set the initial value for username - this is a buffer holds
	 * the user name.
	 */
	bzero((void *)username, PAM_MAX_RESP_SIZE);

	/*
	 * The user_input is guaranteed to be terminated by a null character.
	 */
	ptr = user_input;

	/* Skip all the leading whitespaces if there are any. */
	while ((*ptr == ' ') || (*ptr == '\t'))
		ptr++;

	if (*ptr == '\0') {
		/*
		 * We should never get here since the user_input we got
		 * in pam_get_user() is not all whitespaces nor just "\0".
		 */
		return (PAM_BUF_ERR);
	}

	/*
	 * username will be the first string we get from user_input
	 * - we skip leading whitespaces and ignore trailing whitespaces
	 */
	while (*ptr != '\0') {
		if ((*ptr == ' ') || (*ptr == '\t'))
			break;
		else {
			username[index] = *ptr;
			index++;
			ptr++;
		}
	}

	/* ret_username will be freed in pam_get_user(). */
	if ((*ret_username = malloc(index + 1)) == NULL)
		return (PAM_BUF_ERR);
	(void) strcpy(*ret_username, username);
	return (PAM_SUCCESS);
}

/*
 * Get the value of PAM_USER. If not set, then use the convenience function
 * to prompt for the user. Use prompt if specified, else use PAM_USER_PROMPT
 * if it is set, else use default.
 */
#define	WHITESPACE	0
#define	USERNAME	1

int
pam_get_user(pam_handle_t *pamh, char **user, const char *prompt_override)
{
	int	status;
	char	*prompt = NULL;
	char    *real_username;
	struct pam_response *ret_resp = NULL;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	pam_trace(PAM_DEBUG_DEFAULT,
	    "pam_get_user(%p, %p, %s)", (void *)pamh, (void *)*user,
	    prompt_override ? prompt_override : "NULL");
	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	if ((status = pam_get_item(pamh, PAM_USER, (void **)user))
	    != PAM_SUCCESS) {
		return (status);
	}

	/* if the user is set, return it */

	if (*user != NULL && *user[0] != '\0') {
		return (PAM_SUCCESS);
	}

	/*
	 * if the module is requesting a special prompt, use it.
	 * else use PAM_USER_PROMPT.
	 */

	if (prompt_override != NULL) {
		prompt = (char *)prompt_override;
	} else {
		status = pam_get_item(pamh, PAM_USER_PROMPT, (void**)&prompt);
		if (status != PAM_SUCCESS) {
			return (status);
		}
	}

	/* if the prompt is not set, use default */

	if (prompt == NULL || prompt[0] == '\0') {
		prompt = dgettext(TEXT_DOMAIN, "Please enter user name: ");
	}

	/* prompt for the user */

	(void) strncpy(messages[0], prompt, sizeof (messages[0]));

	for (;;) {
		int state = WHITESPACE;

		status = do_conv(pamh, PAM_PROMPT_ECHO_ON, 1, messages,
		    NULL, &ret_resp);

		if (status != PAM_SUCCESS) {
			return (status);
		}

		if (ret_resp->resp && ret_resp->resp[0] != '\0') {
			int len = strlen(ret_resp->resp);
			int i;

			for (i = 0; i < len; i++) {
				if ((ret_resp->resp[i] != ' ') &&
				    (ret_resp->resp[i] != '\t')) {
					state = USERNAME;
					break;
				}
			}

			if (state == USERNAME)
				break;
		}
		/* essentially empty response, try again */
		free_resp(1, ret_resp);
		ret_resp = NULL;
	}

	/* set PAM_USER */
	/* Parse the user input to get the user name. */
	status = parse_user_name(ret_resp->resp, &real_username);

	if (status != PAM_SUCCESS) {
		if (real_username != NULL)
			free(real_username);
		free_resp(1, ret_resp);
		return (status);
	}

	status = pam_set_item(pamh, PAM_USER, real_username);

	free(real_username);

	free_resp(1, ret_resp);
	if (status != PAM_SUCCESS) {
		return (status);
	}

	/*
	 * finally, get PAM_USER. We have to call pam_get_item to get
	 * the value of user because pam_set_item mallocs the memory.
	 */

	status = pam_get_item(pamh, PAM_USER, (void**)user);
	return (status);
}

/*
 * Set module specific data
 */

int
pam_set_data(pam_handle_t *pamh, const char *module_data_name, void *data,
    void (*cleanup)(pam_handle_t *pamh, void *data, int pam_end_status))
{
	struct pam_module_data *psd;

	pam_trace(PAM_DEBUG_DATA,
	    "pam_set_data(%p:%s:%d)=%p", (void *)pamh,
	    (module_data_name != NULL) ? module_data_name : "NULL",
	    (pamh != NULL) ? pamh->pam_inmodule : -1, data);
	if (pamh == NULL || (pamh->pam_inmodule != WO_OK) ||
	    module_data_name == NULL) {
		return (PAM_SYSTEM_ERR);
	}

	/* check if module data already exists */

	for (psd = pamh->ssd; psd; psd = psd->next) {
		if (strcmp(psd->module_data_name, module_data_name) == 0) {
			/* clean up original data before setting the new data */
			if (psd->cleanup) {
				psd->cleanup(pamh, psd->data, PAM_SUCCESS);
			}
			psd->data = (void *)data;
			psd->cleanup = cleanup;
			return (PAM_SUCCESS);
		}
	}

	psd = malloc(sizeof (struct pam_module_data));
	if (psd == NULL)
		return (PAM_BUF_ERR);

	psd->module_data_name = strdup(module_data_name);
	if (psd->module_data_name == NULL) {
		free(psd);
		return (PAM_BUF_ERR);
	}

	psd->data = (void *)data;
	psd->cleanup = cleanup;
	psd->next = pamh->ssd;
	pamh->ssd = psd;
	return (PAM_SUCCESS);
}

/*
 * get module specific data
 */

int
pam_get_data(const pam_handle_t *pamh, const char *module_data_name,
    const void **data)
{
	struct pam_module_data *psd;

	if (pamh == NULL || (pamh->pam_inmodule != WO_OK) ||
	    module_data_name == NULL) {
		pam_trace(PAM_DEBUG_DATA,
		    "pam_get_data(%p:%s:%d)=%p", (void *)pamh,
		    module_data_name ? module_data_name : "NULL",
		    pamh->pam_inmodule, *data);
		return (PAM_SYSTEM_ERR);
	}

	for (psd = pamh->ssd; psd; psd = psd->next) {
		if (strcmp(psd->module_data_name, module_data_name) == 0) {
			*data = psd->data;
			pam_trace(PAM_DEBUG_DATA,
			    "pam_get_data(%p:%s)=%p", (void *)pamh,
			    module_data_name, *data);
			return (PAM_SUCCESS);
		}
	}
	pam_trace(PAM_DEBUG_DATA,
	    "pam_get_data(%p:%s)=%s", (void *)pamh, module_data_name,
	    "PAM_NO_MODULE_DATA");

	return (PAM_NO_MODULE_DATA);
}

/*
 * PAM equivalent to strerror()
 */
/* ARGSUSED */
const char *
pam_strerror(pam_handle_t *pamh, int errnum)
{
	switch (errnum) {
	case PAM_SUCCESS:
		return (dgettext(TEXT_DOMAIN, "Success"));
	case PAM_OPEN_ERR:
		return (dgettext(TEXT_DOMAIN, "Dlopen failure"));
	case PAM_SYMBOL_ERR:
		return (dgettext(TEXT_DOMAIN, "Symbol not found"));
	case PAM_SERVICE_ERR:
		return (dgettext(TEXT_DOMAIN,
		    "Error in underlying service module"));
	case PAM_SYSTEM_ERR:
		return (dgettext(TEXT_DOMAIN, "System error"));
	case PAM_BUF_ERR:
		return (dgettext(TEXT_DOMAIN, "Memory buffer error"));
	case PAM_CONV_ERR:
		return (dgettext(TEXT_DOMAIN, "Conversation failure"));
	case PAM_PERM_DENIED:
		return (dgettext(TEXT_DOMAIN, "Permission denied"));
	case PAM_MAXTRIES:
		return (dgettext(TEXT_DOMAIN,
		    "Maximum number of attempts exceeded"));
	case PAM_AUTH_ERR:
		return (dgettext(TEXT_DOMAIN, "Authentication failed"));
	case PAM_NEW_AUTHTOK_REQD:
		return (dgettext(TEXT_DOMAIN, "Get new authentication token"));
	case PAM_CRED_INSUFFICIENT:
		return (dgettext(TEXT_DOMAIN, "Insufficient credentials"));
	case PAM_AUTHINFO_UNAVAIL:
		return (dgettext(TEXT_DOMAIN,
		    "Can not retrieve authentication info"));
	case PAM_USER_UNKNOWN:
		return (dgettext(TEXT_DOMAIN, "No account present for user"));
	case PAM_CRED_UNAVAIL:
		return (dgettext(TEXT_DOMAIN,
		    "Can not retrieve user credentials"));
	case PAM_CRED_EXPIRED:
		return (dgettext(TEXT_DOMAIN,
		    "User credentials have expired"));
	case PAM_CRED_ERR:
		return (dgettext(TEXT_DOMAIN,
		    "Failure setting user credentials"));
	case PAM_ACCT_EXPIRED:
		return (dgettext(TEXT_DOMAIN, "User account has expired"));
	case PAM_AUTHTOK_EXPIRED:
		return (dgettext(TEXT_DOMAIN, "User password has expired"));
	case PAM_SESSION_ERR:
		return (dgettext(TEXT_DOMAIN,
		    "Can not make/remove entry for session"));
	case PAM_AUTHTOK_ERR:
		return (dgettext(TEXT_DOMAIN,
		    "Authentication token manipulation error"));
	case PAM_AUTHTOK_RECOVERY_ERR:
		return (dgettext(TEXT_DOMAIN,
		    "Authentication token can not be recovered"));
	case PAM_AUTHTOK_LOCK_BUSY:
		return (dgettext(TEXT_DOMAIN,
		    "Authentication token lock busy"));
	case PAM_AUTHTOK_DISABLE_AGING:
		return (dgettext(TEXT_DOMAIN,
		    "Authentication token aging disabled"));
	case PAM_NO_MODULE_DATA:
		return (dgettext(TEXT_DOMAIN,
		    "Module specific data not found"));
	case PAM_IGNORE:
		return (dgettext(TEXT_DOMAIN, "Ignore module"));
	case PAM_ABORT:
		return (dgettext(TEXT_DOMAIN, "General PAM failure "));
	case PAM_TRY_AGAIN:
		return (dgettext(TEXT_DOMAIN,
		    "Unable to complete operation. Try again"));
	default:
		return (dgettext(TEXT_DOMAIN, "Unknown error"));
	}
}

static void *
sm_name(int ind)
{
	switch (ind) {
	case PAM_AUTHENTICATE:
		return (PAM_SM_AUTHENTICATE);
	case PAM_SETCRED:
		return (PAM_SM_SETCRED);
	case PAM_ACCT_MGMT:
		return (PAM_SM_ACCT_MGMT);
	case PAM_OPEN_SESSION:
		return (PAM_SM_OPEN_SESSION);
	case PAM_CLOSE_SESSION:
		return (PAM_SM_CLOSE_SESSION);
	case PAM_CHAUTHTOK:
		return (PAM_SM_CHAUTHTOK);
	}
	return (NULL);
}

static int
(*func(pamtab_t *modulep, int ind))()
{
	void	*funcp;

	if ((funcp = modulep->function_ptr) == NULL)
		return (NULL);

	switch (ind) {
	case PAM_AUTHENTICATE:
		return (((struct auth_module *)funcp)->pam_sm_authenticate);
	case PAM_SETCRED:
		return (((struct auth_module *)funcp)->pam_sm_setcred);
	case PAM_ACCT_MGMT:
		return (((struct account_module *)funcp)->pam_sm_acct_mgmt);
	case PAM_OPEN_SESSION:
		return (((struct session_module *)funcp)->pam_sm_open_session);
	case PAM_CLOSE_SESSION:
		return (((struct session_module *)funcp)->pam_sm_close_session);
	case PAM_CHAUTHTOK:
		return (((struct password_module *)funcp)->pam_sm_chauthtok);
	}
	return (NULL);
}

/*
 * Run through the PAM service module stack for the given module type.
 */
static int
run_stack(pam_handle_t *pamh, int flags, int type, int def_err, int ind,
    char *function_name)
{
	int	err = PAM_SYSTEM_ERR;  /* preset */
	int	optional_error = 0;
	int	required_error = 0;
	int	success = 0;
	pamtab_t *modulep;
	int	(*sm_func)();

	if (pamh == NULL)
		return (PAM_SYSTEM_ERR);

	/* read initial entries from pam.conf */
	if ((err = read_pam_conf(pamh, PAM_CONFIG)) != PAM_SUCCESS) {
		return (err);
	}

	if ((modulep =
	    pamh->pam_conf_info[pamh->include_depth][type]) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR, "%s no initial module present",
		    pam_trace_cname(pamh));
		goto exit_return;
	}

	pamh->pam_inmodule = WO_OK;	/* OK to get AUTHTOK */
include:
	pam_trace(PAM_DEBUG_MODULE,
	    "[%d:%s]:run_stack:%s(%p, %x): %s", pamh->include_depth,
	    pam_trace_cname(pamh), function_name, (void *)pamh, flags,
	    modulep ? modulep->module_path : "NULL");

	while (modulep != NULL) {
		if (modulep->pam_flag & PAM_INCLUDE) {
			/* save the return location */
			pamh->pam_conf_modulep[pamh->include_depth] =
			    modulep->next;
			pam_trace(PAM_DEBUG_MODULE,
			    "setting for include[%d:%p]",
			    pamh->include_depth, (void *)modulep->next);
			if (pamh->include_depth++ >= PAM_MAX_INCLUDE) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "run_stack: includes too deep %d "
				    "found trying to include %s from %s, %d "
				    "allowed", pamh->include_depth,
				    modulep->module_path, pamh->pam_conf_name
				    [PAM_MAX_INCLUDE] == NULL ? "NULL" :
				    pamh->pam_conf_name[PAM_MAX_INCLUDE],
				    PAM_MAX_INCLUDE);
				goto exit_return;
			}
			if ((err = read_pam_conf(pamh,
			    modulep->module_path)) != PAM_SUCCESS) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "run_stack[%d:%s]: can't read included "
				    "conf %s", pamh->include_depth,
				    pam_trace_cname(pamh),
				    modulep->module_path);
				goto exit_return;
			}
			if ((modulep = pamh->pam_conf_info
			    [pamh->include_depth][type]) == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "run_stack[%d:%s]: no include module "
				    "present %s", pamh->include_depth,
				    pam_trace_cname(pamh), function_name);
				goto exit_return;
			}
			if (modulep->pam_flag & PAM_INCLUDE) {
				/* first line another include */
				goto include;
			}
			pam_trace(PAM_DEBUG_DEFAULT, "include[%d:%s]"
			    "(%p, %s)=%s", pamh->include_depth,
			    pam_trace_cname(pamh), (void *)pamh,
			    function_name, modulep->module_path);
			if ((err = load_modules(pamh, type, sm_name(ind),
			    pamh->pam_conf_info
			    [pamh->include_depth][type])) != PAM_SUCCESS) {
				pam_trace(PAM_DEBUG_DEFAULT,
				    "[%d:%s]:%s(%p, %x): load_modules failed",
				    pamh->include_depth, pam_trace_cname(pamh),
				    function_name, (void *)pamh, flags);
				goto exit_return;
			}
			if ((modulep = pamh->pam_conf_info
			    [pamh->include_depth][type]) == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "%s no initial module present",
				    pam_trace_cname(pamh));
				goto exit_return;
			}
		} else if ((err = load_modules(pamh, type, sm_name(ind),
		    modulep)) != PAM_SUCCESS) {
			pam_trace(PAM_DEBUG_DEFAULT,
			    "[%d:%s]:%s(%p, %x): load_modules failed",
			    pamh->include_depth, pam_trace_cname(pamh),
			    function_name, (void *)pamh, flags);
			goto exit_return;
		}  /* PAM_INCLUDE */
		sm_func = func(modulep, ind);
		if (sm_func) {
			err = sm_func(pamh, flags, modulep->module_argc,
			    (const char **)modulep->module_argv);

			pam_trace(PAM_DEBUG_MODULE,
			    "[%d:%s]:%s(%p, %x): %s returned %s",
			    pamh->include_depth, pam_trace_cname(pamh),
			    function_name, (void *)pamh, flags,
			    modulep->module_path, pam_strerror(pamh, err));

			switch (err) {
			case PAM_IGNORE:
				/* do nothing */
				break;
			case PAM_SUCCESS:
				if ((modulep->pam_flag & PAM_SUFFI_BIND) &&
				    !required_error) {
					pamh->pam_inmodule = RW_OK;
					pam_trace(PAM_DEBUG_MODULE,
					    "[%d:%s]:%s(%p, %x): %s: success",
					    pamh->include_depth,
					    pam_trace_cname(pamh),
					    function_name, (void *)pamh, flags,
					    (modulep->pam_flag & PAM_BINDING) ?
					    PAM_BINDING_NAME :
					    PAM_SUFFICIENT_NAME);
					goto exit_return;
				}
				success = 1;
				break;
			case PAM_TRY_AGAIN:
				/*
				 * We need to return immediately, and
				 * we shouldn't reset the AUTHTOK item
				 * since it is not an error per-se.
				 */
				pamh->pam_inmodule = RW_OK;
				pam_trace(PAM_DEBUG_MODULE,
				    "[%d:%s]:%s(%p, %x): TRY_AGAIN: %s",
				    pamh->include_depth, pam_trace_cname(pamh),
				    function_name, (void *)pamh, flags,
				    pam_strerror(pamh, required_error ?
				    required_error : err));
				err = required_error ? required_error : err;
				goto exit_return;
			default:
				if (modulep->pam_flag & PAM_REQUISITE) {
					pamh->pam_inmodule = RW_OK;
					pam_trace(PAM_DEBUG_MODULE,
					    "[%d:%s]:%s(%p, %x): requisite: %s",
					    pamh->include_depth,
					    pam_trace_cname(pamh),
					    function_name, (void *)pamh, flags,
					    pam_strerror(pamh,
					    required_error ? required_error :
					    err));
					err = required_error ?
					    required_error : err;
					goto exit_return;
				} else if (modulep->pam_flag & PAM_REQRD_BIND) {
					if (!required_error)
						required_error = err;
				} else {
					if (!optional_error)
						optional_error = err;
				}
				pam_trace(PAM_DEBUG_DEFAULT,
				    "[%d:%s]:%s(%p, %x): error %s",
				    pamh->include_depth, pam_trace_cname(pamh),
				    function_name, (void *)pamh, flags,
				    pam_strerror(pamh, err));
				break;
			}
		}
		modulep = modulep->next;
	}

	pam_trace(PAM_DEBUG_MODULE, "[%d:%s]:stack_end:%s(%p, %x): %s %s: %s",
	    pamh->include_depth, pam_trace_cname(pamh), function_name,
	    (void *)pamh, flags, pamh->include_depth ? "included" : "final",
	    required_error ? "required" : success ? "success" :
	    optional_error ? "optional" : "default",
	    pam_strerror(pamh, required_error ? required_error :
	    success ? PAM_SUCCESS : optional_error ? optional_error : def_err));
	if (pamh->include_depth > 0) {
		free_pam_conf_info(pamh);
		pamh->include_depth--;
		/* continue at next entry */
		modulep = pamh->pam_conf_modulep[pamh->include_depth];
		pam_trace(PAM_DEBUG_MODULE, "looping for include[%d:%p]",
		    pamh->include_depth, (void *)modulep);
		goto include;
	}
	free_pam_conf_info(pamh);
	pamh->pam_inmodule = RW_OK;
	if (required_error != 0)
		return (required_error);
	else if (success != 0)
		return (PAM_SUCCESS);
	else if (optional_error != 0)
		return (optional_error);
	else
		return (def_err);

exit_return:
	/*
	 * All done at whatever depth we're at.
	 * Go back to not having read /etc/pam.conf
	 */
	while (pamh->include_depth > 0) {
		free_pam_conf_info(pamh);
		pamh->include_depth--;
	}
	free_pam_conf_info(pamh);
	pamh->pam_inmodule = RW_OK;
	return (err);
}

/*
 * pam_authenticate - authenticate a user
 */

int
pam_authenticate(pam_handle_t *pamh, int flags)
{
	int	retval;

	retval = run_stack(pamh, flags, PAM_AUTH_MODULE, PAM_AUTH_ERR,
	    PAM_AUTHENTICATE, "pam_authenticate");

	if (retval != PAM_SUCCESS)
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
	return (retval);
}

/*
 * pam_setcred - modify or retrieve user credentials
 */

int
pam_setcred(pam_handle_t *pamh, int flags)
{
	int	retval;

	retval = run_stack(pamh, flags, PAM_AUTH_MODULE, PAM_CRED_ERR,
	    PAM_SETCRED, "pam_setcred");

	if (retval != PAM_SUCCESS)
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
	return (retval);
}

/*
 * pam_acct_mgmt - check password aging, account expiration
 */

int
pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	int	retval;

	retval = run_stack(pamh, flags, PAM_ACCOUNT_MODULE, PAM_ACCT_EXPIRED,
	    PAM_ACCT_MGMT, "pam_acct_mgmt");

	if (retval != PAM_SUCCESS &&
	    retval != PAM_NEW_AUTHTOK_REQD) {
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
	}
	return (retval);
}

/*
 * pam_open_session - begin session management
 */

int
pam_open_session(pam_handle_t *pamh, int flags)
{
	int	retval;

	retval = run_stack(pamh, flags, PAM_SESSION_MODULE, PAM_SESSION_ERR,
	    PAM_OPEN_SESSION, "pam_open_session");

	if (retval != PAM_SUCCESS)
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
	return (retval);
}

/*
 * pam_close_session - terminate session management
 */

int
pam_close_session(pam_handle_t *pamh, int flags)
{
	int	retval;

	retval = run_stack(pamh, flags, PAM_SESSION_MODULE, PAM_SESSION_ERR,
	    PAM_CLOSE_SESSION, "pam_close_session");

	if (retval != PAM_SUCCESS)
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
	return (retval);
}

/*
 * pam_chauthtok - change user authentication token
 */

int
pam_chauthtok(pam_handle_t *pamh, int flags)
{
	int	retval;

	/* do not let apps use PAM_PRELIM_CHECK or PAM_UPDATE_AUTHTOK */
	if (flags & (PAM_PRELIM_CHECK | PAM_UPDATE_AUTHTOK)) {
		pam_trace(PAM_DEBUG_DEFAULT,
		    "pam_chauthtok(%p, %x): %s", (void *)pamh, flags,
		    pam_strerror(pamh, PAM_SYMBOL_ERR));
		return (PAM_SYMBOL_ERR);
	}

	/* 1st pass: PRELIM CHECK */
	retval = run_stack(pamh, flags | PAM_PRELIM_CHECK, PAM_PASSWORD_MODULE,
	    PAM_AUTHTOK_ERR, PAM_CHAUTHTOK, "pam_chauthtok-prelim");

	if (retval == PAM_TRY_AGAIN)
		return (retval);

	if (retval != PAM_SUCCESS) {
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
		return (retval);
	}

	/* 2nd pass: UPDATE AUTHTOK */
	retval = run_stack(pamh, flags | PAM_UPDATE_AUTHTOK,
	    PAM_PASSWORD_MODULE, PAM_AUTHTOK_ERR, PAM_CHAUTHTOK,
	    "pam_chauthtok-update");

	if (retval != PAM_SUCCESS)
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);

	return (retval);
}

/*
 * pam_putenv - add an environment variable to the PAM handle
 *	if name_value == 'NAME=VALUE'	then set variable to the value
 *	if name_value == 'NAME='	then set variable to an empty value
 *	if name_value == 'NAME'		then delete the variable
 */

int
pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	int		error = PAM_SYSTEM_ERR;
	char		*equal_sign = 0;
	char		*name = NULL, *value = NULL, *tmp_value = NULL;
	env_list	*traverse, *trail;

	pam_trace(PAM_DEBUG_DEFAULT,
	    "pam_putenv(%p, %s)", (void *)pamh,
	    name_value ? name_value : "NULL");

	if (pamh == NULL || name_value == NULL)
		goto out;

	/* see if we were passed 'NAME=VALUE', 'NAME=', or 'NAME' */
	if ((equal_sign = strchr(name_value, '=')) != 0) {
		if ((name = calloc(equal_sign - name_value + 1,
		    sizeof (char))) == 0) {
			error = PAM_BUF_ERR;
			goto out;
		}
		(void) strncpy(name, name_value, equal_sign - name_value);
		if ((value = strdup(++equal_sign)) == 0) {
			error = PAM_BUF_ERR;
			goto out;
		}
	} else {
		if ((name = strdup(name_value)) == 0) {
			error = PAM_BUF_ERR;
			goto out;
		}
	}

	/* check to see if we already have this variable in the PAM handle */
	traverse = pamh->pam_env;
	trail = traverse;
	while (traverse && strncmp(traverse->name, name, strlen(name))) {
		trail = traverse;
		traverse = traverse->next;
	}

	if (traverse) {
		/* found a match */
		if (value == 0) {
			/* remove the env variable */
			if (pamh->pam_env == traverse)
				pamh->pam_env = traverse->next;
			else
				trail->next = traverse->next;
			free_env(traverse);
		} else if (strlen(value) == 0) {
			/* set env variable to empty value */
			if ((tmp_value = strdup("")) == 0) {
				error = PAM_SYSTEM_ERR;
				goto out;
			}
			free(traverse->value);
			traverse->value = tmp_value;
		} else {
			/* set the new value */
			if ((tmp_value = strdup(value)) == 0) {
				error = PAM_SYSTEM_ERR;
				goto out;
			}
			free(traverse->value);
			traverse->value = tmp_value;
		}

	} else if (traverse == 0 && value) {
		/*
		 * could not find a match in the PAM handle.
		 * add the new value if there is one
		 */
		if ((traverse = calloc(1, sizeof (env_list))) == 0) {
			error = PAM_BUF_ERR;
			goto out;
		}
		if ((traverse->name = strdup(name)) == 0) {
			free_env(traverse);
			error = PAM_BUF_ERR;
			goto out;
		}
		if ((traverse->value = strdup(value)) == 0) {
			free_env(traverse);
			error = PAM_BUF_ERR;
			goto out;
		}
		if (trail == 0) {
			/* new head of list */
			pamh->pam_env = traverse;
		} else {
			/* adding to end of list */
			trail->next = traverse;
		}
	}

	error = PAM_SUCCESS;
out:
	if (error != PAM_SUCCESS) {
		if (traverse) {
			if (traverse->name)
				free(traverse->name);
			if (traverse->value)
				free(traverse->value);
			free(traverse);
		}
	}
	if (name)
		free(name);
	if (value)
		free(value);
	return (error);
}

/*
 * pam_getenv - retrieve an environment variable from the PAM handle
 */
char *
pam_getenv(pam_handle_t *pamh, const char *name)
{
	int		error = PAM_SYSTEM_ERR;
	env_list	*traverse;

	pam_trace(PAM_DEBUG_DEFAULT,
	    "pam_getenv(%p, %p)", (void *)pamh, (void *)name);

	if (pamh == NULL || name == NULL)
		goto out;

	/* check to see if we already have this variable in the PAM handle */
	traverse = pamh->pam_env;
	while (traverse && strncmp(traverse->name, name, strlen(name))) {
		traverse = traverse->next;
	}
	error = (traverse ? PAM_SUCCESS : PAM_SYSTEM_ERR);
	pam_trace(PAM_DEBUG_DEFAULT,
	    "pam_getenv(%p, %s)=%s", (void *)pamh, name,
	    traverse ? traverse->value : "NULL");
out:
	return (error ? NULL : strdup(traverse->value));
}

/*
 * pam_getenvlist - retrieve all environment variables from the PAM handle
 *                  in a NULL terminated array. On error, return NULL.
 */
char **
pam_getenvlist(pam_handle_t *pamh)
{
	int		error = PAM_SYSTEM_ERR;
	char		**list = 0;
	int		length = 0;
	env_list	*traverse;
	char		*tenv;
	size_t		tenv_size;

	pam_trace(PAM_DEBUG_DEFAULT,
	    "pam_getenvlist(%p)", (void *)pamh);

	if (pamh == NULL)
		goto out;

	/* find out how many environment variables we have */
	traverse = pamh->pam_env;
	while (traverse) {
		length++;
		traverse = traverse->next;
	}

	/* allocate the array we will return to the caller */
	if ((list = calloc(length + 1, sizeof (char *))) == NULL) {
		error = PAM_BUF_ERR;
		goto out;
	}

	/* add the variables one by one */
	length = 0;
	traverse = pamh->pam_env;
	while (traverse != NULL) {
		tenv_size = strlen(traverse->name) +
		    strlen(traverse->value) + 2; /* name=val\0 */
		if ((tenv = malloc(tenv_size)) == NULL) {
			error = PAM_BUF_ERR;
			goto out;
		}
		/*LINTED*/
		(void) sprintf(tenv, "%s=%s", traverse->name, traverse->value);
		list[length++] = tenv;
		traverse = traverse->next;
	}
	list[length] = NULL;

	error = PAM_SUCCESS;
out:
	if (error != PAM_SUCCESS) {
		/* free the partially constructed list */
		if (list) {
			length = 0;
			while (list[length] != NULL) {
				free(list[length]);
				length++;
			}
			free(list);
		}
	}
	return (error ? NULL : list);
}

/*
 * Routines to load a requested module on demand
 */

/*
 * load_modules - load the requested module.
 *		  if the dlopen or dlsym fail, then
 *		  the module is ignored.
 */

static int
load_modules(pam_handle_t *pamh, int type, char *function_name,
    pamtab_t *pam_entry)
{
	void	*mh;
	struct	auth_module *authp;
	struct	account_module *accountp;
	struct	session_module *sessionp;
	struct	password_module *passwdp;
	int	loading_functions = 0; /* are we currently loading functions? */

	pam_trace(PAM_DEBUG_MODULE, "load_modules[%d:%s](%p, %s)=%s:%s",
	    pamh->include_depth, pam_trace_cname(pamh), (void *)pamh,
	    function_name, pam_trace_fname(pam_entry->pam_flag),
	    pam_entry->module_path);

	while (pam_entry != NULL) {
		pam_trace(PAM_DEBUG_DEFAULT,
		    "while load_modules[%d:%s](%p, %s)=%s",
		    pamh->include_depth, pam_trace_cname(pamh), (void *)pamh,
		    function_name, pam_entry->module_path);

		if (pam_entry->pam_flag & PAM_INCLUDE) {
			pam_trace(PAM_DEBUG_DEFAULT,
			    "done load_modules[%d:%s](%p, %s)=%s",
			    pamh->include_depth, pam_trace_cname(pamh),
			    (void *)pamh, function_name,
			    pam_entry->module_path);
			return (PAM_SUCCESS);
		}
		switch (type) {
		case PAM_AUTH_MODULE:

			/* if the function has already been loaded, return */
			authp = pam_entry->function_ptr;
			if (!loading_functions &&
			    (((strcmp(function_name, PAM_SM_AUTHENTICATE)
			    == 0) && authp && authp->pam_sm_authenticate) ||
			    ((strcmp(function_name, PAM_SM_SETCRED) == 0) &&
			    authp && authp->pam_sm_setcred))) {
				return (PAM_SUCCESS);
			}

			/* function has not been loaded yet */
			loading_functions = 1;
			if (authp == NULL) {
				authp = calloc(1, sizeof (struct auth_module));
				if (authp == NULL)
					return (PAM_BUF_ERR);
			}

			/* if open_module fails, return error */
			if ((mh = open_module(pamh,
			    pam_entry->module_path)) == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "load_modules[%d:%s]: can not open module "
				    "%s", pamh->include_depth,
				    pam_trace_cname(pamh),
				    pam_entry->module_path);
				free(authp);
				return (PAM_OPEN_ERR);
			}

			/* load the authentication function */
			if (strcmp(function_name, PAM_SM_AUTHENTICATE) == 0) {
				if (load_function(mh, PAM_SM_AUTHENTICATE,
				    &authp->pam_sm_authenticate)
				    != PAM_SUCCESS) {
					/* return error if dlsym fails */
					free(authp);
					return (PAM_SYMBOL_ERR);
				}

			/* load the setcred function */
			} else if (strcmp(function_name, PAM_SM_SETCRED) == 0) {
				if (load_function(mh, PAM_SM_SETCRED,
				    &authp->pam_sm_setcred) != PAM_SUCCESS) {
					/* return error if dlsym fails */
					free(authp);
					return (PAM_SYMBOL_ERR);
				}
			}
			pam_entry->function_ptr = authp;
			break;
		case PAM_ACCOUNT_MODULE:
			accountp = pam_entry->function_ptr;
			if (!loading_functions &&
			    (strcmp(function_name, PAM_SM_ACCT_MGMT) == 0) &&
			    accountp && accountp->pam_sm_acct_mgmt) {
				return (PAM_SUCCESS);
			}

			/*
			 * If functions are added to the account module,
			 * verify that one of the other functions hasn't
			 * already loaded it.  See PAM_AUTH_MODULE code.
			 */
			loading_functions = 1;
			accountp = calloc(1, sizeof (struct account_module));
			if (accountp == NULL)
				return (PAM_BUF_ERR);

			/* if open_module fails, return error */
			if ((mh = open_module(pamh,
			    pam_entry->module_path)) == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "load_modules[%d:%s]: can not open module "
				    "%s", pamh->include_depth,
				    pam_trace_cname(pamh),
				    pam_entry->module_path);
				free(accountp);
				return (PAM_OPEN_ERR);
			}

			if (load_function(mh, PAM_SM_ACCT_MGMT,
			    &accountp->pam_sm_acct_mgmt) != PAM_SUCCESS) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "load_modules[%d:%s]: pam_sm_acct_mgmt() "
				    "missing", pamh->include_depth,
				    pam_trace_cname(pamh));
				free(accountp);
				return (PAM_SYMBOL_ERR);
			}
			pam_entry->function_ptr = accountp;
			break;
		case PAM_SESSION_MODULE:
			sessionp = pam_entry->function_ptr;
			if (!loading_functions &&
			    (((strcmp(function_name,
			    PAM_SM_OPEN_SESSION) == 0) &&
			    sessionp && sessionp->pam_sm_open_session) ||
			    ((strcmp(function_name,
			    PAM_SM_CLOSE_SESSION) == 0) &&
			    sessionp && sessionp->pam_sm_close_session))) {
				return (PAM_SUCCESS);
			}

			loading_functions = 1;
			if (sessionp == NULL) {
				sessionp = calloc(1,
				    sizeof (struct session_module));
				if (sessionp == NULL)
					return (PAM_BUF_ERR);
			}

			/* if open_module fails, return error */
			if ((mh = open_module(pamh,
			    pam_entry->module_path)) == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "load_modules[%d:%s]: can not open module "
				    "%s", pamh->include_depth,
				    pam_trace_cname(pamh),
				    pam_entry->module_path);
				free(sessionp);
				return (PAM_OPEN_ERR);
			}

			if ((strcmp(function_name, PAM_SM_OPEN_SESSION) == 0) &&
			    load_function(mh, PAM_SM_OPEN_SESSION,
			    &sessionp->pam_sm_open_session) != PAM_SUCCESS) {
				free(sessionp);
				return (PAM_SYMBOL_ERR);
			} else if ((strcmp(function_name,
			    PAM_SM_CLOSE_SESSION) == 0) &&
			    load_function(mh, PAM_SM_CLOSE_SESSION,
			    &sessionp->pam_sm_close_session) != PAM_SUCCESS) {
				free(sessionp);
				return (PAM_SYMBOL_ERR);
			}
			pam_entry->function_ptr = sessionp;
			break;
		case PAM_PASSWORD_MODULE:
			passwdp = pam_entry->function_ptr;
			if (!loading_functions &&
			    (strcmp(function_name, PAM_SM_CHAUTHTOK) == 0) &&
			    passwdp && passwdp->pam_sm_chauthtok) {
				return (PAM_SUCCESS);
			}

			/*
			 * If functions are added to the password module,
			 * verify that one of the other functions hasn't
			 * already loaded it.  See PAM_AUTH_MODULE code.
			 */
			loading_functions = 1;
			passwdp = calloc(1, sizeof (struct password_module));
			if (passwdp == NULL)
				return (PAM_BUF_ERR);

			/* if open_module fails, continue */
			if ((mh = open_module(pamh,
			    pam_entry->module_path)) == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "load_modules[%d:%s]: can not open module "
				    "%s", pamh->include_depth,
				    pam_trace_cname(pamh),
				    pam_entry->module_path);
				free(passwdp);
				return (PAM_OPEN_ERR);
			}

			if (load_function(mh, PAM_SM_CHAUTHTOK,
			    &passwdp->pam_sm_chauthtok) != PAM_SUCCESS) {
				free(passwdp);
				return (PAM_SYMBOL_ERR);
			}
			pam_entry->function_ptr = passwdp;
			break;
		default:
			pam_trace(PAM_DEBUG_DEFAULT,
			    "load_modules[%d:%s](%p, %s): unsupported type %d",
			    pamh->include_depth, pam_trace_cname(pamh),
			    (void *)pamh, function_name, type);
			break;
		}

		pam_entry = pam_entry->next;
	} /* while */

	pam_trace(PAM_DEBUG_MODULE, "load_modules[%d:%s](%p, %s)=done",
	    pamh->include_depth, pam_trace_cname(pamh), (void *)pamh,
	    function_name);

	return (PAM_SUCCESS);
}

/*
 * open_module		- Open the module first checking for
 *			  propers modes and ownerships on the file.
 */

static void *
open_module(pam_handle_t *pamh, char *module_so)
{
	struct stat64	stb;
	char		*errmsg;
	void		*lfd;
	fd_list		*module_fds = 0;
	fd_list		*trail = 0;
	fd_list		*traverse = 0;

	/* Check the ownership and file modes */
	if (stat64(module_so, &stb) < 0) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "open_module[%d:%s]: stat(%s) failed: %s",
		    pamh->include_depth, pam_trace_cname(pamh), module_so,
		    strerror(errno));
		return (NULL);
	}
	if (stb.st_uid != (uid_t)0) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_module[%d:%s]: Owner of the module %s is not root",
		    pamh->include_depth, pam_trace_cname(pamh), module_so);
		return (NULL);
	}
	if (stb.st_mode & S_IWGRP) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_module[%d:%s]: module %s writable by group",
		    pamh->include_depth, pam_trace_cname(pamh), module_so);
		return (NULL);
	}
	if (stb.st_mode & S_IWOTH) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_module[%d:%s]: module %s writable by world",
		    pamh->include_depth, pam_trace_cname(pamh), module_so);
		return (NULL);
	}

	/*
	 * Perform the dlopen()
	 */
	lfd = (void *)dlopen(module_so, RTLD_LAZY);

	if (lfd == NULL) {
		errmsg = dlerror();
		__pam_log(LOG_AUTH | LOG_ERR, "open_module[%d:%s]: %s "
		    "failed: %s", pamh->include_depth, pam_trace_cname(pamh),
		    module_so, errmsg != NULL ? errmsg : "Unknown error");
		return (NULL);
	} else {
		/* add this fd to the pam handle */
		if ((module_fds = calloc(1, sizeof (fd_list))) == 0) {
			(void) dlclose(lfd);
			lfd = 0;
			return (NULL);
		}
		module_fds->mh = lfd;

		if (pamh->fd == 0) {
			/* adding new head of list */
			pamh->fd = module_fds;
		} else {
			/* appending to end of list */
			traverse = pamh->fd;
			while (traverse) {
				trail = traverse;
				traverse = traverse->next;
			}
			trail->next = module_fds;
		}
	}

	return (lfd);
}

/*
 * load_function - call dlsym() to resolve the function address
 */
static int
load_function(void *lfd, char *name, int (**func)())
{
	char *errmsg = NULL;

	if (lfd == NULL)
		return (PAM_SYMBOL_ERR);

	*func = (int (*)())dlsym(lfd, name);
	if (*func == NULL) {
		errmsg = dlerror();
		__pam_log(LOG_AUTH | LOG_ERR, "dlsym failed %s: error %s",
		    name, errmsg != NULL ? errmsg : "Unknown error");
		return (PAM_SYMBOL_ERR);
	}

	pam_trace(PAM_DEBUG_DEFAULT,
	    "load_function: successful load of %s", name);
	return (PAM_SUCCESS);
}

/*
 * Routines to read the pam.conf configuration file
 */

/*
 * open_pam_conf - open the pam.conf config file
 */

static int
open_pam_conf(struct pam_fh **pam_fh, pam_handle_t *pamh, char *config)
{
	struct stat64	stb;
	int		fd;

	if ((fd = open(config, O_RDONLY)) == -1) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_pam_conf[%d:%s]: open(%s) failed: %s",
		    pamh->include_depth, pam_trace_cname(pamh), config,
		    strerror(errno));
		return (0);
	}
	/* Check the ownership and file modes */
	if (fstat64(fd, &stb) < 0) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_pam_conf[%d:%s]: stat(%s) failed: %s",
		    pamh->include_depth, pam_trace_cname(pamh), config,
		    strerror(errno));
		(void) close(fd);
		return (0);
	}
	if (stb.st_uid != (uid_t)0) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_pam_conf[%d:%s]: Owner of %s is not root",
		    pamh->include_depth, pam_trace_cname(pamh), config);
		(void) close(fd);
		return (0);
	}
	if (stb.st_mode & S_IWGRP) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_pam_conf[%d:%s]: %s writable by group",
		    pamh->include_depth, pam_trace_cname(pamh), config);
		(void) close(fd);
		return (0);
	}
	if (stb.st_mode & S_IWOTH) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "open_pam_conf[%d:%s]: %s writable by world",
		    pamh->include_depth, pam_trace_cname(pamh), config);
		(void) close(fd);
		return (0);
	}
	if ((*pam_fh = calloc(1, sizeof (struct pam_fh))) == NULL) {
		(void) close(fd);
		return (0);
	}
	(*pam_fh)->fconfig = fd;
	(*pam_fh)->bufsize = (size_t)stb.st_size;
	if (((*pam_fh)->data = mmap(0, (*pam_fh)->bufsize, PROT_READ,
	    MAP_PRIVATE, (*pam_fh)->fconfig, 0)) == MAP_FAILED) {
		(void) close(fd);
		free (*pam_fh);
		return (0);
	}
	(*pam_fh)->bufferp = (*pam_fh)->data;

	return (1);
}

/*
 * close_pam_conf - close pam.conf
 */

static void
close_pam_conf(struct pam_fh *pam_fh)
{
	(void) munmap(pam_fh->data, pam_fh->bufsize);
	(void) close(pam_fh->fconfig);
	free(pam_fh);
}

/*
 * read_pam_conf - read in each entry in pam.conf and store info
 *		   under the pam handle.
 */

static int
read_pam_conf(pam_handle_t *pamh, char *config)
{
	struct pam_fh	*pam_fh;
	pamtab_t	*pamentp;
	pamtab_t	*tpament;
	char		*service;
	int		error;
	int		i = pamh->include_depth;	/* include depth */
	/*
	 * service types:
	 * error (-1), "auth" (0), "account" (1), "session" (2), "password" (3)
	 */
	int service_found[PAM_NUM_MODULE_TYPES+1] = {0, 0, 0, 0, 0};

	(void) pam_get_item(pamh, PAM_SERVICE, (void **)&service);
	if (service == NULL || *service == '\0') {
		__pam_log(LOG_AUTH | LOG_ERR, "No service name");
		return (PAM_SYSTEM_ERR);
	}

	pamh->pam_conf_name[i] = strdup(config);
	pam_trace(PAM_DEBUG_CONF, "read_pam_conf[%d:%s](%p) open(%s)",
	    i, pam_trace_cname(pamh), (void *)pamh, config);
	if (open_pam_conf(&pam_fh, pamh, config) == 0) {
		return (PAM_SYSTEM_ERR);
	}

	while ((error =
	    get_pam_conf_entry(pam_fh, pamh, &pamentp)) == PAM_SUCCESS &&
	    pamentp) {

		/* See if entry is this service and valid */
		if (verify_pam_conf(pamentp, service)) {
			pam_trace(PAM_DEBUG_CONF,
			    "read_pam_conf[%d:%s](%p): bad entry error %s",
			    i, pam_trace_cname(pamh), (void *)pamh, service);

			error = PAM_SYSTEM_ERR;
			free_pamconf(pamentp);
			goto out;
		}
		if (strcasecmp(pamentp->pam_service, service) == 0) {
			pam_trace(PAM_DEBUG_CONF,
			    "read_pam_conf[%d:%s](%p): processing %s",
			    i, pam_trace_cname(pamh), (void *)pamh, service);
			/* process first service entry */
			if (service_found[pamentp->pam_type + 1] == 0) {
				/* purge "other" entries */
				while ((tpament = pamh->pam_conf_info[i]
				    [pamentp->pam_type]) != NULL) {
					pam_trace(PAM_DEBUG_CONF,
					    "read_pam_conf(%p): purging "
					    "\"other\"[%d:%s][%s]",
					    (void *)pamh, i,
					    pam_trace_cname(pamh),
					    pam_snames[pamentp->pam_type]);
					pamh->pam_conf_info[i]
					    [pamentp->pam_type] = tpament->next;
					free_pamconf(tpament);
				}
				/* add first service entry */
				pam_trace(PAM_DEBUG_CONF,
				    "read_pam_conf(%p): adding 1st "
				    "%s[%d:%s][%s]",
				    (void *)pamh, service, i,
				    pam_trace_cname(pamh),
				    pam_snames[pamentp->pam_type]);
				pamh->pam_conf_info[i][pamentp->pam_type] =
				    pamentp;
				service_found[pamentp->pam_type + 1] = 1;
			} else {
				/* append more service entries */
				pam_trace(PAM_DEBUG_CONF,
				    "read_pam_conf(%p): adding more "
				    "%s[%d:%s][%s]",
				    (void *)pamh, service, i,
				    pam_trace_cname(pamh),
				    pam_snames[pamentp->pam_type]);
				tpament =
				    pamh->pam_conf_info[i][pamentp->pam_type];
				while (tpament->next != NULL) {
					tpament = tpament->next;
				}
				tpament->next = pamentp;
			}
		} else if (service_found[pamentp->pam_type + 1] == 0) {
			/* See if "other" entry available and valid */
			if (verify_pam_conf(pamentp, "other")) {
				pam_trace(PAM_DEBUG_CONF,
				    "read_pam_conf(%p): bad entry error %s "
				    "\"other\"[%d:%s]",
				    (void *)pamh, service, i,
				    pam_trace_cname(pamh));
				error = PAM_SYSTEM_ERR;
				free_pamconf(pamentp);
				goto out;
			}
			if (strcasecmp(pamentp->pam_service, "other") == 0) {
				pam_trace(PAM_DEBUG_CONF,
				    "read_pam_conf(%p): processing "
				    "\"other\"[%d:%s]", (void *)pamh, i,
				    pam_trace_cname(pamh));
				if ((tpament = pamh->pam_conf_info[i]
				    [pamentp->pam_type]) == NULL) {
					/* add first "other" entry */
					pam_trace(PAM_DEBUG_CONF,
					    "read_pam_conf(%p): adding 1st "
					    "other[%d:%s][%s]", (void *)pamh, i,
					    pam_trace_cname(pamh),
					    pam_snames[pamentp->pam_type]);
					pamh->pam_conf_info[i]
					    [pamentp->pam_type] = pamentp;
				} else {
					/* append more "other" entries */
					pam_trace(PAM_DEBUG_CONF,
					    "read_pam_conf(%p): adding more "
					    "other[%d:%s][%s]", (void *)pamh, i,
					    pam_trace_cname(pamh),
					    pam_snames[pamentp->pam_type]);
					while (tpament->next != NULL) {
						tpament = tpament->next;
					}
					tpament->next = pamentp;
				}
			} else {
				/* irrelevant entry */
				free_pamconf(pamentp);
			}
		} else {
			/* irrelevant entry */
			free_pamconf(pamentp);
		}
	}
out:
	(void) close_pam_conf(pam_fh);
	if (error != PAM_SUCCESS)
		free_pam_conf_info(pamh);
	return (error);
}

/*
 * get_pam_conf_entry - get a pam.conf entry
 */

static int
get_pam_conf_entry(struct pam_fh *pam_fh, pam_handle_t *pamh, pamtab_t **pam)
{
	char		*cp, *arg;
	int		argc;
	char		*tmp, *tmp_free;
	int		i;
	char		*current_line = NULL;
	int		error = PAM_SYSTEM_ERR;	/* preset to error */
	int		err;

	/* get the next line from pam.conf */
	if ((cp = nextline(pam_fh, pamh, &err)) == NULL) {
		/* no more lines in pam.conf ==> return */
		error = PAM_SUCCESS;
		*pam = NULL;
		goto out;
	}

	if ((*pam = calloc(1, sizeof (pamtab_t))) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR, "strdup: out of memory");
		goto out;
	}

	/* copy full line for error reporting */
	if ((current_line = strdup(cp)) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR, "strdup: out of memory");
		goto out;
	}

	pam_trace(PAM_DEBUG_CONF,
	    "pam.conf[%s] entry:\t%s", pam_trace_cname(pamh), current_line);

	/* get service name (e.g. login, su, passwd) */
	if ((arg = read_next_token(&cp)) == 0) {
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "illegal pam.conf[%s] entry: %s: missing SERVICE NAME",
		    pam_trace_cname(pamh), current_line);
		goto out;
	}
	if (((*pam)->pam_service = strdup(arg)) == 0) {
		__pam_log(LOG_AUTH | LOG_ERR, "strdup: out of memory");
		goto out;
	}

	/* get module type (e.g. authentication, acct mgmt) */
	if ((arg = read_next_token(&cp)) == 0) {
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "illegal pam.conf[%s] entry: %s: missing MODULE TYPE",
		    pam_trace_cname(pamh), current_line);
		(*pam)->pam_type = -1;	/* 0 is a valid value */
		goto getflag;
	}
	if (strcasecmp(arg, PAM_AUTH_NAME) == 0) {
		(*pam)->pam_type = PAM_AUTH_MODULE;
	} else if (strcasecmp(arg, PAM_ACCOUNT_NAME) == 0) {
		(*pam)->pam_type = PAM_ACCOUNT_MODULE;
	} else if (strcasecmp(arg, PAM_SESSION_NAME) == 0) {
		(*pam)->pam_type = PAM_SESSION_MODULE;
	} else if (strcasecmp(arg, PAM_PASSWORD_NAME) == 0) {
		(*pam)->pam_type = PAM_PASSWORD_MODULE;
	} else {
		/* error */
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "illegal pam.conf[%s] entry: %s: invalid module "
		    "type: %s", pam_trace_cname(pamh), current_line, arg);
		(*pam)->pam_type = -1;	/* 0 is a valid value */
	}

getflag:
	/* get pam flag (e.g., requisite, required, sufficient, optional) */
	if ((arg = read_next_token(&cp)) == 0) {
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "illegal pam.conf[%s] entry: %s: missing CONTROL FLAG",
		    pam_trace_cname(pamh), current_line);
		goto getpath;
	}
	if (strcasecmp(arg, PAM_BINDING_NAME) == 0) {
		(*pam)->pam_flag = PAM_BINDING;
	} else if (strcasecmp(arg, PAM_INCLUDE_NAME) == 0) {
		(*pam)->pam_flag = PAM_INCLUDE;
	} else if (strcasecmp(arg, PAM_OPTIONAL_NAME) == 0) {
		(*pam)->pam_flag = PAM_OPTIONAL;
	} else if (strcasecmp(arg, PAM_REQUIRED_NAME) == 0) {
		(*pam)->pam_flag = PAM_REQUIRED;
	} else if (strcasecmp(arg, PAM_REQUISITE_NAME) == 0) {
		(*pam)->pam_flag = PAM_REQUISITE;
	} else if (strcasecmp(arg, PAM_SUFFICIENT_NAME) == 0) {
		(*pam)->pam_flag = PAM_SUFFICIENT;
	} else {
		/* error */
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "illegal pam.conf[%s] entry: %s",
		    pam_trace_cname(pamh), current_line);
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "\tinvalid control flag: %s", arg);
	}

getpath:
	/* get module path (e.g. /usr/lib/security/pam_unix_auth.so.1) */
	if ((arg = read_next_token(&cp)) == 0) {
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "illegal pam.conf[%s] entry: %s: missing MODULE PATH",
		    pam_trace_cname(pamh), current_line);
		error = PAM_SUCCESS;	/* success */
		goto out;
	}
	if (arg[0] != '/') {
		size_t len;
		/*
		 * If module path does not start with "/", then
		 * prepend PAM_LIB_DIR (/usr/lib/security/).
		 */
		/* sizeof (PAM_LIB_DIR) has room for '\0' */
		len = sizeof (PAM_LIB_DIR) + sizeof (PAM_ISA_DIR) + strlen(arg);
		if (((*pam)->module_path = malloc(len)) == NULL) {
			__pam_log(LOG_AUTH | LOG_ERR, "strdup: out of memory");
			goto out;
		}
		if ((*pam)->pam_flag & PAM_INCLUDE) {
			(void) snprintf((*pam)->module_path, len, "%s%s",
			    PAM_LIB_DIR, arg);
		} else {
			(void) snprintf((*pam)->module_path, len, "%s%s%s",
			    PAM_LIB_DIR, PAM_ISA_DIR, arg);
		}
	} else {
		/* Full path provided for module */
		char *isa;

		/* Check for Instruction Set Architecture indicator */
		if ((isa = strstr(arg, PAM_ISA)) != NULL) {
			size_t len;
			len = strlen(arg) - (sizeof (PAM_ISA)-1) +
			    sizeof (PAM_ISA_DIR);

			/* substitute the architecture dependent path */
			if (((*pam)->module_path = malloc(len)) == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "strdup: out of memory");
				goto out;
			}
			*isa = '\000';
			isa += strlen(PAM_ISA);
			(void) snprintf((*pam)->module_path, len, "%s%s%s",
			    arg, PAM_ISA_DIR, isa);
		} else if (((*pam)->module_path = strdup(arg)) == 0) {
			__pam_log(LOG_AUTH | LOG_ERR, "strdup: out of memory");
			goto out;
		}
	}

	/* count the number of module-specific options first */
	argc = 0;
	if ((tmp = strdup(cp)) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR, "strdup: out of memory");
		goto out;
	}
	tmp_free = tmp;
	for (arg = read_next_token(&tmp); arg; arg = read_next_token(&tmp))
		argc++;
	free(tmp_free);

	/* allocate array for the module-specific options */
	if (argc > 0) {
		if (((*pam)->module_argv =
		    calloc(argc+1, sizeof (char *))) == 0) {
			__pam_log(LOG_AUTH | LOG_ERR, "calloc: out of memory");
			goto out;
		}
		i = 0;
		for (arg = read_next_token(&cp); arg;
		    arg = read_next_token(&cp)) {
			(*pam)->module_argv[i] = strdup(arg);
			if ((*pam)->module_argv[i] == NULL) {
				__pam_log(LOG_AUTH | LOG_ERR, "strdup failed");
				goto out;
			}
			i++;
		}
		(*pam)->module_argv[argc] = NULL;
	}
	(*pam)->module_argc = argc;

	error = PAM_SUCCESS;	/* success */
	(*pam)->pam_err = err;	/* was the line truncated */

out:
	if (current_line)
		free(current_line);
	if (error != PAM_SUCCESS) {
		/* on error free this */
		if (*pam)
			free_pamconf(*pam);
	}
	return (error);
}


/*
 * read_next_token - skip tab and space characters and return the next token
 */

static char *
read_next_token(char **cpp)
{
	register char *cp = *cpp;
	char *start;

	if (cp == (char *)0) {
		*cpp = (char *)0;
		return ((char *)0);
	}
	while (*cp == ' ' || *cp == '\t')
		cp++;
	if (*cp == '\0') {
		*cpp = (char *)0;
		return ((char *)0);
	}
	start = cp;
	while (*cp && *cp != ' ' && *cp != '\t')
		cp++;
	if (*cp != '\0')
		*cp++ = '\0';
	*cpp = cp;
	return (start);
}

static char *
pam_conf_strnchr(char *sp, int c, intptr_t count)
{
	while (count) {
		if (*sp == (char)c)
			return ((char *)sp);
		else {
			sp++;
			count--;
		}
	};
	return (NULL);
}

/*
 * nextline - skip all blank lines and comments
 */

static char *
nextline(struct pam_fh *pam_fh, pam_handle_t *pamh, int *err)
{
	char	*ll;
	int	find_a_line = 0;
	char	*data = pam_fh->data;
	char	*bufferp = pam_fh->bufferp;
	char	*bufferendp = &data[pam_fh->bufsize];
	size_t	input_len;

	/*
	 * Skip the blank line, comment line
	 */
	while (!find_a_line) {
		/* if we are at the end of the buffer, there is no next line */
		if (bufferp == bufferendp)
			return (NULL);

		/* skip blank line */
		while (*bufferp == '\n') {
			/*
			 * If we are at the end of the buffer, there is
			 * no next line.
			 */
			if (++bufferp == bufferendp) {
				return (NULL);
			}
			/* else we check *bufferp again */
		}

		/* skip comment line */
		while (*bufferp == '#') {
			if ((ll = pam_conf_strnchr(bufferp, '\n',
			    bufferendp - bufferp)) != NULL) {
				bufferp = ll;
			} else {
				/*
				 * this comment line the last line.
				 * no next line
				 */
				return (NULL);
			}

			/*
			 * If we are at the end of the buffer, there is
			 * no next line.
			 */
			if (bufferp == bufferendp) {
				return (NULL);
			}
		}

		if ((*bufferp != '\n') && (*bufferp != '#')) {
			find_a_line = 1;
		}
	}

	*err = PAM_SUCCESS;
	/* now we find one line */
	if ((ll = pam_conf_strnchr(bufferp, '\n', bufferendp - bufferp))
	    != NULL) {
		if ((input_len = ll - bufferp) >= sizeof (pam_fh->line)) {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "nextline[%d:%s]: pam.conf line too long %.256s",
			    pamh->include_depth, pam_trace_cname(pamh),
			    bufferp);
			input_len = sizeof (pam_fh->line) - 1;
			*err = PAM_SERVICE_ERR;
		}
		(void) strncpy(pam_fh->line, bufferp, input_len);
		pam_fh->line[input_len] = '\0';
		pam_fh->bufferp = ll++;
	} else {
		ll = bufferendp;
		if ((input_len = ll - bufferp) >= sizeof (pam_fh->line)) {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "nextline[%d:%s]: pam.conf line too long %.256s",
			    pamh->include_depth, pam_trace_cname(pamh),
			    bufferp);
			input_len = sizeof (pam_fh->line) - 1;
			*err = PAM_SERVICE_ERR;
		}
		(void) strncpy(pam_fh->line, bufferp, input_len);
		pam_fh->line[input_len] = '\0';
		pam_fh->bufferp = ll;
	}

	return (pam_fh->line);
}

/*
 * verify_pam_conf - verify that the pam_conf entry is filled in.
 *
 *	True = Error if there is no service.
 *	True = Error if there is a service and it matches the requested service
 *		but, the type, flag, line overflow, or path is in error.
 */

static int
verify_pam_conf(pamtab_t *pam, char *service)
{
	return ((pam->pam_service == (char *)NULL) ||
	    ((strcasecmp(pam->pam_service, service) == 0) &&
	    ((pam->pam_type == -1) ||
	    (pam->pam_flag == 0) ||
	    (pam->pam_err != PAM_SUCCESS) ||
	    (pam->module_path == (char *)NULL))));
}

/*
 * Routines to free allocated storage
 */

/*
 * clean_up -  free allocated storage in the pam handle
 */

static void
clean_up(pam_handle_t *pamh)
{
	int i;
	pam_repository_t *auth_rep;

	if (pamh) {
		while (pamh->include_depth >= 0) {
			free_pam_conf_info(pamh);
			pamh->include_depth--;
		}

		/* Cleanup PAM_REPOSITORY structure */
		auth_rep = pamh->ps_item[PAM_REPOSITORY].pi_addr;
		if (auth_rep != NULL) {
			if (auth_rep->type != NULL)
				free(auth_rep->type);
			if (auth_rep->scope != NULL)
				free(auth_rep->scope);
		}

		for (i = 0; i < PAM_MAX_ITEMS; i++) {
			if (pamh->ps_item[i].pi_addr != NULL) {
				if (i == PAM_AUTHTOK || i == PAM_OLDAUTHTOK) {
					(void) memset(pamh->ps_item[i].pi_addr,
					    0, pamh->ps_item[i].pi_size);
				}
				free(pamh->ps_item[i].pi_addr);
			}
		}
		free(pamh);
	}
}

/*
 * free_pamconf - free memory used to store pam.conf entry
 */

static void
free_pamconf(pamtab_t *cp)
{
	int i;

	if (cp) {
		if (cp->pam_service)
			free(cp->pam_service);
		if (cp->module_path)
			free(cp->module_path);
		for (i = 0; i < cp->module_argc; i++) {
			if (cp->module_argv[i])
				free(cp->module_argv[i]);
		}
		if (cp->module_argc > 0)
			free(cp->module_argv);
		if (cp->function_ptr)
			free(cp->function_ptr);

		free(cp);
	}
}

/*
 * free_pam_conf_info - free memory used to store all pam.conf info
 *			under the pam handle
 */

static void
free_pam_conf_info(pam_handle_t *pamh)
{
	pamtab_t *pamentp;
	pamtab_t *pament_trail;
	int i = pamh->include_depth;
	int j;

	for (j = 0; j < PAM_NUM_MODULE_TYPES; j++) {
		pamentp = pamh->pam_conf_info[i][j];
		pamh->pam_conf_info[i][j] = NULL;
		pament_trail = pamentp;
		while (pamentp) {
			pamentp = pamentp->next;
			free_pamconf(pament_trail);
			pament_trail = pamentp;
		}
	}
	if (pamh->pam_conf_name[i] != NULL) {
		free(pamh->pam_conf_name[i]);
		pamh->pam_conf_name[i] = NULL;
	}
}

static void
free_env(env_list *pam_env)
{
	if (pam_env) {
		if (pam_env->name)
			free(pam_env->name);
		if (pam_env->value)
			free(pam_env->value);
		free(pam_env);
	}
}

/*
 *	Internal convenience functions for Solaris PAM service modules.
 */

#include <libintl.h>
#include <nl_types.h>
#include <synch.h>
#include <locale.h>
#include <thread.h>

typedef struct pam_msg_data {
	nl_catd fd;
} pam_msg_data_t;

/*
 * free_resp():
 *	free storage for responses used in the call back "pam_conv" functions
 */

void
free_resp(int num_msg, struct pam_response *resp)
{
	int			i;
	struct pam_response	*r;

	if (resp) {
		r = resp;
		for (i = 0; i < num_msg; i++, r++) {
			if (r->resp) {
				/* clear before freeing -- may be a password */
				bzero(r->resp, strlen(r->resp));
				free(r->resp);
				r->resp = NULL;
			}
		}
		free(resp);
	}
}

static int
do_conv(pam_handle_t *pamh, int msg_style, int num_msg,
    char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE], void *conv_apdp,
    struct pam_response *ret_respp[])
{
	struct pam_message	*msg;
	struct pam_message	*m;
	int			i;
	int			k;
	int			retcode;
	struct pam_conv		*pam_convp;

	if ((retcode = pam_get_item(pamh, PAM_CONV,
	    (void **)&pam_convp)) != PAM_SUCCESS) {
		return (retcode);
	}

	/*
	 * When pam_set_item() is called to set PAM_CONV and the
	 * item is NULL, memset(pip->pi_addr, 0, size) is called.
	 * So at this point, we should check whether pam_convp->conv
	 * is NULL or not.
	 */
	if ((pam_convp == NULL) || (pam_convp->conv == NULL))
		return (PAM_SYSTEM_ERR);

	i = 0;
	k = num_msg;

	msg = calloc(num_msg, sizeof (struct pam_message));
	if (msg == NULL) {
		return (PAM_BUF_ERR);
	}
	m = msg;

	while (k--) {
		/*
		 * fill out the message structure to display prompt message
		 */
		m->msg_style = msg_style;
		m->msg = messages[i];
		pam_trace(PAM_DEBUG_CONV,
		    "pam_conv_msg(%p:%d[%d]=%s)",
		    (void *)pamh, msg_style, i, messages[i]);
		m++;
		i++;
	}

	/*
	 * The UNIX pam modules always calls __pam_get_authtok() and
	 * __pam_display_msg() with a NULL pointer as the conv_apdp.
	 * In case the conv_apdp is NULL and the pam_convp->appdata_ptr
	 * is not NULL, we should pass the pam_convp->appdata_ptr
	 * to the conversation function.
	 */
	if (conv_apdp == NULL && pam_convp->appdata_ptr != NULL)
		conv_apdp = pam_convp->appdata_ptr;

	/*
	 * Call conv function to display the prompt.
	 */
	retcode = (pam_convp->conv)(num_msg, &msg, ret_respp, conv_apdp);
	pam_trace(PAM_DEBUG_CONV,
	    "pam_conv_resp(%p pam_conv = %s) ret_respp = %p",
	    (void *)pamh, pam_strerror(pamh, retcode), (void *)ret_respp);
	if (*ret_respp == NULL) {
		pam_trace(PAM_DEBUG_CONV,
		    "pam_conv_resp(%p No response requested)", (void *)pamh);
	} else if ((pam_debug & (PAM_DEBUG_CONV | PAM_DEBUG_AUTHTOK)) != 0) {
		struct pam_response *r = *ret_respp;

		for (i = 0; i < num_msg; i++, r++) {
			if (r->resp == NULL) {
				pam_trace(PAM_DEBUG_CONV,
				    "pam_conv_resp(%p:"
				    "[%d] NULL response string)",
				    (void *)pamh, i);
			} else {
				if (msg_style == PAM_PROMPT_ECHO_OFF) {
#ifdef	DEBUG
					pam_trace(PAM_DEBUG_AUTHTOK,
					    "pam_conv_resp(%p:[%d]=%s, "
					    "code=%d)",
					    (void *)pamh, i, r->resp,
					    r->resp_retcode);
#endif	/* DEBUG */
					pam_trace(PAM_DEBUG_CONV,
					    "pam_conv_resp(%p:[%d] len=%lu, "
					    "code=%d)",
					    (void *)pamh, i,
					    (ulong_t)strlen(r->resp),
					    r->resp_retcode);
				} else {
					pam_trace(PAM_DEBUG_CONV,
					    "pam_conv_resp(%p:[%d]=%s, "
					    "code=%d)",
					    (void *)pamh, i, r->resp,
					    r->resp_retcode);
				}
			}
		}
	}

	if (msg)
		free(msg);
	return (retcode);
}

/*
 * __pam_display_msg():
 *	display message by calling the call back functions
 *	provided by the application through "pam_conv" structure
 */

int
__pam_display_msg(pam_handle_t *pamh, int msg_style, int num_msg,
    char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE], void *conv_apdp)
{
	struct pam_response	*ret_respp = NULL;
	int ret;

	ret = do_conv(pamh, msg_style, num_msg, messages,
	    conv_apdp, &ret_respp);

	if (ret_respp != NULL)
		free_resp(num_msg, ret_respp);

	return (ret);
}

/*
 * __pam_get_authtok()
 *	retrieves a password of at most PASS_MAX length from the pam
 *	handle (pam_get_item) or from the input stream (do_conv).
 *
 * This function allocates memory for the new authtok.
 * Applications calling this function are responsible for
 * freeing this memory.
 *
 * If "source" is
 *	PAM_HANDLE
 * and "type" is:
 *	PAM_AUTHTOK - password is taken from pam handle (PAM_AUTHTOK)
 *	PAM_OLDAUTHTOK - password is taken from pam handle (PAM_OLDAUTHTOK)
 *
 * If "source" is
 *	PAM_PROMPT
 * and "type" is:
 *	0:		Prompt for new passwd, do not even attempt
 *			to store it in the pam handle.
 *	PAM_AUTHTOK:	Prompt for new passwd, store in pam handle as
 *			PAM_AUTHTOK item if this value is not already set.
 *	PAM_OLDAUTHTOK:	Prompt for new passwd, store in pam handle as
 *			PAM_OLDAUTHTOK item if this value is not
 *			already set.
 */
int
__pam_get_authtok(pam_handle_t *pamh, int source, int type, char *prompt,
    char **authtok)
{
	int error = PAM_SYSTEM_ERR;
	char *new_password = NULL;
	struct pam_response *ret_resp = NULL;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	if ((*authtok = calloc(PASS_MAX+1, sizeof (char))) == NULL)
		return (PAM_BUF_ERR);

	if (prompt == NULL)
		prompt = dgettext(TEXT_DOMAIN, "password: ");

	switch (source) {
	case PAM_HANDLE:

		/* get password from pam handle item list */

		switch (type) {
		case PAM_AUTHTOK:
		case PAM_OLDAUTHTOK:

			if ((error = pam_get_item(pamh, type,
			    (void **)&new_password)) != PAM_SUCCESS)
				goto err_ret;

			if (new_password == NULL || new_password[0] == '\0') {
				free(*authtok);
				*authtok = NULL;
			} else {
				(void) strlcpy(*authtok, new_password,
				    PASS_MAX+1);
			}
			break;
		default:
			__pam_log(LOG_AUTH | LOG_ERR,
			    "__pam_get_authtok() invalid type: %d", type);
			error = PAM_SYMBOL_ERR;
			goto err_ret;
		}
		break;
	case PAM_PROMPT:

		/*
		 * Prompt for new password and save in pam handle item list
		 * if the that item is not already set.
		 */

		(void) strncpy(messages[0], prompt, sizeof (messages[0]));
		if ((error = do_conv(pamh, PAM_PROMPT_ECHO_OFF, 1, messages,
		    NULL, &ret_resp)) != PAM_SUCCESS)
			goto err_ret;

		if (ret_resp->resp == NULL) {
			/* getpass didn't return anything */
			error = PAM_SYSTEM_ERR;
			goto err_ret;
		}

		/* save the new password if this item was NULL */
		if (type) {
			if ((error = pam_get_item(pamh, type,
			    (void **)&new_password)) != PAM_SUCCESS) {
				free_resp(1, ret_resp);
				goto err_ret;
			}
			if (new_password == NULL)
				(void) pam_set_item(pamh, type, ret_resp->resp);
		}

		(void) strlcpy(*authtok, ret_resp->resp, PASS_MAX+1);
		free_resp(1, ret_resp);
		break;
	default:
		__pam_log(LOG_AUTH | LOG_ERR,
		    "__pam_get_authtok() invalid source: %d", source);
		error = PAM_SYMBOL_ERR;
		goto err_ret;
	}

	return (PAM_SUCCESS);

err_ret:
	bzero(*authtok, PASS_MAX+1);
	free(*authtok);
	*authtok = NULL;
	return (error);
}
