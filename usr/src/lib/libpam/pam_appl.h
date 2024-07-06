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
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _PAM_APPL_H
#define	_PAM_APPL_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Generic PAM errors */
#define	PAM_SUCCESS		0	/* Normal function return */
#define	PAM_OPEN_ERR		1	/* Dlopen failure */
#define	PAM_SYMBOL_ERR		2	/* Symbol not found */
#define	PAM_SERVICE_ERR		3	/* Error in underlying service module */
#define	PAM_SYSTEM_ERR		4	/* System error */
#define	PAM_BUF_ERR		5	/* Memory buffer error */
#define	PAM_CONV_ERR		6	/* Conversation failure */
#define	PAM_PERM_DENIED		7	/* Permission denied */

/* Errors returned by pam_authenticate, pam_acct_mgmt(), and pam_setcred() */
#define	PAM_MAXTRIES		8	/* Maximum number of tries exceeded */
#define	PAM_AUTH_ERR		9	/* Authentication failure */
#define	PAM_NEW_AUTHTOK_REQD	10	/* Get new auth token from the user */
#define	PAM_CRED_INSUFFICIENT	11	/* can not access auth data b/c */
					/* of insufficient credentials  */
#define	PAM_AUTHINFO_UNAVAIL	12	/* Can not retrieve auth information */
#define	PAM_USER_UNKNOWN	13	/* No account present for user */

/* Errors returned by pam_setcred() */
#define	PAM_CRED_UNAVAIL	14	/* can not retrieve user credentials */
#define	PAM_CRED_EXPIRED	15	/* user credentials expired */
#define	PAM_CRED_ERR		16	/* failure setting user credentials */

/* Errors returned by pam_acct_mgmt() */
#define	PAM_ACCT_EXPIRED	17	/* user account has expired */
#define	PAM_AUTHTOK_EXPIRED 	18	/* Password expired and no longer */
					/* usable */

/* Errors returned by pam_open/close_session() */
#define	PAM_SESSION_ERR		19	/* can not make/remove entry for */
					/* specified session */

/* Errors returned by pam_chauthtok() */
#define	PAM_AUTHTOK_ERR		  20	/* Authentication token */
					/*   manipulation error */
#define	PAM_AUTHTOK_RECOVERY_ERR  21	/* Old authentication token */
					/*   cannot be recovered */
#define	PAM_AUTHTOK_LOCK_BUSY	  22	/* Authentication token */
					/*   lock busy */
#define	PAM_AUTHTOK_DISABLE_AGING 23	/* Authentication token aging */
					/*   is disabled */

/* Errors returned by pam_get_data */
#define	PAM_NO_MODULE_DATA	24	/* module data not found */

/* Errors returned by modules */
#define	PAM_IGNORE		25	/* ignore module */

#define	PAM_ABORT		26	/* General PAM failure */
#define	PAM_TRY_AGAIN		27	/* Unable to update password */
					/* Try again another time */
#define	PAM_TOTAL_ERRNUM	28

/*
 * structure pam_message is used to pass prompt, error message,
 * or any text information from scheme to application/user.
 */

struct pam_message {
	int msg_style;		/* Msg_style - see below */
	char *msg; 		/* Message string */
};

/*
 * msg_style defines the interaction style between the
 * scheme and the application.
 */
#define	PAM_PROMPT_ECHO_OFF	1	/* Echo off when getting response */
#define	PAM_PROMPT_ECHO_ON	2 	/* Echo on when getting response */
#define	PAM_ERROR_MSG		3	/* Error message */
#define	PAM_TEXT_INFO		4	/* Textual information */

/*
 * max # of messages passed to the application through the
 * conversation function call
 */
#define	PAM_MAX_NUM_MSG	32

/*
 * max size (in chars) of each messages passed to the application
 * through the conversation function call
 */
#define	PAM_MAX_MSG_SIZE	512

/*
 * max size (in chars) of each response passed from the application
 * through the conversation function call
 */
#define	PAM_MAX_RESP_SIZE	512

/*
 * structure pam_response is used by the scheme to get the user's
 * response back from the application/user.
 */

struct pam_response {
	char *resp;		/* Response string */
	int resp_retcode;	/* Return code - for future use */
};

/*
 * structure pam_conv is used by authentication applications for passing
 * call back function pointers and application data pointers to the scheme
 */
struct pam_conv {
#ifdef _PAM_LEGACY_NONCONST
	int (*conv)(int, struct pam_message **,
#else
	int (*conv)(int, const struct pam_message **,
#endif
	    struct pam_response **, void *);
	void *appdata_ptr;		/* Application data ptr */
};

/* the pam handle */
typedef struct pam_handle pam_handle_t;

/*
 * pam_start() is called to initiate an authentication exchange
 * with PAM.
 */
extern int
pam_start(
	const char *service_name,		/* Service Name */
	const char *user,			/* User Name */
	const struct pam_conv *pam_conv,	/* Conversation structure */
	pam_handle_t **pamh		/* Address to store handle */
);

/*
 * pam_end() is called to end an authentication exchange with PAM.
 */
extern int
pam_end(
	pam_handle_t *pamh,		/* handle from pam_start() */
	int status			/* the final status value that */
					/* gets passed to cleanup functions */
);

/*
 * pam_set_item is called to store an object in PAM handle.
 */
extern int
pam_set_item(
	pam_handle_t *pamh,		/* PAM handle */
	int item_type, 			/* Type of object - see below */
	const void *item		/* Address of place to put pointer */
					/*   to object */
);

/*
 * pam_get_item is called to retrieve an object from the static data area
 */
extern int
pam_get_item(
	const pam_handle_t *pamh, 	/* PAM handle */
	int item_type, 			/* Type of object - see below */
#ifdef _PAM_LEGACY_NONCONST
	void **item			/* Address of place to put pointer */
#else
	const void **item		/* Address of place to put pointer */
#endif
					/*   to object */
);

/* Items supported by pam_[sg]et_item() calls */
#define	PAM_SERVICE	1		/* The program/service name */
#define	PAM_USER	2		/* The user name */
#define	PAM_TTY		3		/* The tty name */
#define	PAM_RHOST	4		/* The remote host name */
#define	PAM_CONV	5		/* The conversation structure */
#define	PAM_AUTHTOK	6		/* The authentication token */
#define	PAM_OLDAUTHTOK	7		/* Old authentication token */
#define	PAM_RUSER	8		/* The remote user name */
#define	PAM_USER_PROMPT	9		/* The user prompt */
#define	PAM_REPOSITORY	10		/* The repository to be updated */
#define	PAM_RESOURCE	11		/* Resource management info */
#define	PAM_AUSER	12		/* The authenticated user name */

/* pam repository structure */

struct pam_repository {
	char   *type;		/* Repository type, e.g., files, nis, ldap */
	void   *scope;		/* Optional scope information */
	size_t  scope_len;	/* length of scope inforamtion */
};

typedef struct pam_repository pam_repository_t;

/*
 * pam_get_user is called to retrieve the user name (PAM_USER). If PAM_USER
 * is not set then this call will prompt for the user name using the
 * conversation function. This function should only be used by modules, not
 * applications.
 */

extern int
pam_get_user(
	pam_handle_t *pamh,	/* PAM handle */
#ifdef _PAM_LEGACY_NONCONST
	char **user, 		/* User Name */
#else
	const char **user, 	/* User Name */
#endif
	const char *prompt	/* Prompt */
);

/*
 * PAM equivalent to strerror();
 */
extern const char *
pam_strerror(
	pam_handle_t *pamh,	/* pam handle */
	int errnum		/* error number */
);

/* general flag for pam_* functions */
#define	PAM_SILENT	0x80000000

/*
 * pam_authenticate is called to authenticate the current user.
 */
extern int
pam_authenticate(
	pam_handle_t *pamh,
	int flags
);

/*
 * Flags for pam_authenticate
 */

#define	PAM_DISALLOW_NULL_AUTHTOK 0x1	/* The password must be non-null */

/*
 * pam_acct_mgmt is called to perform account management processing
 */
extern int
pam_acct_mgmt(
	pam_handle_t *pamh,
	int flags
);

/*
 * pam_open_session is called to note the initiation of new session in the
 * appropriate administrative data bases.
 */
extern int
pam_open_session(
	pam_handle_t *pamh,
	int flags
);

/*
 * pam_close_session records the termination of a session.
 */
extern int
pam_close_session(
	pam_handle_t	*pamh,
	int		flags
);

/* pam_setcred is called to set the credentials of the current user */
extern int
pam_setcred(
	pam_handle_t *pamh,
	int flags
);

/* flags for pam_setcred() */
#define	PAM_ESTABLISH_CRED	0x1	/* set scheme specific user id */
#define	PAM_DELETE_CRED		0x2	/* unset scheme specific user id */
#define	PAM_REINITIALIZE_CRED	0x4	/* reinitialize user credentials */
					/* (after a password has changed */
#define	PAM_REFRESH_CRED	0x8	/* extend lifetime of credentials */

/* pam_chauthtok is called to change authentication token */

extern int
pam_chauthtok(
	pam_handle_t	*pamh,
	int		flags
);

/*
 * Be careful - there are flags defined for pam_sm_chauthtok() in
 * pam_modules.h also:
 * PAM_PRELIM_CHECK	0x1
 * PAM_UPDATE_AUTHTOK	0x2
 */
#define	PAM_CHANGE_EXPIRED_AUTHTOK	0x4 /* update expired passwords only */
#define	PAM_NO_AUTHTOK_CHECK		0x8 /* bypass password strength tests */

/* pam_putenv is called to add environment variables to the PAM handle */

extern int
pam_putenv(
	pam_handle_t	*pamh,
	const char	*name_value
);

/* pam_getenv is called to retrieve an env variable from the PAM handle */

#ifdef _PAM_LEGACY_NONCONST
extern char *
#else
extern const char *
#endif
pam_getenv(
	pam_handle_t	*pamh,
	const char	*name
);

/* pam_getenvlist is called to retrieve all env variables from the PAM handle */

extern char **
pam_getenvlist(
	pam_handle_t	*pamh
);

#ifdef	__cplusplus
}
#endif

#endif /* _PAM_APPL_H */
