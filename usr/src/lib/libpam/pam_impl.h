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

#ifndef	_PAM_IMPL_H
#define	_PAM_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <shadow.h>
#include <sys/types.h>

#define	PAMTXD		"SUNW_OST_SYSOSPAM"

#define	PAM_CONFIG	"/etc/pam.conf"
#define	PAM_ISA		"/$ISA/"
#define	PAM_LIB_DIR	"/usr/lib/security/"
#ifdef	_LP64
#define	PAM_ISA_DIR	"/64/"
#else	/* !_LP64 */
#define	PAM_ISA_DIR	"/"
#endif	/* _LP64 */

/* Service Module Types */

/*
 * If new service types are added, they should be named in
 * pam_framework.c::pam_snames[] as well.
 */

#define	PAM_ACCOUNT_NAME	"account"
#define	PAM_AUTH_NAME		"auth"
#define	PAM_PASSWORD_NAME	"password"
#define	PAM_SESSION_NAME	"session"

#define	PAM_ACCOUNT_MODULE	0
#define	PAM_AUTH_MODULE		1
#define	PAM_PASSWORD_MODULE	2
#define	PAM_SESSION_MODULE	3

#define	PAM_NUM_MODULE_TYPES	4

/* Control Flags */

#define	PAM_BINDING_NAME	"binding"
#define	PAM_INCLUDE_NAME	"include"
#define	PAM_OPTIONAL_NAME	"optional"
#define	PAM_REQUIRED_NAME	"required"
#define	PAM_REQUISITE_NAME	"requisite"
#define	PAM_SUFFICIENT_NAME	"sufficient"

#define	PAM_BINDING	0x01
#define	PAM_INCLUDE	0x02
#define	PAM_OPTIONAL	0x04
#define	PAM_REQUIRED	0x08
#define	PAM_REQUISITE	0x10
#define	PAM_SUFFICIENT	0x20

#define	PAM_REQRD_BIND	(PAM_REQUIRED | PAM_BINDING)
#define	PAM_SUFFI_BIND	(PAM_SUFFICIENT | PAM_BINDING)

/* Function Indicators */

#define	PAM_AUTHENTICATE	1
#define	PAM_SETCRED		2
#define	PAM_ACCT_MGMT		3
#define	PAM_OPEN_SESSION	4
#define	PAM_CLOSE_SESSION	5
#define	PAM_CHAUTHTOK		6

/* PAM tracing */

#define	PAM_DEBUG	"/etc/pam_debug"
#define	LOG_PRIORITY	"log_priority="
#define	LOG_FACILITY	"log_facility="
#define	DEBUG_FLAGS	"debug_flags="
#define	PAM_DEBUG_NONE		0x0000
#define	PAM_DEBUG_DEFAULT	0x0001
#define	PAM_DEBUG_ITEM		0x0002
#define	PAM_DEBUG_MODULE	0x0004
#define	PAM_DEBUG_CONF		0x0008
#define	PAM_DEBUG_DATA		0x0010
#define	PAM_DEBUG_CONV		0x0020
#define	PAM_DEBUG_AUTHTOK	0x8000

#define	PAM_MAX_ITEMS		64	/* Max number of items */
#define	PAM_MAX_INCLUDE		32	/* Max include flag recursions */

/* authentication module functions */
#define	PAM_SM_AUTHENTICATE	"pam_sm_authenticate"
#define	PAM_SM_SETCRED		"pam_sm_setcred"

/* session module functions */
#define	PAM_SM_OPEN_SESSION	"pam_sm_open_session"
#define	PAM_SM_CLOSE_SESSION	"pam_sm_close_session"

/* password module functions */
#define	PAM_SM_CHAUTHTOK		"pam_sm_chauthtok"

/* account module functions */
#define	PAM_SM_ACCT_MGMT		"pam_sm_acct_mgmt"

/* max # of authentication token attributes */
#define	PAM_MAX_NUM_ATTR	10

/* max size (in chars) of an authentication token attribute */
#define	PAM_MAX_ATTR_SIZE	80

/* utility function prototypes */

/* source values when calling __pam_get_authtok() */
#define	PAM_PROMPT	1	/* prompt user for new password */
#define	PAM_HANDLE	2	/* get password from pam handle (item) */

#if	PASS_MAX >= PAM_MAX_RESP_SIZE
#error	PASS_MAX > PAM_MAX_RESP_SIZE
#endif	/* PASS_MAX >= PAM_MAX_RESP_SIZE */

extern int
__pam_get_authtok(pam_handle_t *pamh, int source, int type, char *prompt,
    char **authtok);

extern int
__pam_display_msg(pam_handle_t *pamh, int msg_style, int num_msg,
    char messages[][PAM_MAX_MSG_SIZE], void *conv_apdp);

extern void
__pam_log(int priority, const char *format, ...);

/* file handle for pam.conf */
struct pam_fh {
	int	fconfig;	/* file descriptor returned by open() */
	char    line[256];
	size_t  bufsize;	/* size of the buffer which holds */
				/* the content of pam.conf */
	char   *bufferp;	/* used to process data	*/
	char   *data;		/* contents of pam.conf	*/
};

/* items that can be set/retrieved thru pam_[sg]et_item() */
struct	pam_item {
	void	*pi_addr;	/* pointer to item */
	int	pi_size;	/* size of item */
};

/* module specific data stored in the pam handle */
struct pam_module_data {
	char *module_data_name;		/* unique module data name */
	void *data;			/* the module specific data */
	void (*cleanup)(pam_handle_t *pamh, void *data, int pam_status);
	struct pam_module_data *next;	/* pointer to next module data */
};

/* each entry from pam.conf is stored here (in the pam handle) */
typedef struct pamtab {
	char	*pam_service;	/* PAM service, e.g. login, rlogin */
	int	pam_type;	/* AUTH, ACCOUNT, PASSWORD, SESSION */
	int	pam_flag;	/* required, optional, sufficient */
	int	pam_err;	/* error if line overflow */
	char	*module_path;	/* module library */
	int	module_argc;	/* module specific options */
	char	**module_argv;
	void	*function_ptr;	/* pointer to struct holding function ptrs */
	struct pamtab *next;
} pamtab_t;

/* list of open fd's (modules that were dlopen'd) */
typedef struct fd_list {
	void *mh;		/* module handle */
	struct fd_list *next;
} fd_list;

/* list of PAM environment varialbes */
typedef struct env_list {
	char *name;
	char *value;
	struct env_list *next;
} env_list;

/* pam_inmodule values for pam item checking */
#define	RW_OK	0	/* Read Write items OK */
#define	RO_OK	1	/* Read Only items OK */
#define	WO_OK	2	/* Write Only items/data OK */

/* the pam handle */
struct pam_handle {
	struct  pam_item ps_item[PAM_MAX_ITEMS];	/* array of PAM items */
	int	include_depth;
	int	pam_inmodule;	/* Protect restricted pam_get_item calls */
	char	*pam_conf_name[PAM_MAX_INCLUDE+1];
	pamtab_t *pam_conf_info[PAM_MAX_INCLUDE+1][PAM_NUM_MODULE_TYPES];
	pamtab_t *pam_conf_modulep[PAM_MAX_INCLUDE+1];
	struct	pam_module_data *ssd;		/* module specific data */
	fd_list *fd;				/* module fd's */
	env_list *pam_env;			/* environment variables */
};

/*
 * the function_ptr field in pamtab_t
 * will point to one of these modules
 */
struct auth_module {
	int	(*pam_sm_authenticate)(pam_handle_t *pamh, int flags, int argc,
		    const char **argv);
	int	(*pam_sm_setcred)(pam_handle_t *pamh, int flags, int argc,
		    const char **argv);
};

struct password_module {
	int	(*pam_sm_chauthtok)(pam_handle_t *pamh, int flags, int argc,
		    const char **argv);
};

struct session_module {
	int	(*pam_sm_open_session)(pam_handle_t *pamh, int flags, int argc,
		    const char **argv);
	int	(*pam_sm_close_session)(pam_handle_t *pamh, int flags, int argc,
		    const char **argv);
};

struct account_module {
	int	(*pam_sm_acct_mgmt)(pam_handle_t *pamh, int flags, int argc,
		    const char **argv);
};

#ifdef __cplusplus
}
#endif

#endif	/* _PAM_IMPL_H */
