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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <dlfcn.h>
#include <alloca.h>
#include "lm.h"
#include <lm_proto.h>
#include "mms_strapp.h"

static	char	*_SrcFile = __FILE__;

/*
 * lm_need_libapi
 *	- type: Type of library that LM is controlling
 * The function will return 1 if the library type requires
 * LM to set LD_LIBRARY_PATH to include the path stored in SMF
 * (libapi_path)
 * If libapi is not needed for this library type return 0
 *
 */
int
lm_need_libapi(char *type) {

	/* need libapi for all acsls supported libraries */
	/* L180  L500  L700  SL500 */
	if (strcmp(type, "L180") == 0) {
		return (1);
	}
	if (strcmp(type, "L500") == 0) {
		return (1);
	}
	if (strcmp(type, "L700") == 0) {
		return (1);
	}
	if (strcmp(type, "SL500") == 0) {
		return (1);
	}
	return (0);
}




/*
 * lm_load_cmds()
 *
 * Parameters:
 *	- libName:	Type of library that LM is controlling. Ex: L700
 *	- connection:	The type of connection, network or direct
 *	- cmdData:	An array of strutures which contains the name of
 *			the LM commands and a pointer location which will
 *			contain the entry mms_address to the command processing
 *			functions which support the library type.
 *
 * Globals:
 *	None
 *
 * This functions dynamically opens a shared library that contains the
 * set of LM command processing functions that support the type of library
 * the LM is configured to control. Once opened, it searches for the
 * entry points to each of the LM commands and stores those in the cmdData
 * array.
 *
 * Return Values:
 *	NULL:		If an error was encountered.
 *	handle:		The handle to the open shared library.
 *
 */

lm_cmdHandle_t
lm_load_cmds(char *libName, int connection, lm_cmdData_t *cmdData)
{
	lm_cmdHandle_t handle;
	lm_cmdData_t *cd;
	char *cmdPathname;
	void *symAddr;
	char symName[64];

	char		*libapi_path = NULL;

	mms_trace(MMS_DEVP,
	    "lm_load_cmds : "
	    "libName == %s", libName);

	if (lm_need_libapi(libName)) {
		mms_trace(MMS_DEBUG,
		    "lm_load_cmds :"
		    "libapi needed");
		/* get libapi_path from SMF */
		if ((libapi_path =
		    mms_cfg_alloc_getvar(MMS_CFG_LIBAPI_PATH, NULL))
		    == NULL) {
			/* report service configuration */
			/* repoistory scf_error() */
			mms_trace(MMS_ERR,
			    "using default-path, libapi path cfg error");
			libapi_path = strdup("/opt/mms/lib/acsls");
		}
		mms_trace(MMS_DEBUG,
		    "lm_load_cmds :"
		    "path to libapi.so == %s",
		    libapi_path);

		libapi_path = mms_strapp(libapi_path, "/libapi.so");

		if (dlopen(libapi_path, RTLD_NOW | RTLD_GLOBAL) == NULL) {
			mms_trace(MMS_CRIT,
			    "lm_load_cmds: dlopen "
			    "failed for libapi.so, dlerror - %s",
			    dlerror());
			free(libapi_path);
			return (NULL);
		}
		free(libapi_path);
		mms_trace(MMS_DEBUG,
		    "lm_load_cmds : "
		    "libapi.so loaded successfully");
	} else {
		mms_trace(MMS_DEBUG,
		    "lm_load_cmds : "
		    "%s does not need libapi", libName);
	}




	cmdPathname = (char *)alloca(strlen(libName) +
	    strlen(CMDPATH_DIRECTORY) + 4);
	(void) strcpy(cmdPathname, CMDPATH_DIRECTORY);
	(void) strcat(cmdPathname, libName);
	if (connection == LM_DIRECT_ATTACHED)
		(void) strcat(cmdPathname, "_direct");
	else if (connection == LM_NETWORK_ATTACHED)
		(void) strcat(cmdPathname, "_net");
	(void) strcat(cmdPathname, ".so");
	mms_trace(MMS_DEBUG, "lm_load_cmds: libname - %s", cmdPathname);
	if ((handle = dlopen(cmdPathname, RTLD_NOW)) == NULL) {
		mms_trace(MMS_CRIT, "lm_load_cmds: dlopen failed, dlerror - %s",
		    dlerror());
		return (NULL);
	}

	for (cd = cmdData; cd->cd_symName != NULL; cd++) {
		(void) strcpy(&symName[0], cd->cd_symName);
		symAddr = dlsym(handle, symName);
		if (symAddr != NULL) {
			cd->cd_cmdptr = (int (*)())symAddr;
		} else {
			mms_trace(MMS_CRIT,
			    "lm_load_cmds: Cmds lib %s does not "
			    "contain cmd %s", libName, symName);
			lm_unload_cmds(handle);
			return (NULL);
		}
	}
	return (handle);
}

/*
 * lm_unload_cmds()
 *
 * Parameters:
 *	- cmdHandle	The handle that was returned from the dlopen in
 *			lm_load_cmds().
 *
 * Globals:
 *	None
 *
 * This functions closes the shared library that was dynamically opened
 * in the lm_load_cmds() routine.
 *
 * Return Values:
 *	None
 *
 */

void
lm_unload_cmds(lm_cmdHandle_t cmdHandle)
{
	(void) dlclose(cmdHandle);
}

/*
 * lm_serr()
 *
 * Parameters:
 *	- severity	The severity of the internal error encountered
 *	- file		The name of the file in which the error occurred
 *	- line		The line number in the file where the error occurred
 *	- fmt		The format of the message to be mms_printed.
 *	- ...		The variable number of arguments for the message.
 *
 * Globals:
 *	lm_internal_error	Set to indicate an internal error occured
 *	exit_code		Set so exit indicates LM can be restarted
 *
 * This function is used within LM to handle internal processing errors.
 * The function will handle what needs to be done when an internal
 * processing error occurs and then will output the message to the mms_trace
 * file.
 *
 * Return Values:
 *	None
 *
 */
void
lm_serr(mms_trace_sev_t severity, char *file, int line, char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);

	mms_trace_va(severity, file, line, fmt, args);

	va_end(args);

	exit_code = LM_RESTART;
	lm_internal_error = LM_ERROR;
}

/*
 * lm_log()
 *
 * Parameters:
 *	- priority	The syslog priority of the error
 *	- fmt		The format of the log message to be mms_printed
 *	- ...		The variable number of arguments for the message.
 *
 * Globals:
 *	lm_daemon_mode	Uses this to know if it should print message to
 *			syslog or stderr.
 *
 * This function is used to print messages that should go to syslog
 * if LM is in daemon mode or to stderr if it is running in standalone mode.
 *
 * Return Values:
 *	None
 *
 */
void
lm_log(int priority, char *fmt, ...)
{
	int	count;
	char	tmp[10];
	char	*ptr;
	va_list	args;

	if (lm_daemon_mode)
		openlog("MMS_LM", LOG_PID | LOG_NOWAIT, LOG_LOCAL7);

	va_start(args, fmt);

	/* LINTED [E_SEC_PRINTF_VAR_FMT] */
	if ((count = vsnprintf(tmp, 10, fmt, args)) == -1) {
		va_end(args);
		return;
	}

	if ((ptr = (char *)malloc(count + 1)) == NULL) {
		va_end(args);
		return;
	}

	/* LINTED [E_SEC_PRINTF_VAR_FMT] */
	if (vsprintf(ptr, fmt, args) < 0) {
		va_end(args);
		free(ptr);
		return;
	}

	va_end(args);

	if (lm_daemon_mode) {
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		syslog(priority, ptr);
		closelog();
	} else
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		(void) fprintf(stderr, ptr);


	free(ptr);
}

void
handle_lmpl_cmd_error(int rc, char *cmd, char *lmpl, char *tid, char *msg)
{

	char msg_str[1024];

	if (rc == LMPL_UNACCEPTABLE)
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7030_MSG, cmd, lmpl, "unacceptable",
		    cmd, lmpl, "unacceptable");
	else if (rc == LMPL_FINAL_ERROR)
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7030_MSG, cmd, lmpl, "final error",
		    cmd, lmpl, "final error");
	else if (rc == LMPL_FINAL_CANCEL)
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7030_MSG, cmd, lmpl, "final cancel",
		    cmd, lmpl, "final cancel");
	else
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7030_MSG, cmd, lmpl, "invalid final",
		    cmd, lmpl, "invalid final");

	mms_trace(MMS_ERR, "handle_lmpl_cmd_error: %s", msg_str);

	(void) snprintf(msg, RMBUFSIZE, LM_ERR_FINAL,
	    tid, mms_sym_code_to_str(MMS_INTERNAL),
	    mms_sym_code_to_str(MMS_LM_E_SUBCMDFAILED), msg_str);
}

void
lm_connect_failure(mms_t *conn)
{

	char ebuf[MMS_EBUF_LEN];

	mms_get_error_string(&conn->mms_err, ebuf, MMS_EBUF_LEN);
	switch (conn->mms_err.mms_id) {
		case MMS_ERR_SERVICE_NOT_FOUND:
			lm_serr(MMS_CRIT, "connect_failure: mm is not "
			    "running, - %s", ebuf);
			break;
		default:
			lm_serr(MMS_CRIT, "connect_failure: mm connect "
			    "failure, - %s", ebuf);
			break;
		}
}

/*
 * lm_send_cancel
 *
 * Parameters:
 *	taskid	The task id of the LMPL command to be cancelled.
 *
 * This function is used by the LM to be able to cancel a LMPL command
 * that it has sent to MM but the timeout for how long to wait for
 * a response has expired.
 *
 * Currently, when lm_gen_lmpl_cmd() sends a LMPL command as part of
 * processing a LMPM command, the routine processing the LMPM command
 * can specifiy a timeout for how long it will wait for a response to
 * the LMPL command. If the timeout is hit, the LM will then send a
 * cancel command for the LMPL command. This is done by adding an
 * internal cancel command to the work queue, which will cause this
 * routine to be invoked by the lm_cmd_handler().
 *
 * Note: No commands currently send a LMPL command with a timeout, thus
 * nothing within LM currently will generate the lm_send_cancel.
 *
 * Return Values:
 *    None	Since the command just adds an internal cancel command
 *		to the LM's work queue, no response is required. If
 *		lm_queue_add() fails, it will cause LM to eventually
 *		exit.
 */
void
lm_send_cancel(int taskid)
{
	char		input[1024];
	char		*tid;

	mms_par_node_t	*cmd;
	mms_list_t		err_list;

	mms_trace(MMS_DEVP, "Entering lm_send_cancel for LMPL cmd taskid - %d",
	    taskid);

	(void) sprintf(input, LM_SEND_CANCEL, taskid);

	if (mms_lmpm_parse(&cmd, &err_list, input)) {
		mms_trace(MMS_ERR, "lmpm parser failure, unable to send cancel "
		    "of LMPL command with task id of %d", taskid);
		mms_pe_destroy(&err_list);
		return;
	}
	mms_pe_destroy(&err_list);

		/* No real LMPM command, just a place holder */
	tid = NULL;

	if (lm_queue_add(&lm_cmdq, (void *)cmd, &tid, LM_C_INTERNAL) != 0) {
		mms_trace(MMS_CRIT, "lm_send_cancel: adding internal cancel "
		    "command to work queue failed");
		return;
	}
}
