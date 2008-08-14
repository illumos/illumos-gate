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


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include "mms_list.h"
#include "mms_parser.h"
#include "mms_network.h"
#include <mms_sym.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include "mms_sock.h"


#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>



#define	MMS_OK 0
#define	MMS_ERROR -1
#define	MMS_WELCOME 6
#define	MMS_UNWELCOME 7

static	char	*_SrcFile = __FILE__;

/*
 *
 * mms_intrp()
 *
 * Parameters:
 *	rsp		The response to the welcome command (XML format) that
 *			was sent from the MM to the client.
 *	err_code	The error code if MMS_ERROR was returned.
 *
 * Globals:
 *	None
 *
 * This function will determine the type of response that was received in
 * response to the client's "hello" command.
 *
 * Return Values:
 *	MMS_WELCOME	If the response was a welcome
 *	MMS_UNWELCOME	If the response was a unwelcome
 *	MMS_ERROR	If an error was encountered while processing response
 *			or if the respone was a error response.
 *
 */

int
mms_intrp(char *rsp, char **pass, char **cert, char **auth, int *err_code)
{
	mms_par_node_t	*cmd;
	mms_par_node_t	*node;
	mms_par_node_t	*clause;
	mms_par_node_t	*value;
	mms_par_node_t	*index;
	mms_list_t		err_list;
	mms_par_err_t 	*err;
	int		ret_val;

	*pass = NULL;
	*cert = NULL;
	*auth = NULL;

	if (mms_mmp_parse(&cmd, &err_list, rsp)) {
		mms_list_foreach(&err_list, err) {
			mms_trace(MMS_ERR,
			    "mms_mmconnect mms_mmp_parse, line %d, "
			    "col %d, near token \"%s\", err code %d, %s\n",
			    err->pe_line,
			    err->pe_col,
			    err->pe_token,
			    err->pe_code,
			    err->pe_msg);
		}
		mms_pe_destroy(&err_list);
		mms_pn_destroy(cmd);
		*err_code = MMS_E_SYNTAX_ERR;
		return (MMS_ERROR);
	}

	mms_pe_destroy(&err_list);

	if (mms_pn_lookup(cmd, "welcome", MMS_PN_CMD, 0) != NULL) {
		if (clause = mms_pn_lookup_arg(cmd, "password",
		    MMS_PN_CLAUSE, NULL)) {
			if (value = mms_pn_lookup_arg(clause, NULL,
			    MMS_PN_STRING, NULL)) {
				*pass = strdup(value->pn_string);
			}
		}
		if (clause = mms_pn_lookup_arg(cmd, "certificate",
		    MMS_PN_CLAUSE, NULL)) {
			index = NULL;
			if (value = mms_pn_lookup_arg(clause, NULL,
			    MMS_PN_STRING, &index)) {
				*cert = strdup(value->pn_string);
			}

			if (value = mms_pn_lookup_arg(clause, NULL,
			    MMS_PN_STRING, &index)) {
				*auth = strdup(value->pn_string);
			}
		}
		ret_val = MMS_WELCOME;
	} else if (mms_pn_lookup(cmd, "unwelcome", MMS_PN_CMD, 0) != NULL) {
		ret_val = MMS_UNWELCOME;
		if ((node = mms_pn_lookup(cmd, NULL, MMS_PN_STRING, 0))
		    == NULL) {
			*err_code = MMS_E_INVALID_RESPONSE;
		} else {
			*err_code = mms_sym_str_to_code(mms_pn_token(node));
		}
	} else {
		*err_code = MMS_E_INVALID_RESPONSE;
		ret_val = MMS_ERROR;
	}

	mms_pn_destroy(cmd);
	return (ret_val);
}

#define	MMS_HELLO_CMD_STRING "hello client [\"%s\"] instance [\"%s\"] \
language [%s] version [\"%s\"] password [\"%s\"]; "
#define	MMS_HELLO_CMD_TAG_STRING "hello client [\"%s\"] instance [\"%s\"] \
language [%s] version [\"%s\"] password [\"%s\"] tag [\"%s\"]; "
#define	MMS_HELLO_CMD_CERT_STRING "hello client [\"%s\"] instance [\"%s\"] \
language [%s] version [\"%s\"] certificate [\"\n%s\n\" \"%s\"]; "
#define	MMS_HELLO_CMD_CERT_TAG_STRING "hello client [\"%s\"] instance [\"%s\"] \
language [%s] version [\"%s\"] certificate [\"\n%s\n\" \"%s\"] tag [\"%s\"]; "

/*
 *
 * mms_mmconnect()
 *
 * Parameters:
 *	net		Structure containing network information for
 *			connecting to the MM. This structure contains all
 *			necessary information needed to compose a "hello"
 *			command from a client module to the MM.
 *	conn		Structure which will contain the socket connection
 *			information.
 *	err_code	error code if MMS_ERROR is returned.
 *			error code is either MMS error code.
 *	tag		Tag to be used for the connection.
 *
 * Globals:
 *	None.
 *
 * This is a general purpose routine that can be used by a client that
 * need to connect to MM. All client specific information is contained in
 * the mms_network_cfg structure. This routine generates a "hello" command and
 * send it to the MM. It waits for a response from the MM and determines
 * if a welcome or unwelcome response was sent by MM.
 *
 * Return Values:
 *	fd		If a welcome response was received from MM, then
 *			this routine returns the file descriptor that the
 *			client will use to communicate with MM.
 *	MMS_ERROR		If an error occurred while processing or if an
 *			unwelcome response was receieved from MM.
 *
 */

int
mms_mmconnect(mms_network_cfg_t *net,
    void *ssl_data,
    mms_t *conn,
    int *err_code,
    char *tag)
{
	int	n;
	int	len;
	char	ebuf[MMS_EBUF_LEN];
	char	cmd_str[4096];
	char	*rsp = NULL;
	char	*cert = NULL;
	char	*auth = NULL;
	char	*pass = NULL;
	int	rc;


	*err_code = 0;

	/*
	 * Connect to media manager, if ssl data is not null
	 * then establish a SSLv3 connection.
	 */
	mms_trace(MMS_DEVP, "host %s port %s", net->cli_host, net->cli_port);
	if (mms_connect(net->cli_host, net->cli_port, ssl_data, conn)) {
		mms_get_error_string(&conn->mms_err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "mms_mmconnect: failed to connect to MMS, "
		    "%s\n", ebuf);
		*err_code = MMS_E_CONNECT_ERR;
		return (MMS_ERROR);
	}

	/*
	 * Create hello command.
	 */
#ifdef	MMS_OPENSSL
	if (mms_ssl_has_cert_clause(ssl_data, conn)) {
		/*
		 * Create auth-clause hello command using
		 * its private key for the signature.
		 */
		if (mms_ssl_build_cert_clause(ssl_data, conn,
		    net->cli_pass, &cert, &auth)) {
			mms_trace(MMS_ERR,
			    "mms_mmconnect: hello certificate-clause");
			*err_code = MMS_E_SSL_CERT_CLAUSE;
			return (MMS_ERROR);
		}
		if (tag == NULL) {
			(void) snprintf(cmd_str, sizeof (cmd_str),
			    MMS_HELLO_CMD_CERT_STRING,
			    net->cli_name, net->cli_inst,
			    net->cli_lang, net->cli_vers,
			    cert, auth);
		} else {
			(void) snprintf(cmd_str, sizeof (cmd_str),
			    MMS_HELLO_CMD_CERT_TAG_STRING,
			    net->cli_name, net->cli_inst,
			    net->cli_lang, net->cli_vers,
			    cert, auth, tag);
		}
		free(cert);
		free(auth);
		cert = NULL;
		auth = NULL;
		mms_trace(MMS_DEBUG, cmd_str);

	} else {
#endif	/* MMS_OPENSSL */

		/*
		 * Use password, client does not have
		 * private key for signature.
		 */
		if (tag == NULL) {
			(void) snprintf(cmd_str, sizeof (cmd_str),
			    MMS_HELLO_CMD_STRING,
			    net->cli_name, net->cli_inst,
			    net->cli_lang, net->cli_vers,
			    net->cli_pass);
			mms_trace(MMS_DEBUG, MMS_HELLO_CMD_STRING,
			    net->cli_name, net->cli_inst,
			    net->cli_lang, net->cli_vers,
			    "");
		} else {
			(void) snprintf(cmd_str, sizeof (cmd_str),
			    MMS_HELLO_CMD_TAG_STRING,
			    net->cli_name, net->cli_inst,
			    net->cli_lang, net->cli_vers,
			    net->cli_pass, tag);
			mms_trace(MMS_DEBUG, MMS_HELLO_CMD_TAG_STRING,
			    net->cli_name, net->cli_inst,
			    net->cli_lang, net->cli_vers,
			    "", tag);
		}

#ifdef	MMS_OPENSSL
	}
#endif	/* MMS_OPENSSL */

	len = strlen(cmd_str);
	if ((n = mms_writer(conn, cmd_str)) != len) {
		mms_get_error_string(&conn->mms_err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR,
		    "mms_mmconnect: Failed to write hello cmd, %d, "
		    "%s\n", n, ebuf);
		mms_close(conn);
		*err_code = MMS_E_NET_IO_ERR;
		return (MMS_ERROR);
	}

	rsp = NULL;
	if ((n = mms_reader(conn, &rsp)) <= 0) {
		mms_get_error_string(&conn->mms_err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR,
		    "mms_mmconnect: Failed to read response to hello "
		    "cmd, %d, %s\n", n, ebuf);
		mms_close(conn);
		*err_code = MMS_E_NET_IO_ERR;
		return (MMS_ERROR);
	}

	switch (mms_intrp(rsp, &pass, &cert, &auth, err_code)) {

	case MMS_WELCOME:
		/*
		 * Verifing welcome auth-clause is optional.
		 */
		rc = MMS_OK;
		if (pass != NULL) {

			if (net->mm_pass != NULL) {

				if (strcmp(net->mm_pass, pass) != 0) {

					mms_trace(MMS_ERR,
					    "mms_mmconnect: welcome "
					    "password mismatch");

					*err_code = MMS_E_WELCOME_PASSWORD;
					rc = MMS_ERROR;

				} else {
					mms_trace(MMS_DEVP,
					    "mms_mmconnect: welcome "
					    "password matched");
				}
			}

#ifdef	MMS_OPENSSL
		} else if (cert != NULL && auth != NULL) {

			char *tmp_pass = NULL;

			if (mms_ssl_verify_cert_clause(ssl_data, conn,
			    cert, auth, &tmp_pass)) {

				mms_trace(MMS_ERR,
				    "mms_mmconnect: welcome certificate-clause "
				    "invalid");

				*err_code = MMS_E_SSL_VERIFY;
				rc = MMS_ERROR;

			} else if (net->mm_pass != NULL) {

				if (strcmp(net->mm_pass, tmp_pass) != 0) {

					mms_trace(MMS_ERR,
					    "mms_mmconnect: welcome "
					    "certificate-clause "
					    "password mismatch");

					*err_code = MMS_E_WELCOME_PASSWORD;
					rc = MMS_ERROR;

				} else {
					mms_trace(MMS_DEVP,
					    "mms_mmconnect: welcome "
					    "certificate-clause ok");
				}

				free(tmp_pass);
			}

#endif	/* MMS_OPENSSL */

		} else if (net->mm_pass != NULL) {

			mms_trace(MMS_ERR,
			    "mms_mmconnect: welcome missing auth-clause");

			*err_code = MMS_E_NO_WELCOME_PASSWORD;
			rc = MMS_ERROR;

		}
		free(pass);
		free(cert);
		free(auth);
		if (rc == MMS_OK) {
			free(rsp);
			return (MMS_OK);
		}
		break;
	case MMS_UNWELCOME:
		mms_trace(MMS_NOTICE,
		    "mms_mmconnect: unwelcome resp - %s", rsp);
		break;
	case MMS_ERROR:
		break;
	default:
		break;
	}

	free(rsp);
	mms_close(conn);
	return (MMS_ERROR);
}

/*
 *
 * mms_mmdisconnect()
 *
 * Parameters:
 *	conn		Structure containing network information for
 *			connecting to the MM. This structure contains all
 *			necessary information needed to compose a "goodbye"
 *			command from a client module to the MM.
 *
 * Globals:
 *	None.
 *
 * This is a general purpose routine that can be used by a client that
 * is disconnecting from the MM. This routine generates a "goodbye" command and
 * send it to the MM. It does not wait for a response from the MM.
 *
 * Return Values:
 *	MMS_OK		If the goodbye command was sent successfully.
 *	MMS_ERROR		If an error occurred while processing
 *
 */

int
mms_mmdisconnect(mms_t *conn)
{

	int n;
	int len;
	char ebuf[MMS_EBUF_LEN];
	char cmd_str[1024];

	(void) snprintf(cmd_str, sizeof (cmd_str),
	    "goodbye task[\"goodbye%d\"];", conn->mms_fd);

	len = strlen(cmd_str);
	if ((n = mms_writer(conn, cmd_str)) != len) {
		mms_get_error_string(&conn->mms_err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "Failed to write goodbye cmd - %d, %s \n",
		    n, ebuf);
		mms_close(conn);
		return (MMS_ERROR);
	}

	mms_close(conn);
	return (MMS_OK);
}
