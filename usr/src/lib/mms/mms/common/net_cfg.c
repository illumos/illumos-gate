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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include "mms_list.h"
#include "mms_parser.h"
#include "mms_network.h"
#include "mms_cfg.h"
#include <mms_trace.h>

#define	MMS_OK	0
#define	MMS_ERROR	-1

static	char	*_SrcFile = __FILE__;

/*
 * mms_build_net_cfg()
 *
 * Parameters:
 *	net	Ptr to mms_network_cfg structure that is to be populated from
 *		the network configuration file
 *	cfg	Ptr to arse tree of network configuration file
 *
 * Globals:
 *	None
 *
 * Obtain a module's network configuration information from the parse tree.
 * The information is then stored in the mms_network_cfg structure to be used
 * to connect to MM
 *
 * Return Values:
 *	MMS_OK:	Able to obtain all network information correctly.
 *	MMS_ERROR:	Unable to obtain all network information.
 *
 */
static int
mms_build_net_cfg(mms_network_cfg_t *net, mms_par_node_t *cfg)
{
	mms_par_node_t	*root;
	mms_par_node_t	*elem;
	mms_par_node_t	*attr;
	mms_par_node_t	*value;
	char		*kw;

	/* configuration */
	MMS_PN_LOOKUP(root, cfg, kw = "mms_cfg", MMS_PN_CONFIG, NULL);

	/* network configuration */
	MMS_PN_LOOKUP(elem, root, kw = "mms_network_cfg", MMS_PN_OPTION, NULL);

	MMS_PN_LOOKUP(attr, elem, kw = "host", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
	net->cli_host = strdup(mms_pn_token(value));

	MMS_PN_LOOKUP(attr, elem, kw = "port", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
	net->cli_port = strdup(mms_pn_token(value));

	MMS_PN_LOOKUP(attr, elem, kw = "name", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
	net->cli_name = strdup(mms_pn_token(value));

	MMS_PN_LOOKUP(attr, elem, kw = "language", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
	net->cli_lang = strdup(mms_pn_token(value));

	if (attr = mms_pn_lookup(elem, kw = "version",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->cli_vers = strdup(mms_pn_token(value));
	}

	MMS_PN_LOOKUP(attr, elem, kw = "instance", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
	net->cli_inst = strdup(mms_pn_token(value));

	MMS_PN_LOOKUP(attr, elem, kw = "password", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
	net->cli_pass = strdup(mms_pn_token(value));

	if (attr = mms_pn_lookup(elem, kw = "mm_password",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->mm_pass = strdup(mms_pn_token(value));
	}

	if (attr = mms_pn_lookup(elem, kw = "ssl_enabled",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		if (strcasecmp(mms_pn_token(value), "true") == 0) {
			net->ssl_enabled = 1;
		}
	}

	if (attr = mms_pn_lookup(elem, kw = "ssl_cert_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->ssl_cert_file = strdup(mms_pn_token(value));
	}

	if (attr = mms_pn_lookup(elem, kw = "ssl_pass",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->ssl_pass = strdup(mms_pn_token(value));
	}

	if (attr = mms_pn_lookup(elem, kw = "ssl_pass_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->ssl_pass_file = strdup(mms_pn_token(value));
	}

	if (attr = mms_pn_lookup(elem, kw = "ssl_crl_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->ssl_crl_file = strdup(mms_pn_token(value));
	}

	if (attr = mms_pn_lookup(elem, kw = "ssl_peer_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->ssl_peer_file = strdup(mms_pn_token(value));
	}

	if (attr = mms_pn_lookup(elem, kw = "ssl_cipher",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(value, attr, NULL, MMS_PN_STRING, NULL);
		net->ssl_cipher = strdup(mms_pn_token(value));
	}

	return (MMS_OK);

not_found:
	mms_net_cfg_free(net);
	syslog(LOG_ERR, "%s:%d mms_build_net_cfg: "
	    "Missing keyword - %s in config "
	    "file\n", MMS_HERE, kw);
	return (MMS_ERROR);
}

/*
 * mms_net_cfg_read()
 *
 * Parameters:
 *	net	Ptr to module's mms_network_cfg, which is a generic strcture
 *		used by mms_mmconnect to connect to the MM. This routine
 *		passes this to mms_build_net_cfg() to actually populate the
 *		structure
 *	cfgfn	Path and name of the network configuration file that is to
 *		be parsed
 *
 * Globals:
 *	None
 *
 * Read network configuration for a module and then parses the contents of
 * the file and then populates the mms_network_cfg structure. This structure
 * is then passed to mms_mmconnect() to do the actual connect to MM on behalf
 * of the module.
 *
 * Return Values:
 *	MMS_OK:		If the configuration file parses cleanly.
 *	MMS_ERROR:		If the configuration file contained errors.
 *
 */
int
mms_net_cfg_read(mms_network_cfg_t *net, char *cfgfn)
{
	mms_par_node_t	*cfg;
	char		*buf;
	mms_list_t		err_list;
	mms_par_err_t	*err;
	int		rc;
	int		fd;
	struct stat	statbuf;


	(void) memset(net, 0, sizeof (mms_network_cfg_t));
	if ((fd = open(cfgfn, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "%s:%d mms_net_cfg_read: "
		    "Unable to open config file %s\n",
		    MMS_HERE, cfgfn);
		return (MMS_ERROR);
	}

		/* Allocate a buffer to read in the entire config file */
	if (fstat(fd, &statbuf)) {
		syslog(LOG_ERR, "%s:%d mms_net_cfg_read: "
		    "Unable to stat config file %s\n",
		    MMS_HERE, cfgfn);
		return (MMS_ERROR);
	}
	if ((buf = (char *)malloc(statbuf.st_size + 1)) == NULL) {
		syslog(LOG_ERR, "%s:%d mms_net_cfg_read: "
		    "Unable to alloc buf for config file %s\n",
		    MMS_HERE, cfgfn);
		return (MMS_ERROR);
	}

		/* Read in config file */
	if ((rc = read(fd, buf, statbuf.st_size)) < 0) {
		syslog(LOG_ERR, "%s:%d mms_net_cfg_read: "
		    "Unable to read config file %s\n",
		    MMS_HERE, cfgfn);
		return (MMS_ERROR);
	}
	buf[rc] = '\0';

		/* Parse the config file */
	if (rc = mms_config_parse(&cfg, &err_list, buf)) {
		mms_list_foreach(&err_list, err) {
			syslog(LOG_ERR, "mms_net_cfg_read: Parse error "
			    "line %d, col %d, near token \"%s\", "
			    "err code %d, %s",
			    err->pe_line,
			    err->pe_col,
			    err->pe_token,
			    err->pe_code,
			    err->pe_msg);
		}

		(void) close(fd);
		free(buf);
		mms_pe_destroy(&err_list);
		mms_pn_destroy(cfg);
		return (MMS_ERROR);
	}
	free(buf);
	mms_pe_destroy(&err_list);
	(void) close(fd);

	if ((rc = mms_build_net_cfg(net, cfg)) == MMS_ERROR) {
		syslog(LOG_ERR, "%s:%d mms_net_cfg_read: Error while building "
		    "network config structure from config file %s\n",
		    MMS_HERE, cfgfn);
	}

	mms_pn_destroy(cfg);
	return (rc);
}

void
mms_net_cfg_free(mms_network_cfg_t *net)
{
	if (net != NULL) {
		free(net->cli_host);
		free(net->cli_port);
		free(net->cli_name);
		free(net->cli_inst);
		free(net->cli_pass);
		free(net->cli_lang);
		free(net->cli_vers);
		free(net->mm_pass);
		free(net->ssl_cert_file);
		free(net->ssl_pass);
		free(net->ssl_pass_file);
		free(net->ssl_crl_file);
		free(net->ssl_peer_file);
		free(net->ssl_cipher);
		(void) memset(net, 0, sizeof (mms_network_cfg_t));
	}
}
