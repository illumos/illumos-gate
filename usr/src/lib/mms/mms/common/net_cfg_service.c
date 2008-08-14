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
#include "net_cfg_service.h"

static	char	*_SrcFile = __FILE__;

int
mms_net_cfg_service(mms_network_cfg_t *net, char *inst, char *lang, char *ver)
{
	char	*value;

	/* read common service config */

	(void) memset(net, 0, sizeof (mms_network_cfg_t));

	if (inst == NULL || lang == NULL || ver == NULL) {
		mms_trace(MMS_ERR, "net cfg service args invalid");
		return (1);
	}

	net->cli_host = mms_cfg_alloc_getvar(MMS_CFG_MGR_HOST, NULL);
	net->cli_port = mms_cfg_alloc_getvar(MMS_CFG_MGR_PORT, NULL);
	net->cli_name = strdup("MMS");
	net->cli_inst = strdup(inst);
	net->cli_lang = strdup(lang);
	net->cli_vers = strdup(ver);
	net->cli_pass = mms_net_cfg_read_pass_file(MMS_NET_CFG_HELLO_FILE);
	net->mm_pass = mms_net_cfg_read_pass_file(MMS_NET_CFG_WELCOME_FILE);
	if (value = mms_cfg_alloc_getvar(MMS_CFG_SSL_ENABLED, NULL)) {
		if (strcasecmp(value, "true") == 0) {
			net->ssl_enabled = 1;
		}
		free(value);
	}
	net->ssl_cert_file = mms_cfg_alloc_getvar(MMS_CFG_SSL_CERT_FILE, NULL);
	net->ssl_pass_file = mms_cfg_alloc_getvar(MMS_CFG_SSL_PASS_FILE, NULL);
	net->ssl_crl_file = mms_cfg_alloc_getvar(MMS_CFG_SSL_CRL_FILE, NULL);
	net->ssl_peer_file = mms_cfg_alloc_getvar(MMS_CFG_SSL_PEER_FILE, NULL);
	net->ssl_cipher = mms_cfg_alloc_getvar(MMS_CFG_SSL_CIPHER, NULL);

	if (net->cli_host == NULL ||
	    net->cli_port == NULL ||
	    net->cli_name == NULL ||
	    net->cli_inst == NULL ||
	    net->cli_lang == NULL ||
	    net->cli_vers == NULL) {
		mms_trace(MMS_ERR, "net cfg service incomplete");
		mms_net_cfg_free(net);
		return (1);
	}

	if (net->cli_pass == NULL) {
		mms_trace(MMS_WARN, "net cfg service hello password");
		return (2);
	}

	return (0);
}

/* ARGSUSED1 */
char *
mms_obfpassword(char *password, int ed)
{
	char	*buf = NULL;

	if (password) {
		buf = strdup(password);
		/*
		 * Put obfuscation algorithm here.
		 *
		 * If ed is zero then encrypt else decrypt.
		 */
	}
	return (buf);
}

int
mms_net_cfg_write_pass_file(char *file, char *password)
{
	struct stat	sbuf;
	int		fd = -1;
	int		n;
	int		rc = 1;
	char		*obfpass = NULL;
	const char	*newline = "\n";
	char		*p;
	struct iovec	iov[2];
	char		*tmpass = NULL;
	int		len;

	if (file == NULL) {
		mms_trace(MMS_ERR, "net cfg write null file");
		return (1);
	}
	if (password == NULL) {
		mms_trace(MMS_ERR,
		    "net cfg write file %s null password", file);
		return (1);
	}
	if (stat(file, &sbuf) == 0) {
		if ((sbuf.st_mode & ~(S_IFREG|S_IRUSR|S_IWUSR)) != 0) {
			mms_trace(MMS_DEVP, "net cfg write file %s mode %x",
			    file, sbuf.st_mode);
			return (1);
		}
	}

	if ((tmpass = strdup(password)) == NULL) {
		mms_trace(MMS_ERR,
		    "net cfg write file %s alloc %s",
		    file,
		    strerror(errno));
		return (1);
	}
	if (p = strchr(tmpass, '\n')) {
		*p = 0;
	}
	if ((fd = open(file, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR)) < 0) {
		mms_trace(MMS_DEVP, "net cfg write file %s open %s",
		    file, strerror(errno));
		free(tmpass);
		return (1);
	}

	if ((obfpass = mms_obfpassword(tmpass, 0)) == NULL) {
		mms_trace(MMS_DEVP,
		    "net cfg write file %s password obfuscation",
		    file);
	} else {
		iov[0].iov_base = obfpass;
		iov[0].iov_len = strlen(obfpass);
		iov[1].iov_base = (char *)newline;
		iov[1].iov_len = strlen(newline);
		len = strlen(obfpass) + strlen(newline);
		if ((n = writev(fd, iov, 2)) == len) {
			rc = 0;
		} else {
			mms_trace(MMS_DEVP,
			    "net cfg write file %s write %s n %d len %d",
			    file, strerror(errno), n, len);
		}
		free(obfpass);
	}
	free(tmpass);
	if (fd >= 0)
		(void) close(fd);
	return (rc);
}

char *
mms_net_cfg_read_pass_file(char *file)
{
	struct stat	sbuf;
	int		fd = -1;
	char		*password = NULL;
	char		*obfpass = NULL;
	char		*p;
	int		n;
	int		len;

	if (file == NULL) {
		mms_trace(MMS_ERR, "net cfg read null file");
		goto out;
	}
	if (stat(file, &sbuf) != 0) {
		mms_trace(MMS_DEVP, "net cfg read file %s stat %s",
		    file, strerror(errno));
		goto out;
	}
	len = sbuf.st_size;

	if ((sbuf.st_mode & ~(S_IFREG|S_IRUSR|S_IWUSR)) != 0) {
		mms_trace(MMS_DEVP,
		    "net cfg read file %s mode %x",
		    file,
		    sbuf.st_mode);
		goto out;
	}

	if ((fd = open(file, O_RDONLY)) < 0) {
		mms_trace(MMS_DEVP,
		    "net cfg read file %s open %s",
		    file,
		    strerror(errno));
		goto out;
	}

	if ((obfpass = (char *)malloc(len + 1)) == NULL) {
		mms_trace(MMS_DEVP,
		    "net cfg read file %s alloc %s",
		    file,
		    strerror(errno));
		goto out;
	}

	if ((n = read(fd, obfpass, len)) != len) {
		mms_trace(MMS_DEVP,
		    "net cfg read file %s read %s n %d len %d",
		    file,
		    strerror(errno),
		    n,
		    len);
		goto out;
	}
	obfpass[len] = (char)0;

	if (p = strchr(obfpass, '\n')) {
		*p = (char)0;
	}
	if ((password = mms_obfpassword(obfpass, 1)) == NULL) {
		mms_trace(MMS_DEVP,
		    "net cfg read file %s password un-obfuscate",
		    file);
	}

out:
	if (obfpass)
		free(obfpass);
	if (fd >= 0)
		(void) close(fd);
	return (password);
}
