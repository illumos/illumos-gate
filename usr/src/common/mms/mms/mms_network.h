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


#ifndef	__MMS_NETWORK_H__
#define	__MMS_NETWORK_H__

#include <limits.h>
#include <netdb.h>
#include <mms_err.h>

#define	MMS_MMP_VERSION	"1.0"
#define	MMS_LMP_VERSION	"1.0"
#define	MMS_DMP_VERSION	"1.0"
#define	MMS_MMP_LANG		"MMP";
#define	MMS_LMP_LANG		"LMP";
#define	MMS_DMP_LANG		"DMP";

typedef	char mms_cli_host_t[MAXHOSTNAMELEN];

typedef struct mms_network_cfg mms_network_cfg_t;
struct mms_network_cfg {
	char *cli_host;
	char *cli_port;
	char *cli_name;
	char *cli_inst;
	char *cli_lang;
	char *cli_vers;
	char *cli_pass;			/* client hello command password */
	char *mm_pass;			/* mm welcome response password */
	int  ssl_enabled;		/* ssl enabled */
	char *ssl_cert_file;		/* cert, private key, cert chain */
	char *ssl_pass;			/* private key password */
	char *ssl_pass_file;		/* private key password file */
	char *ssl_crl_file;		/* CRL file */
	char *ssl_cipher;		/* SSL context cipher change */
	char *ssl_peer_file;		/* client mm cert file */
};

#define	MMS_SERVICE		"7151"	/* default mms service port */
#define	MMS_BACKLOG		1024	/* socket listen backlog */
#define	MMS_EBUF_LEN		300	/* mms socket error string length, */
					/* must be 120 bytes min for ssl */
#define	MMS_SOCK_HDR_SIZE	16	/* socket message header size */
#define	MMS_MSG_MAGIC		"SUNW-MMS"
#define	MMS_MSG_MAGIC_LEN	8

typedef struct mms mms_t;
struct mms {	/* socket connection */
	int		mms_fd;		/* socket file descriptor */
	mms_err_t	mms_err;		/* error information */
	void		*mms_ssl;		/* secure socket layer */
};

#ifdef	MMS_OPENSSL
int mms_ssl_client(mms_network_cfg_t *net, void **ssl_data, mms_err_t *err);
void mms_ssl_finish(void *ssl_data);
#define	MMS_SSL
#else
#undef	MMS_SSL
#endif	/* MMS_OPENSSL */

int mms_connect(char *host, char *service, void *ssl_data, mms_t *cli_conn);
int mms_reader(mms_t *conn, char **buf);
int mms_writer(mms_t *conn, char *buf);
void mms_close(mms_t *conn);
int mms_net_cfg_read(mms_network_cfg_t *net, char *cfgfn);
void mms_net_cfg_free(mms_network_cfg_t *net);
int mms_mmconnect(mms_network_cfg_t *net,
	void *ssl_data,
	mms_t *conn,
	int *err_code,
	char *tag);
int mms_mmdisconnect(mms_t *conn);

#endif	/* __MMS_NETWORK_H__ */
