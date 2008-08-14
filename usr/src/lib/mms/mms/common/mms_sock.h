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

#ifndef	_MMS_SOCK_H
#define	_MMS_SOCK_H


#ifdef	__cplusplus
extern "C" {
#endif

int mms_listen(char *host, char *service, int *serv_fd, mms_err_t *err);
int mms_accept(int serv_fd, void *ssl_data, mms_t *cli_conn);
int mms_read(mms_t *conn, char *buf, int len);
int mms_write(mms_t *conn, struct iovec *iov, int num);
void mms_error(mms_err_t *err, int id);
int mms_read_has_error(mms_t *conn);
int mms_write_has_error(mms_t *conn);
void mms_error(mms_err_t *err, int id);
void mms_sys_error(mms_err_t *err, int id);

#ifdef	MMS_OPENSSL
int mms_ssl_server(mms_network_cfg_t *net, char *dh_file,
	int verify_peer, void **ssl_data, mms_err_t *err);
char *mms_ssl_get_cipher(void *ssl_data, mms_err_t *err);
int mms_ssl_has_cert_clause(void *ssl_data, mms_t *conn);
int mms_ssl_build_cert_clause(void *ssl_data, mms_t *conn,
	char *password, char **cert, char **auth);
int mms_ssl_verify_cert_clause(void *ssl_data, mms_t *conn,
	char *cert, char *auth, char **password);
void mms_ssl_server_set_verify_peer(void *ssl_data, int verify_peer);
int mms_ssl_reload_crl_file(void *ssl_data, char *crl_file,
	mms_err_t *err);
int mms_ssl_has_crl(void *ssl_data);
int mms_ssl_check_conn_cert(void *ssl_data, mms_t *conn);
int mms_ssl_connect(void *ssl_data, mms_t *conn);
int mms_ssl_accept(void *ssl_data, mms_t *conn);
int mms_ssl_read(mms_t *conn, char *buf, int len);
int mms_ssl_read_has_error(mms_t *conn);
int mms_ssl_write(mms_t *conn, struct iovec *iov, int iovcnt);
int mms_ssl_write_has_error(mms_t *conn);
void mms_ssl_close(mms_t *conn);
void mms_ssl_get_error_string(mms_err_t *err, char *ebuf, int ebuflen);
#endif	/* MMS_OPENSSL */

#ifdef	__cplusplus
}
#endif

#endif	/* _MMS_SOCK_H */
