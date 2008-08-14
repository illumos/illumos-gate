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


#ifdef  MMS_OPENSSL
#define	MMS_OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <pthread.h>
#include "mms_network.h"
#include "mms_sym.h"
#include "mms_sock.h"
#include <mms_trace.h>

static char *_SrcFile = __FILE__;

#define	UNWELCOME_SSL		"unwelcome \"SSAI_E_SSL\";"
#define	UNWELCOME_ACCESS_SSL	"unwelcome \"SSAI_E_ACCESS_DENIED\" " \
					"\"SSAI_E_SSL\";"
#define	MMS_SSL_CIPHER		"EDH-RSA-DES-CBC3-SHA"

typedef struct mms_ssl_data mms_ssl_t;
struct mms_ssl_data {
	char		*mms_cipher;
	int		mms_verify;
	X509		**mms_chain;
	int		mms_nchain;
	X509		*mms_peer;
	RSA		*mms_key;
	SSL_CTX		*mms_ctx;
	DH		*mms_dh;
	X509_CRL	*mms_crl;
	X509_STORE	*mms_store;
};

typedef struct mms_ssl_conn mms_sc_t;
struct mms_ssl_conn {
	SSL		*mms_sc_ssl;
	X509		*mms_sc_cert;
};

static pthread_mutex_t *mms_ssl_mutex = NULL;

static int mms_ssl_init(mms_err_t *err);
static int mms_ssl_client_ctx(void *ssl_data, mms_err_t *err);
static int mms_ssl_server_ctx(void *ssl_data, int verify_peer, mms_err_t *err);
static int mms_ssl_set_cipher(void *ssl_data, char *cipher, mms_err_t *err);
static int mms_ssl_set_peer_file(void *ssl_data, char *peer_cert_file,
    mms_err_t *err);
static int mms_ssl_data_use_files(void **ssl_data, char *cert_file, char *pass,
    char *pass_file, char *dh_file, char *crl_file, mms_err_t *err);
static void mms_ssl_data_free(void *ssl_data);
static void mms_ssl_error(mms_err_t *err, int id);
static void mms_ssl_set_error(mms_err_t *err, int id, ulong_t num);
static int mms_ssl_check_cert(mms_ssl_t *data, X509 *x509_cert,
    mms_err_t *err);
static int mms_ssl_use_crl_file(mms_ssl_t *data, char *crl_file,
    mms_err_t *err);
static int mms_ssl_compare_cert(X509 *acert, X509 *bcert);

int
mms_ssl_client(mms_network_cfg_t *net, void **ssl_data, mms_err_t *err)
{
	if (net->ssl_enabled) {
		if (mms_ssl_init(err)) {
			return (1);
		}
		if (mms_ssl_data_use_files(ssl_data,
		    net->ssl_cert_file,
		    net->ssl_pass,
		    net->ssl_pass_file,
		    NULL,
		    net->ssl_crl_file,
		    err)) {
			mms_ssl_finish(NULL);
			return (1);
		}
		if (mms_ssl_set_peer_file(*ssl_data, net->ssl_peer_file, err) ||
		    mms_ssl_set_cipher(*ssl_data, net->ssl_cipher, err) ||
		    mms_ssl_client_ctx(*ssl_data, err)) {
			mms_ssl_finish(*ssl_data);
			return (1);
		}
	}
	return (0);
}

int
mms_ssl_server(mms_network_cfg_t *net, char *dh_file, int verify_peer,
    void **ssl_data, mms_err_t *err)
{
	if (net->ssl_enabled) {
		if (mms_ssl_init(err)) {
			return (1);
		}
		if (mms_ssl_data_use_files(ssl_data,
		    net->ssl_cert_file,
		    net->ssl_pass,
		    net->ssl_pass_file,
		    dh_file,
		    net->ssl_crl_file,
		    err)) {
			mms_ssl_finish(NULL);
			return (1);
		}
		if (mms_ssl_set_cipher(*ssl_data, net->ssl_cipher, err) ||
		    mms_ssl_server_ctx(*ssl_data, verify_peer, err)) {
			mms_ssl_finish(*ssl_data);
			return (1);
		}
	}
	return (0);
}

static int
mms_ssl_set_cipher(void *ssl_data, char *cipher, mms_err_t *err)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;

	if (data == NULL) {
		mms_trace(MMS_ERR, "no ssl");
		mms_error(err, MMS_ERR_NO_SSL);
		return (1);
	}
	if (data->mms_cipher) {
		free(data->mms_cipher);
		data->mms_cipher = NULL;
	}
	if (cipher == NULL) {
		return (0);
	}
	if ((data->mms_cipher = strdup(cipher)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "cipher dup");
		return (1);
	}
	return (0);
}

char *
mms_ssl_get_cipher(void *ssl_data, mms_err_t *err)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	char		*cipher = NULL;

	if (data == NULL) {
		mms_trace(MMS_ERR, "no ssl");
		mms_error(err, MMS_ERR_NO_SSL);
	} else {
		if (data->mms_cipher) {
			cipher = strdup(data->mms_cipher);
		} else {
			cipher = strdup(MMS_SSL_CIPHER);
		}
		if (cipher == NULL) {
			mms_sys_error(err, MMS_ERR_NOMEM);
		}
	}
	return (cipher);
}

static void
mms_ssl_lock(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		if (pthread_mutex_lock(&mms_ssl_mutex[n]) != 0) {
			mms_trace(MMS_ERR, "openssl lock %s:%d",
			    file, line);
		}
	} else {
		if (pthread_mutex_unlock(&mms_ssl_mutex[n]) != 0) {
			mms_trace(MMS_ERR, "openssl unlock %s:%d",
			    file, line);
		}
	}
}

static ulong_t
mms_ssl_id(void)
{
	return ((ulong_t)pthread_self());
}

static int
mms_ssl_lock_setup(mms_err_t *err)
{
	int	i;

#if defined(OPENSSL_THREADS)
	mms_trace(MMS_DEVP, "openssl lock setup - %d",
	    CRYPTO_num_locks());
	if ((mms_ssl_mutex = (pthread_mutex_t *)calloc(CRYPTO_num_locks(),
	    sizeof (pthread_mutex_t))) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "openssl lock setup %s",
		    strerror(errno));
		return (1);
	}
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		if (pthread_mutex_init(&mms_ssl_mutex[i], NULL)) {
			mms_sys_error(err, MMS_ERR_NOMEM);
			mms_trace(MMS_ERR, "openssl lock setup mutex init");
			for (i -= 1; i >= 0; i--) {
				(void) pthread_mutex_destroy(&mms_ssl_mutex[i]);
			}
			free(mms_ssl_mutex);
			mms_ssl_mutex = NULL;
			return (1);
		}
	}
	CRYPTO_set_id_callback(mms_ssl_id);
	CRYPTO_set_locking_callback(mms_ssl_lock);
#endif
	return (0);
}

static void
mms_ssl_lock_cleanup(void)
{
	int	i;

#if defined(OPENSSL_THREADS)
	if (mms_ssl_mutex) {
		mms_trace(MMS_DEVP, "openssl lock cleanup - %d",
		    CRYPTO_num_locks());
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		for (i = 0; i < CRYPTO_num_locks(); i++) {
			(void) pthread_mutex_destroy(&mms_ssl_mutex[i]);
		}
		free(mms_ssl_mutex);
		mms_ssl_mutex = NULL;
	}
#endif
}

int
mms_ssl_init(mms_err_t *err)
{
	/* openssl needs locks for multithreaded applications */
	if (mms_ssl_lock_setup(err)) {
		return (1);
	}
	(void) SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	(void) RAND_load_file("/dev/random", 1024);
	return (0);
}

void
mms_ssl_finish(void *ssl_data)
{
	if (ssl_data) {
		mms_ssl_data_free(ssl_data);
	}
	mms_ssl_lock_cleanup();
}

int
mms_ssl_connect(void *ssl_data, mms_t *conn)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	mms_sc_t	*sc;
	int		rc;

	/*
	 * Client connects to SSL server.
	 */
	conn->mms_ssl = (void *)calloc(1, sizeof (mms_sc_t));
	if (conn->mms_ssl == NULL) {
		mms_sys_error(&conn->mms_err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "connect ssl alloc");
		goto error;
	}
	sc = (mms_sc_t *)conn->mms_ssl;
	if (data->mms_ctx == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_CTX);
		mms_trace(MMS_ERR, "no ssl context");
		goto error;
	}
	if ((sc->mms_sc_ssl = SSL_new(data->mms_ctx)) == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "ssl new");
		goto error;
	}
	if (SSL_set_fd(sc->mms_sc_ssl, conn->mms_fd) != 1) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "ssl set fd");
		goto error;
	}
	if ((rc = SSL_connect(sc->mms_sc_ssl)) != 1) {
		mms_ssl_set_error(&conn->mms_err,
		    MMS_ERR_SSL_CONNECT,
		    SSL_get_error(sc->mms_sc_ssl, rc));
		mms_trace(MMS_ERR, "ssl connect");
		goto error;
	}
	sc->mms_sc_cert = SSL_get_peer_certificate(sc->mms_sc_ssl);
	if (sc->mms_sc_cert == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_VERIFY);
		mms_trace(MMS_ERR,
		    "unauthenticated ssl connection, "
		    "no server certificate");
		goto error;
	}
	if (mms_ssl_check_cert(data, sc->mms_sc_cert, &conn->mms_err)) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_VERIFY);
		mms_trace(MMS_ERR, "invalid server certificate");
		goto error;
	}
	/* verify connection cert matches expected peer cert */
	if (data->mms_peer &&
	    mms_ssl_compare_cert(data->mms_peer, sc->mms_sc_cert)) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_VERIFY);
		goto error;
	}
	mms_trace(MMS_DEBUG, "client ssl connection");
	return (0);

error:
	mms_ssl_close(conn);
	return (1);
}

int
mms_ssl_accept(void *ssl_data, mms_t *conn)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	mms_sc_t	*sc;
	int		rc;
	mms_t		myconn;

	/*
	 * Server accepts client SSL connection.
	 */
	conn->mms_ssl = (void *)calloc(1, sizeof (mms_sc_t));
	if (conn->mms_ssl == NULL) {
		mms_sys_error(&conn->mms_err, MMS_ERR_NOMEM);
		goto error;
	}
	sc = (mms_sc_t *)conn->mms_ssl;
	if (data->mms_ctx == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_CTX);
		mms_trace(MMS_ERR, "server no ssl context");
		goto error;
	}
	if ((sc->mms_sc_ssl = SSL_new(data->mms_ctx)) == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "server ssl new");
		goto error;
	}
	if (SSL_set_fd(sc->mms_sc_ssl, conn->mms_fd) != 1) {
		mms_error(&conn->mms_err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "server ssl set fd");
		goto error;
	}
	SSL_set_accept_state(sc->mms_sc_ssl);
	if ((rc = SSL_accept(sc->mms_sc_ssl)) != 1) {
		mms_ssl_set_error(&conn->mms_err,
		    MMS_ERR_ACCEPT_FAILED,
		    SSL_get_error(sc->mms_sc_ssl, rc));
		mms_trace(MMS_ERR, "server ssl accept");
		goto error_no_ssl;
	}
	sc->mms_sc_cert = SSL_get_peer_certificate(sc->mms_sc_ssl);
	if (sc->mms_sc_cert == NULL) {
		if (data->mms_verify) {
			mms_error(&conn->mms_err, MMS_ERR_SSL_VERIFY);
			mms_trace(MMS_ERR, "client certificate is required");
			goto error_ssl;
		}
		mms_trace(MMS_DEVP,
		    "unauthenticated ssl connection, "
		    "no client certificate");
	} else if (mms_ssl_check_cert(data, sc->mms_sc_cert,
	    &conn->mms_err)) {
		mms_trace(MMS_ERR, "invalid client certificate");
		goto error_ssl;
	}
	mms_trace(MMS_DEBUG, "server accepted ssl connection");
	return (0);

error_no_ssl:
	/*
	 * Assume problem is non-ssl client.
	 * Attempt to send unwelcome ssl to client.
	 */
	mms_trace(MMS_DEVP, "send fd %d -> %s", conn->mms_fd, UNWELCOME_SSL);
	(void) memset(&myconn, 0, sizeof (mms_t));
	myconn.mms_fd = conn->mms_fd;
	(void) mms_writer(&myconn, UNWELCOME_SSL);
	mms_ssl_close(conn);
	return (1);

error_ssl:
	/*
	 * Problem is client ssl validation.
	 * Attempt to send unwelcome access deined ssl to client.
	 */
	mms_trace(MMS_DEVP, "send fd %d -> %s", conn->mms_fd,
	    UNWELCOME_ACCESS_SSL);
	(void) mms_writer(conn, UNWELCOME_ACCESS_SSL);
	mms_ssl_close(conn);
	return (1);

error:
	/*
	 * Don't know if connection is ssl or non-ssl.
	 */
	mms_trace(MMS_DEVP, "close fd %d", conn->mms_fd);
	mms_ssl_close(conn);
	return (1);
}

int
mms_ssl_read(mms_t *conn, char *buf, int len)
{
	mms_sc_t	*sc = (mms_sc_t *)conn->mms_ssl;
	int		rc;
	int		n;

	/* data is decrypted by ssl read */

	(void) memset(&conn->mms_err, 0, sizeof (mms_err_t));
	for (n = 0; n < len; n += rc) {
		rc = SSL_read(sc->mms_sc_ssl, buf + n, len - n);
		if (rc <= 0) {
			mms_ssl_set_error(&conn->mms_err,
			    MMS_ERR_READ,
			    SSL_get_error(sc->mms_sc_ssl, rc));
			mms_trace(MMS_ERR, "ssl read");
			return (-1);
		}
	}
	return (n);
}

int
mms_ssl_read_has_error(mms_t *conn)
{
	if (conn->mms_err.mms_id == 0) {
		return (0); /* continue reading */
	}
	return (1); /* stop reading */
}

int
mms_ssl_write(mms_t *conn, struct iovec *iov, int iovcnt)
{
	mms_sc_t	*sc = (mms_sc_t *)conn->mms_ssl;
	int		rc;
	int		i;
	int		n;
	int		total = 0;

	/* data is encrypted by ssl write */

	(void) memset(&conn->mms_err, 0, sizeof (mms_err_t));
	for (i = 0; i < iovcnt; i++) {
		for (n = 0; n < iov[i].iov_len; n += rc) {
			rc = SSL_write(sc->mms_sc_ssl,
			    iov[i].iov_base + n,
			    iov[i].iov_len - n);
			if (rc <= 0) {
				mms_ssl_set_error(&conn->mms_err,
				    MMS_ERR_WRITE,
				    SSL_get_error(sc->mms_sc_ssl, rc));
				mms_trace(MMS_ERR, "ssl write");
				return (-1);
			}
		}
		total += n;
	}
	return (total);
}

int
mms_ssl_write_has_error(mms_t *conn)
{
	if (conn->mms_err.mms_id == 0) {
		return (0); /* continue writing */
	}
	return (1); /* stop writing */
}

void
mms_ssl_close(mms_t *conn)
{
	mms_sc_t	*sc = (mms_sc_t *)conn->mms_ssl;

	/*
	 * Close SSL connection.
	 */
	if (sc == NULL) {
		return;
	}

	if (sc->mms_sc_ssl) {
		if (SSL_get_shutdown(sc->mms_sc_ssl) & SSL_RECEIVED_SHUTDOWN) {
			(void) SSL_shutdown(sc->mms_sc_ssl);
		} else {
			(void) SSL_clear(sc->mms_sc_ssl);
		}
		SSL_free(sc->mms_sc_ssl);
		(void) close(conn->mms_fd);
		conn->mms_fd = -1;
	}

	if (sc->mms_sc_cert) {
		X509_free(sc->mms_sc_cert);
	}

	free(sc);
	conn->mms_ssl = NULL;
}

static void
mms_ssl_error(mms_err_t *err, int id)
{
	err->mms_type = MMS_ERR_SSL;
	err->mms_id = id;
	err->mms_num = ERR_get_error();
}

static void
mms_ssl_set_error(mms_err_t *err, int id, ulong_t num)
{
	err->mms_type = MMS_ERR_SSL;
	err->mms_id = id;
	err->mms_num = num;
}

/* Get error string */
void
mms_ssl_get_error_string(mms_err_t *err, char *ebuf, int ebuflen)
{
	int	id;
	char	buf[MMS_EBUF_LEN];

	if (err != NULL && ebuf != NULL && ebuflen > 0) {

		if ((id = err->mms_id) == 0)
			id = MMS_ERR_NONE;

		if (err->mms_num == 0) {
			/* no ssl error */
			(void) snprintf(ebuf, ebuflen, "%s",
			    mms_sym_code_to_str(id));
		} else {
			/* ssl error string */
			ERR_error_string_n(err->mms_num, buf, sizeof (buf));
			(void) snprintf(ebuf, ebuflen, "%s (%lu) %s",
			    mms_sym_code_to_str(id),
			    err->mms_num,
			    buf);
		}
	}
}

/* ARGSUSED0 */
static int
mms_ssl_pass_file_cb(char *buf, int size, int rwflag, void *u)
{
	FILE	*fp;
	char	*file = (char *)u;
	char	*ptr;

	/*
	 * Read private key password pharse from file.
	 */
	if (file == NULL) {
		mms_trace(MMS_ERR, "null pass file");
		return (0);
	}
	if ((fp = fopen(file, "r")) == NULL) {
		mms_trace(MMS_ERR, "pass file open %s %s",
		    file, strerror(errno));
		return (0);
	}
	ptr = fgets(buf, size, fp);
	(void) fclose(fp);
	if (ptr == NULL || ptr != buf) {
		mms_trace(MMS_WARN, "pass file empty %s", file);
		return (0);
	}
	if (ptr = strrchr(buf, '\n')) {
		*ptr = '\0';
	}
	return (strlen(buf));
}

static int
mms_ssl_store_cb(int ok, X509_STORE_CTX *store)
{
	X509	*cert;
	int	depth;
	int	err;
	char	issuer[256];
	char	subject[256];

	if (!ok) {
		cert = X509_STORE_CTX_get_current_cert(store);
		depth = X509_STORE_CTX_get_error_depth(store);
		err = X509_STORE_CTX_get_error(store);

		(void) X509_NAME_oneline(X509_get_issuer_name(cert),
		    issuer, sizeof (issuer));
		(void) X509_NAME_oneline(X509_get_subject_name(cert),
		    subject, sizeof (subject));

		mms_trace(MMS_ERR,
		    "Certificate Store Error:\n"
		    "\tdepth %d\n"
		    "\tissuer %s\n"
		    "\tsubject %s\n"
		    "\terror %s\n",
		    depth,
		    issuer,
		    subject,
		    X509_verify_cert_error_string(err));
	}
	return (ok);
}

static int
mms_ssl_check_cert(mms_ssl_t *data, X509 *cert, mms_err_t *err)
{
	X509_STORE_CTX	*store_ctx;
	int		rc;

	/*
	 * Verify certificate.
	 */
	if (data->mms_store == NULL ||
	    cert == NULL) {
		return (0);
	}
	if ((store_ctx = X509_STORE_CTX_new()) == NULL) {
		mms_ssl_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "x509 store new");
		return (1);
	}

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
	if (X509_STORE_CTX_init(store_ctx, data->mms_store,
	    cert, NULL) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_STORE);
		X509_STORE_CTX_free(store_ctx);
		mms_trace(MMS_ERR, "x509 store init");
		return (1);
	}
#else
	X509_STORE_CTX_init(store_ctx, data->mms_store, cert, NULL);
#endif

	if (!(rc = X509_verify_cert(store_ctx))) {
		mms_ssl_error(err, MMS_ERR_SSL_VERIFY);
		mms_trace(MMS_WARN, "x509 invalid cert");
	}
	X509_STORE_CTX_cleanup(store_ctx);
	X509_STORE_CTX_free(store_ctx);

	return (!rc);
}

int
mms_ssl_reload_crl_file(void *ssl_data, char *crl_file, mms_err_t *err)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	int		rc;

	if (data == NULL) {
		return (0);
	}

	/*
	 * Release previous CRL.
	 */
	if (data->mms_crl) {
		X509_CRL_free(data->mms_crl);
		data->mms_crl = NULL;
	}
	if (data->mms_store) {
		X509_STORE_free(data->mms_store);
		data->mms_store = NULL;
	}

	/*
	 * Get updated CRL.
	 */
	if (rc = mms_ssl_use_crl_file(data, crl_file, err)) {
		if (crl_file) {
			mms_trace(MMS_ERR, "reload crl file %s", crl_file);
		} else {
			mms_trace(MMS_ERR, "reload crl file");
		}
	}
	return (rc);
}

int
mms_ssl_has_crl(void *ssl_data)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;

	if (data == NULL || data->mms_store == NULL) {
		return (0); /* no crl */
	}
	return (1); /* has valid crl */
}

int
mms_ssl_check_conn_cert(void *ssl_data, mms_t *conn)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	mms_sc_t	*sc = (mms_sc_t *)conn->mms_ssl;
	int		rc;

	/*
	 * Check conn certs against updated CRL.
	 */
	if (data == NULL || data->mms_store == NULL ||
	    sc == NULL || sc->mms_sc_cert == NULL) {
		return (0);
	}
	if (rc = mms_ssl_check_cert(data, sc->mms_sc_cert, &conn->mms_err)) {
		mms_trace(MMS_DEVP, "check conn cert");
	}
	return (rc);
}

static int
mms_ssl_use_crl_file(mms_ssl_t *data, char *crl_file, mms_err_t *err)
{
	FILE		*fp;
	int		i;

	if (crl_file && data->mms_nchain) {
		mms_trace(MMS_DEBUG, "handle crl file %s", crl_file);
		if ((fp = fopen(crl_file, "r")) == NULL) {
			mms_sys_error(err, MMS_ERR_SSL_FILE);
			mms_trace(MMS_ERR, "open crl %s %s",
			    crl_file, strerror(errno));
			return (1);
		}
		data->mms_crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
		(void) fclose(fp);
		if (data->mms_crl == NULL) {
			mms_ssl_error(err, MMS_ERR_SSL_FILE);
			mms_trace(MMS_ERR, "read crl %s", crl_file);
			return (1);
		}

		if ((data->mms_store = X509_STORE_new()) == NULL) {
			mms_ssl_error(err, MMS_ERR_NOMEM);
			mms_trace(MMS_ERR, "new crl store");
			return (1);
		}
		X509_STORE_set_verify_cb_func(data->mms_store,
		    mms_ssl_store_cb);
		if (X509_STORE_add_cert(data->mms_store,
		    data->mms_chain[data->mms_nchain-1]) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_CERT);
			mms_trace(MMS_ERR, "add cacert %s %d",
			    crl_file, data->mms_nchain-1);
			return (1);
		}
		if (X509_STORE_add_crl(data->mms_store, data->mms_crl) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_FILE);
			mms_trace(MMS_ERR, "add crl %s", crl_file);
			return (1);
		}
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
		(void) X509_STORE_set_flags(data->mms_store,
		    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
#endif

		for (i = 0; i < data->mms_nchain; i++) {
			if (mms_ssl_check_cert(data,
			    data->mms_chain[i], err)) {
				mms_trace(MMS_ERR, "check cert %s at %d",
				    crl_file, i);
				return (1);
			}
		}
	}
	return (0);
}

/*
 * Source SSL data from files.
 *
 * To source SSL data not from files, write a function to load the
 * ssl data from your SSL source. The other ssl calls remain the same.
 *
 * Two-way authentication, server and client both have the following
 * PEM-encoded certificate file structure:
 *	1. RSA certificate
 *	2. Private key
 *	3. CA RSA Certificate Chain
 *
 * One-way authentication, the server has a RSA certificate, private key,
 * and CA RSA certificate chain. The client only has the server's
 * CA RSA certificate chain in the following PEM-encoded certificate
 * file structure:
 *	1. Optional for client
 *	2. Certificate Chain
 *
 * The RSA certificate private key password pharse:
 *	1. Optional
 *	2. password argument
 *	3. password file argument
 *
 * The CRL file is optional.
 */
static int
mms_ssl_data_use_files(void **ssl_data,
    char *cert_file,
    char *pass,
    char *pass_file,
    char *dh_file,
    char *crl_file,
    mms_err_t *err)
{
	mms_ssl_t	*data;
	FILE		*fp = NULL;
	X509		*cert = NULL;
	X509		**chain;
	long		off;
	ulong_t		rc;

	/*
	 * Load PEM-encoded files into SSL structures.
	 */
	if ((data = (mms_ssl_t *)calloc(1, sizeof (mms_ssl_t))) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		return (NULL);
	}

	/*
	 * User Certificate or CA Certificate
	 */
	if (cert_file == NULL) {
		/*
		 * User wants unauthenticated connection.
		 */
		*ssl_data = data;
		mms_trace(MMS_DEVP, "no cert file");
		return (0);
	}
	mms_trace(MMS_DEVP, "handle cert file %s", cert_file);
	if ((fp = fopen(cert_file, "r")) == NULL) {
		mms_sys_error(err, MMS_ERR_SSL_FILE);
		mms_trace(MMS_ERR, "cert file open %s %s",
		    cert_file, strerror(errno));
		goto error;
	}
	if ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL) {
		mms_ssl_error(err, MMS_ERR_SSL_FILE);
		mms_trace(MMS_ERR, "read 1st cert %s", cert_file);
		goto error;
	}
	if ((data->mms_chain = (X509 **)malloc(sizeof (X509 *))) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		goto error;
	}
	data->mms_chain[data->mms_nchain++] = cert;
	cert = NULL;
	mms_trace(MMS_DEVP, "read cert");

	/*
	 * Private Key Password Pharse
	 */
	if ((off = ftell(fp)) == -1) {
		mms_sys_error(err, MMS_ERR_SSL_FILE);
		mms_trace(MMS_ERR, "cert file tell %s %s",
		    cert_file, strerror(errno));
		goto error;
	}
	if (pass) {
		mms_trace(MMS_DEVP, "password");
		data->mms_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, pass);
	} else if (pass_file) {
		mms_trace(MMS_DEVP, "password file %s", pass_file);
		data->mms_key = PEM_read_RSAPrivateKey(fp, NULL,
		    mms_ssl_pass_file_cb, pass_file);
	} else {
		mms_trace(MMS_DEVP, "no password");
		data->mms_key = PEM_read_RSAPrivateKey(fp, NULL,
		    mms_ssl_pass_file_cb, NULL);
	}
	if (data->mms_key == NULL) {
		if (rc = ERR_get_error()) {
			switch (ERR_GET_REASON(rc)) {
			case PEM_R_NO_START_LINE:
				mms_trace(MMS_DEVP, "no private key");
				break;
			default:
				mms_ssl_set_error(err, MMS_ERR_SSL_FILE, rc);
				mms_trace(MMS_ERR,
				    "read private key %s %d %d",
				    cert_file, rc, ERR_GET_REASON(rc));
				goto error;
			}
		}
		/* one-way authentication */
		if (fseek(fp, off, SEEK_SET) == -1) {
			mms_sys_error(err, MMS_ERR_SSL_FILE);
			mms_trace(MMS_ERR, "cert file seek %s %s",
			    cert_file, strerror(errno));
			goto error;
		}
	} else {
		mms_trace(MMS_DEBUG, "read private key");
	}

	/*
	 * Certificate Chain Hierarchy
	 */
	while (cert = PEM_read_X509(fp, NULL, NULL, NULL)) {
		if ((chain = (X509 **)realloc(data->mms_chain,
		    sizeof (X509 *) * (data->mms_nchain + 1))) == NULL) {
			mms_sys_error(err, MMS_ERR_NOMEM);
			mms_trace(MMS_ERR, "pem alloc");
			goto error;
		}
		data->mms_chain = chain;
		data->mms_chain[data->mms_nchain++] = cert;
		cert = NULL;
		mms_trace(MMS_DEVP, "added to cert chain, count %d",
		    data->mms_nchain);
	}
	if (rc = ERR_get_error()) {
		switch (ERR_GET_REASON(rc)) {
		case PEM_R_NO_START_LINE:
			break;
		default:
			mms_ssl_set_error(err, MMS_ERR_SSL_FILE, rc);
			mms_trace(MMS_ERR,
			    "read cert chain %s %d %d\n",
			    cert_file, rc, ERR_GET_REASON(rc));
			goto error;
		}
	}
	(void) fclose(fp);
	fp = NULL;

	/*
	 * Optional Certificate Revocation List
	 */
	if (mms_ssl_use_crl_file(data, crl_file, err)) {
		mms_trace(MMS_DEVP, "crl file failed");
		goto error;
	}

	/*
	 * Diffie-Hellman required for server, client does not use.
	 */
	if (dh_file) {
		int	code;

		mms_trace(MMS_DEBUG, "handle server dh file %s", dh_file);
		if ((fp = fopen(dh_file, "r")) == NULL) {
			mms_sys_error(err, MMS_ERR_SSL_FILE);
			mms_trace(MMS_ERR, "open dh %s %s",
			    dh_file, strerror(errno));
			goto error;
		}
		data->mms_dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
		if (data->mms_dh == NULL) {
			mms_ssl_error(err, MMS_ERR_SSL_FILE);
			mms_trace(MMS_ERR, "read dh %s", dh_file);
			goto error;
		}
		(void) fclose(fp);
		fp = NULL;
		if (DH_check(data->mms_dh, &code) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_OP);
			mms_trace(MMS_WARN, "%s dh parameters are bad 0x%x",
			    dh_file, code);
			goto error;
		}
	}

	*ssl_data = data;
	return (0);

error:
	if (cert)
		X509_free(cert);
	mms_ssl_data_free(data);
	(void) fclose(fp);
	return (1);
}

static int
mms_ssl_set_peer_file(void *ssl_data, char *peer_cert_file, mms_err_t *err)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	FILE		*fp;

	/*
	 * Optional, clients only, load the mm peer certificate.
	 * This certificate is compared to the ssl connection peer
	 * certificate obtained from the ssl connection and will
	 * prevent the client from sending the password to a mm
	 * imposter.
	 */
	if (ssl_data == NULL) {
		mms_trace(MMS_ERR, "no ssl data");
		mms_error(err, MMS_ERR_NO_SSL);
		return (0);
	}
	if (data->mms_peer) {
		X509_free(data->mms_peer);
		data->mms_peer = NULL;
	}
	if (peer_cert_file == NULL) {
		return (0);
	}
	if ((fp = fopen(peer_cert_file, "r")) == NULL) {
		mms_sys_error(err, MMS_ERR_SSL_CERT);
		mms_trace(MMS_ERR, "unable to open %s", peer_cert_file);
		return (1);
	}
	data->mms_peer = PEM_read_X509(fp, NULL, NULL, NULL);
	(void) fclose(fp);
	if (data->mms_peer == NULL) {
		mms_ssl_error(err, MMS_ERR_SSL_CERT);
		mms_trace(MMS_ERR, "read %s", peer_cert_file);
		return (1);
	}
	if (mms_ssl_check_cert(data, data->mms_peer, err)) {
		X509_free(data->mms_peer);
		data->mms_peer = NULL;
		return (1);
	}
	return (0);
}

static void
mms_ssl_data_free(void *ssl_data)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	int		i;

	/*
	 * Free SSL connection context data.
	 */
	if (data) {
		if (data->mms_chain) {
			for (i = 0; i < data->mms_nchain; i++) {
				X509_free(data->mms_chain[i]);
			}
			free(data->mms_chain);
		}
		if (data->mms_peer)
			X509_free(data->mms_peer);
		if (data->mms_key)
			RSA_free(data->mms_key);
		if (data->mms_ctx)
			SSL_CTX_free(data->mms_ctx);
		if (data->mms_dh)
			DH_free(data->mms_dh);
		if (data->mms_store)
			X509_STORE_free(data->mms_store);
		free(data);
	}
}

static int
mms_ssl_verify_cb(int ok, X509_STORE_CTX *store)
{
	X509	*cert;
	int	depth;
	int	err;
	char	issuer[256];
	char	subject[256];

	if (!ok) {
		cert = X509_STORE_CTX_get_current_cert(store);
		depth = X509_STORE_CTX_get_error_depth(store);
		err = X509_STORE_CTX_get_error(store);

		(void) X509_NAME_oneline(X509_get_issuer_name(cert),
		    issuer, sizeof (issuer));
		(void) X509_NAME_oneline(X509_get_subject_name(cert),
		    subject, sizeof (subject));

		if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
			mms_trace(MMS_DEVP, "self signed cert in chain");
			ok = 1;
		} else {
			mms_trace(MMS_ERR,
			    "Certificate Verify Error:\n"
			    "\tdepth %d\n"
			    "\tissuer %s\n"
			    "\tsubject %s\n"
			    "\terror %s\n",
			    depth,
			    issuer,
			    subject,
			    X509_verify_cert_error_string(err));
		}
	}
	return (ok);
}

void
mms_ssl_server_set_verify_peer(void *ssl_data, int verify_peer)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;

	if (data) {
		data->mms_verify = verify_peer;
	}
}

static int
mms_ssl_server_ctx(void *ssl_data, int verify_peer, mms_err_t *err)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	char		*cipher_name = MMS_SSL_CIPHER;
	int		i;

	/*
	 * Create server SSL connection context.
	 */
	if (data->mms_nchain < 2 ||
	    data->mms_key == NULL ||
	    data->mms_dh == NULL) {
		mms_trace(MMS_ERR, "server context requires chain, key and dh");
		return (1);
	}
	if ((data->mms_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		mms_ssl_error(err, MMS_ERR_NOMEM);
		return (1);
	}
	if (SSL_CTX_use_certificate(data->mms_ctx,
	    data->mms_chain[0]) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_CERT);
		mms_trace(MMS_ERR, "server context 1st cert");
		return (1);
	}
	for (i = 1; i < data->mms_nchain; i++) {
		if (SSL_CTX_add_extra_chain_cert(data->mms_ctx,
		    data->mms_chain[i]) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_CERT);
			mms_trace(MMS_ERR, "server context cert %d", i);
			return (1);
		}
	}
	if (SSL_CTX_use_RSAPrivateKey(data->mms_ctx,
	    data->mms_key) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_KEY);
		mms_trace(MMS_ERR, "server private key");
		return (1);
	}
	SSL_CTX_set_verify_depth(data->mms_ctx, data->mms_nchain);
	data->mms_verify = verify_peer;
	if (data->mms_verify == 0) {
		mms_trace(MMS_DEVP, "client certificate not required");
	} else {
		mms_trace(MMS_DEVP, "client certificate required");
	}
	SSL_CTX_set_verify(data->mms_ctx, SSL_VERIFY_PEER,
	    mms_ssl_verify_cb);
	if (SSL_CTX_set_tmp_dh(data->mms_ctx, data->mms_dh) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_DH);
		mms_trace(MMS_ERR, "server context dh");
		return (1);
	}
	(void) SSL_CTX_set_options(data->mms_ctx,
	    SSL_OP_ALL|SSL_OP_NO_SSLv2|
	    SSL_MODE_AUTO_RETRY|SSL_OP_SINGLE_DH_USE);
	if (data->mms_cipher)
		cipher_name = data->mms_cipher;
	if (SSL_CTX_set_cipher_list(data->mms_ctx, cipher_name) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_CIPHER);
		mms_trace(MMS_ERR, "server context cipher %s", cipher_name);
		return (1);
	}
	return (0);
}

static int
mms_ssl_client_ctx(void *ssl_data, mms_err_t *err)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	char		*cipher_name = MMS_SSL_CIPHER;
	int		i;

	/*
	 * Create client SSL connection context.
	 */
	if ((data->mms_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
		mms_ssl_error(err, MMS_ERR_NOMEM);
		return (1);
	}
	if (data->mms_nchain) {
		if (SSL_CTX_use_certificate(data->mms_ctx,
		    data->mms_chain[0]) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_CERT);
			mms_trace(MMS_ERR, "client context 1st cert");
			return (1);
		}
	}
	for (i = 1; i < data->mms_nchain; i++) {
		if (SSL_CTX_add_extra_chain_cert(data->mms_ctx,
		    data->mms_chain[i]) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_CERT);
			mms_trace(MMS_ERR, "client context cert %d", i);
			return (1);
		}
	}
	if (data->mms_key) {
		if (SSL_CTX_use_RSAPrivateKey(data->mms_ctx,
		    data->mms_key) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_KEY);
			mms_trace(MMS_ERR, "client context private key");
			return (1);
		}
	}
	if (data->mms_nchain) {
		SSL_CTX_set_verify_depth(data->mms_ctx, data->mms_nchain);
		SSL_CTX_set_verify(data->mms_ctx, SSL_VERIFY_PEER,
		    mms_ssl_verify_cb);
	}
	(void) SSL_CTX_set_options(data->mms_ctx,
	    SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_MODE_AUTO_RETRY);
	if (data->mms_cipher)
		cipher_name = data->mms_cipher;
	if (SSL_CTX_set_cipher_list(data->mms_ctx, cipher_name) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_CIPHER);
		mms_trace(MMS_ERR, "client context cipher %s", cipher_name);
		return (1);
	}
	return (0);
}

static char *
mms_ssl_x509_to_pem(X509 *cert, mms_err_t *err)
{
	BIO	*bio = NULL;
	char	*buf = NULL;
	int	len;
	int	i;
	int	n;

	/*
	 * Convert x509 certificate structure to text certficate.
	 */
	if (cert == NULL) {
		mms_error(err, MMS_ERR_SSL_NOCERT);
		mms_trace(MMS_ERR, "x509 to pem null cert");
		goto error;
	}
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		mms_ssl_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "x509 to pem s mem");
		goto error;
	}
	if (PEM_write_bio_X509(bio, cert) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "x509 to pem write");
		goto error;
	}
	len = 4096;
	if ((buf = malloc(len)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "x509 to pem buf");
		goto error;
	}
	if ((n = BIO_read(bio, buf, len)) <= 0) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "x509 to pem read");
		goto error;
	}
	buf[n] = '\0';
	/* remove trailing newlines */
	for (i = strlen(buf) - 1; i >= 0; i--) {
		if (buf[i] == '-')
			break;
		buf[i] = '\0';
	}
	(void) BIO_free(bio);
	return (buf);

error:
	if (bio)
		(void) BIO_free(bio);
	if (buf)
		free(buf);
	return (NULL);
}

static X509 *
mms_ssl_pem_to_x509(char *cert, mms_err_t *err)
{
	BIO	*bio = NULL;
	X509	*cert_x509;
	int	len;
	int	n;

	/*
	 * Convert text certificate to x509 certificate structure.
	 */
	if (cert == NULL) {
		mms_error(err, MMS_ERR_SSL_NOCERT);
		mms_trace(MMS_ERR, "pem to x509 null cert");
		goto error;
	}
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		mms_ssl_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "pem to x509 s mem");
		goto error;
	}
	len = strlen(cert);
	n = BIO_write(bio, cert, len);
	if (n <= 0 || n != len) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "pem to x509 write");
		goto error;
	}
	if ((cert_x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "pem to x509 read");
		goto error;
	}
	(void) BIO_free(bio);
	return (cert_x509);

error:
	if (bio)
		(void) BIO_free(bio);
	return (NULL);
}

static int
mms_ssl_compare_cert(X509 *acert, X509 *bcert)
{
	char 		*atext = NULL;
	char 		*btext = NULL;
	mms_err_t	err;
	int		rc = 1;

	if ((atext = mms_ssl_x509_to_pem(acert, &err)) == NULL)
		goto out;
	if ((btext = mms_ssl_x509_to_pem(bcert, &err)) == NULL)
		goto out;
	if (strlen(atext) != strlen(btext))
		goto out;
	if (rc = memcmp(atext, btext, strlen(atext))) {
		mms_trace(MMS_DEVP, "cert compare failed");
	}
out:
	free(atext);
	free(btext);
	return (rc);
}

static char *
mms_ssl_encode(uchar_t *buf, int len, mms_err_t *err)
{
	uchar_t		*out = NULL;
	int		outl;
	EVP_ENCODE_CTX	encode_ctx;
	int		tmplen;

	/* base64 encode */

	if (buf) {
		outl = ((len + 2 / 3) * 4) + 1;
		if ((out = (uchar_t *)malloc(outl)) == NULL) {
			mms_sys_error(err, MMS_ERR_NOMEM);
			mms_trace(MMS_ERR, "encode");
		} else {
			EVP_EncodeInit(&encode_ctx);
			EVP_EncodeUpdate(&encode_ctx, out, &outl, buf, len);
			EVP_EncodeFinal(&encode_ctx, out + outl, &tmplen);
			outl += tmplen;
			out[outl - 1] = 0;
		}
	}
	return ((char *)out);
}

static uchar_t *
mms_ssl_decode(char *buf, int *len, mms_err_t *err)
{
	uchar_t		*out = NULL;
	int		outl;
	EVP_ENCODE_CTX	encode_ctx;
	int		tmplen;

	/* base64 decode */

	if (buf) {
		outl = (((strlen(buf) + 3) / 4) * 3);
		if ((out = (uchar_t *)malloc(outl)) == NULL) {
			mms_sys_error(err, MMS_ERR_NOMEM);
			mms_trace(MMS_ERR, "decode");
		} else {
			EVP_DecodeInit(&encode_ctx);
			if (EVP_DecodeUpdate(&encode_ctx, out, len,
			    (uchar_t *)buf, strlen(buf)) == -1) {
				mms_sys_error(err, MMS_ERR_SSL_OP);
				mms_trace(MMS_ERR, "decode update");
				goto failed;
			}
			if (EVP_DecodeFinal(&encode_ctx, out + *len,
			    &tmplen) == -1) {
				mms_sys_error(err, MMS_ERR_SSL_OP);
				mms_trace(MMS_ERR, "decode final");
				goto failed;
			}
			*len += tmplen;
		}
	}
	return (out);

failed:
	free(out);
	return (NULL);
}

static int
mms_ssl_encrypt(EVP_PKEY *pubkey, char *passwd, char *data[], mms_err_t *err)
{
	EVP_CIPHER_CTX	cipher_ctx;
	EVP_PKEY	*pub_key[1] = {pubkey};
	uchar_t		*ek[1] = {NULL};
	int		eklen;
	uchar_t		*iv = NULL;
	int		ivlen;
	uchar_t		*encbuf = NULL;
	int		enclen;
	int		tmplen;
	int		i;
	int		rc = 1;

	/* public key encrypt */

	EVP_CIPHER_CTX_init(&cipher_ctx);

	eklen = EVP_PKEY_size(pubkey);
	if ((ek[0] = (uchar_t *)malloc(eklen)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "encrypt init");
		goto out;
	}
	ivlen = EVP_CIPHER_iv_length(EVP_des_cbc());
	if ((iv = (uchar_t *)malloc(ivlen)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "encrypt init");
		goto out;
	}

	(void) RAND_pseudo_bytes(ek[0], eklen);
	(void) RAND_pseudo_bytes(iv, ivlen);

	if (EVP_SealInit(&cipher_ctx, EVP_des_cbc(),
	    ek, &eklen, iv, pub_key, 1) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "encrypt init");
		goto out;
	}
	enclen = strlen(passwd) + EVP_CIPHER_CTX_block_size(&cipher_ctx);
	if ((encbuf = (uchar_t *)malloc(enclen)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "encrypt buf");
		goto out;
	}
	if (EVP_SealUpdate(&cipher_ctx, encbuf, &enclen,
	    (uchar_t *)passwd, strlen(passwd)) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "encrypt update");
		goto out;
	}
	if (EVP_SealFinal(&cipher_ctx, encbuf + enclen, &tmplen) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "encrypt final");
		goto out;
	}
	enclen += tmplen;
	if ((data[0] = mms_ssl_encode(ek[0], eklen, err)) == NULL) {
		mms_trace(MMS_DEVP, "encrypt encode ek");
		goto out;
	}
	if ((data[1] = mms_ssl_encode(iv, ivlen, err)) == NULL) {
		mms_trace(MMS_DEVP, "encrypt encode iv");
		goto out;
	}
	if ((data[2] = mms_ssl_encode(encbuf, enclen, err)) == NULL) {
		mms_trace(MMS_DEVP, "encrypt encode buf");
		goto out;
	}
	rc = 0;

out:
	if (rc) {
		for (i = 0; i < 4; i++) {
			free(data[i]);
		}
	}
	free(ek[0]);
	free(iv);
	free(encbuf);
	(void) EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	return (rc);
}

static char *
mms_ssl_decrypt(EVP_PKEY *pkey, char *data[], mms_err_t *err)
{
	EVP_CIPHER_CTX	cipher_ctx;
	int		len;
	char		*password = NULL;
	uchar_t		*ek = NULL;
	int		eklen;
	uchar_t		*iv = NULL;
	int		ivlen;
	uchar_t		*encbuf = NULL;
	int		enclen;
	int		tmplen;
	int		rc = 1;

	/* private key decrypt */

	(void) EVP_CIPHER_CTX_init(&cipher_ctx);

	if ((ek = mms_ssl_decode(data[0], &eklen, err)) == NULL) {
		mms_trace(MMS_DEVP, "decrypt decode ek");
		goto out;
	}
	if ((iv = mms_ssl_decode(data[1], &ivlen, err)) == NULL) {
		mms_trace(MMS_DEVP, "decrypt decode iv");
		goto out;
	}
	if ((encbuf = mms_ssl_decode(data[2], &enclen, err)) == NULL) {
		mms_trace(MMS_DEVP, "decrypt decode buf");
		goto out;
	}
	if ((password = (char *)malloc(enclen)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "decrypt get memory");
		goto out;
	}
	if (EVP_OpenInit(&cipher_ctx, EVP_des_cbc(),
	    ek, eklen, iv, pkey) == 0) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "decrypt init");
		goto out;
	}
	if (EVP_OpenUpdate(&cipher_ctx, (uchar_t *)password, &len,
	    encbuf, enclen) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "decrypt update");
		goto out;
	}
	if (EVP_OpenFinal(&cipher_ctx, (uchar_t *)password + len,
	    &tmplen) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "decrypt final");
		goto out;
	}
	len += tmplen;
	password[len] = 0;
	rc = 0;

out:
	if (rc) {
		free(password);
		password = NULL;
	}
	free(ek);
	free(iv);
	free(encbuf);
	(void) EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	return (password);
}

static int
mms_ssl_sign(EVP_PKEY *pkey, char *data[], mms_err_t *err)
{
	EVP_MD_CTX	md_ctx;
	uchar_t		*signbuf = NULL;
	int		signlen;
	int		i;
	int		rc = 1;

	/* private key sign */

	(void) EVP_MD_CTX_init(&md_ctx);

	signlen = EVP_PKEY_size(pkey);
	if ((signbuf = (uchar_t *)malloc(signlen)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "sign get buf memory");
		goto out;
	}
	if (EVP_SignInit_ex(&md_ctx, EVP_sha1(), NULL) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "sign init");
		goto out;
	}
	for (i = 0; i < 3; i++) {
		if (EVP_SignUpdate(&md_ctx, data[i], strlen(data[i])) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_OP);
			mms_trace(MMS_ERR, "sign update %d", i);
			goto out;
		}
	}
	if (EVP_SignFinal(&md_ctx, signbuf, (uint_t *)&signlen, pkey) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "sign final");
		goto out;
	}
	if ((data[3] = mms_ssl_encode(signbuf, signlen, err)) == NULL) {
		mms_trace(MMS_DEVP, "sign encode");
		goto out;
	}
	rc = 0;

out:
	(void) EVP_MD_CTX_cleanup(&md_ctx);
	free(signbuf);
	return (rc);
}

static int
mms_ssl_verify_sign(EVP_PKEY *pubkey, char *data[], mms_err_t *err)
{
	EVP_MD_CTX	md_ctx;
	uchar_t		*signbuf = NULL;
	int		signlen;
	int		i;
	int		rc = 1;

	/* public key verify sign */

	(void) EVP_MD_CTX_init(&md_ctx);

	if ((signbuf = mms_ssl_decode(data[3], &signlen, err)) == NULL) {
		mms_trace(MMS_DEVP, "verify sign decode");
		goto out;
	}
	if (EVP_VerifyInit_ex(&md_ctx, EVP_sha1(), NULL) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "verify sign init");
		goto out;
	}
	for (i = 0; i < 3; i++) {
		if (EVP_VerifyUpdate(&md_ctx, data[i], strlen(data[i])) != 1) {
			mms_ssl_error(err, MMS_ERR_SSL_OP);
			mms_trace(MMS_ERR, "verify sign update %d", i);
			goto out;
		}
	}
	if (EVP_VerifyFinal(&md_ctx, signbuf, signlen, pubkey) != 1) {
		mms_ssl_error(err, MMS_ERR_SSL_OP);
		mms_trace(MMS_ERR, "verify sign final");
		goto out;
	}
	rc = 0;

out:
	(void) EVP_MD_CTX_cleanup(&md_ctx);
	free(signbuf);
	return (rc);
}

int
mms_ssl_has_cert_clause(void *ssl_data, mms_t *conn)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	mms_sc_t	*sc = (mms_sc_t *)conn->mms_ssl;

	if (data != NULL && sc != NULL) {
		/*
		 * my certificate, my private key and
		 * other guy's certificate
		 */
		if (data->mms_nchain > 0 &&
		    data->mms_key != NULL &&
		    (data->mms_peer != NULL || sc->mms_sc_cert != NULL)) {
			return (1); /* use hello/welcome certificate-clause */
		}
	}
	return (0); /* don't use hello/welcome certificate-clause */
}

int
mms_ssl_build_cert_clause(void *ssl_data,
    mms_t *conn,
    char *password,
    char **cert,
    char **auth)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	mms_sc_t	*sc = (mms_sc_t *)conn->mms_ssl;
	mms_err_t	*err = &conn->mms_err;
	EVP_PKEY	*pkey = NULL;
	EVP_PKEY	*pubkey = NULL;
	char		*mydata[4] = {0, 0, 0, 0};
	int		i;
	int		len;
	int		rc = 1;
	X509		*peer_cert;

	/* create certificate clause */

	*cert = NULL;
	*auth = NULL;

	mms_trace(MMS_DEVP, "build certificate clause");

	/* my private key */
	if ((pkey = EVP_PKEY_new()) == NULL) {
		mms_ssl_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "new evp key");
		goto out;
	}
	if (EVP_PKEY_set1_RSA(pkey, data->mms_key) == 0) {
		mms_ssl_error(err, MMS_ERR_SSL_KEY);
		mms_trace(MMS_ERR, "set evp rsa key");
		goto out;
	}
	/* my certificate */
	if ((*cert = mms_ssl_x509_to_pem(data->mms_chain[0], err)) == NULL) {
		mms_trace(MMS_DEVP, "my certificate");
		goto out;
	}
	/* get other guy's public key */
	if ((peer_cert = data->mms_peer) == NULL) {
		peer_cert = sc->mms_sc_cert;
	}
	if ((pubkey = X509_get_pubkey(peer_cert)) == NULL) {
		mms_ssl_error(err, MMS_ERR_SSL_KEY);
		mms_trace(MMS_ERR, "other guy's public key");
		goto out;
	}
	/* encrypt password using other guy's public key */
	if (mms_ssl_encrypt(pubkey, password, mydata, err)) {
		mms_trace(MMS_DEVP, "encryption failed");
		goto out;
	}
	/* sign password using my private key */
	if (mms_ssl_sign(pkey, mydata, err)) {
		mms_trace(MMS_DEVP, "signing failed");
		goto out;
	}
	/* build authenticaton message */
	len = 0;
	for (i = 0; i < 4; i++) {
		len += (strlen(mydata[i]) + 1);
	}
	if ((*auth = (char *)malloc(len)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "get auth memory");
		goto out;
	}
	(void) snprintf(*auth, len, "%s %s %s %s",
	    mydata[0], mydata[1], mydata[2], mydata[3]);
	rc = 0;

out:
	if (rc) {
		free(*cert);
		free(*auth);
	}
	for (i = 0; i < 4; i++) {
		free(mydata[i]);
	}
	if (pkey)
		EVP_PKEY_free(pkey);
	return (rc);
}

int
mms_ssl_verify_cert_clause(void *ssl_data,
    mms_t *conn,
    char *cert_pem,
    char *auth,
    char **password)
{
	mms_ssl_t	*data = (mms_ssl_t *)ssl_data;
	X509		*cert = NULL;
	mms_err_t	*err = &conn->mms_err;
	EVP_PKEY	*pkey = NULL;
	EVP_PKEY	*pubkey = NULL;
	char		*mydata[4] = {0, 0, 0, 0};
	int		i;
	int		rc = 1;

	/* verify certificate clause */

	*password = NULL;

	mms_trace(MMS_DEVP, "verify certificate clause");

	/* my private key */
	if ((pkey = EVP_PKEY_new()) == NULL) {
		mms_ssl_error(err, MMS_ERR_SSL_KEY);
		mms_trace(MMS_ERR, "new evp key");
		goto out;
	}
	if (EVP_PKEY_set1_RSA(pkey, data->mms_key) == 0) {
		mms_ssl_error(err, MMS_ERR_SSL_KEY);
		mms_trace(MMS_ERR, "set evp rsa key");
		goto out;
	}
	/* get certificate from other guy's certificate text */
	if ((cert = mms_ssl_pem_to_x509(cert_pem, err)) == NULL) {
		mms_trace(MMS_ERR, "other guy's cert failed");
		goto out;
	}
	/* check other guy's cert */
	if (mms_ssl_check_cert(data, cert, err)) {
		mms_trace(MMS_ERR, "other guy's cert invalid");
		goto out;
	}
	/* get other guy's public key */
	if ((pubkey = X509_get_pubkey(cert)) == NULL) {
		mms_ssl_error(err, MMS_ERR_SSL_KEY);
		mms_trace(MMS_ERR, "other guy's public key");
		goto out;
	}
	/* parse authentication message */
	if ((mydata[0] = strdup(auth)) == NULL) {
		mms_sys_error(err, MMS_ERR_NOMEM);
		mms_trace(MMS_ERR, "auth message dup");
		goto out;
	}
	for (i = 1; i < 4; i++) {
		if ((mydata[i] = strchr(mydata[i - 1], ' ')) == NULL) {
			mms_error(err, MMS_ERR_SSL_OP);
			mms_trace(MMS_ERR, "parse auth message");
			goto out;
		}
		mydata[i][0] = 0;
		mydata[i]++;
	}
	/* verify other guy's signature */
	if (mms_ssl_verify_sign(pubkey, mydata, err)) {
		mms_trace(MMS_ERR, "other guy's signature invalid");
		goto out;
	}
	/* decrypt password using my private key */
	if ((*password = mms_ssl_decrypt(pkey, mydata, err)) == NULL) {
		mms_trace(MMS_ERR, "decryption failed");
		goto out;
	}
	rc = 0;

out:
	if (cert)
		X509_free(cert);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (mydata[0])
		free(mydata[0]);
	return (rc);
}

#endif /* MMS_OPENSSL */
