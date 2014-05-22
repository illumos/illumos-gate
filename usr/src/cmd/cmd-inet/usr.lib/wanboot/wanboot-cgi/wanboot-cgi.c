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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wanboot_impl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <p12aux.h>

#include <parseURL.h>
/*
 * These can be replaced with wanbootutil.h once the openssl interfaces
 * are moved to libwanboot.
 */
#include <wanboot/key_util.h>
#include <wanboot/key_xdr.h>
#include <hmac_sha1.h>

#include <netboot_paths.h>
#include <wanboot_conf.h>

/*
 * Exit status:
 */
#define	WBCGI_STATUS_OK		0
#define	WBCGI_STATUS_ERR	1

#define	WBCGI_FILE_EXISTS(file, statbuf) \
	(stat(file, &statbuf) == 0 && S_ISREG(statbuf.st_mode))

#define	WBCGI_DIR_EXISTS(dir, statbuf) \
	(stat(dir, &statbuf) == 0 && S_ISDIR(statbuf.st_mode))

#define	WBCGI_HMAC_PATH		"/usr/lib/inet/wanboot/hmac"
#define	WBCGI_ENCR_PATH		"/usr/lib/inet/wanboot/encr"
#define	WBCGI_KEYMGMT_PATH	"/usr/lib/inet/wanboot/keymgmt"
#define	WBCGI_MKISOFS_PATH	"/bin/mkisofs"

#define	WBCGI_DEV_URANDOM	"/dev/urandom"

#define	WBCGI_CONTENT_TYPE	"Content-Type: "
#define	WBCGI_CONTENT_LENGTH	"Content-Length: "
#define	WBCGI_WANBOOT_BNDTXT	"WANBoot_Part_Boundary"
#define	WBCGI_CRNL		"\r\n"

#define	WBCGI_CNSTR		"CN="
#define	WBCGI_CNSTR_LEN		(sizeof (WBCGI_CNSTR) - 1)
#define	WBCGI_NAMESEP		",/\n\r"

#define	WBCGI_MAXBUF		256

/*
 * Possible return values from netboot_ftw():
 */
#define	WBCGI_FTW_CBOK		2	/* CB terminated walk OK */
#define	WBCGI_FTW_CBCONT	1	/* CB wants walk should continue */
#define	WBCGI_FTW_DONE		0	/* Walk terminated without CBERR/CBOK */
#define	WBCGI_FTW_CBERR		-1	/* CB terminated walk with err */

/*
 * getsubopt() is used to map one of the contents[] keywords
 * to one of these types
 */
#define	WBCGI_CONTENT_ERROR	-1
#define	WBCGI_CONTENT_BOOTFILE	0
#define	WBCGI_CONTENT_BOOTFS	1
#define	WBCGI_CONTENT_ROOTFS	2

static char *contents[] =
	{ "bootfile", "bootfs", "rootfs", NULL };

/*
 * getsubopt() is used to parse the query string for
 * the keywords defined by queryopts[]
 */
#define	WBCGI_QUERYOPT_CONTENT	0
#define	WBCGI_QUERYOPT_NET	1
#define	WBCGI_QUERYOPT_CID	2
#define	WBCGI_QUERYOPT_NONCE	3

static char *queryopts[] =
	{ "CONTENT", "IP", "CID", "NONCE", NULL };

static bc_handle_t	bc_handle;


static char *
status_msg(int status)
{
	char	*msg;

	switch (status) {
	case 400:
		msg = "Bad Request";
		break;
	case 403:
		msg = "Forbidden";
		break;
	case 500:
		msg = "Internal Server Error";
		break;
	default:
		msg = "Unknown status";
		break;
	}

	return (msg);
}

static void
print_status(int status, const char *spec_msg)
{
	if (spec_msg == NULL) {
		spec_msg = "";
	}

	(void) fprintf(stdout, "Status: %d %s %s%s", status,
	    status_msg(status), spec_msg, WBCGI_CRNL);
}

static char *
make_path(const char *root, const char *suffix)
{
	char	path[MAXPATHLEN];
	char	*ptr = NULL;
	int	chars;

	if ((chars = snprintf(path, sizeof (path),
	    "%s/%s", root, suffix)) < 0 || chars > sizeof (path) ||
	    (ptr = strdup(path)) == NULL) {
		print_status(500, "(error making path)");
	}

	return (ptr);
}

static void
free_path(char **pathp)
{
	if (*pathp != NULL) {
		free(*pathp);
		*pathp = NULL;
	}
}

static char *
gen_tmppath(const char *prefix, const char *net, const char *cid)
{
	pid_t	pid;
	time_t	secs;
	int	chars;
	char	path[MAXPATHLEN];
	char	*ptr = NULL;

	if ((pid = getpid()) < 0 || (secs = time(NULL)) < 0 ||
	    (chars = snprintf(path, sizeof (path), "/tmp/%s_%s_%s_%ld_%ld",
	    prefix, net, cid, pid, secs)) < 0 || chars > sizeof (path) ||
	    (ptr = strdup(path)) == NULL) {
		print_status(500, "(error creating temporary filename)");
	}

	return (ptr);
}

/*
 * File I/O stuff:
 */
static boolean_t
write_buffer(int fd, const void *buffer, size_t buflen)
{
	size_t		nwritten;
	ssize_t		nbytes;
	const char	*buf = buffer;

	for (nwritten = 0; nwritten < buflen; nwritten += nbytes) {
		nbytes = write(fd, &buf[nwritten], buflen - nwritten);
		if (nbytes <= 0) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
write_file(int ofd, const char *filename, size_t size)
{
	boolean_t	ret = B_TRUE;
	int		ifd;
	char		buf[1024];
	size_t		rlen;
	ssize_t		wlen;

	if ((ifd = open(filename, O_RDONLY)) < 0) {
		return (B_FALSE);
	}

	for (; size != 0; size -= wlen) {
		rlen = (size < sizeof (buf)) ? size : sizeof (buf);

		if ((wlen = read(ifd, buf, rlen)) < 0 ||
		    !write_buffer(ofd, buf, wlen)) {
			ret = B_FALSE;
			break;
		}
	}
	(void) close(ifd);

	return (ret);
}

static boolean_t
copy_file(const char *src, const char *dest)
{
	boolean_t	ret = B_FALSE;
	char		message[WBCGI_MAXBUF];
	const size_t	chunksize = 16 * PAGESIZE;
	size_t		validsize;
	size_t		nwritten = 0;
	size_t		nbytes = 0;
	off_t		roff;
	int		mflags = MAP_PRIVATE;
	char		*buf = NULL;
	struct stat	st;
	int		rfd = -1;
	int		wfd = -1;
	int		chars;

	if ((rfd = open(src, O_RDONLY)) < 0 ||
	    (wfd = open(dest, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR)) < 0 ||
	    fstat(rfd, &st) == -1) {
		goto cleanup;
	}

	for (nbytes = st.st_size, roff = 0; nwritten < nbytes;
	    nwritten += validsize, roff += validsize) {
		buf = mmap(buf, chunksize, PROT_READ, mflags, rfd, roff);
		if (buf == MAP_FAILED) {
			goto cleanup;
		}
		mflags |= MAP_FIXED;

		validsize = MIN(chunksize, nbytes - nwritten);
		if (!write_buffer(wfd, buf, validsize)) {
			(void) munmap(buf, chunksize);
			goto cleanup;
		}

	}
	if (buf != NULL) {
		(void) munmap(buf, chunksize);
	}

	ret = B_TRUE;
cleanup:
	if (ret == B_FALSE) {
		if ((chars = snprintf(message, sizeof (message),
		    "error copying %s to %s", src, dest)) > 0 &&
		    chars <= sizeof (message)) {
			print_status(500, message);
		} else {
			print_status(500, NULL);
		}
	}
	if (rfd != -1) {
		(void) close(rfd);
	}
	if (wfd != -1) {
		(void) close(wfd);
	}

	return (ret);
}

static boolean_t
create_nonce(const char *noncepath, const char *nonce)
{
	boolean_t	ret = B_TRUE;
	int		fd;

	if ((fd = open(noncepath,
	    O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) == -1 ||
	    !write_buffer(fd, nonce, strlen(nonce))) {
		print_status(500, "(error creating nonce file)");
		ret = B_FALSE;
	}
	if (fd != -1) {
		(void) close(fd);
	}

	return (ret);
}

static boolean_t
create_timestamp(const char *timestamppath, const char *timestamp)
{
	boolean_t	ret = B_TRUE;
	int		fd;

	if ((fd = open(timestamppath,
	    O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) == -1 ||
	    !write_buffer(fd, timestamp, strlen(timestamp))) {
		print_status(500, "(error creating timestamp file)");
		ret = B_FALSE;
	}
	if (fd != -1) {
		(void) close(fd);
	}

	return (ret);
}

static boolean_t
create_urandom(const char *urandompath)
{
	boolean_t	ret = B_TRUE;
	int		fd;

	if ((fd = open(urandompath,
	    O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) == -1 ||
	    !write_file(fd, WBCGI_DEV_URANDOM, 32 * 1024)) {
		print_status(500, "(error creating urandom file)");
		ret = B_FALSE;
	}
	if (fd != -1) {
		(void) close(fd);
	}

	return (ret);
}

static boolean_t
create_null_hash(const char *hashpath)
{
	boolean_t	ret = B_TRUE;
	int		fd;
	static char	null_hash[HMAC_DIGEST_LEN];

	if ((fd = open(hashpath,
	    O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) == -1 ||
	    !write_buffer(fd, null_hash, sizeof (null_hash))) {
		print_status(500, "(error creating null hash)");
		ret = B_FALSE;
	}
	if (fd != -1) {
		(void) close(fd);
	}

	return (ret);
}


static char *
determine_doc_root(void)
{
	char	*doc_root;

	/*
	 * If DOCUMENT_ROOT is valid, use that.
	 */
	if ((doc_root = getenv("DOCUMENT_ROOT")) == NULL ||
	    strlen(doc_root) == 0) {
		/*
		 * No DOCUMENT_ROOT - try PATH_TRANSLATED.
		 */
		if ((doc_root = getenv("PATH_TRANSLATED")) == NULL ||
		    strlen(doc_root) == 0) {
			/*
			 * Can't determine the document root.
			 */
			return (NULL);
		}
	}

	return (doc_root);
}

static boolean_t
get_request_info(int *contentp, char **netp, char **cidp, char **noncep,
    char **docrootp)
{
	char	*method;
	char	*query_string;
	char	*value;
	char	*junk;
	int	i;

	if ((method = getenv("REQUEST_METHOD")) == NULL ||
	    strncasecmp(method, "GET", strlen("GET") != 0)) {
		print_status(403, "(GET method expected)");
		return (B_FALSE);
	}

	if ((query_string = getenv("QUERY_STRING")) == NULL) {
		print_status(400, "(empty query string)");
		return (B_FALSE);
	}

	for (i = 0; i < strlen(query_string); i++) {
		if (query_string[i] == '&') {
			query_string[i] = ',';
		}
	}

	*contentp = WBCGI_CONTENT_ERROR;
	*netp = *cidp = *noncep = NULL;

	if ((*docrootp = determine_doc_root()) == NULL) {
		print_status(400, "(unable to determine document root)");
		return (B_FALSE);
	}

	while (*query_string != '\0') {
		switch (getsubopt(&query_string, queryopts, &value)) {
		case WBCGI_QUERYOPT_CONTENT:
			*contentp = getsubopt(&value, contents, &junk);
			break;
		case WBCGI_QUERYOPT_NET:
			*netp = value;
			break;
		case WBCGI_QUERYOPT_CID:
			*cidp = value;
			break;
		case WBCGI_QUERYOPT_NONCE:
			*noncep = value;
			break;
		default:
			print_status(400, "(illegal query string)");
			return (B_FALSE);
		}
	}

	switch (*contentp) {
	default:
		print_status(400, "(missing or illegal CONTENT)");
		return (B_FALSE);

	case WBCGI_CONTENT_BOOTFS:
		if (*netp == NULL || *cidp == NULL || *noncep == NULL) {
			print_status(400,
			    "(CONTENT, IP, CID and NONCE required)");
			return (B_FALSE);
		}
		break;

	case WBCGI_CONTENT_BOOTFILE:
	case WBCGI_CONTENT_ROOTFS:
		if (*netp == NULL || *cidp == NULL || *docrootp == NULL) {
			print_status(400,
			    "(CONTENT, IP, CID and DOCUMENT_ROOT required)");
			return (B_FALSE);
		}
		break;
	}

	return (B_TRUE);
}

static boolean_t
encrypt_payload(const char *payload, const char *encr_payload,
    const char *keyfile, const char *encryption_type)
{
	struct stat	sbuf;
	int		chars;
	char		cmd[MAXPATHLEN];
	FILE		*fp;
	int		status;
	char		msg[WBCGI_MAXBUF];

	if (!WBCGI_FILE_EXISTS(payload, sbuf)) {
		print_status(500, "(encrypt_payload: missing payload)");
		return (B_FALSE);
	}

	if ((chars = snprintf(cmd, sizeof (cmd),
	    "%s -o type=%s -k %s < %s > %s", WBCGI_ENCR_PATH,
	    encryption_type, keyfile, payload, encr_payload)) < 0 ||
	    chars > sizeof (cmd)) {
		print_status(500, "(encrypt_payload: buffer overflow)");
		return (B_FALSE);
	}

	if ((fp = popen(cmd, "w")) == NULL) {
		print_status(500, "(encrypt_payload: missing/file error)");
		return (B_FALSE);
	}
	if ((status = WEXITSTATUS(pclose(fp))) != 0) {
		(void) snprintf(msg, sizeof (msg),
		    "(encrypt_payload: failed, status=%d)", status);
		print_status(500, msg);
		return (B_FALSE);
	}

	if (!WBCGI_FILE_EXISTS(encr_payload, sbuf)) {
		print_status(500, "(encrypt_payload: bad encrypted file)");
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
hash_payload(const char *payload, const char *payload_hash,
    const char *keyfile)
{
	struct stat	sbuf;
	int		chars;
	char		cmd[MAXPATHLEN];
	FILE		*fp;
	int		status;
	char		msg[WBCGI_MAXBUF];

	if (!WBCGI_FILE_EXISTS(payload, sbuf)) {
		print_status(500, "(hash_payload: missing payload)");
		return (B_FALSE);
	}

	if ((chars = snprintf(cmd, sizeof (cmd), "%s -i %s -k %s > %s",
	    WBCGI_HMAC_PATH, payload, keyfile, payload_hash)) < 0 ||
	    chars > sizeof (cmd)) {
		print_status(500, "(hash_payload: buffer overflow)");
		return (B_FALSE);
	}

	if ((fp = popen(cmd, "w")) == NULL) {
		print_status(500, "(hash_payload: missing/file error)");
		return (B_FALSE);
	}
	if ((status = WEXITSTATUS(pclose(fp))) != 0) {
		(void) snprintf(msg, sizeof (msg),
		    "(hash_payload: failed, status=%d)", status);
		print_status(500, msg);
		return (B_FALSE);
	}

	if (!WBCGI_FILE_EXISTS(payload_hash, sbuf) ||
	    sbuf.st_size < HMAC_DIGEST_LEN) {
		print_status(500, "(hash_payload: bad signature file)");
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
extract_keystore(const char *path, const char *keystorepath)
{
	struct stat	sbuf;
	int		chars;
	char		cmd[MAXPATHLEN];
	FILE		*fp;
	int		status;
	char		msg[WBCGI_MAXBUF];

	if (!WBCGI_FILE_EXISTS(path, sbuf)) {
		print_status(500, "(extract_keystore: missing keystore)");
		return (B_FALSE);
	}

	if ((chars = snprintf(cmd, sizeof (cmd),
	    "%s -x -f %s -s %s -o type=rsa",
	    WBCGI_KEYMGMT_PATH, keystorepath, path)) < 0 ||
	    chars > sizeof (cmd)) {
		print_status(500, "(extract_keystore: buffer overflow)");
		return (B_FALSE);
	}

	if ((fp = popen(cmd, "w")) == NULL) {
		print_status(500, "(extract_keystore: missing/file error)");
		return (B_FALSE);
	}
	if ((status = WEXITSTATUS(pclose(fp))) != 0) {
		(void) snprintf(msg, sizeof (msg),
		    "(extract_keystore: failed, status=%d)", status);
		print_status(500, msg);
		return (B_FALSE);
	}

	if (!WBCGI_FILE_EXISTS(keystorepath, sbuf)) {
		print_status(500, "(extract_keystore: failed to create)");
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
mkisofs(const char *image_dir, const char *image)
{
	struct stat	sbuf;
	int		chars;
	char		cmd[MAXPATHLEN];
	FILE		*fp;
	int		status;
	char		msg[WBCGI_MAXBUF];

	if (!WBCGI_DIR_EXISTS(image_dir, sbuf)) {
		print_status(500, "(mksiofs: missing image_dir)");
		return (B_FALSE);
	}

	if ((chars = snprintf(cmd, sizeof (cmd), "%s -quiet -o %s -r %s",
	    WBCGI_MKISOFS_PATH, image, image_dir)) < 0 ||
	    chars > sizeof (cmd)) {
		print_status(500, "(mkisofs: buffer overflow)");
		return (B_FALSE);
	}

	if ((fp = popen(cmd, "w")) == NULL) {
		print_status(500, "(mkisofs: missing/file error)");
		return (B_FALSE);
	}
	if ((status = WEXITSTATUS(pclose(fp))) != 0) {
		(void) snprintf(msg, sizeof (msg),
		    "(mkisofs: failed, status=%d)", status);
		print_status(500, msg);
		return (B_FALSE);
	}

	if (!WBCGI_FILE_EXISTS(image, sbuf)) {
		print_status(500, "(mksiofs: failed to create image)");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This function, when invoked with a file name, optional network and
 * client ID strings, and callback function will search for the file
 * in the following locations:
 *
 * NB_NETBOOT_ROOT/<network>/<client id>/<file>
 * NB_NETBOOT_ROOT/<client id>/<file>
 * NB_NETBOOT_ROOT/<network>/<file>
 * NB_NETBOOT_ROOT/<file>
 *
 * The callback function is invoked each time the file is found until
 * we have searched all of the above locations or the callback function
 * returns a value other than WBCGI_FTW_CBCONT.
 *
 * Arguments:
 *	filename - Name of file to search for.
 *	net      - Optional network number to include in search hierarchy.
 *	cid      - Optional client ID to include in search hierarchy.
 *	cb       - Callback function to be called when file is found.
 *	arg	 - Argument to be supplied to the callback funtion.
 *
 * Returns:
 *	WBCGI_FTW_DONE, WBCGI_FTW_CBOK or WBCGI_FTW_CBERR.
 */
static int
netboot_ftw(const char *filename, const char *net, const char *cid,
    int (*cb)(const char *, void *arg), void *arg)
{
	char		ckpath[4][MAXPATHLEN];
	int		ret;
	struct		stat buf;
	int		i = 0;

	if (snprintf(ckpath[i++], MAXPATHLEN, "%s%s", NB_NETBOOT_ROOT, filename)
	    >= MAXPATHLEN)
		return (WBCGI_FTW_CBERR);

	if (net != NULL && snprintf(ckpath[i++], MAXPATHLEN, "%s%s/%s",
	    NB_NETBOOT_ROOT, net, filename) >= MAXPATHLEN)
		return (WBCGI_FTW_CBERR);

	if (cid != NULL) {
		if (snprintf(ckpath[i++], MAXPATHLEN, "%s%s/%s",
		    NB_NETBOOT_ROOT, cid, filename) >= MAXPATHLEN)
			return (WBCGI_FTW_CBERR);

		if (net != NULL && snprintf(ckpath[i++], MAXPATHLEN,
		    "%s%s/%s/%s", NB_NETBOOT_ROOT, net, cid, filename) >=
		    MAXPATHLEN)
			return (WBCGI_FTW_CBERR);
	}

	/*
	 * Loop through hierarchy and check for file existence.
	 */
	while (i > 0) {
		--i;
		if (WBCGI_FILE_EXISTS(ckpath[i], buf)) {
			if ((ret = cb(ckpath[i], arg)) != WBCGI_FTW_CBCONT)
				return (ret);
		}
	}
	return (WBCGI_FTW_DONE);
}

/*ARGSUSED*/
static int
noact_cb(const char *path, void *arg)
{
	return (WBCGI_FTW_CBOK);
}

static int
set_pathname(const char *path, void *pathname)
{
	*(char **)pathname = strdup((char *)path);
	return (WBCGI_FTW_CBOK);
}

static int
create_keystore(const char *path, void *keystorepath)
{
	if (!extract_keystore(path, (char *)keystorepath)) {
		return (WBCGI_FTW_CBERR);
	}
	return (WBCGI_FTW_CBOK);
}

static int
copy_certstore(const char *path, void *certstorepath)
{
	if (!copy_file(path, (char *)certstorepath)) {
		return (WBCGI_FTW_CBERR);
	}
	return (WBCGI_FTW_CBOK);
}

/*
 * Add the certs found in the trustfile found in path (a trust store) to
 * the file found at bootfs_dir/truststore.  If necessary, create the
 * output file.
 */
static int
build_trustfile(const char *path, void *truststorepath)
{
	int		ret = WBCGI_FTW_CBERR;
	STACK_OF(X509)	*i_anchors = NULL;
	STACK_OF(X509)	*o_anchors = NULL;
	char		message[WBCGI_MAXBUF];
	PKCS12		*p12 = NULL;
	FILE		*rfp = NULL;
	FILE		*wfp = NULL;
	struct stat	i_st;
	struct stat	o_st;
	X509		*x = NULL;
	int		errtype = 0;
	int		wfd = -1;
	int		chars;
	int		i;

	if (!WBCGI_FILE_EXISTS(path, i_st)) {
		goto cleanup;
	}

	if (WBCGI_FILE_EXISTS((char *)truststorepath, o_st)) {
		/*
		 * If we are inadvertantly writing to the input file.
		 * return success.
		 * XXX Pete: how can this happen, and why success?
		 */
		if (i_st.st_ino == o_st.st_ino) {
			ret = WBCGI_FTW_CBCONT;
			goto cleanup;
		}
		if ((wfp = fopen((char *)truststorepath, "r+")) == NULL) {
			goto cleanup;
		}
		/*
		 * Read what's already there, so that new information
		 * can be added.
		 */
		if ((p12 = d2i_PKCS12_fp(wfp, NULL)) == NULL) {
			errtype = 1;
			goto cleanup;
		}
		i = sunw_PKCS12_parse(p12, WANBOOT_PASSPHRASE, DO_NONE, NULL,
		    0, NULL, NULL, NULL, &o_anchors);
		if (i <= 0) {
			errtype = 1;
			goto cleanup;
		}

		PKCS12_free(p12);
		p12 = NULL;
	} else {
		if (errno != ENOENT) {
			chars = snprintf(message, sizeof (message),
			    "(error accessing file %s, error %s)",
			    path, strerror(errno));
			if (chars > 0 && chars < sizeof (message))
				print_status(500, message);
			else
				print_status(500, NULL);
			return (WBCGI_FTW_CBERR);
		}

		/*
		 * Note: We could copy the file to the new trustfile, but
		 * we can't verify the password that way.  Therefore, copy
		 * it by reading it.
		 */
		if ((wfd = open((char *)truststorepath,
		    O_CREAT|O_EXCL|O_RDWR, 0700)) < 0) {
			goto cleanup;
		}
		if ((wfp = fdopen(wfd, "w+")) == NULL) {
			goto cleanup;
		}
		o_anchors = sk_X509_new_null();
		if (o_anchors == NULL) {
			goto cleanup;
		}
	}

	if ((rfp = fopen(path, "r")) == NULL) {
		goto cleanup;
	}
	if ((p12 = d2i_PKCS12_fp(rfp, NULL)) == NULL) {
		errtype = 1;
		goto cleanup;
	}
	i = sunw_PKCS12_parse(p12, WANBOOT_PASSPHRASE, DO_NONE, NULL, 0, NULL,
	    NULL, NULL, &i_anchors);
	if (i <= 0) {
		errtype = 1;
		goto cleanup;
	}
	PKCS12_free(p12);
	p12 = NULL;

	/*
	 * Merge the two stacks of pkcs12 certs.
	 */
	for (i = 0; i < sk_X509_num(i_anchors); i++) {
		/* LINTED */
		x = sk_X509_delete(i_anchors, i);
		(void) sk_X509_push(o_anchors, x);
	}

	/*
	 * Create the pkcs12 structure from the modified input stack and
	 * then write out that structure.
	 */
	p12 = sunw_PKCS12_create((const char *)WANBOOT_PASSPHRASE, NULL, NULL,
	    o_anchors);
	if (p12 == NULL) {
		goto cleanup;
	}
	rewind(wfp);
	if (i2d_PKCS12_fp(wfp, p12) == 0) {
		goto cleanup;
	}

	ret = WBCGI_FTW_CBCONT;
cleanup:
	if (ret == WBCGI_FTW_CBERR) {
		if (errtype == 1) {
			chars = snprintf(message, sizeof (message),
			    "(internal PKCS12 error while copying %s to %s)",
			    path, (char *)truststorepath);
		} else {
			chars = snprintf(message, sizeof (message),
			    "(error copying %s to %s)",
			    path, (char *)truststorepath);
		}
		if (chars > 0 && chars <= sizeof (message)) {
			print_status(500, message);
		} else {
			print_status(500, NULL);
		}
	}
	if (rfp != NULL) {
		(void) fclose(rfp);
	}
	if (wfp != NULL) {
		/* Will also close wfd */
		(void) fclose(wfp);
	}
	if (p12 != NULL) {
		PKCS12_free(p12);
	}
	if (i_anchors != NULL) {
		sk_X509_pop_free(i_anchors, X509_free);
	}
	if (o_anchors != NULL) {
		sk_X509_pop_free(o_anchors, X509_free);
	}

	return (ret);
}

static boolean_t
check_key_type(const char *keyfile, const char *keytype, int flag)
{
	boolean_t	ret = B_FALSE;
	FILE		*key_fp = NULL;
	wbku_key_attr_t	ka;

	/*
	 * Map keytype into the ka structure
	 */
	if (wbku_str_to_keyattr(keytype, &ka, flag) != WBKU_SUCCESS) {
		goto cleanup;
	}

	/*
	 * Open the key file for reading.
	 */
	if ((key_fp = fopen(keyfile, "r")) == NULL) {
		goto cleanup;
	}

	/*
	 * Find the valid client key, if it exists.
	 */
	if (wbku_find_key(key_fp, NULL, &ka, NULL, B_FALSE) != WBKU_SUCCESS) {
		goto cleanup;
	}

	ret = B_TRUE;
cleanup:
	if (key_fp != NULL) {
		(void) fclose(key_fp);
	}

	return (ret);
}

static boolean_t
resolve_hostname(const char *hostname, nvlist_t *nvl, boolean_t may_be_crap)
{
	struct sockaddr_in	sin;
	struct hostent		*hp;
	struct utsname		un;
	static char 		myname[SYS_NMLN] = { '\0' };
	char			*cp = NULL;
	char			msg[WBCGI_MAXBUF];

	/*
	 *  Initialize cached nodename
	 */
	if (strlen(myname) == 0) {
		if (uname(&un) == -1) {
			(void) snprintf(msg, sizeof (msg),
			    "(unable to retrieve uname, errno %d)", errno);
			print_status(500, msg);
			return (B_FALSE);
		}
		(void) strcpy(myname, un.nodename);
	}

	/*
	 * If hostname is local node name, return the address this
	 * request came in on, which is supplied as SERVER_ADDR in the
	 * cgi environment.  This ensures we don't send back a possible
	 * alternate address that may be unreachable from the client's
	 * network.  Otherwise, just resolve with nameservice.
	 */
	if ((strcmp(hostname, myname) != 0) ||
	    ((cp = getenv("SERVER_ADDR")) == NULL)) {
		if (((hp = gethostbyname(hostname)) == NULL) ||
		    (hp->h_addrtype != AF_INET) ||
		    (hp->h_length != sizeof (struct in_addr))) {
			if (!may_be_crap) {
				print_status(500, "(error resolving hostname)");
			}
			return (may_be_crap);
		}
		(void) memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
		cp = inet_ntoa(sin.sin_addr);
	}

	if (nvlist_add_string(nvl, (char *)hostname, cp) != 0) {
		print_status(500, "(error adding hostname to nvlist)");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * one_name() is called for each certificate found and is passed the string
 * that X509_NAME_oneline() returns.  Its job is to find the common name and
 * determine whether it is a host name; if it is then a line suitable for
 * inclusion in /etc/inet/hosts is written to that file.
 */
static boolean_t
one_name(const char *namestr, nvlist_t *nvl)
{
	boolean_t	ret = B_TRUE;
	char		*p;
	char		*q;
	char		c;

	if (namestr != NULL &&
	    (p = strstr(namestr, WBCGI_CNSTR)) != NULL) {
		p += WBCGI_CNSTR_LEN;

		if ((q = strpbrk(p, WBCGI_NAMESEP)) != NULL) {
			c = *q;
			*q = '\0';
			ret = resolve_hostname(p, nvl, B_TRUE);
			*q = c;
		} else {
			ret = resolve_hostname(p, nvl, B_TRUE);
		}
	}

	return (ret);
}

/*
 * Loop through the certificates in a file
 */
static int
get_hostnames(const char *path, void *nvl)
{
	int		ret = WBCGI_FTW_CBERR;
	STACK_OF(X509)	*certs = NULL;
	PKCS12		*p12 = NULL;
	char		message[WBCGI_MAXBUF];
	char		buf[WBCGI_MAXBUF + 1];
	FILE		*rfp = NULL;
	X509		*x = NULL;
	int		errtype = 0;
	int		chars;
	int		i;

	if ((rfp = fopen(path, "r")) == NULL) {
		goto cleanup;
	}

	if ((p12 = d2i_PKCS12_fp(rfp, NULL)) == NULL) {
		errtype = 1;
		goto cleanup;
	}
	i = sunw_PKCS12_parse(p12, WANBOOT_PASSPHRASE, DO_NONE, NULL, 0, NULL,
	    NULL, NULL, &certs);
	if (i <= 0) {
		errtype = 1;
		goto cleanup;
	}

	PKCS12_free(p12);
	p12 = NULL;

	for (i = 0; i < sk_X509_num(certs); i++) {
		/* LINTED */
		x = sk_X509_value(certs, i);
		if (!one_name(sunw_issuer_attrs(x, buf, sizeof (buf) - 1),
		    nvl)) {
			goto cleanup;
		}
	}

	ret = WBCGI_FTW_CBCONT;
cleanup:
	if (ret == WBCGI_FTW_CBERR) {
		if (errtype == 1) {
			chars = snprintf(message, sizeof (message),
			    "(internal PKCS12 error reading %s)", path);
		} else {
			chars = snprintf(message, sizeof (message),
			    "error reading %s", path);
		}
		if (chars > 0 && chars <= sizeof (message)) {
			print_status(500, message);
		} else {
			print_status(500, NULL);
		}
	}
	if (rfp != NULL) {
		(void) fclose(rfp);
	}
	if (p12 != NULL) {
		PKCS12_free(p12);
	}
	if (certs != NULL) {
		sk_X509_pop_free(certs, X509_free);
	}

	return (ret);
}

/*
 * Create a hosts file by extracting hosts from client and truststore
 * files.  Use the CN. Then we should copy that file to the inet dir.
 */
static boolean_t
create_hostsfile(const char *hostsfile, const char *net, const char *cid)
{
	boolean_t	ret = B_FALSE;
	nvlist_t	*nvl;
	nvpair_t	*nvp;
	FILE		*hostfp = NULL;
	int		hostfd = -1;
	int		i;
	char		*hostslist;
	const char	*bc_urls[] = { BC_ROOT_SERVER, BC_BOOT_LOGGER, NULL };

	/*
	 * Allocate nvlist handle to store our hostname/IP pairs.
	 */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		print_status(500, "(error allocating hostname nvlist)");
		goto cleanup;
	}

	/*
	 * Extract and resolve hostnames from CNs.
	 */
	if (netboot_ftw(NB_CLIENT_CERT, net, cid,
	    get_hostnames, nvl) == WBCGI_FTW_CBERR ||
	    netboot_ftw(NB_CA_CERT, net, cid,
	    get_hostnames, nvl) == WBCGI_FTW_CBERR) {
		goto cleanup;
	}

	/*
	 * Extract and resolve hostnames from any URLs in bootconf.
	 */
	for (i = 0; bc_urls[i] != NULL; ++i) {
		char	*urlstr;
		url_t	url;

		if ((urlstr = bootconf_get(&bc_handle, bc_urls[i])) != NULL &&
		    url_parse(urlstr, &url) == URL_PARSE_SUCCESS) {
			if (!resolve_hostname(url.hport.hostname,
			    nvl, B_FALSE)) {
				goto cleanup;
			}
		}
	}

	/*
	 * If there is a resolve-hosts list in bootconf, resolve those
	 * hostnames too.
	 */
	if ((hostslist = bootconf_get(&bc_handle, BC_RESOLVE_HOSTS)) != NULL) {
		char	*hostname;

		for (hostname = strtok(hostslist, ","); hostname != NULL;
		    hostname = strtok(NULL, ",")) {
			if (!resolve_hostname(hostname, nvl, B_FALSE)) {
				goto cleanup;
			}
		}
	}

	/*
	 * Now write the hostname/IP pairs gathered to the hosts file.
	 */
	if ((hostfd = open(hostsfile,
	    O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) == -1 ||
	    (hostfp = fdopen(hostfd, "w+")) == NULL) {
		print_status(500, "(error creating hosts file)");
		goto cleanup;
	}
	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		char	*hostname;
		char	*ipstr;

		hostname = nvpair_name(nvp);
		if (nvpair_value_string(nvp, &ipstr) != 0) {
			print_status(500, "(nvl error writing hosts file)");
			goto cleanup;
		}

		if (fprintf(hostfp, "%s\t%s\n", ipstr, hostname) < 0) {
			print_status(500, "(error writing hosts file)");
			goto cleanup;
		}
	}

	ret = B_TRUE;
cleanup:
	if (nvl != NULL) {
		nvlist_free(nvl);
	}
	if (hostfp != NULL) {
		/*
		 * hostfd is automatically closed as well.
		 */
		(void) fclose(hostfp);
	}

	return (ret);
}

static boolean_t
bootfile_payload(const char *docroot, char **bootpathp)
{
	boolean_t	ret = B_FALSE;
	char		*boot_file;
	struct stat	sbuf;

	if ((boot_file = bootconf_get(&bc_handle, BC_BOOT_FILE)) == NULL) {
		print_status(500, "(boot_file must be specified)");
		goto cleanup;
	}
	if ((*bootpathp = make_path(docroot, boot_file)) == NULL) {
		goto cleanup;
	}
	if (!WBCGI_FILE_EXISTS(*bootpathp, sbuf)) {
		print_status(500, "(boot_file missing)");
		goto cleanup;
	}

	ret = B_TRUE;
cleanup:
	return (ret);
}

/*
 * Create the wanboot file system whose contents are determined by the
 * security configuration specified in bootconf.
 */
static boolean_t
wanbootfs_payload(const char *net, const char *cid, const char *nonce,
    const char *bootconf, char **wanbootfs_imagep)
{
	int		ret = B_FALSE;

	char		*server_authentication;
	char		*client_authentication;
	char		*scf;

	char		*bootfs_dir = NULL;
	char		*bootfs_etc_dir = NULL;
	char		*bootfs_etc_inet_dir = NULL;
	char		*bootfs_dev_dir = NULL;

	char		*systemconf = NULL;
	char		*keystorepath = NULL;
	char		*certstorepath = NULL;
	char		*truststorepath = NULL;
	char		*bootconfpath = NULL;
	char		*systemconfpath = NULL;
	char		*urandompath = NULL;
	char		*noncepath = NULL;
	char		*hostspath = NULL;
	char		*etc_hostspath = NULL;
	char		*timestamppath = NULL;

	boolean_t	authenticate_client;
	boolean_t	authenticate_server;

	struct stat	sbuf;

	/*
	 * Initialize SSL stuff.
	 */
	sunw_crypto_init();

	/*
	 * Get the security strategy values.
	 */
	client_authentication = bootconf_get(&bc_handle,
	    BC_CLIENT_AUTHENTICATION);
	authenticate_client = (client_authentication != NULL &&
	    strcmp(client_authentication, "yes") == 0);
	server_authentication = bootconf_get(&bc_handle,
	    BC_SERVER_AUTHENTICATION);
	authenticate_server = (server_authentication != NULL &&
	    strcmp(server_authentication, "yes") == 0);

	/*
	 * Make a temporary directory structure for the wanboot file system.
	 */
	if ((bootfs_dir = gen_tmppath("bootfs_dir", net, cid)) == NULL ||
	    (bootfs_etc_dir = make_path(bootfs_dir, "etc")) == NULL ||
	    (bootfs_etc_inet_dir = make_path(bootfs_etc_dir, "inet")) == NULL ||
	    (bootfs_dev_dir = make_path(bootfs_dir, "dev")) == NULL) {
		goto cleanup;
	}
	if (mkdirp(bootfs_dir, 0700) ||
	    mkdirp(bootfs_etc_dir, 0700) ||
	    mkdirp(bootfs_etc_inet_dir, 0700) ||
	    mkdirp(bootfs_dev_dir, 0700)) {
		print_status(500, "(error creating wanbootfs dir structure)");
		goto cleanup;
	}

	if (authenticate_client) {
		/*
		 * Add the client private key.
		 */
		if ((keystorepath = make_path(bootfs_dir,
		    NB_CLIENT_KEY)) == NULL ||
		    netboot_ftw(NB_CLIENT_KEY, net, cid,
		    create_keystore, keystorepath) != WBCGI_FTW_CBOK) {
			goto cleanup;
		}

		/*
		 * Add the client certificate.
		 */
		if ((certstorepath = make_path(bootfs_dir,
		    NB_CLIENT_CERT)) == NULL ||
		    netboot_ftw(NB_CLIENT_CERT, net, cid,
		    copy_certstore, certstorepath) != WBCGI_FTW_CBOK) {
			goto cleanup;
		}
	}

	if (authenticate_client || authenticate_server) {
		/*
		 * Add the trustfile; at least one truststore must exist.
		 */
		if ((truststorepath = make_path(bootfs_dir,
		    NB_CA_CERT)) == NULL) {
			goto cleanup;
		}
		if (netboot_ftw(NB_CA_CERT, net, cid,
		    noact_cb, NULL) != WBCGI_FTW_CBOK) {
			print_status(500, "(truststore not found)");
		}
		if (netboot_ftw(NB_CA_CERT, net, cid,
		    build_trustfile, truststorepath) == WBCGI_FTW_CBERR) {
			goto cleanup;
		}

		/*
		 * Create the /dev/urandom file.
		 */
		if ((urandompath = make_path(bootfs_dev_dir,
		    "urandom")) == NULL ||
		    !create_urandom(urandompath)) {
			goto cleanup;
		}
	}

	/*
	 * Add the wanboot.conf(4) file.
	 */
	if ((bootconfpath = make_path(bootfs_dir, NB_WANBOOT_CONF)) == NULL ||
	    !copy_file(bootconf, bootconfpath)) {
		goto cleanup;
	}

	/*
	 * Add the system_conf file if present.
	 */
	if ((scf = bootconf_get(&bc_handle, BC_SYSTEM_CONF)) != NULL) {
		if (netboot_ftw(scf, net, cid,
		    set_pathname, &systemconf) != WBCGI_FTW_CBOK) {
			print_status(500, "(system_conf file not found)");
			goto cleanup;
		}
		if ((systemconfpath = make_path(bootfs_dir,
		    NB_SYSTEM_CONF)) == NULL ||
		    !copy_file(systemconf, systemconfpath)) {
			goto cleanup;
		}
	}

	/*
	 * Create the /nonce file.
	 */
	if ((noncepath = make_path(bootfs_dir, "nonce")) == NULL ||
	    !create_nonce(noncepath, nonce)) {
		goto cleanup;
	}

	/*
	 * Create an /etc/inet/hosts file by extracting hostnames from CN,
	 * URLs in bootconf and resolve-hosts in bootconf.
	 */
	if ((hostspath = make_path(bootfs_etc_inet_dir, "hosts")) == NULL ||
	    !create_hostsfile(hostspath, net, cid)) {
		goto cleanup;
	}

	/*
	 * We would like to create a symbolic link etc/hosts -> etc/inet/hosts,
	 * but unfortunately the HSFS support in the standalone doesn't handle
	 * symlinks.
	 */
	if ((etc_hostspath = make_path(bootfs_etc_dir, "hosts")) == NULL ||
	    !copy_file(hostspath, etc_hostspath)) {
		goto cleanup;
	}

	/*
	 * Create the /timestamp file.
	 */
	if ((timestamppath = make_path(bootfs_dir, "timestamp")) == NULL ||
	    !create_timestamp(timestamppath, "timestamp")) {
		goto cleanup;
	}

	/*
	 * Create an HSFS file system for the directory.
	 */
	if ((*wanbootfs_imagep = gen_tmppath("wanbootfs", net, cid)) == NULL ||
	    !mkisofs(bootfs_dir, *wanbootfs_imagep)) {
		goto cleanup;
	}

	ret = B_TRUE;
cleanup:
	/*
	 * Clean up temporary files and directories.
	 */
	if (keystorepath != NULL &&
	    WBCGI_FILE_EXISTS(keystorepath, sbuf)) {
		(void) unlink(keystorepath);
	}
	if (certstorepath != NULL &&
	    WBCGI_FILE_EXISTS(certstorepath, sbuf)) {
		(void) unlink(certstorepath);
	}
	if (truststorepath != NULL &&
	    WBCGI_FILE_EXISTS(truststorepath, sbuf)) {
		(void) unlink(truststorepath);
	}
	if (bootconfpath != NULL &&
	    WBCGI_FILE_EXISTS(bootconfpath, sbuf)) {
		(void) unlink(bootconfpath);
	}
	if (systemconfpath != NULL &&
	    WBCGI_FILE_EXISTS(systemconfpath, sbuf)) {
		(void) unlink(systemconfpath);
	}
	if (urandompath != NULL &&
	    WBCGI_FILE_EXISTS(urandompath, sbuf)) {
		(void) unlink(urandompath);
	}
	if (noncepath != NULL &&
	    WBCGI_FILE_EXISTS(noncepath, sbuf)) {
		(void) unlink(noncepath);
	}
	if (hostspath != NULL &&
	    WBCGI_FILE_EXISTS(hostspath, sbuf)) {
		(void) unlink(hostspath);
	}
	if (etc_hostspath != NULL &&
	    WBCGI_FILE_EXISTS(etc_hostspath, sbuf)) {
		(void) unlink(etc_hostspath);
	}
	if (timestamppath != NULL &&
	    WBCGI_FILE_EXISTS(timestamppath, sbuf)) {
		(void) unlink(timestamppath);
	}

	if (bootfs_etc_inet_dir != NULL &&
	    WBCGI_DIR_EXISTS(bootfs_etc_inet_dir, sbuf)) {
		(void) rmdir(bootfs_etc_inet_dir);
	}
	if (bootfs_etc_dir != NULL &&
	    WBCGI_DIR_EXISTS(bootfs_etc_dir, sbuf)) {
		(void) rmdir(bootfs_etc_dir);
	}
	if (bootfs_dev_dir != NULL &&
	    WBCGI_DIR_EXISTS(bootfs_dev_dir, sbuf)) {
		(void) rmdir(bootfs_dev_dir);
	}
	if (bootfs_dir != NULL &&
	    WBCGI_DIR_EXISTS(bootfs_dir, sbuf)) {
		(void) rmdir(bootfs_dir);
	}

	/*
	 * Free allocated memory.
	 */
	free_path(&bootfs_dir);
	free_path(&bootfs_etc_dir);
	free_path(&bootfs_etc_inet_dir);
	free_path(&bootfs_dev_dir);

	free_path(&systemconf);
	free_path(&keystorepath);
	free_path(&certstorepath);
	free_path(&truststorepath);
	free_path(&bootconfpath);
	free_path(&systemconfpath);
	free_path(&urandompath);
	free_path(&noncepath);
	free_path(&hostspath);
	free_path(&etc_hostspath);
	free_path(&timestamppath);

	return (ret);
}

static boolean_t
miniroot_payload(const char *net, const char *cid, const char *docroot,
    char **rootpathp, char **rootinfop, boolean_t *https_rootserverp)
{
	boolean_t	ret = B_FALSE;
	char		*root_server;
	char		*root_file;
	url_t		url;
	struct stat	sbuf;
	char		sizebuf[WBCGI_MAXBUF];
	int		chars;
	int		fd = -1;

	if ((root_server = bootconf_get(&bc_handle, BC_ROOT_SERVER)) == NULL) {
		print_status(500, "(root_server must be specified)");
		goto cleanup;
	}
	if (url_parse(root_server, &url) != URL_PARSE_SUCCESS) {
		print_status(500, "(root_server URL is invalid)");
	}
	*https_rootserverp = url.https;

	if ((root_file = bootconf_get(&bc_handle, BC_ROOT_FILE)) == NULL) {
		print_status(500, "(rootfile must be specified)");
		goto cleanup;
	}
	if ((*rootpathp = make_path(docroot, root_file)) == NULL) {
		goto cleanup;
	}
	if (!WBCGI_FILE_EXISTS(*rootpathp, sbuf)) {
		print_status(500, "(root filesystem image missing)");
		goto cleanup;
	}

	if ((*rootinfop = gen_tmppath("mrinfo", net, cid)) == NULL) {
		goto cleanup;
	}
	if ((chars = snprintf(sizebuf, sizeof (sizebuf), "%ld",
	    sbuf.st_size)) < 0 || chars > sizeof (sizebuf) ||
	    (fd = open(*rootinfop,
	    O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) == -1 ||
	    !write_buffer(fd, sizebuf, strlen(sizebuf))) {
		print_status(500, "(error creating miniroot info file)");
		goto cleanup;
	}

	ret = B_TRUE;
cleanup:
	if (fd != -1) {
		(void) close(fd);
	}

	return (ret);
}

static boolean_t
deliver_payload(const char *payload, const char *payload_hash)
{
	int		fd = fileno(stdout);
	struct stat	payload_buf, hash_buf;
	int		chars;
	char		main_header[WBCGI_MAXBUF];
	char		multi_header[WBCGI_MAXBUF];
	char		multi_header1[WBCGI_MAXBUF];
	char		multi_header2[WBCGI_MAXBUF];
	char		multi_end[WBCGI_MAXBUF];
	size_t		msglen;

	if (!WBCGI_FILE_EXISTS(payload, payload_buf) ||
	    !WBCGI_FILE_EXISTS(payload_hash, hash_buf)) {
		print_status(500, "(payload/hash file(s) missing)");
		return (B_FALSE);
	}

	/*
	 * Multi-part header.
	 */
	if ((chars = snprintf(multi_header, sizeof (multi_header),
	    "%s--%s%s%sapplication/octet-stream%s%s", WBCGI_CRNL,
	    WBCGI_WANBOOT_BNDTXT, WBCGI_CRNL, WBCGI_CONTENT_TYPE, WBCGI_CRNL,
	    WBCGI_CONTENT_LENGTH)) < 0 || chars > sizeof (multi_header)) {
		print_status(500, "(error creating multi_header)");
		return (B_FALSE);
	}

	/*
	 * Multi-part header for part one.
	 */
	if ((chars = snprintf(multi_header1, sizeof (multi_header1),
	    "%s%ld%s%s", multi_header, payload_buf.st_size, WBCGI_CRNL,
	    WBCGI_CRNL)) < 0 || chars > sizeof (multi_header1)) {
		print_status(500, "(error creating multi_header1)");
		return (B_FALSE);
	}

	/*
	 * Multi-part header for part two.
	 */
	if ((chars = snprintf(multi_header2, sizeof (multi_header2),
	    "%s%ld%s%s", multi_header, hash_buf.st_size, WBCGI_CRNL,
	    WBCGI_CRNL)) < 0 || chars > sizeof (multi_header2)) {
		print_status(500, "(error creating multi_header2)");
		return (B_FALSE);
	}

	/*
	 * End-of-parts Trailer.
	 */
	if ((chars = snprintf(multi_end, sizeof (multi_end),
	    "%s--%s--%s", WBCGI_CRNL, WBCGI_WANBOOT_BNDTXT,
	    WBCGI_CRNL)) < 0 || chars > sizeof (multi_end)) {
		print_status(500, "(error creating multi_end)");
		return (B_FALSE);
	}

	/*
	 * Message header.
	 */
	msglen = payload_buf.st_size +  hash_buf.st_size +
	    strlen(multi_header1) + strlen(multi_header2) + strlen(multi_end);

	if ((chars = snprintf(main_header, sizeof (main_header),
	    "%s%u%s%smultipart/mixed; boundary=%s%s%s", WBCGI_CONTENT_LENGTH,
	    msglen, WBCGI_CRNL, WBCGI_CONTENT_TYPE, WBCGI_WANBOOT_BNDTXT,
	    WBCGI_CRNL, WBCGI_CRNL)) < 0 || chars > sizeof (main_header)) {
		print_status(500, "(error creating main_header)");
		return (B_FALSE);
	}

	/*
	 * Write the message out.  If things fall apart during this then
	 * there's no way to report the error back to the client.
	 */
	if (!write_buffer(fd, main_header, strlen(main_header)) ||
	    !write_buffer(fd, multi_header1, strlen(multi_header1)) ||
	    !write_file(fd, payload, payload_buf.st_size) ||
	    !write_buffer(fd, multi_header2, strlen(multi_header2)) ||
	    !write_file(fd, payload_hash, hash_buf.st_size) ||
	    !write_buffer(fileno(stdout), multi_end, strlen(multi_end))) {
		return (B_FALSE);
	}

	return (B_TRUE);
}


/*ARGSUSED*/
int
main(int argc, char **argv)
{
	int		ret = WBCGI_STATUS_ERR;
	struct stat	sbuf;
	int		content;
	char		*net;
	char		*cid;
	char		*nonce;
	char		*docroot;
	char		*payload;
	char		*signature_type;
	char		*encryption_type;
	char		*bootconf = NULL;
	char		*keyfile = NULL;
	char		*bootpath = NULL;
	char		*wanbootfs_image = NULL;
	char		*rootpath = NULL;
	char		*miniroot_info = NULL;
	char		*encr_payload = NULL;
	char		*payload_hash = NULL;
	boolean_t	https_rootserver;

	/*
	 * Process the query string.
	 */
	if (!get_request_info(&content, &net, &cid, &nonce, &docroot)) {
		goto cleanup;
	}

	/*
	 * Sanity check that the netboot directory exists.
	 */
	if (!WBCGI_DIR_EXISTS(NB_NETBOOT_ROOT, sbuf)) {
		print_status(500, "(" NB_NETBOOT_ROOT " does not exist)");
		goto cleanup;
	}

	/*
	 * Get absolute bootconf pathname.
	 */
	if (netboot_ftw(NB_WANBOOT_CONF, net, cid,
	    set_pathname, &bootconf) != WBCGI_FTW_CBOK) {
		print_status(500, "(wanboot.conf not found)");
		goto cleanup;
	}

	/*
	 * Initialize bc_handle from the given wanboot.conf file.
	 */
	if (bootconf_init(&bc_handle, bootconf) != BC_SUCCESS) {
		char	message[WBCGI_MAXBUF];
		int	chars;

		chars = snprintf(message, sizeof (message),
		    "(wanboot.conf error: %s)", bootconf_errmsg(&bc_handle));
		if (chars > 0 && chars < sizeof (message))
			print_status(500, message);
		else
			print_status(500, "(wanboot.conf error)");
		goto cleanup;
	}

	/*
	 * Get and check signature and encryption types,
	 * presence of helper utilities, keystore, etc.
	 */
	if ((signature_type = bootconf_get(&bc_handle,
	    BC_SIGNATURE_TYPE)) != NULL) {
		if (!WBCGI_FILE_EXISTS(WBCGI_HMAC_PATH, sbuf)) {
			print_status(500, "(hmac utility not found)");
			goto cleanup;
		}
		if (keyfile == NULL && netboot_ftw(NB_CLIENT_KEY, net, cid,
		    set_pathname, &keyfile) != WBCGI_FTW_CBOK) {
			print_status(500, "(keystore not found)");
			goto cleanup;
		}
		if (!check_key_type(keyfile, signature_type, WBKU_HASH_KEY)) {
			print_status(500, "(hash key not found)");
			goto cleanup;
		}
	}
	if ((encryption_type = bootconf_get(&bc_handle,
	    BC_ENCRYPTION_TYPE)) != NULL) {
		if (signature_type == NULL) {
			print_status(500, "(encrypted but not signed)");
			goto cleanup;
		}
		if (!WBCGI_FILE_EXISTS(WBCGI_ENCR_PATH, sbuf)) {
			print_status(500, "(encr utility not found)");
			goto cleanup;
		}
		if (keyfile == NULL && netboot_ftw(NB_CLIENT_KEY, net, cid,
		    set_pathname, &keyfile) != WBCGI_FTW_CBOK) {
			print_status(500, "(keystore not found)");
			goto cleanup;
		}
		if (!check_key_type(keyfile, encryption_type, WBKU_ENCR_KEY)) {
			print_status(500, "(encr key not found)");
			goto cleanup;
		}
	}

	/*
	 * Determine/create our payload.
	 */
	switch (content) {
	case WBCGI_CONTENT_BOOTFILE:
		if (!bootfile_payload(docroot, &bootpath)) {
			goto cleanup;
		}
		payload = bootpath;

		break;

	case WBCGI_CONTENT_BOOTFS:
		if (!wanbootfs_payload(net, cid, nonce,
		    bootconf, &wanbootfs_image)) {
			goto cleanup;
		}
		payload = wanbootfs_image;

		break;

	case WBCGI_CONTENT_ROOTFS:
		if (!miniroot_payload(net, cid, docroot,
		    &rootpath, &miniroot_info, &https_rootserver)) {
			goto cleanup;
		}
		payload = rootpath;

		break;
	}

	/*
	 * Encrypt the payload if necessary.
	 */
	if (content != WBCGI_CONTENT_BOOTFILE &&
	    content != WBCGI_CONTENT_ROOTFS &&
	    encryption_type != NULL) {
		if ((encr_payload = gen_tmppath("encr", net, cid)) == NULL) {
			goto cleanup;
		}

		if (!encrypt_payload(payload, encr_payload, keyfile,
		    encryption_type)) {
			goto cleanup;
		}

		payload = encr_payload;
	}

	/*
	 * Compute the hash (actual or null).
	 */
	if ((payload_hash = gen_tmppath("hash", net, cid)) == NULL) {
		goto cleanup;
	}

	if (signature_type != NULL &&
	    (content != WBCGI_CONTENT_ROOTFS || !https_rootserver)) {
		if (!hash_payload(payload, payload_hash, keyfile)) {
			goto cleanup;
		}
	} else {
		if (!create_null_hash(payload_hash)) {
			goto cleanup;
		}
	}

	/*
	 * For the rootfs the actual payload transmitted is the file
	 * containing the size of the rootfs (as a string of ascii digits);
	 * point payload at this instead.
	 */
	if (content == WBCGI_CONTENT_ROOTFS) {
		payload = miniroot_info;
	}

	/*
	 * Finally, deliver the payload and hash as a multipart message.
	 */
	if (!deliver_payload(payload, payload_hash)) {
		goto cleanup;
	}

	ret = WBCGI_STATUS_OK;
cleanup:
	/*
	 * Clean up temporary files.
	 */
	if (wanbootfs_image != NULL &&
	    WBCGI_FILE_EXISTS(wanbootfs_image, sbuf)) {
		(void) unlink(wanbootfs_image);
	}
	if (miniroot_info != NULL &&
	    WBCGI_FILE_EXISTS(miniroot_info, sbuf)) {
		(void) unlink(miniroot_info);
	}
	if (encr_payload != NULL &&
	    WBCGI_FILE_EXISTS(encr_payload, sbuf)) {
		(void) unlink(encr_payload);
	}
	if (payload_hash != NULL &&
	    WBCGI_FILE_EXISTS(payload_hash, sbuf)) {
		(void) unlink(payload_hash);
	}

	/*
	 * Free up any allocated strings.
	 */
	free_path(&bootconf);
	free_path(&keyfile);
	free_path(&bootpath);
	free_path(&wanbootfs_image);
	free_path(&rootpath);
	free_path(&miniroot_info);
	free_path(&encr_payload);
	free_path(&payload_hash);

	bootconf_end(&bc_handle);

	return (ret);
}
