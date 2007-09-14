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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * File: CLIENT.C
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <kmfapi.h>
#include <kmfapiP.h>
#include <libxml2/libxml/uri.h>

extern int errno;

#define	OCSP_BUFSIZE 1024

typedef enum {
	KMF_RESPONSE_OCSP = 1,
	KMF_RESPONSE_FILE = 2
} KMF_RESPONSE_TYPE;

#define	TEMP_TEMPLATE	"temp.XXXXXX"

/*
 * This function will establish a socket to the host on the specified port.
 * If succeed, it return a socket descriptor; otherwise, return -1.
 */
static int init_socket(char *host, short port)
{
	struct sockaddr_in sin;
	struct hostent *hp, hrec;
	int sockfd, opt, herrno;
	char hostbuf[BUFSIZ];

	sin.sin_family = PF_INET;
	sin.sin_port = htons(port);
	if ((sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE) {
		if ((hp = gethostbyname_r(host, &hrec, hostbuf,
		    sizeof (hostbuf), &herrno)) == NULL) {
			return (-1);
		}
		(void) memcpy((char *)&sin.sin_addr, hp->h_addr,
		    hp->h_length);
	}

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		return (-1);
	}

	opt = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
	    sizeof (opt)) < 0) {
		(void) close(sockfd);
		return (-1);
	}

	if (connect(sockfd, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		(void) close(sockfd);
		return (-1);
	}

	return (sockfd);
}

/*
 * This function will connect to host on the port.
 * If succeed, return a socket descriptor; otherwise, return 0.
 */
static int
connect_to_server(char *host, short port)
{
	int retry = 1;
	int sd = 0;

	while (retry) {
		if ((sd = init_socket(host, port)) == -1) {
			if (errno == ECONNREFUSED) {
				retry = 1;
				(void) sleep(1);
			} else {
				retry = 0;
			}
		} else	{
			retry = 0;
		}
	}
	return (sd);
}

static KMF_RETURN
send_ocsp_request(int sock, char *reqfile, char *hostname)
{
	KMF_RETURN ret = KMF_OK;
	int filefd, bytes, n, total = 0;
	char buf[OCSP_BUFSIZE];
	struct stat s;
	char req_header[256];
	static char req_format[] =
"POST %s HTTP/1.0\r\n\
Content-Type: application/ocsp-request\r\n\
Content-Length: %d\r\n\r\n";

	if ((filefd = open(reqfile, O_RDONLY)) == -1) {
		ret = KMF_ERR_OPEN_FILE;
		return (ret);
	}

	/* open the request file */
	if (fstat(filefd, &s) < 0) {
		ret = KMF_ERR_OPEN_FILE;
		return (ret);
	}


	/* Send http header */
	if (hostname != NULL) {
		(void) snprintf(req_header, 256, req_format, hostname,
		    s.st_size);
	} else {
		(void) snprintf(req_header, 256, req_format, "/", s.st_size);
	}
	bytes = strlen(req_header);

	if ((n = write(sock, req_header, bytes)) < 0) {
		ret = KMF_ERR_SEND_REQUEST;
		goto exit;
	}

	/* Send the request content */
	while ((bytes = read(filefd, buf, OCSP_BUFSIZE)) > 0) {
		if ((n = write(sock, buf, bytes)) < 0) {
			ret = KMF_ERR_SEND_REQUEST;
			goto exit;
		}
		total += n;
		(void) memset(buf, 0, sizeof (buf));
	}

exit:
	(void) close(filefd);
	return (ret);
}


/*
 * Perform a write that can handle EINTR.
 */
static int
looping_write(int fd, void *buf, int len)
{
	char *p = buf;
	int cc, len2 = 0;

	if (len == 0)
		return (0);
	do {
		cc = write(fd, p, len);
		if (cc < 0) {
			if (errno == EINTR)
				continue;
			return (cc);
		} else if (cc == 0) {
			return (len2);
		} else {
			p += cc;
			len2 += cc;
			len -= cc;
		}
	} while (len > 0);

	return (len2);
}

/*
 * This function will get the response from the server, check the http status
 * line, and write the response content to a file.  If this is a OCSP response,
 * it will check the content type also.
 */
static KMF_RETURN
get_encoded_response(int sock, KMF_RESPONSE_TYPE resptype, int filefd,
    unsigned int maxsecs)
{
	int ret = KMF_OK;
	char *buf = NULL;
	int buflen = 0;
	int offset = 0;
	int search_offset;
	const int buf_incre = OCSP_BUFSIZE; /* 1 KB at a time */
	const int maxBufSize = 8 * buf_incre; /* 8 KB max */
	const char *CRLF = "\r\n";
	const char *headerEndMark = "\r\n\r\n";
	const char *httpprotocol = "HTTP/";
	const int CRLFlen = strlen(CRLF);
	const int marklen = strlen(headerEndMark);
	const int httplen = strlen(httpprotocol);
	char *headerEnd = NULL;
	boolean_t EOS = B_FALSE;
	const char *httpcode = NULL;
	const char *contenttype = NULL;
	int contentlength = 0;
	int bytes = 0;
	char *statusLineEnd = NULL;
	char *space = NULL;
	char *nextHeader = NULL;
	struct pollfd pfd;
	int sock_flag;
	int poll_ret;
	boolean_t timeout = B_FALSE;

	/* set O_NONBLOCK flag on socket */
	if ((sock_flag = fcntl(sock, F_GETFL, 0)) == -1) {
		return (KMF_ERR_RECV_RESPONSE);
	}
	sock_flag |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, sock_flag) == -1) {
		return (KMF_ERR_RECV_RESPONSE);
	}

	/* set up poll */
	pfd.fd = sock;
	pfd.events = POLLIN;

	/*
	 * First read HTTP status line and headers.  We will read up to at
	 * least the end of the HTTP headers
	 */
	do {
		if ((buflen - offset) < buf_incre) {
			buflen += buf_incre;
			buf = realloc(buf, buflen + 1);
			if (buf == NULL) {
				ret = KMF_ERR_MEMORY;
				goto out;
			}
		}

		pfd.revents = 0;
		poll_ret = poll(&pfd, 1, maxsecs * MILLISEC);
		if (poll_ret == 0) {
			timeout = B_TRUE;
			break;
		} else if (poll_ret < 0) {
			ret = KMF_ERR_RECV_RESPONSE;
			goto out;
		} else {
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				ret = KMF_ERR_RECV_RESPONSE;
				goto out;
			}
		}

		bytes = read(sock, buf + offset,  buf_incre);
		if (bytes < 0) {
			if (errno == EWOULDBLOCK) { /* no data this time */
				continue;
			} else {
				ret = KMF_ERR_RECV_RESPONSE;
				goto out;
			}
		} else if (bytes == 0) { /* no more data */
			EOS = B_TRUE;
		} else { /* bytes > 0 */
			search_offset = (offset - marklen) > 0 ?
			    offset - marklen : 0;
			offset += bytes;
			*(buf + offset) = '\0'; /* NULL termination */

			headerEnd = strstr((const char *)buf + search_offset,
			    headerEndMark);
		}

	} while ((!headerEnd) && (EOS == B_FALSE) && (buflen < maxBufSize));

	if (timeout == B_TRUE) {
		ret = KMF_ERR_RECV_TIMEOUT;
		goto out;
	} else if (headerEnd == NULL) {
		/* could not find the end of headers */
		ret = KMF_ERR_BAD_HTTP_RESPONSE;
		goto out;
	}

	/*
	 * Parse the HTTP status line, which will look like this:
	 * "HTTP/1.1 200 OK".
	 */
	statusLineEnd = strstr((const char *)buf, CRLF);
	if (statusLineEnd == NULL) {
		ret = KMF_ERR_BAD_HTTP_RESPONSE;
		goto out;
	}
	*statusLineEnd = '\0';

	space = strchr((const char *)buf, ' ');
	if (space == NULL ||
	    (strncasecmp((const char *)buf, httpprotocol, httplen) != 0)) {
		ret = KMF_ERR_BAD_HTTP_RESPONSE;
		goto out;
	}

	/*
	 * Check the HTTP status code. If it is not 200, the HTTP response
	 * is not good.
	 */
	httpcode = space + 1;
	space = strchr(httpcode, ' ');
	if (space == NULL) {
		ret = KMF_ERR_BAD_HTTP_RESPONSE;
		goto out;
	}

	*space = 0;
	if (strcmp(httpcode, "200") != 0) {
		ret = KMF_ERR_BAD_HTTP_RESPONSE;
		goto out;
	}

	/*
	 * Parse the HTTP headers in the buffer.  Save content-type and
	 * content-length only.
	 */
	nextHeader = statusLineEnd + CRLFlen;
	*headerEnd = '\0'; /* terminate */
	do {
		char *thisHeaderEnd = NULL;
		char *value = NULL;
		char *colon = strchr(nextHeader, ':');

		if (colon == NULL) {
			ret = KMF_ERR_BAD_HTTP_RESPONSE;
			goto out;
		}
		*colon = '\0';

		value = colon + 1;
		if (*value != ' ') {
			ret = KMF_ERR_BAD_HTTP_RESPONSE;
			goto out;
		}
		value++;

		thisHeaderEnd  = strstr(value, CRLF);
		if (thisHeaderEnd != NULL)
			*thisHeaderEnd  = '\0';

		if (strcasecmp(nextHeader, "content-type") == 0) {
			contenttype = value;
		} else if (strcasecmp(nextHeader, "content-length") == 0) {
			contentlength = atoi(value);
		}

		if (thisHeaderEnd != NULL) {
			nextHeader = thisHeaderEnd + CRLFlen;
		} else {
			nextHeader = NULL;
		}

	} while (nextHeader && (nextHeader < (headerEnd + CRLFlen)));

	/* Check the contenttype if this is an OCSP response */
	if (resptype == KMF_RESPONSE_OCSP) {
		if (contenttype == NULL) {
			ret = KMF_ERR_BAD_HTTP_RESPONSE;
			goto out;
		} else if (strcasecmp(contenttype,
		    "application/ocsp-response") != 0) {
			ret = KMF_ERR_BAD_HTTP_RESPONSE;
			goto out;
		}
	}

	/* Now we are ready to read the body of the response */
	offset = offset - (int)(headerEnd - (const char *)buf) - marklen;
	if (offset) {
		/* move all data to the beginning of the buffer */
		(void) memmove(buf, headerEnd + marklen, offset);
	}

	/* resize buffer to only what's needed to hold the current response */
	buflen = (1 + (offset-1) / buf_incre) * buf_incre;

	while ((EOS == B_FALSE) &&
	    ((contentlength == 0) || (offset < contentlength)) &&
	    (buflen < maxBufSize)) {
		/* we still need to receive more content data */
		if ((buflen - offset) < buf_incre) {
			buflen += buf_incre;
			buf = realloc(buf, buflen + 1);
			if (buf == NULL) {
				ret = KMF_ERR_MEMORY;
				goto out;
			}
		}

		pfd.revents = 0;
		poll_ret = poll(&pfd, 1, maxsecs * MILLISEC);
		if (poll_ret == 0) {
			timeout = B_TRUE;
			break;
		} else if (poll_ret < 0) {
			ret = KMF_ERR_RECV_RESPONSE;
			goto out;
		} else {
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				ret = KMF_ERR_RECV_RESPONSE;
				goto out;
			}
		}

		bytes = read(sock, buf + offset,  buf_incre);
		if (bytes < 0) {
			if (errno == EWOULDBLOCK) {
				continue;
			} else {
				ret = KMF_ERR_RECV_RESPONSE;
				goto out;
			}
		} else if (bytes == 0) { /* no more data */
			EOS = B_TRUE;
		} else {
			offset += bytes;
		}
	}

	if (timeout == B_TRUE) {
		ret = KMF_ERR_RECV_TIMEOUT;
		goto out;
	} else if (((contentlength != 0) && (offset < contentlength)) ||
	    offset == 0) {
		ret = KMF_ERR_BAD_HTTP_RESPONSE;
		goto out;
	}

	/* write to the file */
	if (looping_write(filefd, buf, offset) != offset) {
		ret = KMF_ERR_WRITE_FILE;
	}

out:
	free(buf);
	return (ret);
}

KMF_RETURN
kmf_get_encoded_ocsp_response(KMF_HANDLE_T handle,
    char *reqfile, char *hostname,
    int port, char *proxy, int proxy_port, char *respfile,
    unsigned int maxsecs)
{
	KMF_RETURN ret = KMF_OK;
	int sock, respfd;
	char http_hostname[256];
	int final_proxy_port, final_port;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (hostname == NULL || reqfile == NULL || respfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	final_proxy_port = (proxy_port == 0 || proxy_port == -1) ?
	    80 : proxy_port;
	final_port = (port == 0 || port == -1) ? 80 : port;

	/* Connect to server */
	if (proxy != NULL) {
		sock = connect_to_server(proxy, final_proxy_port);
	} else {
		sock = connect_to_server(hostname, final_port);
	}

	if (sock == -1) {
		return (KMF_ERR_CONNECT_SERVER);
	}

	/* Send the OCSP request */
	if (proxy != NULL) {
		(void) snprintf(http_hostname, sizeof (http_hostname),
		    "http://%s:%d", hostname, final_port);
		ret = send_ocsp_request(sock, reqfile, http_hostname);
	} else {
		ret = send_ocsp_request(sock, reqfile, NULL);
	}

	if (ret != KMF_OK) {
		goto out;
	}

	/* Retrieve the OCSP response */
	if (maxsecs == 0) {
		maxsecs = 30; /* default poll time limit is 30 seconds */
	}

	if ((respfd = open(respfile, O_CREAT |O_RDWR | O_EXCL, 0600)) == -1) {
		ret = KMF_ERR_OPEN_FILE;
	} else {
		ret = get_encoded_response(sock, KMF_RESPONSE_OCSP,
		    respfd, maxsecs);
		(void) close(respfd);
	}

out:
	(void) close(sock);
	return (ret);
}

static KMF_RETURN
send_download_request(int sock, char *hostname, int port, boolean_t is_proxy,
    char *loc)
{
	KMF_RETURN ret = KMF_OK;
	char url[256];
	char req_header[1024];
	static char req_format[] =
"GET %s HTTP/1.0\r\n\
Host: %s:%d\r\n\
Accept: */*\r\n\r\n";

	if (is_proxy) {
		(void) snprintf(url, sizeof (url), "http://%s:%d/%s",
		    hostname, port, loc);
	} else {
		(void) snprintf(url, sizeof (url), "/%s", loc);
	}

	(void) snprintf(req_header, sizeof (req_header), req_format, url,
	    hostname, port);

	if (write(sock, req_header, strlen(req_header)) < 0) {
		ret = KMF_ERR_SEND_REQUEST;
	}

	return (ret);
}

static KMF_RETURN
download_file(char *uri, char *proxy, int proxy_port,
    unsigned int maxsecs, int filefd)
{
	KMF_RETURN ret = KMF_OK;
	xmlURIPtr   uriptr;
	int sock;
	boolean_t is_proxy;
	int final_proxy_port;
	char *hostname = NULL;
	char *path = NULL;
	int port;

	if (uri == NULL || filefd == -1)
		return (KMF_ERR_BAD_PARAMETER);

	/* Parse URI */
	uriptr = xmlParseURI(uri);
	if (uriptr == NULL) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}

	if (uriptr->scheme == NULL ||
	    strncasecmp(uriptr->scheme, "http", 4) != 0) {
		ret = KMF_ERR_BAD_URI;  /* we support http only */
		goto out;
	}

	/* get the host name */
	hostname = uriptr->server;
	if (hostname == NULL) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}

	/* get the port number */
	port = uriptr->port;
	if (port == 0) {
		port = 80;
	}

	/* Get the path */
	path = uriptr->path;
	if (path == NULL) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}

	/* Connect to server */
	if (proxy != NULL) {
		final_proxy_port = (proxy_port == 0 || proxy_port == -1) ?
		    80 : proxy_port;
		is_proxy = B_TRUE;
		sock = connect_to_server(proxy, final_proxy_port);
	} else {
		is_proxy = B_FALSE;
		sock = connect_to_server(hostname, port);
	}
	if (sock == -1) {
		ret = KMF_ERR_CONNECT_SERVER;
		goto out;
	}

	/* Send the request */
	ret = send_download_request(sock, hostname, port, is_proxy, path);
	if (ret != KMF_OK) {
		goto out;
	}

	/* Retrieve the response */
	ret = get_encoded_response(sock, KMF_RESPONSE_FILE, filefd,
	    maxsecs == 0 ? 30 : maxsecs);
	if (ret != KMF_OK) {
		goto out;
	}

out:
	if (uriptr != NULL)
		xmlFreeURI(uriptr);

	if (sock != -1)
		(void) close(sock);

	return (ret);
}


KMF_RETURN
kmf_download_crl(KMF_HANDLE_T handle, char *uri, char *proxy, int proxy_port,
    unsigned int maxsecs, char *crlfile, KMF_ENCODE_FORMAT *pformat)
{
	KMF_RETURN ret = KMF_OK;
	char *filename = NULL;
	char tempfn[MAXPATHLEN];
	boolean_t temp_created = B_FALSE;
	mode_t old_mode;
	int fd = -1, tmpfd = -1;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (uri == NULL || crlfile == NULL || pformat == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if ((fd = open(crlfile, O_CREAT |O_RDWR | O_EXCL, 0644)) == -1)
		return (KMF_ERR_OPEN_FILE);

	/*
	 * Download the file and save it to a temp file. To make rename()
	 * happy, the temp file needs to be created in the same directory as
	 * the target file.
	 */
	if ((filename = strdup(crlfile)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}
	(void) snprintf(tempfn, MAXPATHLEN, "%s/%s", dirname(filename),
	    TEMP_TEMPLATE);
	old_mode = umask(077);
	tmpfd = mkstemp(tempfn);
	(void) umask(old_mode);
	if (tmpfd == -1) {
		ret = KMF_ERR_INTERNAL;
		goto out;
	} else {
		temp_created = B_TRUE;
	}

	ret = download_file(uri, proxy, proxy_port, maxsecs, tmpfd);
	(void) close(tmpfd);
	if (ret != KMF_OK) {
		goto out;
	}

	/* Check if it is a CRL file and get its format */
	if (kmf_is_crl_file(handle, tempfn, pformat) != KMF_OK) {
		ret = KMF_ERR_BAD_CRLFILE;
		goto out;
	}

	/* Finally, change the temp filename to the target crlfile */
	if (rename(tempfn, crlfile) == -1) {
		ret = KMF_ERR_WRITE_FILE;
		goto out;
	}

out:
	if (filename != NULL)
		free(filename);

	if (ret != KMF_OK && temp_created == B_TRUE)
		(void) unlink(tempfn);

	if (fd != -1)
		(void) close(fd);

	return (ret);
}


KMF_RETURN
kmf_download_cert(KMF_HANDLE_T handle, char *uri, char *proxy, int proxy_port,
    unsigned int maxsecs, char *certfile, KMF_ENCODE_FORMAT *pformat)
{
	KMF_RETURN ret = KMF_OK;
	char *filename = NULL;
	char tempfn[MAXPATHLEN];
	boolean_t temp_created = B_FALSE;
	mode_t old_mode;
	int fd = -1, tmpfd = -1;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (uri == NULL || certfile == NULL || pformat == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if ((fd = open(certfile, O_CREAT |O_RDWR | O_EXCL, 0644)) == -1)
		return (KMF_ERR_OPEN_FILE);

	/*
	 * Download the file and save it to a temp file. To make rename()
	 * happy, the temp file needs to be created in the same directory as
	 * the target file.
	 */
	if ((filename = strdup(certfile)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}
	(void) snprintf(tempfn, MAXPATHLEN, "%s/%s", dirname(filename),
	    TEMP_TEMPLATE);

	old_mode = umask(077);
	tmpfd = mkstemp(tempfn);
	(void) umask(old_mode);
	if (tmpfd == -1) {
		ret = KMF_ERR_INTERNAL;
		goto out;
	} else {
		temp_created = B_TRUE;
	}

	ret = download_file(uri, proxy, proxy_port, maxsecs, tmpfd);
	(void) close(tmpfd);
	if (ret != KMF_OK) {
		goto out;
	}

	/* Check if it is a Cert file and get its format */
	if (kmf_is_cert_file(handle, tempfn, pformat) != KMF_OK) {
		ret = KMF_ERR_BAD_CERTFILE;
		goto out;
	}

	/* Finally, change the temp filename to the target filename */
	if (rename(tempfn, certfile) == -1) {
		ret = KMF_ERR_WRITE_FILE;
		goto out;
	}

out:
	if (filename != NULL)
		free(filename);

	if (ret != KMF_OK && temp_created == B_TRUE)
		(void) unlink(tempfn);

	if (fd != -1)
		(void) close(fd);

	return (ret);
}

KMF_RETURN
kmf_get_ocsp_for_cert(KMF_HANDLE_T handle,
	KMF_DATA *user_cert,
	KMF_DATA *ta_cert,
	KMF_DATA *response)
{
	KMF_POLICY_RECORD *policy;
	KMF_RETURN ret = KMF_OK;
	char *hostname = NULL, *host_uri = NULL, *proxyname = NULL;
	char *proxy_port_s = NULL;
	int host_port = 0, proxy_port = 0;
	char ocsp_reqname[MAXPATHLEN];
	char ocsp_respname[MAXPATHLEN];
	KMF_X509EXT_AUTHINFOACCESS aia;
	int i;
	boolean_t found = B_FALSE;
	KMF_X509EXT_ACCESSDESC *access_info;
	xmlURIPtr   uriptr = NULL;
	KMF_ATTRIBUTE attrlist[10];
	int numattr = 0;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (user_cert == NULL || ta_cert == NULL || response == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;

	/* Create an OCSP request  */
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_ISSUER_CERT_DATA_ATTR, ta_cert,
	    sizeof (KMF_DATA));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_USER_CERT_DATA_ATTR, user_cert,
	    sizeof (KMF_DATA));
	numattr++;

	/*
	 * Create temporary files to hold the OCSP request & response data.
	 */
	(void) strlcpy(ocsp_reqname, OCSPREQ_TEMPNAME,
	    sizeof (ocsp_reqname));
	if (mkstemp(ocsp_reqname) == -1) {
		return (KMF_ERR_INTERNAL);
	}

	(void) strlcpy(ocsp_respname, OCSPRESP_TEMPNAME,
	    sizeof (ocsp_respname));
	if (mkstemp(ocsp_respname) == -1) {
		return (KMF_ERR_INTERNAL);
	}

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_OCSP_REQUEST_FILENAME_ATTR, ocsp_respname,
	    strlen(ocsp_respname));
	numattr++;

	ret = kmf_create_ocsp_request(handle, numattr, attrlist);
	if (ret != KMF_OK) {
		goto out;
	}

	if (policy->VAL_OCSP_BASIC.uri_from_cert == 0) {
		if (policy->VAL_OCSP_BASIC.responderURI == NULL) {
			ret = KMF_ERR_OCSP_POLICY;
			goto out;
		}
		host_uri = policy->VAL_OCSP_BASIC.responderURI;

	} else {
		/*
		 * Get the responder URI from certificate
		 * Authority Information Access
		 * thru OID_PKIX_AD_OCSP
		 */
		ret = kmf_get_cert_auth_info_access(user_cert, &aia);
		if (ret != KMF_OK) {
			goto out;
		}

		for (i = 0; i < aia.numberOfAccessDescription; i++) {
			access_info = &aia.AccessDesc[i];
			if (IsEqualOid(&access_info->AccessMethod,
			    (KMF_OID *)&KMFOID_PkixAdOcsp)) {
				host_uri =
				    (char *)access_info->AccessLocation.Data;
				found = B_TRUE;
				break;
			}
		}

		if (!found) {
			ret = KMF_ERR_OCSP_POLICY;
			goto out;
		}
	}

	/* Parse the URI string; get the hostname and port */
	uriptr = xmlParseURI(host_uri);
	if (uriptr == NULL) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}

	if (strncasecmp(uriptr->scheme, "http", 4) != 0) {
		ret = KMF_ERR_BAD_URI;  /* we support http only */
		goto out;
	}

	hostname = uriptr->server;
	if (hostname == NULL) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}

	host_port = uriptr->port;
	if (host_port == 0)
		host_port = 80;

	/* get the proxy info */
	if (policy->VAL_OCSP_BASIC.proxy != NULL) {
		char *last;
		proxyname =
		    strtok_r(policy->VAL_OCSP_BASIC.proxy, ":", &last);
		proxy_port_s = strtok_r(NULL, "\0", &last);
		if (proxy_port_s != NULL) {
			proxy_port = strtol(proxy_port_s, NULL, 0);
		} else {
			proxy_port = 8080; /* default */
		}
	}

	/*
	 * Send the request to an OCSP responder and receive an
	 * OCSP response.
	 */
	ret = kmf_get_encoded_ocsp_response(handle, ocsp_reqname,
	    hostname, host_port,  proxyname, proxy_port,
	    ocsp_respname, 30);
	if (ret != KMF_OK) {
		goto out;
	}

	ret = kmf_read_input_file(handle, ocsp_respname, response);

out:
	(void) unlink(ocsp_reqname);
	(void) unlink(ocsp_respname);

	if (uriptr != NULL)
		xmlFreeURI(uriptr);

	return (ret);
}
