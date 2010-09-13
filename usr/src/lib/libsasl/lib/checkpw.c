/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: checkpw.c,v 1.62 2003/03/19 18:25:27 rjs3 Exp $
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

/* checkpw stuff */

#include <stdio.h>
#include "sasl.h"
#include "saslutil.h"
#include "saslplug.h"
#include "saslint.h"

#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef USE_DOORS
#include <sys/mman.h>
#include <door.h>
#endif

#include <stdlib.h>

#ifndef WIN32
#include <strings.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/un.h>
#else
#include <string.h>
#endif

#include <sys/types.h>
#include <ctype.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif /* HAVE_PWD_H */
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif /* HAVE_SHADOW_H */

#if defined(HAVE_PWCHECK) || defined(HAVE_SASLAUTHD)
# include <errno.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/un.h>
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif

extern int errno;
#endif


/* we store the following secret to check plaintext passwords:
 *
 * <salt> \0 <secret>
 *
 * where <secret> = MD5(<salt>, "sasldb", <pass>)
 */
#ifdef _SUN_SDK_
static int _sasl_make_plain_secret(const sasl_utils_t *utils, const char *salt,
				const char *passwd, size_t passlen,
				sasl_secret_t **secret)
#else
static int _sasl_make_plain_secret(const char *salt, 
				   const char *passwd, size_t passlen,
				   sasl_secret_t **secret)
#endif /* _SUN_SDK_ */
{
    MD5_CTX ctx;
    unsigned sec_len = 16 + 1 + 16; /* salt + "\0" + hash */

#ifdef _SUN_SDK_
    *secret = (sasl_secret_t *)utils->malloc(sizeof(sasl_secret_t) +
					sec_len * sizeof(char));
#else
    *secret = (sasl_secret_t *) sasl_ALLOC(sizeof(sasl_secret_t) +
					   sec_len * sizeof(char));
#endif /* _SUN_SDK_ */
    if (*secret == NULL) {
	return SASL_NOMEM;
    }

    _sasl_MD5Init(&ctx);
    _sasl_MD5Update(&ctx, salt, 16);
    _sasl_MD5Update(&ctx, "sasldb", 6);
    _sasl_MD5Update(&ctx, passwd, passlen);
    memcpy((*secret)->data, salt, 16);
    (*secret)->data[16] = '\0';
    _sasl_MD5Final((*secret)->data + 17, &ctx);
    (*secret)->len = sec_len;
    
    return SASL_OK;
}

/* erase & dispose of a sasl_secret_t
 */
static int auxprop_verify_password(sasl_conn_t *conn,
				   const char *userstr,
				   const char *passwd,
				   const char *service __attribute__((unused)),
				   const char *user_realm __attribute__((unused)))
{
    int ret = SASL_FAIL;
    char *userid = NULL;
#ifndef _SUN_SDK_
    char *realm = NULL;
#endif /* !_SUN_SDK_ */
    int result = SASL_OK;
    sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       "*cmusaslsecretPLAIN",
				       NULL };
    struct propval auxprop_values[3];
    
    if (!conn || !userstr)
	return SASL_BADPARAM;

    /* We need to clear any previous results and re-canonify to 
     * ensure correctness */

    prop_clear(sconn->sparams->propctx, 0);
	
    /* ensure its requested */
    result = prop_request(sconn->sparams->propctx, password_request);

    if(result != SASL_OK) return result;

    result = _sasl_canon_user(conn, userstr, 0,
			      SASL_CU_AUTHID | SASL_CU_AUTHZID,
			      &(conn->oparams));
    if(result != SASL_OK) return result;
    
    result = prop_getnames(sconn->sparams->propctx, password_request,
			   auxprop_values);
    if(result < 0)
	return result;

    if((!auxprop_values[0].name
         || !auxprop_values[0].values || !auxprop_values[0].values[0])
       && (!auxprop_values[1].name
         || !auxprop_values[1].values || !auxprop_values[1].values[0]))
	    return SASL_NOUSER;
        
    /* It is possible for us to get useful information out of just
     * the lookup, so we won't check that we have a password until now */
    if(!passwd) {
	ret = SASL_BADPARAM;
	goto done;
    }

    /* At the point this has been called, the username has been canonified
     * and we've done the auxprop lookup.  This should be easy. */
    if(auxprop_values[0].name
       && auxprop_values[0].values
       && auxprop_values[0].values[0]
       && !strcmp(auxprop_values[0].values[0], passwd)) {
	/* We have a plaintext version and it matched! */
	return SASL_OK;
    } else if(auxprop_values[1].name
	      && auxprop_values[1].values
	      && auxprop_values[1].values[0]) {
	const char *db_secret = auxprop_values[1].values[0];
	sasl_secret_t *construct;
	
#ifdef _SUN_SDK_
	ret = _sasl_make_plain_secret(sconn->sparams->utils, db_secret,
				passwd, strlen(passwd),
				&construct);
#else
	ret = _sasl_make_plain_secret(db_secret, passwd,
				      strlen(passwd),
				      &construct);
#endif /* _SUN_SDK_ */
	if (ret != SASL_OK) {
	    goto done;
	}

	if (!memcmp(db_secret, construct->data, construct->len)) {
	    /* password verified! */
	    ret = SASL_OK;
	} else {
	    /* passwords do not match */
	    ret = SASL_BADAUTH;
	}

#ifdef _SUN_SDK_
	sconn->sparams->utils->free(construct);
#else
	sasl_FREE(construct);
#endif /* _SUN_SDK_ */
    } else {
	/* passwords do not match */
	ret = SASL_BADAUTH;
    }

 done:
#ifdef _SUN_SDK_
    if (userid) sconn->sparams->utils->free(userid);
#else
    if (userid) sasl_FREE(userid);
    if (realm)  sasl_FREE(realm);
#endif /* _SUN_SDK_ */

    /* We're not going to erase the property here because other people
     * may want it */
    return ret;
}

#ifdef DO_SASL_CHECKAPOP
int _sasl_auxprop_verify_apop(sasl_conn_t *conn,
			      const char *userstr,
			      const char *challenge,
			      const char *response,
			      const char *user_realm __attribute__((unused)))
{
    int ret = SASL_BADAUTH;
    char *userid = NULL;
#ifndef _SUN_SDK_
    char *realm = NULL;
#endif /* !_SUN_SDK_ */
    unsigned char digest[16];
    char digeststr[33];
    const char *password_request[] = { SASL_AUX_PASSWORD, NULL };
    struct propval auxprop_values[2];
    sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;
    MD5_CTX ctx;
    int i;

    if (!conn || !userstr || !challenge || !response)
       PARAMERROR(conn)

    /* We've done the auxprop lookup already (in our caller) */
    /* sadly, APOP has no provision for storing secrets */
    ret = prop_getnames(sconn->sparams->propctx, password_request,
			auxprop_values);
    if(ret < 0) {
#ifdef _SUN_SDK_
	_sasl_log(conn, SASL_LOG_ERR, "could not perform password lookup");
#else
	sasl_seterror(conn, 0, "could not perform password lookup");
#endif /* _SUN_SDK_ */
	goto done;
    }
    
    if(!auxprop_values[0].name ||
       !auxprop_values[0].values ||
       !auxprop_values[0].values[0]) {
#ifdef _INTEGRATED_SOLARIS_
	sasl_seterror(conn, 0, gettext("could not find password"));
#else
	sasl_seterror(conn, 0, "could not find password");
#endif /* _INTEGRATED_SOLARIS_ */
	ret = SASL_NOUSER;
	goto done;
    }
    
    _sasl_MD5Init(&ctx);
    _sasl_MD5Update(&ctx, challenge, strlen(challenge));
    _sasl_MD5Update(&ctx, auxprop_values[0].values[0],
		    strlen(auxprop_values[0].values[0]));
    _sasl_MD5Final(digest, &ctx);

    /* convert digest from binary to ASCII hex */
    for (i = 0; i < 16; i++)
      sprintf(digeststr + (i*2), "%02x", digest[i]);

    if (!strncasecmp(digeststr, response, 32)) {
      /* password verified! */
      ret = SASL_OK;
    } else {
      /* passwords do not match */
      ret = SASL_BADAUTH;
    }

 done:
#ifdef _INTEGRATED_SOLARIS_
    if (ret == SASL_BADAUTH) sasl_seterror(conn, SASL_NOLOG,
					   gettext("login incorrect"));
#else
    if (ret == SASL_BADAUTH) sasl_seterror(conn, SASL_NOLOG,
					   "login incorrect");
#endif /* _INTEGRATED_SOLARIS_ */
#ifdef _SUN_SDK_
    if (userid) sconn->sparams->utils->free(userid);
#else
    if (userid) sasl_FREE(userid);
    if (realm)  sasl_FREE(realm);
#endif /* _SUN_SDK_ */

    return ret;
}
#endif /* DO_SASL_CHECKAPOP */

#if defined(HAVE_PWCHECK) || defined(HAVE_SASLAUTHD)
/*
 * Keep calling the writev() system call with 'fd', 'iov', and 'iovcnt'
 * until all the data is written out or an error occurs.
 */
static int retry_writev(int fd, struct iovec *iov, int iovcnt)
{
    int n;
    int i;
    int written = 0;
    static int iov_max =
#ifdef MAXIOV
	MAXIOV
#else
#ifdef IOV_MAX
	IOV_MAX
#else
	8192
#endif
#endif
	;
    
    for (;;) {
	while (iovcnt && iov[0].iov_len == 0) {
	    iov++;
	    iovcnt--;
	}

	if (!iovcnt) return written;

	n = writev(fd, iov, iovcnt > iov_max ? iov_max : iovcnt);
	if (n == -1) {
	    if (errno == EINVAL && iov_max > 10) {
		iov_max /= 2;
		continue;
	    }
	    if (errno == EINTR) continue;
	    return -1;
	}

	written += n;

	for (i = 0; i < iovcnt; i++) {
	    if (iov[i].iov_len > (unsigned) n) {
		iov[i].iov_base = (char *)iov[i].iov_base + n;
		iov[i].iov_len -= n;
		break;
	    }
	    n -= iov[i].iov_len;
	    iov[i].iov_len = 0;
	}

	if (i == iovcnt) return written;
    }
}

#endif

#ifdef HAVE_PWCHECK
/* pwcheck daemon-authenticated login */
static int pwcheck_verify_password(sasl_conn_t *conn,
				   const char *userid, 
				   const char *passwd,
				   const char *service __attribute__((unused)),
				   const char *user_realm 
				               __attribute__((unused)))
{
    int s;
    struct sockaddr_un srvaddr;
    int r;
    struct iovec iov[10];
    static char response[1024];
    unsigned start, n;
    char pwpath[1024];

    if (strlen(PWCHECKDIR)+8+1 > sizeof(pwpath)) return SASL_FAIL;

    strcpy(pwpath, PWCHECKDIR);
    strcat(pwpath, "/pwcheck");

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) return errno;

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strncpy(srvaddr.sun_path, pwpath, sizeof(srvaddr.sun_path));
    r = connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	sasl_seterror(conn,0,"cannot connect to pwcheck server");
	return SASL_FAIL;
    }

    iov[0].iov_base = (char *)userid;
    iov[0].iov_len = strlen(userid)+1;
    iov[1].iov_base = (char *)passwd;
    iov[1].iov_len = strlen(passwd)+1;

    retry_writev(s, iov, 2);

    start = 0;
    while (start < sizeof(response) - 1) {
	n = read(s, response+start, sizeof(response) - 1 - start);
	if (n < 1) break;
	start += n;
    }

    close(s);

    if (start > 1 && !strncmp(response, "OK", 2)) {
	return SASL_OK;
    }

    response[start] = '\0';
    sasl_seterror(conn,0,response);
    return SASL_BADAUTH;
}

#endif

#ifdef HAVE_SASLAUTHD

/*
 * Keep calling the read() system call with 'fd', 'buf', and 'nbyte'
 * until all the data is read in or an error occurs.
 */
static int retry_read(int fd, void *buf0, unsigned nbyte)
{
    int n;
    int nread = 0;
    char *buf = buf0;

    if (nbyte == 0) return 0;

    for (;;) {
	n = read(fd, buf, nbyte);
	if (n == -1 || n == 0) {
	    if (errno == EINTR || errno == EAGAIN) continue;
	    return -1;
	}

	nread += n;

	if (nread >= (int) nbyte) return nread;

	buf += n;
	nbyte -= n;
    }
}

/* saslauthd-authenticated login */
static int saslauthd_verify_password(sasl_conn_t *conn,
				     const char *userid, 
				     const char *passwd,
				     const char *service,
				     const char *user_realm)
{
    char response[1024];
    char query[8192];
    char *query_end = query;
    int s;
    struct sockaddr_un srvaddr;
    sasl_getopt_t *getopt;
    void *context;
    char pwpath[sizeof(srvaddr.sun_path)];
    const char *p = NULL;
#ifdef USE_DOORS
    door_arg_t arg;
#endif

    /* check to see if the user configured a rundir */
    if (_sasl_getcallback(conn, SASL_CB_GETOPT, &getopt, &context) == SASL_OK) {
	getopt(context, NULL, "saslauthd_path", &p, NULL);
    }
    if (p) {
	strncpy(pwpath, p, sizeof(pwpath));
    } else {
	if (strlen(PATH_SASLAUTHD_RUNDIR) + 4 + 1 > sizeof(pwpath))
	    return SASL_FAIL;

	strcpy(pwpath, PATH_SASLAUTHD_RUNDIR);
	strcat(pwpath, "/mux");
    }

    /*
     * build request of the form:
     *
     * count authid count password count service count realm
     */
    {
 	unsigned short u_len, p_len, s_len, r_len;
 
 	u_len = (strlen(userid));
 	p_len = (strlen(passwd));
	s_len = (strlen(service));
	r_len = ((user_realm ? strlen(user_realm) : 0));

	if (u_len + p_len + s_len + r_len + 30 > (unsigned short) sizeof(query)) {
	    /* request just too damn big */
            sasl_seterror(conn, 0, "saslauthd request too large");
	    return SASL_FAIL;
	}

	u_len = htons(u_len);
	p_len = htons(p_len);
	s_len = htons(s_len);
	r_len = htons(r_len);

	memcpy(query_end, &u_len, sizeof(unsigned short));
	query_end += sizeof(unsigned short);
	while (*userid) *query_end++ = *userid++;

	memcpy(query_end, &p_len, sizeof(unsigned short));
	query_end += sizeof(unsigned short);
	while (*passwd) *query_end++ = *passwd++;

	memcpy(query_end, &s_len, sizeof(unsigned short));
	query_end += sizeof(unsigned short);
	while (*service) *query_end++ = *service++;

	memcpy(query_end, &r_len, sizeof(unsigned short));
	query_end += sizeof(unsigned short);
	if (user_realm) while (*user_realm) *query_end++ = *user_realm++;
    }

#ifdef USE_DOORS
    s = open(pwpath, O_RDONLY);
    if (s < 0) {
	sasl_seterror(conn, 0, "cannot open door to saslauthd server: %m", errno);
	return SASL_FAIL;
    }

    arg.data_ptr = query;
    arg.data_size = query_end - query;
    arg.desc_ptr = NULL;
    arg.desc_num = 0;
    arg.rbuf = response;
    arg.rsize = sizeof(response);

    door_call(s, &arg);

    if (arg.data_ptr != response || arg.data_size >= sizeof(response)) {
	/* oh damn, we got back a really long response */
	munmap(arg.rbuf, arg.rsize);
	sasl_seterror(conn, 0, "saslauthd sent an overly long response");
	return SASL_FAIL;
    }
    response[arg.data_size] = '\0';

    close(s);
#else
    /* unix sockets */

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	sasl_seterror(conn, 0, "cannot create socket for saslauthd: %m", errno);
	return SASL_FAIL;
    }

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strncpy(srvaddr.sun_path, pwpath, sizeof(srvaddr.sun_path));

    {
	int r = connect(s, (struct sockaddr *) &srvaddr, sizeof(srvaddr));
	if (r == -1) {
	    sasl_seterror(conn, 0, "cannot connect to saslauthd server: %m", errno);
	    return SASL_FAIL;
	}
    }

    {
 	struct iovec iov[8];
 
	iov[0].iov_len = query_end - query;
	iov[0].iov_base = query;

	if (retry_writev(s, iov, 1) == -1) {
            sasl_seterror(conn, 0, "write failed");
  	    return SASL_FAIL;
  	}
    }

    {
	unsigned short count = 0;

	/*
	 * read response of the form:
	 *
	 * count result
	 */
	if (retry_read(s, &count, sizeof(count)) < (int) sizeof(count)) {
	    sasl_seterror(conn, 0, "size read failed");
	    return SASL_FAIL;
	}
	
	count = ntohs(count);
	if (count < 2) { /* MUST have at least "OK" or "NO" */
	    close(s);
	    sasl_seterror(conn, 0, "bad response from saslauthd");
	    return SASL_FAIL;
	}
	
	count = (int)sizeof(response) < count ? sizeof(response) : count;
	if (retry_read(s, response, count) < count) {
	    close(s);
	    sasl_seterror(conn, 0, "read failed");
	    return SASL_FAIL;
	}
	response[count] = '\0';
    }

    close(s);
#endif /* USE_DOORS */
  
    if (!strncmp(response, "OK", 2)) {
	return SASL_OK;
    }
  
    sasl_seterror(conn, SASL_NOLOG, "authentication failed");
    return SASL_BADAUTH;
}

#endif

#ifdef HAVE_ALWAYSTRUE
static int always_true(sasl_conn_t *conn,
		       const char *userstr,
		       const char *passwd __attribute__((unused)),
		       const char *service __attribute__((unused)),
		       const char *user_realm __attribute__((unused))) 
{
    _sasl_log(conn, SASL_LOG_WARN, "AlwaysTrue Password Verifier Verified: %s",
	      userstr);
    return SASL_OK;
}
#endif

struct sasl_verify_password_s _sasl_verify_password[] = {
    { "auxprop", &auxprop_verify_password },
#ifdef HAVE_PWCHECK
    { "pwcheck", &pwcheck_verify_password },
#endif
#ifdef HAVE_SASLAUTHD
    { "saslauthd", &saslauthd_verify_password },
#endif
#ifdef HAVE_ALWAYSTRUE
    { "alwaystrue", &always_true },
#endif     
    { NULL, NULL }
};
