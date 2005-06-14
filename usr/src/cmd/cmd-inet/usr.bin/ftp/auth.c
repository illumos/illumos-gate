/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1985, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ftp_var.h"
#include <sys/types.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

int	auth_type;	/* Authentication succeeded?  If so, what type? */

char	*radix_error(int);
static void get_inet_addr_info(struct sockaddr_in6 *, gss_buffer_t);

static char *radixN =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char radix_pad = '=';

/*
 * authenticate the user, if auth_type is AUTHTYPE_NONE
 *
 * Returns:	0 if there is no auth type
 *		1 if success
 * 		2 if failure
 */

gss_OID		mechoid;
gss_ctx_id_t	gcontext;	/* global gss security context */
static		const char *gss_trials[] = { "ftp", "host" };
/* the number of elements in gss_trials array */
static const	int n_gss_trials = sizeof (gss_trials)/sizeof (char *);
char		*reply_parse;

int
do_auth(void)
{
	int oldverbose = verbose;
	uchar_t *out_buf = NULL;
	size_t outlen;
	int i;

	if (auth_type != AUTHTYPE_NONE)
	    return (1);		/* auth already succeeded */

	/* Other auth types go here ... */

	if (command("AUTH %s", "GSSAPI") == CONTINUE) {
	    OM_uint32 maj_stat, min_stat;
	    gss_name_t target_name;
	    gss_buffer_desc send_tok, recv_tok, *token_ptr;
	    gss_buffer_desc temp_buf;
	    char stbuf[FTPBUFSIZ];
	    int comcode, trial;
	    int req_flags;
	    struct gss_channel_bindings_struct chan;

	    get_inet_addr_info(&myctladdr, &temp_buf);
	    chan.initiator_addrtype = GSS_C_AF_INET; /* OM_uint32  */
	    chan.initiator_address.length =  temp_buf.length;
	    chan.initiator_address.value = malloc(temp_buf.length);
	    memcpy(chan.initiator_address.value, temp_buf.value,
		temp_buf.length);

	    get_inet_addr_info(&remctladdr, &temp_buf);
	    chan.acceptor_addrtype = GSS_C_AF_INET; /* OM_uint32 */
	    chan.acceptor_address.length = temp_buf.length;
	    chan.acceptor_address.value = malloc(temp_buf.length);
	    memcpy(chan.acceptor_address.value, temp_buf.value,
		temp_buf.length);

	    chan.application_data.length = 0;
	    chan.application_data.value  = 0;

	    if (verbose)
		(void) printf("GSSAPI accepted as authentication type\n");

	    /* set the forward flag */
	    req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;

	    if (fflag)
		req_flags |= GSS_C_DELEG_FLAG;

	    /* blob from gss-client */
	    for (trial = 0; trial < n_gss_trials; trial++) {
		/* ftp@hostname first, then host@hostname */
		/* the V5 GSSAPI binding canonicalizes this for us... */
		(void) snprintf(stbuf, FTPBUFSIZ, "%s@%s",
			gss_trials[trial], hostname);
		if (debug)
		    (void) fprintf(stderr,
			"Trying to authenticate to <%s>\n", stbuf);

		send_tok.value = stbuf;
		send_tok.length = strlen(stbuf) + 1;
		maj_stat = gss_import_name(&min_stat, &send_tok,
			GSS_C_NT_HOSTBASED_SERVICE, &target_name);

		if (maj_stat != GSS_S_COMPLETE) {
		    user_gss_error(maj_stat, min_stat, "parsing name");
		    (void) fprintf(stderr, "name parsed <%s>\n", stbuf);
		    continue;
		}

		token_ptr = GSS_C_NO_BUFFER;
		gcontext = GSS_C_NO_CONTEXT; /* structure copy */

		do {
		    if (debug)
			(void) fprintf(stderr,
				"calling gss_init_sec_context\n");

		    if (mechstr && !mechoid &&
			__gss_mech_to_oid(mechstr, (gss_OID*)&mechoid) !=
			GSS_S_COMPLETE)
				(void) printf("do_auth: %s: not a valid "
					"security mechanism\n", mechstr);

		    if (!mechoid)
			mechoid = GSS_C_NULL_OID;

		    maj_stat = gss_init_sec_context(&min_stat,
				    GSS_C_NO_CREDENTIAL,
				    &gcontext,
				    target_name,
				    mechoid,
				    req_flags,
				    0,
				    &chan,	/* channel bindings */
				    token_ptr,
				    NULL,	/* ignore mech type */
				    &send_tok,
				    NULL,	/* ignore ret_flags */
				    NULL);	/* ignore time_rec */

		    if (maj_stat != GSS_S_COMPLETE &&
			maj_stat != GSS_S_CONTINUE_NEEDED) {

			/* return an error if this is NOT the ftp ticket */
			if (strcmp(gss_trials[trial], "ftp"))
				user_gss_error(maj_stat, min_stat,
					"initializing context");

			(void) gss_release_name(&min_stat, &target_name);
			/* could just be that we missed on the service name */
			goto outer_loop;

		    }

		if (send_tok.length != 0) {
		    int len = send_tok.length;
		    reply_parse = "ADAT="; /* for command() later */
		    oldverbose = verbose;
		    verbose = (trial == n_gss_trials-1)?0:-1;

		    outlen = ENCODELEN(send_tok.length);
		    out_buf = (uchar_t *)malloc(outlen);
		    if (out_buf == NULL) {
			(void) fprintf(stderr, "memory error allocating "
				"auth buffer\n");
			maj_stat = GSS_S_FAILURE;
			goto outer_loop;
		    }
		    auth_error = radix_encode(send_tok.value, out_buf,
			outlen, &len, 0);

		    if (auth_error)  {
			(void) fprintf(stderr, "Base 64 encoding failed: %s\n",
				radix_error(auth_error));
		    } else if ((comcode = command("ADAT %s", out_buf))
			!= COMPLETE /* && comcode != 3 (335)*/) {

			if (trial == n_gss_trials-1) {
			    (void) fprintf(stderr, "GSSAPI ADAT failed (%d)\n",
				comcode);

			    /* force out of loop */
			    maj_stat = GSS_S_FAILURE;
			}

			/*
			 * backoff to the v1 gssapi is still possible.
			 * Send a new AUTH command.  If that fails,
			 * terminate the loop
			 */
			if (command("AUTH %s", "GSSAPI") != CONTINUE) {
			    (void) fprintf(stderr,
				"GSSAPI ADAT failed, AUTH restart failed\n");
			    /* force out of loop */
			    maj_stat = GSS_S_FAILURE;
			}

			goto outer_loop;
		    } else if (!reply_parse) {
			(void) fprintf(stderr,
			    "No authentication data received from server\n");
			if (maj_stat == GSS_S_COMPLETE) {
			    (void) fprintf(stderr,
				"...but no more was needed\n");
			    goto gss_complete_loop;
			} else {
			    user_gss_error(maj_stat, min_stat, "no reply.");
			    goto gss_complete_loop;
			}
		    } else if (auth_error = radix_encode((uchar_t *)
			reply_parse, out_buf, outlen, &i, 1)) {
			    (void) fprintf(stderr,
				"Base 64 decoding failed: %s\n",
				radix_error(auth_error));
		    } else {
			/* everything worked */
			token_ptr = &recv_tok;
			recv_tok.value = out_buf;
			recv_tok.length = i;
			continue;
		    } /* end if (auth_error) */

/* get out of loop clean */
gss_complete_loop:
		    trial = n_gss_trials-1;
		    gss_release_buffer(&min_stat, &send_tok);
		    gss_release_name(&min_stat, &target_name);
		    goto outer_loop;
		} /* end if (send_tok.length != 0) */

	    } while (maj_stat == GSS_S_CONTINUE_NEEDED);

outer_loop:
	    if (maj_stat == GSS_S_COMPLETE)
		break;

	    } /* end for loop */

	    verbose = oldverbose;
	    if (out_buf != NULL)
		free(out_buf);

	    if (maj_stat == GSS_S_COMPLETE) {
		(void) printf("GSSAPI authentication succeeded\n");
		reply_parse = NULL;
		auth_type = AUTHTYPE_GSSAPI;
		return (1);
	    } else {
		(void) fprintf(stderr, "GSSAPI authentication failed\n");
		reply_parse = NULL;
	    }
	} /* end if (command...) */

	/* Other auth types go here ... */

	return (0);
}

/*
 * Get the information for the channel structure.
 */
void
get_inet_addr_info(struct sockaddr_in6 *in_ipaddr, gss_buffer_t in_buffer)
{
	size_t length;
	char *value;

	if (in_ipaddr == NULL) {
		in_buffer->length = 0;
		in_buffer->value = NULL;
		return;
	}

	/* get the initiator address.value and address.length */

	if (in_ipaddr->sin6_family == AF_INET6) {
		struct in_addr in_ipv4addr;
		struct sockaddr_in6 *sin6 =
			(struct sockaddr_in6 *)in_ipaddr;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr,
				&in_ipv4addr);
			in_buffer->length = length = sizeof (struct in_addr);
			in_buffer->value = value = malloc(length);
			memcpy(value, &in_ipv4addr, length);
		} else {
			in_buffer->length = length = sizeof (struct in6_addr);
			in_buffer->value = value = malloc(length);
			memcpy(value, &(sin6->sin6_addr.s6_addr),
				length);
		}
	} else {
		in_buffer->length = length = sizeof (struct in_addr);
		in_buffer->value = value = malloc(in_buffer->length);
		memcpy(value,
			&((struct sockaddr_in *)(in_ipaddr))->sin_addr,
			length);
	}
}

int
radix_encode(uchar_t *inbuf, uchar_t *outbuf, size_t buflen,
	int *outlen, int decode)
{
	int i, j, D;
	char *p;
	uchar_t c;

	if (decode) {
		for (i = j = 0;
		    inbuf[i] && inbuf[i] != radix_pad && (j < buflen);
		    i++) {
		    if ((p = strchr(radixN, inbuf[i])) == NULL)
			return (1);
		    D = p - radixN;
		    switch (i&3) {
			case 0:
			    outbuf[j] = D<<2;
			    break;
			case 1:
			    outbuf[j++] |= D>>4;
			    outbuf[j] = (D&15)<<4;
			    break;
			case 2:
			    outbuf[j++] |= D>>2;
			    outbuf[j] = (D&3)<<6;
			    break;
			case 3:
			    outbuf[j++] |= D;
		    }
		}
		if (j == buflen && (inbuf[i] && inbuf[i] != radix_pad)) {
			return (4);
		}
		switch (i&3) {
			case 1: return (3);
			case 2: if (D&15)
					return (3);
				if (strcmp((char *)&inbuf[i], "=="))
					return (2);
				break;
			case 3: if (D&3)
					return (3);
				if (strcmp((char *)&inbuf[i], "="))
					return (2);
		}
		*outlen = j;
	} else {
		for (i = j = 0; i < *outlen && j < buflen; i++)
		    switch (i%3) {
			case 0:
			    outbuf[j++] = radixN[inbuf[i]>>2];
			    c = (inbuf[i]&3)<<4;
			    break;
			case 1:
			    outbuf[j++] = radixN[c|inbuf[i]>>4];
			    c = (inbuf[i]&15)<<2;
			    break;
			case 2:
			    outbuf[j++] = radixN[c|inbuf[i]>>6];
			    outbuf[j++] = radixN[inbuf[i]&63];
			    c = 0;
		    }
		if (j == buflen && i < *outlen) {
			return (4);
		}
		if (i%3)
			outbuf[j++] = radixN[c];
		switch (i%3) {
			case 1:
				outbuf[j++] = radix_pad;
				/* FALLTHROUGH */
			case 2:
				outbuf[j++] = radix_pad;
				break;
		}
		outbuf[*outlen = j] = '\0';
	}
	return (0);
}

char *
radix_error(int e)
{
	switch (e) {
	    case 0:  return ("Success");
	    case 1:  return ("Bad character in encoding");
	    case 2:  return ("Encoding not properly padded");
	    case 3:  return ("Decoded # of bits not a multiple of 8");
	    case 4:  return ("Buffer size error");
	    default: return ("Unknown error");
	}
}
