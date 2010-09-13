/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_ldap/ldap_service_stash.c
 *
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_service_stash.h"
#include <libintl.h>

krb5_error_code
krb5_ldap_readpassword(context, ldap_context, password)
    krb5_context                context;
    krb5_ldap_context           *ldap_context;
    unsigned char               **password;
{
    int                         entryfound=0;
    krb5_error_code             st=0;
    char                        line[RECORDLEN]="0", *start=NULL, *file=NULL;
    char                        errbuf[1024];
    FILE                        *fptr=NULL;

    *password = NULL;

    if (ldap_context->service_password_file)
	file = ldap_context->service_password_file;

#ifndef HAVE_STRERROR_R
# undef strerror_r
    /* Solaris Kerberos: safer macro, added more (), use strlcpy() */
# define strerror_r(ERRNUM, BUF, SIZE) (strlcpy((BUF), strerror(ERRNUM), (SIZE)), (BUF)[(SIZE)-1] = 0)
#endif

    /* Solaris Kerberos: access()'s are unsafe and useless */
#if 0 /************** Begin IFDEF'ed OUT *******************************/
    /* check whether file exists */
    if (access(file, F_OK) < 0) {
	st = errno;
	strerror_r(errno, errbuf, sizeof(errbuf));
	krb5_set_error_message (context, st, "%s", errbuf);
	goto rp_exit;
    }

    /* check read access */
    if (access(file, R_OK) < 0) {
	st = errno;
	strerror_r(errno, errbuf, sizeof(errbuf));
	krb5_set_error_message (context, st, "%s", errbuf);
	goto rp_exit;
    }
#endif /**************** END IFDEF'ed OUT *******************************/

    /* Solaris Kerberos: using F to deal with 256 open file limit */
    if ((fptr = fopen(file, "rF")) == NULL) {
	st = errno;
	strerror_r(errno, errbuf, sizeof(errbuf));
	krb5_set_error_message (context, st, "%s", errbuf);
	goto rp_exit;
    }

    /* get the record from the file */
    while (fgets(line, RECORDLEN, fptr) != NULL) {
	char tmp[RECORDLEN];

	tmp[0] = '\0';
	/* Handle leading white-spaces */
	for (start = line; isspace(*start); ++start);

	/* Handle comment lines */
	if (*start == '!' || *start == '#')
	    continue;
	sscanf(line, "%*[ \t]%[^#]", tmp);
	if (tmp[0] == '\0')
	    sscanf(line, "%[^#]", tmp);
	if (strcasecmp(tmp, ldap_context->bind_dn) == 0) {
	    entryfound = 1; /* service_dn record found !!! */
	    break;
	}
    }
    (void) fclose (fptr);

    if (entryfound == 0)  {
	st = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (context, st, gettext("Bind DN entry missing in stash file"));
	goto rp_exit;
    }
    /* replace the \n with \0 */
    start = strchr(line, '\n');
    if (start)
	*start = '\0';

    start = strchr(line, '#');
    if (start == NULL) {
	/* password field missing */
	st = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (context, st, gettext("Stash file entry corrupt"));
	goto rp_exit;
    }
    ++ start;
    /* Extract the plain password / certificate file information */
    {
	struct data PT, CT;

	/* Check if the entry has the path of a certificate */
	if (!strncmp(start, "{FILE}", strlen("{FILE}"))) {
	    /* Set *password = {FILE}<path to cert>\0<cert password> */
	    /*ptr = strchr(start, ':');
	      if (ptr == NULL) { */
	    *password = (unsigned char *)malloc(strlen(start) + 2);
	    if (*password == NULL) {
		st = ENOMEM;
		goto rp_exit;
	    }
	    (*password)[strlen(start) + 1] = '\0';
	    (*password)[strlen(start)] = '\0';
	    /*LINTED*/
	    strcpy((char *)(*password), start);
	    goto got_password;
	} else {
	    CT.value = (unsigned char *)start;
	    CT.len = strlen((char *)CT.value);
	    st = dec_password(CT, &PT);
	    if (st != 0) {
		switch (st) {
		case ERR_NO_MEM:
		    st = ENOMEM;
		    break;
		case ERR_PWD_ZERO:
		    st = EINVAL;
		    krb5_set_error_message(context, st, gettext("Password has zero length"));
		    break;
		case ERR_PWD_BAD:
		    st = EINVAL;
		    krb5_set_error_message(context, st, gettext("Password corrupted"));
		    break;
		case ERR_PWD_NOT_HEX:
		    st = EINVAL;
		    krb5_set_error_message(context, st, gettext("Not a hexadecimal password"));
		    break;
		default:
		    st = KRB5_KDB_SERVER_INTERNAL_ERR;
		    break;
		}
		goto rp_exit;
	    }
	    *password = PT.value;
	}
    }
got_password:

rp_exit:
    if (st) {
	if (*password)
	    free (*password);
	*password = NULL;
    }
    return st;
}

/* Encodes a sequence of bytes in hexadecimal */

int
tohex(in, ret)
    krb5_data         in;
    krb5_data         *ret;
{
    int                i=0, err = 0;

    ret->length = 0;
    ret->data = NULL;

    ret->data = malloc((unsigned int)in.length * 2 + 1 /*Null termination */);
    if (ret->data == NULL) {
	err = ENOMEM;
	goto cleanup;
    }
    ret->length = in.length * 2;
    ret->data[ret->length] = 0;

    for (i = 0; i < in.length; i++)
	sprintf(ret->data + (2 * i), "%02x", in.data[i] & 0xff);

cleanup:

    if (ret->length == 0) {
	free(ret->data);
	ret->data = NULL;
    }

    return err;
}

/* The entry in the password file will have the following format
 * <FQDN of service> = <secret>
 *   <secret> := {HEX}<password in hexadecimal>
 *
 * <password> is the actual eDirectory password of the service
 * Return values:
 * ERR_NO_MEM      - No Memory
 * ERR_PWD_ZERO    - Password has zero length
 * ERR_PWD_BAD     - Passowrd corrupted
 * ERR_PWD_NOT_HEX - Not a hexadecimal password
 */

int dec_password(struct data pwd, struct data *ret) {
    int err=0;
    int i=0, j=0;

    ret->len = 0;
    ret->value = NULL;

    if (pwd.len == 0) {
	err = ERR_PWD_ZERO;
	ret->len = 0;
	goto cleanup;
    }

    /* Check if it is a hexadecimal encoded password */
    if (pwd.len >= strlen("{HEX}") &&
	strncmp((char *)pwd.value, "{HEX}", strlen("{HEX}")) == 0) {

	if ((pwd.len - strlen("{HEX}")) % 2 != 0) {
	    /* A hexadecimal encoded password should have even length */
	    err = ERR_PWD_BAD;
	    ret->len = 0;
	    goto cleanup;
	}
	ret->value = (unsigned char *)malloc((pwd.len - strlen("{HEX}")) / 2 + 1);
	if (ret->value == NULL) {
	    err = ERR_NO_MEM;
	    ret->len = 0;
	    goto cleanup;
	}
	ret->len = (pwd.len - strlen("{HEX}")) / 2;
	ret->value[ret->len] = '\0';
	for (i = strlen("{HEX}"), j = 0; i < pwd.len; i += 2, j++) {
	    unsigned int k;
	    /* Check if it is a hexadecimal number */
	    if (isxdigit(pwd.value[i]) == 0 || isxdigit(pwd.value[i + 1]) == 0) {
		err = ERR_PWD_NOT_HEX;
		ret->len = 0;
		goto cleanup;
	    }
	    sscanf((char *)pwd.value + i, "%2x", &k);
	    ret->value[j] = k;
	}
	goto cleanup;
    } else {
	err = ERR_PWD_NOT_HEX;
	ret->len = 0;
	goto cleanup;
    }

cleanup:

    if (ret->len == 0) {
	free(ret->value);
	ret->value = NULL;
    }
    return(err);
}
