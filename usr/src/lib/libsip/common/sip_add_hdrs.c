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
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <strings.h>
#include <stdlib.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"

/*
 * Returns number of digits in the given int
 */
static int
sip_num_of_digits(int num)
{
	int	num_of_bytes = 0;

	do {
		num_of_bytes += 1;
		num = num / 10;
	} while (num > 0);
	return (num_of_bytes);
}

/*
 * Return the int as a string
 */
static char *
sip_int_to_str(int i)
{
	int	count;
	int	t;
	int	x;
	char	*str;

	if (i < 0)
		return (NULL);
	/*
	 * the following two loops convert int i to str
	 */
	count = 1;
	t = i;
	while ((t = t / 10) != 0) {
		count++;
	}

	str = calloc(1, sizeof (char) * count + 1);
	if (str == NULL)
		return (NULL);
	t = i;
	for (x = 0; x < count; x++) {
		int a;
		a = t % 10;
		str[count - 1 - x] = a + '0';
		t = t / 10;
	}
	str[count] = '\0';
	return (str);
}

/*
 * Add quotes to the give str and return the quoted string
 */
static char *
sip_add_aquot_to_str(char *str, boolean_t *alloc)
{
	char 		*new_str;
	char 		*tmp = str;
	int		size;

	while (isspace(*tmp))
		tmp++;

	*alloc = B_FALSE;
	if (*tmp != SIP_LAQUOT) {
		size = strlen(str) + 2 * sizeof (char);
		new_str = calloc(1, size + 1);
		if (new_str == NULL)
			return (NULL);
		new_str[0] = SIP_LAQUOT;
		new_str[1] = '\0';
		(void) strncat(new_str, str, strlen(str));
		(void) strncat(new_str, ">", 1);
		new_str[size] = '\0';
		*alloc = B_TRUE;
		return (new_str);
	}

	return (str);
}

/*
 * Add an empty header
 */
static int
sip_add_empty_hdr(sip_msg_t sip_msg, char *hdr_name)
{
	_sip_header_t	*new_header;
	int 		header_size;
	_sip_msg_t 	*_sip_msg;
	int		csize = sizeof (char);

	if (sip_msg == NULL || hdr_name == NULL)
		return (EINVAL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize;

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}

	(void) snprintf(new_header->sip_hdr_start, header_size + 1,
	    "%s %c",  hdr_name, SIP_HCOLON);

	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, hdr_name);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (0);
}

/*
 * Generic function to add a header with two strings to message
 */
static int
sip_add_2strs_to_msg(sip_msg_t sip_msg, char *hdr_name, char *str1,
    boolean_t qstr1, char *str2, char *plist, char sep)
{
	_sip_header_t	*new_header;
	int 		header_size;
	_sip_msg_t 	*_sip_msg;
	int		csize = sizeof (char);

	if (sip_msg == NULL || str1 == NULL || str2 == NULL ||
	    (str1 != NULL && str1[0] == '\0') ||
	    (str2 != NULL && str2[0] == '\0')) {
		return (EINVAL);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	if (plist == NULL) {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + strlen(str1) + csize + strlen(str2) +
		    strlen(SIP_CRLF);
	} else {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + strlen(str1) + csize + strlen(str2) +
		    csize + strlen(plist) + strlen(SIP_CRLF);
	}
	if (qstr1)
		header_size += 2 * sizeof (char);

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}

	if (plist == NULL) {
		if (qstr1) {
			(void) snprintf(new_header->sip_hdr_start,
			    header_size + 1, "%s %c \"%s\"%c%s%s",
			    hdr_name, SIP_HCOLON, str1, sep, str2, SIP_CRLF);
		} else {
			(void) snprintf(new_header->sip_hdr_start,
			    header_size + 1, "%s %c %s%c%s%s",
			    hdr_name, SIP_HCOLON, str1, sep, str2, SIP_CRLF);
		}
	} else {
		if (qstr1) {
			(void) snprintf(new_header->sip_hdr_start,
			    header_size + 1,
			    "%s %c \"%s\"%c%s%c%s%s", hdr_name, SIP_HCOLON,
			    str1, sep, str2, SIP_SEMI, plist, SIP_CRLF);
		} else {
			(void) snprintf(new_header->sip_hdr_start,
			    header_size + 1, "%s %c %s%c%s%c%s%s",
			    hdr_name, SIP_HCOLON, str1, sep, str2, SIP_SEMI,
			    plist, SIP_CRLF);
		}
	}
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (0);
}

/*
 * Generic function to add a header with a string to message
 */
static int
sip_add_str_to_msg(sip_msg_t sip_msg, char *hdr_name, char *str, char *plist,
    char param_sep)
{
	_sip_header_t	*new_header;
	int 		header_size;
	_sip_msg_t 	*_sip_msg;
	int		csize = sizeof (char);

	if (sip_msg == NULL || str == NULL || (str != NULL && str[0] == '\0'))
		return (EINVAL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	if (plist == NULL) {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + + strlen(str) + strlen(SIP_CRLF);
	} else {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + + strlen(str) + csize + strlen(plist) +
		    strlen(SIP_CRLF);
	}

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}
	if (plist == NULL) {
		(void) snprintf(new_header->sip_hdr_start, header_size + 1,
		    "%s %c %s%s", hdr_name, SIP_HCOLON, str, SIP_CRLF);
	} else {
		(void) snprintf(new_header->sip_hdr_start, header_size + 1,
		    "%s %c %s%c%s%s", hdr_name, SIP_HCOLON, str, param_sep,
		    plist, SIP_CRLF);
	}
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (0);
}

/*
 * Add an header with an int to sip_msg
 */
static int
sip_add_int_to_msg(sip_msg_t sip_msg, char *hdr_name, int i, char *plist)
{
	_sip_header_t	*new_header;
	int 		header_size;
	_sip_msg_t 	*_sip_msg;
	char		*digit_str;
	int		csize = sizeof (char);

	if (sip_msg == NULL || (hdr_name == NULL))
		return (EINVAL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	/*
	 * the following two loops convert int i to str
	 */
	digit_str = sip_int_to_str(i);
	if (digit_str == NULL)
		return (EINVAL);

	if (plist == NULL) {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + strlen(digit_str) + strlen(SIP_CRLF);
	} else {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + strlen(digit_str) + csize +
		    strlen(plist) + strlen(SIP_CRLF);
	}

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		free(digit_str);
		return (ENOMEM);
	}

	if (plist == NULL) {
		(void) snprintf(new_header->sip_hdr_start, header_size + 1,
		    "%s %c %s%s", hdr_name, SIP_HCOLON, digit_str, SIP_CRLF);
	} else {
		(void) snprintf(new_header->sip_hdr_start, header_size + 1,
		    "%s %c %s%c%s%s", hdr_name, SIP_HCOLON, digit_str,
		    SIP_SEMI, plist, SIP_CRLF);
	}
	free(digit_str);
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (0);
}

/*
 * Add a header with an int and string to sip_msg
 */
static int
sip_add_intstr_to_msg(sip_msg_t sip_msg, char *hdr_name, int i, char *s,
    char *plist)
{
	_sip_header_t	*new_header;
	int 		header_size;
	_sip_msg_t 	*_sip_msg;
	char		*digit_str;
	int		csize = sizeof (char);

	if (sip_msg == NULL || (hdr_name == NULL))
		return (EINVAL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	/*
	 * the following two loops convert int i to str
	 */
	digit_str = sip_int_to_str(i);
	if (digit_str == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (EINVAL);
	}
	if (plist == NULL) {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + strlen(digit_str) + csize + strlen(s) +
		    strlen(SIP_CRLF);
	} else {
		header_size = strlen(hdr_name) + SIP_SPACE_LEN + csize +
		    SIP_SPACE_LEN + strlen(digit_str) + csize + strlen(s) +
		    csize + strlen(plist) + strlen(SIP_CRLF);
	}

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		free(digit_str);
		return (ENOMEM);
	}

	if (plist == NULL) {
		(void) snprintf(new_header->sip_hdr_start, header_size + 1,
		    "%s %c %s %s%s", hdr_name, SIP_HCOLON, digit_str, s,
		    SIP_CRLF);
	} else {
		(void) snprintf(new_header->sip_hdr_start, header_size + 1,
		    "%s %c %s %s%c%s%s", hdr_name, SIP_HCOLON, digit_str,
		    s, SIP_SEMI, plist, SIP_CRLF);
	}
	free(digit_str);
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (0);
}

/*
 * Generic function to add Contact, From,  To, Route or Record-Route header
 */
static int
sip_add_name_aspec(sip_msg_t sip_msg, char *display_name, char *uri,
    char *tags, boolean_t add_aquot, char *header_name, char *params)
{
	char		*t = uri;
	boolean_t	qalloc = B_FALSE;
	boolean_t	palloc = B_FALSE;
	int		r;

	if (sip_msg == NULL || uri == NULL || header_name == NULL)
		return (EINVAL);
	if (display_name != NULL && !add_aquot)
		return (EINVAL);
	if (add_aquot) {
		t = sip_add_aquot_to_str(uri, &qalloc);
		if (t == NULL)
			return (ENOMEM);
	}
	if (tags != NULL) {
		int	plen;

		if (params != NULL)
			return (EINVAL);

		plen = strlen(SIP_TAG) + strlen(tags) + 1;
		params = malloc(plen);
		if (params == NULL)
			return (ENOMEM);
		(void) snprintf(params, plen, "%s%s", SIP_TAG, tags);
		params[plen - 1] = '\0';
		palloc = B_TRUE;
	}
	if (display_name == NULL) {
		r = sip_add_2strs_to_msg(sip_msg, header_name, " ", B_FALSE,
		    t, params, SIP_SP);
	} else {
		r = sip_add_2strs_to_msg(sip_msg, header_name, display_name,
		    B_TRUE, t, params, SIP_SP);
	}
	if (qalloc)
		free(t);
	if (palloc)
		free(params);
	return (r);
}

/*
 * Accept = "Accept" ":" (media-range [ accept-params ])
 * media-range = ( "X/X" | (type "/" "*") | (type "/" subtype))*(";" parameter)
 * accept-params = ";" "q" "=" qvalue *(accept-extension)
 * accept-extension = ";" token [ "=" (token | quoted-str)
 *
 * function take two char ptrs - type and subtype - if any of them is NULL
 * the corresponding value will be set to "*" in header
 */
int
sip_add_accept(sip_msg_t sip_msg, char *type, char *subtype, char *m_par,
    char *a_par)
{
	int		ret;
	char		*plist;
	int		size;
	boolean_t	alloc = B_FALSE;

	if (type == NULL && subtype == NULL) {
		ret = sip_add_empty_hdr(sip_msg, SIP_ACCEPT);
		return (ret);
	}

	if ((m_par != NULL) && (a_par != NULL)) {
		size = strlen(m_par) + strlen(a_par) + 2 * sizeof (char);
		plist = calloc(1, size * sizeof (char));
		(void) strncpy(plist, m_par, strlen(m_par));
		(void) strncat(plist, ";", 1);
		(void) strncat(plist, a_par, strlen(a_par));
		alloc = B_TRUE;
	} else if (m_par != NULL) {
		plist = m_par;
	} else
		plist = a_par;

	if ((type != NULL) && (subtype != NULL)) {
		ret = sip_add_2strs_to_msg(sip_msg, SIP_ACCEPT, type, B_FALSE,
		    subtype, plist, SIP_SLASH);
	} else if (type != NULL) {
		ret = sip_add_2strs_to_msg(sip_msg, SIP_ACCEPT, type, B_FALSE,
		    "*", plist, SIP_SLASH);
	} else {
		ret = EINVAL;
	}

	if (alloc == B_TRUE)
		free(plist);

	return (ret);
}


/*
 * Accept-Encoding = "Accept-Encoding" ":" 1#(codings [ ";" "q" "=" qval])
 * codings = ( content-coding | "*" )
 * content-coding   =  token
 *
 * function take one char ptr, if NULL value will be set to "*"
 */
int
sip_add_accept_enc(sip_msg_t sip_msg, char *code, char *plist)
{
	int ret;

	if (code == NULL) {
		ret = sip_add_str_to_msg(sip_msg, SIP_ACCEPT_ENCODE, "*", plist,
		    SIP_SEMI);
	} else {
		ret = sip_add_str_to_msg(sip_msg, SIP_ACCEPT_ENCODE, code,
		    plist, SIP_SEMI);
	}
	return (ret);
}

/*
 * Accept-Language = "Accept-Language" ":" 1#( language-range [ ";" "q""=" val])
 * language-range = ( ( 1*8ALPHA *("-" 1*8ALPHA))|"*")
 */
int
sip_add_accept_lang(sip_msg_t sip_msg, char *lang, char *plist)
{
	int	ret;

	if (lang == NULL) {
		ret = sip_add_empty_hdr(sip_msg, SIP_ACCEPT_LANG);
		return (ret);
	}
	ret = sip_add_str_to_msg(sip_msg, SIP_ACCEPT_LANG, lang, plist,
	    SIP_SEMI);
	return (ret);
}

/*
 * Alert-Info = "Alert-Info" ":" "<" URI ">"
 */
int
sip_add_alert_info(sip_msg_t sip_msg, char *alert, char *plist)
{
	int		ret;
	char		*tmp;
	boolean_t	alloc;

	if (alert == NULL)
		return (EINVAL);
	tmp = sip_add_aquot_to_str(alert, &alloc);
	if (tmp == NULL)
		return (ENOMEM);
	ret = sip_add_str_to_msg(sip_msg, SIP_ALERT_INFO, tmp, plist, SIP_SEMI);
	if (alloc)
		free(tmp);
	return (ret);
}

/*
 * Allow = "Allow" ":" method-name1[, method-name2..]
 * method-name = "INVITE" | "ACK" | "OPTIONS" | "CANCEL" | "BYE"
 */
int
sip_add_allow(sip_msg_t sip_msg, sip_method_t method)
{
	int	ret;

	if (method == 0 || method >= MAX_SIP_METHODS)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_ALLOW, sip_methods[method].name,
	    NULL, (char)NULL);
	return (ret);
}

/*
 * Call-Info   =  "Call-Info" HCOLON info *(COMMA info)
 * info        =  LAQUOT absoluteURI RAQUOT *( SEMI info-param)
 * info-param  =  ( "purpose" EQUAL ( "icon" / "info"
 *		/ "card" / token ) ) / generic-param
 */
int
sip_add_call_info(sip_msg_t sip_msg, char *uri, char *plist)
{
	char		*tmp;
	boolean_t	alloc;
	int		r;

	if (uri == NULL)
		return (EINVAL);
	tmp = sip_add_aquot_to_str(uri, &alloc);
	if (tmp == NULL)
		return (ENOMEM);
	r = sip_add_str_to_msg(sip_msg, SIP_CALL_INFO, tmp, plist, SIP_SEMI);
	if (alloc)
		free(tmp);
	return (r);
}

/*
 * Content-Disposition   =  "Content-Disposition" HCOLON
 *				disp-type *( SEMI disp-param )
 * disp-type             =  "render" / "session" / "icon" / "alert"
 *				/ disp-extension-token
 * disp-param            =  handling-param / generic-param
 * handling-param        =  "handling" EQUAL
 *				( "optional" / "required"
 *				/ other-handling )
 * other-handling        =  token
 * disp-extension-token  =  token
 */
int
sip_add_content_disp(sip_msg_t sip_msg, char *dis_type, char *plist)
{
	int	ret;

	if (dis_type == NULL)
		return (EINVAL);

	ret = sip_add_str_to_msg(sip_msg, SIP_CONTENT_DIS, dis_type, plist,
	    SIP_SEMI);
	return (ret);
}

/*
 * Content-Encoding  =  ( "Content-Encoding" / "e" ) HCOLON
 *			content-coding *(COMMA content-coding)
 * content-coding   =  token
 */
int
sip_add_content_enc(sip_msg_t sip_msg, char *code)
{
	int	ret;

	if (code == NULL)
		return (EINVAL);

	ret = sip_add_str_to_msg(sip_msg, SIP_CONTENT_ENCODE, code, NULL,
	    (char)NULL);
	return (ret);
}

/*
 * Content-Language  =  "Content-Language" HCOLON
 *			language-tag *(COMMA language-tag)
 * language-tag      =  primary-tag *( "-" subtag )
 * primary-tag       =  1*8ALPHA
 * subtag            =  1*8ALPHA
 */
int
sip_add_content_lang(sip_msg_t sip_msg, char *lang)
{
	int	ret;

	if (lang == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_CONTENT_LANG, lang, NULL,
	    (char)NULL);
	return (ret);
}

/*
 * Date          =  "Date" HCOLON SIP-date
 * SIP-date      =  rfc1123-date
 * rfc1123-date  =  wkday "," SP date1 SP time SP "GMT"
 * date1         =  2DIGIT SP month SP 4DIGIT
 * 			; day month year (e.g., 02 Jun 1982)
 * time          =  2DIGIT ":" 2DIGIT ":" 2DIGIT
 *			; 00:00:00 - 23:59:59
 * wkday         =  "Mon" / "Tue" / "Wed"
 *			/ "Thu" / "Fri" / "Sat" / "Sun"
 * month         =  "Jan" / "Feb" / "Mar" / "Apr"
 *			/ "May" / "Jun" / "Jul" / "Aug"
 *			/ "Sep" / "Oct" / "Nov" / "Dec"
 */
int
sip_add_date(sip_msg_t sip_msg, char *date)
{
	int	ret;

	if (date == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_DATE, date, NULL, (char)NULL);
	return (ret);
}

/*
 * Error-Info  =  "Error-Info" HCOLON error-uri *(COMMA error-uri)
 * error-uri   =  LAQUOT absoluteURI RAQUOT *( SEMI generic-param )
 */
int
sip_add_error_info(sip_msg_t sip_msg, char *uri, char *plist)
{
	char		*tmp;
	boolean_t	alloc;
	int		r;

	if (uri == NULL)
		return (EINVAL);
	tmp = sip_add_aquot_to_str(uri, &alloc);
	if (tmp == NULL)
		return (EINVAL);

	r = sip_add_str_to_msg(sip_msg, SIP_ERROR_INFO, tmp, plist, SIP_SEMI);
	if (alloc)
		free(tmp);
	return (r);
}

/*
 * Expires     =  "Expires" HCOLON delta-seconds
 * delta-seconds      =  1*DIGIT
 */
int
sip_add_expires(sip_msg_t sip_msg, int secs)
{
	int	ret;

	if (sip_msg == NULL || (int)secs < 0)
		return (EINVAL);

	ret = sip_add_int_to_msg(sip_msg, SIP_EXPIRE, secs, NULL);
	return (ret);
}

/*
 * In-Reply-To  =  "In-Reply-To" HCOLON callid *(COMMA callid)
 * callid   =  word [ "@" word ]
 */
int
sip_add_in_reply_to(sip_msg_t sip_msg, char *reply_id)
{
	int		r;

	if (reply_id == NULL)
		return (EINVAL);
	r = sip_add_str_to_msg(sip_msg, SIP_IN_REPLY_TO, reply_id, NULL,
	    (char)NULL);
	return (r);
}

/*
 * RSeq          =  "RSeq" HCOLON response-num
 */
int
sip_add_rseq(sip_msg_t sip_msg, int resp_num)
{
	int	ret;

	if (sip_msg == NULL || resp_num <= 0)
		return (EINVAL);
	ret = sip_add_int_to_msg(sip_msg, SIP_RSEQ, resp_num, NULL);
	return (ret);
}

/*
 * Min-Expires  =  "Min-Expires" HCOLON delta-seconds
 */
int
sip_add_min_expires(sip_msg_t sip_msg, int secs)
{
	int	ret;

	if (sip_msg == NULL || (int)secs < 0)
		return (EINVAL);
	ret = sip_add_int_to_msg(sip_msg, SIP_MIN_EXPIRE, secs, NULL);
	return (ret);
}

/*
 * MIME-Version  =  "MIME-Version" HCOLON 1*DIGIT "." 1*DIGIT
 */
int
sip_add_mime_version(sip_msg_t sip_msg, char *version)
{
	int	ret;

	if (version == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_MIME_VERSION, version, NULL,
	    (char)NULL);
	return (ret);
}

/*
 * Organization  =  "Organization" HCOLON [TEXT-UTF8-TRIM]
 */
int
sip_add_org(sip_msg_t sip_msg, char *org)
{
	int	ret;

	if (org == NULL) {
		ret = sip_add_empty_hdr(sip_msg, SIP_ORGANIZATION);
	} else {
		ret = sip_add_str_to_msg(sip_msg, SIP_ORGANIZATION, org, NULL,
		    (char)NULL);
	}
	return (ret);
}

/*
 * Priority        =  "Priority" HCOLON priority-value
 * priority-value  =  "emergency" / "urgent" / "normal"
 *			/ "non-urgent" / other-priority
 * other-priority  =  token
 */
int
sip_add_priority(sip_msg_t sip_msg, char *prio)
{
	int	ret;

	if (prio == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_PRIORITY, prio, NULL, (char)NULL);

	return (ret);
}

/*
 * Reply-To      =  "Reply-To" HCOLON rplyto-spec
 * rplyto-spec   =  ( name-addr / addr-spec )
 *			*( SEMI rplyto-param )
 * rplyto-param  =  generic-param
 */
int
sip_add_reply_to(sip_msg_t sip_msg, char *uname, char *addr, char *plist,
    boolean_t add_aquot)
{
	return (sip_add_name_aspec(sip_msg, uname, addr, NULL, add_aquot,
	    SIP_REPLYTO, plist));
}


/*
 * Privacy-hdr  =  "Privacy" HCOLON priv-value *(";" priv-value)
 * priv-value   =   "header" / "session" / "user" / "none" / "critical"
 *			/ token
 */
int
sip_add_privacy(sip_msg_t sip_msg, char *priv_val)
{
	int	ret;

	if (priv_val == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_PRIVACY, priv_val, NULL,
	    (char)NULL);
	return (ret);
}

/*
 * Require       =  "Require" HCOLON option-tag *(COMMA option-tag)
 * option-tag     =  token
 */
int
sip_add_require(sip_msg_t sip_msg, char *req)
{
	int	ret;

	if (req == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_REQUIRE, req, NULL, (char)NULL);
	return (ret);
}

/*
 * Retry-After  =  "Retry-After" HCOLON delta-seconds
 *			[ comment ] *( SEMI retry-param )
 * retry-param  =  ("duration" EQUAL delta-seconds)
 *			/ generic-param
 */
int
sip_add_retry_after(sip_msg_t sip_msg, int secs, char *cmt, char *plist)
{
	int	r;

	if (secs <= 0)
		return (EINVAL);

	if (cmt == NULL) {
		r = sip_add_int_to_msg(sip_msg, SIP_RETRY_AFTER, secs, plist);
		return (r);
	}

	r = sip_add_intstr_to_msg(sip_msg, SIP_RETRY_AFTER, secs, cmt, plist);
	return (r);
}

/*
 * Server           =  "Server" HCOLON server-val *(LWS server-val)
 * server-val       =  product / comment
 * product          =  token [SLASH product-version]
 * product-version  =  token
 */
int
sip_add_server(sip_msg_t sip_msg, char *svr)
{
	int	ret;

	if (svr == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_SERVER, svr, NULL, (char)NULL);
	return (ret);
}

/*
 * Subject  =  ( "Subject" / "s" ) HCOLON [TEXT-UTF8-TRIM]
 */
int
sip_add_subject(sip_msg_t sip_msg, char *subject)
{
	int	ret;

	if (subject == NULL) {
		ret = sip_add_empty_hdr(sip_msg, SIP_SUBJECT);
	} else {
		ret = sip_add_str_to_msg(sip_msg, SIP_SUBJECT, subject, NULL,
		    (char)NULL);
	}
	return (ret);
}

/*
 * Supported  =  ( "Supported" / "k" ) HCOLON
 *		[option-tag *(COMMA option-tag)]
 */
int
sip_add_supported(sip_msg_t sip_msg, char *support)
{
	int	ret;

	if (support == NULL) {
		ret = sip_add_empty_hdr(sip_msg, SIP_SUPPORT);
	} else {
		ret = sip_add_str_to_msg(sip_msg, SIP_SUPPORT, support, NULL,
		    (char)NULL);
	}
	return (ret);
}

/*
 * Timestamp  =  "Timestamp" HCOLON 1*(DIGIT)
 *		[ "." *(DIGIT) ] [ LWS delay ]
 * delay      =  *(DIGIT) [ "." *(DIGIT) ]
 */
int
sip_add_tstamp(sip_msg_t sip_msg, char *time, char *delay)
{
	int	ret;

	if (delay == NULL) {
		ret = sip_add_str_to_msg(sip_msg, SIP_TIMESTAMP, time, NULL,
		    (char)NULL);
	} else {
		ret = sip_add_2strs_to_msg(sip_msg, SIP_TIMESTAMP, time,
		    B_FALSE, delay, NULL, ' ');
	}
	return (ret);
}

/*
 * Unsupported  =  "Unsupported" HCOLON option-tag *(COMMA option-tag)
 */
int
sip_add_unsupported(sip_msg_t sip_msg, char *unsupport)
{
	int	ret;

	if (unsupport == NULL)
		return (EINVAL);
	ret = sip_add_str_to_msg(sip_msg, SIP_UNSUPPORT, unsupport, NULL,
	    (char)NULL);
	return (ret);
}

/*
 * User-Agent  =  "User-Agent" HCOLON server-val *(LWS server-val)
 */
int
sip_add_user_agent(sip_msg_t sip_msg, char *usr)
{
	int	r;

	if (usr == NULL)
		return (EINVAL);
	r = sip_add_str_to_msg(sip_msg, SIP_USER_AGENT, usr, NULL, (char)NULL);
	return (r);
}

/*
 * Warning        =  "Warning" HCOLON warning-value *(COMMA warning-value)
 * warning-value  =  warn-code SP warn-agent SP warn-text
 * warn-code      =  3DIGIT
 * warn-agent     =  hostport / pseudonym
 *			;  the name or pseudonym of the server adding
 *			;  the Warning header, for use in debugging
 * warn-text      =  quoted-string
 * pseudonym      =  token
 */
int
sip_add_warning(sip_msg_t sip_msg, int code, char *addr, char *msg)
{
	_sip_header_t	*new_header;
	int 		header_size;
	_sip_msg_t 	*_sip_msg;
	char		*hdr_name = SIP_WARNING;

	if (sip_msg == NULL || addr == NULL || msg == NULL ||
	    addr[0] == '\0' || msg[0] == '\0' || code < 100 || code > 999) {
		return (EINVAL);
	}

	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	header_size = strlen(hdr_name) + SIP_SPACE_LEN + sizeof (char) +
	    SIP_SPACE_LEN + sip_num_of_digits(code) + SIP_SPACE_LEN +
	    strlen(addr) + SIP_SPACE_LEN + sizeof (char) + strlen(msg) +
	    sizeof (char) + strlen(SIP_CRLF);

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}

	(void) snprintf(new_header->sip_hdr_start, header_size + 1,
	    "%s %c %d %s \"%s\"%s", hdr_name, SIP_HCOLON, code, addr,
	    msg, SIP_CRLF);
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (0);
}

/*
 * RAck          =  "RAck" HCOLON response-num LWS CSeq-num LWS Method
 * response-num  =  1*DIGIT
 * CSeq-num      =  1*DIGIT
 */
int
sip_add_rack(sip_msg_t sip_msg, int resp_num, int cseq, sip_method_t method)
{
	_sip_header_t	*new_header;
	int 		header_size;
	_sip_msg_t 	*_sip_msg;
	char		*hdr_name = SIP_RACK;

	if (sip_msg == NULL || resp_num <= 0 || cseq < 0 || method <= 0 ||
	    method >= MAX_SIP_METHODS) {
		return (EINVAL);
	}

	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	header_size = strlen(hdr_name) + SIP_SPACE_LEN + sizeof (char) +
	    SIP_SPACE_LEN + sip_num_of_digits(resp_num) + SIP_SPACE_LEN +
	    sip_num_of_digits(cseq) + SIP_SPACE_LEN +
	    strlen(sip_methods[method].name) + strlen(SIP_CRLF);

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}

	(void) snprintf(new_header->sip_hdr_start, header_size + 1,
	    "%s %c %d %d %s%s", hdr_name, SIP_HCOLON, resp_num, cseq,
	    sip_methods[method].name, SIP_CRLF);

	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (0);

}

/*
 * Allow-Events =  ( "Allow-Events" / "u" ) HCOLON event-type
 *			*(COMMA event-type)
 */
int
sip_add_allow_events(sip_msg_t sip_msg, char *t_event)
{
	return (sip_add_str_to_msg(sip_msg, SIP_ALLOW_EVENTS, t_event, NULL,
	    (char)NULL));
}

/*
 * Event             =  ( "Event" / "o" ) HCOLON event-type
 *			*( SEMI event-param )
 * event-type        =  event-package *( "." event-template )
 * event-package     =  token-nodot
 * event-template    =  token-nodot
 * token-nodot       =  1*( alphanum / "-"  / "!" / "%" / "*"
 *			/ "_" / "+" / "`" / "'" / "~" )
 * event-param       =  generic-param / ( "id" EQUAL token )
 */
int
sip_add_event(sip_msg_t sip_msg, char *t_event, char *plist)
{
	return (sip_add_str_to_msg(sip_msg, SIP_EVENT, t_event, plist,
	    SIP_SEMI));
}

/*
 * Subscription-State   = "Subscription-State" HCOLON substate-value
 * 			*( SEMI subexp-params )
 * substate-value       = "active" / "pending" / "terminated"
 *			/ extension-substate
 * extension-substate   = token
 * subexp-params        =   ("reason" EQUAL event-reason-value)
 *			/ ("expires" EQUAL delta-seconds)*
 * 			/ ("retry-after" EQUAL delta-seconds)
 *			/ generic-param
 * event-reason-value   =   "deactivated"
 *				/ "probation"
 *				/ "rejected"
 *				/ "timeout"
 *				/ "giveup"
 *				/ "noresource"
 *				/ event-reason-extension
 * event-reason-extension = token
 */
int
sip_add_substate(sip_msg_t sip_msg, char *sub, char *plist)
{
	return (sip_add_str_to_msg(sip_msg, SIP_SUBSCRIPTION_STATE, sub, plist,
	    SIP_SEMI));
}

/*
 * Authorization     =  "Authorization" HCOLON credentials
 * credentials       =  ("Digest" LWS digest-response)
 *			/ other-response
 * digest-response   =  dig-resp *(COMMA dig-resp)
 * dig-resp          =  username / realm / nonce / digest-uri
 *			/ dresponse / algorithm / cnonce
 *			/ opaque / message-qop
 *			/ nonce-count / auth-param
 * username          =  "username" EQUAL username-value
 * username-value    =  quoted-string
 * digest-uri        =  "uri" EQUAL LDQUOT digest-uri-value RDQUOT
 * digest-uri-value  =  rquest-uri ; Equal to request-uri as specified
 *			by HTTP/1.1
 * message-qop       =  "qop" EQUAL qop-value
 * cnonce            =  "cnonce" EQUAL cnonce-value
 * cnonce-value      =  nonce-value
 * nonce-count       =  "nc" EQUAL nc-value
 * nc-value          =  8LHEX
 * dresponse         =  "response" EQUAL request-digest
 * request-digest    =  LDQUOT 32LHEX RDQUOT
 * auth-param        =  auth-param-name EQUAL
 * 			( token / quoted-string )
 * auth-param-name   =  token
 * other-response    =  auth-scheme LWS auth-param
 *			*(COMMA auth-param)
 * auth-scheme       =  token
 */
int
sip_add_author(sip_msg_t sip_msg, char *scheme, char *param)
{
	return (sip_add_str_to_msg(sip_msg, SIP_AUTHOR, scheme, param, SIP_SP));
}

/*
 * Authentication-Info  =  "Authentication-Info" HCOLON ainfo
 *				*(COMMA ainfo)
 * ainfo                =  nextnonce / message-qop
 *				/ response-auth / cnonce
 *				/ nonce-count
 * nextnonce            =  "nextnonce" EQUAL nonce-value
 * response-auth        =  "rspauth" EQUAL response-digest
 * response-digest      =  LDQUOT *LHEX RDQUOT
 */
int
sip_add_authen_info(sip_msg_t sip_msg, char *ainfo)
{
	return (sip_add_str_to_msg(sip_msg, SIP_AUTHEN_INFO, ainfo, NULL,
	    (char)NULL));
}

/*
 * Proxy-Authenticate  =  "Proxy-Authenticate" HCOLON challenge
 * challenge           =  ("Digest" LWS digest-cln *(COMMA digest-cln))
 *				/ other-challenge
 * other-challenge     =  auth-scheme LWS auth-param
 * 				*(COMMA auth-param)
 * digest-cln          =  realm / domain / nonce
 *				/ opaque / stale / algorithm
 *				/ qop-options / auth-param
 * realm               =  "realm" EQUAL realm-value
 * realm-value         =  quoted-string
 * domain              =  "domain" EQUAL LDQUOT URI
 *				*( 1*SP URI ) RDQUOT
 * URI                 =  absoluteURI / abs-path
 * nonce               =  "nonce" EQUAL nonce-value
 * nonce-value         =  quoted-string
 * opaque              =  "opaque" EQUAL quoted-string
 * stale               =  "stale" EQUAL ( "true" / "false" )
 * algorithm           =  "algorithm" EQUAL ( "MD5" / "MD5-sess"
 *			/ token )
 * qop-options         =  "qop" EQUAL LDQUOT qop-value
 *			*("," qop-value) RDQUOT
 * qop-value           =  "auth" / "auth-int" / token
 */
int
sip_add_proxy_authen(sip_msg_t sip_msg, char *pascheme, char *paparam)
{
	return (sip_add_str_to_msg(sip_msg, SIP_PROXY_AUTHEN, pascheme, paparam,
	    SIP_SP));
}

/*
 * Proxy-Authorization  =  "Proxy-Authorization" HCOLON credentials
 */
int
sip_add_proxy_author(sip_msg_t sip_msg, char *paschem, char *paparam)
{
	return (sip_add_str_to_msg(sip_msg, SIP_PROXY_AUTHOR, paschem, paparam,
	    SIP_SP));
}

/*
 * Proxy-Require  =  "Proxy-Require" HCOLON option-tag
 *			*(COMMA option-tag)
 * option-tag     =  token
 */
int
sip_add_proxy_require(sip_msg_t sip_msg, char *opt)
{
	return (sip_add_str_to_msg(sip_msg, SIP_PROXY_REQ, opt, NULL,
	    (char)NULL));
}

/*
 * WWW-Authenticate  =  "WWW-Authenticate" HCOLON challenge
 * extension-header  =  header-name HCOLON header-value
 * header-name       =  token
 * header-value      =  *(TEXT-UTF8char / UTF8-CONT / LWS)
 * message-body  =  *OCTET
 */
int
sip_add_www_authen(sip_msg_t sip_msg, char *wascheme, char *waparam)
{
	return (sip_add_str_to_msg(sip_msg, SIP_WWW_AUTHEN, wascheme, waparam,
	    SIP_SP));
}

/*
 * Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
 */
int
sip_add_callid(sip_msg_t sip_msg, char *callid)
{
	int		ret;
	boolean_t	allocd = B_FALSE;

	if (sip_msg == NULL || (callid != NULL && callid[0] == '\0'))
		return (EINVAL);
	if (callid == NULL) {
		callid = (char *)sip_guid();
		if (callid == NULL)
			return (ENOMEM);
		allocd = B_TRUE;
	}
	ret = sip_add_str_to_msg(sip_msg, SIP_CALL_ID, callid, NULL,
	    (char)NULL);
	if (allocd)
		free(callid);
	return (ret);
}

/*
 * CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method
 */
int
sip_add_cseq(sip_msg_t sip_msg, sip_method_t method, uint32_t cseq)
{
	int	r;

	if (sip_msg == NULL || (int)cseq < 0 || method == 0 ||
	    method >= MAX_SIP_METHODS) {
		return (EINVAL);
	}
	r = sip_add_intstr_to_msg(sip_msg, SIP_CSEQ, cseq,
	    sip_methods[method].name, NULL);
	return (r);
}

/*
 * Via =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
 * via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
 * via-params        =  via-ttl / via-maddr
 *                      / via-received / via-branch
 *                      / via-extension
 * via-ttl           =  "ttl" EQUAL ttl
 * via-maddr         =  "maddr" EQUAL host
 * via-received      =  "received" EQUAL (IPv4address / IPv6address)
 * via-branch        =  "branch" EQUAL token
 * via-extension     =  generic-param
 * sent-protocol     =  protocol-name SLASH protocol-version
 *                      SLASH transport
 * protocol-name     =  "SIP" / token
 * protocol-version  =  token
 * transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
 *                      / other-transport
 * sent-by           =  host [ COLON port ]
 * ttl               =  1*3DIGIT ; 0 to 255
 */
_sip_header_t *
sip_create_via_hdr(char *sent_protocol_transport, char *sent_by_host,
    int sent_by_port, char *via_params)
{
	_sip_header_t	*new_header;
	int		header_size;
	int		count;

	header_size = strlen(SIP_VIA) + SIP_SPACE_LEN + sizeof (char) +
	    SIP_SPACE_LEN + strlen(SIP_VERSION) + sizeof (char) +
	    strlen(sent_protocol_transport) + SIP_SPACE_LEN +
	    strlen(sent_by_host) + strlen(SIP_CRLF);

	if (sent_by_port > 0) {
		header_size += SIP_SPACE_LEN + sizeof (char) + SIP_SPACE_LEN +
		    sip_num_of_digits(sent_by_port);
	}

	if (via_params != NULL) {
		header_size += SIP_SPACE_LEN + sizeof (char) +
		    strlen(via_params);
	}
	new_header = sip_new_header(header_size);
	if (new_header->sip_hdr_start == NULL)
		return (NULL);
	count = snprintf(new_header->sip_hdr_current, header_size + 1,
	    "%s %c %s/%s %s",
	    SIP_VIA, SIP_HCOLON, SIP_VERSION, sent_protocol_transport,
	    sent_by_host);
	new_header->sip_hdr_current += count;
	header_size -= count;

	if (sent_by_port > 0) {
		count = snprintf(new_header->sip_hdr_current, header_size + 1,
		    " %c %d", SIP_HCOLON, sent_by_port);
		new_header->sip_hdr_current += count;
		header_size -= count;
	}

	if (via_params != NULL) {
		count = snprintf(new_header->sip_hdr_current, header_size + 1,
		    " %c%s", SIP_SEMI, via_params);
		new_header->sip_hdr_current += count;
		header_size -= count;
	}

	(void) snprintf(new_header->sip_hdr_current, header_size + 1,
	    "%s", SIP_CRLF);
	return (new_header);
}

/*
 * There can be multiple via headers we always append the header.
 * We expect the via params to be a semi-colon separated list of parameters.
 * We will add a semi-clone, before adding the list to the header.
 */
int
sip_add_via(sip_msg_t sip_msg, char *sent_protocol_transport,
    char *sent_by_host, int sent_by_port, char *via_params)
{
	_sip_header_t	*new_header;
	_sip_msg_t	*_sip_msg;

	if (sip_msg == NULL || sent_protocol_transport == NULL ||
	    sent_by_host == NULL || sent_by_port < 0) {
		return (EINVAL);
	}

	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	new_header = sip_create_via_hdr(sent_protocol_transport, sent_by_host,
	    sent_by_port, via_params);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (0);
}

/*
 * Max-Forwards  =  "Max-Forwards" HCOLON 1*DIGIT
 */
int
sip_add_maxforward(sip_msg_t sip_msg, uint_t maxforward)
{
	if (sip_msg == NULL || (int)maxforward < 0)
		return (EINVAL);
	return (sip_add_int_to_msg(sip_msg, SIP_MAX_FORWARDS, maxforward,
	    NULL));
}

/*
 * Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
 * media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
 * m-type           =  discrete-type / composite-type
 * discrete-type    =  "text" / "image" / "audio" / "video"
 *			/ "application" / extension-token
 * composite-type   =  "message" / "multipart" / extension-token
 * extension-token  =  ietf-token / x-token
 * ietf-token       =  token
 * x-token          =  "x-" token
 * m-subtype        =  extension-token / iana-token
 * iana-token       =  token
 * m-parameter      =  m-attribute EQUAL m-value
 * m-attribute      =  token
 * m-value          =  token / quoted-string
 */
int
sip_add_content_type(sip_msg_t sip_msg, char *type, char *subtype)
{
	if (sip_msg == NULL || type == NULL || subtype == NULL)
		return (EINVAL);
	return (sip_add_2strs_to_msg(sip_msg, SIP_CONTENT_TYPE, type, B_FALSE,
	    subtype, NULL, SIP_SLASH));
}

/*
 * Content-Length  =  ( "Content-Length" / "l" ) HCOLON 1*DIGIT
 */
int
sip_add_content_length(_sip_msg_t *_sip_msg, int length)
{
	_sip_header_t	*new_header;
	int 		header_size;

	if (_sip_msg == NULL || length < 0)
		return (EINVAL);
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	header_size = strlen(SIP_CONTENT_LENGTH) + SIP_SPACE_LEN +
	    sizeof (char) + SIP_SPACE_LEN + sip_num_of_digits(length) +
	    strlen(SIP_CRLF) + strlen(SIP_CRLF);

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}
	(void) snprintf(new_header->sip_hdr_start, header_size + 1,
	    "%s %c %u%s%s", SIP_CONTENT_LENGTH, SIP_HCOLON, length,
	    SIP_CRLF, SIP_CRLF);

	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (0);
}


/*
 * Contact = ("Contact" / "m" ) HCOLON
 *		( STAR / (contact-param *(COMMA contact-param)))
 * contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
 * name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
 * addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
 * display-name   =  *(token LWS)/ quoted-string
 * contact-params     =  c-p-q / c-p-expires
 *                     / contact-extension
 */
int
sip_add_contact(sip_msg_t sip_msg, char *display_name, char *contact_uri,
    boolean_t add_aquot, char *contact_params)
{
	return (sip_add_name_aspec(sip_msg, display_name, contact_uri, NULL,
	    add_aquot, SIP_CONTACT, contact_params));
}

/*
 * From =  ( "From" / "f" ) HCOLON from-spec
 * from-spec = ( name-addr / addr-spec )
 *	*( SEMI from-param )
 * from-param  =  tag-param / generic-param
 * tag-param   =  "tag" EQUAL token
 *
 * Since there can be more than one tags, fromtags is a semi colon separated
 * list of tags.
 */
int
sip_add_from(sip_msg_t sip_msg, char *display_name, char *from_uri,
    char *fromtags, boolean_t add_aquot, char *from_params)
{
	return (sip_add_name_aspec(sip_msg, display_name, from_uri, fromtags,
	    add_aquot, SIP_FROM, from_params));
}

/*
 * To =  ( "To" / "t" ) HCOLON ( name-addr
 *	/ addr-spec ) *( SEMI to-param )
 * to-param  =  tag-param / generic-param
 */
int
sip_add_to(sip_msg_t sip_msg, char *display_name, char *to_uri,
    char *totags, boolean_t add_aquot, char *to_params)
{
	return (sip_add_name_aspec(sip_msg, display_name, to_uri, totags,
	    add_aquot, SIP_TO, to_params));
}

/*
 * Route        =  "Route" HCOLON route-param *(COMMA route-param)
 * route-param  =  name-addr *( SEMI rr-param )
 */
int
sip_add_route(sip_msg_t sip_msg, char *display_name, char *uri,
    char *route_params)
{
	return (sip_add_name_aspec(sip_msg, display_name, uri, NULL, B_TRUE,
	    SIP_ROUTE, route_params));
}

/*
 * Record-Route  =  "Record-Route" HCOLON rec-route *(COMMA rec-route)
 * rec-route     =  name-addr *( SEMI rr-param )
 * rr-param      =  generic-param
 */
int
sip_add_record_route(sip_msg_t sip_msg, char *display_name, char *uri,
    char *route_params)
{
	return (sip_add_name_aspec(sip_msg, display_name, uri, NULL, B_TRUE,
	    SIP_RECORD_ROUTE, route_params));
}


/*
 * PAssertedID = "P-Asserted-Identity" HCOLON PAssertedID-value
 *			*(COMMA PAssertedID-value)
 * PAssertedID-value = name-addr / addr-spec
 */
int
sip_add_passertedid(sip_msg_t sip_msg, char *display_name, char *addr,
    boolean_t add_aquot)
{
	return (sip_add_name_aspec(sip_msg, display_name, addr, NULL, add_aquot,
	    SIP_PASSERTEDID, NULL));
}

/*
 * PPreferredID = "P-Preferred-Identity" HCOLON PPreferredID-value
 *			*(COMMA PPreferredID-value)
 * PPreferredID-value = name-addr / addr-spec
 */
int
sip_add_ppreferredid(sip_msg_t sip_msg, char *display_name, char *addr,
    boolean_t add_aquot)
{
	return (sip_add_name_aspec(sip_msg, display_name, addr, NULL, add_aquot,
	    SIP_PPREFERREDID, NULL));
}
