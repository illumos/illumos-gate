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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <strings.h>
#include <sip.h>

#include "sip_miscdefs.h"

/*
 * Local version of case insensitive strstr().
 */
static char *
sip_reass_strstr(const char *as1, const char *as2)
{
	const char	*s1;
	const char	*s2;
	const char	*tptr;
	char	c;

	s1 = as1;
	s2 = as2;

	if (s2 == NULL || *s2 == '\0')
		return ((char *)s1);
	c = *s2;

	while (*s1)
		if (tolower(*s1++) == c) {
			tptr = s1;
			while ((c = *++s2) == tolower(*s1++) && c)
				;
			if (c == 0)
				return ((char *)tptr - 1);
			s1 = tptr;
			s2 = as2;
			c = *s2;
		}

	return (NULL);
}

/*
 * Get the value in the content-length field and add it to the header length
 * and return the total length. returns -1 if the length cannot be determined
 * or if the message does not contain the entire message.
 */
static int
sip_get_msglen(char *p, size_t msglen)
{
	int	value = 0;
	int 	hlen;
	char	*c;
	char	*e;
	int	base = 10;
	char	*edge;
	int	digits = 0;

	edge = p + msglen;
	if ((c = sip_reass_strstr(p, "content-length")) == NULL)
		return (-1);
	hlen = c - p;
	if ((hlen +  strlen("content-length")) >= msglen)
		return (-1);
	c += strlen("content-length");
	e = c + 1;
	while (*e == ' ' || *e == ':') {
		e++;
		if (e == edge)
			return (-1);
	}
	while (*e  != '\r' && *e != ' ') {
		if (e == edge)
			return (-1);
		if (*e >= '0' && *e <= '9')
			digits = *e - '0';
		else
			return (-1);
		value = (value * base) + digits;
		e++;
	}
	while (*e != '\r') {
		e++;
		if (e == edge)
			return (-1);
	}
	hlen = e - p + 4;	/* 4 for 2 CRLFs ?? */
	value += hlen;

	return (value);
}

/*
 * We have determined that msg does not contain a *single* complete message.
 * Add it to the reassembly list and check if we have a complete message.
 * a NULL 'msg' means we are just checking if there are more complete
 * messages in the list that can be passed up.
 */
char *
sip_get_tcp_msg(sip_conn_object_t obj, char *msg, size_t *msglen)
{
	int			value;
	sip_conn_obj_pvt_t	*pvt_data;
	sip_reass_entry_t	*reass;
	void			**obj_val;
	char			*msgbuf = NULL;
	int			splitlen;
	char			*splitbuf;

	if (msg != NULL) {
		assert(*msglen > 0);
		msgbuf = (char *)malloc(*msglen + 1);
		if (msgbuf == NULL)
			return (NULL);
		(void) strncpy(msgbuf, msg, *msglen);
		msgbuf[*msglen] = '\0';
		msg = msgbuf;
	}
	obj_val = (void *)obj;
	pvt_data = (sip_conn_obj_pvt_t *)*obj_val;
	/*
	 * connection object not initialized
	 */
	if (pvt_data == NULL) {
		if (msg == NULL)
			return (NULL);
		value = sip_get_msglen(msg, *msglen);
		if (value == *msglen) {
			return (msg);
		} else {
			if (msgbuf != NULL)
				free(msgbuf);
			return (NULL);
		}
	}
	(void) pthread_mutex_lock(&pvt_data->sip_conn_obj_reass_lock);
	reass = pvt_data->sip_conn_obj_reass;
	assert(reass != NULL);
	if (reass->sip_reass_msg == NULL) {
		assert(reass->sip_reass_msglen == 0);
		if (msg == NULL) {
			(void) pthread_mutex_unlock(
			    &pvt_data->sip_conn_obj_reass_lock);
			return (NULL);
		}
		value = sip_get_msglen(msg, *msglen);
		if (value == *msglen) {
			(void) pthread_mutex_unlock(
			    &pvt_data->sip_conn_obj_reass_lock);
			return (msg);
		}
		reass->sip_reass_msg = msg;
		reass->sip_reass_msglen = *msglen;
		if (value != -1 && value < reass->sip_reass_msglen)
			goto tryone;
		(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_reass_lock);
		return (NULL);
	} else if (msg != NULL) {
		/*
		 * Resize, not optimal
		 */
		int	newlen = reass->sip_reass_msglen + *msglen;
		char	*newmsg;

		assert(strlen(reass->sip_reass_msg) == reass->sip_reass_msglen);
		newmsg = malloc(newlen + 1);
		if (newmsg == NULL) {
			(void) pthread_mutex_unlock(
			    &pvt_data->sip_conn_obj_reass_lock);
			if (msgbuf != NULL)
				free(msgbuf);
			return (NULL);
		}
		(void) strncpy(newmsg, reass->sip_reass_msg,
		    reass->sip_reass_msglen);
		newmsg[reass->sip_reass_msglen] = '\0';
		(void) strncat(newmsg, msg, *msglen);
		newmsg[newlen] = '\0';
		assert(strlen(newmsg) == newlen);
		reass->sip_reass_msglen = newlen;
		free(msg);
		free(reass->sip_reass_msg);
		reass->sip_reass_msg = newmsg;
	}
	value = sip_get_msglen(reass->sip_reass_msg, reass->sip_reass_msglen);
	if (value == -1 || value >  reass->sip_reass_msglen) {
		(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_reass_lock);
		return (NULL);
	}
tryone:
	if (value == reass->sip_reass_msglen) {
		msg = reass->sip_reass_msg;
		*msglen = reass->sip_reass_msglen;
		reass->sip_reass_msg = NULL;
		reass->sip_reass_msglen = 0;
		(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_reass_lock);
		return (msg);
	}
	splitlen = reass->sip_reass_msglen - value;
	msg = (char *)malloc(value + 1);
	splitbuf = (char *)malloc(splitlen + 1);
	if (msg == NULL || splitbuf == NULL) {
		if (msg != NULL)
			free(msg);
		if (splitbuf != NULL)
			free(splitbuf);
		(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_reass_lock);
		return (NULL);
	}
	(void) strncpy(msg, reass->sip_reass_msg, value);
	msg[value] = '\0';
	(void) strncpy(splitbuf, reass->sip_reass_msg + value, splitlen);
	splitbuf[splitlen] = '\0';
	free(reass->sip_reass_msg);
	reass->sip_reass_msg = splitbuf;
	reass->sip_reass_msglen = splitlen;
	(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_reass_lock);
	*msglen = value;
	return (msg);
}
