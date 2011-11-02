/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ldap_util.h"
#include "ldap_glob.h"

static time_t	msgtime[MSG_LASTMSG] = {0};
static time_t	msgtimeout = 3600;

static pthread_key_t		tsdKey;

/*
 * Log a message to the appropriate place.
 */
void
logmsg(int msgtype, int priority, const char *fmt, ...) {
	va_list		ap;
	struct timeval	tp;

	/*
	 * Only log LOG_INFO priority if 'verbose' is on, or if
	 * msgtype is MSG_ALWAYS.
	 */
	if (priority == LOG_INFO && !verbose && msgtype != MSG_ALWAYS)
		return;

	/* Make sure we don't log the same message too often */
	if (msgtype != MSG_NOTIMECHECK && msgtype != MSG_ALWAYS &&
			msgtype > 0 && msgtype < MSG_LASTMSG &&
			gettimeofday(&tp, 0) != -1) {
		if (tp.tv_sec - msgtime[msgtype] < msgtimeout)
			return;
		msgtime[msgtype] = tp.tv_sec;
	}

	va_start(ap, fmt);
	if (cons == 0) {
		vsyslog(priority, fmt, ap);
	} else {
		int	flen = slen(fmt);

		vfprintf(cons, fmt, ap);
		/*
		 * If the last character in 'fmt' wasn't a '\n', write one
		 * to the console.
		 */
		if (flen > 0 && fmt[flen-1] != '\n')
			fprintf(cons, "\n");
	}
	va_end(ap);
}

void
__destroyTsdKey(void *arg) {
	__nis_deferred_error_t	*defErr = arg;

	if (defErr != 0) {
		sfree(defErr->message);
		free(defErr);
	}
}

static void
__initTsdKey(void)
{
	(void) pthread_key_create(&tsdKey, __destroyTsdKey);
}
#pragma init(__initTsdKey)

void
reportError(int error, char *fmt, ...) {
	__nis_deferred_error_t	*defErr = pthread_getspecific(tsdKey);
	int			doStore = (defErr == 0);
	char			*myself = "reportError";
	va_list			ap;
	__nis_buffer_t		b = {0, 0};

	if (defErr == 0 && (defErr = am(myself, sizeof (*defErr))) == 0)
		return;

	va_start(ap, fmt);
	b.len = vp2buf(myself, &b.buf, b.len, fmt, ap);
	va_end(ap);

	if (b.len > 0) {
		defErr->error = error;
		defErr->message = b.buf;
		if (doStore) {
			int	ret = pthread_setspecific(tsdKey, defErr);
			if (ret != 0) {
				logmsg(MSG_TSDERR, LOG_ERR,
					"%s: pthread_setspecific() => %d",
					myself, ret);
				sfree(b.buf);
				free(defErr);
			}
		}
	}
}

int
getError(char **message) {
	__nis_deferred_error_t	*defErr = pthread_getspecific(tsdKey);
	char			*myself = "getError";

	if (defErr == 0) {
		if (message != 0)
			*message = sdup(myself, T, "no TSD");
		return (NPL_TSDERR);
	}

	if (message != 0)
		*message = sdup(myself, T, defErr->message);

	return (defErr->error);
}

void
clearError(void) {
	__nis_deferred_error_t	*defErr = pthread_getspecific(tsdKey);

	if (defErr != 0) {
		sfree(defErr->message);
		defErr->message = 0;
		defErr->error = NPL_NOERROR;
	}
}

void
logError(int priority) {
	__nis_deferred_error_t	*defErr = pthread_getspecific(tsdKey);
	int			msgtype;

	if (defErr != 0) {
		switch (defErr->error) {
		case NPL_NOERROR:
			msgtype = MSG_LASTMSG;
			break;
		case NPL_NOMEM:
			msgtype = MSG_NOMEM;
			break;
		case NPL_TSDERR:
			msgtype = MSG_TSDERR;
			break;
		case NPL_BERENCODE:
		case NPL_BERDECODE:
			msgtype = MSG_BER;
			break;
		default:
			msgtype = MSG_LASTMSG;
			break;
		}

		if (msgtype != MSG_LASTMSG) {
			logmsg(msgtype, priority, defErr->message);
		}
	}
}

/*
 * Allocate zero-initialized memory of the specified 'size'. If the
 * allocation fails, log a message and return NULL. Allocation of
 * zero bytes is legal, and returns a NULL pointer.
 */
void *
am(const char *msg, int size) {
	void	*p;

	if (size > 0) {
		p = calloc(1, size);
		if (p == 0) {
			if (msg == 0)
				msg = "<unknown>";
			logmsg(MSG_NOMEM, LOG_ERR, "%s: calloc(%d) => NULL\n",
				msg, size);
			return (0);
		}
	} else if (size == 0) {
		p = 0;
	} else {
		if (msg == 0)
			msg = "<unknown>";
		logmsg(MSG_MEMPARAM, LOG_INFO, "%s: size (%d) < 0\n", size);
		exit(-1);
	}
	return (p);
}

/*
 * Return the length of a string, just like strlen(), but don't croak
 * on a NULL pointer.
 */
int
slen(const char *str) {
	return ((str != 0) ? strlen(str) : 0);
}

/*
 * If allocate==0, return 'str'; othewise, duplicate the string just
 * like strdup(), but don't die if 'str' is a NULL pointer.
 */
char *
sdup(const char *msg, int allocate, char *str) {
	char	*s;

	if (!allocate)
		return (str);

	if (str == 0) {
		s = strdup("");
	} else {
		s = strdup(str);
	}
	if (s == 0) {
		logmsg(MSG_NOMEM, LOG_ERR, "%s: strdup(%d bytes) => NULL\n",
			(msg != 0) ? msg : "<unknown>", slen(str)+1);
	}
	return (s);
}

/*
 * Concatenate strings like strcat(), but don't expire if passed a
 * NULL pointer or two. If deallocate!=0, free() the input strings.
 */
char *
scat(const char *msg, int deallocate, char *s1, char *s2) {
	char	*n;
	int	l1 = 0, l2 = 0;

	if (s1 == 0) {
		n = sdup(msg, T, s2);
		if (deallocate)
			sfree(s2);
		return (n);
	} else if (s2 == 0) {
		n = sdup(msg, T, s1);
		if (deallocate)
			free(s1);
		return (n);
	}

	l1 = strlen(s1);
	l2 = strlen(s2);

	n = malloc(l1+l2+1);
	if (n != 0) {
		memcpy(n, s1, l1);
		memcpy(&n[l1], s2, l2);
		n[l1+l2] = '\0';
	} else {
		logmsg(MSG_NOMEM, LOG_ERR, "%s: malloc(%d) => NULL\n",
			(msg != 0) ? msg : "<unknown>", l1+l2+1);
	}

	if (deallocate) {
		free(s1);
		free(s2);
	}

	return (n);
}

/* For debugging */
static void		*PTR = 0;

/*
 * Counters for memory errors. Note that we don't protect access,
 * so the values aren't entirely reliable in an MT application.
 */
ulong_t	numMisaligned = 0;
ulong_t	numNotActive = 0;

/* free() the input, but don't pass away if it's NULL */
void
sfree(void *ptr) {

	/* NULL pointer OK */
	if (ptr == 0)
		return;

	/*
	 * For use in the debugger, when we need to detect free of a
	 * certain address.
	 */
	if (ptr == PTR)
		abort();

	/*
	 * All addresses returned by malloc() and friends are "suitably
	 * aligned for any use", so they should fall on eight-byte boundaries.
	 */
	if (((unsigned long)ptr % 8) != 0) {
		numMisaligned++;
		return;
	}

#ifdef	NISDB_LDAP_DEBUG
	/*
	 * Malloc:ed memory should have the length (four bytes), starting
	 * eight bytes before the block, and with the least-significant
	 * bit set.
	 */
	if ((((uint_t *)ptr)[-2] & 0x1) == 0) {
		numNotActive++;
		return;
	}
#endif	/* NISDB_LDAP_DEBUG */

	/* Finally, we believe it's OK to free() the pointer */
	free(ptr);
}

/*
 * If a __nis_single_value_t represents a string, the length count may or may
 * not include a concluding NUL. Hence this function, which returns the last
 * non-NUL character of the value.
 */
char
lastChar(__nis_single_value_t *v) {
	char	*s;

	if (v == 0 || v->value == 0 || v->length < 2)
		return ('\0');

	s = v->value;
	if (s[v->length - 1] != '\0')
		return (s[v->length - 1]);
	else
		return (s[v->length - 2]);
}

void *
appendString2SingleVal(char *str, __nis_single_value_t *v, int *newLen) {
	void	*s;
	int	l, nl;
	char	*myself = "appendString2SingleVal";

	if (v == 0 || v->length < 0)
		return (0);

	/*
	 * If 'str' is NULL or empty, just return NULL so that the caller
	 * does nothing.
	 */
	l = slen(str);
	if (l <= 0)
		return (0);

	s = am(myself, (nl = l + v->length) + 1);
	if (s == 0) {
		/* Caller does nothing; let's hope for the best... */
		return (0);
	}

	if (v->value != 0)
		memcpy(s, v->value, v->length);

	memcpy(&(((char *)s)[v->length]), str, l);

	if (newLen != 0)
		*newLen = nl;

	return (s);
}


/*
 * Do the equivalent of a strcmp() between a string and a string-valued
 * __nis_single_value_t.
 */
int
scmp(char *s, __nis_single_value_t *v) {

	if (s == 0)
		return (1);
	else if (v == 0 || v->value == 0 || v->length <= 0)
		return (-1);

	return (strncmp(s, v->value, v->length));
}

/*
 * Do the equivalent of a strcasecmp() between a string and a string-valued
 * __nis_single_value_t.
 */
int
scasecmp(char *s, __nis_single_value_t *v) {

	if (s == 0)
		return (1);
	else if (v == 0 || v->value == 0 || v->length <= 0)
		return (-1);

	return (strncasecmp(s, v->value, v->length));
}

#define	STDBUFSIZE	81

/*
 * vsprintf the 'fmt' and 'ap' to a buffer, then concatenate the
 * result to '*buf'.
 */
int
vp2buf(const char *msg, char **buf, int buflen, const char *fmt, va_list ap) {
	char		*newbuf = am(msg, STDBUFSIZE);
	int		size = 0;

	if (newbuf == 0)
		return (0);

	if (buf == 0 || buflen < 0 || fmt == 0) {
		free(newbuf);
		return (0);
	}

	/* Find out how large the new buffer needs to be */
	size = vsnprintf(newbuf, STDBUFSIZE, fmt, ap);

	if (size > STDBUFSIZE) {
		free(newbuf);
		newbuf = am(msg, size+1);
		if (newbuf == 0)
			return (0);
		size = vsnprintf(newbuf, size+1, fmt, ap);
	}

	*buf = scat(msg, T, *buf, newbuf);
	/* Don't count the NUL. This enables us to concatenate correctly */
	buflen += size;

	return (buflen);
}

/* Generic print buffer */
__nis_buffer_t	pb = {0, 0};

/* sprintf to the generic __nis_buffer_t */
void
p2buf(char *msg, char *fmt, ...) {
	va_list	ap;

	va_start(ap, fmt);
	pb.len = vp2buf(msg, &pb.buf, pb.len, fmt, ap);
	va_end(ap);
}

/* sprintf to the specified __nis_buffer_t */
void
bp2buf(const char *msg, __nis_buffer_t *b, const char *fmt, ...) {
	va_list	ap;

	va_start(ap, fmt);
	b->len = vp2buf(msg, &b->buf, b->len, fmt, ap);
	va_end(ap);
}

/* Copy 'buf' to the specified __nis_buffer_t */
void
bc2buf(const char *msg, void *buf, int len, __nis_buffer_t *b) {
	void	*new;

	/*
	 * Make buffer one byte larger than the lenghts indicate. This
	 * gives us room to append a NUL, so that we can mix string and
	 * non-string copies into the buffer, and still end up with
	 * something that can be sent to printf(), strcat(), etc.
	 */
	new = realloc(b->buf, b->len+len+1);
	if (new != 0) {
		b->buf = new;
		memcpy(&(b->buf[b->len]), buf, len);
		b->len += len;
		/* Put a NUL at the end, just in case we printf() */
		if (b->len > 0 && b->buf[b->len-1] != '\0')
			b->buf[b->len] = '\0';
	} else {
		logmsg(MSG_NOMEM, LOG_ERR, "%s: realloc(%d) => NULL\n",
			(msg != 0) ? msg : "<unknown", b->len+len);
	}
}

/* Like bc2buf(), but remove any trailing NUL bytes */
void
sbc2buf(const char *msg, void *buf, int len, __nis_buffer_t *b) {
	if (buf == 0 || len <= 0 || b == 0)
		return;
	/* Snip off trailing NULs */
	while (len > 0 && ((char *)buf)[len-1] == '\0')
		len--;
	if (len <= 0)
		return;
	bc2buf(msg, buf, len, b);
}

/* Copy 'buf' to the generic __nis_buffer_t */
void
c2buf(char *msg, void *buf, int len) {
	bc2buf(msg, buf, len, &pb);
}

/* Like c2buf(), but remove trailing NUL bytes */
void
sc2buf(char *msg, void *buf, int len) {
	sbc2buf(msg, buf, len, &pb);
}

/* How many times we try write(2) if it fails */
#define	MAXTRY	10

/* Output the generic __nis_buffer_t to stdout */
void
printbuf(void) {
	int	maxtry = MAXTRY, len = pb.len;

	if (pb.buf != 0) {
		int	tmp;

		while (len > 0 && maxtry > 0) {
			tmp = write(1, pb.buf, len);
			if (tmp < 0)
				break;
			len -= tmp;
			if (tmp > 0)
				maxtry = MAXTRY;
			else
				maxtry--;
		}
		free(pb.buf);
		pb.buf = 0;
	}
	pb.len = 0;
}

void *
extendArray(void *array, int newsize) {
	void	*new = realloc(array, newsize);
	if (new == 0)
		sfree(array);
	return (new);
}

/*
 * Determine if the given string is an IP address (IPv4 or IPv6).
 * If so, it converts it to the format as required by rfc2307bis
 * and *newaddr will point to the new Address.
 *
 * Returns	-2		: error
 *		-1		: not an IP address
 *		0		: IP address not supported by rfc2307bis
 *		AF_INET		: IPv4
 *		AF_INET6	: IPv6
 */
int
checkIPaddress(char *addr, int len, char **newaddr) {
	ipaddr_t	addr_ipv4;
	in6_addr_t	addr_ipv6;
	char		*buffer;
	int		s, e;
	char		*myself = "checkIPaddress";

	/* skip leading whitespaces */
	for (s = 0; (s < len) && (addr[s] == ' ' || addr[s] == '\t'); s++);
	if (s >= len)
		return (-1);

	/* skip trailing whitespaces */
	for (e = len - 1; (e > s) && (addr[e] == ' ' || addr[e] == '\t'); e--);
	if (s == e)
		return (-1);

	/* adjust len */
	len = e - s + 1;

	if ((buffer = am(myself, len + 1)) == 0)
		return (-2);
	(void) memcpy(buffer, addr + s, len);

	if (inet_pton(AF_INET6, buffer, &addr_ipv6) == 1) {
		sfree(buffer);
		/*
		 * IPv4-compatible IPv6 address and IPv4-mapped
		 * IPv6 addresses not allowed by rfc2307bis
		 */
		if (IN6_IS_ADDR_V4COMPAT(&addr_ipv6))
			return (0);
		if (IN6_IS_ADDR_V4MAPPED(&addr_ipv6))
			return (0);
		if (newaddr == 0)
			return (AF_INET6);
		if ((*newaddr = am(myself, INET6_ADDRSTRLEN)) == 0)
			return (-2);
		if (inet_ntop(AF_INET6, &addr_ipv6, *newaddr, INET6_ADDRSTRLEN))
			return (AF_INET6);
		sfree(*newaddr);
		return (-2);
	}

	if (inet_pton(AF_INET, buffer, &addr_ipv4) == 1) {
		sfree(buffer);
		if (newaddr == 0)
			return (AF_INET);
		if ((*newaddr = am(myself, INET_ADDRSTRLEN)) == 0)
			return (-2);
		if (inet_ntop(AF_INET, &addr_ipv4, *newaddr, INET_ADDRSTRLEN))
			return (AF_INET);
		sfree(*newaddr);
		return (-2);
	}

	sfree(buffer);
	return (-1);
}

int
sstrncmp(const char *s1, const char *s2, int n) {
	if (s1 == 0 && s2 == 0)
		return (0);

	if (s1 == 0)
		return (1);

	if (s2 == 0)
		return (-1);

	return (strncmp(s1, s2, n));
}

/*
 * Does the following:
 * - Trims leading and trailing whitespaces
 * - Collapses two or more whitespaces into one space
 * - Converts all whitespaces into spaces
 * - At entrance, *len contains length of str
 * - At exit, *len will contain length of the return string
 * - In case of mem alloc failure, *len should be ignored
 */
char *
trimWhiteSpaces(char *str, int *len, int deallocate) {
	char	*ostr;
	int	olen = 0;
	int	first = 1, i;
	char	*myself = "trimWhiteSpaces";

	if ((ostr = am(myself, *len + 1)) == 0) {
		if (deallocate)
			sfree(str);
		*len = 0;
		return (0);
	}

	/* Skip leading whitespaces */
	for (i = 0; i < *len && (str[i] == ' ' || str[i] == '\t'); i++);

	/* Collapse multiple whitespaces into one */
	for (; i < *len; i++) {
		if (str[i] == ' ' || str[i] == '\t') {
			if (first) {
				first = 0;
				ostr[olen++] = ' ';
			}
			continue;
		}
		first = 1;
		ostr[olen++] = str[i];
	}

	/* Handle the trailing whitespace if any */
	if (olen && ostr[olen - 1] == ' ') {
			olen--;
			ostr[olen] = 0;
	}

	if (deallocate)
			sfree(str);

	*len = olen;
	return (ostr);
}

/*
 * Escapes special characters in DN using the list from RFC 2253
 */
int
escapeSpecialChars(__nis_value_t *val) {
	int	i, j, k, count;
	char	*newval, *s;
	char	*myself = "escapeSpecialChars";

	/* Assume val is always non NULL */

	for (i = 0; i < val->numVals; i++) {
		/*
		 * Count the special characters in value to determine
		 * the length for the new value
		 */
		s = val->val[i].value;
		for (j = 0, count = 0; j < val->val[i].length; j++, s++) {
			if (*s == '#' || *s == ',' || *s == '+' || *s == '"' ||
			*s == '\\' || *s == '<' || *s == '>' || *s == ';')
				count++;
		}
		if (count == 0)
			continue;

		if ((newval = am(myself, val->val[i].length + count + 1)) == 0)
			return (-1);

		/* Escape the special characters using '\\' */
		s = val->val[i].value;
		for (j = 0, k = 0; j < val->val[i].length; j++, k++, s++) {
			if (*s == '#' || *s == ',' || *s == '+' || *s == '"' ||
			*s == '\\' || *s == '<' || *s == '>' || *s == ';')
				newval[k++] = '\\';
			newval[k] = *s;
		}

		sfree(val->val[i].value);
		val->val[i].value = newval;
		val->val[i].length += count;
	}

	return (1);
}

/*
 * Remove escape characters from DN returned by LDAP server
 */
void
removeEscapeChars(__nis_value_t *val) {
	int	i;
	char	*s, *d, *end;


	for (i = 0; i < val->numVals; i++) {
		s = val->val[i].value;
		end = s + val->val[i].length;

		/*
		 * This function is called frequently and for most entries
		 * there will be no escapes. Process rapidly up to first escape.
		 */
		for (d = s; s < end;  s++, d++) {
			if (*s == '\\')
				break;
		}

		/*
		 * Reached the end, in which case will not go into loop,
		 * or found an escape and now have to start moving data.
		 */
		for (; s < end;  s++) {
			if (*s == '\\') {
				val->val[i].length--;
				/*
				 * Next character gets coppied without being
				 * checked
				 */
				s++;
				if (s >= end)
					break;
			}

			*d = *s;
			d++;
		}
	}
}
