/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.
 */

#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <umem.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include <thread.h>
#include <sys/debug.h>

#include <bunyan.h>
#include <bunyan_provider_impl.h>

struct bunyan_key;
struct bunyan_stream;
struct bunyan;

typedef struct bunyan_stream {
	struct bunyan_stream	*bs_next;
	char			*bs_name;
	bunyan_level_t		bs_level;
	bunyan_stream_f		bs_func;
	void			*bs_arg;
	uint_t			bs_count;
} bunyan_stream_t;

typedef struct bunyan_key {
	struct bunyan_key	*bk_next;
	char			*bk_name;
	bunyan_type_t		bk_type;
	void			*bk_data;
	size_t			bk_len;
} bunyan_key_t;

typedef struct bunyan {
	pthread_mutex_t	bun_lock;
	bunyan_key_t	*bun_keys;
	bunyan_stream_t	*bun_streams;
	char		*bun_name;
	char		bun_host[MAXHOSTNAMELEN+1];
} bunyan_t;

#define	ISO_TIMELEN	25
static const int bunyan_version = 0;

static void
bunyan_key_fini(bunyan_key_t *bkp)
{
	size_t nlen = strlen(bkp->bk_name) + 1;
	umem_free(bkp->bk_data, bkp->bk_len);
	umem_free(bkp->bk_name, nlen);
	umem_free(bkp, sizeof (bunyan_key_t));
}

static void
bunyan_stream_fini(bunyan_stream_t *bsp)
{
	size_t nlen = strlen(bsp->bs_name) + 1;
	umem_free(bsp->bs_name, nlen);
	umem_free(bsp, sizeof (bunyan_stream_t));
}

int
bunyan_init(const char *name, bunyan_logger_t **bhp)
{
	int ret;
	bunyan_t *b;
	size_t nlen = strlen(name) + 1;

	b = umem_zalloc(sizeof (bunyan_t), UMEM_DEFAULT);
	if (b == NULL)
		return (ENOMEM);

	b->bun_name = umem_alloc(nlen, UMEM_DEFAULT);
	if (b->bun_name == NULL) {
		umem_free(b, sizeof (bunyan_t));
		return (ENOMEM);
	}
	bcopy(name, b->bun_name, nlen);

	if ((ret = pthread_mutex_init(&b->bun_lock, NULL)) != 0) {
		umem_free(b->bun_name, nlen);
		umem_free(b, sizeof (bunyan_t));
		return (ret);
	}

	VERIFY(gethostname(b->bun_host, sizeof (b->bun_host)) == 0);
	b->bun_host[MAXHOSTNAMELEN] = '\0';

	*bhp = (bunyan_logger_t *)b;
	return (0);
}

void
bunyan_fini(bunyan_logger_t *bhp)
{
	bunyan_t *b = (bunyan_t *)bhp;
	bunyan_key_t *bkp;
	bunyan_stream_t *bsp;

	while ((bkp = b->bun_keys) != NULL) {
		b->bun_keys = bkp->bk_next;
		bunyan_key_fini(bkp);
	}

	while ((bsp = b->bun_streams) != NULL) {
		b->bun_streams = bsp->bs_next;
		bunyan_stream_fini(bsp);
	}

	if (b->bun_name != NULL)
		umem_free(b->bun_name, strlen(b->bun_name) + 1);

	VERIFY(pthread_mutex_destroy(&b->bun_lock) == 0);
	umem_free(b, sizeof (bunyan_t));
}

/* ARGSUSED */
int
bunyan_stream_fd(nvlist_t *nvl, const char *js, void *arg)
{
	uintptr_t fd = (uintptr_t)arg;
	size_t jslen = strlen(js);
	off_t off = 0;
	ssize_t ret = 0;
	static int maxbuf = -1;

	if (maxbuf == -1)
		maxbuf = getpagesize();

	while (off != jslen) {
		/*
		 * Write up to a page of data at a time. If for some reason an
		 * individual write fails, move on and try to still write a new
		 * line at least...
		 */
		ret = write(fd, js + off, MIN(jslen - off, maxbuf));
		if (ret < 0)
			break;
		off += ret;
	}

	if (ret < 0) {
		(void) write(fd, "\n", 1);
	} else {
		ret = write(fd, "\n", 1);
	}
	return (ret < 0 ? 1: 0);
}

int
bunyan_stream_add(bunyan_logger_t *bhp, const char *name, int level,
    bunyan_stream_f func, void *arg)
{
	bunyan_stream_t *bs, *cur;
	size_t nlen = strlen(name) + 1;
	bunyan_t *b = (bunyan_t *)bhp;

	if (level != BUNYAN_L_TRACE &&
	    level != BUNYAN_L_DEBUG &&
	    level != BUNYAN_L_INFO &&
	    level != BUNYAN_L_WARN &&
	    level != BUNYAN_L_ERROR &&
	    level != BUNYAN_L_FATAL)
		return (EINVAL);

	bs = umem_alloc(sizeof (bunyan_stream_t), UMEM_DEFAULT);
	if (bs == NULL)
		return (ENOMEM);

	bs->bs_name = umem_alloc(nlen, UMEM_DEFAULT);
	if (bs->bs_name == NULL) {
		umem_free(bs, sizeof (bunyan_stream_t));
		return (ENOMEM);
	}
	bcopy(name, bs->bs_name, nlen);
	bs->bs_level = level;
	bs->bs_func = func;
	bs->bs_arg = arg;
	bs->bs_count = 0;
	(void) pthread_mutex_lock(&b->bun_lock);
	cur = b->bun_streams;
	while (cur != NULL) {
		if (strcmp(name, cur->bs_name) == 0) {
			(void) pthread_mutex_unlock(&b->bun_lock);
			umem_free(bs->bs_name, nlen);
			umem_free(bs, sizeof (bunyan_stream_t));
			return (EEXIST);
		}
		cur = cur->bs_next;
	}
	bs->bs_next = b->bun_streams;
	b->bun_streams = bs;
	(void) pthread_mutex_unlock(&b->bun_lock);

	return (0);
}

int
bunyan_stream_remove(bunyan_logger_t *bhp, const char *name)
{
	bunyan_stream_t *cur, *prev;
	bunyan_t *b = (bunyan_t *)bhp;

	(void) pthread_mutex_lock(&b->bun_lock);
	prev = NULL;
	cur = b->bun_streams;
	while (cur != NULL) {
		if (strcmp(name, cur->bs_name) == 0)
			break;
		prev = cur;
		cur = cur->bs_next;
	}
	if (cur == NULL) {
		(void) pthread_mutex_unlock(&b->bun_lock);
		return (ENOENT);
	}
	if (prev == NULL)
		b->bun_streams = cur->bs_next;
	else
		prev->bs_next = cur->bs_next;
	cur->bs_next = NULL;
	(void) pthread_mutex_unlock(&b->bun_lock);

	bunyan_stream_fini(cur);

	return (0);
}

static int
bunyan_key_add_one(bunyan_t *b, const char *name, bunyan_type_t type,
    const void *arg)
{
	bunyan_key_t *bkp, *cur, *prev;
	size_t nlen = strlen(name) + 1;
	size_t blen;

	bkp = umem_alloc(sizeof (bunyan_key_t), UMEM_DEFAULT);
	if (bkp == NULL)
		return (ENOMEM);
	bkp->bk_name = umem_alloc(nlen, UMEM_DEFAULT);
	if (bkp->bk_name == NULL) {
		umem_free(bkp, sizeof (bunyan_key_t));
		return (ENOMEM);
	}
	bcopy(name, bkp->bk_name, nlen);

	switch (type) {
	case BUNYAN_T_STRING:
		blen = strlen(arg) + 1;
		break;
	case BUNYAN_T_POINTER:
		blen = sizeof (uintptr_t);
		break;
	case BUNYAN_T_IP:
		blen = sizeof (struct in_addr);
		break;
	case BUNYAN_T_IP6:
		blen = sizeof (struct in6_addr);
		break;
	case BUNYAN_T_BOOLEAN:
		blen = sizeof (boolean_t);
		break;
	case BUNYAN_T_INT32:
		blen = sizeof (int32_t);
		break;
	case BUNYAN_T_INT64:
	case BUNYAN_T_INT64STR:
		blen = sizeof (int64_t);
		break;
	case BUNYAN_T_UINT32:
		blen = sizeof (uint32_t);
		break;
	case BUNYAN_T_UINT64:
	case BUNYAN_T_UINT64STR:
		blen = sizeof (uint64_t);
		break;
	case BUNYAN_T_DOUBLE:
		blen = sizeof (double);
		break;
	default:
		umem_free(bkp->bk_name, nlen);
		umem_free(bkp, sizeof (bunyan_key_t));
		return (EINVAL);
	}

	bkp->bk_data = umem_alloc(blen, UMEM_DEFAULT);
	if (bkp->bk_data == NULL) {
		umem_free(bkp->bk_name, nlen);
		umem_free(bkp, sizeof (bunyan_key_t));
		return (ENOMEM);
	}
	bcopy(arg, bkp->bk_data, blen);
	bkp->bk_len = blen;
	bkp->bk_type = type;

	(void) pthread_mutex_lock(&b->bun_lock);
	prev = NULL;
	cur = b->bun_keys;
	while (cur != NULL) {
		if (strcmp(name, cur->bk_name) == 0)
			break;
		prev = cur;
		cur = cur->bk_next;
	}
	if (cur != NULL) {
		if (prev == NULL)
			b->bun_keys = cur->bk_next;
		else
			prev->bk_next = cur->bk_next;
		bunyan_key_fini(cur);
	}
	bkp->bk_next = b->bun_keys;
	b->bun_keys = bkp;
	(void) pthread_mutex_unlock(&b->bun_lock);

	return (0);
}

static int
bunyan_key_vadd(bunyan_t *b, va_list *ap)
{
	int type, ret;
	void *data;
	boolean_t bt;
	int32_t i32;
	int64_t i64;
	uint32_t ui32;
	uint64_t ui64;
	double d;
	uintptr_t ptr;

	while ((type = va_arg(*ap, int)) != BUNYAN_T_END) {
		const char *name = va_arg(*ap, char *);

		switch (type) {
		case BUNYAN_T_STRING:
			data = va_arg(*ap, char *);
			break;
		case BUNYAN_T_POINTER:
			ptr = (uintptr_t)va_arg(*ap, void *);
			data = &ptr;
			break;
		case BUNYAN_T_IP:
		case BUNYAN_T_IP6:
			data = va_arg(*ap, void *);
			break;
		case BUNYAN_T_BOOLEAN:
			bt  = va_arg(*ap, boolean_t);
			data = &bt;
			break;
		case BUNYAN_T_INT32:
			i32 = va_arg(*ap, int32_t);
			data = &i32;
			break;
		case BUNYAN_T_INT64:
		case BUNYAN_T_INT64STR:
			i64 = va_arg(*ap, int64_t);
			data = &i64;
			break;
		case BUNYAN_T_UINT32:
			ui32 = va_arg(*ap, uint32_t);
			data = &ui32;
			break;
		case BUNYAN_T_UINT64:
		case BUNYAN_T_UINT64STR:
			ui64 = va_arg(*ap, uint64_t);
			data = &ui64;
			break;
		case BUNYAN_T_DOUBLE:
			d = va_arg(*ap, double);
			data = &d;
			break;
		default:
			return (EINVAL);
		}

		if ((ret = bunyan_key_add_one(b, name, type, data)) != 0)
			return (ret);
	}

	return (0);
}

int
bunyan_key_add(bunyan_logger_t *bhp, ...)
{
	int ret;
	va_list ap;
	bunyan_t *b = (bunyan_t *)bhp;

	va_start(ap, bhp);
	ret = bunyan_key_vadd(b, &ap);
	va_end(ap);

	return (ret);
}

int
bunyan_key_remove(bunyan_logger_t *bhp, const char *name)
{
	bunyan_t *b = (bunyan_t *)bhp;
	bunyan_key_t *cur, *prev;

	(void) pthread_mutex_lock(&b->bun_lock);
	prev = NULL;
	cur = b->bun_keys;
	while (cur != NULL) {
		if (strcmp(name, cur->bk_name) == 0)
			break;
		prev = cur;
		cur = cur->bk_next;
	}

	if (cur == NULL) {
		(void) pthread_mutex_unlock(&b->bun_lock);
		return (ENOENT);
	}

	if (prev == NULL)
		b->bun_keys = cur->bk_next;
	else
		prev->bk_next = cur->bk_next;
	(void) pthread_mutex_unlock(&b->bun_lock);

	bunyan_key_fini(cur);
	return (0);
}

static bunyan_key_t *
bunyan_key_dup(const bunyan_key_t *bkp)
{
	bunyan_key_t *nkp;
	size_t nlen = strlen(bkp->bk_name) + 1;

	nkp = umem_alloc(sizeof (bunyan_key_t), UMEM_DEFAULT);
	if (nkp == NULL)
		return (NULL);
	nkp->bk_next = NULL;
	nkp->bk_name = umem_alloc(nlen, UMEM_DEFAULT);
	if (nkp->bk_name == NULL) {
		umem_free(nkp, sizeof (bunyan_key_t));
		return (NULL);
	}
	bcopy(bkp->bk_name, nkp->bk_name, nlen);
	nkp->bk_type = bkp->bk_type;
	nkp->bk_data = umem_alloc(bkp->bk_len, UMEM_DEFAULT);
	if (nkp->bk_data == NULL) {
		umem_free(nkp->bk_name, nlen);
		umem_free(nkp, sizeof (bunyan_key_t));
		return (NULL);
	}
	bcopy(bkp->bk_data, nkp->bk_data, bkp->bk_len);
	nkp->bk_len = bkp->bk_len;

	return (nkp);
}

static bunyan_stream_t *
bunyan_stream_dup(const bunyan_stream_t *bsp)
{
	bunyan_stream_t *nsp;
	size_t nlen = strlen(bsp->bs_name) + 1;

	nsp = umem_alloc(sizeof (bunyan_stream_t), UMEM_DEFAULT);
	if (nsp == NULL)
		return (NULL);

	nsp->bs_next = NULL;
	nsp->bs_name = umem_alloc(nlen, UMEM_DEFAULT);
	if (nsp->bs_name == NULL) {
		umem_free(nsp, sizeof (bunyan_stream_t));
		return (NULL);
	}
	bcopy(bsp->bs_name, nsp->bs_name, nlen);
	nsp->bs_level = bsp->bs_level;
	nsp->bs_func = bsp->bs_func;
	nsp->bs_arg = bsp->bs_arg;
	nsp->bs_count = 0;

	return (nsp);
}

static bunyan_t *
bunyan_dup(const bunyan_t *b)
{
	bunyan_t *n;
	const bunyan_key_t *bkp;
	const bunyan_stream_t *bsp;
	size_t nlen;

	n = umem_zalloc(sizeof (bunyan_t), UMEM_DEFAULT);
	if (n == NULL)
		return (NULL);

	if (pthread_mutex_init(&n->bun_lock, NULL) != 0) {
		umem_free(n, sizeof (bunyan_t));
		return (NULL);
	}

	for (bkp = b->bun_keys; bkp != NULL; bkp = bkp->bk_next) {
		bunyan_key_t *nkp;
		nkp = bunyan_key_dup(bkp);
		if (nkp == NULL) {
			bunyan_fini((bunyan_logger_t *)n);
			return (NULL);
		}

		nkp->bk_next = n->bun_keys;
		n->bun_keys = nkp;
	}

	for (bsp = b->bun_streams; bsp != NULL; bsp = bsp->bs_next) {
		bunyan_stream_t *nsp;
		nsp = bunyan_stream_dup(bsp);
		if (bsp == NULL) {
			bunyan_fini((bunyan_logger_t *)n);
			return (NULL);
		}

		nsp->bs_next = n->bun_streams;
		n->bun_streams = nsp;
	}

	nlen = strlen(b->bun_name) + 1;
	n->bun_name = umem_alloc(nlen, UMEM_DEFAULT);
	if (n->bun_name == NULL) {
		bunyan_fini((bunyan_logger_t *)n);
		return (NULL);
	}
	bcopy(b->bun_name, n->bun_name, nlen);
	bcopy(b->bun_host, n->bun_host, MAXHOSTNAMELEN+1);

	return (n);
}

int
bunyan_child(const bunyan_logger_t *bhp, bunyan_logger_t **outp, ...)
{
	const bunyan_t *b = (const bunyan_t *)bhp;
	bunyan_t *n;
	va_list ap;
	int ret;

	n = bunyan_dup(b);
	if (n == NULL)
		return (ENOMEM);

	va_start(ap, outp);
	ret = bunyan_key_vadd(n, &ap);
	va_end(ap);

	if (ret != 0)
		bunyan_fini((bunyan_logger_t *)n);
	else
		*outp = (bunyan_logger_t *)n;

	return (ret);
}

static int
bunyan_iso_time(char *buf)
{
	struct timeval tv;
	struct tm tm;

	if (gettimeofday(&tv, NULL) != 0)
		return (errno);

	if (gmtime_r(&tv.tv_sec, &tm) == NULL)
		return (errno);

	VERIFY(strftime(buf, ISO_TIMELEN, "%FT%T", &tm) == 19);

	(void) snprintf(&buf[19], 6, ".%03dZ", (int)(tv.tv_usec / 1000));

	return (0);
}

/*
 * Note, these fields are all required, so even if a user attempts to use one of
 * them in their own fields, we'll override them and therefore, have it be the
 * last one.
 */
static int
bunyan_vlog_defaults(nvlist_t *nvl, bunyan_t *b, bunyan_level_t level,
    const char *msg)
{
	int ret;
	char tbuf[ISO_TIMELEN];

	if ((ret = bunyan_iso_time(tbuf)) != 0)
		return (ret);

	if ((ret = nvlist_add_int32(nvl, "v", bunyan_version)) != 0 ||
	    (ret = nvlist_add_int32(nvl, "level", level) != 0) ||
	    (ret = nvlist_add_string(nvl, "name", b->bun_name) != 0) ||
	    (ret = nvlist_add_string(nvl, "hostname", b->bun_host) != 0) ||
	    (ret = nvlist_add_int32(nvl, "pid", getpid()) != 0) ||
	    (ret = nvlist_add_uint32(nvl, "tid", thr_self()) != 0) ||
	    (ret = nvlist_add_string(nvl, "time", tbuf) != 0) ||
	    (ret = nvlist_add_string(nvl, "msg", msg) != 0))
		return (ret);

	return (0);
}

static int
bunyan_vlog_add(nvlist_t *nvl, const char *key, bunyan_type_t type, void *arg)
{
	int ret;
	uintptr_t *up;
	struct in_addr *v4;
	struct in6_addr *v6;

	/*
	 * Our buffer needs to hold the string forms of pointers, IPv6 strings,
	 * etc. INET6_ADDRSTRLEN is large enough for all of these.
	 */
	char buf[INET6_ADDRSTRLEN];

	switch (type) {
	case BUNYAN_T_STRING:
		ret = nvlist_add_string(nvl, key, (char *)arg);
		break;
	case BUNYAN_T_POINTER:
		up = arg;
		(void) snprintf(buf, sizeof (buf), "0x%p", *up);
		ret = nvlist_add_string(nvl, key, buf);
		break;
	case BUNYAN_T_IP:
		v4 = arg;
		VERIFY(inet_ntop(AF_INET, v4, buf, sizeof (buf)) != NULL);
		ret = nvlist_add_string(nvl, key, buf);
		break;
	case BUNYAN_T_IP6:
		v6 = arg;
		VERIFY(inet_ntop(AF_INET6, v6, buf, sizeof (buf)) != NULL);
		ret = nvlist_add_string(nvl, key, buf);
		break;
	case BUNYAN_T_BOOLEAN:
		ret = nvlist_add_boolean_value(nvl, key, *(boolean_t *)arg);
		break;
	case BUNYAN_T_INT32:
		ret = nvlist_add_int32(nvl, key, *(int32_t *)arg);
		break;
	case BUNYAN_T_INT64:
		ret = nvlist_add_int64(nvl, key, *(int64_t *)arg);
		break;
	case BUNYAN_T_UINT32:
		ret = nvlist_add_uint32(nvl, key, *(uint32_t *)arg);
		break;
	case BUNYAN_T_UINT64:
		ret = nvlist_add_uint64(nvl, key, *(uint32_t *)arg);
		break;
	case BUNYAN_T_DOUBLE:
		ret = nvlist_add_double(nvl, key, *(double *)arg);
		break;
	case BUNYAN_T_INT64STR:
		(void) snprintf(buf, sizeof (buf), "%lld", *(int64_t *)arg);
		ret = nvlist_add_string(nvl, key, buf);
		break;
	case BUNYAN_T_UINT64STR:
		(void) snprintf(buf, sizeof (buf), "%llu", *(uint64_t *)arg);
		ret = nvlist_add_string(nvl, key, buf);
		break;
	default:
		ret = EINVAL;
		break;
	}

	return (ret);
}

static int
bunyan_vlog(bunyan_logger_t *bhp, bunyan_level_t level, const char *msg,
    va_list *ap)
{
	nvlist_t *nvl = NULL;
	int ret, type;
	bunyan_key_t *bkp;
	bunyan_stream_t *bsp;
	char *buf = NULL;
	bunyan_t *b = (bunyan_t *)bhp;

	if (msg == NULL)
		return (EINVAL);

	(void) pthread_mutex_lock(&b->bun_lock);

	if ((ret = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0) {
		(void) pthread_mutex_unlock(&b->bun_lock);
		return (ret);
	}

	/*
	 * We add pre-defined keys, then go through and process the users keys,
	 * and finally go ahead and our defaults. If all that succeeds, then we
	 * can go ahead and call all the built-in logs.
	 */
	for (bkp = b->bun_keys; bkp != NULL; bkp = bkp->bk_next) {
		if ((ret = bunyan_vlog_add(nvl, bkp->bk_name, bkp->bk_type,
		    bkp->bk_data)) != 0)
			goto out;
	}

	while ((type = va_arg(*ap, int)) != BUNYAN_T_END) {
		void *data;
		boolean_t bt;
		int32_t i32;
		int64_t i64;
		uint32_t ui32;
		uint64_t ui64;
		double d;
		uintptr_t ptr;
		const char *key = va_arg(*ap, char *);

		switch (type) {
		case BUNYAN_T_STRING:
			data = va_arg(*ap, char *);
			break;
		case BUNYAN_T_POINTER:
			ptr = (uintptr_t)va_arg(*ap, void *);
			data = &ptr;
			break;
		case BUNYAN_T_IP:
		case BUNYAN_T_IP6:
			data = va_arg(*ap, void *);
			break;
		case BUNYAN_T_BOOLEAN:
			bt  = va_arg(*ap, boolean_t);
			data = &bt;
			break;
		case BUNYAN_T_INT32:
			i32 = va_arg(*ap, int32_t);
			data = &i32;
			break;
		case BUNYAN_T_INT64:
		case BUNYAN_T_INT64STR:
			i64 = va_arg(*ap, int64_t);
			data = &i64;
			break;
		case BUNYAN_T_UINT32:
			ui32 = va_arg(*ap, uint32_t);
			data = &ui32;
			break;
		case BUNYAN_T_UINT64:
		case BUNYAN_T_UINT64STR:
			ui64 = va_arg(*ap, uint64_t);
			data = &ui64;
			break;
		case BUNYAN_T_DOUBLE:
			d = va_arg(*ap, double);
			data = &d;
			break;
		default:
			ret = EINVAL;
			goto out;
		}

		if ((ret = bunyan_vlog_add(nvl, key, type, data)) != 0)
			goto out;

	}
	/*
	 * This must be the last thing we do before we log to ensure that all of
	 * our defaults always make it out.
	 */
	if ((ret = bunyan_vlog_defaults(nvl, b, level, msg)) != 0)
		goto out;

	if (nvlist_dump_json(nvl, &buf) < 0) {
		ret = errno;
		goto out;
	}

	/* Fire DTrace probes */
	switch (level) {
	case BUNYAN_L_TRACE:
		BUNYAN_LOG_TRACE(buf);
		break;
	case BUNYAN_L_DEBUG:
		BUNYAN_LOG_DEBUG(buf);
		break;
	case BUNYAN_L_INFO:
		BUNYAN_LOG_INFO(buf);
		break;
	case BUNYAN_L_WARN:
		BUNYAN_LOG_WARN(buf);
		break;
	case BUNYAN_L_ERROR:
		BUNYAN_LOG_ERROR(buf);
		break;
	case BUNYAN_L_FATAL:
		BUNYAN_LOG_FATAL(buf);
		break;
	}

	for (bsp = b->bun_streams; bsp != NULL; bsp = bsp->bs_next) {
		if (bsp->bs_level <= level)
			if (bsp->bs_func(nvl, buf, bsp->bs_arg) != 0)
				bsp->bs_count++;
	}
	ret = 0;
out:
	(void) pthread_mutex_unlock(&b->bun_lock);
	if (buf != NULL)
		nvlist_dump_json_free(nvl, buf);
	if (nvl != NULL)
		nvlist_free(nvl);
	return (ret);
}

int
bunyan_trace(bunyan_logger_t *bhp, const char *msg, ...)
{
	va_list va;
	int ret;

	va_start(va, msg);
	ret = bunyan_vlog(bhp, BUNYAN_L_TRACE, msg, &va);
	va_end(va);

	return (ret);
}

int
bunyan_debug(bunyan_logger_t *bhp, const char *msg, ...)
{
	va_list va;
	int ret;

	va_start(va, msg);
	ret = bunyan_vlog(bhp, BUNYAN_L_DEBUG, msg, &va);
	va_end(va);

	return (ret);
}

int
bunyan_info(bunyan_logger_t *bhp, const char *msg, ...)
{
	va_list va;
	int ret;

	va_start(va, msg);
	ret = bunyan_vlog(bhp, BUNYAN_L_INFO, msg, &va);
	va_end(va);

	return (ret);
}

int
bunyan_warn(bunyan_logger_t *bhp, const char *msg, ...)
{
	va_list va;
	int ret;

	va_start(va, msg);
	ret = bunyan_vlog(bhp, BUNYAN_L_WARN, msg, &va);
	va_end(va);

	return (ret);
}

int
bunyan_error(bunyan_logger_t *bhp, const char *msg, ...)
{
	va_list va;
	int ret;

	va_start(va, msg);
	ret = bunyan_vlog(bhp, BUNYAN_L_ERROR, msg, &va);
	va_end(va);

	return (ret);
}


int
bunyan_fatal(bunyan_logger_t *bhp, const char *msg, ...)
{
	va_list va;
	int ret;

	va_start(va, msg);
	ret = bunyan_vlog(bhp, BUNYAN_L_FATAL, msg, &va);
	va_end(va);

	return (ret);
}
