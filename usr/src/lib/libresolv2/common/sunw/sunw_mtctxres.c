/*
 * Copyright (c) 1998-2000 by Sun Microsystems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <port_before.h>
#include <thread.h>
#include <errno.h>
#include <netdb.h>
#include <malloc.h>
#include <string.h>
#include <resolv_mt.h>
#include <irs.h>
#include <port_after.h>

static int		thr_keycreate_ret = 0;

static thread_key_t	key;
static int		mt_key_initialized = 0;

static mtctxres_t	sharedctx;

static int		__res_init_ctx(thread_key_t);
static void		__res_destroy_ctx(void *);

#pragma init	(_mtctxres_init)

/*
 * Initialize the TSD key. By doing this at library load time, we're
 * implicitly running without interference from other threads, so there's
 * no need for locking.
 */
static void
_mtctxres_init(void) {

	if ((thr_keycreate_ret = thr_keycreate(&key, __res_destroy_ctx)) == 0) {
		mt_key_initialized = 1;
	}
}


/*
 * To support binaries that used the private MT-safe interface in
 * on998 or on28, we still need to provide the __res_enable_mt()
 * and __res_disable_mt() entry points. They're do-nothing routines.
 */
int
__res_enable_mt(void) {
	return (-1);
}

int
__res_disable_mt(void) {
	return (0);
}


static int
__res_init_ctx(thread_key_t key) {

	mtctxres_t	*mt;
	int		ret;


	if (thr_getspecific(key, (void **)&mt) == 0 && mt != 0) {
		/* Already exists */
		return (0);
	}

	if ((mt = malloc(sizeof (mtctxres_t))) == 0) {
		errno = ENOMEM;
		return (-1);
	}

	memset(mt, 0, sizeof (*mt));

	if ((ret = thr_setspecific(key, mt)) != 0) {
		errno = ret;
		free(mt);
		return (-1);
	}

	return (0);

}


static void
__res_destroy_ctx(void *value) {

	mtctxres_t	*mt = (mtctxres_t *)value;

	if (mt != 0) {
		free(mt);
	}
}


mtctxres_t *
___mtctxres() {

	mtctxres_t	*mt;


	if (mt_key_initialized) {
		if ((thr_getspecific(key, (void **)&mt) == 0 &&	mt != 0) ||
			(__res_init_ctx(key) == 0 &&
			thr_getspecific(key, (void **)&mt) == 0 && mt != 0)) {
			return (mt);
		}
	}

	return (&sharedctx);
}


/*
 * There used to be a private, MT-safe resolver interface that used TSD
 * to store per-thread _res, h_errno, etc. We continue to provide the
 * access functions __res_get_res() and __res_get_h_errno() so that binaries
 * that used the private interface will continue to work.
 */

#ifdef	_res
#undef	_res
#endif

extern struct __res_state	*__res_state(void);

struct __res_state *
__res_get_res(void) {
	return (__res_state());
}


#ifdef	h_errno
#undef	h_errno
#endif

extern int			*__h_errno(void);

int *
__res_get_h_errno(void) {
	return (__h_errno());
}


#ifdef SUNW_HOSTS_FALLBACK

/*
 * When the name service switch calls libresolv, it doesn't want fallback
 * to /etc/hosts, so we provide a method to turn it off.
 */

void
__res_set_no_hosts_fallback(void) {
	___mtctxres()->no_hosts_fallback_private = 1;
}

void
__res_unset_no_hosts_fallback(void) {
	___mtctxres()->no_hosts_fallback_private = 0;
}

int
__res_no_hosts_fallback(void) {
	return (___mtctxres()->no_hosts_fallback_private);
}

#endif  /* SUNW_HOSTS_FALLBACK */

#ifdef	SUNW_OVERRIDE_RETRY

/*
 * The NS switch wants to be able to override the number of retries.
 */

int
__res_override_retry(int retry) {
	___mtctxres()->retry_private = retry;
	/*
	 * This function doesn't really need a return value; saving the
	 * old retry setting, and restoring it, is handled by __res_retry()
	 * and __res_retry_reset() below. However, the nss_dns library
	 * must have a private version of this function to be used when
	 * running with an old libresolv. That private nss_dns function
	 * needs a return value, and a function pointer is used to select
	 * the right function at runtime. Thus, __res_override_retry
	 * must have a function prototype consistent with the private
	 * nss_dns function, i.e., one that returns an int.
	 *
	 * Given that we do have a return value, that value must be zero.
	 * That's because retry_private == 0 is used to indicate that
	 * no override retry value is in effect, and the way we expect
	 * nss_dns to call us is:
	 *
	 *	int oldretry = __res_override_retry(N);
	 *	<whatever>
	 *	(void)__res_override_retry(old_retry);
	 */
	return (0);
}

int
__res_retry(int retry) {
	mtctxres_t	*mt = ___mtctxres();

	mt->retry_save = retry;
	return ((mt->retry_private != 0) ? mt->retry_private : retry);
}

int
__res_retry_reset(void) {
	mtctxres_t	*mt = ___mtctxres();

	return (mt->retry_save);
}

#endif	/* SUNW_OVERRIDE_RETRY */
