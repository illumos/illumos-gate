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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/atomic.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/t_lock.h>

/*
 * This module provides the framework that manage STREAMS modules.
 * fmodsw_alloc() is called from modconf.c as a result of a module calling
 * mod_install() and fmodsw_free() is called as the result of the module
 * calling mod_remove().
 * fmodsw_find() will find the fmodsw_impl_t structure relating to a named
 * module. There is no equivalent of driver major numbers for modules; the
 * the database of fmodsw_impl_t structures is purely keyed by name and
 * is hence a hash table to keep lookup cost to a minimum.
 */

/*
 * fmodsw_hash is the hash table that will be used to map module names to
 * their fmodsw_impl_t structures. The hash function requires that the value is
 * a power of 2 so this definition specifies the log of the hash table size.
 */
#define	FMODSW_LOG_HASHSZ	8

/*
 * Hash table and associated reader-writer lock
 *
 * NOTE: Because the lock is global data, it is initialized to zero and hence
 *       a call to rw_init() is not required. Similarly all the pointers in
 *       the hash table will be implicitly initialized to NULL.
 */
#define	FMODSW_HASHSZ		(1 << FMODSW_LOG_HASHSZ)

static fmodsw_impl_t	*fmodsw_hash[FMODSW_HASHSZ];
static krwlock_t	fmodsw_lock;

/*
 * Debug code:
 *
 * This is not conditionally compiled since it may be useful to third
 * parties when developing new modules.
 */

#define	BUFSZ	512

#define	FMODSW_INIT		0x00000001
#define	FMODSW_REGISTER		0x00000002
#define	FMODSW_UNREGISTER	0x00000004
#define	FMODSW_FIND		0x00000008

uint32_t	fmodsw_debug_flags = 0x00000000;

static void fmodsw_dprintf(uint_t flag, const char *fmt, ...) __KPRINTFLIKE(2);

/* PRINTFLIKE2 */
static void
i_fmodsw_dprintf(uint_t flag, const char *fmt, ...)
{
	va_list	alist;
	char	buf[BUFSZ + 1];
	char	*ptr;

	if (fmodsw_debug_flags & flag) {
		va_start(alist, fmt);
		ptr = buf;
		(void) sprintf(ptr, "strmod debug: ");
		ptr += strlen(buf);
		(void) vsnprintf(ptr, buf + BUFSZ - ptr, fmt, alist);
		printf(buf);
		va_end(alist);
	}
}


/*
 * Local functions:
 */

#define	FMODSW_HASH(_key) \
	(uint_t)(((_key[0] << 4) | (_key[1] & 0x0f)) & (FMODSW_HASHSZ - 1))

#define	FMODSW_KEYCMP(_k1, _k2, _match)					\
	{								\
		char	*p1 = (char *)(_k1);				\
		char	*p2 = (char *)(_k2);				\
									\
		while (*p1 == *p2++) {					\
			if (*p1++ == '\0') {				\
				goto _match;				\
			}						\
		}							\
	}

static int
i_fmodsw_hash_insert(fmodsw_impl_t *fp)
{
	uint_t		bucket;
	fmodsw_impl_t	**pp;
	fmodsw_impl_t	*p;

	ASSERT(rw_write_held(&fmodsw_lock));

	bucket = FMODSW_HASH(fp->f_name);
	for (pp = &(fmodsw_hash[bucket]); (p = *pp) != NULL;
	    pp = &(p->f_next))
		FMODSW_KEYCMP(p->f_name, fp->f_name, found);

	fp->f_next = p;
	*pp = fp;
	return (0);

found:
	return (EEXIST);
}

static int
i_fmodsw_hash_remove(const char *name, fmodsw_impl_t **fpp)
{
	uint_t		bucket;
	fmodsw_impl_t	**pp;
	fmodsw_impl_t	*p;

	ASSERT(rw_write_held(&fmodsw_lock));

	bucket = FMODSW_HASH(name);
	for (pp = &(fmodsw_hash[bucket]); (p = *pp) != NULL;
	    pp = &(p->f_next))
		FMODSW_KEYCMP(p->f_name, name, found);

	return (ENOENT);

found:
	if (p->f_ref > 0)
		return (EBUSY);

	*pp = p->f_next;
	*fpp = p;
	return (0);
}

static int
i_fmodsw_hash_find(const char *name, fmodsw_impl_t **fpp)
{
	uint_t		bucket;
	fmodsw_impl_t	*p;
	int		rc = 0;

	ASSERT(rw_read_held(&fmodsw_lock));

	bucket = FMODSW_HASH(name);
	for (p = fmodsw_hash[bucket]; p != NULL; p = p->f_next)
		FMODSW_KEYCMP(p->f_name, name, found);

	rc = ENOENT;
found:
	*fpp = p;
#ifdef	DEBUG
	if (p != NULL)
		p->f_hits++;
#endif	/* DEBUG */

	return (rc);
}


/*
 * Exported functions:
 */

int
fmodsw_register(const char *name, struct streamtab *str, int flag)
{
	fmodsw_impl_t	*fp;
	int		len;
	int		err;
	uint_t	qflag;
	uint_t	sqtype;

	if ((len = strlen(name)) > FMNAMESZ)
		return (EINVAL);

	if ((fp = kmem_zalloc(sizeof (fmodsw_impl_t), KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	(void) strncpy(fp->f_name, name, len);
	fp->f_name[len] = '\0';

	if ((err = devflg_to_qflag(str, flag, &qflag, &sqtype)) != 0)
		goto failed;

	fp->f_str = str;
	fp->f_qflag = qflag;
	fp->f_sqtype = sqtype;
	if (qflag & (QPERMOD | QMTOUTPERIM))
		fp->f_dmp = hold_dm(str, qflag, sqtype);

	rw_enter(&fmodsw_lock, RW_WRITER);
	if ((err = i_fmodsw_hash_insert(fp)) != 0) {
		rw_exit(&fmodsw_lock);
		goto failed;
	}
	rw_exit(&fmodsw_lock);

	i_fmodsw_dprintf(FMODSW_REGISTER, "registered module '%s'\n", name);
	return (0);
failed:
	i_fmodsw_dprintf(FMODSW_REGISTER, "failed to register module '%s'\n",
	    name);
	if (fp->f_dmp != NULL)
		rele_dm(fp->f_dmp);
	kmem_free(fp, sizeof (fmodsw_impl_t));
	return (err);
}

int
fmodsw_unregister(const char *name)
{
	fmodsw_impl_t	*fp;
	int		err;

	rw_enter(&fmodsw_lock, RW_WRITER);
	if ((err = i_fmodsw_hash_remove(name, &fp)) != 0) {
		rw_exit(&fmodsw_lock);
		goto failed;
	}
	rw_exit(&fmodsw_lock);

	if (fp->f_dmp != NULL)
		rele_dm(fp->f_dmp);
	kmem_free(fp, sizeof (fmodsw_impl_t));

	i_fmodsw_dprintf(FMODSW_UNREGISTER, "unregistered module '%s'\n",
	    name);
	return (0);
failed:
	i_fmodsw_dprintf(FMODSW_UNREGISTER, "failed to unregister module "
	    "'%s'\n", name);
	return (err);
}

fmodsw_impl_t *
fmodsw_find(const char *name, fmodsw_flags_t flags)
{
	fmodsw_impl_t	*fp;
	int		id;

try_again:
	rw_enter(&fmodsw_lock, RW_READER);
	if (i_fmodsw_hash_find(name, &fp) == 0) {
		if (flags & FMODSW_HOLD) {
			atomic_inc_32(&(fp->f_ref));	/* lock must be held */
			ASSERT(fp->f_ref > 0);
		}

		rw_exit(&fmodsw_lock);
		return (fp);
	}
	rw_exit(&fmodsw_lock);

	if (flags & FMODSW_LOAD) {
		if ((id = modload("strmod", (char *)name)) != -1) {
			i_fmodsw_dprintf(FMODSW_FIND,
			    "module '%s' loaded: id = %d\n", name, id);
			goto try_again;
		}
	}

	return (NULL);
}

void
fmodsw_rele(fmodsw_impl_t *fp)
{
	ASSERT(fp->f_ref > 0);
	atomic_dec_32(&(fp->f_ref));
}
