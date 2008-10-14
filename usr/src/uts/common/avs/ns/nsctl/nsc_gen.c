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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/varargs.h>
#if defined(DEBUG) && !defined(DS_DDICT)
#include <sys/kobj.h>
#endif

#include <sys/ncall/ncall.h>

#define	__NSC_GEN__
#include "nsc_gen.h"
#include "nsc_mem.h"
#include "../nsctl.h"
#ifdef DS_DDICT
#include "../contract.h"
#endif


static kcondvar_t _nsc_delay_cv;
static kmutex_t _nsc_delay_mutex;

static nsc_service_t *_nsc_services;
static kmutex_t _nsc_svc_mutex;

static int _nsc_rmmap_inuse(nsc_rmmap_t *, ulong_t *, size_t *);

static void _nsc_sprint_dec(char **, int, int, int);
static void _nsc_sprint_hex(char **, unsigned int, int, int, int, int);

clock_t HZ;

extern nsc_rmhdr_t *_nsc_rmhdr_ptr;

void
_nsc_init_gen()
{
	HZ = drv_usectohz(1000000);
}


void
nsc_decode_param(nsc_def_t *args, nsc_def_t *def, long *v)
{
	nsc_def_t *dp;

	for (; def && def->name; def++) {
		for (dp = args; dp && dp->name; dp++) {
			if (strcmp(dp->name, def->name) == 0) {
				v[def->offset] = dp->value;
				break;
			}
		}

		if ((!dp || !dp->name) && !v[def->offset])
			v[def->offset] = def->value;
	}
}


clock_t
nsc_lbolt()
{
#ifdef _SunOS_5_6
	clock_t lbolt;
	time_t time;

	if (drv_getparm(LBOLT, &lbolt) == 0)
		return (lbolt);

	if (drv_getparm(TIME, &time) != 0)
		return ((clock_t)0);

	time %= (60 * 60 * 24 * 365);

	return (clock_t)(time * HZ);
#else
	return (ddi_get_lbolt());
#endif
}


time_t
nsc_time()
{
	time_t time;

	if (drv_getparm(TIME, &time) != 0)
		return ((time_t)0);

	return (time);
}


int
nsc_node_up(int node)
{
	return (node == ncall_self());
}



/*
 * HACK increment nodeid in data parameter
 */
int
nsc_nodeid_data()
{
	int data;
	return ((data = nsc_node_id()) == 0 ? 1 : data);
}


int
nsc_node_id(void)
{
	return (ncall_self());
}

char *
nsc_node_name()
{
	return (ncall_nodename(ncall_self()));
}


/*
 * int
 * _nsc_rmmap_init (nsc_rmmap_t *map, char *name, int nslot,
 *					size_t size, ulong_t offset)
 *	Initialise a global resource map.
 *
 * Calling/Exit State:
 *	Returns TRUE if the map was successfully created. Otherwise
 *	returns FALSE.
 *
 * Description:
 *	Initialises a global resource map. If the map already exists
 *	the arguments are validated against it.
 */
int
_nsc_rmmap_init(nsc_rmmap_t *map, char *name,
    int nslot, size_t size, ulong_t offset)
{
	nsc_rmmap_t *nvmap = NULL;

	if (!size)
		return (0);

	mutex_enter(&_nsc_global_lock);

	if (_nsc_rm_nvmem_base)
		nvmap = _nsc_global_nvmemmap_lookup(map);

	if (!map->size)
		map->size = size;
	if (!map->inuse)
		map->inuse = nslot;
	if (!map->offset)
		map->offset = offset;

	if (!map->name[0])
		(void) strncpy(map->name, name, _NSC_MAXNAME);

	/* actually we only need to do this if an update occurred above */
	if (nvmap) {
		(void) nsc_commit_mem(map, nvmap,
		    sizeof (nsc_rmmap_t), nsc_cm_errhdlr);
	}

	if (strncmp(map->name, name, _NSC_MAXNAME) ||
	    (uint32_t)size != map->size || (int32_t)offset != map->offset) {
		mutex_exit(&_nsc_global_lock);
		return (0);
	}

	mutex_exit(&_nsc_global_lock);
	return (1);
}


/*
 * ulong_t
 * _nsc_rmmap_alloc (nsc_rmmap_t *map, char *name,
 *					size_t size, void (*alloc)())
 *	Allocate entry in a global resource map.
 *
 * Calling/Exit State:
 *	On success, returns the base of the allocated area. Otherwise,
 *	returns NULL. The function 'alloc' will be called if the
 *	allocated area is not currently in use.
 *
 * Description:
 *	Allocates an entry in the global resource map. If the entry
 *	already exists but is a different size an error is returned.
 */
ulong_t
_nsc_rmmap_alloc(nsc_rmmap_t *map, char *name, size_t size, void (*alloc)())
{
	int i, nslot = map[0].inuse;
	size_t want = size;
	ulong_t offset;
	nsc_rmmap_t *nvmap = NULL;

	if (!size)
		return (0);

	mutex_enter(&_nsc_global_lock);
	if (_nsc_rm_nvmem_base)
		nvmap = _nsc_global_nvmemmap_lookup(map);

	for (i = 1; i < nslot; i++) {
		if (!map[i].inuse || !map[i].size)
			continue;
		if (strncmp(map[i].name, name, _NSC_MAXNAME))
			continue;
		if ((uint32_t)size == map[i].size) {
			map[i].inuse |= (1 << nsc_node_id());
			if (nvmap) {
				(void) nsc_commit_mem(&map[i], &nvmap[i],
				    sizeof (nsc_rmmap_t), nsc_cm_errhdlr);
			}
			mutex_exit(&_nsc_global_lock);
			return (map[i].offset);
		}

		mutex_exit(&_nsc_global_lock);
		return (0);
	}

	offset = map[0].offset;

	while ((int32_t)offset < (map[0].offset + map[0].size)) {
		if (_nsc_rmmap_inuse(map, &offset, &want))
			continue;

		if (size > want) {
			offset += want;
			want = size;
			continue;
		}

		for (i = 1; i < nslot; i++)
			if (!map[i].inuse || !map[i].size)
				break;

		if (i == nslot)
			break;

		bzero(&map[i], sizeof (map[i]));
		(void) strncpy(map[i].name, name, _NSC_MAXNAME);

		map[i].size = size;
		map[i].offset = offset;
		map[i].inuse = (1 << nsc_node_id());
		if (nvmap) {  /* update the map and hdr dirty bit. */
			(void) nsc_commit_mem(&map[i], &nvmap[i],
			    sizeof (nsc_rmmap_t), nsc_cm_errhdlr);
		}

		if (alloc)
			(*alloc)(offset, size);

		mutex_exit(&_nsc_global_lock);
		return (offset);
	}

	mutex_exit(&_nsc_global_lock);
	return (0);
}


/*
 * void
 * _nsc_rmmap_free (nsc_rmmap_t *map, char *name)
 *	Free entry in a global resource map.
 *
 * Description:
 *	Frees an entry in the global resource map.
 */
void
_nsc_rmmap_free(nsc_rmmap_t *map, char *name, nsc_mem_t *mp)
{
	int i, nslot = map[0].inuse;
	nsc_rmmap_t *nvmap = NULL;

	mutex_enter(&_nsc_global_lock);
	if (_nsc_rm_nvmem_base)
		nvmap = _nsc_global_nvmemmap_lookup(map);

	for (i = 1; i < nslot; i++) {
		if (!map[i].inuse || !map[i].size)
			continue;
		if (strncmp(map[i].name, name, _NSC_MAXNAME))
			continue;

		map[i].inuse &= ~(1 << nsc_node_id());
		if (nvmap) {
			/*
			 * if dirty, set the inuse bit so this area
			 * will not be _nsc_global_zero'd on restart.
			 */
			if (mp && (mp->type & NSC_MEM_NVDIRTY)) {
				map[i].inuse |= (1 << nsc_node_id());
			}

			(void) nsc_commit_mem(&map[i], &nvmap[i],
			    sizeof (nsc_rmmap_t), nsc_cm_errhdlr);
		}
		mutex_exit(&_nsc_global_lock);
		return;
	}

	mutex_exit(&_nsc_global_lock);

	cmn_err(CE_WARN, "nsctl: _nsc_rmmap_free: invalid free");
}


/*
 * size_t
 * _nsc_rmmap_size (nsc_rmmap_t *map, char *name)
 *	Find size of area in map.
 *
 * Calling/Exit State:
 *	Returns the size of the specified area in the map,
 *	or 0 if it is currently unallocated.
 */
size_t
_nsc_rmmap_size(nsc_rmmap_t *map, char *name)
{
	int i, nslot = map[0].inuse;
	size_t size = 0;

	mutex_enter(&_nsc_global_lock);

	for (i = 1; i < nslot; i++) {
		if (!map[i].inuse || !map[i].size)
			continue;

		if (strncmp(map[i].name, name, _NSC_MAXNAME) == 0) {
			size = map[i].size;
			break;
		}
	}

	mutex_exit(&_nsc_global_lock);
	return (size);
}


/*
 * size_t
 * _nsc_rmmap_avail (nsc_rmmap_t *map)
 *	Find available space in global resource map.
 *
 * Calling/Exit State:
 *	Returns the size of the largest available area in
 *	the global resource map.
 */
size_t
_nsc_rmmap_avail(nsc_rmmap_t *map)
{
	size_t size, avail = 0;
	ulong_t offset;

	mutex_enter(&_nsc_global_lock);

	size = 1;
	offset = map[0].offset;

	while ((int32_t)offset < (map[0].offset + map[0].size))
		if (!_nsc_rmmap_inuse(map, &offset, &size)) {
			if (size > avail)
				avail = size;
			offset += size;
			size = 1;
		}

	mutex_exit(&_nsc_global_lock);
	return (avail);
}


/*
 * static int
 * _nsc_rmmap_inuse (nsc_rmmap_t *map, ulong_t *offsetp, size_t *sizep)
 *	Check if a section of the map is in use.
 *
 * Calling/Exit State:
 *	The global lock must be held across calls to the function.
 *
 *	Returns TRUE if the specified area is currently in use and
 *	updates offset to point just past the section that was found
 *	to be in use.
 *
 *	Otherwise, returns FALSE and updates size to reflect the
 *	amount of free space at the specified offset.
 *
 * Description:
 *	Checks the specified global map to determine if any part
 *	of the area is in use.
 */
static int
_nsc_rmmap_inuse(nsc_rmmap_t *map, ulong_t *offsetp, size_t *sizep)
{
	size_t avail, size = (*sizep);
	ulong_t offset = (*offsetp);
	int i, nslot;

	nslot = map[0].inuse;
	avail = map[0].offset + map[0].size - offset;

	for (i = 1; i < nslot; i++) {
		if (!map[i].size || !map[i].inuse)
			continue;
		if ((int32_t)(offset + size) > map[i].offset &&
		    (int32_t)offset < (map[i].offset + map[i].size)) {
			(*offsetp) = map[i].offset + map[i].size;
			return (1);
		}

		if (map[i].offset >= (int32_t)offset)
			if (avail > map[i].offset - offset)
				avail = map[i].offset - offset;
	}

	(*sizep) = avail;
	return (0);
}

/*
 * int
 * nsc_delay_sig (clock_t tics)
 *	Delay for a number of clock ticks.
 *
 * Calling/Exit State:
 *	Returns FALSE if the delay was interrupted by a
 *	signal, TRUE otherwise.
 *
 * Description:
 *	Delays execution for the specified number of ticks
 *	or until a signal is received.
 */
int
nsc_delay_sig(clock_t tics)
{
	clock_t target, remain, rc;

	target = nsc_lbolt() + tics;
	rc = 1;

	mutex_enter(&_nsc_delay_mutex);

	/* CONSTCOND */

	while (1) {
		remain = target - nsc_lbolt();

		if (remain <= 0 || rc == -1) {
			/* timeout */
			break;
		}

		rc = cv_timedwait_sig(&_nsc_delay_cv,
		    &_nsc_delay_mutex, target);

		if (rc == 0) {
			/* signalled */
			mutex_exit(&_nsc_delay_mutex);
			return (FALSE);
		}
	}

	mutex_exit(&_nsc_delay_mutex);

	return (TRUE);
}


/*
 * void
 * nsc_sprintf (char *s, char *fmt, ...)
 *	String printf.
 *
 * Calling/Exit State:
 *	Builds a NULL terminated string in the buffer
 *	pointed to by 's', using the format 'fmt'.
 *
 * Description:
 *	Simple version of sprintf supporting fairly
 *	basic formats.
 */

/* PRINTFLIKE2 */

void
nsc_sprintf(char *s, char *fmt, ...)
{
	int alt, zero, len;
	char c, *cp;
	va_list p;

	va_start(p, fmt);

	/* CONSTCOND */

	while (1) {
		alt = 0, zero = 0, len = 0;

		if ((c = *fmt++) != '%') {
			if (!c)
				break;
			*s++ = c;
			continue;
		}

		if ((c = *fmt++) == 0) {
			*s++ = '%';
			break;
		}

		alt = (c == '#');
		if (alt && !(c = *fmt++))
			break;

		zero = (c == '0');
		if (zero && !(c = *fmt++))
			break;

		while ((len ? '0' : '1') <= c && c <= '9') {
			len = (len * 10) + (c - '0');
			if (!(c = *fmt++))
				break;
		}

		if (c == 's') {
			cp = (char *)va_arg(p, caddr_t);
			while (*cp)
				*s++ = *cp++;
			continue;
		}

		if (c == 'd' || c == 'u') {
			_nsc_sprint_dec(&s, va_arg(p, int), zero, len);
			continue;
		}

		if (c == 'x' || c == 'X') {
			_nsc_sprint_hex(&s, va_arg(p, uint_t),
			    (c == 'X'), alt, zero, len);
			continue;
		}

		*s++ = '%';
		if (alt)
			*s++ = '#';
		if (zero)
			*s++ = '0';

		if (len)
			_nsc_sprint_dec(&s, len, 0, 0);
		*s++ = c;
	}

	if (alt || zero || len) {
		*s++ = '%';

		if (alt)
			*s++ = '#';
		if (zero)
			*s++ = '0';

		if (len)
			_nsc_sprint_dec(&s, len, 0, 0);
	}

	va_end(p);
	*s = 0;
}


/*
 * static void
 * _nsc_sprint_dec (char **sptr, int n, int zero, int len)
 *	Decimal to string conversion.
 *
 * Calling/Exit State:
 *	Stores a character representation of 'n' in the
 *	buffer referenced by 'sptr' and	updates the pointer
 *	accordingly.
 *
 * Description:
 *	Generates a string representation of a signed decimal
 *	integer.
 */

static void
_nsc_sprint_dec(char **sptr, int n, int zero, int len)
{
	unsigned int v = (n < 0) ? (-n) : n;
	char c[20];
	int i;

	for (i = 0; v; i++) {
		c[i] = (v % 10) + '0';
		v /= 10;
	}

	len -= (i ? i : 1);

	if (n < 0 && !zero)
		for (len--; len > 0; len--)
			*(*sptr)++ = ' ';

	if (n < 0) {
		*(*sptr)++ = '-';
		len--;
	}

	for (; len > 0; len--)
		*(*sptr)++ = (zero ? '0' : ' ');

	if (!i)
		*(*sptr)++ = '0';

	while (i--)
		*(*sptr)++ = c[i];
}


/*
 * static void
 * _nsc_sprint_hex (char **sptr, unsigned int v,
 *			int up, int alt, int zero, int len)
 *	Hexadecimal to string conversion.
 *
 * Calling/Exit State:
 *	Stores a character representation of 'v' in the
 *	buffer referenced by 'sptr' and	updates the pointer
 *	accordingly.
 *
 * Description:
 *	Generates a string representation of an unsigned
 *	hexadecimal integer.
 */

static void
_nsc_sprint_hex(char **sptr, uint_t v, int up, int alt, int zero, int len)
{
	char *str = "0123456789abcdef";
	char c[20];
	int i;

	if (up)
		str = "0123456789ABCDEF";

	for (i = 0; v; i++) {
		c[i] = str[(v % 16)];
		v /= 16;
	}

	if (alt) {
		*(*sptr)++ = '0';
		*(*sptr)++ = (up ? 'X' : 'x');
	}

	for (len -= (i ? i : 1); len > 0; len--)
		*(*sptr)++ = (zero ? '0' : ' ');

	if (!i)
		*(*sptr)++ = '0';
	while (i--)
		*(*sptr)++ = c[i];
}


/*
 * char *
 * nsc_strdup (char *s)
 *	Duplicate string.
 *
 * Calling/Exit State:
 *	Returns the address of the new string.
 *
 * Description:
 *	Allocates a suitably sized area of memory and
 *	copies the string into it. The string should be
 *	free'd using nsc_strfree().
 */
char *
nsc_strdup(char *s)
{
	char *cp;

	if (s == NULL)
		return (NULL);

	cp = nsc_kmem_alloc(strlen(s) + 1, KM_SLEEP, NULL);
	(void) strcpy(cp, s);
	return (cp);
}


/*
 * void
 * nsc_strfree (char *s)
 *	Free string.
 *
 * Description:
 *	Frees a string previously allocated by nsc_strdup.
 */
void
nsc_strfree(char *s)
{
	if (s)
		nsc_kmem_free(s, strlen(s) + 1);
}


/*
 * int
 * nsc_strmatch (char *s, char *pat)
 *	Match string against pattern.
 *
 * Calling/Exit State:
 *	Returns TRUE if the string matches against the
 *	pattern, FALSE otherwise.
 *
 * Description:
 *	Compares string against regular expression which
 *	can contain '*', '?' and '[]' constructs.
 */
int
nsc_strmatch(char *s, char *pat)
{
	int neg;

	for (; *pat; pat++, s++) {
		if (*pat == '*') {
			while (*pat == '*')
				pat++;

			if (!*pat)
				return (1);

			for (; *s; s++)
				if (*pat == '[' || *pat == '?' || *pat == *s)
					if (nsc_strmatch(s, pat))
						return (1);
			return (0);
		}

		if (!*s)
			return (0);

		if (*pat == '[') {
			if ((neg = (*++pat == '^')) != 0)
				pat++;

			while (*pat) {
				if (*pat == *s)
					break;

				if (pat[1] == '-' && pat[2] != ']') {
					if (*pat <= *s && *s <= pat[2])
						break;
					pat += 2;
				}

				if (*++pat == ']') {
					if (neg)
						goto lp;
					else
						return (0);
				}
			}

			while (*pat && *++pat != ']')
			;

			if (!*pat || neg)
				return (0);
		    lp:
			continue;
		}

		if (*pat != '?' && *pat != *s)
			return (0);
	}

	return (!*s);
}


/*
 * uint64_t
 * nsc_strhash(char *str)
 *	Calculate a simple hash for the specified string
 *
 * Calling/Exit State:
 *	Returns a simple hash of the NULL terminated string, str.
 *
 * Description:
 */
uint64_t
nsc_strhash(char *str)
{
	uint64_t hash = (uint64_t)0;

	if (str == NULL)
		return (hash);

	while (*str != '\0') {
		hash <<= 1;
		hash += (uint64_t)*str;
		str++;
	}

	return (hash);
}


/*
 * int
 * nsc_fatal(void)
 *	Fatal error stub function
 *
 * Calling/Exit State:
 *	Returns EINVAL (non-DEBUG) or forces a panic.
 *
 * Description:
 *	This is a stub function suitable for default actions in
 *	nsctl i/o provider definitions. It should be used when
 *	calling the stub would be a programming error. The most
 *	common reason for nsc_fatal() being called is that an
 *	nsctl client module has called an nsc_fd_t i/o function
 *	without the fd already reserved.
 *
 *	The function will display a diagnostic message and when
 *	built -DDEBUG will force a panic and display the textual
 *	name of the symbol closest to the caller address of this
 *	function.
 */
int
nsc_fatal()
{
	void *caller = nsc_caller();
#ifdef DEBUG
	caddr_t caller_sym = NULL;
	ulong_t offset = 0UL;

#ifndef DS_DDICT
	caller_sym = kobj_getsymname((uintptr_t)caller, &offset);
#endif	/* !DS_DDICT */

	cmn_err(CE_WARN, "nsctl: nsc_fatal called at 0x%p (%s+0x%lx)",
	    caller, caller_sym ? caller_sym : "?", offset);

	/*
	 * Force TRAP due to NULL pointer dereference
	 * - CE_PANIC can result in the stack trace being unreadable
	 * by (k)adb.
	 */
	*(int *)0 = 0x12345678;

#else	/* !DEBUG */

	cmn_err(CE_WARN, "nsctl: nsc_fatal called at 0x%p", caller);

#endif	/* DEBUG */

	return (EINVAL);
}


int nsc_null() { return (0); }
int nsc_true() { return (1); }
int nsc_inval() { return (-1); }
int nsc_ioerr() { return (EIO); }

/*ARGSUSED*/
int
nsc_commit_mem(void *src, void *dst, size_t len, nsc_mem_err_cb err_action)
{

	return (0);
}

static int _nsc_nvmem_errs;

/* ARGSUSED */
void
nsc_cm_errhdlr(void *src, void *dst, size_t len, int errval)
{
	static int _nsc_baddma_already_seen = 0;

	if (!(_nsc_baddma_already_seen % 100)) {
		cmn_err(CE_WARN, "nsc_cm_errhdlr: media down, forced_wrthru");

		_nsc_baddma_already_seen += 1;

		if (_nsc_baddma_already_seen >= 100) {
			cmn_err(CE_WARN,
			    "nsc_cm_errhdlr: this message "
			    "displayed every 100 errors");
		}
	}

	(void) nsc_node_hints_set(NSC_FORCED_WRTHRU);

	_nsc_nvmem_errs++;
}


void
_nsc_init_svc(void)
{
	mutex_init(&_nsc_svc_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&_nsc_delay_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&_nsc_delay_cv, NULL, CV_DRIVER, NULL);
}


void
_nsc_deinit_svc(void)
{
	if (_nsc_services != NULL) {
		cmn_err(CE_PANIC,
			"nsctl: services registered in _nsc_deinit_svc");
		/* NOTREACHED */
	}

	cv_destroy(&_nsc_delay_cv);
	mutex_destroy(&_nsc_delay_mutex);
	mutex_destroy(&_nsc_svc_mutex);
}


nsc_svc_t *
nsc_register_svc(char *name, void (*service_fn)(intptr_t))
{
	nsc_service_t *sp, *new;
	nsc_svc_t *svc;

	new = nsc_kmem_zalloc(sizeof (*new), KM_SLEEP, 0);
	if (new == NULL)
		return (NULL);

	svc = nsc_kmem_zalloc(sizeof (*svc), KM_SLEEP, 0);
	if (svc == NULL) {
		nsc_kmem_free(new, sizeof (*new));
		return (NULL);
	}

	mutex_enter(&_nsc_svc_mutex);

	for (sp = _nsc_services; sp != NULL; sp = sp->s_next)
		if (strcmp(name, sp->s_name) == 0)
			break;

	if (sp == NULL) {
		sp = new;
		sp->s_name = nsc_strdup(name);
		if (sp->s_name == NULL) {
			mutex_exit(&_nsc_svc_mutex);
			nsc_kmem_free(new, sizeof (*new));
			nsc_kmem_free(svc, sizeof (*svc));
			return (NULL);
		}

		rw_init(&sp->s_rwlock, NULL, RW_DRIVER, NULL);
		sp->s_next = _nsc_services;
		_nsc_services = sp;
	}

	rw_enter(&sp->s_rwlock, RW_WRITER);

	svc->svc_fn = service_fn;
	svc->svc_svc = sp;

	if (svc->svc_fn != NULL) {
		svc->svc_next = sp->s_servers;
		sp->s_servers = svc;
	} else {
		svc->svc_next = sp->s_clients;
		sp->s_clients = svc;
	}

	rw_exit(&sp->s_rwlock);
	mutex_exit(&_nsc_svc_mutex);

	if (sp != new)
		nsc_kmem_free(new, sizeof (*new));

	return (svc);
}


int
nsc_unregister_svc(nsc_svc_t *svc)
{
	nsc_service_t *sp, **spp;
	nsc_svc_t **svcp;

	if (svc == NULL)
		return (EINVAL);

	sp = svc->svc_svc;
	if (sp == NULL)
		return (EINVAL);

	mutex_enter(&_nsc_svc_mutex);
	rw_enter(&sp->s_rwlock, RW_WRITER);

	svcp = (svc->svc_fn == NULL) ? &sp->s_clients : &sp->s_servers;
	for (; *svcp; svcp = &((*svcp)->svc_next))
		if (svc == (*svcp))
			break;

	if (*svcp)
		(*svcp) = svc->svc_next;

	nsc_kmem_free(svc, sizeof (*svc));

	if (sp->s_servers == NULL && sp->s_clients == NULL) {
		for (spp = &_nsc_services; *spp; spp = &((*spp)->s_next))
			if ((*spp) == sp)
				break;

		if (*spp)
			(*spp) = sp->s_next;

		rw_exit(&sp->s_rwlock);
		mutex_exit(&_nsc_svc_mutex);

		rw_destroy(&sp->s_rwlock);
		nsc_strfree(sp->s_name);

		nsc_kmem_free(sp, sizeof (*sp));
		return (0);
	}

	rw_exit(&sp->s_rwlock);
	mutex_exit(&_nsc_svc_mutex);

	return (0);
}


int
nsc_call_svc(nsc_svc_t *svc, intptr_t arg)
{
	nsc_service_t *sp;
	nsc_svc_t *svcp;
	int found;

	if (svc == NULL)
		return (EINVAL);

	sp = svc->svc_svc;
	if (sp == NULL)
		return (EINVAL);

	rw_enter(&sp->s_rwlock, RW_READER);

	found = (sp->s_servers != NULL);

	for (svcp = sp->s_servers; svcp; svcp = svcp->svc_next)
		(*svcp->svc_fn)(arg);

	rw_exit(&sp->s_rwlock);

	if (found == 0)
		return (ENOSYS);

	return (0);
}
