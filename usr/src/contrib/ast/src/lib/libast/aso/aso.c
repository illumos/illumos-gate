/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include "asohdr.h"
#include "FEATURE/aso"

#if defined(_UWIN) && defined(_BLD_ast)

NoN(aso)

#else

/*
 * ast atomic scalar operations
 * AT&T Research
 *
 * cas { 8 16 32 [64] } subset snarfed from the work by
 * Adam Edgar and Kiem-Phong Vo 2010-10-10
 *
 * lock methods and emulations by
 * Glenn Fowler 2011-11-11
 *
 * hopefully stable by 2012-12-12
 */

#if !_PACKAGE_ast

#if _UWIN

extern ssize_t		sfsprintf(char*, size_t, const char*, ...);

#else

#include <stdio.h>

#define sfsprintf	snprintf

#endif

#endif

#if defined(_aso_casptr) && (defined(_aso_cas32) || defined(_aso_cas64))
#define ASO_METHOD		(&_aso_meth_intrinsic)
#define ASO_LOCKF		0
#else
#define ASO_METHOD		(&_aso_meth_signal)
#define ASO_LOCKF		_aso_lock_signal
#endif

typedef union
{
	uint8_t			c[2];
	uint16_t		i;
} U16_8_t;

typedef union
{
	uint8_t			c[4];
	uint32_t		i;
} U32_8_t;

typedef union
{
	uint16_t		c[2];
	uint32_t		i;
} U32_16_t;

#ifdef _ast_int8_t

typedef union
{
	uint8_t			c[8];
	uint64_t		i;
} U64_8_t;

typedef union
{
	uint16_t		c[4];
	uint64_t		i;
} U64_16_t;

typedef union
{
	uint32_t		c[2];
	uint64_t		i;
} U64_32_t;

#endif

typedef struct State_s
{
	Asometh_t*		meth;
	Asolock_f		lockf;
	Asoerror_f		errorf;
	uintmax_t		hung;
	unsigned int		hung2;
	void*			data;
	pid_t			pid;
} State_t;

static unsigned int		_aso_data_signal;

static ssize_t
_aso_lock_signal(void* data, ssize_t k, void volatile* p)
{
	if (k >= 0)
	{
		_aso_data_signal--;
		return 0;
	}
	while (_aso_data_signal++)
		_aso_data_signal--;
	return 1;
}

static Asometh_t	_aso_meth_signal =    { "signal",    ASO_SIGNAL,    0, _aso_lock_signal };
extern Asometh_t	_aso_meth_semaphore;
extern Asometh_t	_aso_meth_fcntl;
static Asometh_t	_aso_meth_intrinsic = { "intrinsic", ASO_INTRINSIC|ASO_PROCESS|ASO_THREAD|ASO_SIGNAL, 0, 0 };

static Asometh_t*	method[] =
{
	&_aso_meth_signal,
#if defined(_ast_int8_t) && defined(_aso_cas64) || !defined(_ast_int8_t) && defined(_aso_cas32)
	&_aso_meth_intrinsic,
#endif
#if _aso_semaphore
	&_aso_meth_semaphore,
#endif
#if _aso_fcntl
	&_aso_meth_fcntl,
#endif
};

static State_t			state =
{
	ASO_METHOD, ASO_LOCKF
};

static int
asoerror(int type, const char* format, const char* a, const char* b, long n)
{
	char	buf[128];

	if (b)
		sfsprintf(buf, sizeof(buf), format, a, b, n);
	else if (a)
		sfsprintf(buf, sizeof(buf), format, a, n);
	else
		sfsprintf(buf, sizeof(buf), format, n);
	return state.errorf(type, buf);
}

/*
 * if type!=0 return lock method for type with name details
 * else if name!=0 return lock method matching <name>[,<details>]
 * else return the current lock method
 * 0 returned on error
 *
 * the user visible asometh() calls this function
 * it allows, e.g., for -ltaso to provide an asometh() intercept
 * that prepends its ASO_THREAD methods ahead of the _asometh() methods
 */

Asometh_t*
_asometh(int type, void* data)
{
	size_t		n;
	int		i;
	char*		e;
	Asometh_t*	meth;
	char*		name;

	if (type == ASO_NEXT)
	{
		if (!(meth = (Asometh_t*)data))
			return method[0];
		for (i = 0; i < elementsof(method) - 1; i++)
			if (meth == method[i])
				return method[i+1];
		return 0;
	}
	if (type)
	{
		for (i = 0; i < elementsof(method); i++)
			if (method[i]->type & type)
			{
				method[i]->details = (char*)data;
				return method[i];
			}
		return 0;
	}
	if (!(name = (char*)data))
		return state.meth;
	n = (e = strchr(name, ',')) ? (e - name) : strlen(name);
	for (i = 0; i < elementsof(method); i++)
		if (strncmp(name, method[i]->name, n) == 0)
		{
			if (e)
				method[i]->details = e + 1;
			return method[i];
		}
	return 0;
}

/*
 * clean up lock method on exit
 */

static void
asoexit(void)
{
	if (state.meth && state.meth->initf && state.data && state.pid == getpid())
	{
		state.lockf = ASO_METHOD->lockf;
		state.meth->initf(state.data, 0);
		state.data = 0;
	}
}

/*
 * initialize lock method
 */

int
asoinit(const char* details, Asometh_t* meth, Asodisc_t* disc)
{
	void*		data;

	if (disc)
	{
		state.errorf = disc->errorf;
		state.hung2 = disc->hung;
		state.hung = 1;
		state.hung <<= state.hung2;
		state.hung--;
	}
	if (!meth)
		return state.pid != 0;
	if (!meth->lockf && !(meth->type & ASO_INTRINSIC))
	{
		if (state.errorf)
			asoerror(ASO_EMETHOD, "%s method has no lock function", meth->name, 0, 0);
		return -1;
	}
	state.lockf = ASO_METHOD->lockf;
	if (state.meth && state.meth->initf && state.data)
	{
		state.meth->initf(state.data, 0);
		state.data = 0;
	}
	if (!meth->initf)
		data = 0;
	else if (!(data = meth->initf(0, details ? details : meth->details)))
	{
		state.meth = ASO_METHOD;
		if (state.errorf)
			asoerror(ASO_EMETHOD, "%s method initialization failed -- reverting to the %s method", meth->name, state.meth->name, 0);
		return -1;
	}
	state.meth = meth;
	state.data = data;
	state.lockf = meth->lockf;
	if (!state.pid)
	{
		state.pid = getpid();
		atexit(asoexit);
	}
	return 0;
}

/*
 * loop check for hung spin locks
 * and periodic relinquishing of the processor
 */

int
asoloop(uintmax_t rep)
{
	if (state.hung && !(rep & state.hung) && state.errorf)
		return asoerror(ASO_EHUNG, "spin lock possibly hung after 2^%u attempts", 0, 0, state.hung2);
	return (rep & ASO_RELAX) ? 0 : asorelax(1);
}

/*
 * error checking state.lockf() call
 */

static ssize_t
lock(void* data, ssize_t k, void volatile* p)
{
	ssize_t		r;

	if ((r = state.lockf(data, k, p)) < 0 && state.errorf)
		asoerror(ASO_EMETHOD, "%s method lock failed", state.meth->name, 0, 0);
	return r;
}

/*
 * sync and return "current" value
 */

uint8_t
asoget8(uint8_t volatile* p)
{
	int	o;

	do
	{
		o = *p;
	} while (asocas8(p, o, o) != o);
	return o;
}

uint16_t
asoget16(uint16_t volatile* p)
{
	int	o;

	do
	{
		o = *p;
	} while (asocas16(p, o, o) != o);
	return o;
}

uint32_t
asoget32(uint32_t volatile* p)
{
	uint32_t	o;

	do
	{
		o = *p;
	} while (asocas32(p, o, o) != o);
	return o;
}

#ifdef _ast_int8_t

uint64_t
asoget64(uint64_t volatile* p)
{
	uint64_t	o;

	do
	{
		o = *p;
	} while (asocas64(p, o, o) != o);
	return o;
}

#endif

void*
asogetptr(void volatile* p)
{
	void*	o;

	do
	{
		o = *(void* volatile*)p;
	} while (asocasptr(p, o, o) != o);
	return o;
}

/*
 * increment and return old value
 */

uint8_t
asoinc8(uint8_t volatile* p)
{
	ssize_t		k;
	int		o;

#if defined(_aso_inc8)
	if (!state.lockf)
		return _aso_inc8(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas8(p, o, o + 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)++;
	lock(state.data, k, p);
	return o;
}

uint16_t
asoinc16(uint16_t volatile* p)
{
	ssize_t		k;
	int		o;

#if defined(_aso_inc16)
	if (!state.lockf)
		return _aso_inc16(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas16(p, o, o + 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)++;
	lock(state.data, k, p);
	return o;
}

uint32_t
asoinc32(uint32_t volatile* p)
{
	ssize_t		k;
	int		o;

#if defined(_aso_inc32)
	if (!state.lockf)
		return _aso_inc32(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas32(p, o, o + 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)++;
	lock(state.data, k, p);
	return o;
}

#ifdef _ast_int8_t

uint64_t
asoinc64(uint64_t volatile* p)
{
	ssize_t		k;
	uint64_t	o;

#if defined(_aso_inc64)
	if (!state.lockf)
		return _aso_inc64(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas64(p, o, o + 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)++;
	lock(state.data, k, p);
	return o;
}

#endif

/*
 * decrement and return old value
 */

uint8_t
asodec8(uint8_t volatile* p)
{
	ssize_t		k;
	int		o;

#if defined(_aso_dec8)
	if (!state.lockf)
		return _aso_dec8(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas8(p, o, o - 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)--;
	lock(state.data, k, p);
	return o;
}

uint16_t
asodec16(uint16_t volatile* p)
{
	ssize_t		k;
	int		o;

#if defined(_aso_dec16)
	if (!state.lockf)
		return _aso_dec16(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas16(p, o, o - 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)--;
	lock(state.data, k, p);
	return o;
}

uint32_t
asodec32(uint32_t volatile* p)
{
	ssize_t		k;
	int		o;

#if defined(_aso_dec32)
	if (!state.lockf)
		return _aso_dec32(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas32(p, o, o - 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)--;
	lock(state.data, k, p);
	return o;
}

#ifdef _ast_int8_t

uint64_t
asodec64(uint64_t volatile* p)
{
	ssize_t		k;
	uint64_t	o;

#if defined(_aso_dec64)
	if (!state.lockf)
		return _aso_dec64(p);
#else
	if (!state.lockf)
	{
		do
		{
			o = *p;
		} while (asocas64(p, o, o - 1) != o);
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	o = (*p)--;
	lock(state.data, k, p);
	return o;
}

#endif

/*
 * { 8 16 32 [64] } compare with old, swap with new if same, and return old value
 */

uint8_t
asocas8(uint8_t volatile* p, int o, int n)
{
	ssize_t		k;

#if defined(_aso_cas8)
	if (!state.lockf)
		return _aso_cas8(p, o, n);
#elif defined(_aso_cas16)
	if (!state.lockf)
	{
		U16_8_t		u;
		U16_8_t		v;
		U16_8_t*	a;
		int		s;
		int		i;

		s = (int)(integralof(p) & (sizeof(u.i) - 1));
		a = (U16_8_t*)((char*)0 + (integralof(p) & ~(sizeof(u.i) - 1)));
		for (;;)
		{
			u.i = a->i;
			u.c[s] = o;
			v.i = u.i;
			v.c[s] = n;
			if (_aso_cas16(&a->i, u.i, v.i) == u.i)
				break;
			for (i = 0;; i++)
				if (i >= elementsof(u.c))
					return a->c[s];
				else if (i != s && u.c[i] != a->c[i])
					break;
		}
		return o;
	}
#elif defined(_aso_cas32)
	if (!state.lockf)
	{
		U32_8_t		u;
		U32_8_t		v;
		U32_8_t*	a;
		int		s;
		int		i;

		s = (int)(integralof(p) & (sizeof(u.i) - 1));
		a = (U32_8_t*)((char*)0 + (integralof(p) & ~(sizeof(u.i) - 1)));
		for (;;)
		{
			u.i = a->i;
			u.c[s] = o;
			v.i = u.i;
			v.c[s] = n;
			if (_aso_cas32(&a->i, u.i, v.i) == u.i)
				break;
			for (i = 0;; i++)
				if (i >= elementsof(u.c))
					return a->c[s];
				else if (i != s && u.c[i] != a->c[i])
					break;
		}
		return o;
	}
#elif defined(_aso_cas64)
	if (!state.lockf)
	{
		U64_8_t		u;
		U64_8_t		v;
		U64_8_t*	a;
		int		s;
		int		i;

		s = (int)(integralof(p) & (sizeof(u.i) - 1));
		a = (U64_8_t*)((char*)0 + (integralof(p) & ~(sizeof(u.i) - 1)));
		for (;;)
		{
			u.i = a->i;
			u.c[s] = o;
			v.i = u.i;
			v.c[s] = n;
			if (_aso_cas64(&a->i, u.i, v.i) == u.i)
				break;
			for (i = 0;; i++)
				if (i >= elementsof(u.c))
					return a->c[s];
				else if (i != s && u.c[i] != a->c[i])
					break;
		}
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	if (*p == o)
		*p = n;
	else
		o = *p;
	lock(state.data, k, p);
	return o;
}

uint16_t
asocas16(uint16_t volatile* p, uint16_t o, uint16_t n)
{
	ssize_t		k;

#if defined(_aso_cas16)
	if (!state.lockf)
		return _aso_cas16(p, o, n);
#elif defined(_aso_cas32)
	if (!state.lockf)
	{
		U32_16_t	u;
		U32_16_t	v;
		U32_16_t*	a;
		int		s;
		int		i;

		s = (int)(integralof(p) & (sizeof(u.i) - 1)) / 2;
		a = (U32_16_t*)((char*)0 + (integralof(p) & ~(sizeof(u.i) - 1)));
		for (;;)
		{
			u.i = a->i;
			u.c[s] = o;
			v.i = u.i;
			v.c[s] = n;
			if (_aso_cas32(&a->i, u.i, v.i) == u.i)
				break;
			for (i = 0;; i++)
				if (i >= elementsof(u.c))
					return a->c[s];
				else if (i != s && u.c[i] != a->c[i])
					break;
		}
		return o;
	}
#elif defined(_aso_cas64)
	if (!state.lockf)
	{
		U64_16_t	u;
		U64_16_t	v;
		U64_16_t*	a;
		int		s;
		int		i;

		s = (int)(integralof(p) & (sizeof(u.i) - 1)) / 2;
		a = (U64_16_t*)((char*)0 + (integralof(p) & ~(sizeof(u.i) - 1)));
		for (;;)
		{
			u.i = a->i;
			u.c[s] = o;
			v.i = u.i;
			v.c[s] = n;
			if (_aso_cas64(&a->i, u.i, v.i) == u.i)
				break;
			for (i = 0;; i++)
				if (i >= elementsof(u.c))
					return a->c[s];
				else if (i != s && u.c[i] != a->c[i])
					break;
		}
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	if (*p == o)
		*p = n;
	else
		o = *p;
	lock(state.data, k, p);
	return o;
}

uint32_t
asocas32(uint32_t volatile* p, uint32_t o, uint32_t n)
{
	ssize_t		k;

#if defined(_aso_cas32)
	if (!state.lockf)
		return _aso_cas32(p, o, n);
#elif defined(_aso_cas64)
	if (!state.lockf)
	{
		U64_32_t	u;
		U64_32_t	v;
		U64_32_t*	a;
		int		s;
		int		i;

		s = (int)(integralof(p) & (sizeof(u.i) - 1)) / 4;
		a = (U64_32_t*)((char*)0 + (integralof(p) & ~(sizeof(u.i) - 1)));
		for (;;)
		{
			u.i = a->i;
			u.c[s] = o;
			v.i = u.i;
			v.c[s] = n;
			if (_aso_cas64(&a->i, u.i, v.i) == u.i)
				break;
			for (i = 0;; i++)
				if (i >= elementsof(u.c))
					return a->c[s];
				else if (i != s && u.c[i] != a->c[i])
					break;
		}
		return o;
	}
#endif
	k = lock(state.data, 0, p);
	if (*p == o)
		*p = n;
	else
		o = *p;
	lock(state.data, k, p);
	return o;
}

#ifdef _ast_int8_t

uint64_t
asocas64(uint64_t volatile* p, uint64_t o, uint64_t n)
{
	ssize_t		k;

#if defined(_aso_cas64)
	if (!state.lockf)
		return _aso_cas64(p, o, n);
#endif
	k = lock(state.data, 0, p);
	if (*p == o)
		*p = n;
	else
		o = *p;
	lock(state.data, k, p);
	return o;
}

#endif

/*
 * compare with old, swap with new if same, and return old value
 */

void*
asocasptr(void volatile* p, void* o, void* n)
{
	ssize_t		k;

#if defined(_aso_casptr)
	if (!state.lockf)
		return _aso_casptr((void**)p, o, n);
#endif
	k = lock(state.data, 0, p);
	if (*(void* volatile*)p == o)
		*(void* volatile*)p = n;
	else
		o = *(void* volatile*)p;
	lock(state.data, k, p);
	return o;
}

#endif
