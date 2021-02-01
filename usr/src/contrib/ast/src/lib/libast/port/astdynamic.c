/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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

/*
 * ast dynamic data initialization
 */

#ifdef _UWIN

#define _std_def_cfree	1

#include <sfio_t.h>
#include <ast.h>

#undef	strcoll

#include <ast_windows.h>

extern Sfio_t	_Sfstdin;
extern Sfio_t	_Sfstdout;
extern Sfio_t	_Sfstderr;

#include "sfhdr.h"

#undef	sfstdin
#undef	sfstdout
#undef	sfstderr

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

/*
 * for backward compatibility with early UNIX
 */

extern void
cfree(void* addr)
{
	free(addr);
}

extern void
_ast_libinit(void* in, void* out, void* err)
{
	Sfio_t*		sp;

	sp = (Sfio_t*)in;
	*sp =  _Sfstdin;
	sfstdin = sp;
	sp = (Sfio_t*)out;
	*sp =  _Sfstdout;
	sfstdout = sp;
	sp = (Sfio_t*)err;
	*sp =  _Sfstderr;
	sfstderr = sp;
}

extern void
_ast_init(void)
{
	struct _astdll*	ap = _ast_getdll();

	_ast_libinit(ap->_ast_stdin,ap->_ast_stdout,ap->_ast_stderr);
}

extern void
_ast_exit(void)
{
	if (_Sfcleanup)
		(*_Sfcleanup)();
}

BOOL WINAPI
DllMain(HINSTANCE hinst, DWORD reason, VOID* reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		_ast_exit();
		break;
	}
	return 1;
}

#else

#include <ast.h>

#if _dll_data_intercept && ( _DLL_BLD || _BLD_DLL )

#undef	environ

extern char**	environ;

struct _astdll	_ast_dll = { &environ };

struct _astdll*
_ast_getdll(void)
{
	return &_ast_dll;
}

#else

NoN(astdynamic)

#endif

#endif
