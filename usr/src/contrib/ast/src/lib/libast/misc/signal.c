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
 * signal that disables syscall restart on interrupt with clear signal mask
 * fun==SIG_DFL also unblocks signal
 */

#if !_UWIN

#undef	signal
#define signal		______signal

#endif

#include <ast.h>
#include <sig.h>

#if !_UWIN

#undef	signal

#undef	_def_map_ast
#include <ast_map.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

#endif

#if defined(SV_ABORT)                                         
#undef	SV_INTERRUPT
#define SV_INTERRUPT	SV_ABORT
#endif

#if !_std_signal && (_lib_sigaction && defined(SA_NOCLDSTOP) || _lib_sigvec && defined(SV_INTERRUPT))

#if !defined(SA_NOCLDSTOP) || !defined(SA_INTERRUPT) && defined(SV_INTERRUPT)
#undef	SA_INTERRUPT
#define SA_INTERRUPT	SV_INTERRUPT
#undef	sigaction
#define sigaction	sigvec
#undef	sigemptyset
#define sigemptyset(p)	(*(p)=0)
#undef	sa_flags
#define sa_flags	sv_flags
#undef	sa_handler
#define sa_handler	sv_handler
#undef	sa_mask
#define	sa_mask		sv_mask
#endif

extern Sig_handler_t
signal(int sig, Sig_handler_t fun)
{
	struct sigaction	na;
	struct sigaction	oa;
	int			unblock;
#ifdef SIGNO_MASK
	unsigned int		flags;
#endif

	if (sig < 0)
	{
		sig = -sig;
		unblock = 0;
	}
	else
		unblock = fun == SIG_DFL;
#ifdef SIGNO_MASK
	flags = sig & ~SIGNO_MASK;
	sig &= SIGNO_MASK;
#endif
	memzero(&na, sizeof(na));
	na.sa_handler = fun;
#if defined(SA_INTERRUPT) || defined(SA_RESTART)
	switch (sig)
	{
#if defined(SIGIO) || defined(SIGTSTP) || defined(SIGTTIN) || defined(SIGTTOU)
#if defined(SIGIO)
	case SIGIO:
#endif
#if defined(SIGTSTP)
	case SIGTSTP:
#endif
#if defined(SIGTTIN)
	case SIGTTIN:
#endif
#if defined(SIGTTOU)
	case SIGTTOU:
#endif
#if defined(SA_RESTART)
		na.sa_flags = SA_RESTART;
#endif
		break;
#endif
	default:
#if defined(SA_INTERRUPT)
		na.sa_flags = SA_INTERRUPT;
#endif
		break;
	}
#endif
	if (sigaction(sig, &na, &oa))
		return 0;
	if (unblock)
		sigunblock(sig);
	return oa.sa_handler;
}

#else

NoN(signal)

#endif
