/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include	<shell.h>

#include	"FEATURE/externs"

#if defined(__sun) && _sys_mman && _lib_memcntl && defined(MHA_MAPSIZE_STACK) && defined(MC_HAT_ADVISE)
#   undef	VM_FLAGS	/* solaris vs vmalloc.h symbol clash */
#   include	<sys/mman.h>
#else
#   undef	_lib_memcntl
#endif

typedef int (*Shnote_f)(int, long, int);

int main(int argc, char *argv[])
{
#if _lib_memcntl
	/* advise larger stack size */
	struct memcntl_mha mha;
	mha.mha_cmd = MHA_MAPSIZE_STACK;
	mha.mha_flags = 0;
	mha.mha_pagesize = 64 * 1024;
	(void)memcntl(NULL, 0, MC_HAT_ADVISE, (caddr_t)&mha, 0, 0);
#endif
	sh_waitnotify((Shnote_f)0);
	return(sh_main(argc, argv, (Shinit_f)0));
}
