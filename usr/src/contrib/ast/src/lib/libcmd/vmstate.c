/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped

#define FORMAT		"region=%(region)p method=%(method)s flags=%(flags)s size=%(size)d segments=%(segments)d busy=(%(busy_size)d,%(busy_blocks)d,%(busy_max)d) free=(%(free_size)d,%(free_blocks)d,%(free_max)d)"

static const char usage[] =
"[-?\n@(#)$Id: vmstate (AT&T Research) 2010-04-08 $\n]"
USAGE_LICENSE
"[+NAME?vmstate - list the calling process vmalloc region state]"
"[+DESCRIPTION?When invoked as a shell builtin, \bvmstate\b lists the "
    "calling process \bvmalloc\b(3) state for all regions.]"
"[f:format?List the ids specified by \aformat\a. \aformat\a follows "
    "\bprintf\b(3) conventions, except that \bsfio\b(3) inline ids are used "
    "instead of arguments: "
    "%[-+]][\awidth\a[.\aprecis\a[.\abase\a]]]]]](\aid\a)\achar\a. The "
    "supported \aid\as are:]:[format:=" FORMAT "]"
    "{"
	"[+method?The vmalloc method name.]"
	"[+flags?The vmalloc method flags.]"
        "[+size?The total region size.]"
        "[+segments?The number of segments in the region.]"
        "[+busy_size?The total busy block size.]"
        "[+busy_blocks?The number of busy blocks.]"
        "[+busy_max?The maximum busy block size.]"
        "[+free_size?The total free block size.]"
        "[+free_blocks?The number of free blocks.]"
        "[+free_max?The maximum free block size.]"
    "}"
"[+SEE ALSO?\bvmalloc\b(3)]"
;

#include <cmd.h>
#include <vmalloc.h>
#include <sfdisc.h>

typedef struct State_s
{
	char*		format;
	Vmalloc_t*	vm;
	Vmstat_t	vs;
	unsigned int	regions;
	Vmalloc_t*	region[256];
} State_t;

/*
 * sfkeyprintf() lookup
 * handle==0 for heading
 */

static int
key(void* handle, Sffmt_t* fp, const char* arg, char** ps, Sflong_t* pn)
{
	register State_t*	state = (State_t*)handle;
	register char*		s;

	if (!(s = fp->t_str) || streq(s, "size"))
		*pn = state->vs.extent;
	else if (streq(s, "region"))
		*pn = integralof(state->vm);
	else if (streq(s, "segments"))
		*pn = state->vs.n_seg;
	else if (streq(s, "busy_size"))
		*pn = state->vs.s_busy;
	else if (streq(s, "busy_blocks"))
		*pn = state->vs.n_busy;
	else if (streq(s, "busy_max"))
		*pn = state->vs.m_busy;
	else if (streq(s, "flags"))
	{
		*ps = s = fmtbuf(32);
#ifdef VM_TRUST
		if (state->vs.mode & VM_TRUST)
			s = strcopy(s, "TRUST|");
#endif
		if (state->vs.mode & VM_TRACE)
			s = strcopy(s, "TRACE|");
		if (state->vs.mode & VM_DBCHECK)
			s = strcopy(s, "DBCHECK|");
		if (state->vs.mode & VM_DBABORT)
			s = strcopy(s, "DBABORT|");
		if (s > *ps)
			*(s - 1) = 0;
		else
			strcpy(s, "0");
	}
	else if (streq(s, "free_size"))
		*pn = state->vs.s_free;
	else if (streq(s, "free_blocks"))
		*pn = state->vs.n_free;
	else if (streq(s, "free_max"))
		*pn = state->vs.m_free;
	else if (streq(s, "format"))
		*ps = (char*)state->format;
	else if (streq(s, "method"))
	{
		if (state->vs.mode & VM_MTBEST)
			*ps = "best";
		else if (state->vs.mode & VM_MTPOOL)
			*ps = "pool";
		else if (state->vs.mode & VM_MTLAST)
			*ps = "last";
		else if (state->vs.mode & VM_MTDEBUG)
			*ps = "debug";
		else if (state->vs.mode & VM_MTPROFILE)
			*ps = "profile";
		else
			*ps = "UNKNOWN";
	}
	else
	{
		error(2, "%s: unknown format identifier", s);
		return 0;
	}
	return 1;
}

static int
visit(Vmalloc_t* vm, void* addr, size_t size, Vmdisc_t* disc, void* handle)
{
	State_t*	state = (State_t*)handle;

	if (vm != state->vm)
	{
		state->vm = vm;
		if (state->regions < elementsof(state->region))
			state->region[state->regions++] = vm;
	}
	return 0;
}

int
b_vmstate(int argc, char** argv, Shbltin_t* context)
{
	register int	i;
	State_t		state;

	memset(&state, 0, sizeof(state));
	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'f':
			state.format = opt_info.arg;
			continue;
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			break;
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || *argv)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	if (!state.format)
		state.format = FORMAT;

	/*
	 * the walk must do no allocations because it locks the regions
	 */

	vmwalk(NiL, visit, &state);

	/*
	 * now we can compute and list the state of each region
	 */

	for (i = 0; i < state.regions; i++)
	{
		state.vm = state.region[i];
		vmstat(state.vm, &state.vs);
		sfkeyprintf(sfstdout, &state, state.format, key, NiL);
		sfprintf(sfstdout, "\n");
	}
	return 0;
}
