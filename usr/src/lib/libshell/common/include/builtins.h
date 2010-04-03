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

#ifndef SYSDECLARE

#include	<option.h>
#include	"FEATURE/options"
#include	"FEATURE/dynamic"
#include	"shtable.h"

#define	SYSLOGIN	(sh.bltin_cmds)
#define SYSEXEC		(sh.bltin_cmds+1)
#define SYSSET		(sh.bltin_cmds+2)
#define SYSTRUE		(sh.bltin_cmds+4)
#define SYSCOMMAND	(sh.bltin_cmds+5)
#define SYSCD		(sh.bltin_cmds+6)
#define SYSBREAK	(sh.bltin_cmds+7)
#define SYSCONT		(sh.bltin_cmds+8)
#define SYSTYPESET	(sh.bltin_cmds+9)
#define SYSTEST		(sh.bltin_cmds+10)
#define SYSBRACKET	(sh.bltin_cmds+11)
#define SYSLET		(sh.bltin_cmds+12)
#define SYSEXPORT	(sh.bltin_cmds+13)
#define SYSDOT		(sh.bltin_cmds+14)
#define SYSRETURN	(sh.bltin_cmds+15)
#if SHOPT_BASH
#   define SYSLOCAL	(sh.bltin_cmds+16)
#else
#   define SYSLOCAL	0
#endif

/* entry point for shell special builtins */

#if _BLD_shell && defined(__EXPORT__)
#	define extern	__EXPORT__
#endif

extern int b_alias(int, char*[],void*);
extern int b_break(int, char*[],void*);
extern int b_dot_cmd(int, char*[],void*);
extern int b_enum(int, char*[],void*);
extern int b_exec(int, char*[],void*);
extern int b_eval(int, char*[],void*);
extern int b_return(int, char*[],void*);
extern int B_login(int, char*[],void*);
extern int b_true(int, char*[],void*);
extern int b_false(int, char*[],void*);
extern int b_readonly(int, char*[],void*);
extern int b_set(int, char*[],void*);
extern int b_shift(int, char*[],void*);
extern int b_trap(int, char*[],void*);
extern int b_typeset(int, char*[],void*);
extern int b_unset(int, char*[],void*);
extern int b_unalias(int, char*[],void*);

/* The following are for job control */
#if defined(SIGCLD) || defined(SIGCHLD)
    extern int b_jobs(int, char*[],void*);
    extern int b_kill(int, char*[],void*);
#   ifdef SIGTSTP
	extern int b_bg(int, char*[],void*);
#   endif	/* SIGTSTP */
#endif

/* The following utilities are built-in because of side-effects */
extern int b_builtin(int, char*[],void*);
extern int b_cd(int, char*[],void*);
extern int b_command(int, char*[],void*);
extern int b_getopts(int, char*[],void*);
extern int b_hist(int, char*[],void*);
extern int b_let(int, char*[],void*);
extern int b_read(int, char*[],void*);
extern int b_ulimit(int, char*[],void*);
extern int b_umask(int, char*[],void*);
#ifdef _cmd_universe
    extern int b_universe(int, char*[],void*);
#endif /* _cmd_universe */
#if SHOPT_FS_3D
    extern int b_vpath(int, char*[],void*);
#endif /* SHOPT_FS_3D */
extern int b_wait(int, char*[],void*);
extern int b_whence(int, char*[],void*);

extern int b_alarm(int, char*[],void*);
extern int b_print(int, char*[],void*);
extern int b_printf(int, char*[],void*);
extern int b_pwd(int, char*[],void*);
extern int b_sleep(int, char*[],void*);
extern int b_test(int, char*[],void*);
#if !SHOPT_ECHOPRINT
    extern int B_echo(int, char*[],void*);
#endif /* SHOPT_ECHOPRINT */

#undef	extern

extern const char	e_alrm1[];
extern const char	e_alrm2[];
extern const char	e_badfun[];
extern const char	e_baddisc[];
extern const char	e_nofork[];
extern const char	e_nosignal[];
extern const char	e_nolabels[];
extern const char	e_notimp[];
extern const char	e_nosupport[];
extern const char	e_badbase[];
extern const char	e_overlimit[];

extern const char	e_eneedsarg[];
extern const char	e_oneoperand[];
extern const char	e_toodeep[];
extern const char	e_badname[];
extern const char	e_badsyntax[];
#ifdef _cmd_universe
    extern const char	e_nouniverse[];
#endif /* _cmd_universe */
extern const char	e_histopen[];
extern const char	e_condition[];
extern const char	e_badrange[];
extern const char	e_trap[];
extern const char	e_direct[];
extern const char	e_defedit[];
extern const char	e_cneedsarg[];
extern const char	e_defined[];
#if SHOPT_FS_3D
    extern const char	e_cantset[];
    extern const char	e_cantget[];
    extern const char	e_mapping[];
    extern const char	e_versions[];
#endif /* SHOPT_FS_3D */

/* for option parsing */
extern const char sh_set[];
extern const char sh_optalarm[];
extern const char sh_optalias[];
extern const char sh_optbreak[];
extern const char sh_optbuiltin[];
extern const char sh_optcd[];
extern const char sh_optcommand[];
extern const char sh_optcont[];
extern const char sh_optdot[];
#ifndef ECHOPRINT
    extern const char sh_optecho[];
#endif /* !ECHOPRINT */
extern const char sh_opteval[];
extern const char sh_optexec[];
extern const char sh_optexit[];
extern const char sh_optexport[];
extern const char sh_optgetopts[];
extern const char sh_optbg[];
extern const char sh_optdisown[];
extern const char sh_optfg[];
extern const char sh_opthist[];
extern const char sh_optjobs[];
extern const char sh_optkill[];
extern const char sh_optksh[];
extern const char sh_optlet[];
extern const char sh_optprint[];
extern const char sh_optprintf[];
extern const char sh_optpwd[];
extern const char sh_optread[];
extern const char sh_optreadonly[];
extern const char sh_optreturn[];
extern const char sh_optset[];
extern const char sh_optshift[];
extern const char sh_optsleep[];
extern const char sh_opttrap[];
extern const char sh_opttypeset[];
extern const char sh_optulimit[];
extern const char sh_optumask[];
extern const char sh_optunalias[];
extern const char sh_optwait[];
#ifdef _cmd_universe
    extern const char sh_optuniverse[];
#endif /* _cmd_universe */
extern const char sh_optunset[];
#if SHOPT_FS_3D
    extern const char sh_optvpath[];
    extern const char sh_optvmap[];
#endif /* SHOPT_FS_3D */
extern const char sh_optwhence[];
#endif /* SYSDECLARE */

extern const char e_dict[];

