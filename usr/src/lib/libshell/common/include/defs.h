/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1982-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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
/*
 * David Korn
 * AT&T Labs
 *
 * Shell interface private definitions
 *
 */

#include	<ast.h>
#include	<sfio.h>
#include	<error.h>
#include	"FEATURE/options"
#include	<cdt.h>
#include	<history.h>
#include	"fault.h"
#include	"argnod.h"

#ifndef pointerof
#define pointerof(x)		((void*)((char*)0+(x)))
#endif

#define	env_change()		(++ast.env_serial)
#if SHOPT_ENV
#   include	<env.h>
#else
#   define Env_t		void
#   define sh_envput(e,p)	env_change()
#   define env_delete(e,p)	env_change()
#endif

/*
 * note that the first few fields have to be the same as for
 * Shscoped_t in <shell.h>
 */
struct sh_scoped
{
	struct sh_scoped *prevst;	/* pointer to previous state */
	int		dolc;
	char		**dolv;
	char		*cmdname;
	char		*filename;
	int		lineno;
	Dt_t		*save_tree;	/* var_tree for calling function */
	struct sh_scoped *self;		/* pointer to copy of this scope*/
	Dt_t		*var_local;	/* local level variables for name() */
	struct slnod	*staklist;	/* link list of function stacks */
	int		states;
	int		breakcnt;
	int		execbrk;
	int		loopcnt;
	int		firstline;
	int32_t		optindex;
	int32_t		optnum;
	int32_t		tmout;		/* value for TMOUT */ 
	short		optchar;
	short		opterror;
	int		ioset;
	unsigned short	trapmax;
	char		*trap[SH_DEBUGTRAP+1];
	char		**trapcom;
	char		**otrapcom;
	void		*timetrap;
};

struct limits
{
	long		arg_max;	/* max arg+env exec() size */
	int		open_max;	/* maximum number of file descriptors */
	int		clk_tck;	/* number of ticks per second */
	int		child_max;	/* maxumum number of children */
	int		ngroups_max;	/* maximum number of process groups */
	unsigned char	posix_version;	/* posix version number */
	unsigned char	posix_jobcontrol;/* non-zero for job control systems */
	unsigned char	fs3d;		/* non-zero for 3-d file system */
};

#define _SH_PRIVATE \
	struct sh_scoped st;		/* scoped information */ \
	struct limits	lim;		/* run time limits */ \
	Sfio_t		*heredocs;	/* current here-doc temp file */ \
	Sfio_t		*funlog;	/* for logging function definitions */ \
	int		**fdptrs;	/* pointer to file numbers */ \
	int		savexit; \
	char		*lastarg; \
	char		*lastpath;	/* last alsolute path found */ \
	int		path_err;	/* last error on path search */ \
	Dt_t		*track_tree;	/* for tracked aliases*/ \
	Namval_t	*bltin_nodes;	/* pointer to built-in variables */ \
	Dt_t		*var_base;	/* global level variables */ \
	Namval_t	*namespace;	/* current active namespace*/ \
	Namval_t	*last_table;	/* last table used in last nv_open  */ \
	Sfio_t		*outpool;	/* ouput stream pool */ \
	long		timeout;	/* read timeout */ \
	short		curenv;		/* current subshell number */ \
	short		jobenv;		/* subshell number for jobs */ \
	int		nextprompt;	/* next prompt is PS<nextprompt> */ \
	Namval_t	*bltin_cmds;	/* pointer to built-in commands */ \
	Namval_t	*posix_fun;	/* points to last name() function */ \
	int		infd;		/* input file descriptor */ \
	char		*outbuff;	/* pointer to output buffer */ \
	char		*errbuff;	/* pointer to stderr buffer */ \
	char		*prompt;	/* pointer to prompt string */ \
	char		*shname;	/* shell name */ \
	char		*shpath;	/* path name of shell */ \
	char		*user;		/* name of real user for pfsh */ \
	char		*comdiv;	/* points to sh -c argument */ \
	char		*prefix;	/* prefix for compound assignment */ \
	sigjmp_buf	*jmplist;	/* longjmp return stack */ \
	char		**sigmsg;	/* points to signal messages */ \
	int		oldexit; \
	uid_t 		userid,euserid;	/* real and effective user id */ \
	gid_t 		groupid,egroupid;/* real and effective group id */ \
	pid_t		pid;		/* process id of shell */ \
	pid_t		bckpid;		/* background process id */ \
	pid_t		cpid; \
	int32_t		ppid;		/* parent process id of shell */ \
	int		topfd; \
	int		sigmax;		/* maximum number of signals */ \
	int		savesig; \
	unsigned char	*sigflag;	/* pointer to signal states */ \
	char		intrap; \
	char		login_sh; \
	char		lastbase; \
	char		forked;	\
	char		binscript; \
	char		deftype; \
	char		used_pos;	/* used postional parameter */\
	unsigned char	lastsig;	/* last signal received */ \
	char		*readscript;	/* set before reading a script */ \
	int		*inpipe;	/* input pipe pointer */ \
	int		*outpipe;	/* output pipe pointer */ \
	int		cpipe[2]; \
	int		coutpipe; \
	int		inuse_bits; \
	struct argnod	*envlist; \
	struct dolnod	*arglist; \
	int		fn_depth; \
	int		dot_depth; \
	int		hist_depth; \
	int		xargmin; \
	int		xargmax; \
	int		xargexit; \
	mode_t		mask; \
	long		nforks; \
	Env_t		*env; \
	void		*init_context; \
	void		*mac_context; \
	void		*lex_context; \
	void		*arg_context; \
	void		*ed_context; \
	void		*job_context; \
	void		*pathlist; \
	void		*defpathlist; \
	void		*cdpathlist; \
	char		**argaddr; \
	void		*optlist; \
	int		optcount ; \
	struct sh_scoped global; \
	struct checkpt	checkbase; \
	Shinit_f	userinit; \
	Shbltin_f	bltinfun; \
	Shwait_f	waitevent; \
	char		*cur_line; \
	char		*rcfile; \
	char		**login_files; \
	short		offsets[10]; \
	Sfio_t		**sftable; \
	unsigned char	*fdstatus; \
	const char	*pwd; \
	History_t	*hist_ptr; \
	char		universe; \
	void		*jmpbuffer; \
	void		*mktype; \
	Sfio_t		*strbuf; \
	Dt_t		*last_root; \
	char		ifstable[256]; \
	Shopt_t		offoptions;

#include	<shell.h>


/* error exits from various parts of shell */
#define	NIL(type)	((type)0)

#define new_of(type,x)	((type*)malloc((unsigned)sizeof(type)+(x)))

#define exitset()	(sh.savexit=sh.exitval)

#ifndef SH_DICT
#define SH_DICT		(void*)e_dict
#endif

#ifndef SH_CMDLIB_DIR
#define SH_CMDLIB_DIR	"/opt/ast/bin"
#endif

/* states */
/* low numbered states are same as options */
#define SH_NOFORK	0	/* set when fork not necessary, not a state */
#define SH_COMPLETE	0	/* set for command completion */
#define	SH_FORKED	7	/* set when process has been forked */
#define	SH_PROFILE	8	/* set when processing profiles */
#define SH_NOALIAS	9	/* do not expand non-exported aliases */
#define SH_NOTRACK	10	/* set to disable sftrack() function */
#define SH_STOPOK	11	/* set for stopable builtins */
#define SH_GRACE	12	/* set for timeout grace period */
#define SH_TIMING	13	/* set while timing pipelines */
#define SH_DEFPATH	14	/* set when using default path */
#define SH_INIT		15	/* set when initializing the shell */
#define SH_TTYWAIT	16	/* waiting for keyboard input */ 
#define	SH_FCOMPLETE	17	/* set for filename completion */
#define	SH_PREINIT	18	/* set with SH_INIT before parsing options */

#define SH_BASH			41
#define SH_BRACEEXPAND		42
#define SH_POSIX		46
#define SH_MULTILINE    	47

#define SH_NOPROFILE		78
#define SH_NOUSRPROFILE		79
#define SH_LOGIN_SHELL		67
#define SH_COMMANDLINE		0x100
#define SH_BASHEXTRA		0x200
#define SH_BASHOPT		0x400

#define SH_ID			"ksh"	/* ksh id */
#define SH_STD			"sh"	/* standard sh id */

/* defines for sh_type() */

#define SH_TYPE_SH		001
#define SH_TYPE_KSH		002
#define SH_TYPE_BASH		004
#define SH_TYPE_LOGIN		010
#define SH_TYPE_PROFILE		020
#define SH_TYPE_RESTRICTED	040

#if SHOPT_BASH
#   ifndef SHOPT_HISTEXPAND
#	define SHOPT_HISTEXPAND	1
#   endif
/*
 *  define for all the bash options
 */
#   define SH_CDABLE_VARS	51
#   define SH_CDSPELL		52
#   define SH_CHECKHASH		53
#   define SH_CHECKWINSIZE	54
#   define SH_CMDHIST		55
#   define SH_DOTGLOB		56
#   define SH_EXECFAIL		57
#   define SH_EXPAND_ALIASES	58
#   define SH_EXTGLOB		59
#   define SH_HOSTCOMPLETE	63
#   define SH_HUPONEXIT		64
#   define SH_INTERACTIVE_COMM	65
#   define SH_LITHIST		66
#   define SH_MAILWARN		68
#   define SH_NOEMPTYCMDCOMPL	69
#   define SH_NOCASEGLOB	70
#   define SH_NULLGLOB		71
#   define SH_PHYSICAL		45
#   define SH_PROGCOMP		72
#   define SH_PROMPTVARS	73
#   define SH_RESTRICTED2	74
#   define SH_SHIFT_VERBOSE	75
#   define SH_SOURCEPATH	76
#   define SH_XPG_ECHO		77
#endif

#if SHOPT_HISTEXPAND
#   define SH_HISTAPPEND	60
#   define SH_HISTEXPAND	43
#   define SH_HISTORY2		44
#   define SH_HISTREEDIT	61
#   define SH_HISTVERIFY	62
#endif

#ifndef PIPE_BUF
#   define PIPE_BUF		512
#endif

#define MATCH_MAX		64

extern int		sh_addlib(void*);
extern void 		*sh_argopen(Shell_t*);
extern Namval_t		*sh_assignok(Namval_t*,int);
extern char		*sh_checkid(char*,char*);
extern int		sh_debug(const char*,const char*,const char*,char *const[],int);
extern int 		sh_echolist(Sfio_t*, int, char**);
extern struct argnod	*sh_endword(int);
extern char 		**sh_envgen(void);
#if SHOPT_ENV
extern void 		sh_envput(Env_t*, Namval_t*);
#endif
extern void 		sh_envnolocal(Namval_t*,void*);
extern Sfdouble_t	sh_arith(const char*);
extern void		*sh_arithcomp(char*);
extern pid_t 		sh_fork(int,int*);
extern pid_t		_sh_fork(pid_t, int ,int*);
extern char 		*sh_mactrim(char*,int);
extern int 		sh_macexpand(struct argnod*,struct argnod**,int);
extern void 		sh_machere(Sfio_t*, Sfio_t*, char*);
extern void 		*sh_macopen(Shell_t*);
extern char 		*sh_macpat(struct argnod*,int);
extern char 		*sh_mactry(char*);
extern void		sh_printopts(Shopt_t,int,Shopt_t*);
extern int 		sh_readline(Shell_t*,char**,int,int,long);
extern Sfio_t		*sh_sfeval(char*[]);
extern void		sh_setmatch(const char*,int,int,int[]);
extern Dt_t		*sh_subaliastree(int);
extern Dt_t		*sh_subfuntree(int);
extern int		sh_subsavefd(int);
extern void		sh_subtmpfile(void);
extern char 		*sh_substitute(const char*,const char*,char*);
extern const char	*_sh_translate(const char*);
extern int		sh_trace(char*[],int);
extern void		sh_trim(char*);
extern int		sh_type(const char*);
extern void		sh_utol(const char*, char*);
extern int 		sh_whence(char**,int);

#ifndef ERROR_dictionary
#   define ERROR_dictionary(s)	(s)
#endif
#define sh_translate(s)	_sh_translate(ERROR_dictionary(s))

#define WBITS		(sizeof(long)*8)
#define WMASK		(0xff)

#define is_option(s,x)	((s)->v[((x)&WMASK)/WBITS] & (1L << ((x) % WBITS)))
#define on_option(s,x)	((s)->v[((x)&WMASK)/WBITS] |= (1L << ((x) % WBITS)))
#define off_option(s,x)	((s)->v[((x)&WMASK)/WBITS] &= ~(1L << ((x) % WBITS)))
#define sh_isoption(x)	is_option(&sh.options,x)
#define sh_onoption(x)	on_option(&sh.options,x)
#define sh_offoption(x)	off_option(&sh.options,x)


#define sh_state(x)	( 1<<(x))
#define	sh_isstate(x)	(sh.st.states&sh_state(x))
#define	sh_onstate(x)	(sh.st.states |= sh_state(x))
#define	sh_offstate(x)	(sh.st.states &= ~sh_state(x))
#define	sh_getstate()	(sh.st.states)
#define	sh_setstate(x)	(sh.st.states = (x))

#define sh_sigcheck() do{if(sh.trapnote&SH_SIGSET)sh_exit(SH_EXITSIG);} while(0)

extern int32_t		sh_mailchk;
extern const char	e_dict[];

/* sh_printopts() mode flags -- set --[no]option by default */

#define PRINT_VERBOSE	0x01	/* option on|off list		*/
#define PRINT_ALL	0x02	/* list unset iptions too	*/
#define PRINT_NO_HEADER	0x04	/* omit listing header		*/
#define PRINT_SHOPT	0x08	/* shopt -s|-u			*/
#define PRINT_TABLE	0x10	/* table of all options		*/
