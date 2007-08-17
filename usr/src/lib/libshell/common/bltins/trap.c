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
 * trap  [-p]  action sig...
 * kill  [-l] [sig...]
 * kill  [-s sig] pid...
 *
 *   David Korn
 *   AT&T Labs
 *   research!dgk
 *
 */

#include	"defs.h"
#include	<ctype.h>
#include	"jobs.h"
#include	"builtins.h"

#define L_FLAG	1
#define S_FLAG	2

static const char trapfmt[] = "trap -- %s %s\n";

static int	sig_number(const char*);
static void	sig_list(Shell_t*,int);

int	b_trap(int argc,char *argv[],void *extra)
{
	register char *arg = argv[1];
	register int sig, pflag = 0;
	register Shell_t *shp = (Shell_t*)extra;
	NOT_USED(argc);
	while (sig = optget(argv, sh_opttrap)) switch (sig)
	{
	    case 'p':
		pflag=1;
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
		return(2);
		break;
	}
	argv += opt_info.index;
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s", optusage((char*)0));
	if(arg = *argv)
	{
		register int	clear;
		char *action = arg;
		if(!pflag)
		{
			/* first argument all digits or - means clear */
			while(isdigit(*arg))
				arg++;
			clear = (arg!=action && *arg==0);
			if(!clear)
			{
				++argv;
				if(*action=='-' && action[1]==0)
					clear++;
			}
			while(!argv[0])
				errormsg(SH_DICT,ERROR_exit(1),e_condition);
		}
		while(arg = *argv++)
		{
			sig = sig_number(arg);
			if(sig<0)
			{
				errormsg(SH_DICT,2,e_trap,arg);
				return(1);
			}
			/* internal traps */
			if(sig&SH_TRAP)
			{
				sig &= ~SH_TRAP;
				if(sig>SH_DEBUGTRAP)
				{
					errormsg(SH_DICT,2,e_trap,arg);
					return(1);
				}
				if(pflag)
				{
					if(arg=shp->st.trap[sig])
						sfputr(sfstdout,sh_fmtq(arg),'\n');
					continue;
				}
				if(shp->st.trap[sig])
					free(shp->st.trap[sig]);
				shp->st.trap[sig] = 0;
				if(!clear && *action)
					shp->st.trap[sig] = strdup(action);
				if(sig == SH_DEBUGTRAP)
				{
					if(shp->st.trap[sig])
						shp->trapnote |= SH_SIGTRAP;
					else
						shp->trapnote = 0;
				}
				continue;
			}
			if(sig>shp->sigmax)
			{
				errormsg(SH_DICT,2,e_trap,arg);
				return(1);
			}
			else if(pflag)
			{
				char **trapcom = (shp->st.otrapcom?shp->st.otrapcom:shp->st.trapcom);
				if(arg=trapcom[sig])
					sfputr(sfstdout,arg,'\n');
			}
			else if(clear)
				sh_sigclear(sig);
			else
			{
				if(sig >= shp->st.trapmax)
					shp->st.trapmax = sig+1;
				if(arg=shp->st.trapcom[sig])
					free(arg);
				shp->st.trapcom[sig] = strdup(action);
				sh_sigtrap(sig);
			}
		}
	}
	else /* print out current traps */
		sig_list(shp,-1);
	return(0);
}

int	b_kill(int argc,char *argv[],void *extra)
{
	register char *signame;
	register int sig=SIGTERM, flag=0, n;
	register Shell_t *shp = (Shell_t*)extra;
	NOT_USED(argc);
	while((n = optget(argv,sh_optkill))) switch(n)
	{
		case ':':
			if((signame=argv[opt_info.index++]) && (sig=sig_number(signame+1))>=0)
				goto endopts;
			opt_info.index--;
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case 'n':
			sig = (int)opt_info.num;
			goto endopts;
		case 's':
			flag |= S_FLAG;
			signame = opt_info.arg;
			goto endopts;
		case 'l':
			flag |= L_FLAG;
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
			break;
	}
endopts:
	argv += opt_info.index;
	if(*argv && strcmp(*argv,"--")==0 && strcmp(*(argv-1),"--")!=0)
		argv++;
	if(error_info.errors || flag==(L_FLAG|S_FLAG) || (!(*argv) && !(flag&L_FLAG)))
		errormsg(SH_DICT,ERROR_usage(2),"%s", optusage((char*)0));
	/* just in case we send a kill -9 $$ */
	sfsync(sfstderr);
	if(flag&L_FLAG)
	{
		if(!(*argv))
			sig_list(shp,0);
		else while(signame = *argv++)
		{
			if(isdigit(*signame))
				sig_list(shp,((int)strtol(signame, (char**)0, 10)&0177)+1);
			else
			{
				if((sig=sig_number(signame))<0)
				{
					shp->exitval = 2;
					errormsg(SH_DICT,ERROR_exit(1),e_nosignal,signame);
				}
				sfprintf(sfstdout,"%d\n",sig);
			}
		}
		return(shp->exitval);
	}
	if(flag&S_FLAG)
	{
		if((sig=sig_number(signame)) < 0 || sig > shp->sigmax)
			errormsg(SH_DICT,ERROR_exit(1),e_nosignal,signame);
	}
	if(job_walk(sfstdout,job_kill,sig,argv))
		shp->exitval = 1;
	return(shp->exitval);
}

/*
 * Given the name or number of a signal return the signal number
 */

static int sig_number(const char *string)
{
	const Shtable_t	*tp;
	register int	n,sig=0;
	char		*last;
	if(isdigit(*string))
	{
		n = strtol(string,&last,10);
		if(*last)
			n = -1;
	}
	else
	{
		register int c;
		n = staktell();
		do
		{
			c = *string++;
			if(islower(c))
				c = toupper(c);
			stakputc(c);
		}
		while(c);
		stakseek(n);
		if(memcmp(stakptr(n),"SIG",3)==0)
		{
			sig = 1;
			n += 3;
		}
		tp = sh_locate(stakptr(n),(const Shtable_t*)shtab_signals,sizeof(*shtab_signals));
		n = tp->sh_number;
		if(sig==1 && (n>=(SH_TRAP-1) && n < (1<<SH_SIGBITS)))
		{
			/* sig prefix cannot match internal traps */
			n = 0;
			tp = (Shtable_t*)((char*)tp + sizeof(*shtab_signals));
			if(strcmp(stakptr(n),tp->sh_name)==0)
				n = tp->sh_number;
		}
		n &= (1<<SH_SIGBITS)-1;
		if(n < SH_TRAP)
			n--;
	}
	return(n);
}

/*
 * if <flag> is positive, then print signal name corresponding to <flag>
 * if <flag> is zero, then print all signal names
 * if <flag> is negative, then print all traps
 */
static void sig_list(register Shell_t *shp,register int flag)
{
	register const struct shtable2	*tp;
	register int sig = shp->sigmax+1;
	const char *names[SH_TRAP];
	const char *traps[SH_DEBUGTRAP+1];
	tp=shtab_signals;
	if(flag==0)
	{
		/* not all signals may be defined, so initialize */
		while(--sig >= 0)
			names[sig] = 0;
		for(sig=SH_DEBUGTRAP; sig>=0; sig--)
			traps[sig] = 0;
	}
	while(*tp->sh_name)
	{
		sig = tp->sh_number;
		sig &= ((1<<SH_SIGBITS)-1);
		if(sig==flag)
		{
			sfprintf(sfstdout,"%s\n",tp->sh_name);
			return;
		}
		else if(sig&SH_TRAP)
			traps[sig&~SH_TRAP] = (char*)tp->sh_name;
		else if(sig < sizeof(names)/sizeof(char*))
			names[sig] = (char*)tp->sh_name;
		tp++;
	}
	if(flag > 0)
		sfprintf(sfstdout,"%d\n",flag-1);
	else if(flag<0)
	{
		/* print the traps */
		register char *trap,*sname,**trapcom;
		char name[6];
		sig = shp->st.trapmax;
		/* use parent traps if otrapcom is set (for $(trap)  */
		trapcom = (shp->st.otrapcom?shp->st.otrapcom:shp->st.trapcom);
		while(--sig >= 0)
		{
			if(!(trap=trapcom[sig]))
				continue;
			if(!(sname=(char*)names[sig+1]))
			{
				sname = name;
				sname[0] = 'S';
				sname[1] = 'I';
				sname[2] = 'G';
				sname[3] = (sig/10)+'0';
				sname[4] = (sig%10)+'0';
			}
			sfprintf(sfstdout,trapfmt,sh_fmtq(trap),sname);
		}
		for(sig=SH_DEBUGTRAP; sig>=0; sig--)
		{
			if(!(trap=shp->st.trap[sig]))
				continue;
			sfprintf(sfstdout,trapfmt,sh_fmtq(trap),traps[sig]);
		}
	}
	else
	{
		/* print all the signal names */
		for(sig=2; sig <= shp->sigmax; sig++)
		{
			if(names[sig])
				sfputr(sfstdout,names[sig],'\n');
			else
				sfprintf(sfstdout,"SIG%d\n",sig-1);
		}
	}
}

