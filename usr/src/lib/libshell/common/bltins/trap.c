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
	register int sig, clear = 0, dflag = 0, pflag = 0;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
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
		char *action = arg;
		if(!dflag && !pflag)
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
				/*
				 * NOTE: 2007-11-26: workaround for tests/signal.sh
				 * if function semantics can be worked out then it
				 * may merit a -d,--default option
				 */
				else if(*action=='+' && action[1]==0 && sh.st.self == &sh.global)
				{
					clear++;
					dflag++;
				}
			}
			if(!argv[0])
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
			{
				sh_sigclear(sig);
				if(dflag)
					signal(sig,SIG_DFL);
			}
			else
			{
				if(sig >= shp->st.trapmax)
					shp->st.trapmax = sig+1;
				arg = shp->st.trapcom[sig];
				sh_sigtrap(sig);
				shp->st.trapcom[sig] = (shp->sigflag[sig]&SH_SIGOFF) ? Empty : strdup(action);
				if(arg && arg != Empty)
					free(arg);
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
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
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
	register int	n,o,sig=0;
	char		*last, *name;
	if(isdigit(*string))
	{
		n = strtol(string,&last,10);
		if(*last)
			n = -1;
	}
	else
	{
		register int c;
		o = staktell();
		do
		{
			c = *string++;
			if(islower(c))
				c = toupper(c);
			stakputc(c);
		}
		while(c);
		stakseek(o);
		if(memcmp(stakptr(o),"SIG",3)==0)
		{
			sig = 1;
			o += 3;
			if(isdigit(*stakptr(o)))
			{
				n = strtol(stakptr(o),&last,10);
				if(!*last)
					return(n);
			}
		}
		tp = sh_locate(stakptr(o),(const Shtable_t*)shtab_signals,sizeof(*shtab_signals));
		n = tp->sh_number;
		if(sig==1 && (n>=(SH_TRAP-1) && n < (1<<SH_SIGBITS)))
		{
			/* sig prefix cannot match internal traps */
			n = 0;
			tp = (Shtable_t*)((char*)tp + sizeof(*shtab_signals));
			if(strcmp(stakptr(o),tp->sh_name)==0)
				n = tp->sh_number;
		}
		if((n>>SH_SIGBITS)&SH_SIGRUNTIME)
			n = sh.sigruntime[(n&((1<<SH_SIGBITS)-1))-1];
		else
		{
			n &= (1<<SH_SIGBITS)-1;
			if(n < SH_TRAP)
				n--;
		}
		if(n<0 && sh.sigruntime[1] && (name=stakptr(o)) && *name++=='R' && *name++=='T')
		{
			if(name[0]=='M' && name[1]=='I' && name[2]=='N' && name[3]=='+')
			{
				if((sig=(int)strtol(name+4,&name,10)) >= 0 && !*name)
					n = sh.sigruntime[SH_SIGRTMIN] + sig;
			}
			else if(name[0]=='M' && name[1]=='A' && name[2]=='X' && name[3]=='-')
			{
				if((sig=(int)strtol(name+4,&name,10)) >= 0 && !*name)
					n = sh.sigruntime[SH_SIGRTMAX] - sig;
			}
			else if((sig=(int)strtol(name,&name,10)) > 0 && !*name)
				n = sh.sigruntime[SH_SIGRTMIN] + sig - 1;
			if(n<sh.sigruntime[SH_SIGRTMIN] || n>sh.sigruntime[SH_SIGRTMAX])
				n = -1;
		}
	}
	return(n);
}

/*
 * synthesize signal name for sig in buf
 * pfx!=0 prepends SIG to default signal number
 */
static char* sig_name(int sig, char* buf, int pfx)
{
	register int	i;

	i = 0;
	if(sig>sh.sigruntime[SH_SIGRTMIN] && sig<sh.sigruntime[SH_SIGRTMAX])
	{
		buf[i++] = 'R';
		buf[i++] = 'T';
		buf[i++] = 'M';
		if(sig>sh.sigruntime[SH_SIGRTMIN]+(sh.sigruntime[SH_SIGRTMAX]-sh.sigruntime[SH_SIGRTMIN])/2)
		{
			buf[i++] = 'A';
			buf[i++] = 'X';
			buf[i++] = '-';
			sig = sh.sigruntime[SH_SIGRTMAX]-sig;
		}
		else
		{
			buf[i++] = 'I';
			buf[i++] = 'N';
			buf[i++] = '+';
			sig = sig-sh.sigruntime[SH_SIGRTMIN];
		}
	}
	else if(pfx)
	{
		buf[i++] = 'S';
		buf[i++] = 'I';
		buf[i++] = 'G';
	}
	i += sfsprintf(buf+i, 8, "%d", sig);
	buf[i] = 0;
	return buf;
}

/*
 * if <flag> is positive, then print signal name corresponding to <flag>
 * if <flag> is zero, then print all signal names
 * if <flag> is negative, then print all traps
 */
static void sig_list(register Shell_t *shp,register int flag)
{
	register const struct shtable2	*tp;
	register int sig;
	register char *sname;
	char name[10];
	const char *names[SH_TRAP];
	const char *traps[SH_DEBUGTRAP+1];
	tp=shtab_signals;
	if(flag<=0)
	{
		/* not all signals may be defined, so initialize */
		for(sig=shp->sigmax; sig>=0; sig--)
			names[sig] = 0;
		for(sig=SH_DEBUGTRAP; sig>=0; sig--)
			traps[sig] = 0;
	}
	for(; *tp->sh_name; tp++)
	{
		sig = tp->sh_number&((1<<SH_SIGBITS)-1);
		if (((tp->sh_number>>SH_SIGBITS) & SH_SIGRUNTIME) && (sig = sh.sigruntime[sig-1]+1) == 1)
			continue;
		if(sig==flag)
		{
			sfprintf(sfstdout,"%s\n",tp->sh_name);
			return;
		}
		else if(sig&SH_TRAP)
			traps[sig&~SH_TRAP] = (char*)tp->sh_name;
		else if(sig-- && sig < elementsof(names))
			names[sig] = (char*)tp->sh_name;
	}
	if(flag > 0)
		sfputr(sfstdout, sig_name(flag-1,name,0), '\n');
	else if(flag<0)
	{
		/* print the traps */
		register char *trap,**trapcom;
		sig = shp->st.trapmax;
		/* use parent traps if otrapcom is set (for $(trap)  */
		trapcom = (shp->st.otrapcom?shp->st.otrapcom:shp->st.trapcom);
		while(--sig >= 0)
		{
			if(!(trap=trapcom[sig]))
				continue;
			if(sig > shp->sigmax || !(sname=(char*)names[sig]))
				sname = sig_name(sig,name,1);
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
		for(sig=1; sig <= shp->sigmax; sig++)
		{
			if(!(sname=(char*)names[sig]))
				sname = sig_name(sig,name,1);
			sfputr(sfstdout,sname,'\n');
		}
	}
}
