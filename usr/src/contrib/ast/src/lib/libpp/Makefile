/*
 * C preprocessor library
 */

:PACKAGE: ast

LICENSE = since=1986,author=gsf

ID = pp

DEBUG ==

IDNAME = "$(ID)"

$(ID) 2.0 :LIBRARY: BUGS NOTES RELEASE HISTORY pp.3 \
		pp.h ppfsm.h ppkey.h pplib.h pp.tab \
		ppargs.c ppbuiltin.c ppcall.c ppcomment.c \
		ppcontext.c ppcontrol.c ppcpp.c ppdata.c \
		pperror.c ppexpr.c ppfsm.c ppincref.c ppinput.c ppkey.c \
		pplex.c ppline.c ppmacref.c ppmisc.c ppop.c pppragma.c \
		ppprintf.c ppproto.c ppsearch.c pptrace.c

"hp.pa*"	:NOOPTIMIZE: ppfsm.c
"osf.alpha*"	:NOOPTIMIZE: ppcall.c
"sol*.i386*"	:NOOPTIMIZE: ppcpp.c pplex.c

ppdef.h : gentab pp.tab
	$(*:N=*gentab:P=A) -d $(*:N=*.tab) > $(<)

pptab.h : gentab pp.tab
	$(*:N=*gentab:P=A) -t $(*:N=*.tab) > $(<)

:INSTALLDIR: gentab ppsym

gentab :: gentab.sh

ppsym :: ppsym.c +last

/* MAM workaround */
if "$(-mam)"
.ALL : .INSERT ppsym
end

$(INCLUDEDIR) :INSTALLPROTO: pp.h ppkey.h

$(INCLUDEDIR) :INSTALLDIR: pp.yacc ppkey.yacc

C $(ID) :PROBE: pp.probe pp.def pp.key ppsym probe.ini

probe.ini : (CC.HOSTTYPE) probe.win32
	t=$(CC.HOSTTYPE)
	ifs=$IFS
	IFS=.
	set x $t
	IFS=$ifs
	t=$2
	set x $(*)
	while	:
	do	shift
		case $# in
		0)	break ;;
		esac
		case $1 in
		*probe.$t)
			break
		esac
	done
	case $1 in
	?*)	cmp -s $1 $(<) || cp $1 $(<) ;;
	*)	: > $(<)
	esac

%.yacc : %.h pp.h
	$(RM) -f $(<)
	{
	$(*:N!=$(>):?$(SED) -n -e '/^#define T_TOKEN/p' -e '/^#define N_/p' $(*:N!=$(>))$("\n")??)cat $(>)
	} > 1.$(tmp).c
	$(STDED|ED) $(STDEDFLAGS|EDFLAGS) 1.$(tmp).c <<'!'
	g/^#define N_/m0
	v/^#define [NT]_/d
	1,$s/^#define \(T_[A-Z0-9_]*\).*/&\
	printf(" \1 %d", \1);/
	g/^printf.*T_HEADER/d
	g/^printf.*T_KEYWORD/d
	g/^printf.*T_TOKCAT/d
	g/^printf.*T_TOKEN/d
	0a
	$("#")include <stdio.h>
	int
	main(argc, argv)
	int	argc;
	char**	argv;
	{
	printf("%%token /*generated from $(>)*/");
	.
	$a
	printf("\n");
	return 0;
	}
	.
	w
	q
	!
	$(CC.NATIVE|CC) -o $(tmp).exe 1.$(tmp).c
	./$(tmp).exe > $(<)
	$(RM) -f 1.$(tmp).c $(tmp).exe

ppdebug.h : ppfsm.h ppdef.h pplib.h
	: > 1.$(tmp).c
	$(STDED|ED) $(STDEDFLAGS|EDFLAGS) 1.$(tmp).c <<'!'
	r $(*:N=*fsm.h)
	1,/^#define PROTO/-d
	/^#define LAST/,$d
	v/^#define/d
	g/PROTOMAIN/d
	1,$s/^#define //
	1,$s/[^A-Za-z0-9_].*//
	1,$s/.*/	"&", &,/
	1i
	$("/")*
	 * preprocessor library debug maps
	 *$("/")
	struct map
	{
		char*	nam;
		long	val;
	};
	static struct map pplexmap[] =
	{
	.
	$a
	};
	.
	ka
	r $(*:N=*def.h)
	$("'")a+1,/^#define ADD/-d
	/^$/,$d
	$("'")a+1,$s/^#define //
	$("'")a+1,$s/[ 	].*//
	$("'")a+1,$s/.*/	"&", &,/
	$("'")aa
	static struct map ppstatemap[] =
	{
	.
	$a
	};
	.
	ka
	r $(*:N=*def.h)
	$("'")a+1,/^#define ALLMULTIPLE/-d
	/^$/,$d
	$("'")a+1,$s/^#define //
	$("'")a+1,$s/[ 	].*//
	$("'")a+1,$s/.*/	"&", &,/
	$("'")aa
	static struct map ppmodemap[] =
	{
	.
	$a
	};
	.
	ka
	r $(*:N=*def.h)
	$("'")a+1,/^#define ELSEIF/-d
	/^$/,$d
	$("'")a+1,$s/^#define //
	$("'")a+1,$s/[ 	].*//
	$("'")a+1,$s/.*/	"&", &,/
	$("'")aa
	static struct map ppoptionmap[] =
	{
	.
	$a
	};
	.
	ka
	r $(*:N=*lib.h)
	$("'")a+1,/^#define IN_BUFFER/-d
	/^$/,$d
	$("'")a+1,$s/^#define IN_//
	$("'")a+1,$s/[ 	].*//
	$("'")a+1,$s/.*/	"&", IN_&,/
	$("'")aa
	static struct map ppinmap[] =
	{
	.
	$a
	};
	.
	w
	q
	!
	if	$(CMP) -s 1.$(tmp).c $(<)
	then	$(RM) -f 1.$(tmp).c
	else	$(MV) 1.$(tmp).c $(<)
	fi
