/*
 * ksh makefile
 */

SH := $(PWD:B:/[0-9]*$//:N=ksh*:-ksh)		/* name of the shell program */
VERSION = 1.1
LICENSE = since=1982,author=dgk
CATALOG = libshell
ERROR_CONTEXT_T == Error_context_t /* workaround until switch from errorpush()/errorpop() => errorctx() */
RELEASE := $(SH:/.*sh//)
SHCOMP := shcomp$(RELEASE)

/*
 * set these variables to 1 to enable, 0 to disable, null to probe
 * override SHOPT_foo=1 can be placed one per line in the build dir Makeargs
 */

SHOPT_2DMATCH == 1		/* two dimensional .sh.match for ${var//pat/str} */
SHOPT_ACCT ==  			/* accounting */
SHOPT_ACCTFILE ==  		/* per user accounting info */
SHOPT_AUDIT == 1		/* enable auditing per SHOPT_AUDITFILE */
SHOPT_AUDITFILE == "/etc/ksh_audit"  		/* auditing file */
SHOPT_BASH ==			/* bash compatibility code */
SHOPT_BGX == 1			/* one SIGCHLD trap per completed job */
SHOPT_BRACEPAT == 1		/* C-shell {...,...} expansions (, required) */
SHOPT_CMDLIB_HDR ==		/* -lcmd builtin list (<cmdlist.h>) */
SHOPT_CMDLIB_DIR ==		/* SHOPT_CMDLIB_HDR directory prefix (default "/opt/ast/bin") */
SHOPT_COSHELL == 1		/* build with connection to coshell */
SHOPT_CRNL ==			/* accept <cr><nl> for <nl> */
SHOPT_DYNAMIC == 1		/* dynamic loading for builtins */
SHOPT_ECHOPRINT ==		/* make echo equivalent to print */
SHOPT_EDPREDICT == 1		/* predictive editing  */
SHOPT_ESH == 1			/* emacs/gmacs edit mode */
SHOPT_FILESCAN == 1		/* fast file scan */
SHOPT_FIXEDARRAY == 1		/* fixed dimension indexed array */
SHOPT_FS_3D == 			/* 3d file system */
SHOPT_HISTEXPAND == 1		/* csh-style history file expansions */
SHOPT_KIA == 1			/* shell information database generation */
SHOPT_MULTIBYTE == 1		/* multibyte character handling */
SHOPT_NAMESPACE == 1		/* allow namespaces */
SHOPT_OLDTERMIO ==		/* support both TCGETA and TCGETS */
SHOPT_OPTIMIZE == 1		/* optimize loop invariants */
SHOPT_PFSH == 1			/* solaris exec_attr(4) profile execution */
SHOPT_P_SUID ==			/* real uid's that require -p for set[ug]id */
SHOPT_RAWONLY == 1		/* make viraw the only vi mode */
SHOPT_REGRESS ==		/* enable __regress__ builtin and instrumented intercepts for testing */
SHOPT_REMOTE ==			/* enable --rc if running as a remote shell */
SHOPT_SEVENBIT ==		/* strip the eigth bit from characters */
SHOPT_SPAWN ==			/* use spawnveg for fork/exec */
SHOPT_STATS ==	1		/* add .sh.stats variable */
SHOPT_SUID_EXEC == 1		/* allow (safe) suid/sgid shell scripts */
SHOPT_SYSRC ==			/* attempt . /etc/ksh.kshrc if interactive */
SHOPT_TIMEOUT ==		/* number of seconds for shell timeout */
SHOPT_TYPEDEF == 1		/* enable typeset type definitions */
SHOPT_VSH == 1			/* vi edit mode */

if CC.HOSTTYPE == "linux.alpha"
	/* workaround for "BUG IN DYNAMIC LINKER ld.so" */
	:PACKAGE: - m:static:noinclude /*noCC.EXPORT.DYNAMIC*/
end

if CC.HOSTTYPE == "*.s390-64"
	CC.DLL = $(CC.DLLBIG)
end

if SHOPT_DYNAMIC && ( "$(CC.DIALECT:N=EXPORT=DLL)" || "$(PACKAGE_OPTIONS:N=optimize-space)" )
	if "$(PACKAGE_OPTIONS:N=optimize-space)" && ! SHOPT_CMDLIB_HDR
		SHOPT_CMDLIB_HDR == <cmdlist.h>
	end
	CCFLAGS += $$(CC.DLL) $$(CC.SUFFIX.DEBUG:+$$(CC.DEBUG))
	LIBS_req = -lshell$(RELEASE)
else
	if VARIANT
		SHOPT_DYNAMIC = 1
	else
		libtype = :static
	end
	if SHOPT_DYNAMIC
		CCLDFLAGS += $$(CC.EXPORT.DYNAMIC)
	end
	LIBS_req = +lshell$(RELEASE)
end

:PACKAGE: ast$(libtype):20100309 coshell:order --clobber=!($(SH))

.SOURCE : edit sh bltins data tests fun
.SOURCE.h : include 

/* documentation files */
DOCFILES = sh.memo builtins.mm README RELEASE TYPES PROMO.mm COMPATIBILITY \
		DESIGN OBSOLETE RELEASE93 RELEASE88

KSHELL == 1			/* this is ksh */

SH_CMDLIB_DIR ==		/* SHOPT_CMDLIB_DIR dir prefix */
SH_DICT ==			/* message catalog */
DEBUG ==			/* debugging purposes only */

if  CC.HOSTTYPE == "win32*"
	SHOPT_CRNL == 1		/* <cr><nl> is eqivalent to <nl> */
end

if SHOPT_BASH
	BASH_HOSTTYPE == "$(CC.HOSTTYPE:S:/\.//)"
	BASH_MACHTYPE == "$(BASH_HOSTTYPE)-unknown-$(CC.HOSTTYPE:B)"
end

/* use the following libraries only if they exist */
LIBS_opt := +ljobs +li

if  CC.HOSTTYPE == "sol([89]|[1-9][0-9]).*"
	LDFLAGS  += $(CC.LD.LAZY) $(CC.LD.NORECORD)
end

if "$(-mam:N=static*)"
	LIBS_opt += -lsocket -lnsl
elif CC.HOSTTYPE == "sol?([789]|[1-9][0-9]).*"
	LIBS_opt += +lsocket -lnsl
elif CC.HOSTTYPE != "sgi.mips*"
	LIBS_opt += +lsocket +lnsl
end
if CC.HOSTTYPE == "linux.sparc*"
	/* the linux.sparc linker still has some problems */
	LIBS_opt += -ldll
end
LIBS_opt += -lsecdb
if CC.HOSTTYPE == "sol.*"
	LIBS_opt += -lw
end
$(LIBS_opt)	: .DONTCARE

LDLIBRARIES = $(LIBS_opt)

FILES_opt =		/* optional file list enabled by vars above */
if SHOPT_ESH
	FILES_opt += emacs.c
end
if SHOPT_VSH
	FILES_opt += vi.c
end
if SHOPT_BASH
	FILES_opt += bash.c bash_pre_rc.c
	SHOPT_HISTEXPAND == 1
end
if SHOPT_HISTEXPAND
	FILES_opt += hexpand.c
end
if SHOPT_DYNAMIC
	FILES_opt += -ldll
end
if SHOPT_X
	LDFLAGS += -u _XtAppInitialize -L/usr/add-on/X11/lib
end

:ALL: $(SH) $(SHCOMP) $(SHOPT_SUID_EXEC:+suid_exec) $(SHOPT_BASH:+bash$(RELEASE))

$(SH) :: sh.1 pmain.c $(LIBS_req)

DATAFILES = limits.c msg.c strdata.c testops.c keywords.c options.c \
                 signals.c aliases.c builtins.c variables.c lexstates.c

shell$(RELEASE) $(VERSION) id=shell :LIBRARY: shell.3 nval.3 alarm.c cd_pwd.c cflow.c deparse.c \
	enum.c getopts.c hist.c misc.c print.c read.c sleep.c trap.c test.c \
	typeset.c ulimit.c umask.c whence.c main.c nvdisc.c nvtype.c \
	arith.c args.c array.c completion.c defs.c edit.c expand.c regress.c \
	fault.c fcin.c history.c init.c io.c jobs.c lex.c macro.c name.c \
	nvtree.c parse.c path.c string.c streval.c subshell.c tdump.c timers.c \
	trestore.c waitevent.c xec.c env.c $(DATAFILES) $(FILES_opt) \
	$(SHOPT_COSHELL:+-lcoshell) -lcmd -last -lm

"sol*.i386*"	:NOOPTIMIZE: main.c
"win32*"	:NOOPTIMIZE: strdata.c trestore.c

if CC.HOSTTYPE == "win32*"
:DLL: $(CC.DEBUG)
else
:DLL: $(CC.OPTIMIZE)
end

:READONLY: $(DATAFILES)

$(INCLUDEDIR) :INSTALLPROTO: nval.h shell.h history.h

LIBCMD = $(.LIB.NAME. cmd:T=F)

if SHOPT_SUID_EXEC && ! "$(RELEASE)"
suid_exec ::	CC.DLL= suid_exec.c +last
end

$(SHCOMP) ::	CC.DLL= SH_DICT='"libshell"' shcomp.c $(LIBS_req)

$(FUNDIR) :INSTALLDIR: mode=+x dirs popd pushd

shcomp.o : _BLD_DLL= $(CC.HOSTTYPE:N=cygwin.*:??_BLD_shell=?)

if SHOPT_BASH

bash$(RELEASE) :LINK: $(SH)

bash_pre_rc.c : bash_pre_rc.sh
	echo "const char bash_pre_rc[] = " > $(<)
	sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/'"'"'/\\'"'"'/g' -e 's/^[[:space:]]*\(.*\)$/\"\1\\n\"/' $(*) >> $(<)
	echo ";" >> $(<)

end

:: math.tab syscall.s mamexec mamstate.c $(DOCFILES) \
	bash.c bash_pre_rc.sh hexpand.c mkservice.c \
	shopen.mk shopen.c

:: shtests \
	alias.sh append.sh arith.sh arrays.sh arrays2.sh \
	attributes.sh basic.sh bracket.sh builtins.sh case.sh \
	comvar.sh comvario.sh coprocess.sh cubetype.sh enum.sh exit.sh \
	expand.sh functions.sh glob.sh grep.sh heredoc.sh io.sh \
	leaks.sh locale.sh math.sh nameref.sh namespace.sh options.sh \
	path.sh pointtype.sh pty.sh quoting.sh quoting2.sh readcsv.sh \
	recttype.sh restricted.sh return.sh select.sh shtests \
	sigchld.sh signal.sh statics.sh subshell.sh substring.sh \
	tilde.sh timetype.sh treemove.sh types.sh variables.sh \
	vartree1.sh vartree2.sh

:: ksh-regress.rt ksh-regress.tst

if "$(PWD:B:N=cc-*)"

test : .NULL

else

test : test.ksh

test.ksh : $(BINDIR)/$(SH) $(SH) shtests
	$(SILENT) $(CMP) $(CMPFLAGS) $(*:O=1) $(*:O=2) 2>/dev/null ||
	echo "make install to run the tests on the latest $(SH)" >&2
	cd $(*:O=3:P=L!:D)
	SHELL=$(*:O=1:P=A) $(*:O=1:P=A) $(*:O=3:B) $(SHTESTSFLAGS)

test.% : %.sh COSHELL_OPTIONS=separate $(BINDIR)/$(SH) $(SH) shtests
	$(SILENT) $(CMP) $(CMPFLAGS) $(*:O=2) $(*:O=3) 2>/dev/null ||
	echo "make install to run the tests on the latest $(SH)" >&2
	cd $(*:O=4:P=L!:D)
	SHELL=$(*:O=2:P=A) $(*:O=2:P=A) $(*:O=4:B) $(SHTESTSFLAGS) $(*:O=1:P=A)

if RELEASE

.INSTALL : .CLEAR $(*.INSTALL:N=*$(RELEASE)*([!/]))

end

end
