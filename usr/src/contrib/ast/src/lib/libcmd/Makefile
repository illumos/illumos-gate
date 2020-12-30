/*
 * command library -- commands small enough to be builtins
 */

:PACKAGE: ast

LICENSE = since=1992,author=gsf+dgk

CCFLAGS = $(CC.SUFFIX.DEBUG:+$(CC.DEBUG)) $(CC.OPTIMIZE) $(CC.DLL)

/* 2009-04-15 ld.so experiment -- may become a default for all plugins */
CC.DLL.ORIGIN = $(CC.LD.ORIGIN:C,/.*,,)
LDFLAGS = $(CC.DLL.ORIGIN)

CP = $(STDCP|"cp")
CHMOD = $(STDCHMOD|"chmod")

HOSTTYPE == "$(CC.HOSTTYPE)"

cmd 1.2 :LIBRARY: RELEASE cmdinit.c \
	cmd.h rev.h wc.h \
	basename.c cat.c chgrp.c chmod.c chown.c cksum.c cmp.c \
	comm.c cp.c cut.c dirname.c date.c expr.c fds.c fmt.c fold.c \
	getconf.c head.c id.c join.c ln.c logname.c md5sum.c mkdir.c \
	mkfifo.c mktemp.c mv.c paste.c pathchk.c pids.c rev.c rm.c \
	rmdir.c stty.c sum.c sync.c tail.c tee.c tty.c uname.c uniq.c \
	vmstate.c wc.c revlib.c wclib.c sumlib.o \
	fts_fix.c lib.c \
	-lfsg -lmd -lutil

sumlib.o : +lsum
	$(AR) x $(*:O=1) $(<)

$(INCLUDEDIR) :INSTALLPROTO: cmd.h cmdext.h cmdlist.h

"win32*" :NOOPTIMIZE: id.c

src = $(*$(*$(*cmd)):N=*.c:T=F)

cmdext.h : (src) $$(-mam:+$$(src))
	{
	cat <<!
	$("#")pragma prototyped
	$("/")*
	$(" ")* -lcmd extern function prototypes
	$(" ")*/
	
	$("#")include <shcmd.h>

	!
	$(SED) \
		-e '/^b_[a-z_][a-z_0-9]*(/!d' \
		-e 's/^b_//' \
		-e 's/(.*//' \
		-e 's/.*/extern int	b_&(int, char**, Shbltin_t*);/' \
		$($(~:O=1)) |
	$(SORT) -u
	} > 1.$(tmp).h
	if	$(CMP) $(CMPFLAGS) 1.$(tmp).h $(<)
	then	$(RM) $(RMFLAGS) 1.$(tmp).h
	else	$(MV) 1.$(tmp).h $(<)
	fi

cmdlist.h : (src) $$(-mam:+$$(src))
	{
	cat <<!
	$("#")pragma prototyped
	$("/")*
	$(" ")* -lcmd function list -- define your own CMDLIST()
	$(" ")*/
	
	!
	$(SED) \
		-e '/^b_[a-z_][a-z_0-9]*(/!d' \
		-e 's/^b_//' \
		-e 's/(.*//' \
		-e 's/.*/CMDLIST(&)/' \
		$($(~):T=F) |
	$(SORT) -u
	} > 1.$(tmp).h
	if	$(CMP) $(CMPFLAGS) 1.$(tmp).h $(<)
	then	$(RM) $(RMFLAGS) 1.$(tmp).h
	else	$(MV) 1.$(tmp).h $(<)
	fi

if CC.HOSTTYPE == "sun4"
	pathsetlink == symlink	/* ld.so workaround */
end

ignore dlldefs.h /* prevents bootstrap double build */
