#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This builds all objects needed for libbc.
#

LIBRARY= libc.a
# Default rules in ../../Makefile.targ not used.
VERS= bogus
DYNLIB4X= libc.so.1.9
DYNLIBS5= libc.so.2.9
#DYNLIBS5 is also defined in ../Makefile

M4= m4
ECHO=	echo

# objects are grouped by source directory.

COMPATCOM= \
gtty.o      lockf.o     pause.o     stty.o      tell.o      ulimit.o \
utime.o

COMPAT4.1=\
ftime.o     nice.o      rand.o      vlimit.o    vtimes.o    getpw.o times.o
 
COMPATSYS5=\
nice.o      rand.o      getpw.o     times.o

CRTSPARC =\
_ftou.o      misalign.o  ptr_call.o \
start_float.o \
alloc_pbuf.o mon.o muldiv.o

GENCOM=\
_crypt.o _nlist.o _perror.o _psignal.o a64l.o abs.o alarm.o\
asctime.o atof.o atoi.o atol.o bcmp.o bsearch.o\
clock.o closedir.o crypt.o ctime.o ctype_.o\
drand48.o dysize.o errlst.o execvp.o exit.o exportent.o ecvt.o\
fabs.o fmod.o frexp.o\
fstab.o ftok.o ftw.o getauid.o getauditflags.o \
getcwd.o getenv.o getgraent.o getlogin.o \
getopt.o getsubopt.o getpwaent.o  getttyent.o\
getttynam.o getusershell.o grpauth.o hsearch.o\
ieee_globals.o index.o isatty.o \
issecure.o jcsetpgrp.o\
l64a.o labeltostring.o ldexp.o lfind.o lsearch.o\
madvise.o mallopt.o \
euc.multibyte.o iso.multibyte.o xccs.multibyte.o \
mblib.o mbstowcs.o mbtowc.o wcstombs.o wctomb.o \
memalign.o memccpy.o memchr.o memcmp.o\
mkstemp.o mktemp.o mlock.o mlockall.o\
mntent.o modf.o msync.o munlock.o munlockall.o\
nl_cxtime.o nl_strncmp.o  ndbm.o on_exit.o\
opendir.o optind.o perror.o plock.o \
posix_sig.o posix_tty.o popen.o psignal.o putenv.o \
pwdauth.o pwdnm.o qsort.o\
random.o readdir.o realpath.o regex.o rindex.o scandir.o seekdir.o\
setlocale.o setregid.o setreuid.o setrgid.o setruid.o sigfpe.o siglist.o\
ssignal.o strchr.o stricmp.o \
strftime.o strncat.o \
strpbrk.o strptime.o strrchr.o strspn.o strstr.o \
strtod.o strtok.o strtol.o swab.o syslog.o\
telldir.o tfind.o time.o tsearch.o \
ualarm.o usleep.o valloc.o string_decim.o \
file_decim.o func_decim.o econvert.o seconvert.o gconvert.o \
decimal_bin.o float_decim.o double_decim.o \
pack_float.o _unpack_dble.o unpack_float.o \
_base_S.o _base_il.o _base_sup.o _big_power.o _small_power.o \
_sprintf_sup.o _times_power.o qeconvert.o \
_Q_neg.o _Q_add.o _Q_sub.o _Q_mul.o _Q_div.o _Q_cmp.o \
_Q_cmpe.o _Q_stoq.o _Q_dtoq.o _Q_itoq.o _Q_utoq.o _Q_qtos.o _Q_qtod.o \
_Q_qtoi.o _Q_qtou.o _Q_sqrt.o _Qfaddsub.o _Qfcompare.o _Qfdiv.o \
_Qfmul.o _Qfpack.o _Qfunpack.o _Qfutility.o _Q_fcc.o _Q_get_rp_rd.o \
calloc.o malloc.o \
getpass.o localtime.o ttyslot.o

GENCOMSPARC=\
alloca.o   ffs.o insque.o    remque.o    isinf.o     base_conv.o 

GEN4.2=\
nlist.o     timezone.o  sleep.o  system.o

GENSYS5=\
assert.o    nlist.o     sgetl.o    sleep.o      sputl.o     system.o \
sighold.o   

STDIOCOM=\
clrerr.o    ctermid.o   cuserid.o   doprnt.o    doscan.o    fdopen.o \
feof.o      ferror.o    fgetc.o     fgets.o     fileno.o    findiop.o \
fputc.o     fputs.o     fread.o     fseek.o     ftell.o \
fwrite.o    getc.o      getchar.o   gets.o      getw.o      iob.o \
putc.o      putchar.o   puts.o      putw.o      remove.o \
rew.o       scanf.o     setbuffer.o setvbuf.o   tmpnam.o    tempnam.o \
tmpfile.o   ungetc.o

STDIO4.2=\
filbuf.o    fopen.o     fprintf.o   printf.o    flsbuf.o  setbuf.o \
sprintf.o   vfprintf.o  vprintf.o   vsprintf.o

STDIOSYS5=\
filbuf.o    fopen.o     fprintf.o   flsbuf.o    printf.o    setbuf.o \
sprintf.o   vfprintf.o  vprintf.o   vsprintf.o

SYSCOM=\
_access.o acct.o  adjtime.o close.o _creat.o dup.o dup2.o \
fchdir.o fchroot.o \
fdlist.o flock.o  fpathconf.o fsync.o ftruncate.o getdents.o \
getdtablesize.o getgid.o  getitimer.o getpid.o gettimeofday.o \
getuid.o ioctl.o kill.o lseek.o mincore.o mprotect.o munmap.o\
_open.o profil.o setitimer.o \
rlimit.o _statfs.o  sync.o umask.o uname.o\
execl.o execle.o execv.o mkfifo.o msgsys.o\
pathconf.o semsys.o shmsys.o unmount.o wait.o setuid.o\
setgid.o _stat.o seteuid.o setegid.o signalmap.o syscall.o \
maperror.o sigsetjmp.o accept.o bind.o connect.o getpeername.o \
getsockname.o getsockopt.o listen.o recv.o send.o \
setsockopt.o shutdown.o socket.o socketpair.o setsid.o sigaction.o

SYSCOMSPARC=\
_exit.o     brk.o       cerror.o    errno.o     \
getegid.o   geteuid.o   getppid.o   mmap.o      pipe.o      putmsg.o \
sbrk.o      _syscall.o  getmsg.o    _read.o     _write.o \
_readv.o    _writev.o	sendsig.o

SYS4.2=\
access.o    chdir.o     chmod.o     chown.o     chroot.o    \
creat.o     execve.o    getpgrp.o   link.o      mkdir.o  \
mknod.o     open.o      readlink.o  rename.o    rmdir.o  \
setpgrp.o   stat.o      symlink.o   truncate.o  unlink.o     \
statfs.o    fcntl.o     read.o      write.o     readv.o \
writev.o    setjmp.o	mount.o 

SYS4.2SPARC=\
getgroups.o setgroups.o

SYSSYS5=\
access.o    chdir.o     chmod.o     chown.o     chroot.o \
creat.o     execve.o    getgroups.o getpgrp.o   link.o \
mkdir.o     mknod.o     open.o      readlink.o  rename.o \
rmdir.o     setgroups.o setpgrp.o   stat.o      statfs.o \
stime.o     symlink.o   truncate.o  unlink.o    fcntl.o \
read.o      write.o     readv.o     writev.o    setjmp.o \
mount.o

#SSYSSPARC=\
#_getpgrp.o  _kill.o     _lseek.o    _mknod.o    _mount.o    _setpgrp.o \
#umount.o

INET=\
inet_addr.o        inet_lnaof.o     inet_makeaddr.o  inet_netof.o \
inet_network.o     inet_ntoa.o

NET=\
ether_addr.o bindresvport.o getrpcport.o rcmd.o \
rexec.o ruserpass.o authunix.o

NETSPARC= htonl.o     htons.o         ntohl.o          ntohs.o

YP= yp_bind.o

YP= yp_bind.o
PSEUDO_SRCS= adjtime.s fchdir.s \
fchroot.s      \
fpathconf.s getitimer.s    getpid.s    \
mincore.s   mprotect.s munmap.s    \
profil.s    setitimer.s \
sync.s     sysconf.s   umask.s         ustat.s \
acct.s    stime.s

#
# libbc build rules
pics/%.o s5pics/%.o : ../libc/compat/common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o : ../libc/compat/4.1/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

s5pics/%.o : ../libc/compat/sys5/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/crt/sparc/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/crt/sparc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../csu/common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/gen/common/%.S
	$(BUILD.s)
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/gen/common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/gen/common/sparc/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/gen/common/sparc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o : ../libc/gen/4.2/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

s5pics/%.o : ../libc/gen/sys5/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/inet/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/net/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/net/sparc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/stdio/common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o : ../libc/stdio/4.2/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

s5pics/%.o : ../libc/stdio/sys5/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/sys/common/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/sys/common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/sys/common/sparc/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

pics/%.o : ../libc/sys/4.2/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o : ../libc/sys/4.2/sparc/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

s5pics/%.o : ../libc/sys/sys5/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

s5pics/%.o : ../libc/sys/sys5/sparc/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

s5pics/%.o : ../libc/stdio/sys5/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/rpc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o s5pics/%.o : ../libc/yp/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)


# include common library definitions
include ../../Makefile.lib

# There should be a mapfile here
MAPFILES =

CSTD=	$(CSTD_GNU89)

#
# The BCP include files depend on old preprocessor semantics.
#
CCMODE = -Xt

# the bcp libraries go in /usr/4lib. override ROOTLIBDIR from ../../Makefile.lib
# and save it so we can find the libraries with which to link
ROOTLIBDIR=     $(ROOT)/usr/4lib

CPPFLAGS= -Dsparc \
	-I. -Iinc -I../inc/include -I../inc/include/sys $(CPPFLAGS.master)
ASFLAGS=  -P -D__STDC__ -DLOCORE -D_SYS_SYS_S -D_ASM $(CPPFLAGS)
LDLIBS= -t -R/usr/ucblib -L$(ROOT)/usr/ucblib $(LDLIBS.lib) \
	-lucb -lc -lnsl -lsocket

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-extra
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-address

# SONAME is used by DYNFLAGS
$(DYNLIB4X) :=	SONAME = $(DYNLIB4X)
$(DYNLIBS5) :=	SONAME = $(DYNLIBS5)

pics/%.o:= ASFLAGS += -K pic -DPIC
pics/%.o:= CPPFLAGS += -K pic -DPIC
s5pics/%.o:= ASFLAGS += -K pic -DPIC
DYNFLAGS += $(ZINTERPOSE)

BUILD.s=  $(AS) $(ASFLAGS) $< -o $@

# libbc method of building an archive
BUILD.AR= $(RM) $@ ; \
	$(AR) q $@ $(OBJECTS:%=$(DIR)/%)

# the TXTS macro is used for NSE bootstrapping.
TXTS=	inc/SYS.h inc/PIC.h inc/machine/asm_linkage.h 

LIBS = $(DYNLIB4X) $(DYNLIBS5)

OBJECTS= $(COMPATCOM) $(COMPAT4.1) $(CRTSPARC) $(GENCOM) \
$(GENCOMSPARC) $(GEN4.2) $(STDIOCOM) $(STDIO4.2) \
$(INET) $(NET) $(NETSPARC) $(YP) \
$(SYSCOM) $(SYSCOMSPARC) $(SYS4.2) 

#
# Since this library is strictly for binary compability with ancient
# applications, we deactivate CTF to avoid kicking up dust.
#
CTFCONVERT_POST = :
CTFMERGE_LIB = :

S5OBJECTS= $(COMPATCOM) $(COMPATSYS5) $(CRTSPARC) $(GENCOM) \
$(GENCOMSPARC) $(GENSYS5) $(STDIOCOM) $(STDIOSYS5) \
$(SYSCOM) $(SYSCOMSPARC) $(SYSSYS5) $(SSYS5SPARC) \
$(INET) $(NET) $(NETSPARC) $(YP)

S5PICOBJS=	$(S5OBJECTS:%=s5pics/%)

CLEANFILES= ../libc/yp/ypupdate_prot.c ../inc/include/rpcsvc/ypupdate_prot.h \
	../libc/compat/sys5/epoch.h \
	$(S5PICOBJS)
CLOBBERFILES= ../libc/compat/sys5/mkepoch

# conditional assignments
s5pics/%.o:= CPPFLAGS = -Dsparc -DS5EMUL -K pic -DPIC -I. -Iinc \
	-I../inc/5include -I../inc/include -I../inc/include/sys \
	$(CPPFLAGS.master)

s5pics/%.o := CFLAGS += -xregs=no%appl
pics/%.o := CFLAGS += -xregs=no%appl

$(DYNLIB4X):= DIR = pics
$(DYNLIBS5):= DIR = s5pics

.KEEP_STATE:

# Declare that all .o's can be made in parallel.
.PARALLEL:	$(PICS) $(S5PICOBJS)

all: $(TXTS) $(LIBS)

$(DYNLIB4X): pics .WAIT $(PICS)
	$(CC) -o $@ -G $(DYNFLAGS) $(PICS) $(LDLIBS)
	$(POST_PROCESS_SO)

$(DYNLIBS5): s5pics .WAIT $(S5PICOBJS)
	$(CC) -o $@ -G $(DYNFLAGS) $(S5PICOBJS) $(LDLIBS)
	$(POST_PROCESS_SO)

# include common library targets
include ../../Makefile.targ

s5pics:
	-@mkdir -p $@

# special cases
PSEUDO_POBJS= $(PSEUDO_SRCS:%.s=pics/%.o)
PSEUDO_PS5OBJS= $(PSEUDO_SRCS:%.s=s5pics/%.o) 

$(PSEUDO_POBJS) $(PSEUDO_PS5OBJS):
	@(echo '#include "SYS.h"'; \
	echo '  SYSCALL($(@F:.o=))'; \
	echo '  RET'; \
	echo '  SET_SIZE($(@F:.o=))') >  tmp.$(@F:.o=).s
	$(AS) $(ASFLAGS) -o $@ tmp.$(@F:.o=).s
	$(POST_PROCESS_O)
	@$(RM) tmp.$(@F:.o=).s

s5pics/times.o : ../libc/compat/sys5/epoch.h ../libc/compat/sys5/times.c
	$(COMPILE.c) -o $@ ../libc/compat/sys5/times.c
	$(POST_PROCESS_O)

../libc/compat/sys5/epoch.h: ../libc/compat/sys5/mkepoch
	../libc/compat/sys5/mkepoch > $@

../libc/compat/sys5/mkepoch: ../libc/compat/sys5/mkepoch.c
	$(NATIVECC) -O -o $@ ../libc/compat/sys5/mkepoch.c

pics/maperror.o s5pics/maperror.o: ../libc/sys/common/maperror.c
	$(CC) -I../libc/sys/common $(CPPFLAGS) $(CFLAGS) -c -o $@ ../libc/sys/common/maperror.c

#
# The following rules generate the .h file and XDR routines from the
# rpcgen source. Objects built here, look for it here. Further, when
# building ypupdated it should look here too, but doesn't at the moment.
#
# It would be nice to use a ".x.h" rule for this, but that causes problems.
#
pics/yp_update.o \
s5pics/yp_update.o : ../inc/include/rpcsvc/ypupdate_prot.h ../libc/yp/yp_update.c
	$(COMPILE.c) -o $@ ../libc/yp/yp_update.c
	$(POST_PROCESS_O)

pics/ypupdate_prot.o s5pics/ypupdate_prot.o : ../inc/include/rpcsvc/ypupdate_prot.h\
				../libc/yp/ypupdate_prot.c 
	$(COMPILE.c) -o $@ ../libc/yp/ypupdate_prot.c
	$(POST_PROCESS_O)

../libc/yp/ypupdate_prot.c: ../libc/yp/ypupdate_prot.x
	$(RM) $@
	$(RPCGEN) -c -o $@ ../libc/yp/ypupdate_prot.x

../libc/yp/ypupdate_prot.h: ../libc/yp/ypupdate_prot.x
	$(RM) $@ ../libc/yp/ypupdate_prot.h
	$(RPCGEN) -h -o ../libc/yp/ypupdate_prot.h ../libc/yp/ypupdate_prot.x

../inc/include/rpcsvc/ypupdate_prot.h: ../libc/yp/ypupdate_prot.h
	cp ../libc/yp/ypupdate_prot.h $@
