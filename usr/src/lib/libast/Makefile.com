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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#

SHELL=/usr/bin/ksh93

LIBRARY=	libast.a
VERS=		.1

# platform-independent sources are in common/
OBJECTS += \
	common/cdt/dtclose.o \
	common/cdt/dtdisc.o \
	common/cdt/dtextract.o \
	common/cdt/dtflatten.o \
	common/cdt/dthash.o \
	common/cdt/dtlist.o \
	common/cdt/dtmethod.o \
	common/cdt/dtnew.o \
	common/cdt/dtopen.o \
	common/cdt/dtrenew.o \
	common/cdt/dtrestore.o \
	common/cdt/dtsize.o \
	common/cdt/dtstat.o \
	common/cdt/dtstrhash.o \
	common/cdt/dttree.o \
	common/cdt/dttreeset.o \
	common/cdt/dtview.o \
	common/cdt/dtwalk.o \
	common/comp/atexit.o \
	common/comp/basename.o \
	common/comp/catopen.o \
	common/comp/closelog.o \
	common/comp/creat64.o \
	common/comp/dirname.o \
	common/comp/dup2.o \
	common/comp/eaccess.o \
	common/comp/errno.o \
	common/comp/execlp.o \
	common/comp/execve.o \
	common/comp/execvp.o \
	common/comp/execvpe.o \
	common/comp/fcntl.o \
	common/comp/fmtmsglib.o \
	common/comp/fnmatch.o \
	common/comp/frexp.o \
	common/comp/frexpl.o \
	common/comp/fsync.o \
	common/comp/ftw.o \
	common/comp/getdate.o \
	common/comp/getgroups.o \
	common/comp/getlogin.o \
	common/comp/getopt.o \
	common/comp/getoptl.o \
	common/comp/getpgrp.o \
	common/comp/getsubopt.o \
	common/comp/getwd.o \
	common/comp/gross.o \
	common/comp/hsearch.o \
	common/comp/iconv.o \
	common/comp/killpg.o \
	common/comp/link.o \
	common/comp/localeconv.o \
	common/comp/lstat.o \
	common/comp/memccpy.o \
	common/comp/memchr.o \
	common/comp/memcmp.o \
	common/comp/memcpy.o \
	common/comp/memmove.o \
	common/comp/memset.o \
	common/comp/mkdir.o \
	common/comp/mkfifo.o \
	common/comp/mknod.o \
	common/comp/mktemp.o \
	common/comp/mktime.o \
	common/comp/mount.o \
	common/comp/nftw.o \
	common/comp/omitted.o \
	common/comp/open.o \
	common/comp/openlog.o \
	common/comp/putenv.o \
	common/comp/re_comp.o \
	common/comp/readlink.o \
	common/comp/realpath.o \
	common/comp/regcmp.o \
	common/comp/regexp.o \
	common/comp/remove.o \
	common/comp/rename.o \
	common/comp/resolvepath.o \
	common/comp/rmdir.o \
	common/comp/setenv.o \
	common/comp/setlocale.o \
	common/comp/setlogmask.o \
	common/comp/setpgid.o \
	common/comp/setsid.o \
	common/comp/sigunblock.o \
	common/comp/sigflag.o \
	common/comp/spawnveg.o \
	common/comp/statvfs.o \
	common/comp/strcasecmp.o \
	common/comp/strchr.o \
	common/comp/strftime.o \
	common/comp/strncasecmp.o \
	common/comp/strptime.o \
	common/comp/strrchr.o \
	common/comp/strstr.o \
	common/comp/strtod.o \
	common/comp/strtol.o \
	common/comp/strtold.o \
	common/comp/strtoll.o \
	common/comp/strtoul.o \
	common/comp/strtoull.o \
	common/comp/swab.o \
	common/comp/symlink.o \
	common/comp/syslog.o \
	common/comp/system.o \
	common/comp/tempnam.o \
	common/comp/tmpnam.o \
	common/comp/transition.o \
	common/comp/tsearch.o \
	common/comp/unlink.o \
	common/comp/unsetenv.o \
	common/comp/vfork.o \
	common/comp/waitpid.o \
	common/comp/wc.o \
	common/comp/wordexp.o \
	common/dir/getdents.o \
	common/dir/opendir.o \
	common/dir/readdir.o \
	common/dir/rewinddir.o \
	common/dir/seekdir.o \
	common/dir/telldir.o \
	common/disc/memfatal.o \
	common/disc/sfdcdio.o \
	common/disc/sfdcdos.o \
	common/disc/sfdcfilter.o \
	common/disc/sfdcmore.o \
	common/disc/sfdcprefix.o \
	common/disc/sfdcseekable.o \
	common/disc/sfdcslow.o \
	common/disc/sfdcsubstr.o \
	common/disc/sfdctee.o \
	common/disc/sfdcunion.o \
	common/disc/sfkeyprintf.o \
	common/disc/sfstrtmp.o \
	common/hash/hashalloc.o \
	common/hash/hashdump.o \
	common/hash/hashfree.o \
	common/hash/hashlast.o \
	common/hash/hashlook.o \
	common/hash/hashscan.o \
	common/hash/hashsize.o \
	common/hash/hashview.o \
	common/hash/hashwalk.o \
	common/hash/memhash.o \
	common/hash/memsum.o \
	common/hash/strhash.o \
	common/hash/strkey.o \
	common/hash/strsum.o \
	common/misc/astintercept.o \
	common/misc/debug.o \
	common/misc/cmdarg.o \
	common/misc/error.o \
	common/misc/errorf.o \
	common/misc/errormsg.o \
	common/misc/errorx.o \
	common/misc/fastfind.o \
	common/misc/fmtrec.o \
	common/misc/fs3d.o \
	common/misc/fts.o \
	common/misc/ftwalk.o \
	common/misc/ftwflags.o \
	common/misc/getcwd.o \
	common/misc/getenv.o \
	common/misc/glob.o \
	common/misc/magic.o \
	common/misc/mime.o \
	common/misc/mimetype.o \
	common/misc/optesc.o \
	common/misc/optget.o \
	common/misc/optjoin.o \
	common/misc/optctx.o \
	common/misc/procclose.o \
	common/misc/procfree.o \
	common/misc/procopen.o \
	common/misc/procrun.o \
	common/misc/recfmt.o \
	common/misc/reclen.o \
	common/misc/recstr.o \
	common/misc/setenviron.o \
	common/misc/sigcrit.o \
	common/misc/sigdata.o \
	common/misc/signal.o \
	common/misc/stack.o \
	common/misc/state.o \
	common/misc/stk.o \
	common/misc/systrace.o \
	common/misc/translate.o \
	common/misc/univdata.o \
	common/obsolete/spawn.o \
	common/path/pathaccess.o \
	common/path/pathbin.o \
	common/path/pathcanon.o \
	common/path/pathcat.o \
	common/path/pathcd.o \
	common/path/pathcheck.o \
	common/path/pathexists.o \
	common/path/pathfind.o \
	common/path/pathgetlink.o \
	common/path/pathkey.o \
	common/path/pathnative.o \
	common/path/pathpath.o \
	common/path/pathposix.o \
	common/path/pathprobe.o \
	common/path/pathprog.o \
	common/path/pathrepl.o \
	common/path/pathsetlink.o \
	common/path/pathshell.o \
	common/path/pathstat.o \
	common/path/pathtemp.o \
	common/path/pathtmp.o \
	common/port/astconf.o \
	common/port/astcopy.o \
	common/port/astdynamic.o \
	common/port/astlicense.o \
	common/port/astquery.o \
	common/port/aststatic.o \
	common/port/astwinsize.o \
	common/port/iblocks.o \
	common/port/lc.o \
	common/port/mc.o \
	common/port/mnt.o \
	common/port/touch.o \
	common/preroot/getpreroot.o \
	common/preroot/ispreroot.o \
	common/preroot/realopen.o \
	common/preroot/setpreroot.o \
	common/regex/regalloc.o \
	common/regex/regcache.o \
	common/regex/regclass.o \
	common/regex/regcoll.o \
	common/regex/regcomp.o \
	common/regex/regdecomp.o \
	common/regex/regerror.o \
	common/regex/regexec.o \
	common/regex/regfatal.o \
	common/regex/reginit.o \
	common/regex/regnexec.o \
	common/regex/regrecord.o \
	common/regex/regrexec.o \
	common/regex/regstat.o \
	common/regex/regsub.o \
	common/regex/regsubcomp.o \
	common/regex/regsubexec.o \
	common/sfio/_sfclrerr.o \
	common/sfio/_sfdlen.o \
	common/sfio/_sfeof.o \
	common/sfio/_sferror.o \
	common/sfio/_sffileno.o \
	common/sfio/_sfgetc.o \
	common/sfio/_sfgetl.o \
	common/sfio/_sfgetl2.o \
	common/sfio/_sfgetu.o \
	common/sfio/_sfgetu2.o \
	common/sfio/_sfllen.o \
	common/sfio/_sfopen.o \
	common/sfio/_sfputc.o \
	common/sfio/_sfputd.o \
	common/sfio/_sfputl.o \
	common/sfio/_sfputm.o \
	common/sfio/_sfputu.o \
	common/sfio/_sfslen.o \
	common/sfio/_sfstacked.o \
	common/sfio/_sfulen.o \
	common/sfio/_sfvalue.o \
	common/sfio/sfclose.o \
	common/sfio/sfclrlock.o \
	common/sfio/sfcvt.o \
	common/sfio/sfdisc.o \
	common/sfio/sfdlen.o \
	common/sfio/sfecvt.o \
	common/sfio/sfexcept.o \
	common/sfio/sfextern.o \
	common/sfio/sffcvt.o \
	common/sfio/sffilbuf.o \
	common/sfio/sfflsbuf.o \
	common/sfio/sfgetd.o \
	common/sfio/sfgetl.o \
	common/sfio/sfgetm.o \
	common/sfio/sfgetr.o \
	common/sfio/sfgetu.o \
	common/sfio/sfllen.o \
	common/sfio/sfmode.o \
	common/sfio/sfmove.o \
	common/sfio/sfmutex.o \
	common/sfio/sfnew.o \
	common/sfio/sfnotify.o \
	common/sfio/sfnputc.o \
	common/sfio/sfopen.o \
	common/sfio/sfpeek.o \
	common/sfio/sfpkrd.o \
	common/sfio/sfpoll.o \
	common/sfio/sfpool.o \
	common/sfio/sfpopen.o \
	common/sfio/sfprintf.o \
	common/sfio/sfprints.o \
	common/sfio/sfpurge.o \
	common/sfio/sfputd.o \
	common/sfio/sfputl.o \
	common/sfio/sfputm.o \
	common/sfio/sfputr.o \
	common/sfio/sfputu.o \
	common/sfio/sfraise.o \
	common/sfio/sfrd.o \
	common/sfio/sfread.o \
	common/sfio/sfreserve.o \
	common/sfio/sfresize.o \
	common/sfio/sfscanf.o \
	common/sfio/sfseek.o \
	common/sfio/sfset.o \
	common/sfio/sfsetbuf.o \
	common/sfio/sfsetfd.o \
	common/sfio/sfsize.o \
	common/sfio/sfsk.o \
	common/sfio/sfstack.o \
	common/sfio/sfstrtod.o \
	common/sfio/sfswap.o \
	common/sfio/sfsync.o \
	common/sfio/sftable.o \
	common/sfio/sftell.o \
	common/sfio/sftmp.o \
	common/sfio/sfungetc.o \
	common/sfio/sfvprintf.o \
	common/sfio/sfvscanf.o \
	common/sfio/sfwalk.o \
	common/sfio/sfwr.o \
	common/sfio/sfwrite.o \
	common/stdio/_doprnt.o \
	common/stdio/_doscan.o \
	common/stdio/_filbuf.o \
	common/stdio/_flsbuf.o \
	common/stdio/_stdfun.o \
	common/stdio/_stdopen.o \
	common/stdio/_stdprintf.o \
	common/stdio/_stdscanf.o \
	common/stdio/_stdsprnt.o \
	common/stdio/_stdvbuf.o \
	common/stdio/_stdvsnprnt.o \
	common/stdio/_stdvsprnt.o \
	common/stdio/_stdvsscn.o \
	common/stdio/asprintf.o \
	common/stdio/clearerr.o \
	common/stdio/fclose.o \
	common/stdio/fcloseall.o \
	common/stdio/fdopen.o \
	common/stdio/feof.o \
	common/stdio/ferror.o \
	common/stdio/fflush.o \
	common/stdio/fgetc.o \
	common/stdio/fgetpos.o \
	common/stdio/fgets.o \
	common/stdio/fgetwc.o \
	common/stdio/fgetws.o \
	common/stdio/fileno.o \
	common/stdio/flockfile.o \
	common/stdio/fmemopen.o \
	common/stdio/fopen.o \
	common/stdio/fprintf.o \
	common/stdio/fpurge.o \
	common/stdio/fputc.o \
	common/stdio/fputs.o \
	common/stdio/fputwc.o \
	common/stdio/fputws.o \
	common/stdio/funlockfile.o \
	common/stdio/fread.o \
	common/stdio/freopen.o \
	common/stdio/fscanf.o \
	common/stdio/fseek.o \
	common/stdio/fseeko.o \
	common/stdio/fsetpos.o \
	common/stdio/ftell.o \
	common/stdio/ftello.o \
	common/stdio/ftrylockfile.o \
	common/stdio/fwide.o \
	common/stdio/fwprintf.o \
	common/stdio/fwrite.o \
	common/stdio/fwscanf.o \
	common/stdio/getc.o \
	common/stdio/getchar.o \
	common/stdio/getdelim.o \
	common/stdio/getline.o \
	common/stdio/getw.o \
	common/stdio/getwc.o \
	common/stdio/getwchar.o \
	common/stdio/pclose.o \
	common/stdio/popen.o \
	common/stdio/printf.o \
	common/stdio/putc.o \
	common/stdio/putchar.o \
	common/stdio/puts.o \
	common/stdio/putw.o \
	common/stdio/putwc.o \
	common/stdio/putwchar.o \
	common/stdio/rewind.o \
	common/stdio/scanf.o \
	common/stdio/setbuf.o \
	common/stdio/setbuffer.o \
	common/stdio/setlinebuf.o \
	common/stdio/setvbuf.o \
	common/stdio/snprintf.o \
	common/stdio/sprintf.o \
	common/stdio/sscanf.o \
	common/stdio/stdio_c99.o \
	common/stdio/swprintf.o \
	common/stdio/swscanf.o \
	common/stdio/tmpfile.o \
	common/stdio/ungetc.o \
	common/stdio/ungetwc.o \
	common/stdio/vasprintf.o \
	common/stdio/vfprintf.o \
	common/stdio/vfscanf.o \
	common/stdio/vfwprintf.o \
	common/stdio/vfwscanf.o \
	common/stdio/vprintf.o \
	common/stdio/vscanf.o \
	common/stdio/vsnprintf.o \
	common/stdio/vsprintf.o \
	common/stdio/vsscanf.o \
	common/stdio/vswprintf.o \
	common/stdio/vswscanf.o \
	common/stdio/vwprintf.o \
	common/stdio/vwscanf.o \
	common/stdio/wprintf.o \
	common/stdio/wscanf.o \
	common/string/base64.o \
	common/string/ccmap.o \
	common/string/ccmapid.o \
	common/string/ccnative.o \
	common/string/chresc.o \
	common/string/chrtoi.o \
	common/string/fmtbase.o \
	common/string/fmtbuf.o \
	common/string/fmtclock.o \
	common/string/fmtdev.o \
	common/string/fmtelapsed.o \
	common/string/fmterror.o \
	common/string/fmtesc.o \
	common/string/fmtfmt.o \
	common/string/fmtfs.o \
	common/string/fmtgid.o \
	common/string/fmtident.o \
	common/string/fmtip4.o \
	common/string/fmtip6.o \
	common/string/fmtls.o \
	common/string/fmtmatch.o \
	common/string/fmtmode.o \
	common/string/fmtnum.o \
	common/string/fmtperm.o \
	common/string/fmtre.o \
	common/string/fmtscale.o \
	common/string/fmtsignal.o \
	common/string/fmttime.o \
	common/string/fmttmx.o \
	common/string/fmttv.o \
	common/string/fmtuid.o \
	common/string/fmtversion.o \
	common/string/memdup.o \
	common/string/modedata.o \
	common/string/modei.o \
	common/string/modex.o \
	common/string/stracmp.o \
	common/string/strcopy.o \
	common/string/strdup.o \
	common/string/strelapsed.o \
	common/string/strerror.o \
	common/string/stresc.o \
	common/string/streval.o \
	common/string/strexpr.o \
	common/string/strgid.o \
	common/string/strlcat.o \
	common/string/strlcpy.o \
	common/string/strlook.o \
	common/string/strmatch.o \
	common/string/strmode.o \
	common/string/strnacmp.o \
	common/string/strncopy.o \
	common/string/strnpcmp.o \
	common/string/strntod.o \
	common/string/strntol.o \
	common/string/strntold.o \
	common/string/strntoll.o \
	common/string/strnton.o \
	common/string/strntoul.o \
	common/string/strntonll.o \
	common/string/strntoull.o \
	common/string/strnvcmp.o \
	common/string/stropt.o \
	common/string/strpcmp.o \
	common/string/strperm.o \
	common/string/strpsearch.o \
	common/string/strsearch.o \
	common/string/strsort.o \
	common/string/strtape.o \
	common/string/strtoip4.o \
	common/string/strtoip6.o \
	common/string/strton.o \
	common/string/strtonll.o \
	common/string/struid.o \
	common/string/struniq.o \
	common/string/strvcmp.o \
	common/string/swapget.o \
	common/string/swapmem.o \
	common/string/swapop.o \
	common/string/swapput.o \
	common/string/tok.o \
	common/string/tokline.o \
	common/string/tokscan.o \
	common/tm/tmdata.o \
	common/tm/tmdate.o \
	common/tm/tmequiv.o \
	common/tm/tmfix.o \
	common/tm/tmfmt.o \
	common/tm/tmform.o \
	common/tm/tmgoff.o \
	common/tm/tminit.o \
	common/tm/tmleap.o \
	common/tm/tmlex.o \
	common/tm/tmlocale.o \
	common/tm/tmmake.o \
	common/tm/tmpoff.o \
	common/tm/tmscan.o \
	common/tm/tmsleep.o \
	common/tm/tmtime.o \
	common/tm/tmtype.o \
	common/tm/tmweek.o \
	common/tm/tmword.o \
	common/tm/tmxdate.o \
	common/tm/tmxduration.o \
	common/tm/tmxfmt.o \
	common/tm/tmxgettime.o \
	common/tm/tmxleap.o \
	common/tm/tmxmake.o \
	common/tm/tmxscan.o \
	common/tm/tmxsettime.o \
	common/tm/tmxsleep.o \
	common/tm/tmxtime.o \
	common/tm/tmxtouch.o \
	common/tm/tmzone.o \
	common/tm/tvcmp.o \
	common/tm/tvgettime.o \
	common/tm/tvsettime.o \
	common/tm/tvsleep.o \
	common/tm/tvtouch.o \
	common/uwin/a64l.o \
	common/uwin/acosh.o \
	common/uwin/asinh.o \
	common/uwin/atanh.o \
	common/uwin/cbrt.o \
	common/uwin/crypt.o \
	common/uwin/erf.o \
	common/uwin/err.o \
	common/uwin/exp.o \
	common/uwin/exp__E.o \
	common/uwin/expm1.o \
	common/uwin/gamma.o \
	common/uwin/getpass.o \
	common/uwin/lgamma.o \
	common/uwin/log.o \
	common/uwin/log1p.o \
	common/uwin/log__L.o \
	common/uwin/rand48.o \
	common/uwin/random.o \
	common/uwin/rcmd.o \
	common/uwin/rint.o \
	common/uwin/support.o \
	common/vec/vecargs.o \
	common/vec/vecfile.o \
	common/vec/vecfree.o \
	common/vec/vecload.o \
	common/vec/vecstring.o \
	common/vmalloc/malloc.o \
	common/vmalloc/vmbest.o \
	common/vmalloc/vmclear.o \
	common/vmalloc/vmclose.o \
	common/vmalloc/vmdcheap.o \
	common/vmalloc/vmdebug.o \
	common/vmalloc/vmdisc.o \
	common/vmalloc/vmexit.o \
	common/vmalloc/vmgetmem.o \
	common/vmalloc/vmlast.o \
	common/vmalloc/vmmopen.o \
	common/vmalloc/vmopen.o \
	common/vmalloc/vmpool.o \
	common/vmalloc/vmprivate.o \
	common/vmalloc/vmprofile.o \
	common/vmalloc/vmregion.o \
	common/vmalloc/vmsegment.o \
	common/vmalloc/vmset.o \
	common/vmalloc/vmstat.o \
	common/vmalloc/vmstrdup.o \
	common/vmalloc/vmtrace.o \
	common/vmalloc/vmwalk.o

# We are storing the object files into subdirs avoid the
# confusion with having 550+ object files in the toplevel pics/
# directory (this matches the way how the original AST build system
# deals with this "logistic" issue) - the rules below ensure that
# the destination directory is available.
OBJDIRS += \
	common/cdt \
	common/comp \
	common/dir \
	common/disc \
	common/hash \
	common/misc \
	common/obsolete \
	common/path \
	common/port \
	common/preroot \
	common/regex \
	common/sfio \
	common/stdio \
	common/string \
	common/tm \
	common/uwin \
	common/vec \
	common/vmalloc
PICSDIRS= $(OBJDIRS:%=pics/%)
mkpicdirs:
	@mkdir -p $(PICSDIRS)

# We need our own rules here since some source files come from
# the plaftorm-specific directories and the default rules do
# not cover this
pics/%.o: ../%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.astmsg

include ../../Makefile.lib

# mapfile-vers does not live with the sources in in common/ to make
# automated code updates easier.
MAPFILES=       ../mapfile-vers

# Set common AST build flags (e.g. C99/XPG6, needed to support the math stuff)
include ../../../Makefile.ast

# special rule because sources live both ../common (normal)
# and $(TRANSMACH) (generated)
SRCS=		$(OBJECTS:%.o=../%.c)

LIBS =		$(DYNLIB) $(LINTLIB)

LDLIBS += \
	-lsocket \
	-lm \
	-lc

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR =	../common

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
# Notes:
#   - "-D_BLD_DLL" comes from ${mam_cc_DLL} in Mamfile
#   - Be careful with "-D__OBSOLETE__=xxx". Make sure this is in sync with
#     upstream (see Mamfile) and do not change the |__OBSOLETE__| value
#     without examining the symbols that will be removed, and evaluating
#     whether that breaks compatibility with upstream binaries.
CPPFLAGS = \
	$(DTEXTDOM) $(DTS_ERRNO) \
	$(ASTPLATFORMCPPFLAGS) \
	-Isrc/lib/libast \
	-I$(SRCDIR) \
	-I$(SRCDIR)/comp \
	-I$(SRCDIR)/include \
	-I$(SRCDIR)/std \
	-I$(SRCDIR)/dir \
	-I$(SRCDIR)/port \
	-I$(SRCDIR)/sfio \
	-I$(SRCDIR)/astsa \
	-I$(SRCDIR)/misc \
	-I$(SRCDIR)/string \
	-Iinclude/ast \
	-I$(ROOT)/usr/include \
	'-DCONF_LIBSUFFIX=".so"' \
	'-DCONF_LIBPREFIX="lib"' \
	-DERROR_CATALOG=\""libast"\" \
	-D__OBSOLETE__=20100101 \
	-D_BLD_ast \
	-D_PACKAGE_ast \
	-D_BLD_DLL

CFLAGS += \
	$(ASTCFLAGS)
CFLAGS64 += \
	$(ASTCFLAGS64)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-clobbered
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-but-set-variable
CERRWARN += -_gcc=-Wno-unused-but-set-parameter
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-empty-body
CERRWARN += -_gcc=-Wno-type-limits
CERRWARN += -_gcc=-Wno-address

pics/$(MACH)/src/lib/libast/conftab.o \
pics/$(MACH64)/src/lib/libast/conftab.o	:= CERRWARN += -erroff=E_INIT_DOES_NOT_FIT
pics/common/comp/setlocale.o		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/common/comp/setlocale.o		:= CERRWARN += -erroff=E_INIT_DOES_NOT_FIT
pics/common/comp/setlocale.o		:= CERRWARN += -erroff=E_INIT_SIGN_EXTEND
pics/common/hash/hashlook.o		:= CERRWARN += -erroff=E_CONST_PROMOTED_UNSIGNED_LONG
pics/common/hash/memhash.o		:= CERRWARN += -erroff=E_CONST_PROMOTED_UNSIGNED_LONG
pics/common/hash/memsum.o		:= CERRWARN += -erroff=E_CONST_PROMOTED_UNSIGNED_LONG
pics/common/hash/strhash.o		:= CERRWARN += -erroff=E_CONST_PROMOTED_UNSIGNED_LONG
pics/common/hash/strsum.o		:= CERRWARN += -erroff=E_CONST_PROMOTED_UNSIGNED_LONG
pics/common/misc/recstr.o 		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/common/misc/translate.o 		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/common/path/pathkey.o		:= CERRWARN += -erroff=E_CONST_PROMOTED_UNSIGNED_LONG
pics/common/port/astconf.o		:= CERRWARN += -erroff=E_CONST_OBJ_SHOULD_HAVE_INITIZR
pics/common/stdio/fflush.o 		:= CERRWARN += -erroff=E_NO_IMPLICIT_DECL_ALLOWED
pics/common/stdio/getline.o 		:= CERRWARN += -erroff=E_NO_IMPLICIT_DECL_ALLOWED
pics/common/sfio/sfmove.o 		:= CERRWARN += -erroff=E_NO_IMPLICIT_DECL_ALLOWED
pics/common/sfio/sfrd.o 		:= CERRWARN += -erroff=E_NO_IMPLICIT_DECL_ALLOWED
pics/common/sfio/sfvscanf.o 		:= CERRWARN += -erroff=E_END_OF_LOOP_CODE_NOT_REACHED
pics/common/tm/tmxduration.o 		:= CERRWARN += -erroff=E_NO_IMPLICIT_DECL_ALLOWED

.KEEP_STATE:

all: mkpicdirs .WAIT $(LIBS)

#
# libast is not lint-clean yet; fake up a target.  (You can use
# "make lintcheck" to actually run lint; please send all lint fixes
# upstream (to AT&T) so the next update will pull them into ON.)
#
lint:
	@ print "usr/src/lib/libast is not lint-clean: skipping"

include ../../Makefile.targ
