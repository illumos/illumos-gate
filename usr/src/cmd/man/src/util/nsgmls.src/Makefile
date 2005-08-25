# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#
# Copyright 1994, 1995 James Clark
#

#ident	"%Z%%M%	%I%	%E% SMI"

include ../../../../Makefile.cmd
prefix=$(ROOTLIB)
exec_prefix=$(prefix)
# Where to install the binaries
bindir=$(exec_prefix)/sgml
# Extension for man pages.
man1ext=1
# Directory for man pages
man1dir=$(prefix)/man/man$(man1ext)
INSTALL=cp
# You might want to change this to uncomment this on BSD systems
#INSTALL=install

# If you use gcc, then you must have at least version 2.6.1 and
# you must use -fno-implicit-templates
# and -O (or any optimization level >= 1).
# c++ is a front-end for gcc which takes care of linking with -lstdc++
#CXX=c++ -fno-implicit-templates -O2
#CXX=$(CCC) -O
WARN=-Wall -Wno-reorder -Wwrite-strings -Wpointer-arith -Wnested-externs -Woverloaded-virtual -Wbad-function-cast
# Executables will be *very* large if you use -g.
DEBUG=
# Add -DSP_HAVE_BOOL if you have the bool type.
# Add -DSP_ANSI_CLASS_INST for ANSI style explicit class template instantiation.
# Add -DSP_MULTI_BYTE for multi-byte support.
# Add -DSP_HAVE_LOCALE if you have setlocale().
# Add -DSP_HAVE_GETTEXT if you gettext() and friends (eg Solaris 2.3).
# Add -DSP_HAVE_SOCKET if you have sockets and you want support for HTTP
# Add -DSGML_CATALOG_FILES_DEFAULT=\"/usr/local/lib/sgml/catalog\"
#   (for example) to change the value used if the SGML_CATALOG_FILES
#   environment variable is unset.  SP now automatically searches for a file
#   called "catalog" in the same directory as the document entity.
XDEFINES=-DSP_MULTI_BYTE -DSP_HAVE_LOCALE -DSP_HAVE_GETTEXT -DSP_HAVE_SOCKET -DSGML_CATALOG_FILES_DEFAULT=\"/usr/share/lib/sgml/locale/C/dtds/catalog\"
DEFINES=$(XDEFINES) 
#CXXFLAGS=-ansi $(DEBUG) $(WARN)
CXXFLAGS=
# Flag to pass to CXX to make it output list of dependencies as a Makefile.
LDFLAGS += -norunpath -nolib
OPT=
CFLAGS += $(OPT) $(DEBUG) 
CCFLAGS += -noex
# Missing library functions
# Uncomment these if your C++ system doesn't provide them.
LIBOBJS=#strerror.o memmove.o
# iostreams are required
# If you defined SP_HAVE_SOCKET, add any libraries that are needed for sockets
#-lsocket -lnsl needed on Solaris 2.x
# -lnsl on SunOS 4.1.3
XLIBS=-lsocket -lnsl
# -L/usr/local/lib may be needed on the RS/6000
LIBS += $(ENVLDLIBS1) $(ENVLDLIBS2) $(XLIBS) $(CCNEEDED) -lc
# If you're building in another directory, copy or link this Makefile
# to the build directory, and set srcdir to point to the source directory.
srcdir=.
AR=ar
RANLIB=:
# Uncomment this for SunOS 4.1.3 or FreeBSD
# (and probably other BSD flavor systems as well)
#RANLIB=ranlib
M4=m4
# perl is needed if you change or add messages
PERL=perl
# Suffix for executables.
EXE=
# Uncomment this for OS/2.
#EXE=.exe

LIBDIRS=lib $(XLIBDIRS)
PROGDIRS=nsgmls $(XPROGDIRS)
dodirs=$(LIBDIRS) $(PROGDIRS)
PURIFYFLAGS=
PURIFY=purify $(PURIFYFLAGS) -g++=yes -collector=`dirname \`gcc -print-libgcc-file-name\``/ld

MDEFINES='CXX=$(CXX)' 'CC=$(CC)' 'LIBOBJS=$(LIBOBJS)' 'CXXFLAGS=$(CXXFLAGS)' \
 'CCFLAGS=$(CCFLAGS)' \
 'CFLAGS=$(CFLAGS)' 'LDFLAGS=$(LDFLAGS)' 'DEFINES=$(DEFINES)' \
 'srcdir=$(srcdir)' 'AR=$(AR)' 'RANLIB=$(RANLIB)' \
 'M4=$(M4)' 'PERL=$(PERL)' 'LIBS=$(LIBS)' 'PURIFY=$(PURIFY)' \
 'PIC_FLAG=$(PIC_FLAG)' 'XPROGDIRS=$(XPROGDIRS)' 'XLIBDIRS=$(XLIBDIRS)' \
 'libMakefile=$(libMakefile)' 'EXE=$(EXE)' 'bindir=$(bindir)' \
 'man1dir=$(man1dir)' 'man1ext=$(man1ext)' 'INSTALL=$(INSTALL)'


# Automatic template instantiation can cause compilers to generate
# various extra files; the clean target won't delete these.
TARGETS=all install depend gen clean clobber
libMakefile=Makefile.lib
do=all

$(TARGETS): FORCE
	@$(MAKE) -f $(srcdir)/Makefile $(MDEFINES) do=$@ $(dodirs)


$(LIBDIRS): FORCE
	@if test $(srcdir) = .; \
	then srcdir=.; \
	else srcdir=`cd $(srcdir); pwd`/$@; \
	fi; \
	test -d $@ || mkdir $@; \
	cd $@; \
	test -f $$srcdir/Makefile.dep || touch $$srcdir/Makefile.dep; \
	$(MAKE) $(MDEFINES) srcdir=$$srcdir VPATH=$$srcdir \
		-f $$srcdir/../Makefile.comm -f $$srcdir/Makefile.sub \
	        -f $$srcdir/../$(libMakefile) -f $$srcdir/Makefile.dep $(do)

$(PROGDIRS): FORCE
	@if test $(srcdir) = .; \
	then srcdir=.; \
	else srcdir=`cd $(srcdir); pwd`/$@; \
	fi; \
	test -d $@ || mkdir $@; \
	cd $@; \
	test -f $$srcdir/Makefile.dep || touch $$srcdir/Makefile.dep; \
	$(MAKE) $(MDEFINES) srcdir=$$srcdir VPATH=$$srcdir \
		-f $$srcdir/../Makefile.comm -f $$srcdir/Makefile.sub \
	        -f $$srcdir/../Makefile.prog -f $$srcdir/Makefile.dep $(do)

$(PROGDIRS): lib

# GNU tar
TAR=tar

dist: FORCE
	#cd test; ./CLEAN
	#version=`cat VERSION`; \
	#rm -f sp-$$version; \
	#ln -s `pwd` sp-$$version; \
	#$(TAR) -c -f sp-$$version.tar.gz -h -z \
	  #--exclude sp-$$version/test/cap \
	  #--exclude sp-$$version/test/out \
	  #--exclude sp-$$version/test/err \
	  #`sed -e "s|.*|sp-$$version/&|" FILES`; \
	#rm -f sp-$$version

#check: FORCE
	#NSGMLS=`pwd`/nsgmls/nsgmls; export NSGMLS; cd $(srcdir); ./dotest

FORCE:
