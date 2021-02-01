:PACKAGE: ast

LICENSE = since=1997,author=gsf

CCFLAGS = $(CC.OPTIMIZE) $(CC.DLL)

dll 1.0 :LIBRARY: dlfcn.c dllopen.c dllfind.c dllplug.c dll_lib.c \
	dllnext.c dlllook.c dllscan.c dllcheck.c dllerror.c \
	-ldl -ldld

win32.i386-64 :NOOPTIMIZE: dllscan.c

$(INCLUDEDIR) :INSTALLPROTO: dlldefs.h

dlldefs.h :COPY: FEATURE/dll

:: RELEASE
