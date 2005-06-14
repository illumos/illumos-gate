#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

LIBRARY= digestmd5.a
VERS= .1

PLUG_OBJS=	digestmd5.o	digestmd5_init.o

PLUG_LIBS=	-lpkcs11
ENC_FLAGS=	-DUSE_UEF_SERVER=1 -DUSE_UEF_CLIENT=1 -DUSE_UEF=1

# include common definitions
include ../../Makefile.com
