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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

include $(SRC)/Makefile.master
include ../../Makefile.tools

PYSRCS = \
	__init__.py	\
	cdm.py

#
# We deliver .pyc files specific to the python version, with the
# exception of cdm.pyc, which we don't deliver at all.
#
# An exception to this is cdm.py, which is typically loaded using an
# extension path in an .hgrc.  This path might refer to a Python
# version that's different from the one Mercurial is using.  If we
# delivered a cdm.pyc, differing Pythons running Mercurial could cause
# it to be overwritten, causing packaging noise.  Logic within cdm.py
# causes modules loaded from there to be those built by the correct
# version of Python.
# 
PYSRC2 =	$(PYSRCS:cdm.py=)
PYOBJS =	$(PYSRC2:%.py=%.pyc)
PYTOPDIR =	$(ROOTONBLDLIB)
PYMODDIR =	onbld/hgext

include ../../Makefile.python

all: $(PYVERSOBJS)

install: all $(ROOTPYFILES)

clean:

clobber: clean pyclobber
