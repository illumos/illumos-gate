#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

# Copyright 2011, Richard Lowe

include ../../Makefile.master

MANSECT = 	3secdb

MANFILES = 	getauthattr.3secdb		\
		getexecattr.3secdb		\
		getprofattr.3secdb		\
		getuserattr.3secdb		\
		kva_match.3secdb

MANSOFILES =	chkauthattr.3secdb	\
		endauthattr.3secdb	\
		endexecattr.3secdb	\
		endprofattr.3secdb	\
		enduserattr.3secdb	\
		fgetuserattr.3secdb	\
		free_authattr.3secdb	\
		free_execattr.3secdb	\
		free_profattr.3secdb	\
		free_proflist.3secdb	\
		free_userattr.3secdb	\
		getauthnam.3secdb	\
		getexecprof.3secdb	\
		getexecuser.3secdb	\
		getproflist.3secdb	\
		getprofnam.3secdb	\
		getusernam.3secdb	\
		getuseruid.3secdb	\
		match_execattr.3secdb	\
		setauthattr.3secdb	\
		setexecattr.3secdb	\
		setprofattr.3secdb	\
		setuserattr.3secdb

MANFILES +=	$(MANSOFILES)

chkauthattr.3secdb	:= SOSRC = man3secdb/getauthattr.3secdb
endauthattr.3secdb	:= SOSRC = man3secdb/getauthattr.3secdb
free_authattr.3secdb	:= SOSRC = man3secdb/getauthattr.3secdb
getauthnam.3secdb	:= SOSRC = man3secdb/getauthattr.3secdb
setauthattr.3secdb	:= SOSRC = man3secdb/getauthattr.3secdb

endexecattr.3secdb	:= SOSRC = man3secdb/getexecattr.3secdb
free_execattr.3secdb	:= SOSRC = man3secdb/getexecattr.3secdb
getexecprof.3secdb	:= SOSRC = man3secdb/getexecattr.3secdb
getexecuser.3secdb	:= SOSRC = man3secdb/getexecattr.3secdb
match_execattr.3secdb	:= SOSRC = man3secdb/getexecattr.3secdb
setexecattr.3secdb	:= SOSRC = man3secdb/getexecattr.3secdb

endprofattr.3secdb	:= SOSRC = man3secdb/getprofattr.3secdb
free_profattr.3secdb	:= SOSRC = man3secdb/getprofattr.3secdb
free_proflist.3secdb	:= SOSRC = man3secdb/getprofattr.3secdb
getproflist.3secdb	:= SOSRC = man3secdb/getprofattr.3secdb
getprofnam.3secdb	:= SOSRC = man3secdb/getprofattr.3secdb
setprofattr.3secdb	:= SOSRC = man3secdb/getprofattr.3secdb

enduserattr.3secdb	:= SOSRC = man3secdb/getuserattr.3secdb
fgetuserattr.3secdb	:= SOSRC = man3secdb/getuserattr.3secdb
free_userattr.3secdb	:= SOSRC = man3secdb/getuserattr.3secdb
getusernam.3secdb	:= SOSRC = man3secdb/getuserattr.3secdb
getuseruid.3secdb	:= SOSRC = man3secdb/getuserattr.3secdb
setuserattr.3secdb	:= SOSRC = man3secdb/getuserattr.3secdb

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)


