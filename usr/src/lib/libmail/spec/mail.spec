#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#pragma	ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libmail/spec/mail.spec

function	maillock
include		<maillock.h>
declaration	int maillock(char *user, int retrycnt)
version		SUNW_1.1
end		

function	mailunlock
include		<maillock.h>
declaration	void mailunlock(void)
version		SUNW_1.1
end		

function	touchlock
include		<maillock.h>
declaration	void touchlock(void)
version		SUNW_1.1
end		

function	abspath
include		<libmail.h>
declaration	string *abspath(char *path, char *dot, string *to)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	casncmp
include		<libmail.h>
declaration	int casncmp(char *s1, char *s2, ssize_t n)
version		SUNWprivate_1.1
end		

function	copystream
include		<libmail.h>
declaration	int copystream(FILE *infp, FILE *outfp)
version		SUNWprivate_1.1
end		

function	delempty
include		<libmail.h>
declaration	int delempty(mode_t m, char *mailname)
version		SUNWprivate_1.1
end		

function	maildomain
include		<libmail.h>
declaration	char *maildomain(void)
version		SUNWprivate_1.1
end		

function	notify
include		<libmail.h>
declaration	void notify(char *user, char *msg, int check_mesg_y, char *etcdir)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	pclosevp
include		<libmail.h>
declaration	int pclosevp(FILE *fp)
version		SUNWprivate_1.1
end		

function	popenvp
include		<libmail.h>
declaration	FILE *popenvp(char *file, char **argv, char *mode, int resetid)
version		SUNWprivate_1.1
end		

function	setup_exec
include		<libmail.h>
declaration	char **setup_exec(char *s)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	skipspace
include		<libmail.h>
declaration	char *skipspace(char *p)
version		SUNWprivate_1.1
end		

function	substr
include		<libmail.h>
declaration	int substr(char *string1, char *string2)
version		SUNWprivate_1.1
end		

function	strmove
include		<libmail.h>
declaration	void strmove(char *from, char *to)
version		SUNWprivate_1.1
end		

function	systemvp
include		<libmail.h>
declaration	pid_t systemvp(char *file, char **argv, int resetid)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	trimnl
include		<libmail.h>
declaration	void trimnl(char *s)
version		SUNWprivate_1.1
end		

function	Xgetenv
include		<libmail.h>
declaration	char *Xgetenv(char *env)
version		SUNWprivate_1.1
end		

function	xgetenv
include		<libmail.h>
declaration	char *xgetenv(char *env)
version		SUNWprivate_1.1
end		

function	xsetenv
include		<libmail.h>
declaration	int xsetenv(char *file)
version		SUNWprivate_1.1
end		

function	s_append
include		<s_string.h>
declaration	string *s_append(string *to, char *from)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_array
include		<s_string.h>
declaration	string *s_array(char *, size_t len)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_copy
include		<s_string.h>
declaration	string *s_copy(char *)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_free
include		<s_string.h>
declaration	void s_free(string*)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_grow
include		<s_string.h>
declaration	int s_grow(string *sp, int c)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_new
include		<s_string.h>
declaration	string *s_new(void)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_parse
include		<s_string.h>
declaration	string *s_parse(string *from, string *to)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_read_line
include		<s_string.h>
declaration	char *s_read_line(FILE *fp, string *to)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_read_to_eof
include		<s_string.h>
declaration	size_t s_read_to_eof(FILE *fp, string *to)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_seq_read
include		<s_string.h>
declaration	string *s_seq_read(FILE *fp, string *to, int lineortoken)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_skipwhite
include		<s_string.h>
declaration	void s_skipwhite(string *from)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_tok
include		<s_string.h>
declaration	string *s_tok(string*, char*)
arch		sparc i386
version		SUNWprivate_1.1
end		

function	s_tolower
include		<s_string.h>
declaration	void s_tolower(string*)
arch		sparc i386
version		SUNWprivate_1.1
end		
