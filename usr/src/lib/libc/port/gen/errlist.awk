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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2024 Oxide Computer Company
#
# Create two files from a list of input strings;
# new_list.c contains an array of characters indexed into by perror and
# strerror and an array of strings for strerrorname_np;
# errlst.c contains an array of pointers to strings for compatibility
# with existing user programs that reference it directly;
# errlst.c references the strings in new_list.c indirectly using a library
# private symbol, __sys_errs[], in order to get relative relocations.
#
# Since the 64 bit ABI doesn't define the old symbols, the second file
# should be left out 64 bit libraries.
#
# WARNING!
#        Do NOT add entries to this list such that it grows the list
#        beyond the last entry:
#              151     Stale NFS file handle
#        Growing this list may damage programs because this array is
#        copied into a reserved array at runtime.  See bug 4097669.
#
#        If you need to add an entry please use one of the empty
#        slots.
#        The arrays _sys_errs[], accessible via perror(3C) and strerror(3C)
#        interfaces, and sys_errlist[] are created from this list.
#        It is the direct referencing of sys_errlist[] that is the problem.
#        Your code should only use perror() or strerror().


BEGIN	{
		FS = "\t"
		hi = 0

		newfile = "new_list.c"
		oldfile = "errlst.c"

		print "#pragma weak _sys_errlist = sys_errlist\n" >oldfile
		print "#include \"lint.h\"\n" >oldfile
		# We need to include the errors strings proper in the
		# C source for gettext; the macro C allows us to embed
		# them as comment.
		print "#define\tC(x)\n" >oldfile
		print "extern const char __sys_errs[];\n" >oldfile
		print "const char *sys_errlist[] = {" >oldfile

		print "#include \"lint.h\"" >newfile
		print "#include <sys/isa_defs.h>\n" >newfile
		print "#include <errno.h>\n" >newfile
		print "#pragma weak __sys_errs = _sys_errs\n" >newfile
	}

/^[0-9]+/ {
		if ($1 > hi)
			hi = $1
		aname[$1] = $2
		astr[$1] = $3
	}

END	{
		print "const int _sys_index[] =\n{" >newfile
		k = 0
		mx = 151	# max number of entries for sys_errlist[]
		if (hi > mx)
		{
			printf "awk: ERROR! sys_errlist[] > %d entries\n", mx
			printf "Please read comments in"
			printf " usr/src/lib/libc/port/gen/errlist\n"
			exit 1
		}
		for (j = 0; j <= hi; ++j)
		{
			if (astr[j] == "")
				astr[j] = sprintf("Error %d", j)
			printf "\t%d,\n", k >newfile
			printf "\t&__sys_errs[%d], C(\"%s\")\n", k, astr[j] \
				>oldfile
			k += length(astr[j]) + 1
		}
		print "};\n" >newfile

		print "/* This is one long string */" >newfile
		printf "const char _sys_errs[%d] =\n", k >newfile
		for (j = 0; j <= hi; ++j)
		{
			printf "\t\"%s\\0\"\n", astr[j] >newfile
		}
		print ";\n" >newfile
		print "};\n" >oldfile

		#
		# This stanza is used to generate the array of names for mapping
		# an errno to its constant (e.g. "ENOENT").
		#
		printf "const char *_sys_err_names[%d] = {\n", hi + 1 >newfile
		printf "\t[0] = \"0\",\n" >newfile
		for (j = 1; j <= hi; ++j)
		{
			if (aname[j] != "" && aname[j] != "SKIP")
				printf "\t[%s] = \"%s\",\n", aname[j], aname[j] \
				>newfile
		}
		print "};\n" > newfile

		print "const int _sys_num_err = " hi + 1 ";\n" >newfile
		print "#undef sys_nerr" >newfile
		print "#ifndef _LP64" >newfile
		print "#pragma weak _sys_nerr = _sys_num_err" >newfile
		print "#pragma weak sys_nerr = _sys_num_err" >newfile
		print "#endif /* _LP64 */" >newfile
	}
