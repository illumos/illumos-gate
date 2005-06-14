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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# This file generates three different C files:
#
#	<sys/priv_const.h>
#		An implementation private set of manifest integer constant
#		for privileges and privilege sets and manifest constants for
#		set size, number of sets, number of privileges
#
#	os/priv_const.c
#		A C source file containing the set names, privilege names
#		arrays for the name <-> number mappings
#
#	<sys/priv_names.h>
#		A public header file containing the PRIV_* defines
#		that map to strings; these are for convenience.
#		(it's easy to misspell a string, harder to misspell a
#		manifest constant)
#
#	/etc/security/priv_names
#		A privilege name to explanation mapping.
#
#
# The files are output on the awk variable privhfile, pubhfile, cfile,
# and pnamesfile respectively
#
# The input file should contain a standard Sun comment and ident string
# which is copied verbatim and lines of
#
#	[keyword] privilege	PRIV_<privilege>
#	set			PRIV_<set>
#
# Which are converted to privileges and privilege sets
#


BEGIN	{
	# Number of privileges read
	npriv = 0

	# Number of privilege sets
	nset = 0

	# Length of all strings concatenated, including \0
	privbytes = 0
	setbytes = 0

	# Number of reserved privilege slots
	slack = 10

	privhcmt = \
	" * Privilege constant definitions; these constants are subject to\n" \
	" * change, including renumbering, without notice and should not be\n" \
	" * used in any code.  Privilege names must be used instead.\n" \
	" * Privileges and privilege sets must not be stored in binary\n" \
	" * form; privileges and privileges sets must be converted to\n" \
	" * textual representation before being committed to persistent store."

	ccmt = \
	" * Privilege name table and size definitions."

	pubhcmt = \
	" * Privilege constant definitions.  Privileges and privilege sets\n" \
	" * are only known by name and should be mapped at runtime."

	pnamescmt = \
	"#\n" \
	"# Privilege name explanation file\n" \
	"# The format of entries is a privilege name starting at the\n" \
	"# beginning of a line directly folowed by a new line followed\n" \
	"# by several lines of texts starting with white space terminated\n" \
	"# by a line with a single newline or not starting with white space\n" \
	"#\n"
}

#
# Privilege strings are represented as lower case strings;
# PRIV_ is stripped from the strings.
#
/^([A-Za-z]* )?privilege / {
	if (NF == 3) {
		key = toupper($1)
		priv = toupper($3)
		if (set[key] != "")
			set[key] = set[key] ";"
		set[key] = set[key] "\\\n\t\tPRIV_ASSERT((set), " priv ")"
	} else {
		priv = toupper($2);
	}
	privs[npriv] = tolower(substr(priv, 6));
	inset = 0
	inpriv = 1

	privind[npriv] = privbytes;

	tabs = (32 - length(priv) - 1)/8
	# length + \0 - PRIV_
	privbytes += length(priv) - 4
	pdef[npriv] = "#define\t" priv substr("\t\t\t\t\t", 1, tabs)

	npriv++
	next
}

#
# Set strings are represented as strings with an initial cap;
# PRIV_ is stripped from the strings.
#
/^set / {
	$2 = toupper($2)
	sets[nset] = toupper(substr($2, 6, 1)) tolower(substr($2, 7));
	inset = 1
	inpriv = 0

	setind[nset] = setbytes

	# length + \0 - PRIV_
	setbytes += length($2) - 4
	tabs = (32 - length($2) - 1)/8
	sdef[nset] = "#define\t" $2 substr("\t\t\t\t\t", 1, tabs)

	nset++
	next
}

/INSERT COMMENT/ {
	acmt = " *\n * THIS FILE WAS GENERATED; DO NOT EDIT"
	if (cfile) {
		print ccmt > cfile
		print acmt > cfile
	}
	if (privhfile) {
		print privhcmt > privhfile
		print acmt > privhfile
	}
	if (pubhfile) {
		print pubhcmt > pubhfile
		print acmt > pubhfile
	}
	next
}
/^#pragma/ {
	pragma = $0;
	if (pnamesfile) {
		print "#" substr($0, 9) > pnamesfile
	}
	next;
}

/^#/ && ! /^#pragma/{
	# Comments, ignore
	next
}

{
	#
	# Comments describing privileges and sets follow the definitions.
	#
	if (inset || inpriv) {
		sub("^[ 	]*", "")
		sub("[ 	]*$", "")
		if (/^$/) next;
	}
	if (inset) {
		setcmt[nset - 1] = setcmt[nset - 1] " * " $0 "\n"
		next
	} else if (inpriv) {
		sub("^[ 	]*", "")
		privcmt[npriv - 1] = privcmt[npriv - 1] " * " $0 "\n"
		privncmt[npriv - 1] = privncmt[npriv - 1] "\t" $0 "\n"
		next
	}

	if (cfile)
		print > cfile
	if (privhfile)
		print > privhfile
	if (pubhfile)
		print > pubhfile
	if (pnamesfile) {
		sub("^/\\*", "#")
		sub("^ \\*/", "")
		sub("^ \\*", "#")
		if (/^$/) next;
		print > pnamesfile
	}
}

END	{

	if (!pubhfile && !privhfile && !cfile && !pnamesfile) {
		print "Output file parameter not set" > "/dev/stderr"
		exit 1
	}

	setsize = int((npriv + slack)/(8 * 4)) + 1
	maxnpriv = setsize * 8 * 4
	# Assume allocated privileges are on average "NSDQ" bytes larger.
	maxprivbytes = int((privbytes / npriv + 5.5)) * (maxnpriv - npriv)
	maxprivbytes += privbytes

	if (cfile) {
		print "\n" > cfile
		print pragma "\n"> cfile
		print "#include <sys/types.h>" > cfile
		print "#include <sys/priv_const.h>" > cfile
		print "#include <sys/priv_impl.h>" > cfile
		print "#include <sys/priv.h>" > cfile
		print "#include <sys/sysmacros.h>" > cfile
		print "\n" > cfile
		#
		# Create the entire priv info structure here.
		# When adding privileges, the kernel needs to update
		# too many fields as the number of privileges is kept in
		# many places.
		#
		print \
		    "static struct _info {\n" \
		    "	priv_impl_info_t	impl_info;\n" \
		    "	priv_info_t		settype;\n" \
		    "	int			nsets;\n" \
		    "	const char		sets[" setbytes "];\n" \
		    "	priv_info_t		privtype;\n" \
		    "	int			nprivs;\n" \
		    "	char			privs[" maxprivbytes "];\n" \
		    "	priv_info_t		sysset;\n" \
		    "	priv_set_t		basicset;\n" \
		    "} info = {\n" \
		    "	{ sizeof (priv_impl_info_t), 0, PRIV_NSET, " \
			"PRIV_SETSIZE, " npriv ",\n" \
			"\t\tsizeof (priv_info_uint_t),\n" \
			"\t\tsizeof (info) - sizeof (info.impl_info)},\n" \
		    "	{ PRIV_INFO_SETNAMES,\n" \
		    "	    offsetof(struct _info, privtype) - " \
		    "offsetof(struct _info, settype)},\n\tPRIV_NSET," > cfile

		sep = "\t\""
		len = 9;
		for (i = 0; i < nset; i++) {
			if (len + length(sets[i]) > 80) {
				sep = "\\0\"\n\t\""
				len = 9
			}
			printf sep sets[i]  > cfile
			len += length(sets[i]) + length(sep);
			sep = "\\0"
		}
		print "\\0\"," > cfile

		print "\t{ PRIV_INFO_PRIVNAMES,\n\t    " \
			"offsetof(struct _info, sysset) - " \
			"offsetof(struct _info, privtype)},\n\t" npriv "," \
			> cfile

		sep = "\t\""
		len = 9;
		for (i = 0; i < npriv; i++) {
			if (len + length(privs[i]) > 80) {
				sep = "\\0\"\n\t\""
				len = 9
			}
			printf sep privs[i]  > cfile
			len += length(privs[i]) + length(sep);
			sep = "\\0"
		}
		print "\\0\"," > cfile

		print "\t{ PRIV_INFO_BASICPRIVS, sizeof (info) - " \
			"offsetof(struct _info, sysset)},"  > cfile

		print "};\n" > cfile

		print "\nconst char *priv_names[" maxnpriv "] =\n{" > cfile
		for (i = 0; i < npriv; i++)
			print "\t&info.privs[" privind[i] "]," > cfile

		print "};\n" > cfile

		print "\nconst char *priv_setnames[" nset "] =\n{" > cfile
		for (i = 0; i < nset; i++)
			print "\t&info.sets[" setind[i] "]," > cfile

		print "};\n" > cfile

		print "int nprivs = " npriv ";" > cfile
		print "int privbytes = " privbytes ";" > cfile
		print "int maxprivbytes = " maxprivbytes ";" > cfile
		print "size_t privinfosize = sizeof (info);" > cfile
		print "char *priv_str = info.privs;" > cfile
		print "priv_set_t *priv_basic = &info.basicset;" > cfile
		print "priv_impl_info_t *priv_info = &info.impl_info;" > cfile
		print "priv_info_names_t *priv_ninfo = " \
			"(priv_info_names_t *)&info.privtype;" > cfile
		close(cfile)
	}

	# Kernel private
	if (privhfile) {
		print "#ifndef _SYS_PRIV_CONST_H" > privhfile
		print "#define\t_SYS_PRIV_CONST_H\n" > privhfile
		print pragma "\n"> privhfile
		print "\n#include <sys/types.h>\n\n" > privhfile
		print "#ifdef __cplusplus\nextern \"C\" {\n#endif\n" > privhfile

		print "#if defined(_KERNEL) || defined(_KMEMUSER)" > privhfile
		print "#define\tPRIV_NSET\t\t\t  " nset > privhfile
		print "#define\tPRIV_SETSIZE\t\t\t  " setsize > privhfile
		print "#endif\n\n#ifdef _KERNEL" > privhfile
		print "#define\t__PRIV_CONST_IMPL\n" > privhfile
		print "extern const char *priv_names[];" > privhfile
		print "extern const char *priv_setnames[];" > privhfile

		print "extern int nprivs;" > privhfile
		print "extern int privbytes;" > privhfile
		print "extern int maxprivbytes;" > privhfile
		print "extern size_t privinfosize;" > privhfile
		print "extern char *priv_str;" > privhfile
		print "extern struct priv_set *priv_basic;" > privhfile
		print "extern struct priv_impl_info *priv_info;" > privhfile
		print "extern struct priv_info_names *priv_ninfo;" > privhfile

		print "\n/* Privileges */" > privhfile
		 
		for (i = 0; i < npriv; i++)
			print pdef[i] sprintf("%3d", i) > privhfile

		print "\n/* Privilege sets */" > privhfile
		for (i = 0; i < nset; i++)
			print sdef[i] sprintf("%3d", i) > privhfile

		print "\n#define\tMAX_PRIVILEGE\t\t\t "  setsize * 32 \
			> privhfile

		# Special privilege categories.
		for (s in set)
			print "\n#define\tPRIV_" s "_ASSERT(set)" set[s] \
				> privhfile

		print "\n#endif /* _KERNEL */" > privhfile
		print "\n#ifdef __cplusplus\n}\n#endif" > privhfile
		print "\n#endif /* _SYS_PRIV_CONST_H */" > privhfile
		close(privhfile)
	}

	if (pubhfile) {
		cast="((const char *)"
		print "#ifndef _SYS_PRIV_NAMES_H" > pubhfile
		print "#define\t_SYS_PRIV_NAMES_H\n" > pubhfile

		print pragma "\n" > pubhfile
		print "#ifdef __cplusplus\nextern \"C\" {\n#endif\n" > pubhfile

		print "#ifndef __PRIV_CONST_IMPL" > pubhfile
		print "/*\n * Privilege names\n */" > pubhfile
		for (i = 0; i < npriv; i++) {
			print "/*\n" privcmt[i] " */" > pubhfile
			print pdef[i] cast "\"" privs[i] "\")\n" > pubhfile
		}

		print "" > pubhfile

		print "/*\n * Privilege set names\n */" > pubhfile
		for (i = 0; i < nset; i++) {
			print "/*\n" setcmt[i] " */" > pubhfile
			print sdef[i] cast "\"" sets[i] "\")\n" > pubhfile
		}

		print "\n#endif /* __PRIV_CONST_IMPL */" > pubhfile
		print "\n#ifdef __cplusplus\n}\n#endif" > pubhfile
		print "\n#endif /* _SYS_PRIV_NAMES_H */" > pubhfile
		close(pubhfile)
	}

	if (pnamesfile) {
		print pnamescmt > pnamesfile
		for (i = 0; i < npriv; i++) {
			print privs[i] > pnamesfile
			print privncmt[i] > pnamesfile
		}
	}

}
