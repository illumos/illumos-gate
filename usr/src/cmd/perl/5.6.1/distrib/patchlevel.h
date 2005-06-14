#ifndef __PATCHLEVEL_H_INCLUDED__

/* do not adjust the whitespace! Configure expects the numbers to be
 * exactly on the third column */

#define PERL_REVISION	5		/* age */
#define PERL_VERSION	6		/* epoch */
#define PERL_SUBVERSION	1		/* generation */

/* The following numbers describe the earliest compatible version of
   Perl ("compatibility" here being defined as sufficient binary/API
   compatibility to run XS code built with the older version).
   Normally this should not change across maintenance releases.

   Note that this only refers to an out-of-the-box build.  Many non-default
   options such as usemultiplicity tend to break binary compatibility
   more often.

   This is used by Configure et al to figure out 
   PERL_INC_VERSION_LIST, which lists version libraries
   to include in @INC.  See INSTALL for how this works.
*/
#define PERL_API_REVISION	5	/* Adjust manually as needed.  */
#define PERL_API_VERSION	5	/* Adjust manually as needed.  */
#define PERL_API_SUBVERSION	0	/* Adjust manually as needed.  */
/*
   XXX Note:  The selection of non-default Configure options, such
   as -Duselonglong may invalidate these settings.  Currently, Configure
   does not adequately test for this.   A.D.  Jan 13, 2000
*/

#define __PATCHLEVEL_H_INCLUDED__
#endif

/*
	local_patches -- list of locally applied less-than-subversion patches.
	If you're distributing such a patch, please give it a name and a
	one-line description, placed just before the last NULL in the array
	below.  If your patch fixes a bug in the perlbug database, please
	mention the bugid.  If your patch *IS* dependent on a prior patch,
	please place your applied patch line after its dependencies. This
	will help tracking of patch dependencies.

	Please edit the hunk of diff which adds your patch to this list,
	to remove context lines which would give patch problems.  For instance,
	if the original context diff is
	   *** patchlevel.h.orig	<date here>
	   --- patchlevel.h	<date here>
	   *** 38,43 ***
	   --- 38,44 ---
	     	,"FOO1235 - some patch"
	     	,"BAR3141 - another patch"
	     	,"BAZ2718 - and another patch"
	   + 	,"MINE001 - my new patch"
	     	,NULL
	     };
	
	please change it to 
	   *** patchlevel.h.orig	<date here>
	   --- patchlevel.h	<date here>
	   *** 41,43 ***
	   --- 41,44 ---
	   + 	,"MINE001 - my new patch"
	     };
	
	(Note changes to line numbers as well as removal of context lines.)
	This will prevent patch from choking if someone has previously
	applied different patches than you.
 */
#if !defined(PERL_PATCHLEVEL_H_IMPLICIT) && !defined(LOCAL_PATCH_COUNT)
static	char	*local_patches[] = {
	NULL,
	" 9676 Port the OpenBSD glob() security patch",
	" 9678 Addendum to #9676: some missing changes from OpenBSD glob.c",
	" 9679 Up $File::Glob::VERSION, add OpenBSD glob version note",
	" 9693 $VERSION and Version() on same line provokes CPAN.pm warning",
	" 9706 #7210 broke .packlist generation",
	" 9707 ExtUtils::Installed doesn't quote regex metacharacters in paths",
	" 9775 Typo in utf8.h",
	" 9950 Revert integration of #8254,#8255 in #8620 (causes coredump)",
	"10021 Insecure regexes",
	"10091 $ref1 == $ref2 behaves unpredictably if not NV_PRESERVES_UV",
	"10093 Incorrect line numbers in AutoSplit",
	"10100 [20010514.027] PL_last_in_gv may not be GV if stale filehandle",
	"10145 [20010515.004] Segfaults from premature GC",
	"10203 Don't think about UTF8",
	"10250 [20010422.005] perl -e '{s//${}/; //}' segfaults",
	"10394 Leakage of file scope lexicals into predeclared subroutines",
	"10404 eval.t was relying on pre-#10394 buggy behavior",
	"10412 Rationalize locale handling to fix bugs uncovered by #10394",
	"10422 Potential buffer overrun if the radix separator > 1 byte",
	"10448 Lexicals outside eval weren't resolved correctly pre-#10394",
	"10450 Optimize #10448 slightly",
	"10543 Add LC_MESSAGES constant to POSIX module",
	"10667 #10449 broke visibility of lexicals inside DB::DB()",
	"10739 C<eval \"/x$\\r\\n/x\"> fails to compile correctly",
	"10939 Proposed fix for Pod::Man",
	"11169 Doc patch for Tie::Hash",
	"11374 Make h2ph grok ccsymbols fo the form 1234L, 1234ULL etc",
	"11427 t/harness wasn't picking up all the tests",
	"11428 run/runenv.t needs fflushNULL sanity",
	"11431 pod/*.t tests not picked up by t/TEST either",
	"11510 eval 'format foo=' would loop indefinitely",
	"11713 UTF8 wasn't printing for PVMGs",
	"11716 UTF8 flag should be meaningful only when POK",
	"11808 [20010831.002] Bug in Term::Cap on Solaris ansi terminal",
	"11847 Typo in perl_clone() code causes local(*foo) breakage",
	"12005 [20010912.007] substr reference core dump",
	"12024 Fix local() precedence bug in #8311",
	"12303 Fix 'local $!=0;undef*STDOUT;' segfault",
	"12304 Pod::Html makes a poor guess at author",
	"12350 Typo in IO::Seekable doc",
	"12496 Carp::shortmess_heavy() doesn't notice trailing newline",
	"12549 readline() doesn't work with 'our' variables",
	"12550 #12549 wasn't aware of strictures",
	"12752 croak(Nullch) wasn't printing the contents of ERRSV",
	"12811 [20011101.069] \\stat('.') gives 'free unref scalar' error",
	"12812 Slight modification of #12811",
	"13149 Integrate #13147 from mainline (fixes nit in #10091)",
	"13261 Integrate #8340,#13260 from mainline",
	NULL
};

/* Initial space prevents this variable from being inserted in config.sh  */
#  define	LOCAL_PATCH_COUNT	\
	(sizeof(local_patches)/sizeof(local_patches[0])-2)

/* the old terms of reference, add them only when explicitly included */
#define PATCHLEVEL		PERL_VERSION
#undef  SUBVERSION		/* OS/390 has a SUBVERSION in a system header */
#define SUBVERSION		PERL_SUBVERSION
#endif
