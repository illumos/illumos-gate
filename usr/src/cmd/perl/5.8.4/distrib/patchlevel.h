/*    patchlevel.h
 *
 *    Copyright (C) 1993, 1995, 1996, 1997, 1998, 1999,
 *    2000, 2001, 2002, 2003, 2004, by Larry Wall and others
 *
 *    You may distribute under the terms of either the GNU General Public
 *    License or the Artistic License, as specified in the README file.
 *
 */

#ifndef __PATCHLEVEL_H_INCLUDED__

/* do not adjust the whitespace! Configure expects the numbers to be
 * exactly on the third column */

#define PERL_REVISION	5		/* age */
#define PERL_VERSION	8		/* epoch */
#define PERL_SUBVERSION	4		/* generation */

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
#define PERL_API_VERSION	8	/* Adjust manually as needed.  */
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

	Please either use 'diff --unified=0' if your diff supports
	that or edit the hunk of the diff output which adds your patch
	to this list, to remove context lines which would give patch
	problems. For instance, if the original context diff is

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
	     	,NULL
	     };
	
	(Note changes to line numbers as well as removal of context lines.)
	This will prevent patch from choking if someone has previously
	applied different patches than you.

        History has shown that nobody distributes patches that also
        modify patchlevel.h. Do it yourself. The following perl
        program can be used to add a comment to patchlevel.h:

#!perl
die "Usage: perl -x patchlevel.h comment ..." unless @ARGV;
open PLIN, "patchlevel.h" or die "Couldn't open patchlevel.h : $!";
open PLOUT, ">patchlevel.new" or die "Couldn't write on patchlevel.new : $!";
my $seen=0;
while (<PLIN>) {
    if (/\t,NULL/ and $seen) {
       while (my $c = shift @ARGV){
            print PLOUT qq{\t,"$c"\n};
       }
    }
    $seen++ if /local_patches\[\]/;
    print PLOUT;
}
close PLOUT or die "Couldn't close filehandle writing to patchlevel.new : $!";
close PLIN or die "Couldn't close filehandle reading from patchlevel.h : $!";
unlink "patchlevel.bak" or warn "Couldn't unlink patchlevel.bak : $!"
  if -e "patchlevel.bak";
rename "patchlevel.h", "patchlevel.bak" or
  die "Couldn't rename patchlevel.h to patchlevel.bak : $!";
rename "patchlevel.new", "patchlevel.h" or
  die "Couldn't rename patchlevel.new to patchlevel.h : $!";
__END__

Please keep empty lines below so that context diffs of this file do
not ever collect the lines belonging to local_patches() into the same
hunk.

 */




#if !defined(PERL_PATCHLEVEL_H_IMPLICIT) && !defined(LOCAL_PATCH_COUNT)
static	char	*local_patches[] = {
        NULL,
	"22667 The optree builder was looping when constructing the ops ...",
	"22715 Upgrade to FileCache 1.04",
	"22733 Missing copyright in the README.",
	"22746 fix a coredump caused by rv2gv not fully converting a PV ...",
	"22755 Fix 29149 - another UTF8 cache bug hit by substr.",
	"22774 [perl #28938] split could leave an array without ...",
	"22775 [perl #29127] scalar delete of empty slice returned garbage",
	"22776 [perl #28986] perl -e \"open m\" crashes Perl",
	"22777 add test for change #22776 (\"open m\" crashes Perl)",
	"22778 add test for change #22746 ([perl #29102] Crash on assign ...",
	"22781 [perl #29340] Bizarre copy of ARRAY make sure a pad op's ...",
	"22796 [perl #29346] Double warning for int(undef) and abs(undef) ...",
	"22818 BOM-marked and (BOMless) UTF-16 scripts not working",
	"22823 [perl #29581] glob() misses a lot of matches",
	"22827 Smoke [5.9.2] 22818 FAIL(F) MSWin32 WinXP/.Net SP1 (x86/1 cpu)",
	"22830 [perl #29637] Thread creation time is hypersensitive",
	"22831 improve hashing algorithm for ptr tables in perl_clone: ...",
	"22839 [perl #29790] Optimization busted: '@a = \"b\", sort @a' ...",
	"22850 [PATCH] 'perl -v' fails if local_patches contains code snippets",
	"22852 TEST needs to ignore SCM files",
	"22886 Pod::Find should ignore SCM files and dirs",
	"22888 Remove redundant %SIG assignments from FileCache",
	"23006 [perl #30509] use encoding and \"eq\" cause memory leak",
	"23074 Segfault using HTML::Entities",
	"23106 Numeric comparison operators mustn't compare addresses of ...",
	"23320 [perl #30066] Memory leak in nested shared data structures ...",
	"23321 [perl #31459] Bug in read()",
	"27722 perlio.c breaks on Solaris/gcc when > 256 FDs are available",
 	"SPRINTF0 - fixes for sprintf formatting issues - CVE-2005-3962",
	"6663288 Upgrade to CGI.pm 3.33",
 	"REGEXP0 - fix for UTF-8 recoding in regexps - CVE-2007-5116",
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
