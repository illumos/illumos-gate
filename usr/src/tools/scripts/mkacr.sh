#!/bin/ksh -p
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
# This script builds the overhead information used by bfu to do
# automatic conflict resolution.  This overhead information is stored
# in a gzip'ed cpio archive called "conflict_resolution.gz" in the
# archive directory. It contains all of the class-action script
# required to upgrade the editable files, plus a control file
# (editable_file_db) which lists the editable files and the
# class-action scripts needed to upgrade them.
#

parse_pkginfo() {

	isa=$1
	dir=$2

	nawk -v matchisa=$isa -v pkginst=$dir -F= '

	# This clause matches architecture specific entries. e.g. CLASSES_i386=
	# It has a different format to the other ERE entries as this allows
	# the variable substition.

	$1 ~ "CLASSES_"matchisa"[\t ]*$" {
		gsub(/"/, "", $2);
		numisaclasses = split($2, isaclasses, " ");
		next;
	}
	/^CLASSES *=/ {
	  	gsub(/"/, "", $2);
		numclasses = split($2, classes, " ");
	  	next;
	}
	/^PKG *=/  {
	  	gsub(/"/, "", $2);
		pkg = $2;
		next;
	}
	/^ARCH *=/ {
		mach = "-";
	  	gsub(/"/, "", $2);
		if ($2 ~ /ISA/) {
			pkgisa = matchisa;
		} else {
			dotpos = index($2, ".");
			if (dotpos != 0 ) {
				pkgisa = substr($2, 1, dotpos - 1);
				mach = substr($2, dotpos + 1);
			} else {
				pkgisa = $2
			}
		}
		if (pkgisa != matchisa)
			exit 0;
		next;
	}
	END {
		if (numclasses == 0 && numisaclasses == 0)
			exit 0;

		for (i in isaclasses) {
		    	if (isaclasses[i] == "none") 
			    	continue;

			printf("%s %s %s %s %s\n", pkg, pkginst, pkgisa, mach, 
				isaclasses[i]);
		}
		for (i in classes) {
		    	if (classes[i] == "none") 
			    	continue;

			printf("%s %s %s %s %s\n", pkg, pkginst, pkgisa, mach, 
				classes[i]);
		}
	}
	' $dir/pkginfo.tmpl 
}


process_non_on_classes () {

    # $1 is one of non_on_classes
    # $2 is editablefilelist
    nononclass=$1
    efilelist=$2
    pkgdir=$3
    
    if [ "$1" = "build" ] ; then
	# print the target file name and pkg name from editablefilelist
	nawk -v class=${nononclass} '$3 == class { print $1,$2 }' $efilelist | \
	    while read tgtfile pkgname; do
		mkdir -p ${pkgdir}/${pkgname}/`dirname ${tgtfile}`
		if [ -s ${pkgname}/`basename ${tgtfile}` ] ; then
		    cp ${pkgname}/`basename ${tgtfile}` \
			${pkgdir}/${pkgname}/${tgtfile}
		else
		    print -u2 "mkacr: Can't find i.build source script."
		fi
	    done
    fi
}

#
# the process_pkdefs_directory function generates the conflict
# resolution information for a single pkgdefs directory (there can
# be more than one in an ON workspace).
# 
# It gets two arguments explicitly:
#	$1 - the location of the pkgdefs directory
#	$2 - a string to be used as a "uniquifier" for generating
#	     pathnames for class files (there can be more than one
#	     class action script with the same name, but they are all
#	     stored in one directory in the conflict resolution
#	     database).
#
# It gets two pieces of data globally:  the values of the "corepkgs"
# and the "bfu_incompatible_classes" variables.
#
process_pkgdefs_directory() {

	pkgdefsdir=$1
	un=$2

	cd $pkgdefsdir

	# Step 1: Generate a list of packages to be processed, with the
	# "core" packages at the head of the list.

	if [ "$ACR_DEBUG" = "yes" ] ; then
		print "Step 1: Generating list of packages to be processed"
	fi

	for dir in $corepkgs; do
		if [ -d $dir -a -s $dir/pkginfo.tmpl -a \
		     -s $dir/prototype_$isa ] ; then
			print $dir
		fi
	done | sort > $pkglist

	for dir in *; do
		if [ -d $dir -a -s $dir/pkginfo.tmpl -a \
		    -s $dir/prototype_$isa ] ; then
			print $dir
		fi
	done | sort > $allpkglist

	# make copy of pkglist so comm doesn't keep going because it's
	# appending to an input file

	cp $pkglist $pkgcopy
	comm -13 $pkgcopy $allpkglist >> $pkglist

	#
	# Step 2: build a list of all of the classes in all the packages
	# (except for the "none" class).  The order of each package's class
	# list must match the order in the pkginfo.tmpl file.
	#

	if [ "$ACR_DEBUG" = "yes" ] ; then
		print "Step 2: Build list of all classes in all packages."
	fi

	cat $pkglist | while read dir; do
	    	parse_pkginfo $isa $dir 
	done > $allclasslist_t

	cat $allclasslist_t | while read pkg pkginst p_isa mach class; do
		if [ -s common_files/i.$class -o \
		     -s common_files/i.${class}_$isa ] ; then
			print $pkg $pkginst $p_isa $mach $class c
		else
			echo ${non_on_classes} |
				    /usr/bin/grep -w i.${class} > /dev/null
			if [ $? -eq 0 ] ; then
				print $pkg $pkginst $p_isa $mach $class n
			else
				print $pkg $pkginst $p_isa $mach $class s
			fi		
		fi
	done > $allclasslist

	#
	# Step 3: For each package with at least one installation class,
	# scan the package's prototype files and look for files that are
	# editable or volatile and which have class-action scripts.  Make
	# a list of those files, with their packages and script names.
	#

	if [ "$ACR_DEBUG" = "yes" ] ; then
		print "Step 3: Build list of editable files."
	fi

	nawk '$3 == "'$isa'" {print $2}' $allclasslist | sort -u |
	while read pkginst; do
		if [ -s $pkginst/prototype_com ] ; then
			protos="$pkginst/prototype_com $pkginst/prototype_$isa"
		else
			protos="$pkginst/prototype_$isa"
		fi
		
		cat $protos | nawk -v pkginst=$pkginst \
		    '(/^[ev] /) && ($2 != "none") && ($2 != "build") {
				printf("%s %s %s\n", $3, pkginst, $2);}
		    (/^[ev] /) && ($2 == "build") {
				split($3,buildtgt,"=");
				printf("%s %s %s\n", buildtgt[1], pkginst,$2);}'
	done > $editablefilelist

	#
	# Step 4: Use the information in $allclasslist and
	# $editablefilelist to generate the list of files
	# to be copied to the bfu archive and the
	# editable-file/class-action-script database to be installed
	# in the archive.
	#

	if [ "$ACR_DEBUG" = "yes" ] ; then
		print "Step 4: Merge class list and editable files list"
	fi

	cat $allclasslist | while read pkg pkgdir classisa mach class iscommon
	do
		nawk -v pkgdir=$pkgdir -v class=$class -v pkg=$pkg \
		    -v isa=$classisa -v mach=$mach -v iscommon=$iscommon \
		    -v uniquifier=$un '
			{ if ($2 == pkgdir && $3 == class)
				printf("%s i.%s %s %s %s %s %s %s\n", $1,
					class, pkg, $2, isa, mach, iscommon,
					uniquifier);
			}' $editablefilelist
	done > $db

	for badclass in $bfu_incompatible_classes; do
		nawk -v badclass=$badclass -v replclass="upgrade_default" '{
			if ($2 == badclass)
				class = replclass;
			else
				class = $2;
			printf("%s %s %s %s %s %s %s %s\n", 
					$1, class, $3, $4, $5, $6, $7, $8)
		    }' $db > $tmpdb
		mv $tmpdb $db
	done

	#
	# Step 5 - Copy the editable-file/class-action-script database file
	#   to the class scripts to the archive directory.
	#

	if [ "$ACR_DEBUG" = "yes" ] ; then
		print "Step 5: Create bfu conflict resolution directory"
	fi

	mkdir -p $tmpdir/conflict_resolution/$un

	nawk '{ print $3 }' $editablefilelist | sort -u | while read class; do
		if [ -s common_files/i.$class ] ; then
			cp common_files/i.$class \
			    $tmpdir/conflict_resolution/$un
		elif [ -s common_files/i.${class}_$isa ] ; then
			cp common_files/i.${class}_$isa \
			    $tmpdir/conflict_resolution/$un/i.$class
		else
			echo ${non_on_classes} |
			    /usr/bin/grep -w i.${class} > /dev/null
			if [ $? -eq 0 ] ; then
			    #
			    # process_non_on_classes is called only once
			    # per non_on_class due to sort -u above. 
			    #
			    process_non_on_classes ${class} \
				 ${editablefilelist} \
				 $tmpdir/conflict_resolution/$un
			    continue;
			else
			    nawk -v class=$class '$3 == class { print $2 }' \
				$editablefilelist | sort -u > $classpk
			    if [ $(wc -l < $classpk) -ne 1 ] ; then
				    cat >&2 <<EOF
mkacr: The class script i.$class cannot be found in the pkgdefs common files
directory, and there is more than one package that uses it.
EOF
				    exit 1
			    fi
			fi
			pkgdir=$(cat $classpk)
			if [ -s $pkgdir/i.$class ] ; then
				mkdir -p $tmpdir/conflict_resolution/$un/$pkgdir
				cp $pkgdir/i.$class \
				    $tmpdir/conflict_resolution/$un/$pkgdir
			elif [ -s $pkgdir/i.${class}_$isa ] ; then
				mkdir -p $tmpdir/conflict_resolution/$un/$pkgdir
				cp $pkgdir/i.${class}_$isa \
				    $tmpdir/conflict_resolution/$un/$pkgdir/i.$class
			else
				print -u2 "mkacr: Can't find class script i.$class"
				exit 1
			fi
		fi
	done

	cat $db >> $tmpdir/conflict_resolution/editable_file_db

	if [ "$ACR_DEBUG" = "yes" ] ; then
		mkdir $tmpdir/$un
		mv $tmpdir/ps.* $tmpdir/$un
	else
		rm -fr $tmpdir/ps.*
	fi
}

#
# Execution starts here
#

export LC_ALL=C
ACR_DEBUG=${ACR_DEBUG-no}

USAGE="Usage: $0 <workspace> <instruction-set-architecture> <archive-dir>"

if [ $# -ne 3 ] ; then
	print -u2 $USAGE
	exit 1
fi

workspace=$1
isa=$2
if [ -d $workspace/pkgdefs ] ; then
	:
elif [ -d $workspace/usr/src/pkgdefs ] ; then
	workspace=$workspace/usr/src
else 
	print -u2 $USAGE
	exit 1
fi

if [ ! -d $3 ] ; then
	print -u2 $USAGE
	exit 1
fi
archivedir=$(cd $3; pwd)

if [ "$isa" != "sparc" -a "$isa" != "i386" ] ; then
	print -u2 "$0: Instruction set architecture must be \"sparc\" or \"i386\""
	exit 1
fi

#
# temporary file scorecard, in order of appearance:
# (Temporary files that begin with "ps." are pass-specific.  mkacr
# generates its database in multiple passes:  one for each pkgdef
# directory in the ON source base.  Currently there are 2:
# usr/src/pkgdefs and usr/src/realmode/pkgdefs.  The temp files
# that begin with "ps." are deleted at the end of each pass.)
#
# ps.pkglist	package names, starting with core pkgs
#
# ps.allpkglist 	pass 1 additional package list
#
# ps.pkgcopy	pass 1 temporary copy of core package names 
#
# ps.allclasslist	list of all classes
#
# ps.allclasslist_t	preliminary version of ps.allclasslist
#
# ps.editablefilelist	list of editable files.
#
# ps.db, tmpdb	temporary files used in construction of editable_file_db
#
# ps.cpioerr 	stderr from cpio.
#

tmpdir=$(mktemp -t -d mkacr.XXXXXX)

if [ -z "$tmpdir" ] ; then
        print -u2 "mktemp failed to produce output; aborting"
        exit 1
fi

if [ ! -d "$tmpdir" ] ; then
    	print -u2 "$0: Couldn't create temporary directory $tmpdir"
	exit 1
fi

if [ "$ACR_DEBUG" = "yes" ] ; then
    	print "Temporary files will be left in $tmpdir"
else
	trap 'rm -rf $tmpdir' 0
fi

cpioerr=$tmpdir/ps.cpioerr
pkglist=$tmpdir/ps.pkglist
allpkglist=$tmpdir/ps.allpkglist
pkgcopy=$tmpdir/ps.pkgcopy
allclasslist=$tmpdir/ps.allclasslist
allclasslist_t=$tmpdir/ps.allclasslist_t
editablefilelist=$tmpdir/ps.editablefilelist
db=$tmpdir/ps.db
tmpdb=$tmpdir/ps.tmpdb
classpk=$tmpdir/ps.classpk

#
# set up the list of corepkgs and bfs-incompatible classes for the
# processing of the usr/src/pkgdefs directory
#

corepkgs="
	SUNWcar.*
	SUNWcakr.*
	SUNWckr
	SUNWcsd
	SUNWcsr
	SUNWcsu
	SUNWcsl
	SUNWcslr
	SUNWkvm.*
"
bfu_incompatible_classes="
	i.initd
"
non_on_classes="
        i.CONFIG.prsv
        i.CompCpio
        i.awk
        i.build 
        i.ipsecalgs
        i.kcfconf
        i.kmfconf 
        i.pkcs11conf
        i.sed
"

process_pkgdefs_directory $workspace/pkgdefs std

if [[ -d $workspace/../closed/pkgdefs && "$CLOSED_IS_PRESENT" != no ]]; then
	process_pkgdefs_directory $workspace/../closed/pkgdefs std-closed
fi

#
# set up the list of corepkgs and bfs-incompatible classes for the
# processing of the usr/src/realmode/pkgdefs directory
#

corepkgs="SUNWrmodr"
bfu_incompatible_classes=""

if [ -d $workspace/realmode/pkgdefs ] ; then
    	process_pkgdefs_directory $workspace/realmode/pkgdefs realmode
fi

if [ "$ACR_DEBUG" = "yes" ] ; then
	print "Final processing: Create bfu conflict resolution archive"
fi

print "Creating conflict resolution archive: \c";

(cd $tmpdir
find conflict_resolution -print | cpio -ocB 2>$cpioerr |
    gzip -c > $archivedir/conflict_resolution.gz ) || exit 1

awk '/^[0-9]* blocks$/ { blocks=1; print $0; next }
{ print $0 > "/dev/stderr" }
END {
	if (!blocks) {
		# Terminate the "print \c" line above.
		print
		print "No cpio block count" > "/dev/stderr"
	}
}' <$cpioerr

exit 0
