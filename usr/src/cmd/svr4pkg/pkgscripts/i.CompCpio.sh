#!/bin/sh
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# i.CompCpio 
#
# This shell script uncompresses and installs files archived in
# old-style WOS packages using the utilities cpio and compress. It
# looks in the PKGSRC directory for the archives which may be called
# out in one of eight ways :
#
#	reloc.cpio.Z	relocatable paths, less old style
#	root.cpio.Z	absolute paths, less old style
#	reloc.cpio	relocatable paths less old style, not compressed
#	root.cpio	absolute paths, less old style, not compressed
#	reloc.Z		relocatable paths, old style, compressed
#	root.Z		absolute paths, old style, compressed
#	reloc		relocatable paths, old style, not compressed
#	root		absolute paths, old style, not compressed
#
# stdin carries the source directory as the first entry followed by the
# paths of the files to be installed as indicated in the pkgmap. Since
# all operations take place from the declared base directory, both relative
# and absolute paths will install correctly. There are three methods and
# since speed is of the essence, we skip straight to the right one :
#
#	If it's an initial install
#		do a full cpio for each archive
#	else
#		If there's only the reloc archive
#			make a file list, rm executables, do a selective cpio
#		else
#			rm executables, do a full cpio for each archive
#
# Since the old-style archives contain no execute permissions, this
# script saves the executables it requires so it can clean up after
# unloading the archive. If /usr/lib/ld.so or .so.1 is included in the
# package, no cleanup will be possible (nothing will run) so we clean
# up first and then unload the entire archive without a file list.
#
NAME="i.CompCpio"
FILELIST=${PKGSAV:?undefined}/filelist
BD=${BASEDIR:-/}
IR=${PKG_INSTALL_ROOT:-/}
MAXLIST=550	# This is arbitrary based upon 2.4 cpio
count=0

reloc_cpio_Z=0
root_cpio_Z=0
reloc_cpio=0
root_cpio=0
Reloc_Arch=""
Root_Arch=""
is_an_archive=0
is_a_filelist=0
mk_filelist=0
list_empty=1
local_install=0
Spcl_init=0
Rm_alt_sav=0

# critical archived dynamic libraries and executables
Spcl_lib=0
Spcl_exec=0
Movelist=""
Ld_Preload=""
Ld1=usr/lib/ld.so.1
Ld=usr/lib/ld.so
Libintl=usr/lib/libintl.so.1
Libmalloc=usr/lib/libmapmalloc.so.1
Libc=usr/lib/libc.so.1	
Libw=usr/lib/libw.so.1
Libdl=usr/lib/libdl.so.1
Cpio=usr/bin/cpio
Rm=usr/bin/rm
Ln=usr/bin/ln
Mv=usr/bin/mv
Nawk=usr/bin/nawk
Zcat=usr/bin/zcat

# Set up the default paths
MV_xpath=/usr/bin
MV_cmd=$MV_xpath/mv
CPIO_xpath=/usr/bin
CPIO_cmd=$CPIO_xpath/cpio
ZCAT_xpath=/usr/bin
ZCAT_cmd=$ZCAT_xpath/zcat
LN_xpath=/usr/bin
LN_cmd=$LN_xpath/ln
NAWK_xpath=/usr/bin
NAWK_cmd=$NAWK_xpath/nawk
RM_xpath=/usr/bin
RM_cmd=$RM_xpath/rm
Tmp_xpath=/usr/tmp$$dir
Tmp_Creat=0
rm_cpio=0
rm_ln=0
rm_zcat=0
rm_nawk=0
rm_rm=0
rm_mv=0
no_select=0

# Functions

#
# This creates the temporary directory for holding the old dynamic
# libraries and executables.
#
mktempdir() {
	if [ ! -d $Tmp_xpath ]; then
		mkdir $Tmp_xpath
		if [ $? -ne 0 ]; then
			echo `gettext "ERROR : $NAME cannot create $Tmp_xpath."`
			exit 1
		fi
	fi
	Tmp_Creat=1
}

#
# Test a path to see if it represents a dynamic library or executable that
# we use in this script. If it is, deal with the special case.
#
spclcase() {	# $1 is the pathname to special case
	if [ $local_install -eq 1 ]; then
		case $1 in
			$Ld)		no_select=1;;
			$Ld1)		no_select=1;;
			$Libintl)	Spcl_lib=1; file=libintl.so.1;;
			$Libmalloc)	Spcl_lib=1; file=libmapmalloc.so.1;;
			$Libc)		Spcl_lib=1; file=libc.so.1;;
			$Libw)		Spcl_lib=1; file=libw.so.1;;
			$Libdl)		Spcl_lib=1; file=libdl.so.1;;
			$Cpio)		rm_cpio=1; Spcl_exec=1;;
			$Ln)		rm_ln=1; Spcl_exec=1;;
			$Zcat)		rm_zcat=1; Spcl_exec=1;;
			$Nawk)		rm_nawk=1; Spcl_exec=1;;
			$Rm)		rm_rm=1; Spcl_exec=1;;
			$Mv)		rm_mv=1; Spcl_exec=1;;
		esac

		if [ $no_select -eq 1 ]; then
			is_a_filelist=0
			list_empty=1
			$RM_cmd $FILELIST
			if [ $Rm_alt_sav -eq 1 ]; then
				$RM_cmd -r $PKGSAV
				Rm_alt_sav=0
			fi
			exec_clean 1
			return 1
		elif [ $Spcl_lib -eq 1 ]; then
			if [ $Tmp_Creat -eq 0 ]; then
				mktempdir
			fi

			if [ $Spcl_init -eq 0 ]; then
				Org_LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
				LD_LIBRARY_PATH="$Org_LD_LIBRARY_PATH $Tmp_xpath"
				export LD_LIBRARY_PATH
				Spcl_init=1
			fi
			Ld_Preload="$Ld_Preload $Tmp_xpath/$file"
			LD_PRELOAD=$Ld_Preload
			export LD_PRELOAD
			Movelist="$1 $file $Movelist"
			$MV_cmd $1 $Tmp_xpath
			$LN_cmd -s ../..$Tmp_xpath/$file $1
			Spcl_lib=0
		elif [ $Spcl_exec -eq 1 ]; then
			if [ $Tmp_Creat -eq 0 ]; then
				mktempdir
			fi

			$MV_cmd $1 $Tmp_xpath
			if [ $rm_cpio -eq 1 ]; then
				$LN_cmd -s ../..$Tmp_xpath/cpio $1
				CPIO_cmd="$Tmp_xpath/cpio"
				Movelist="$1 cpio $Movelist"
				rm_cpio=0
			elif [ $rm_ln -eq 1 ]; then
				$Tmp_xpath/ln -s ../..$Tmp_xpath/ln $1
				LN_cmd="$Tmp_xpath/ln"
				Movelist="$1 ln $Movelist"
				rm_ln=0
			elif [ $rm_nawk -eq 1 ]; then
				$LN_cmd -s ../..$Tmp_xpath/nawk $1
				NAWK_cmd="$Tmp_xpath/nawk"
				Movelist="$1 nawk $Movelist"
				rm_nawk=0
			elif [ $rm_zcat -eq 1 ]; then
				$LN_cmd -s ../..$Tmp_xpath/zcat $1
				ZCAT_cmd="$Tmp_xpath/zcat"
				Movelist="$1 zcat $Movelist"
				rm_zcat=0
			elif [ $rm_rm -eq 1 ]; then
				$LN_cmd -s ../..$Tmp_xpath/rm $1
				RM_cmd="$Tmp_xpath/rm"
				Movelist="$Movelist $1 rm"
				rm_rm=0
			elif [ $rm_mv -eq 1 ]; then
				$LN_cmd -s ../..$Tmp_xpath/mv $1
				MV_cmd="$Tmp_xpath/mv"
				Movelist="$Movelist $1 mv"
				rm_mv=0
			fi
			Spcl_exec=0
		fi
	fi

	return 0
}

#
# Clean up the libraries and executables that were moved.
#
exec_clean() {	# $1 =1 means be quiet
	if [ ! -z "${Movelist}" ]; then
		echo $Movelist | $NAWK_cmd '
			{ split ($0, line)
			for (n=1; n <= NF; n++) {
				print line[n]
			}
		}' | while read path; do
			read file
			if [ -h $path ]; then	# If it's our slink
				# then put the original back
				if [ $1 -eq 0 ]; then
					echo `gettext "WARNING : $path not found in archive."`
				fi
				$MV_cmd $Tmp_xpath/$file $path
			else	# if the archive put something down
				# remove the temporary copy
				$RM_cmd $Tmp_xpath/$file
			fi
		done
		for path in $Movelist; do
			if [ -x $path ]; then
				case $path in
					$Cpio)	CPIO_cmd="$CPIO_xpath/cpio";;
					$Ln)	LN_cmd="$LN_xpath/ln";;
					$Zcat)	ZCAT_cmd="$ZCAT_xpath/zcat";;
					$Nawk)	NAWK_cmd="$NAWK_xpath/nawk";;
					$Rm)	RM_cmd="$RM_xpath/rm";;
					$Mv)	MV_cmd="$MV_xpath/mv";;
				esac
			fi
		done
		Movelist=""

		if [ $Tmp_Creat -eq 1 ]; then
			$RM_cmd -r $Tmp_xpath
			Tmp_Creat=0
		fi
	fi
}

#
# Figure out what kind of package this is
#
eval_pkg() {

	# Any archive, whether compressed or not needs to be handled
	# the same. i.e. reloc.cpio.Z and root.cpio.Z should cause
	# the global is_an_archive to be set to 1.

	read path
	if [ ${path:-NULL} != NULL ]; then # get the package source directory
		PKGSRC=${path:?undefined}

		if [ ${PKG_INSTALL_ROOT:-/} = "/" ]; then
			local_install=1
		fi

		if [ -r $PKGSRC/reloc.cpio.Z ]; then
			reloc_cpio_Z=1
			Reloc_Arch=$PKGSRC/reloc.cpio.Z
			is_an_archive=1
		fi

		if [ -r $PKGSRC/root.cpio.Z ]; then
			root_cpio_Z=1
			Root_Arch=$PKGSRC/root.cpio.Z
			is_an_archive=1
		fi

		if [ -r $PKGSRC/reloc.cpio ]; then
			reloc_cpio=1
			Reloc_Arch=$PKGSRC/reloc.cpio
			is_an_archive=1
		fi

		if [ -r $PKGSRC/root.cpio ]; then
			root_cpio=1
			Root_Arch=$PKGSRC/root.cpio
			is_an_archive=1
		fi

		if [ -r $PKGSRC/reloc.Z ]; then
			reloc_cpio_Z=1
			Reloc_Arch=$PKGSRC/reloc.Z
			is_an_archive=2
		fi

		if [ -r $PKGSRC/root.Z ]; then
			root_cpio_Z=1
			Root_Arch=$PKGSRC/root.Z
			is_an_archive=2
		fi

		if [ -f $PKGSRC/reloc ]; then
			reloc_cpio=1
			Reloc_Arch=$PKGSRC/reloc
			is_an_archive=2
		fi

		if [ -f $PKGSRC/root ]; then
			root_cpio=1
			Root_Arch=$PKGSRC/root
			is_an_archive=2
		fi
	else
		exit 0	# empty pipe, we're done
	fi
}

#
# main
#

eval_pkg

if [ $BD = "/" ]; then
	Client_BD=""
else
	Client_BD=`echo $BD | sed s@/@@`
fi

if [ $is_an_archive -eq 0 ]; then
	echo `gettext "ERROR : $NAME cannot find archived files in $PKGSRC."`
	exit 1
fi

if [ ! -d $PKGSAV ]; then
	echo `gettext "WARNING : $NAME cannot find save directory $PKGSAV."`
	PKGSAV=/tmp/$PKG.sav

	if [ ! -d $PKGSAV ]; then
		/usr/bin/mkdir $PKGSAV
	fi

	if [ $? -eq 0 ]; then
		echo `gettext "  Using alternate save directory" $PKGSAV`
		FILELIST=$PKGSAV/filelist
		Rm_alt_sav=1
	else
		echo `gettext "ERROR : cannot create alternate save directory"` $PKGSAV
		exit 1
	fi
fi

if [ -f $FILELIST ]; then
	rm $FILELIST
fi

cd $BD

# If there's one old-style archive and it is relocatable and this is
# not an initial install then make a file list for extraction.
if [ $is_an_archive -eq 1 -a ${PKG_INIT_INSTALL:-null} = null ]; then
	mk_filelist=1
fi

# If this is not an initial install then clear out potentially executing
# files and libraries for cpio and create an extraction list if necessary
if [ ${PKG_INIT_INSTALL:-null} = null ]; then
	if [ $local_install -eq 1 ]; then
		# If extraction list is desired, create it
		if [ $mk_filelist -eq 1 ]; then
			is_a_filelist=1
			while	read path
			do
				echo $path >> $FILELIST
				list_empty=0
				if [ -x ${path:-NULL} ]; then
					full_path=`echo $Client_BD/$path | sed s@//@/@g`
					spclcase $full_path
					if [ $? -eq 1 ]; then
						break
					fi
				fi
			done

			# If there's a path containing a '$' then we can't
			# use the extraction list because of the shell
			if [ $list_empty -eq 0 ]; then
				s=`LD_PRELOAD="$Ld_Preload" $NAWK_cmd ' /\\$/ { print } ' $FILELIST`

				if [ ! -z "${s}" ]; then
					is_a_filelist=0
				fi
			fi
		else	# No extraction list is desired
			while	read  path
			do
				if [ -x ${path:-NULL} ]; then
					full_path=`echo $Client_BD/$path | sed s@//@/@g`
					spclcase $full_path
					if [ $? -eq 1 ]; then
						break
					fi
				fi
			done
		fi	# $mk_filelist -eq 1
	else	# ! ($local_install -eq 1)
		# If extraction list is desired, create it
		if [ $mk_filelist -eq 1 ]; then
			is_a_filelist=1
			while	read path
			do
				echo $path >> $FILELIST
				list_empty=0
			done

			# If there's a path containing a '$' then we can't
			# use the extraction list because of the shell
			if [ $list_empty -eq 0 ]; then
				s=`LD_PRELOAD="$Ld_Preload" $NAWK_cmd ' /\\$/ { print } ' $FILELIST`

				if [ ! -z "${s}" ]; then
					is_a_filelist=0
				fi
			fi
		fi	# $mk_filelist -eq 1
	fi	# $local_install -eq 1
fi	# ${PKG_INIT_INSTALL:-null} = null

# Now extract the data from the archive(s)
# extract compressed cpio relocatable archive
if [ $reloc_cpio_Z -eq 1 ]; then
	cd $BD
	if [ $is_a_filelist -eq 1 ]; then
		if [ $list_empty -eq 0 ]; then
			$ZCAT_cmd $Reloc_Arch | $CPIO_cmd -idukm -E $FILELIST
			if [ $? -ne 0 ]; then
				echo `gettext "cpio of $Reloc_Arch failed with error $?."`
				exit 1
		   	 fi

		fi
	else
		$ZCAT_cmd $Reloc_Arch | $CPIO_cmd -idukm
	fi
fi

# extract compressed cpio absolute archive
if [ $root_cpio_Z -eq 1 ]; then
	cd $IR
	$ZCAT_cmd $Root_Arch | $CPIO_cmd -idukm
		if [ $? -ne 0 ]; then
			echo `gettext "cpio of $Root_Arch failed with error $?."`
			exit 1
		fi
fi

# extract cpio relocatable archive
if [ $reloc_cpio -eq 1 ]; then
	cd $BD
	if [ $is_a_filelist -eq 1 ]; then
		if [ $list_empty -eq 0 ]; then
			$CPIO_cmd -idukm -I $Reloc_Arch -E $FILELIST

			if [ $? -ne 0 ]; then
				echo `gettext "cpio of $Reloc_Arch failed with error $?."`
				exit 1
			fi
		fi
	else
		$CPIO_cmd -idukm -I $Reloc_Arch
	fi
fi

# extract cpio absolute archive
if [ $root_cpio -eq 1 ]; then
	cd $IR
	$CPIO_cmd -idukm -I $Root_Arch
		if [ $? -ne 0 ]; then
			echo `gettext "cpio of $Root_Arch failed with error $?."`
			exit 1
		fi
fi

if [ -f $FILELIST ]; then
	$RM_cmd $FILELIST
fi

if [ $Rm_alt_sav -eq 1 ]; then
	$RM_cmd -r $PKGSAV
	Rm_alt_sav=0
fi

exec_clean 0

if [ $Tmp_Creat -eq 1 ]; then
	$RM_cmd -r $Tmp_xpath
fi

if [ $Spcl_init -eq 1 ]; then
	LD_LIBRARY_PATH=$Org_LD_LIBRARY_PATH
	export LD_LIBRARY_PATH
	Spcl_init=0
fi

exit 0
