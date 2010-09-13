#!/sbin/sh
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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.12.1.1	*/

#	INSTALL COMMAND

FLIST=$ROOT/etc/syslist
DEFAULT="$ROOT/bin $ROOT/usr/bin $ROOT/etc $ROOT/lib $ROOT/usr/lib" FOUND="" MOVOLD=""
ECHO=echo PATH=/usr/bin FLAG=off
USAGE="eval echo 'usage: install [options] file [dir1 ...]'; exit 2"

if [ $# -lt 2 ] ; then
	$USAGE
fi

MFLAG=off
UFLAG=off
GFLAG=off

MODE=755
GRP=`expr "\`id\`" : ".*gid=[0-9]*(\(..*\)) .*"`
GROUP=`echo $GRP | sed -e 's/) fsid.*//p'`
OWN=`expr "\`id\`" : ".*uid=[0-9]*(\(..*\)) .*"`
OWNER=`echo $OWN | sed -e 's/) .*//p'`
if [ -z "$GROUP" ]
then
	GROUP=`expr "\`id\`" : ".*gid=\([0-9]*\).*"`
fi
if [ -z "$OWNER" ]
then
	OWNER=`expr "\`id\`" : ".*uid=\([0-9]*\).*"`
fi
if [ "$OWNER" = root ]
then
	ROOTFLAG=on
	OWNER=bin
	GROUP=bin
else
	ROOTFLAG=off
fi


for i in $*
do
	if [ $FLAG = on ]
	then
		case $i in
		    -*) echo "install: The -c, -f, -n options each require a directory following!"
			exit 2;;
		     *) FLAG=off
			continue;;
		esac
	fi
	case $i in
	    -c) if [ x$ARG = x-d -o x$ARG = x-f ]
		then
			echo "install: -c dir: illegal option with $ARG option!"
			exit 2
	        elif [ x$arg = x-i -o x$arg = x-o -o x$arg = x-n ]
		then
			echo "install: -c dir: illegal option with $arg option!"
			exit 2
		elif test $# -lt 3
		then
			echo "install: -c option must have at least 3 args!"
			exit 2
		else
			direct=$2
			FLAG=on
			ARG=-c
			shift; shift
		fi;;
	    -f) if [ x$ARG = x-d -o x$ARG = x-c ]
		then
			echo "install: -f dir: illegal option with $ARG option!"
			exit 2
		elif [ x$arg = x-i -o x$arg = x-n ]
		then
			echo "install: -f dir: illegal option with $arg option!"
			exit 2
		elif test $# -lt 3
		then
			echo "install: -f option must have at least 3 args!"
			exit 2
		else
			direct=$2
			FLAG=on
			ARG=-f
			shift; shift
		fi;;
	  -i) if [ x$ARG = x-d -o x$ARG  = x-c -o x$ARG = x-f ]
		then
			echo "install: -i: illegal option with $ARG option!"
			exit 2
		elif test $# -lt 3
		then
			echo "install: -i option requires at least 3 args!"
			exit 2
		else
			DEFAULT=""
			arg=-i
			shift
		fi;;
	    -o) if  [ x$ARG = x-d -o x$ARG = x-c ]
		then
			echo "install: -o: illegal option with $ARG option!"
			exit 2
		elif test $# -lt 2
		then
			$USAGE
		else
			MOVOLD=yes
			arg=-o
			shift
		fi;;
	    -n) if [ x$ARG = x-d -o x$ARG = x-c -o x$ARG = x-f ]
		then
			echo "install: -n dir: illegal option with $ARG option!"
			exit 2
		elif test $# -lt 3
		then
			echo "install: -n option requires at least 3 args!"
			exit 2
		else
			LASTRES=$2
			FLAG=on
			FOUND=n
			arg=-n
			shift; shift
		fi;;
	    -d) if [ x$ARG = x-c -o x$ARG = x-f ]
		then
			echo "install: -d: illegal option with $ARG option!"
			exit 2
		elif [ x$arg = x-i -o x$arg = x-o -o x$arg = x-n ]
		then
			echo "install: -d: illegal option with $arg option!"
			exit 2
		else
			ARG=-d
			shift
		fi;;
	    -s) if test $# -lt 2
		then
			$USAGE
		else
			ECHO=:
			shift
		fi;;
	    -u) if [ $ROOTFLAG = off ]
		then
			echo "install: -u option available only to root -- ignored"
		else
			OWNER=$2
			UFLAG=on
			$ECHO new owner is $OWNER
		fi
		FLAG=on
		shift; shift;;
	    -g) if [ $ROOTFLAG = off ]
		then
			echo "install: -g option available only to root -- ignored"
		else
			GROUP=$2
			GFLAG=on
		fi
		FLAG=on
		shift; shift;;
	    -m) MODE=$2
		MFLAG=on
		FLAG=on
		shift; shift;;
	     *) break;;
	esac
done


if [ x$ARG = x-d ]
then
	if [ ! -d $i ]
	then
		mkdir -p $i
		if [ $? = 0 ]
		then
			$ECHO "directory $i created"
			chgrp $GROUP $i
			chown $OWNER $i
			chmod $MODE $i
		else
			echo "install: mkdir $i failed "
		fi
	else
		chgrp $GROUP $i
		chown $OWNER $i
		chmod $MODE $i
	fi
	exit
fi

FILEP=$i FILE=`echo $i | sed -e "s/.*\///"`
if [ x$ARG = x-c -o x$ARG = x-f ]
then
	case $2 in
		-*) $USAGE ;;
		"") :	;;
	esac
	if test -f $direct/$FILE -o -f $direct/$FILE/$FILE
	then
		case $ARG in
			-c) echo "install: $FILE already exists in $direct"
			    exit 2;;
			-f) GRP=`ls -l $direct/$FILE | awk '{print $4}'`
			    OWN=`ls -l $direct/$FILE | awk '{print $3}'`
			    if [ "$MOVOLD" = yes ]
			    then
				mv -f $direct/$FILE $direct/OLD$FILE
				cp $direct/OLD$FILE $direct/$FILE
				if [ $? = 0 ]
				then
				   $ECHO "$FILE moved to $direct/OLD$FILE"
				else
				   echo "install: mv $direct/OLD$FILE $direct/$FILE failed"
				   exit 2
				fi
			    fi
			    if cp $FILEP $direct/$FILE
			    then
				chgrp $GRP $direct/$FILE
				chown $OWN $direct/$FILE

				if [ "$GFLAG" = on ]
				then	
					chgrp $GROUP $direct/$FILE
				fi
				if [ "$MFLAG" = on ]
				then
					chmod $MODE $direct/$FILE
				fi
				if [ "$UFLAG" = on ]
				then
					chown $OWNER $direct/$FILE
				fi

				$ECHO "$FILEP installed as $direct/$FILE"
			    else
				echo "install: cp $FILEP $direct/$FILE failed "
				exit 2
			    fi
			    exit;;
		esac
	else
		cp $FILEP $direct/$FILE
		if [ $? = 0 ]
		then
			$ECHO "$FILEP installed as $direct/$FILE"
			chgrp $GROUP $direct/$FILE
			chown $OWNER $direct/$FILE
			chmod $MODE $direct/$FILE
		else
			echo "install: cp $FILEP $direct/$FILE failed "
			exit 2
		fi
	fi
	exit
fi

shift

PUTHERE=""
for i in $*
do
	case $i in
		-*) $USAGE ;;
	esac
	PUTHOLD=`find $i -follow -name $FILE -type f -print`
	PUTHERE=`expr "\`echo $PUTHOLD\`" : '\([^ ]*\)'`
	if [ "$PUTHERE" != "" ]
	then break
	fi
done
if [ -r $FLIST -a "$PUTHERE" = "" ]
then
	PUTHERE=`grep "/${FILE}$" $FLIST | sed  -n -e '1p'`
	if [ "$PUTHERE" != "" -a "$ROOT" != "" ]
	then
		PUTHERE=${ROOT}${PUTHERE}
	fi
fi
if [ "$PUTHERE" = "" ]
then
	for i in $DEFAULT
	do
		PUTHOLD=`find $i -follow -name $FILE -type f -print`
		PUTHERE=`expr "\`echo $PUTHOLD\`" : '\([^ ]*\)'`
		if [ "$PUTHERE" != "" ]
		then break
		fi
	done
fi
if [ "$PUTHERE" != "" ]
then
		    GRP=`ls -l $PUTHERE | awk '{print $4}'`
		    OWN=`ls -l $PUTHERE | awk '{print $3}'`
		    if [ "$MOVOLD" = yes ]
		    then
			old=`echo $PUTHERE | sed -e "s/\/[^\/]*$//"`
			mv -f $PUTHERE $old/OLD$FILE
			cp $old/OLD$FILE $PUTHERE
			if [ $? = 0 ]
			then
				    $ECHO "old $FILE moved to $old/OLD$FILE"
			else
				   echo "install: cp $direct/OLD$FILE $direct/$FILE failed"
				    exit 2
			fi
		    fi
		    FOUND=y
		    if cp $FILEP $PUTHERE
		    then
			chgrp $GRP $PUTHERE
			chown $OWN $PUTHERE

			if [ "$GFLAG" = on ]
			then	
				chgrp $GROUP $PUTHERE
			fi
			if [ "$MFLAG" = on ]
			then
				chmod $MODE $PUTHERE
			fi
			if [ "$UFLAG" = on ]
			then
				chown $OWNER $PUTHERE
			fi

			$ECHO "$FILEP installed as $PUTHERE"
			break
		    else
			exit 2
		    fi
fi

case $FOUND in
	"") echo "install: $FILE was not found anywhere!"
	    exit 2;;
	 y) :	;;
	 n) cp $FILEP $LASTRES/$FILE
	    if [ $? = 0 ]
	    then
		$ECHO "$FILEP installed as $LASTRES/$FILE by default!"
		cd $LASTRES
		chgrp $GROUP $FILE
		chown $OWNER $FILE
		chmod $MODE $FILE
	    else
		echo "install: cp $FILEP $LASTRES/$FILE failed"
		exit 2
	    fi;;
esac
