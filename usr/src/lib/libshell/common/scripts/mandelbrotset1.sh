#!/usr/bin/ksh93

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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# mandelbrotset1 - a simple mandelbrot set generation and
# parallel execution demo
#

# Solaris needs /usr/xpg6/bin:/usr/xpg4/bin because the tools in /usr/bin are not POSIX-conformant
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

# Make sure all math stuff runs in the "C" locale to avoid problems
# with alternative # radix point representations (e.g. ',' instead of
# '.' in de_DE.*-locales). This needs to be set _before_ any
# floating-point constants are defined in this script).
if [[ "${LC_ALL}" != "" ]] ; then
    export \
        LC_MONETARY="${LC_ALL}" \
        LC_MESSAGES="${LC_ALL}" \
        LC_COLLATE="${LC_ALL}" \
        LC_CTYPE="${LC_ALL}"
        unset LC_ALL
fi
export LC_NUMERIC=C

function printmsg
{
	print -u2 "$*"
}

function fatal_error
{
	print -u2 "${progname}: $*"
	exit 1
}

# Get terminal size and put values into a compound variable with the integer
# members "columns" and "lines"
function get_term_size
{
	nameref rect=$1
    
	rect.columns=${ tput cols ; } || return 1
	rect.lines=${ tput lines ; }  || return 1
    
	return 0
}

function mandelbrot
{
	nameref result=$1
	float   x=$2
	float   y=$3
	float   xx
	float   yy
	float   x1=$4
	float   y1=$5
	integer iteration=$6
	integer max_iteration=$7
	float   mag

	for (( mag=0 ; mag < max_mag && iteration < max_iteration ; iteration++ )) ; do
		((
			xx=x*x ,
			yy=y*y ,
			mag=xx+yy ,
			y=x*y*2+y1 ,
			x=xx-yy+x1
		))
	done

	(( result=iteration ))

	return 0
}

# build mandelbrot image serially
function loop_serial
{
	integer value
	typeset line=""

	for (( y=y_min ; y < y_max ; y+=stepwidth )) ; do
		for (( x=x_min ; x < x_max ; x+=stepwidth )) ; do
			mandelbrot value ${x} ${y} ${x} ${y} 1 ${symbollistlen}
			line+="${symbollist:value:1}"
		done

		line+=$'\n'
	done
	
	print -r -- "${line}"
	
	return 0
}

# build mandelbrot image using parallel worker jobs
function loop_parallel
{
	integer numjobs=0
	# the following calculation suffers from rounding errors
	integer lines_per_job=$(( ((m_height+(numcpus-1)) / numcpus) ))
	typeset tmpjobdir

	printmsg $"# lines_per_job=${lines_per_job}"
	printmsg $"# numcpus=${numcpus}"

	# "renice" worker jobs
	set -o bgnice

	tmpjobdir="$(mktemp --default=/tmp --directory "mandelbrotset1${PPID}_$$_XXXXXX")" || fatal_error $"Could not create temporary directory."
	trap "rm -r ${tmpjobdir}" EXIT # cleanup

	# try to generate a job identifer prefix which is unique across multiple hosts
	jobident="job_host_$(uname -n)pid_$$_ppid${PPID}"

	printmsg $"## prepare..."
	for (( y=y_min ; y < y_max ; y+=(stepwidth*lines_per_job) )) ; do
		rm -f "${tmpjobdir}/${jobident}_child_$y.joboutput"

		(( numjobs++ ))
	done

	printmsg $"## running ${numjobs} children..."
	for (( y=y_min ; y < y_max ; y+=(stepwidth*lines_per_job) )) ; do
		(
			integer value
			typeset line=""
			# save file name since we're going to modify "y"
			typeset filename="${tmpjobdir}/${jobident}_child_$y.joboutput"

			for (( ; y < y_max && lines_per_job-- > 0 ; y+=stepwidth )) ; do
				for (( x=x_min ; x < x_max ; x+=stepwidth )) ; do
					mandelbrot value ${x} ${y} ${x} ${y} 1 ${symbollistlen}
					line+="${symbollist:value:1}"
				done

				line+=$'\n'
			done
			print -r -- "${line}" >"${filename}"
			
			exit 0
		) &
	done

	printmsg $"## waiting for ${numjobs} children..."
	wait

	printmsg $"## output:"
	for (( y=y_min ; y < y_max ; y+=(stepwidth*lines_per_job) )) ; do
		print -r -- "$( < "${tmpjobdir}/${jobident}_child_$y.joboutput")"
		# EXIT trap will cleanup temporary files
	done

	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${mandelbrotset1_usage}" OPT '-?'
	exit 2
}

# main
builtin basename
builtin cat
builtin rm
builtin uname # loop_parallel needs the ksh93 builtin version to generate unique job file names
builtin mktemp

set -o noglob
set -o nounset

typeset progname="${ basename "${0}" ; }"

float x_max
float x_min
float y_max
float y_min
float m_width
float m_height
float max_mag
float stepwidth
integer numcpus

# terminal size rect
compound termsize=(
	integer columns=-1
	integer lines=-1
)

get_term_size termsize || fatal_error $"Could not get terminal size."

typeset symbollist='    .:0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%#'
typeset symbollistlen=$(( ${#symbollist} - 1))
typeset mode="parallel"

(( max_mag=400 ))
(( stepwidth=0.1 ))

# calculate number of worker CPUs and use 3 as fallback
(( numcpus=$(getconf NPROCESSORS_ONLN || print "3") ))
(( numcpus=numcpus*4 ))

(( m_width=termsize.columns-1 , m_height=termsize.lines-2 ))

typeset -r mandelbrotset1_usage=$'+
[-?\n@(#)\$Id: mandelbrotset1 (Roland Mainz) 2010-03-31 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?mandelbrotset1 - generate mandelbrot set fractals with ksh93]
[+DESCRIPTION?\bmandelbrotset1\b mandelbrot set fractal generator
	which runs either in serial or parallel mode (using multiple worker jobs).]
[w:width?Width of fractal.]:[width]
[h:height?Height of fractal.]:[height]
[s:symbols?Symbols to build the fractal from.]:[symbolstring]
[m:mag?Magnification level.]:[magnificationlevel]
[p:stepwidth?Width per step.]:[widthperstep]
[S:serial?Run in serial mode.]
[P:parallel?Run in parallel mode.]
[M:mode?Execution mode.]:[mode]
[C:numcpus?Number of processors used for parallel execution.]:[numcpus]
[+SEE ALSO?\bjuliaset1\b(1), \bksh93\b(1)]
'

while getopts -a "${progname}" "${mandelbrotset1_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		w)	m_width="${OPTARG}"	;;
		h)	m_height="${OPTARG}"	;;
		s)	symbollist="${OPTARG}"	;;
		m)	max_mag="${OPTARG}"	;;
		p)	stepwidth="${OPTARG}"	;;
		S)	mode="serial"		;;
		+S)	mode="parallel"		;;
		P)	mode="parallel"		;;
		+P)	mode="serial"		;;
		M)	mode="${OPTARG}"	;;
		C)	numcpus="${OPTARG}"	;;
		*)	usage			;;
	esac
done
shift $((OPTIND-1))

printmsg "# width=${m_width}"
printmsg "# height=${m_height}"
printmsg "# max_mag=${max_mag}"
printmsg "# stepwidth=${stepwidth}"
printmsg "# symbollist='${symbollist}'"
printmsg "# mode=${mode}"

(( symbollistlen=${#symbollist}-1 ))

((
	x_max=m_width*stepwidth/2. ,
	x_min=-x_max ,
	y_max=m_height*stepwidth/2. ,
	y_min=-y_max
))

case "${mode}" in
	parallel)	loop_parallel	; exit $? ;;
	serial)		loop_serial	; exit $? ;;
	*)		fatal_error $"Unknown mode \"${mode}\"." ;;
esac

fatal_error "not reached."
# EOF.
