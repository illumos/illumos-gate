########################################################################
#                                                                      #
#               This software is part of the ast package               #
#           Copyright (c) 1982-2007 AT&T Knowledge Ventures            #
#                      and is licensed under the                       #
#                  Common Public License, Version 1.0                  #
#                      by AT&T Knowledge Ventures                      #
#                                                                      #
#                A copy of the License is available at                 #
#            http://www.opensource.org/licenses/cpl1.0.txt             #
#         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         #
#                                                                      #
#              Information and Software Systems Research               #
#                            AT&T Research                             #
#                           Florham Park NJ                            #
#                                                                      #
#                  David Korn <dgk@research.att.com>                   #
#                                                                      #
########################################################################
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

#test for compound variables
Command=${0##*/}
integer Errors=0
Point=(
	float x=1. y=0.
)
eval p="$Point"
if	(( (p.x*p.x + p.y*p.y) > 1.01 ))
then	err_exit 'compound variable not working'
fi
nameref foo=p
if	[[ ${foo.x} != ${Point.x} ]]
then	err_exit 'reference to compound object not working'
fi
unset foo
rec=(
	name='Joe Blow'
	born=(
		month=jan
		integer day=16
		year=1980
	)
)
eval newrec="$rec"
if	[[ ${newrec.name} != "${rec.name}" ]]
then	err_exit 'copying a compound object not working'
fi
if	(( newrec.born.day != 16 ))
then	err_exit 'copying integer field of  compound object not working'
fi
p_t=(
        integer z=0
        typeset -A tokens
)
unset x
typeset -A x
x=( [foo]=bar )
if	[[ ${x[@]} != bar ]]
then	err_exit 'compound assignemnt of associative arrays not working'
fi
unset -n foo x
unset foo x
foo=( x=3)
nameref x=foo
if	[[ ${!x.@} != foo.x ]]
then	err_exit 'name references not expanded on prefix matching'
fi
unset x
(
	x=()
	x.foo.bar=7
	[[ ${x.foo.bar} == 7 ]] || err_exit '[[ ${x.foo.bar} != 7 ]]'
	(( x.foo.bar == 7  ))|| err_exit '(( x.foo.bar != 7 ))'
	[[ ${x.foo} == *bar=7*  ]] || err_exit '[[ ${x.foo} != *bar=7* ]]'
)
foo=(integer x=3)
if	[[ ${foo} != *x=3* ]]
then	err_exit "compound variable with integer subvariable not working"
fi
$SHELL -c $'x=(foo=bar)\n[[ x == x ]]' 2> /dev/null || 
	err_exit '[[ ... ]] not working after compound assignment'
unset foo
[[ ${!foo.@} ]] && err_exit 'unset compound variable leaves subvariables'
suitable=(
  label="Table Viewer"
  langs="ksh"
  uselang=ksh
  launch=no
  groups="default"
  default=(
    label="Table Viewer Preferences"
    entrylist=" \
      vieworigin viewsize viewcolor viewfontname viewfontsize \
      showheader header showfooter footer showtitle title showlegends \
      class_td_lg1_style class_tr_tr1_style \
      class_th_th1_style class_td_td1_style \
      fields fieldorder \
    "
    entries=(
      vieworigin=(
        type=coord var=vieworigin val="0 0" label="Window Position"
      )
      viewsize=(
        type=coord var=viewsize val="400 400" label="Window Size"
      )
      viewcolor=(
        type=2colors var=viewcolor val="gray black"
        label="Window Colors"
      )
      viewfontname=(
        type=fontname var=viewfontname val="Times-Roman"
        label="Window Font Name"
      )
      viewfontsize=(
        type=fontsize var=viewfontsize val=14 label="Window Font Size"
      )

      showheader=(
        type=yesno var=showheader val=no label="Show Header"
      )
      header=(
        type=text var=header val="" label="Header"
      )

      showfooter=(
        type=yesno var=showfooter val=no label="Show Footer"
      )
      footer=(
        type=text var=footer val="" label="Footer"
      )

      showtitle=(
        type=yesno var=showtitle val=yes label="Show Title"
      )
      title=(
        type=text var=title val="SWIFTUI - Table View" label="Title"
      )

      showlegends=(
        type=yesno var=showlegends val=yes label="Show Legends"
      )

      class_td_lg1_style=(
        type=style var=class_td_lg1_style
        val="color: black; font-family: Times-Roman; font-size: 14pt"
        label="Legend 1 Style"
      )

      class_tr_tr1_style=(
        type=style var=class_tr_tr1_style val="background: black"
        label="Table Row 1 Style"
      )

      class_th_th1_style=(
        type=style var=class_th_th1_style
        val="color: black; font-family: Times-Roman; font-size: 14pt; text-align: left"
        label="Table Header 1 Style"
      )

      class_td_td1_style=(
        type=style var=class_td_td1_style
        val="color: black; font-family: Times-Roman; font-size: 14pt; text-align: left"
        label="Table Cell 1 Style"
      )

      fields=(
        type=text var=fields val= label="List of Fields"
      )
      fieldorder=(
        type=text var=fieldorder val= label="Order of Fields"
      )
    )
  )
)
[[ "${suitable}" == *entrylist=* ]] || err_exit 'compound variable expansion omitting fields'
foo=( bar=foo  barbar=bar)
[[ $foo == *bar=foo* ]] || err_exit 'no prefix elements in compound variable output'
function localvar
{
	typeset point=(typeset -i x=3 y=4)
	(( (point.x*point.x + point.y*point.y) == 25 )) || err_exit "local compound variable not working"
}
point=(integer x=6 y=8)
localvar
	(( (point.x*point.x + point.y*point.y) == 100 )) || err_exit "global compound variable not preserved"
[[ $($SHELL -c 'foo=();foo.[x]=(y z); print ${foo.x[@]}') == 'y z' ]] 2> /dev/null || err_exit 'foo=( [x]=(y z)  not working'
unset z
( [[ ${z.foo.bar:-abc} == abc ]] 2> /dev/null) || err_exit ':- not working with compound variables'
exit $((Errors))

