########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2011 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                 Eclipse Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#          http://www.eclipse.org/org/documents/epl-v10.html           #
#         (with md5 checksum b35adb5213ca9657e911e9befb180842)         #
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
	print -u2 -r ${Command}[$Line]: "$@"
	((Errors++))
}

integer Errors=0
Command=${0##*/}

# {...} expansion tests -- ignore if not supported

[[ $(print a{0,1}z) == "a0z a1z" ]] || exit 0

integer Line=$LINENO+1
set -- \
	'ff{c,b,a}'				'ffc ffb ffa' \
	'f{d,e,f}g'				'fdg feg ffg' \
	'{l,n,m}xyz'				'lxyz nxyz mxyz' \
	'{abc\,def}'				'{abc,def}' \
	'{"abc,def"}'				'{abc,def}' \
	"{'abc,def'}"				'{abc,def}' \
	'{abc}'					'{abc}' \
	'\{a,b,c,d,e}'				'{a,b,c,d,e}' \
	'{x,y,\{a,b,c}}'			'x} y} {a} b} c}' \
	'{x\,y,\{abc\},trie}'			'x,y {abc} trie' \
	'/usr/{ucb/{ex,edit},lib/{ex,how_ex}}'	'/usr/ucb/ex /usr/ucb/edit /usr/lib/ex /usr/lib/how_ex' \
	'XXXX\{a,b,c\}'				'XXXX{a,b,c}' \
	'{}'					'{}' \
	'{ }'					'{ }' \
	'}'					'}' \
	'{'					'{' \
	'abcd{efgh'				'abcd{efgh' \
	'foo {1,2} bar'				'foo 1 2 bar' \
	'`print -r -- foo {1,2} bar`'		'foo 1 2 bar' \
	'$(print -r -- foo {1,2} bar)'		'foo 1 2 bar' \
	'{1..10}'				'1 2 3 4 5 6 7 8 9 10' \
	'{0..10,braces}'			'0..10 braces' \
	'{{0..10},braces}'			'0 1 2 3 4 5 6 7 8 9 10 braces' \
	'x{{0..10},braces}y'			'x0y x1y x2y x3y x4y x5y x6y x7y x8y x9y x10y xbracesy' \
	'{3..3}'				'3' \
	'x{3..3}y'				'x3y' \
	'{10..1}'				'10 9 8 7 6 5 4 3 2 1' \
	'{10..1}y'				'10y 9y 8y 7y 6y 5y 4y 3y 2y 1y' \
	'x{10..1}y'				'x10y x9y x8y x7y x6y x5y x4y x3y x2y x1y' \
	'{a..f}'				'a b c d e f' \
	'{f..a}'				'f e d c b a' \
	'{a..A}'				'{a..A}' \
	'{A..a}'				'{A..a}' \
	'{f..f}'				'f' \
	'{1..f}'				'{1..f}' \
	'{f..1}'				'{f..1}' \
	'0{1..9} {10..20}'			'01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20' \
	'{-1..-10}'				'-1 -2 -3 -4 -5 -6 -7 -8 -9 -10' \
	'{-19..0}'				'-19 -18 -17 -16 -15 -14 -13 -12 -11 -10 -9 -8 -7 -6 -5 -4 -3 -2 -1 0' \
	'{0..10}'				'0 1 2 3 4 5 6 7 8 9 10' \
	'{0..10..1}'				'0 1 2 3 4 5 6 7 8 9 10' \
	'{0..10..2}'				'0 2 4 6 8 10' \
	'{0..10..3}'				'0 3 6 9' \
	'{0..10..0}'				'{0..10..0}' \
	'{0..10..-1}'				'0' \
	'{10..0}'				'10 9 8 7 6 5 4 3 2 1 0' \
	'{10..0..-1}'				'10 9 8 7 6 5 4 3 2 1 0' \
	'{10..0..-2}'				'10 8 6 4 2 0' \
	'{10..0..-3}'				'10 7 4 1' \
	'{10..0..0}'				'{10..0..0}' \
	'{10..0..1}'				'10' \
	'{a..z..2}'				'a c e g i k m o q s u w y' \
	'{y..b..-3}'				'y v s p m j g d' \
	'{0..0x1000..0x200}'			'0 512 1024 1536 2048 2560 3072 3584 4096' \
	'{a,b}{0..2}{z,y}'			'a0z a0y a1z a1y a2z a2y b0z b0y b1z b1y b2z b2y' \
	'{0..0100..8%03o}'			'000 010 020 030 040 050 060 070 100' \
	'{0..0100..040%020o}'			'00000000000000000000 00000000000000000040 00000000000000000100' \
	'{0..7%03..2u}'				'000 001 010 011 100 101 110 111' \
	'{0..10%llu}'				'{0..10%llu}' \
	'{0..10%s}'				'{0..10%s}' \
	'{0..10%dl}'				'{0..10%dl}' \
	'{a,b}{0..3%02..2u}{y,z}'		'a00y a00z a01y a01z a10y a10z a11y a11z b00y b00z b01y b01z b10y b10z b11y b11z' \

while (($#>1))
do	((Line++))
	pattern=$1
	shift
	expected=$1
	shift
	got=$(eval print -r -- "$pattern")
	[[ $got == $expected ]] || err_exit "'$pattern' failed -- expected '$expected' got '$got'"
	#print -r -- "	'$pattern'			'$got' \\"
done

# ~(N) no expand glob pattern option
set -- ~(N)/dev/null
[[ $# == 1 && $1 == /dev/null ]] || err_exit "~(N)/dev/null not matching /dev/null"
set -- ~(N)/dev/non_existant_file
[[ $# == 0  ]] || err_exit "~(N)/dev/nonexistant not empty"
set -- ""~(N)/dev/non_existant_file
[[ $# == 1  && ! $1 ]] || err_exit '""~(N)/dev/nonexistant not null argument'
set -- ~(N)/dev/non_existant_file""
[[ $# == 1  && ! $1 ]] || err_exit '~(N)/dev/nonexistent"" not null argument'
for i in ~(N)/dev/non_existent_file
do	err_exit "~(N)/dev/non_existent_file in for loop is $i"
done
for i in ""~(N)/dev/non_existent_file
do	[[ ! $i ]] || err_exit '""~(N)/dev/non_existent_file not null'
done

exit $((Errors<125?Errors:125))
