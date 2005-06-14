" #ident	"@(#)terminfo:cvt.ex	1.2"
"
" CDDL HEADER START
"
" The contents of this file are subject to the terms of the
" Common Development and Distribution License, Version 1.0 only
" (the "License").  You may not use this file except in compliance
" with the License.
"
" You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
" or http://www.opensolaris.org/os/licensing.
" See the License for the specific language governing permissions
" and limitations under the License.
"
" When distributing Covered Code, include this CDDL HEADER in each
" file and include the License file at usr/src/OPENSOLARIS.LICENSE.
" If applicable, add the following below this CDDL HEADER, with the
" fields enclosed by brackets "[]" replaced with your own identifying
" information: Portions Copyright [yyyy] [name of copyright owner]
"
" CDDL HEADER END
"
" Defend against files with spaces instead of tabs
g/^  *:/s/^ */	/
" Clean out all junk lines, making them into comments.
v/^[#	A-Za-z]/s/^/# /
g/^[	A-Za-z].*[^\\:]$/s/^/# /
" Get rid of capabilities on the first line.
g/^[a-zA-Z].|.*:.*:/s/:/:\\\
	/
" Change colons to commas, with appropriate white space
v/^#/s/,/\\054/g
v/^#/s/:/, /g
v/^#/s/^	, /	/
v/^#/s/, \\$/,/
" Get rid of two letter codes
g/^[a-zA-Z].|/s///|s/$/HEADER/
" Change names of capabilities - this list to be updated from caps
v/^#/s/\<mi\>/mir/g
v/^#/s/\<ms\>/msgr/g
v/^#/s/\<pt\>/ht=^I/g
v/^#/s/\<xb\>/xsb/g
v/^#/s/\<xn\>/xenl/g
v/^#/s/\<xo\>/xon/g
v/^#/s/\<xs\>/xhp/g
v/^#/s/\<co\>/cols/g
v/^#/s/\<li\>/lines/g
v/^#/s/\<sg\>/xmc/g
v/^#/s/\<AL\>/il/g
v/^#/s/\<CC\>/CC/g
v/^#/s/\<DL\>/dl/g
v/^#/s/\<DO\>/cud/g
v/^#/s/\<LE\>/cub/g
v/^#/s/\<RI\>/cuf/g
v/^#/s/\<UP\>/cuu/g
v/^#/s/\<ae\>/smacs/g
v/^#/s/\<al\>/il1/g
v/^#/s/\<as\>/rmacs/g
v/^#/s/\<bl\>/bel/g
v/^#/s/\<bt\>/cbt/g
v/^#/s/\<ce\>/el/g
v/^#/s/\<ch\>/hpa/g
v/^#/s/\<cl\>/clear/g
v/^#/s/\<cm\>/cup/g
v/^#/s/\<cs\>/csr/g
v/^#/s/\<ct\>/tbc/g
v/^#/s/\<cv\>/vpa/g
v/^#/s/\<dc\>/dch1/g
v/^#/s/\<dl\>/dl1/g
v/^#/s/\<dm\>/smdc/g
v/^#/s/\<do\>/cud1/g
v/^#/s/\<ed\>/rmdc/g
v/^#/s/\<cd\>/ed/g
v/^#/s/\<ei\>/rmir/g
v/^#/s/\<fs\>/fsl/g
v/^#/s/\<ho\>/home/g
v/^#/s/\<is\>/is2/g
v/^#/s/\<ic\>/ich1/g
v/^#/s/\<im\>/smir/g
v/^#/s/\<k0\>/kf0/g
v/^#/s/\<k1\>/kf1/g
v/^#/s/\<k2\>/kf2/g
v/^#/s/\<k3\>/kf3/g
v/^#/s/\<k4\>/kf4/g
v/^#/s/\<k5\>/kf5/g
v/^#/s/\<k6\>/kf6/g
v/^#/s/\<k7\>/kf7/g
v/^#/s/\<k8\>/kf8/g
v/^#/s/\<k9\>/kf9/g
v/^#/s/\<kA\>/kil1/g
v/^#/s/\<kC\>/kclr/g
v/^#/s/\<kD\>/kdch/g
v/^#/s/\<kE\>/kel/g
v/^#/s/\<kF\>/kind/g
v/^#/s/\<kI\>/kich1/g
v/^#/s/\<kL\>/kdl1/g
v/^#/s/\<kM\>/krmir/g
v/^#/s/\<kN\>/knp/g
v/^#/s/\<kP\>/kpp/g
v/^#/s/\<kR\>/kri/g
v/^#/s/\<kS\>/ked/g
v/^#/s/\<kT\>/khts/g
v/^#/s/\<ka\>/ktbc/g
v/^#/s/\<kb\>/kbs/g
v/^#/s/\<kd\>/kcud1/g
v/^#/s/\<ke\>/rmkx/g
v/^#/s/\<kh\>/khome/g
v/^#/s/\<kl\>/kcub1/g
v/^#/s/\<kr\>/kcuf1/g
v/^#/s/\<ks\>/smkx/g
v/^#/s/\<kt\>/kctab/g
v/^#/s/\<ku\>/kcuu1/g
v/^#/s/\<l0\>/lf0/g
v/^#/s/\<l1\>/lf1/g
v/^#/s/\<l2\>/lf2/g
v/^#/s/\<l3\>/lf3/g
v/^#/s/\<l4\>/lf4/g
v/^#/s/\<l5\>/lf5/g
v/^#/s/\<l6\>/lf6/g
v/^#/s/\<l7\>/lf7/g
v/^#/s/\<l8\>/lf8/g
v/^#/s/\<l9\>/lf9/g
v/^#/s/\<bs\>/cub1=^H/g
v/^#/s/\<bc\>/cub1/g
v/^#/s/\<mb\>/blink/g
v/^#/s/\<md\>/bold/g
v/^#/s/\<me\>/sgr0/g
v/^#/s/\<mh\>/dim/g
v/^#/s/\<mk\>/blank/g
v/^#/s/\<mp\>/prot/g
v/^#/s/\<mr\>/rev/g
v/^#/s/\<nd\>/cuf1/g
v/^#/s/\<nw\>/nel/g
v/^#/s/\<pc\>/pad/g
v/^#/s/\<pf\>/mc4/g
v/^#/s/\<po\>/mc5/g
v/^#/s/\<ps\>/mc0/g
v/^#/s/\<rs\>/rs2/g
v/^#/s/\<rp\>/rep/g
v/^#/s/\<ri\>/cuf1/g
v/^#/s/\<sa\>/sgr/g
v/^#/s/\<se\>/rmso/g
v/^#/s/\<sf\>/ind/g
v/^#/s/\<so\>/smso/g
v/^#/s/\<sr\>/ri/g
v/^#/s/\<st\>/hts/g
v/^#/s/\<ta\>/ht/g
v/^#/s/\<te\>/rmcup/g
v/^#/s/\<ti\>/smcup/g
v/^#/s/\<ts\>/tsl/g
v/^#/s/\<ue\>/rmul/g
v/^#/s/\<up\>/cuu1/g
v/^#/s/\<us\>/smul/g
v/^#/s/\<vb\>/flash/g
v/^#/s/\<ve\>/cnorm/g
v/^#/s/\<vi\>/civis/g
v/^#/s/\<vs\>/cvvis/g
v/^#/s/\<wi\>/wind/g
" Deal with changes in default rules
g/HEADER/s/$/\
	cr=^M, cud1=^J, ind=^J, bel=^G,
$a
# junk
.
g/HEADER/+,/^[^	]/-!fmt
g/HEADER/s///
g/\<nc\>,/s///|?cr=^M, ?s///
g/\<ns\>,/s///|?ind=^J, ?s///
" Still should do something about the cr=, nl=, tab= capabilities.
" Change parameterized strings
v/^#/s/%\./%p1%c/
v/^#/s/%\./%p2%c/
v/^#/s/%\./%p1%c/
v/^#/s/%\./%p2%c/
v/^#/s/%d/%p1%DECIMAL/
v/^#/s/%d/%p2%DECIMAL/
v/^#/s/%d/%p1%DECIMAL/
v/^#/s/%d/%p2%DECIMAL/
v/^#/s/DECIMAL/d/g
v/^#/s/%+\([^%]\)/%p1%'\1'%+%c/
v/^#/s/%+\([^%]\)/%p2%'\1'%+%c/
v/^#/s/%+\([^%]\)/%p1%'\1'%+%c/
v/^#/s/%+\([^%]\)/%p2%'\1'%+%c/
$g/^# junk$/d
w
q
