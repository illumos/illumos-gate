#!/bin/bash

if [[ -z "$AWK" || -z "$WORKDIR" ]]; then
    printf '$AWK and $WORKDIR must be set\n' >&2
    exit 1
fi

TEMP0=$WORKDIR/test.temp.0
TEMP1=$WORKDIR/test.temp.1
TEMP2=$WORKDIR/test.temp.2

RESULT=0

fail() {
	echo "$1" >&2
	RESULT=1
}

echo T.gawk: tests adapted from gawk test suite
# for which thanks.

# arrayref:  
echo '1
1' > $TEMP1
$AWK '
	BEGIN { # foo[10] = 0		# put this line in and it will work
		test(foo); print foo[1]
		test2(foo2); print foo2[1]
	}
	function test(foo) { test2(foo) }
	function test2(bar) { bar[1] = 1 }
' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk arrayref'

# asgext
echo '1 2 3
1
1 2 3 4' > $TEMP0
echo '3
1 2 3 a

1   a
3
1 2 3 a' > $TEMP1
$AWK '{ print $3; $4 = "a"; print }' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk asgext'

# backgsub:
echo 'x\y
x\\y' > $TEMP0
echo 'x\y
xAy
xAy
xAAy' > $TEMP1
$AWK '{	x = y = $0
        gsub( /\\\\/, "A", x); print x
        gsub( "\\\\", "A", y); print y
}' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk backgsub'


# backgsub2:
echo 'x\y
x\\y
x\\\y' > $TEMP0
echo '	x\y
	x\y
	x\y
	x\y
	x\\y
	x\\\y
	x\\y
	x\\\y
	x\\\\y' > $TEMP1
$AWK '{	w = x = y = z = $0
        gsub( /\\\\/, "\\", w); print "	" w
        gsub( /\\\\/, "\\\\", x); print "	" x
        gsub( /\\\\/, "\\\\\\", y); print "	" y
}
' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk backgsub2'


# backgsub3:
echo 'xax
xaax' > $TEMP0
echo '	xax
	x&x
	x&x
	x\ax
	x\ax
	x\&x
	xaax
	x&&x
	x&&x
	x\a\ax
	x\a\ax
	x\&\&x' > $TEMP1
$AWK '{	w = x = y = z = z1 = z2 = $0
        gsub( /a/, "\&", w); print "	" w
        gsub( /a/, "\\&", x); print "	" x
        gsub( /a/, "\\\&", y); print "	" y
        gsub( /a/, "\\\\&", z); print "	" z
        gsub( /a/, "\\\\\&", z1); print "	" z1
        gsub( /a/, "\\\\\\&", z2); print "	" z2
}
' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk backgsub3'


# backsub3:
echo 'xax
xaax' > $TEMP0
echo '	xax
	x&x
	x&x
	x\ax
	x\ax
	x\&x
	xaax
	x&ax
	x&ax
	x\aax
	x\aax
	x\&ax' > $TEMP1
$AWK '{	w = x = y = z = z1 = z2 = $0
        sub( /a/, "\&", w); print "	" w
        sub( /a/, "\\&", x); print "	" x
        sub( /a/, "\\\&", y); print "	" y
        sub( /a/, "\\\\&", z); print "	" z
        sub( /a/, "\\\\\&", z1); print "	" z1
        sub( /a/, "\\\\\\&", z2); print "	" z2
}
' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk backsub3'


# backsub:
echo 'x\y
x\\y' > $TEMP0
echo 'x\y
x\\y
x\\y
x\\\y' > $TEMP1
$AWK '{	x = y = $0
        sub( /\\\\/, "\\\\", x); print x
        sub( "\\\\", "\\\\", y); print y
}' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk backsub'




# dynlj:  
echo 'hello               world' > $TEMP1
$AWK 'BEGIN { printf "%*sworld\n", -20, "hello" }' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk dynlj'

# fsrs:  
echo 'a b
c d
e f

1 2
3 4
5 6' > $TEMP0
# note -n:
echo -n 'a b
c d
e f1 2
3 4
5 6' > $TEMP1
$AWK '
BEGIN {
       RS=""; FS="\n";
       ORS=""; OFS="\n";
      }
{
        split ($2,f," ")
        print $0;
}' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk fsrs'

# intest
echo '0 1' > $TEMP1
$AWK 'BEGIN {
	bool = ((b = 1) in c);
	print bool, b	# gawk-3.0.1 prints "0 "; should print "0 1"
}' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk intest'

# intprec:  
echo '0000000005:000000000e' > $TEMP1
$AWK 'BEGIN { printf "%.10d:%.10x\n", 5, 14 }' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk intprec'

# litoct:  
echo 'axb
ab
a*b' > $TEMP0
echo 'no match
no match
match' > $TEMP1
$AWK '{ if (/a\52b/) print "match" ; else print "no match" }' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk litoct'

# math:  
echo 'cos(0.785398) = 0.707107
sin(0.785398) = 0.707107
e = 2.718282
log(e) = 1.000000
sqrt(pi ^ 2) = 3.141593
atan2(1, 1) = 0.785398' > $TEMP1
$AWK 'BEGIN {
	pi = 3.1415927
	printf "cos(%f) = %f\n", pi/4, cos(pi/4)
	printf "sin(%f) = %f\n", pi/4, sin(pi/4)
	e = exp(1)
	printf "e = %f\n", e
	printf "log(e) = %f\n", log(e)
	printf "sqrt(pi ^ 2) = %f\n", sqrt(pi ^ 2)
	printf "atan2(1, 1) = %f\n", atan2(1, 1)
}' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk math'

# nlfldsep:  
echo 'some stuff
more stuffA
junk
stuffA
final' > $TEMP0
echo '4
some
stuff
more
stuff

2
junk
stuff

1
final
' > $TEMP1
$AWK 'BEGIN { RS = "A" }
{print NF; for (i = 1; i <= NF; i++) print $i ; print ""}
' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk nlfldsep'

# numsubstr:  
echo '5000
10000
5000' > $TEMP0
echo '000
1000
000' > $TEMP1
$AWK '{ print substr(1000+$1, 2) }' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk numsubstr'

# pcntplus:  
echo '+3 4' > $TEMP1
$AWK 'BEGIN { printf "%+d %d\n", 3, 4 }' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk pcntplus'

# prt1eval:  
echo 1 > $TEMP1
$AWK 'function tst () {
	sum += 1
	return sum
}
BEGIN { OFMT = "%.0f" ; print tst() }
' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk prt1eval'

# reparse:  
echo '1 axbxc 2' > $TEMP0
echo '1
1 a b c 2
1 a b' > $TEMP1
$AWK '{	gsub(/x/, " ")
	$0 = $0
	print $1
	print $0
	print $1, $2, $3
}' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk reparse'

# rswhite:  
echo '    a b
c d' > $TEMP0
echo '<    a b
c d>' > $TEMP1
$AWK 'BEGIN { RS = "" }
{ printf("<%s>\n", $0) }' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk rswhite'

# splitvar:  
echo 'Here===Is=Some=====Data' > $TEMP0
echo 4 > $TEMP1
$AWK '{	sep = "=+"
	n = split($0, a, sep)
	print n
}' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk splitvar'

# splitwht:  
echo '4
5' > $TEMP1
$AWK 'BEGIN {
	str = "a   b\t\tc d"
	n = split(str, a, " ")
	print n
	m = split(str, b, / /)
	print m
}' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk splitwht'

# sprintfc:  
echo '65
66
foo' > $TEMP0
echo 'A 65
B 66
f foo' > $TEMP1
$AWK '{ print sprintf("%c", $1), $1 }' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk sprintfc'

# substr:  
echo 'xxA                                      
xxab
xxbc
xxab
xx
xx
xxab
xx
xxef
xx' > $TEMP1
$AWK 'BEGIN {
	x = "A"
	printf("xx%-39s\n", substr(x,1,39))
	print "xx" substr("abcdef", 0, 2)
	print "xx" substr("abcdef", 2.3, 2)
	print "xx" substr("abcdef", -1, 2)
	print "xx" substr("abcdef", 1, 0)
	print "xx" substr("abcdef", 1, -3)
	print "xx" substr("abcdef", 1, 2.3)
	print "xx" substr("", 1, 2)
	print "xx" substr("abcdef", 5, 5)
	print "xx" substr("abcdef", 7, 2)
	exit (0)
}' > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk substr'

# fldchg:  
echo 'aa aab c d e f' > $TEMP0
echo '1: + +b c d e f
2: + +b <c> d e f
2a:%+%+b%<c>%d%e' > $TEMP1
$AWK '{	gsub("aa", "+")
	print "1:", $0
	$3 = "<" $3 ">"
	print "2:", $0
	print "2a:" "%" $1 "%" $2 "%" $3 "%" $4 "%" $5
}' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk fldchg'

# fldchgnf:  
echo 'a b c d' > $TEMP0
echo 'a::c:d
4' > $TEMP1
$AWK '{ OFS = ":"; $2 = ""; print $0; print NF }' $TEMP0 > $TEMP2
diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk fldchgnf'

# OFMT from arnold robbins 6/02:
#	5.7 with OFMT = %0.f is 6
echo '6' > $TEMP1
$AWK 'BEGIN {
	OFMT = "%.0f"
	print 5.7
}' > $TEMP2
cmp -s $TEMP1 $TEMP2 || fail 'BAD: T.gawk ofmt'


### don't know what this is supposed to do now.
### # convfmt:  
### echo 'a = 123.46
### a = 123.456
### a = 123.456' > $TEMP1
### $AWK 'BEGIN {
### 	CONVFMT = "%2.2f"
### 	a = 123.456
### 	b = a ""                # give a string value also
### 	a += 0                  # make a numeric only again
### 	print "a = ", a
### 	CONVFMT = "%.6g"
### 	print "a = ", a
### 	a += 0                  # make a numeric only again
### 	print "a = ", a    # use a as string
### }' > $TEMP2
### diff $TEMP1 $TEMP2 || fail 'BAD: T.gawk convfmt'

exit $RESULT
