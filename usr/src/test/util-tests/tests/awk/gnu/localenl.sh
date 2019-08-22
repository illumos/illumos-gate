#! /bin/sh
# From arnold@f7.net  Sun Apr 22 20:15:25 2007
# Date: Thu, 19 Apr 2007 17:09:02 +0300
# From: Pekka Pessi <Pekka.Pessi@nokia.com>
# X-Face: #V(jdpv[lI!TNUU=2*oh:="#suS*ponXW"yr6G;~L}<xZn_2^0)V{jqdc4y}@2b]ffd}SY#
#  :9||1pew85O,WjiYA"6C7bW^zt^+.{b#B{lEE+4$9lrXL(55g}dU>uZ\JfD\"IG#G{j`hZI;=DmT\H
#  pfDMyJ`i=:M;BM3R.`[>P^ER8+]i
# Subject: UTF-8 locale and \n in regexps
# To: bug-gawk@gnu.org
# Cc: Pekka.Pessi@nokia.com
# Message-id: <pvlkgoh2wx.fsf@nokia.com>
# MIME-version: 1.0
# Content-type: multipart/mixed; boundary="=-=-="
# 
# --=-=-=
# 
# Hello,
# 
# It looks like regexp with \n in [^] behaves badly if locale has
# an UTF-8 ctype.
# 
# It looks like if there is \n and an range without \n, like /\n[^x\n]foo/,
# and first \n ends an even-numbered line within the string, regexp
# does not match.
# 
# Please see the attached script for an demonstration.
# 
# --Pekka Pessi
# 
# 
# --=-=-=
# Content-Disposition: inline; filename=gawk-test
# 
#! /bin/sh

if [ -z "$AWK" ]; then
    printf '$AWK must be set\n' >&2
    exit 1
fi

# April 2010: Remove UNKNOWN, causes spurious failures on some systems
for LC_ALL in C POSIX en_US.ISO8859-1 en_US.UTF-8 #UNKNOWN 
do
export LC_ALL
cat <<EOF |
line1
line2
line3
line4 
line5
line6
line7
line8
line9
EOF
$AWK '
BEGIN { RS="\0"; }
{ 
  if (match($0, /\n[^2\n]*2/)) { got2=1; } else { print "no match 2"; }
  if (match($0, /\n[^3\n]*3/)) { got3=1; } else { print "no match 3"; }
  if (match($0, /\n[^4\n]*4/)) { got4=1; } else { print "no match 4"; }
  if (match($0, /\n[^5\t]*5/)) { got5=1; } else { print "no match 5"; }
  if (match($0, /\n[^6\n]*6/)) { got6=1; } else { print "no match 6"; }
  if (match($0, /\n[a-z]*7\n/)){ got7=1; } else { print "no match 7"; }
  if (match($0, /\n[^8\n]*8/)) { got8=1; } else { print "no match 8"; }
  if (match($0, /8.[^9\n]+9/)) { got9=1; } else { print "no match 9"; }
}

END { exit(!(got2 && got3 && got4 && got5 && got6 && got7 && got8 && got9)); }
' || { 
  echo LC_ALL=$LC_ALL FAILED
  exit 1
}
echo LC_ALL=$LC_ALL passed
done
# 
# --=-=-=--
# 
