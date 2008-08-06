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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

use strict;
use warnings;
use Config;
our $VERSION = '1.2';

my $fh;
open($fh, ">$ARGV[0]") || die("Can't open perlgcc: $!\n");

my $perlver = sprintf('%vd', $^V);
my $startperl = $Config{startperl};
my $perlpath = $Config{perlpath};
my $privlib = "$Config{installprivlib}/Sun/Solaris/PerlGcc";

print $fh <<EOF;
$startperl
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

use $perlver;
use strict;
use warnings;
our \$VERSION = '$VERSION';

\$ENV{PERL5_OVERRIDE_CONFIG} = '1';
if (exists(\$ENV{PERL5LIB})) {
	\$ENV{PERL5LIB} =
	    "$privlib:\$ENV{PERL5LIB}";
} else {
	\$ENV{PERL5LIB} =
	    '$privlib';
}
exec('$perlpath', \@ARGV)
    || die("Can't exec $perlpath: \$!\\n");
EOF
close($fh) || die("Can't open perlgcc: $!\n");
exit(0);
