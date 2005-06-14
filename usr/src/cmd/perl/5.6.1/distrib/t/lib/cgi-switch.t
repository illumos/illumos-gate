#!./perl -w

use lib qw(t/lib);

# Due to a bug in older versions of MakeMaker & Test::Harness, we must
# ensure the blib's are in @INC, else we might use the core CGI.pm
use lib qw(blib/lib blib/arch);

use strict;
use Test;
our $loaded = 1;
BEGIN { 
	plan(tests => 1);
}
END {
	ok($loaded, 1, "Loaded");
}

# Can't do much with this other than make sure it loads properly
use CGI::Switch;
