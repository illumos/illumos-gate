#!./perl -w

use lib qw(t/lib);
use strict;

# Due to a bug in older versions of MakeMaker & Test::Harness, we must
# ensure the blib's are in @INC, else we might use the core CGI.pm
use lib qw(blib/lib blib/arch);

use Test;
our $loaded = 1;
BEGIN { 
	plan(tests => 86);
}
END {
	ok($loaded, 1, "Loaded");
}

use CGI::Util qw(escape unescape);
use POSIX qw(strftime);

# Required for backport from Test::More to Test.
sub eq_set  {
    my($a1, $a2) = @_;
    return 0 unless @$a1 == @$a2;
    my %h = map(( $_ => 1), @$a1);
    foreach $_ (@$a2) {
        $h{$_} += 2;
    }
    return (scalar(grep($_ != 3, values(%h))) == 0 ? 1 : 0);
}

#-----------------------------------------------------------------------------
# make sure module loaded
#-----------------------------------------------------------------------------

use CGI::Cookie;

my @test_cookie = (
		   'foo=123; bar=qwerty; baz=wibble; qux=a1',
		   'foo=123; bar=qwerty; baz=wibble;',
		   'foo=vixen; bar=cow; baz=bitch; qux=politician',
		   'foo=a%20phrase; bar=yes%2C%20a%20phrase; baz=%5Ewibble; qux=%27',
		   );

#-----------------------------------------------------------------------------
# Test parse
#-----------------------------------------------------------------------------

{
  my $result = CGI::Cookie->parse($test_cookie[0]);

  ok(ref($result), 'HASH', "Hash ref returned in scalar context");

  my @result = CGI::Cookie->parse($test_cookie[0]);

  ok(@result, 8, "returns correct number of fields");

  @result = CGI::Cookie->parse($test_cookie[1]);

  ok(@result, 6, "returns correct number of fields");

  my %result = CGI::Cookie->parse($test_cookie[0]);

  ok($result{foo}->value, '123', "cookie foo is correct");
  ok($result{bar}->value, 'qwerty', "cookie bar is correct");
  ok($result{baz}->value, 'wibble', "cookie baz is correct");
  ok($result{qux}->value, 'a1', "cookie qux is correct");
}

#-----------------------------------------------------------------------------
# Test fetch
#-----------------------------------------------------------------------------

{
  # make sure there are no cookies in the environment
  delete $ENV{HTTP_COOKIE};
  delete $ENV{COOKIE};

  my %result = CGI::Cookie->fetch();
  ok(keys %result == 0, 1, "No cookies in environment, returns empty list");

  # now set a cookie in the environment and try again
  $ENV{HTTP_COOKIE} = $test_cookie[2];
  %result = CGI::Cookie->fetch();
  ok(eq_set([keys %result], [qw(foo bar baz qux)]), 1,
     "expected cookies extracted");

  ok(ref($result{foo}), 'CGI::Cookie', 'Type of objects returned is correct');
  ok($result{foo}->value, 'vixen',      "cookie foo is correct");
  ok($result{bar}->value, 'cow',        "cookie bar is correct");
  ok($result{baz}->value, 'bitch',      "cookie baz is correct");
  ok($result{qux}->value, 'politician', "cookie qux is correct");

  # Delete that and make sure it goes away
  delete $ENV{HTTP_COOKIE};
  %result = CGI::Cookie->fetch();
  ok(keys %result == 0, 1, "No cookies in environment, returns empty list");

  # try another cookie in the other environment variable thats supposed to work
  $ENV{COOKIE} = $test_cookie[3];
  %result = CGI::Cookie->fetch();
  ok(eq_set([keys %result], [qw(foo bar baz qux)]), 1,
     "expected cookies extracted");

  ok(ref($result{foo}), 'CGI::Cookie', 'Type of objects returned is correct');
  ok($result{foo}->value, 'a phrase', "cookie foo is correct");
  ok($result{bar}->value, 'yes, a phrase', "cookie bar is correct");
  ok($result{baz}->value, '^wibble', "cookie baz is correct");
  ok($result{qux}->value, "'", "cookie qux is correct");
}

#-----------------------------------------------------------------------------
# Test raw_fetch
#-----------------------------------------------------------------------------

{
  # make sure there are no cookies in the environment
  delete $ENV{HTTP_COOKIE};
  delete $ENV{COOKIE};

  my %result = CGI::Cookie->raw_fetch();
  ok(keys %result == 0, 1, "No cookies in environment, returns empty list");

  # now set a cookie in the environment and try again
  $ENV{HTTP_COOKIE} = $test_cookie[2];
  %result = CGI::Cookie->raw_fetch();
  ok(eq_set([keys %result], [qw(foo bar baz qux)]), 1,
     "expected cookies extracted");

  ok(ref($result{foo}), '', 'Plain scalar returned');
  ok($result{foo}, 'vixen',      "cookie foo is correct");
  ok($result{bar}, 'cow',        "cookie bar is correct");
  ok($result{baz}, 'bitch',      "cookie baz is correct");
  ok($result{qux}, 'politician', "cookie qux is correct");

  # Delete that and make sure it goes away
  delete $ENV{HTTP_COOKIE};
  %result = CGI::Cookie->raw_fetch();
  ok(keys %result == 0, 1, "No cookies in environment, returns empty list");

  # try another cookie in the other environment variable thats supposed to work
  $ENV{COOKIE} = $test_cookie[3];
  %result = CGI::Cookie->raw_fetch();
  ok(eq_set([keys %result], [qw(foo bar baz qux)]), 1,
     "expected cookies extracted");

  ok(ref($result{foo}), '', 'Plain scalar returned');
  ok($result{foo}, 'a%20phrase', "cookie foo is correct");
  ok($result{bar}, 'yes%2C%20a%20phrase', "cookie bar is correct");
  ok($result{baz}, '%5Ewibble', "cookie baz is correct");
  ok($result{qux}, '%27', "cookie qux is correct");
}

#-----------------------------------------------------------------------------
# Test new
#-----------------------------------------------------------------------------

{
  # Try new with full information provided
  my $c = CGI::Cookie->new(-name    => 'foo',
			   -value   => 'bar',
			   -expires => '+3M',
			   -domain  => '.capricorn.com',
			   -path    => '/cgi-bin/database',
			   -secure  => 1
			  );
  ok(ref($c), 'CGI::Cookie', 'new returns objects of correct type');
  ok($c->name   , 'foo',               'name is correct');
  ok($c->value  , 'bar',               'value is correct');
  ok($c->expires, '/(?i)^[a-z]{3},\s*\d{2}-[a-z]{3}-\d{4}/', 'expires in correct format');
  ok($c->domain , '.capricorn.com',    'domain is correct');
  ok($c->path   , '/cgi-bin/database', 'path is correct');
  ok($c->secure , 1, 'secure attribute is set');

  # now try it with the only two manditory values (should also set the default path)
  $c = CGI::Cookie->new(-name    =>  'baz',
			-value   =>  'qux',
		       );
  ok(ref($c), 'CGI::Cookie', 'new returns objects of correct type');
  ok($c->name   , 'baz', 'name is correct');
  ok($c->value  , 'qux', 'value is correct');
  ok(!defined $c->expires, 1,       'expires is not set');
  ok(!defined $c->domain, 1,       'domain attributeis not set');
  ok($c->path, '/',      'path atribute is set to default');
  ok(!defined $c->secure, 1,       'secure attribute is set');

# I'm really not happy about the restults of this section.  You pass
# the new method invalid arguments and it just merilly creates a
# broken object :-)
# I've commented them out because they currently pass but I don't
# think they should.  I think this is testing broken behaviour :-(

#    # This shouldn't work
#    $c = CGI::Cookie->new(-name => 'baz' );
#
#    ok(ref($c), 'CGI::Cookie', 'new returns objects of correct type');
#    ok($c->name   , 'baz',     'name is correct');
#    ok(!defined $c->value, "Value is undefined ");
#    ok(!defined $c->expires, 'expires is not set');
#    ok(!defined $c->domain , 'domain attributeis not set');
#    ok($c->path   , '/', 'path atribute is set to default');
#    ok(!defined $c->secure , 'secure attribute is set');

}

#-----------------------------------------------------------------------------
# Test as_string
#-----------------------------------------------------------------------------

{
  my $c = CGI::Cookie->new(-name    => 'Jam',
			   -value   => 'Hamster',
			   -expires => '+3M',
			   -domain  => '.pie-shop.com',
			   -path    => '/',
			   -secure  => 1
			  );

  my $name = $c->name;
  ok($c->as_string, "/$name/", "Stringified cookie contains name");

  my $value = $c->value;
  ok($c->as_string, "/$value/", "Stringified cookie contains value");

  my $expires = $c->expires;
  ok($c->as_string, "/$expires/", "Stringified cookie contains expires");

  my $domain = $c->domain;
  ok($c->as_string, "/$domain/", "Stringified cookie contains domain");

  my $path = $c->path;
  ok($c->as_string, "/$path/", "Stringified cookie contains path");

  ok($c->as_string, '/secure/', "Stringified cookie contains secure");

  $c = CGI::Cookie->new(-name    =>  'Hamster-Jam',
			-value   =>  'Tulip',
		       );

  $name = $c->name;
  ok($c->as_string, "/$name/", "Stringified cookie contains name");

  $value = $c->value;
  ok($c->as_string, "/$value/", "Stringified cookie contains value");

  ok($c->as_string !~ /expires/, 1, "Stringified cookie has no expires field");

  ok($c->as_string !~ /domain/, 1, "Stringified cookie has no domain field");

  $path = $c->path;
  ok($c->as_string, "/$path/", "Stringified cookie contains path");

  ok($c->as_string !~ /secure/, 1, "Stringified cookie does not contain secure");
}

#-----------------------------------------------------------------------------
# Test compare
#-----------------------------------------------------------------------------

{
  my $c1 = CGI::Cookie->new(-name    => 'Jam',
			    -value   => 'Hamster',
			    -expires => '+3M',
			    -domain  => '.pie-shop.com',
			    -path    => '/',
			    -secure  => 1
			   );

  # have to use $c1->expires because the time will occasionally be
  # different between the two creates causing spurious failures.
  my $c2 = CGI::Cookie->new(-name    => 'Jam',
			    -value   => 'Hamster',
			    -expires => $c1->expires,
			    -domain  => '.pie-shop.com',
			    -path    => '/',
			    -secure  => 1
			   );

  # This looks titally whacked, but it does the -1, 0, 1 comparison
  # thing so 0 means they match
  ok($c1->compare("$c1"), 0, "Cookies are identical");
  ok($c1->compare("$c2"), 0, "Cookies are identical");

  $c1 = CGI::Cookie->new(-name   => 'Jam',
			 -value  => 'Hamster',
			 -domain => '.foo.bar.com'
			);

  # have to use $c1->expires because the time will occasionally be
  # different between the two creates causing spurious failures.
  $c2 = CGI::Cookie->new(-name    =>  'Jam',
			 -value   =>  'Hamster',
			);

  # This looks titally whacked, but it does the -1, 0, 1 comparison
  # thing so 0 (i.e. false) means they match
  ok($c1->compare("$c1"), 0, "Cookies are identical");
  ok($c1->compare("$c2"), -1, "Cookies are not identical");

  $c2->domain('.foo.bar.com');
  ok($c1->compare("$c2"), 0, "Cookies are identical");
}

#-----------------------------------------------------------------------------
# Test name, value, domain, secure, expires and path
#-----------------------------------------------------------------------------

{
  my $c = CGI::Cookie->new(-name    => 'Jam',
			   -value   => 'Hamster',
			   -expires => '+3M',
			   -domain  => '.pie-shop.com',
			   -path    => '/',
			   -secure  => 1
			   );

  ok($c->name,          'Jam',   'name is correct');
  ok($c->name('Clash'), 'Clash', 'name is set correctly');
  ok($c->name,          'Clash', 'name now returns updated value');

  # this is insane!  it returns a simple scalar but can't accept one as
  # an argument, you have to give it an arrary ref.  It's totally
  # inconsitent with these other methods :-(
  ok($c->value,           'Hamster', 'value is correct');
  ok($c->value(['Gerbil']), 'Gerbil',  'value is set correctly');
  ok($c->value,           'Gerbil',  'value now returns updated value');

  my $exp = $c->expires;
  ok($c->expires,         '/(?i)^[a-z]{3},\s*\d{2}-[a-z]{3}-\d{4}/', 'expires is correct');
  ok($c->expires('+12h'), '/(?i)^[a-z]{3},\s*\d{2}-[a-z]{3}-\d{4}/', 'expires is set correctly');
  ok($c->expires,         '/(?i)^[a-z]{3},\s*\d{2}-[a-z]{3}-\d{4}/', 'expires now returns updated value');
  ok($c->expires ne $exp, 1, "Expiry time has changed");

  ok($c->domain,                  '.pie-shop.com', 'domain is correct');
  ok($c->domain('.wibble.co.uk'), '.wibble.co.uk', 'domain is set correctly');
  ok($c->domain,                  '.wibble.co.uk', 'domain now returns updated value');

  ok($c->path,             '/',        'path is correct');
  ok($c->path('/basket/'), '/basket/', 'path is set correctly');
  ok($c->path,             '/basket/', 'path now returns updated value');

  ok($c->secure, 1,     'secure attribute is set');
  ok($c->secure(0), 0, 'secure attribute is cleared');
  ok($c->secure, 0,    'secure attribute is cleared');
}
