#!./perl

BEGIN {
  chdir 't' if -d 't';
  @INC = '../lib';
}

BEGIN {
  our @TEST = stat "TEST";
  our @harness = stat "harness";
  unless (@TEST && @harness) {
    print "1..0 # Skip: no file TEST or harness\n";
    exit 0;
  }
}

print "1..12\n";

use File::Compare qw(compare compare_text);

print "ok 1\n";

# named files, same, existing but different, cause an error
print "not " unless compare("harness","harness") == 0;
print "ok 2\n";

print "not " unless compare("TEST","harness") == 1;
print "ok 3\n";

print "not " unless compare("harness","HLAGHLAG") == -1;
                               # a file which doesn't exist
print "ok 4\n";

# compare_text, the same file, different but existing files
# cause error, test sub form.
print "not " unless compare_text("harness","harness") == 0;
print "ok 5\n";

print "not " unless compare_text("TEST","harness") == 1;
print "ok 6\n";

print "not " unless compare_text("TEST","HLAGHLAG") == -1;
print "ok 7\n";

print "not " unless
  compare_text("harness","harness",sub {$_[0] ne $_[1]}) == 0;
print "ok 8\n";

# filehandle and same file
{
  my $fh;
  open ($fh, "<harness") or print "not ";
  binmode($fh);
  print "not " unless compare($fh,"harness") == 0;
  print "ok 9\n";
  close $fh;
}

# filehandle and different (but existing) file.
{
  my $fh;
  open ($fh, "<harness") or print "not ";
  binmode($fh);
  print "not " unless compare_text($fh,"TEST") == 1;
  print "ok 10\n";
  close $fh;
}

# Different file with contents of known file,
# will use File::Temp to do this, skip rest of
# tests if this doesn't seem to work

my @donetests;
eval {
  require File::Spec; import File::Spec;
  require File::Path; import File::Path;
  require File::Temp; import File::Temp qw/ :mktemp unlink0 /;

  my $template = File::Spec->catfile(File::Spec->tmpdir, 'fcmpXXXX');
  my($tfh,$filename) = mkstemp($template);
  {
    local $/; #slurp
    my $fh;
    open($fh,'harness');
    binmode($fh);
    my $data = <$fh>;
    print $tfh $data;
    close($fh);
  }
  seek($tfh,0,0);
  $donetests[0] = compare($tfh, 'harness');
  $donetests[1] = compare($filename, 'harness');
  unlink0($tfh,$filename);
};
print "# problems when testing with a tempory file\n" if $@;

if (@donetests == 2) {
  print "not " unless $donetests[0] == 0;
  print "ok 11\n";
  if ($^O eq 'VMS') {
    # The open attempt on FROM in File::Compare::compare should fail
    # on this OS since files are not shared by default.
    print "not " unless $donetests[1] == -1;
    print "ok 12\n";
  }
  else {
    print "not " unless $donetests[1] == 0;
    print "ok 12\n";
  }
}
else {
  print "ok 11# Skip\nok 12 # Skip Likely due to File::Temp\n";
}

