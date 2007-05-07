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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# <t> xmlHandlers -- package for generating a tree from an XML doc

use XML::Parser;

package xmlHandlers;

$level = -1;

%endCallback = ();
%startCallback = ();

$currentObj = 0;
@objStack = ();

1;

# <s> methods

# pkg reference, object name (tag), optional fileName.


sub new {
    my $pkg = shift;
    my $parent = shift;   # ref to parent object
    my $class = shift;     # for debug use

    my @kids = ();        # list of child objects

    push (@objStack, $parent);
    $currentObj = bless {'class'       => $class,
	                 'kids'       => \@kids,
#			 'parent'     => $parent,
		         'attributes' => 0,
		         'content'    => ''}, $pkg;

    if (@_) {               # if fileName passed, go!
	die "parent for document creation must be null"
	    if ($parent);
	executeXML (shift);
    }
    return $currentObj;
}

# we'll call you when your object is started
# class method

sub registerStartCallback {
    my $objName = shift;  #  call me when you get <objName>
    my $callback = shift; #  \&foo($objRef, $source);

    if ($startCallback{$objName}) {
	print STDERR "duplicate callback for $objName\n";
	return;
    }
    $startCallback{$objName} =  $callback;
}


# we'll call you when your object is completed
# class method

sub registerEndCallback {
    my $objName = shift;  #  call me when you get </objName>
    my $callback = shift; #  \&foo($objRef);

    if ($endCallback{$objName}) {
	print STDERR "duplicate callback for $objName\n";
	return;
    }
    $endCallback{$objName} =  $callback;
}

sub start {
}
sub end {
}

sub char {
    my ($obj, $class, $string) = @_;


}

sub add {
    my $parent = shift;
    my $kid = shift;

    push (@{$parent->{'kids'}}, $kid);
#    $kid->{'parent'} = $parent;
}

# <s> internal functions
sub executeXML {
    my $file = shift;

    # ErrorContext  - 0 don't report errors
    #               - other = number of lines to display
    # ParseparamEnt - 1 allow parsing of dtd
    my $parser = XML::Parser->new(ErrorContext => 1,
				  ParseParamEnt => 1);
    
    $parser->setHandlers (Char       => \&charHandler,
			  Start      => \&startHandler,
			  Default    => \&defaultHandler,
			  End        => \&endHandler,
			  Proc       => \&procHandler,
			  Comment    => \&commentHandler,
			  ExternEnt  => \&externalHandler);

    $parser->parsefile ($file);
}

sub charHandler {
    my ($xmlObj, $string) = @_;

    chomp $string;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    unless ($string =~ /^\s*$/) {
#	print "charHandler: $currentObj->{'class'} $string\n" if $main::debug;
	$currentObj->{'content'} .= ' ' if ($currentObj->{'content'});
	$currentObj->{'content'} .= $string;
    }
}

# create new object and attach to tree

sub startHandler {
    my $xmlObj = shift;
    my $tag = shift;

    my $obj;
    my $parent = $currentObj;

    $obj = new xmlHandlers($currentObj, $tag);

    $parent->add ($obj);

    $obj->processAttributes ($tag, @_);

    my $functionRef;
    if ($functionRef = $startCallback{$tag}) {
	&$functionRef($obj, 'start');
    }
    elsif ($main::debug) {
#	print "no start callback for $tag\n";
    }
}

sub endHandler {
    my $xmlObj = shift;
    my $element = shift;

#    print "end tag $element\n" if $main::debug;

    my $functionRef;
    if ($functionRef = $endCallback{$element}) {
	&$functionRef($currentObj, 'end');
    }
    elsif ($main::debug) {
#	print "no end callback for $element\n";
    }
#    $currentObj = $currentObj->{'parent'};
    $currentObj = pop (@objStack);
}

sub defaultHandler {
    my ($obj, $string) = @_;

    unless (!$main::debug || ($string =~ /^\s*$/)) {
	if ($string =~ /<\?xml/) {
	    $string =~ s/<\?\S+\s+(.*)/$1/;
	    my (%parameters) = 
		parseProcInstruction ($string);
	    print STDERR "Got call to default, guessed what to do: $string\n";
	}
	else {
	    print STDERR "Got call to default, didn't know what to do: $string\n";
	}
    }
}

sub externalHandler {
    my ($obj, $base, $sysid, $pubid) = @_;

    $base = '' if !$base;
    $pubid = '' if !$pubid;
    print "external:  base $base\nexternal:  sysid $sysid\nexternal:  pubid $pubid\n";
}

sub commentHandler {
    my ($obj, $element) = @_;

    return unless $main::debug;

    unless ($element =~ /^\s*$/) {
	print "comment:  $element\n";
    }
}

sub procHandler {
    my $xmlObj = shift;
    my $target = shift;
    my $data   = shift;

    my (%parameters) = 
      parseProcInstruction ($data);

    $currentObj->processAttributes ($target, $data, @_);
}
#<s> misc subs

sub parseProcInstruction {
    my ($args) = @_;

    my (@outputArray) = ();

    while ($args =~ s/([^ =]+)=\"([^"]+)\"(.*)/$3/) { # "
	push (@outputArray, $1);
	push (@outputArray, $2);
    }
    return (@outputArray);
}

sub processAttributes {
    my $pkg = shift;
    my ($element, %content) = @_;

#    print "processAttributes:  element = $element\n" if $main::debug;

    my $hashCount = 0;
    foreach $attributeName (keys %content) {
	if ($attributeName =~ /^\s*$/) {
	    delete $content{$attributeName};  # remove null entries
	    next;
	}
	$hashCount++;
#	print "attribute: $attributeName = $content{$attributeName}\n"
#	    if $main::debug;
    }
    if ($hashCount && $pkg->{'attributes'}) {
	print STDERR "need to write attribute merge logic\n";
    }
    else {
	$pkg->{'attributes'} = \%content;
    }
}

sub getKid {
    my $pkg = shift;
    my $whichKid = shift;

    my @kids = $pkg->getKids();
    my $kid;
    foreach $kid (@kids) {
	my $class = $kid->getClass();
	return $kid if $class eq $whichKid;
    }
    return undef;
}

sub getKids {
    my $pkg = shift;

    return @{$pkg->{'kids'}};
}

sub getAttributes {
    my $pkg = shift;

    my $ref = $pkg->{'attributes'};

    return %$ref;
}

sub getAttr {
    my $pkg = shift;
    my $attr = shift;

    my $ref = $pkg->{'attributes'};

    return $$ref{$attr};
}

sub getClass {
    my $pkg = shift;

    return $pkg->{'class'};
}

sub getContent {
    my $pkg = shift;

    my $content = $pkg->{'content'};
    return $content ? $content : undef;
}
