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

use xmlHandlers;

package externalEvent;

1;

sub new {
    my $pkg = shift;
    my $id  = shift;
    my $obj = shift;

    my @kid = $obj->getKids(); # kids of event are entry or allowed_types

    # separate kids into classes and create hash of entries and an 
    # array of includes

    my %entry = ();
    my @entry = ();
    my @allowed_types = ();
    my @include = ();
    my $internalName = '';

    my $kid;
    foreach $kid (@kid) {
	my $class = $kid->getClass();
	my $kidId = $kid->getAttr('id');

	if ($class eq 'entry') {
	    my $tokenId = 'undefined';
	    my $format = '';
	    my $internal = $kid->getKid('internal');
	    if (defined $internal) {
	      $tokenId = $internal->getAttr('token');
	      $format = $internal->getAttr('format');
	      $format = '' unless defined $format;
	    }
	    my $comment;
	    my $commentKid = $kid->getKid('comment');
	    if (defined $commentKid) {
	    	$comment = $commentKid->getContent;
	    }
	    my $external = $kid->getKid('external');
	    if (defined ($external)) {
		$entry{$kidId} = [$external, $kid, $tokenId, $format, $comment];
		push (@entry, $kidId);
	    }
	    else {
		print STDERR "no external attributes defined for $id/$kidId\n";
	    }
	} # handle event id translation...
	elsif ($class eq 'altname') {
	    $internalName = $kid->getAttr('id');
	    unless (defined $internalName) {
		print STDERR "missing id for internal name of $id\n";
		$internalName = 'error';
	    }
	}
	elsif ($class eq 'allowed_types') {
	    my $content = $kid->getContent();
	    @allowed_types = (@allowed_types, split(/\s*,\s*/, $content));
	}
    }
    my @entryCopy = @entry;
    return bless {'id'			=> $id,
		  'internalName'	=> $internalName,
		  'allowed_types'	=> \@allowed_types,
		  'entry'		=> \%entry,
		  'entryList'		=> \@entry,
		  'entryListCopy'	=> \@entryCopy,
		  'include'		=> \@include,
		  'xmlObj'		=> $obj}, $pkg;
}

# return id

sub getExternalName {
  my $pkg = shift;

  return $pkg->{'id'};
}


# return internal name if it exists, else id

sub getInternalName {
    $pkg = shift;

    if ($pkg->{'internalName'}) {
	return $pkg->{'internalName'};
    }
    else {
	return $pkg->{'id'};
    }
}

# getNextEntry reads from 'entryList' destructively
# but resets when the list after the list is emptied

sub getNextEntry {
    my $pkg = shift;

    unless (@{$pkg->{'entryList'}}) {
	@{$pkg->{'entryList'}} = @{$pkg->{'entryListCopy'}};
	return undef;
    }
    my $id = shift @{$pkg->{'entryList'}};

    return ($pkg->getEntry($id));  # getEntry returns an array 
}

# getEntryIds returns list of all ids from entryList

sub getEntryIds {
    my $pkg = shift;
    return (@{$pkg->{'entryList'}});
}

# getEntry returns a selected entry for the current event

sub getEntry {
    my $pkg = shift;
    my $id  = shift;  #entry id

    my $ref = $pkg->{'entry'};
    my $array = $$ref{$id};

    return @$array;
}

# getNextInclude reads from 'include' destructively

sub getNextInclude {
    my $pkg = shift;

    return shift @{$pkg->{'include'}};
}

# getIncludes returns list of 'include'

sub getIncludes {
    my $pkg = shift;
    return @{$pkg->{'include'}};
}

# return a reference to the list of event id's allowed for
# this generic event

sub getAllowedTypes {
    my $pkg = shift;

    return $pkg->{'allowed_types'};
}

package internalEvent;

1;

sub new {
    my $pkg = shift;
    my $id  = shift;
    my $obj = shift;

    my @kid = $obj->getKids(); # kids of event are entry

    my @entry = ();

    my $reorder = 0;
    if ($reorder = $obj->getAttr('reorder')) {
	$reorder = 1 if $reorder eq 'yes';
    }
    my $kid;
    foreach $kid (@kid) {
      my $class = $kid->getClass();
      my $id = $kid->getAttr('id');
      
      if ($class eq 'entry') {
	my $internal = $kid->getKid('internal');
	if (defined ($internal)) {
	  push (@entry, [$internal, $kid]);
	}
	else {
	  print STDERR "no internal attributes defined for $id\n";
	}
      }
    }
    return bless {'id'       => $id,
		  'reorder'  => $reorder,
		  'entry'    => \@entry,
		  'xmlObj'   => $obj}, $pkg;
}

# getEntries returns a list of all entry references

sub getEntries {
    my $pkg = shift;

    return undef unless @{$pkg->{'entry'}};

    return @{$pkg->{'entry'}};
}

sub isReorder {
  my $pkg = shift;

  return $pkg->{'reorder'};
}

sub getId {
    my $pkg = shift;

    return $pkg->{'id'};
}

package eventDef;

%uniqueId = ();

1;

sub new {
    my $pkg = shift;
    my $id  = shift;
    my $obj = shift;
    my $super = shift;

    my $omit;
    my $type;
    my $header;
    my $idNo;
    my $javaToo;
    my $title = '';
    my @program = ();
    my @see = ();

    $omit = '' unless $omit = $obj->getAttr('omit');
    $type = '' unless $type = $obj->getAttr('type');
    $header = 0 unless $header = $obj->getAttr('header');
    $idNo = '' unless $idNo = $obj->getAttr('idNo');

    if ($idNo ne '' && $uniqueId{$idNo}) {
        print STDERR "$uniqueId{$idNo} and $id have the same id ($idNo)\n";
    }
    else {
        $uniqueId{$idNo} = $id;
    }

    return bless {'id'		=> $id,
		  'header'	=> $header,
		  'idNo'	=> $idNo,
		  'omit'	=> $omit,
		  'super'	=> $super,
		  'type'	=> $type,
		  'title'	=> $title,
		  'program'	=> \@program,
		  'see'		=> \@see,
		  'external'	=> 0,
		  'internal'	=> 0}, $pkg;
}

# putDef is called at the end of an <event></event> block, so
# it sees a completed object.

sub putDef {
    my $pkg  = shift;
    my $obj  = shift;  # ref to xmlHandlers event object
    my $context = shift;

    my $id = $pkg->{'id'};

    if ($context eq 'internal') {
	$pkg->{$context} = new internalEvent($id, $obj);
	return undef;
    } elsif ($context eq 'external') {
	my $ref = $pkg->{$context} = new externalEvent($id, $obj);
	return $ref->{'internalName'};
    }
}

sub getId {
    my $pkg = shift;

    return $pkg->{'id'};
}

sub getHeader {
    my $pkg = shift;

    return $pkg->{'header'};
}

sub getIdNo {
    my $pkg = shift;

    return $pkg->{'idNo'};
}

sub getSuperClass {
    my $pkg = shift;

    return $pkg->{'super'};
}

sub getOmit {
    my $pkg = shift;

    return $pkg->{'omit'};
}

sub getType {
    my $pkg = shift;

    return $pkg->{'type'};
}

sub getTitle {
    return shift->{'title'};
}

sub getProgram {
    return shift->{'program'};
}

sub getSee {
    return shift->{'see'};
}

sub getInternal {
    my $pkg = shift;

    return $pkg->{'internal'};
}

sub getExternal {
    my $pkg = shift;

    return $pkg->{'external'};
}

# this isn't fully implemented; just a skeleton

package tokenDef;

1;

sub new {
    my $pkg = shift;
    my $obj = shift;
    my $id  = shift;

    $usage	= $obj->getAttr('usage');
    $usage = '' unless defined $usage;

    return bless {'id'		=> $id,
		  'usage'	=> $usage
		  }, $pkg;
}

sub getId {
    my $pkg = shift;

    return $pkg->{'id'};
}

sub getUsage {
    my $pkg = shift;

    return $pkg->{'usage'};
}

package messageList;

1;

sub new {
    my $pkg = shift;
    my $obj = shift;
    my $id  = shift;
    my $header = shift;
    my $start = shift;
    my $public = shift;
    my $deprecated = shift;

    my @msg = ();

    my @kid = $obj->getKids(); # kids of msg_list are msg
    my $kid;
    foreach $kid (@kid) {
	my $class = $kid->getClass();
	if ($class eq 'msg') {
	    my $text = $kid->getContent();
	    $text = '' unless defined ($text);
	    my $msgId = $kid->getAttr('id');
	    if (defined ($msgId)) {
	        push(@msg, join('::', $msgId, $text));
	    }
	    else {
	        print STDERR "missing id for $class <msg>\n";
	    }
	}
	else {
	    print STDERR "invalid tag in <msg_list> block: $class\n";
	}
    }

    return bless {'id'		=> $id,
		  'header'	=> $header,
		  'msg'		=> \@msg,
		  'start'	=> $start,
		  'public'	=> $public,
		  'deprecated'	=> $deprecated
		 }, $pkg;
}

sub getId {
    my $pkg = shift;

    return $pkg->{'id'};
}

sub getMsgStart {
    my $pkg = shift;

    return $pkg->{'start'};
}

sub getDeprecated {
    my $pkg = shift;

    return $pkg->{'deprecated'};
}

sub getMsgPublic {
    my $pkg = shift;

    return $pkg->{'public'};
}

sub getHeader {
    my $pkg = shift;

    return $pkg->{'header'};
}

# destructive read of @msg...

sub getNextMsg {
    my $pkg = shift;

    my @msg = @{$pkg->{'msg'}};

    return undef unless @msg;

    my $text = pop(@msg);
    $pkg->{'msg'} = \@msg;
    return $text;
}

# returns all msgs
sub getMsgs {
    my $pkg = shift;

    return @{$pkg->{'msg'}};
}


package auditxml;

# These aren't internal state because the callback functions don't
# have the object handle.

@debug   = ();            # stack for nesting debug state
%event   = ();            # event name => $objRef
@event   = ();            # event id
%token   = ();            # token name => $objRef
@token   = ();            # token id
%msg_list = ();           # messageList string list id to obj
@msg_list = ();           # id list
%service = ();            # valid service names
%externalToInternal = (); # map external event name to internal event name

1;

sub new {
    my $pkg  = shift;
    my $file = shift;  # xml file to be parsed

    register('event',      \&eventStart,  \&eventEnd);
    register('entry',      0,             \&entry);
    register('external',   0,             \&external);
    register('internal',   0,             \&internal);
    register('include',    0,             \&include);
    register('token',      0,             \&token);
    register('service',    0,             \&service);
    register('msg_list',   0,             \&msg_list);
    register('msg',        0,             \&msg);

    # do not use register() for debug because register generates extra
    # debug information

    xmlHandlers::registerStartCallback('debug', \&debugStart);
    xmlHandlers::registerEndCallback('debug', \&debugEnd);

    $xml = new xmlHandlers(0, 'top level', $file);

    return bless {'xmlObj'     => $xml,
	          'firstToken' => 1,
	          'firstEvent' => 1}, $pkg;
}

# local function -- register both the auditxml function and the
# xmlHandler callback

sub register {
    my $localName     = shift;
    my $startFunction = shift;
    my $endFunction = shift;
    
    if ($startFunction) {
      xmlHandlers::registerStartCallback($localName, \&completed);
	$startFunction{$localName} = $startFunction;
    }
    if ($endFunction) {
      xmlHandlers::registerEndCallback($localName, \&completed);
	$endFunction{$localName} = $endFunction;
    }
}

sub completed {
    my $obj = shift;
    my $callbackSource = shift;

    my $id  = $obj->getAttr('id');
    my $class = $obj->getClass();

    if ($main::debug) {
	print "*** $callbackSource: $class", (defined ($id)) ? "= $id\n" : "\n";

	my %attributes = $obj->getAttributes();
	my $attribute;
	foreach $attribute (keys %attributes) {
	    print "*** $attribute = $attributes{$attribute}\n";
	}
	my $content = $obj->getContent();
	print "*** content = $content\n" if defined $content;
    }
    if ($callbackSource eq 'start') {
	&{$startFunction{$class}}($obj);
    }
    elsif ($callbackSource eq 'end') {
	&{$endFunction{$class}}($obj);
    }
    else {
	print STDERR "no auditxml function defined for $class\n";
    }
}

# getNextEvent reads from @event destructively.  'firstEvent' could
# be used to make a copy from which to read.

sub getNextEvent {
    my $pkg = shift;

    return undef unless (@event);
    if ($pkg->{'firstEvent'}) {
	@token = sort @token;
	$pkg->{'firstEvent'} = 1;
    }

    my $id = shift @event;

    return $event{$id};
}

# returns all event ids
sub getEventIds {
   my $pkg = shift;

   return @event;
}

# returns event for id
sub getEvent {
    my $pkg = shift;
    my $id = shift;

    return $event{$id};
}

sub getToken {
    my $pkg = shift;
    my $id = shift;

    return $token{$id};
}

# getNextToken reads from @token destructively.  'firstToken' could
# be used to make a copy from which to read.

sub getNextToken {
    my $pkg = shift;

    return undef unless (@token);

    if ($pkg->{'firstToken'}) {
	@token = sort @token;
	$pkg->{'firstToken'} = 1;
    }
    my $id = shift @token;

    return $token{$id};
}

# return token Ids

sub getTokenIds {
    my $pkg = shift;

    return @token;
}

# getNextMsgId reads from @msg_list destructively.

sub getNextMsgId {
    my $pkg = shift;

    return undef unless (@msg_list);

    my $id = shift @msg_list;

    return ($id, $msg_list{$id});
}

sub getMsgIds {
    my $pkg = shift;

    return @msg_list;
}

sub getMsg {
    my $pkg = shift;
    my $id = shift;

    return $msg_list{$id};
}

sub external {
}

sub internal {

}

sub eventStart {
    my $obj  = shift;

    my $id = $obj->getAttr('id');
    
    unless ($id) {
	print STDERR "eventStart can't get a valid id\n";
	return;
    }
    unless (defined $event{$id}) {
        my $super;
	if ($super = $obj->getAttr('instance_of')) {
	    $super = $event{$super};
	} else {
	    $super = 0;
	}
	$event{$id} = new eventDef($id, $obj, $super);
        push (@event, $id);
    } else {
	print STDERR "duplicate event id: $id\n";
    }
}

sub eventEnd {
    my $obj  = shift;

    my $id    = $obj->getAttr('id');
    unless (defined $id) {
	print STDERR "event element is missing required id attribute\n";
	return;
    }
    print "event = $id\n" if $main::debug;

    foreach my $kid ($obj->getKids) {
    	my $class = $kid->getClass;
    	next unless ($class =~ /title|program|see/);
	my $content = $kid->getContent;
	if ($class eq 'title') {
	    $event{$id}->{$class} = $content;
	} else {
	    push @{$event{$id}->{$class}}, $content;
	}
    }
    $event{$id}->putDef($obj, 'internal');

    my $internalName = $event{$id}->putDef($obj, 'external');

    $externalToInternal{$id} = $internalName if $internalName;
}

# class method

#sub getInternalName {
#    my $name = shift;
#
#    return $externalToInternal{$name};
#}

sub entry {
}

#sub include {
#    my $obj  = shift;
#
#    my $id = $obj->getAttr('id');
#
#    if (defined $id) {
#	print "include = $id\n" if $main::debug;
#    }
#    else {
#	print STDERR "include element is missing required id attribute\n";
#    }
#}

sub token {
    my $obj  = shift;

    my $id = $obj->getAttr('id');
    
    if (defined $id) {
	print "token = $id\n" if $main::debug;
	$token{$id} = new tokenDef($obj, $id);
	push (@token, $id);
    }
    else {
	print STDERR "token element is missing required id attribute\n";
    }
}

sub msg_list {
    my $obj = shift;

    my $id = $obj->getAttr('id');
    my $header = $obj->getAttr('header');
    my $start = $obj->getAttr('start');
    my $public = $obj->getAttr('public');
    my $deprecated = $obj->getAttr('deprecated');

    $header = 0 unless $header;
    $start = 0 unless $start;
    $public = ($public) ? 1 : 0;
    $deprecated = ($deprecated) ? 1 : 0;

    if (defined $id) {
	print "msg_list = $id\n" if $main::debug;
	$msg_list{$id} = new messageList($obj, $id, $header, $start,
	    $public, $deprecated);
	push (@msg_list, $id);
    }
    else {
	print STDERR
	    "msg_list element is missing required id attribute\n";
    }
}

sub msg {
#    my $obj = shift;
}

# Service name was dropped during PSARC review

sub service {
    my $obj = shift;

    my $name = $obj->getAttr('name');
    my $id   = $obj->getAttr('id');

    if ((defined $id) && (defined $name)) {
	print "service $name = $id\n" if $main::debug;
	$service{$name} = $id;
    }
    elsif (defined $name) {
	print STDERR "service $name is missing an id number\n";
    }
    elsif (defined $id) {
	print STDERR "service name missing for id = $id\n";
    }
    else {
	print STDERR "missing both name and id for a service entry\n";
    }
}

#sub getServices {
#
#    return %service;
#}

# <debug set="on"> or <debug set="off"> or <debug>
# if the set attribute is omitted, debug state is toggled

# debugStart / debugEnd are used to insure debug state is
# scoped to the block between <debug> and </debug>

sub debugStart {
    my $obj = shift;

    push (@debug, $main::debug);
    my $debug = $main::debug;

    my $state = $obj->getAttr('set');

    if (defined $state) {
	$main::debug = ($state eq 'on') ? 1 : 0;
    }
    else {
	$main::debug = !$debug;
    }
    if ($debug != $main::debug) {
	print 'debug is ', $main::debug ? 'on' : 'off', "\n";
    }
}

sub debugEnd {
    my $obj = shift;

    my $debug = $main::debug;
    $main::debug = pop (@debug);

    if ($debug != $main::debug) {
	print 'debug is ', $main::debug ? 'on' : 'off', "\n";
    }
}
