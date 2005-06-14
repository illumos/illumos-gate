#!/usr/local/bin/perl -w
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
# This script will fake a diameter server for testing.
#


$DEFAULT_PORT = 1234;

use Socket;
use Sys::Hostname;
use Fcntl;

require "errno.ph";

#define	MOBILE_IP_OPEN_SESSION_REQUEST			1
#define	MOBILE_IP_OPEN_SESSION_ANSWER			2
#define	MOBILE_IP_OPEN_SESSION_INDICATOIN		3
#define	MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE	4
#define	MOBILE_IP_ACCOUNTING_START_REQUEST		5
#define	MOBILE_IP_ACCOUNTING_START_ANSWER		6
#define	MOBILE_IP_ACCOUNTING_INTERIM_REQUEST		7
#define	MOBILE_IP_ACCOUNTING_INTERIM_ANSWER		8
#define	MOBILE_IP_ACCOUNTING_STOP_REQUEST		9
#define	MOBILE_IP_ACCOUNTING_STOP_ANSWER	       10
#define	MOBILE_IP_CLOSE_SESSION_REQUEST		       11
#define	MOBILE_IP_CLOSE_SESSION_ANSWER		       12

#define	MOBILE_NODE_NAI				       1
#define	FOREIGN_AGENT_NAI			       2
#define	REGISTRATION_REQUEST			       3
#define	NUMBER_OF_CHALLENGE_BYTES_IN_RR		       4
#define	MOBILE_NODE_RESPONSE			       5
#define	MOBILE_NODE_HOME_ADDRESS		       6
#define	HOME_AGENT_ADDRESS			       7
#define	RESULT_CODE				       8
#define	REGISTRATION_REPLY			       9
#define	MN_FA_SPI				      10
#define	MN_FA_KEY				      11
#define	FA_HA_SPI				      12
#define	FA_HA_KEY				      13
#define	SESSION_TIMEOUT				      14
#define	HA_FA_KEY				      15
#define	FA_MN_KEY				      16
#define	MN_HA_SPI				      17
#define	MN_HA_KEY				      18
#define	HA_MN_KEY				      19
#define	SESSION_TIMEOUT_1			      20
#define	SESSION_TIME				      21

my $CONVERT_FROM = 0;
my $CONVERT_TO = 1;

my %commandCodes;
$commandCodes{MOBILE_IP_OPEN_SESSION_REQUEST} = 1;
$commandCodes{MOBILE_IP_OPEN_SESSION_ANSWER} = 2;
$commandCodes{MOBILE_IP_OPEN_SESSION_INDICATOIN} = 3;
$commandCodes{MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE} = 4;
$commandCodes{MOBILE_IP_ACCOUNTING_START_REQUEST} = 5;
$commandCodes{MOBILE_IP_ACCOUNTING_START_ANSWER} = 6;
$commandCodes{MOBILE_IP_ACCOUNTING_INTERIM_REQUEST} = 7;
$commandCodes{MOBILE_IP_ACCOUNTING_INTERIM_ANSWER} = 8;
$commandCodes{MOBILE_IP_ACCOUNTING_STOP_REQUEST} = 9;
$commandCodes{MOBILE_IP_ACCOUNTING_STOP_ANSWER} = 10;
$commandCodes{MOBILE_IP_CLOSE_SESSION_REQUEST} = 11;
$commandCodes{MOBILE_IP_CLOSE_SESSION_ANSWER} = 12;

my @commandCodesRev;
$commandCodesRev[1] = { name => "MOBILE_IP_OPEN_SESSION_REQUEST",
			func => \&processOpenSessionRequest };
$commandCodesRev[2] = { name => "MOBILE_IP_OPEN_SESSION_ANSWER",
			func => \&niy };
$commandCodesRev[3] = { name => "MOBILE_IP_OPEN_SESSION_INDICATOIN",
			func => \&niy };
$commandCodesRev[4] = { name => "MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE",
			func => \&niy };
$commandCodesRev[5] = { name => "MOBILE_IP_ACCOUNTING_START_REQUEST",
			func => \&processAccountingStart };
$commandCodesRev[6] = { name => "MOBILE_IP_ACCOUNTING_START_ANSWER",
			func => \&niy };
$commandCodesRev[7] = { name => "MOBILE_IP_ACCOUNTING_INTERIM_REQUEST",
			func => \&processAccountingInterim };
$commandCodesRev[8] = { name => "MOBILE_IP_ACCOUNTING_INTERIM_ANSWER",
			func => \&niy };
$commandCodesRev[9] = { name => "MOBILE_IP_ACCOUNTING_STOP_REQUEST",
			func => \&processAccountingStop };
$commandCodesRev[10] = { name => "MOBILE_IP_ACCOUNTING_STOP_ANSWER",
			 func => \&niy };
$commandCodesRev[11] = { name => "MOBILE_IP_CLOSE_SESSION_REQUEST",
			 func => \&processCloseSession };
$commandCodesRev[12] = { name => "MOBILE_IP_CLOSE_SESSION_ANSWER", 
			 func => \&niy };

my %avpCodes;
$avpCodes{MOBILE_NODE_NAI} = 1;
$avpCodes{FOREIGN_AGENT_NAI} = 2;
$avpCodes{REGISTRATION_REQUEST} = 3;
$avpCodes{NUMBER_OF_CHALLENGE_BYTES_IN_RR} = 4;
$avpCodes{MOBILE_NODE_RESPONSE} = 5;
$avpCodes{MOBILE_NODE_HOME_ADDRESS} = 6;
$avpCodes{HOME_AGENT_ADDRESS} = 7;
$avpCodes{RESULT_CODE} = 8;
$avpCodes{REGISTRATION_REPLY} = 9;
$avpCodes{MN_FA_SPI} = 10;
$avpCodes{MN_FA_KEY} = 11;
$avpCodes{FA_HA_SPI} = 12;
$avpCodes{FA_HA_KEY} = 13;
$avpCodes{SESSION_TIMEOUT} = 14;
$avpCodes{HA_FA_KEY} = 15;
$avpCodes{FA_MN_KEY} = 16;
$avpCodes{MN_HA_SPI} = 17;
$avpCodes{MN_HA_KEY} = 18;
$avpCodes{HA_MN_KEY} = 19;
$avpCodes{SESSION_TIMEOUT_1} = 20;
$avpCodes{SESSION_TIME} = 21;

my @avpCodesRev;
$avpCodesRev[1] = { name => "MOBILE_NODE_NAI",
		    func => \&ConvertString };
$avpCodesRev[2] = { name => "FOREIGN_AGENT_NAI",
		    func => \&ConvertString };
$avpCodesRev[3] = { name => "REGISTRATION_REQUEST",
		    func => \&ConvertData };
$avpCodesRev[4] = { name => "NUMBER_OF_CHALLENGE_BYTES_IN_RR",
		    func => \&ConvertInteger };
$avpCodesRev[5] = { name => "MOBILE_NODE_RESPONSE",
		    func => \&ConvertData };
$avpCodesRev[6] = { name => "MOBILE_NODE_HOME_ADDRESS",
		    func => \&ConvertIpAddr };
$avpCodesRev[7] = { name => "HOME_AGENT_ADDRESS",
		    func => \&ConvertIpAddr };
$avpCodesRev[8] = { name => "RESULT_CODE",
		    func => \&ConvertInteger };
$avpCodesRev[9] = { name => "REGISTRATION_REPLY",
		    func => \&ConvertData };
$avpCodesRev[10] = { name => "MN_FA_SPI",
		     func => \&ConvertInteger };
$avpCodesRev[11] = { name => "MN_FA_KEY",
		     func => \&ConvertData };
$avpCodesRev[12] = { name => "FA_HA_SPI",
		     func => \&ConvertInteger };
$avpCodesRev[13] = { name => "FA_HA_KEY",
		     func => \&ConvertData };
$avpCodesRev[14] = { name => "SESSION_TIMEOUT",
		     func => \&ConvertInteger };
$avpCodesRev[15] = { name => "HA_FA_KEY",
		     func => \&ConvertData };
$avpCodesRev[16] = { name => "FA_MN_KEY",
		     func => \&ConvertData };
$avpCodesRev[17] = { name => "MN_HA_SPI",
		     func => \&ConvertInteger };
$avpCodesRev[18] = { name => "MN_HA_KEY",
		     func => \&ConvertData };
$avpCodesRev[19] = { name => "HA_MN_KEY",
		     func => \&ConvertData };
$avpCodesRev[20] = { name => "SESSION_TIMEOUT_1",
		     func => \&ConvertInteger };
$avpCodesRev[21] = { name => "SESSION_TIME",
		     func => \&ConvertInteger };


my $CurrentHandle = 1;

# Data Handling routines

# Takes a NULL terminated string, and unpacks it
sub ConvertString($;$;) {
  my ($data,$fromOrTo) = @_;
  if ($fromOrTo == $CONVERT_FROM) {
    return unpack("A*", $data);
  } else {
    return pack("A*",$data);
  }
} # ConvertString

#Converts Data to a printable string
sub ConvertData($;) {
  my ($data,$fromOrTo) = @_;
  my $buffer;
  my $returnBuffer="";
  my $i;

  if ($fromOrTo == $CONVERT_FROM) {
    for ($i=0;$i < length($data); $i ++) {
      $char = unpack("c", substr($data,$i,1));
      $char = $char & 0xff;
      $buffer = sprintf("0x%02x ", $char);
    $returnBuffer = $returnBuffer . $buffer;
    }
    # remove the final space
    return substr($returnBuffer,0,length($returnBuffer) -1 );
  } else {
    # Assume it's already binary.
    return $data;
  }
} # ConvertData

sub ConvertInteger($;) {
  my ($data,$fromOrTo) = @_;
  
  if ($fromOrTo == $CONVERT_FROM) {
    if (length($data) != 4) {
      print "Error: Integer is not 4 bytes long . . treating as data";
      return ConvertData($data);
    }
    return unpack("N", $data);
  } else {
    
    return pack("N", $data);
  }
} #ConvertInteger
sub ConvertIpAddr($;) {
  my ($data,$fromOrTo) = @_;
  
  if ($fromOrTo == $CONVERT_FROM) {
    if (length($data) != 4) {
      print "Error: IPAddr is not 4 bytes long . . treating as data";
      return ConvertData($data);
    }
    return inet_ntoa($data);
  } else {
    return inet_aton($data);
  }
  
} # ConvertIpAddr

sub initSocket {
  my $port = shift;
  $port = $DEFAULT_PORT if (!defined $port);
  
  my $proto = getprotobyname('tcp');
  my $paddr = sockaddr_in($port,INADDR_ANY) ;
  
  socket(SOCKET,PF_INET,SOCK_STREAM,$proto) or die "socket: $!\n";
  setsockopt(SOCKET, SOL_SOCKET, SO_REUSEADDR, 
	     pack("l", 1))   || die "setsockopt: $!";
  bind (SOCKET,$paddr) or die "bind: $!\n";
  
  # make socket non-blocking
  select SOCKET; $|=1; select STDOUT;
  
  my $fh = \*SOCKET;
  return $fh;
}				 # initSocket

sub REAPER {
  $waitedpid = wait;
  $SIG{CHLD} = \&REAPER;	 # loathe sysV
  print "reaped $waitedpid" . ($? ? " with exit $?" : '') . "\n";
}				 # REAPER

sub spawn {
  my $pid;
  if (!defined($pid = fork)) {
    warn "cannot fork: $!\n";
    return;
  } elsif ($pid) {
    warn "begat $pid\n";
    return;			 # I'm the parent
  }
  # else I'm the child -- go spawn
  sleep (1);
  exit &processMessages(\*Client);
}				 # spawn

# seperate the avps out into a hash containing
# the data (indexed by AVP name)
sub processAVPs($;) {
  my $avpBuffer = shift;
  my ($avpCode, $avpLength, $data);
  my %entry;
  my $avpName;
  my %ReturnHash;
  my %EntryHash;
  my $entry;

  print "DEBUG: AVPS:\n";
  while (length($avpBuffer) > 0) {
    ($avpCode,$avpLength) = unpack("N N", $avpBuffer);
    # Now validate the code.
    $entry = $avpCodesRev[$avpCode];
    if (!defined($entry)) {
      print "ERROR: Invalid AVP Code: $avpCode\n";
    } else { 
      %EntryHash = %$entry;
      # Valid Avp . . .  add it
      $avpName = $EntryHash{name};
      $ReturnHash{$avpName} = convertAvp($avpName,
					 substr($avpBuffer,4+4, $avpLength - (4+4)),
					 $CONVERT_FROM);
      print "DEBUG:   $avpName(" . $ReturnHash{$avpName} . ")\n";
    }
    # And, fix the buffer
    $avpBuffer = substr($avpBuffer,$avpLength);
  }

  return \%ReturnHash;
  
} # processAVPs

sub processMessages {
  my $fh = shift;
  my $buffer;
  my $bytesLeftToRead;
  my ($commandCode, $handle, $length);
  my ($avpCode,$avpLength);
  my $avpBytesLeftToRead;
  my $rc;
  my $response;
  
  print "processMessages: executing!\n";
  
  while ( 1 ) {
#    print "Reading in 4+4+4 bytes!\n";
    $rc = recv ($fh,$buffer,4+4+4,0); 
    die "Unable to read in header ($!)\n" if (!defined $rc);
    return (0) if (!length($buffer));
#    print "DEBUG: read " . length($buffer) . " bytes when expecing 4+4+4\n";
    ($commandCode, $handle, $length) = unpack("N N N", $buffer);
    print "Received commandCode $commandCode, handle $handle" . 
      ", length $length\n";
    
    $bytesLeftToRead = $length - (4+4+4);
    
    my $offset=0;
    my $bytesRead = 0;
    # And, read in the rest of the packet.
    while ($bytesLeftToRead) {
      $rc = recv($fh,$buffer,$bytesLeftToRead,$offset);
      die "Unable to read AVPs" if (!defined $rc);
      
      $bytesRead = length($buffer) - $offset;
      return (0) if ($bytesRead == 0);
#      print "DEBUG: readChunk " . $bytesRead . "  bytes\n";
      $bytesLeftToRead -= $bytesRead;
      $offset += $bytesRead;
    }

    print "DEBUG: read " . length($buffer) . " bytes total.\n";

    # Ok, now take apart the packets
    $response = processMessage($commandCode, $handle, $length, $buffer);
    print $fh $response;
  }
}				 # processMessages

sub processMessage($;$;$;$;) {
  my ($commandCode, $handle, $length, $avpBuffer) = @_;
  
  my $entry = $commandCodesRev[$commandCode];
  if (!defined $entry) {
    print "IllegalCommand Code! <" . $commandCode . ">\n";
    sendError();
    return 0;
  }
  my %hash = %$entry;
  print "Recieved " . $hash{name} . "\n";
  
  # Now that we have a good entry, take apart the AVPs
  my $avpRef = processAVPs($avpBuffer);
  my %avps = %$avpRef;
  
  my $func = $hash{func};
  return &$func($hash{name}, $handle, \%avps);
} # processMessage


sub convertAvp($;$;$;) {
  my ($avpName,$data,$fromOrTo) = @_;
  my $avpCode = $avpCodes{$avpName};
  my $entry = $avpCodesRev[$avpCode];
  my %entryHash;
  my $conversionFunc;
  
  if (!defined($entry)) {
    print "ERROR: Invalid AVP: $avpName\n";
    return undef;
  } else { 
    %entryHash = %$entry;
    # Valid Avp . . .  add it
    $conversionFunc = $entryHash{func};
    return
      &$conversionFunc($data, $fromOrTo);
  }
} #addAvp		   

sub processOpenSessionRequest($;$;$;) {
  my ($name, $handle, $avpRef) = @_;
  my %InAvpHash = %$avpRef;
  my %OutAvpHash;
  
  print "OpenSessionRequest($name)\n";
  
  # MobileNode NAI
  $OutAvpHash{MOBILE_NODE_NAI} = convertAvp("MOBILE_NODE_NAI",
					    $InAvpHash{MOBILE_NODE_NAI},
					    $CONVERT_TO);
  
  # ResultCode
  $OutAvpHash{RESULT_CODE} = convertAvp("RESULT_CODE",0,$CONVERT_TO);

  # ForeignAgentNAI
  $OutAvpHash{FOREIGN_AGENT_NAI} = convertAvp("FOREIGN_AGENT_NAI",
					      $InAvpHash{FOREIGN_AGENT_NAI},
					      $CONVERT_TO);

  # Registration Reply
  # WORK

  # MN-FA SPI
  $OutAvpHash{MN_FA_SPI} = convertAvp("MN_FA_SPI",257,$CONVERT_TO);
  # WORK

  # MN-FA Key
  # WORK

  # FA-HA SPI
  $OutAvpHash{FA_HA_SPI} = convertAvp("FA_HA_SPI",258,$CONVERT_TO);
  # WORK

  # FA-HA Key
  # WORK

  # HomeAgentAddress
  $OutAvpHash{HOME_AGENT_ADDRESS} = convertAvp("HOME_AGENT_ADDRESS",
					       "192.168.168.1",
					      $CONVERT_TO);

  # Mobile Node Home ADdress
  $OutAvpHash{MOBILE_NODE_HOME_ADDRESS} = convertAvp("MOBILE_NODE_HOME_ADDRESS",
					 "192.168.168.2",
					$CONVERT_TO);

  # Session Timeout
  $OutAvpHash{SESSION_TIMEOUT} = convertAvp("SESSION_TIMEOUT",10,$CONVERT_TO);
  
  # Send back a changing hancle of one.
  return &buildResponse(\%OutAvpHash,$commandCodes{MOBILE_IP_OPEN_SESSION_ANSWER},
			$CurrentHandle++);


  return 0;

} #processOpenSessionRequest

sub processAccountingStart($;$;$;) {
  my ($name, $handle, $avpRef) = @_;
  my %InAvpHash = %$avpRef;
  my %OutAvpHash;
  
  print "ProcessAccountingStart($name) handle = $handle\n";
  
  # MobileNode NAI
  $OutAvpHash{MOBILE_NODE_NAI} = convertAvp("MOBILE_NODE_NAI",
					    $InAvpHash{MOBILE_NODE_NAI},
					    $CONVERT_TO);
  # ResultCode
  $OutAvpHash{RESULT_CODE} = convertAvp("RESULT_CODE",0,$CONVERT_TO);

  # ForeignAgentNAI
  $OutAvpHash{FOREIGN_AGENT_NAI} = convertAvp("FOREIGN_AGENT_NAI",
					      $InAvpHash{FOREIGN_AGENT_NAI},
					      $CONVERT_TO);
  # Send back the passed in handle.
  return &buildResponse(\%OutAvpHash,$commandCodes{MOBILE_IP_ACCOUNTING_START_ANSWER},
			$handle);

} #processAccountingStart

sub processAccountingInterim($;$;$;) {
  my ($name, $handle, $avpRef) = @_;
  my %InAvpHash = %$avpRef;
  my %OutAvpHash;
  
  print "ProcessAccountingInterim($name)\n";
  
  # MobileNode NAI
  $OutAvpHash{MOBILE_NODE_NAI} = convertAvp("MOBILE_NODE_NAI",
					    $InAvpHash{MOBILE_NODE_NAI},
					    $CONVERT_TO);
  # ResultCode
  $OutAvpHash{RESULT_CODE} = convertAvp("RESULT_CODE",0,$CONVERT_TO);

  # ForeignAgentNAI
  $OutAvpHash{FOREIGN_AGENT_NAI} = convertAvp("FOREIGN_AGENT_NAI",
					      $InAvpHash{FOREIGN_AGENT_NAI},
					      $CONVERT_TO);
  # Send back the passed in handle.
  return &buildResponse(\%OutAvpHash,$commandCodes{MOBILE_IP_ACCOUNTING_INTERIM_ANSWER},
			$handle);

} #processAccountingInterim

sub processAccountingStop($;$;$;) {
  my ($name, $handle, $avpRef) = @_;
  my %InAvpHash = %$avpRef;
  my %OutAvpHash;
  
  print "ProcessAccountingStop($name)\n";
  
  # MobileNode NAI
  $OutAvpHash{MOBILE_NODE_NAI} = convertAvp("MOBILE_NODE_NAI",
					    $InAvpHash{MOBILE_NODE_NAI},
					    $CONVERT_TO);
  # ResultCode
  $OutAvpHash{RESULT_CODE} = convertAvp("RESULT_CODE",0,$CONVERT_TO);

  # ForeignAgentNAI
  $OutAvpHash{FOREIGN_AGENT_NAI} = convertAvp("FOREIGN_AGENT_NAI",
					      $InAvpHash{FOREIGN_AGENT_NAI},
					      $CONVERT_TO);
  # Send back the passed in handle.
  return &buildResponse(\%OutAvpHash,$commandCodes{MOBILE_IP_ACCOUNTING_STOP_ANSWER},
			$handle);

} #processAccountingStop

sub processCloseSession($;$;$;) {
  my ($name, $handle, $avpRef) = @_;
  my %InAvpHash = %$avpRef;
  my %OutAvpHash;
  
  print "ProcessCloseSession($name)\n";
  
  # MobileNode NAI
  $OutAvpHash{MOBILE_NODE_NAI} = convertAvp("MOBILE_NODE_NAI",
					    $InAvpHash{MOBILE_NODE_NAI},
					    $CONVERT_TO);
  # ResultCode
  $OutAvpHash{RESULT_CODE} = convertAvp("RESULT_CODE",0,$CONVERT_TO);

  # ForeignAgentNAI
  $OutAvpHash{FOREIGN_AGENT_NAI} = convertAvp("FOREIGN_AGENT_NAI",
					      $InAvpHash{FOREIGN_AGENT_NAI},
					      $CONVERT_TO);
  # Send back the passed in handle.
  return &buildResponse(\%OutAvpHash,$commandCodes{MOBILE_IP_CLOSE_SESSION_ANSWER},
			$handle);

} #processCloseSession

# This routine will package up the passed in AVPS
sub buildResponse($;$;$;) {
  my ($avpRef,$code,$handle) = @_;
  my %avps = %$avpRef;
  
  my $header;
  my $body = "";

  my $avp;
  my $key;

  foreach $key (keys(%avps)) {
    print "Adding Key = $key length = " . (4+4+length($avps{$key})) . 
      " to response\n";
    $avp = pack("N N", $avpCodes{$key}, (4+4+length($avps{$key}))) . 
      $avps{$key};
    $body = $body . $avp;
  }

  print "Building response with code = $code, handle = $handle, length = " .
    (length($body) +4 +4 +4) . "\n";

  # Now build header
  $header = pack ("N N N",$code, $handle, length($body)+4+4+4);

  return $header . $body;
  
} #buildResponse

sub niy($;$;$;$) {
  my ($name, $handle, $length, $avpBuffer) = @_;
  print "Error: I don't know how to handle $name  (Not Implemented Yet)\n";
} #niy

		   # Main ( multithreaded )


my $socket = initSocket();

listen($socket,5);

my $paddr;

$SIG{CHLD} = \&REAPER;		 # Catch zombies

print "Waiting for connections to port $DEFAULT_PORT\n";

while (1) {
  $paddr = accept(Client,$socket); 
  if (defined($paddr)) {
    my ($port,$iaddr) = sockaddr_in($paddr);
    my $name = gethostbyaddr($iaddr,AF_INET);
    print "connection from $name [" . inet_ntoa($iaddr) .
      "] at port $port\n";
    select Client; $|=1; select STDOUT;
    
    &spawn;
  } else {
    if ($! != &EINTR) {
      die "Error on accept! $! != ". &EINTR . " ($!)\n";
    }
  }
}				 # main for



