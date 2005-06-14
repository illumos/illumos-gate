-- #ident	"%Z%%M%	%I%	%E% SMI"

   APPLICATION-MIB DEFINITIONS ::= BEGIN

   IMPORTS
       OBJECT-TYPE, Counter32, Gauge32
         FROM SNMPv2-SMI
       mib-2
         FROM RFC1213-MIB
       DisplayString, TimeStamp
         FROM SNMPv2-TC;


   -- Textual conventions

   -- DistinguishedName [5] is used to refer to objects in the
   -- directory.

--   DistinguishedName ::= TEXTUAL-CONVENTION
--       STATUS current
--       DESCRIPTION
--           "A Distinguished Name represented in accordance with
--            RFC1485."
--       SYNTAX DisplayString

DisplayString ::= OCTET STRING
DistinguishedName ::= OCTET STRING
TimeStamp ::= TimeTicks
Gauge32 ::= Gauge
Counter32 ::= Counter

--   application MODULE-IDENTITY
--       LAST-UPDATED "9311280000Z"
--       ORGANIZATION "IETF Mail and Directory Management Working Group"
--       CONTACT-INFO
--         "        Ned Freed
--
--          Postal: Innosoft International, Inc.
--                  250 West First Street, Suite 240
--                  Claremont, CA  91711
--                  US
--
--             Tel: +1 909 624 7907
--             Fax: +1 909 621 5319
--
--          E-Mail: ned@innosoft.com"
--       DESCRIPTION
--         "The MIB module describing network service applications"
--       ::= { mib-2 27 }

iso           OBJECT IDENTIFIER ::= { 1 }
org           OBJECT IDENTIFIER ::= { iso 3 }
dod           OBJECT IDENTIFIER ::= { org 6 }
internet      OBJECT IDENTIFIER ::= { dod 1 }
mgmt          OBJECT IDENTIFIER ::= { internet 2 }
mib-2         OBJECT IDENTIFIER ::= { mgmt 1 }
application   OBJECT IDENTIFIER ::= { mib-2 27 }


   -- The basic applTable contains a list of the application
   -- entities.


   applTable OBJECT-TYPE
       SYNTAX SEQUENCE OF ApplEntry
--       MAX-ACCESS not-accessible
       ACCESS not-accessible
--       STATUS current
       STATUS mandatory
       DESCRIPTION
           "The table holding objects which apply to all different
            kinds of applications providing network services."
       ::= {application 1}

   applEntry OBJECT-TYPE
       SYNTAX ApplEntry
--       MAX-ACCESS not-accessible
       ACCESS not-accessible
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "An entry associated with a network service application."
       INDEX {applIndex}
       ::= {applTable 1}

   ApplEntry ::= SEQUENCE {
       applIndex
           INTEGER,
       applName
           DisplayString,
       applDirectoryName
           DistinguishedName,
       applVersion
           DisplayString,
       applUptime
           TimeStamp,
       applOperStatus
           INTEGER,
       applLastChange
           TimeStamp,
       applInboundAssociations
           Gauge32,
       applOutboundAssociations
           Gauge32,
       applAccumulatedInboundAssociations
           Counter32,
       applAccumulatedOutboundAssociations
           Counter32,
       applLastInboundActivity
           TimeStamp,
       applLastOutboundActivity
           TimeStamp,
       applRejectedInboundAssociations
           Counter32,
       applFailedOutboundAssociations
           Counter32
   }

   applIndex OBJECT-TYPE
--       SYNTAX INTEGER (1..2147483647)
       SYNTAX INTEGER
--       MAX-ACCESS not-accessible
       ACCESS not-accessible
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "An index to uniquely identify the network service
          application."
       ::= {applEntry 1}

   applName OBJECT-TYPE
       SYNTAX DisplayString
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The name the network service application chooses to be
          known by."
       ::= {applEntry 2}

   applDirectoryName OBJECT-TYPE
       SYNTAX DistinguishedName
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The Distinguished Name of the directory entry where
          static information about this application is stored.
          An empty string indicates that no information about
          the application is available in the directory."
       ::= {applEntry 3}

   applVersion OBJECT-TYPE
       SYNTAX DisplayString
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The version of network service application software."
       ::= {applEntry 4}

   applUptime OBJECT-TYPE
       SYNTAX TimeStamp
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The value of sysUpTime at the time the network service
          application was last initialized.  If the application was
          last initialized prior to the last initialization of the
          network management subsystem, then this object contains
          a zero value."
       ::= {applEntry 5}

   applOperStatus OBJECT-TYPE
       SYNTAX INTEGER {
         up(1),
         down(2),
         halted(3),
         congested(4),
         restarting(5)
       }
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "Indicates the operational status of the network service
          application. 'down' indicates that the network service is
          not available. 'running' indicates that the network service
          is operational and available.  'halted' indicates that the
          service is operational but not available.  'congested'
          indicates that the service is operational but no additional
          inbound associations can be accomodated.  'restarting'
          indicates that the service is currently unavailable but is
          in the process of restarting and will be available soon."
       ::= {applEntry 6}

   applLastChange OBJECT-TYPE
       SYNTAX TimeStamp
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The value of sysUpTime at the time the network service
          application entered its current operational state.  If
          the current state was entered prior to the last
          initialization of the local network management subsystem,
          then this object contains a zero value."
       ::= {applEntry 7}

   applInboundAssociations OBJECT-TYPE
       SYNTAX Gauge32
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The number of current associations to the network service
          application, where it is the responder.  For dynamic single
          threaded processes, this will be the number of application
          instances."
       ::= {applEntry 8}

   applOutboundAssociations OBJECT-TYPE
       SYNTAX Gauge32
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The number of current associations to the network service
          application, where it is the initiator.  For dynamic single
          threaded processes, this will be the number of application
          instances."
       ::= {applEntry 9}

   applAccumulatedInboundAssociations OBJECT-TYPE
       SYNTAX Counter32
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The total number of associations to the application entity
          since application initialization, where it was the responder.
          For  dynamic single threaded processes, this will be the
          number of application instances."
       ::= {applEntry 10}

   applAccumulatedOutboundAssociations OBJECT-TYPE
       SYNTAX Counter32
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The total number of associations to the application entity
          since application initialization, where it was the initiator.
          For dynamic single threaded processes, this will be the
          number of application instances."
       ::= {applEntry 11}

   applLastInboundActivity OBJECT-TYPE
       SYNTAX TimeStamp
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The value of sysUpTime at the time this application last
          had an inbound association.  If the last association
          occurred prior to the last initialization of the network
          subsystem, then this object contains a zero value."
       ::= {applEntry 12}

   applLastOutboundActivity OBJECT-TYPE
       SYNTAX TimeStamp
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The value of sysUpTime at the time this application last
          had an outbound association.  If the last association
          occurred prior to the last initialization of the network
          subsystem, then this object contains a zero value."
       ::= {applEntry 13}

   applRejectedInboundAssociations OBJECT-TYPE
       SYNTAX Counter32
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The total number of inbound associations the application
          entity has rejected, since application initialization."
       ::= {applEntry 14}

   applFailedOutboundAssociations OBJECT-TYPE
       SYNTAX Counter32
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The total number associations where the application entity
          is initiator and association establishment has failed,
          since application initialization."
       ::= {applEntry 15}


   -- The assocTable augments the information in the applTable
   -- with information about associations.  Note that two levels
   -- of compliance are specified below, depending on whether
   -- association monitoring is mandated.

   assocTable OBJECT-TYPE
       SYNTAX SEQUENCE OF AssocEntry
--       MAX-ACCESS not-accessible
       ACCESS not-accessible
--       STATUS current
       STATUS mandatory
       DESCRIPTION
           "The table holding a set of all active application
            associations."
       ::= {application 2}

   assocEntry OBJECT-TYPE
       SYNTAX AssocEntry
--       MAX-ACCESS not-accessible
       ACCESS not-accessible
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "An entry associated with an association for a network
          service application."
       INDEX {applIndex, assocIndex}
       ::= {assocTable 1}

   AssocEntry ::= SEQUENCE {
       assocIndex
           INTEGER,
       assocRemoteApplication
           DisplayString,
       assocApplicationProtocol
           OBJECT IDENTIFIER,
       assocApplicationType
           INTEGER,
       assocDuration
           TimeStamp
   }

   assocIndex OBJECT-TYPE
       SYNTAX INTEGER (1..2147483647)
--       MAX-ACCESS not-accessible
       ACCESS not-accessible
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "An index to uniquely identify each association for a network
          service application."
       ::= {assocEntry 1}

   assocRemoteApplication OBJECT-TYPE
       SYNTAX DisplayString
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The name of the system running remote network service
          application.  For an IP-based application this should be
          either a domain name or IP address.  For an OSI application
          it should be the string encoded distinguished name of the
          managed object.  For X.400(84) MTAs which do not have a
          Distinguished Name, the RFC1327 [6] syntax
          'mta in globalid' should be used."
       ::= {assocEntry 2}

   assocApplicationProtocol OBJECT-TYPE
       SYNTAX OBJECT IDENTIFIER
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "An identification of the protocol being used for the
          application.  For an OSI Application, this will be the
          Application Context.  For Internet applications, the IANA
          maintains a registry of the OIDs which correspond to
          well-known applications.  If the application protocol is
          not listed in the registry, an OID value of the form
          {applTCPProtoID port} or {applUDProtoID port} are used for
          TCP-based and UDP-based protocols, respectively. In either
          case 'port' corresponds to the primary port number being
          used by the protocol."
       ::= {assocEntry 3}

   assocApplicationType OBJECT-TYPE
       SYNTAX INTEGER {
           ua-initiator(1),
           ua-responder(2),
           peer-initiator(3),
           peer-responder(4)}
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "This indicates whether the remote application is some type of
          client making use of this network service (e.g. a User Agent)
          or a server acting as a peer. Also indicated is whether the
          remote end initiated an incoming connection to the network
          service or responded to an outgoing connection made by the
          local application."
       ::= {assocEntry 4}

   assocDuration OBJECT-TYPE
       SYNTAX TimeStamp
--       MAX-ACCESS read-only
       ACCESS read-only
--       STATUS current
       STATUS mandatory
       DESCRIPTION
         "The value of sysUpTime at the time this association was
          started.  If this association started prior to the last
          initialization of the network subsystem, then this
          object contains a zero value."
       ::= {assocEntry 5}


   applTCPProtoID OBJECT IDENTIFIER ::= {application 4}
   applUDPProtoID OBJECT IDENTIFIER ::= {application 5}

   END

