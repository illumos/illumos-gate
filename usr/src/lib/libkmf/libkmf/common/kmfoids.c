/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright(c) 1995-2000 Intel Corporation. All rights reserved.
 */

#include <kmfapi.h>

/* From X.520 */
static uint8_t
OID_ObjectClass[] = { OID_ATTR_TYPE, 0 },
OID_AliasedEntryName[] = { OID_ATTR_TYPE, 1 },
OID_KnowledgeInformation[] = { OID_ATTR_TYPE, 2 },
OID_CommonName[] = { OID_ATTR_TYPE, 3 },
OID_Surname[] = { OID_ATTR_TYPE, 4 },
OID_SerialNumber[] = { OID_ATTR_TYPE, 5 },
OID_CountryName[] = { OID_ATTR_TYPE, 6 },
OID_LocalityName[] = { OID_ATTR_TYPE, 7 },
OID_StateProvinceName[] = { OID_ATTR_TYPE, 8 },
OID_CollectiveStateProvinceName[] = { OID_ATTR_TYPE, 8, 1 },
OID_StreetAddress[] = { OID_ATTR_TYPE, 9 },
OID_CollectiveStreetAddress[] = { OID_ATTR_TYPE, 9, 1 },
OID_OrganizationName[] = { OID_ATTR_TYPE, 10 },
OID_CollectiveOrganizationName[] = { OID_ATTR_TYPE, 10, 1 },
OID_OrganizationalUnitName[] = { OID_ATTR_TYPE, 11 },
OID_CollectiveOrganizationalUnitName[] = { OID_ATTR_TYPE, 11, 1 },
OID_Title[] = { OID_ATTR_TYPE, 12 },
OID_Description[] = { OID_ATTR_TYPE, 13 },
OID_SearchGuide[] = { OID_ATTR_TYPE, 14 },
OID_BusinessCategory[] = { OID_ATTR_TYPE, 15 },
OID_PostalAddress[] = { OID_ATTR_TYPE, 16 },
OID_CollectivePostalAddress[] = { OID_ATTR_TYPE, 16, 1 },
OID_PostalCode[] = { OID_ATTR_TYPE, 17 },
OID_CollectivePostalCode[] = { OID_ATTR_TYPE, 17, 1 },
OID_PostOfficeBox[] = { OID_ATTR_TYPE, 18 },
OID_CollectivePostOfficeBox[] = { OID_ATTR_TYPE, 18, 1 },
OID_PhysicalDeliveryOfficeName[] = { OID_ATTR_TYPE, 19 },
OID_CollectivePhysicalDeliveryOfficeName[] = { OID_ATTR_TYPE, 19, 1 },
OID_TelephoneNumber[] = { OID_ATTR_TYPE, 20 },
OID_CollectiveTelephoneNumber[] = { OID_ATTR_TYPE, 20, 1 },
OID_TelexNumber[] = { OID_ATTR_TYPE, 21 },
OID_CollectiveTelexNumber[] = { OID_ATTR_TYPE, 21, 1 },
OID_TelexTerminalIdentifier[] = { OID_ATTR_TYPE, 22 },
OID_CollectiveTelexTerminalIdentifier[] = { OID_ATTR_TYPE, 22, 1 },
OID_FacsimileTelephoneNumber[] = { OID_ATTR_TYPE, 23 },
OID_CollectiveFacsimileTelephoneNumber[] = { OID_ATTR_TYPE, 23, 1 },
OID_X_121Address[] = { OID_ATTR_TYPE, 24 },
OID_InternationalISDNNumber[] = { OID_ATTR_TYPE, 25 },
OID_CollectiveInternationalISDNNumber[] = { OID_ATTR_TYPE, 25, 1 },
OID_RegisteredAddress[] = { OID_ATTR_TYPE, 26 },
OID_DestinationIndicator[] = { OID_ATTR_TYPE, 27 },
OID_PreferredDeliveryMethod[] = { OID_ATTR_TYPE, 28 },
OID_PresentationAddress[] = { OID_ATTR_TYPE, 29 },
OID_SupportedApplicationContext[] = { OID_ATTR_TYPE, 30 },
OID_Member[] = { OID_ATTR_TYPE, 31 },
OID_Owner[] = { OID_ATTR_TYPE, 32 },
OID_RoleOccupant[] = { OID_ATTR_TYPE, 33 },
OID_SeeAlso[] = { OID_ATTR_TYPE, 34 },
OID_UserPassword[] = { OID_ATTR_TYPE, 35 },
OID_UserCertificate[] = { OID_ATTR_TYPE, 36 },
OID_CACertificate[] = { OID_ATTR_TYPE, 37 },
OID_AuthorityRevocationList[] = { OID_ATTR_TYPE, 38 },
OID_CertificateRevocationList[] = { OID_ATTR_TYPE, 39 },
OID_CrossCertificatePair[] = { OID_ATTR_TYPE, 40 },
OID_Name[] = { OID_ATTR_TYPE, 41 },
OID_GivenName[] = { OID_ATTR_TYPE, 42 },
OID_Initials[] = { OID_ATTR_TYPE, 43 },
OID_GenerationQualifier[] = { OID_ATTR_TYPE, 44 },
OID_UniqueIdentifier[] = { OID_ATTR_TYPE, 45 },
OID_DNQualifier[] = { OID_ATTR_TYPE, 46 },
OID_EnhancedSearchGuide[] = { OID_ATTR_TYPE, 47 },
OID_ProtocolInformation[] = { OID_ATTR_TYPE, 48 },
OID_DistinguishedName[] = { OID_ATTR_TYPE, 49 },
OID_UniqueMember[] = { OID_ATTR_TYPE, 50 },
OID_HouseIdentifier[] = { OID_ATTR_TYPE, 51 }
/* OID_SupportedAlgorithms[] = { OID_ATTR_TYPE, 52 }, */
/* OID_DeltaRevocationList[] = { OID_ATTR_TYPE, 53 }, */
/* OID_AttributeCertificate[] = { OID_ATTR_TYPE, 58 } */
;

/* From PKCS 9 */
static uint8_t
OID_EmailAddress[] = { OID_PKCS_9, 1 },
OID_UnstructuredName[] = { OID_PKCS_9, 2 },
OID_ContentType[] = { OID_PKCS_9, 3 },
OID_MessageDigest[] = { OID_PKCS_9, 4 },
OID_SigningTime[] = { OID_PKCS_9, 5 },
OID_CounterSignature[] = { OID_PKCS_9, 6 },
OID_ChallengePassword[] = { OID_PKCS_9, 7 },
OID_UnstructuredAddress[] = { OID_PKCS_9, 8 },
OID_ExtendedCertificateAttributes[] = { OID_PKCS_9, 9 },
OID_ExtensionRequest[] = { OID_PKCS_9, 14 };

/* From PKIX 1 */
/* Standard Extensions */
static uint8_t
OID_SubjectDirectoryAttributes[] = { OID_EXTENSION, 9 },
OID_SubjectKeyIdentifier[] = { OID_EXTENSION, 14 },
OID_KeyUsage[] = { OID_EXTENSION, 15 },
OID_PrivateKeyUsagePeriod[] = { OID_EXTENSION, 16 },
OID_SubjectAltName[] = { OID_EXTENSION, 17 },
OID_IssuerAltName[] = { OID_EXTENSION, 18 },
OID_BasicConstraints[] = { OID_EXTENSION, 19 },
OID_CrlNumber[] = { OID_EXTENSION, 20 },
OID_CrlReason[] = { OID_EXTENSION, 21 },
OID_HoldInstructionCode[] = { OID_EXTENSION, 23 },
OID_InvalidityDate[] = { OID_EXTENSION, 24 },
OID_DeltaCrlIndicator[] = { OID_EXTENSION, 27 },
OID_IssuingDistributionPoints[] = { OID_EXTENSION, 28 },

/* OID_CertificateIssuer[] = { OID_EXTENSION, 29 }, */
OID_NameConstraints[] = { OID_EXTENSION, 30 },
OID_CrlDistributionPoints[] = { OID_EXTENSION, 31 },
OID_CertificatePolicies[] = { OID_EXTENSION, 32 },
OID_PolicyMappings[] = { OID_EXTENSION, 33 },
/* 34 deprecated */
OID_AuthorityKeyIdentifier[] = { OID_EXTENSION, 35 },
OID_PolicyConstraints[] = { OID_EXTENSION, 36 },
OID_ExtKeyUsage[] = { OID_EXTENSION, 37 }
;

/* PKIX-defined extended key purpose OIDs */
static uint8_t
OID_QT_CPSuri[]		 = { OID_PKIX_QT_CPS },
OID_QT_Unotice[]	 = { OID_PKIX_QT_UNOTICE },

OID_KP_ServerAuth[]	 = { OID_PKIX_KP, 1 },
OID_KP_ClientAuth[] = { OID_PKIX_KP, 2 },
OID_KP_CodeSigning[] = { OID_PKIX_KP, 3 },
OID_KP_EmailProtection[] = { OID_PKIX_KP, 4 },
OID_KP_IPSecEndSystem[] = { OID_PKIX_KP, 5 },
OID_KP_IPSecTunnel[] = { OID_PKIX_KP, 6 },
OID_KP_IPSecUser[] = { OID_PKIX_KP, 7 },
OID_KP_TimeStamping[] = { OID_PKIX_KP, 8 },
OID_KP_OCSPSigning[] = { OID_PKIX_KP, 9 }
;

/* From PKIX 1 */
static uint8_t
OID_AuthorityInfoAccess[] = { OID_PKIX_PE, 1};

const KMF_OID
KMFOID_AuthorityInfoAccess = {OID_PKIX_LENGTH + 2, OID_AuthorityInfoAccess};

static uint8_t
OID_PkixAdOcsp[] = {OID_PKIX_AD, 1};

const KMF_OID
KMFOID_PkixAdOcsp = {OID_PKIX_AD_LENGTH + 1, OID_PkixAdOcsp};

static uint8_t
OID_PkixAdCaIssuers[] = {OID_PKIX_AD, 2};

const KMF_OID
KMFOID_PkixAdCaIssuers = {OID_PKIX_AD_LENGTH + 1, OID_PkixAdCaIssuers};

/*
 * From RFC 1274
 */
static uint8_t
OID_userid[] =		{OID_PILOT, 1},
OID_RFC822mailbox[] =	{OID_PILOT, 3},
OID_domainComponent[] =	{OID_PILOT, 25};

const KMF_OID
KMFOID_userid		= {OID_PILOT_LENGTH + 1, OID_userid},
KMFOID_RFC822mailbox	= {OID_PILOT_LENGTH + 1, OID_RFC822mailbox},
KMFOID_domainComponent	= {OID_PILOT_LENGTH + 1, OID_domainComponent},
KMFOID_ObjectClass = {OID_ATTR_TYPE_LENGTH+1, OID_ObjectClass},
KMFOID_AliasedEntryName = {OID_ATTR_TYPE_LENGTH+1, OID_AliasedEntryName},
KMFOID_KnowledgeInformation = {OID_ATTR_TYPE_LENGTH+1,
	OID_KnowledgeInformation},
KMFOID_CommonName = {OID_ATTR_TYPE_LENGTH+1, OID_CommonName},
KMFOID_Surname = {OID_ATTR_TYPE_LENGTH+1, OID_Surname},
KMFOID_SerialNumber = {OID_ATTR_TYPE_LENGTH+1, OID_SerialNumber},
KMFOID_CountryName = {OID_ATTR_TYPE_LENGTH+1, OID_CountryName},
KMFOID_LocalityName = {OID_ATTR_TYPE_LENGTH+1, OID_LocalityName},
KMFOID_StateProvinceName = {OID_ATTR_TYPE_LENGTH+1, OID_StateProvinceName},
KMFOID_CollectiveStateProvinceName = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveStateProvinceName},
KMFOID_StreetAddress = {OID_ATTR_TYPE_LENGTH+1, OID_StreetAddress},
KMFOID_CollectiveStreetAddress = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveStreetAddress},
KMFOID_OrganizationName = {OID_ATTR_TYPE_LENGTH+1, OID_OrganizationName},
KMFOID_CollectiveOrganizationName = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveOrganizationName},
KMFOID_OrganizationalUnitName = {OID_ATTR_TYPE_LENGTH+1,
	OID_OrganizationalUnitName},
KMFOID_CollectiveOrganizationalUnitName = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveOrganizationalUnitName},
KMFOID_Title = {OID_ATTR_TYPE_LENGTH+1, OID_Title},
KMFOID_Description = {OID_ATTR_TYPE_LENGTH+1, OID_Description},
KMFOID_SearchGuide = {OID_ATTR_TYPE_LENGTH+1, OID_SearchGuide},
KMFOID_BusinessCategory = {OID_ATTR_TYPE_LENGTH+1, OID_BusinessCategory},
KMFOID_PostalAddress = {OID_ATTR_TYPE_LENGTH+1, OID_PostalAddress},
KMFOID_CollectivePostalAddress = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectivePostalAddress},
KMFOID_PostalCode = {OID_ATTR_TYPE_LENGTH+1, OID_PostalCode},
KMFOID_CollectivePostalCode = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectivePostalCode},
KMFOID_PostOfficeBox = {OID_ATTR_TYPE_LENGTH+1, OID_PostOfficeBox},
KMFOID_CollectivePostOfficeBox = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectivePostOfficeBox},
KMFOID_PhysicalDeliveryOfficeName = {OID_ATTR_TYPE_LENGTH+1,
	OID_PhysicalDeliveryOfficeName},
KMFOID_CollectivePhysicalDeliveryOfficeName = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectivePhysicalDeliveryOfficeName},
KMFOID_TelephoneNumber = {OID_ATTR_TYPE_LENGTH+1, OID_TelephoneNumber},
KMFOID_CollectiveTelephoneNumber = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveTelephoneNumber},
KMFOID_TelexNumber = {OID_ATTR_TYPE_LENGTH+1, OID_TelexNumber},
KMFOID_CollectiveTelexNumber = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveTelexNumber},
KMFOID_TelexTerminalIdentifier = {OID_ATTR_TYPE_LENGTH+1,
	OID_TelexTerminalIdentifier},
KMFOID_CollectiveTelexTerminalIdentifier = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveTelexTerminalIdentifier},
KMFOID_FacsimileTelephoneNumber = {OID_ATTR_TYPE_LENGTH+1,
	OID_FacsimileTelephoneNumber},
KMFOID_CollectiveFacsimileTelephoneNumber = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveFacsimileTelephoneNumber},
KMFOID_X_121Address = {OID_ATTR_TYPE_LENGTH+1, OID_X_121Address},
KMFOID_InternationalISDNNumber = {OID_ATTR_TYPE_LENGTH+1,
	OID_InternationalISDNNumber},
KMFOID_CollectiveInternationalISDNNumber = {OID_ATTR_TYPE_LENGTH+2,
	OID_CollectiveInternationalISDNNumber},
KMFOID_RegisteredAddress = {OID_ATTR_TYPE_LENGTH+1, OID_RegisteredAddress},
KMFOID_DestinationIndicator = {OID_ATTR_TYPE_LENGTH+1,
	OID_DestinationIndicator},
KMFOID_PreferredDeliveryMethod = {OID_ATTR_TYPE_LENGTH+1,
	OID_PreferredDeliveryMethod},
KMFOID_PresentationAddress = {OID_ATTR_TYPE_LENGTH+1,
	OID_PresentationAddress},
KMFOID_SupportedApplicationContext = {OID_ATTR_TYPE_LENGTH+1,
	OID_SupportedApplicationContext},
KMFOID_Member = {OID_ATTR_TYPE_LENGTH+1, OID_Member},
KMFOID_Owner = {OID_ATTR_TYPE_LENGTH+1, OID_Owner},
KMFOID_RoleOccupant = {OID_ATTR_TYPE_LENGTH+1, OID_RoleOccupant},
KMFOID_SeeAlso = {OID_ATTR_TYPE_LENGTH+1, OID_SeeAlso},
KMFOID_UserPassword = {OID_ATTR_TYPE_LENGTH+1, OID_UserPassword},
KMFOID_UserCertificate = {OID_ATTR_TYPE_LENGTH+1, OID_UserCertificate},
KMFOID_CACertificate = {OID_ATTR_TYPE_LENGTH+1, OID_CACertificate},
KMFOID_AuthorityRevocationList = {OID_ATTR_TYPE_LENGTH+1,
	OID_AuthorityRevocationList},
KMFOID_CertificateRevocationList = {OID_ATTR_TYPE_LENGTH+1,
	OID_CertificateRevocationList},
KMFOID_CrossCertificatePair = {OID_ATTR_TYPE_LENGTH+1,
	OID_CrossCertificatePair},
KMFOID_Name = {OID_ATTR_TYPE_LENGTH+1, OID_Name},
KMFOID_GivenName = {OID_ATTR_TYPE_LENGTH+1, OID_GivenName},
KMFOID_Initials = {OID_ATTR_TYPE_LENGTH+1, OID_Initials},
KMFOID_GenerationQualifier = {OID_ATTR_TYPE_LENGTH+1, OID_GenerationQualifier},
KMFOID_UniqueIdentifier = {OID_ATTR_TYPE_LENGTH+1, OID_UniqueIdentifier},
KMFOID_DNQualifier = {OID_ATTR_TYPE_LENGTH+1, OID_DNQualifier},
KMFOID_EnhancedSearchGuide = {OID_ATTR_TYPE_LENGTH+1, OID_EnhancedSearchGuide},
KMFOID_ProtocolInformation = {OID_ATTR_TYPE_LENGTH+1, OID_ProtocolInformation},
KMFOID_DistinguishedName = {OID_ATTR_TYPE_LENGTH+1, OID_DistinguishedName},
KMFOID_UniqueMember = {OID_ATTR_TYPE_LENGTH+1, OID_UniqueMember},
KMFOID_HouseIdentifier = {OID_ATTR_TYPE_LENGTH+1, OID_HouseIdentifier},
KMFOID_EmailAddress = {OID_PKCS_9_LENGTH+1, OID_EmailAddress},
KMFOID_UnstructuredName = {OID_PKCS_9_LENGTH+1, OID_UnstructuredName},
KMFOID_ContentType = {OID_PKCS_9_LENGTH+1, OID_ContentType},
KMFOID_MessageDigest = {OID_PKCS_9_LENGTH+1, OID_MessageDigest},
KMFOID_SigningTime = {OID_PKCS_9_LENGTH+1, OID_SigningTime},
KMFOID_CounterSignature = {OID_PKCS_9_LENGTH+1, OID_CounterSignature},
KMFOID_ChallengePassword = {OID_PKCS_9_LENGTH+1, OID_ChallengePassword},
KMFOID_UnstructuredAddress = {OID_PKCS_9_LENGTH+1, OID_UnstructuredAddress},
KMFOID_ExtendedCertificateAttributes = {OID_PKCS_9_LENGTH+1,
	OID_ExtendedCertificateAttributes},
KMFOID_ExtensionRequest = {OID_PKCS_9_LENGTH + 1, OID_ExtensionRequest};

static uint8_t
OID_AuthorityKeyID[] = { OID_EXTENSION, 1 },
OID_VerisignCertificatePolicy[] = { OID_EXTENSION, 3 },
OID_KeyUsageRestriction[] = { OID_EXTENSION, 4 };

const KMF_OID
KMFOID_AuthorityKeyID		 = {OID_EXTENSION_LENGTH+1, OID_AuthorityKeyID},

KMFOID_VerisignCertificatePolicy = {OID_EXTENSION_LENGTH+1,
	OID_VerisignCertificatePolicy},

KMFOID_KeyUsageRestriction	 = {OID_EXTENSION_LENGTH+1,
	OID_KeyUsageRestriction},

KMFOID_SubjectDirectoryAttributes = {OID_EXTENSION_LENGTH+1,
	OID_SubjectDirectoryAttributes},

KMFOID_SubjectKeyIdentifier	 = {OID_EXTENSION_LENGTH+1,
	OID_SubjectKeyIdentifier },
KMFOID_KeyUsage		 = {OID_EXTENSION_LENGTH+1, OID_KeyUsage },

KMFOID_PrivateKeyUsagePeriod	 = {OID_EXTENSION_LENGTH+1,
	OID_PrivateKeyUsagePeriod},
KMFOID_SubjectAltName	 = {OID_EXTENSION_LENGTH+1, OID_SubjectAltName },
KMFOID_IssuerAltName	 = {OID_EXTENSION_LENGTH+1, OID_IssuerAltName },
KMFOID_BasicConstraints	 = {OID_EXTENSION_LENGTH+1, OID_BasicConstraints },

KMFOID_CrlNumber	 = {OID_EXTENSION_LENGTH+1, OID_CrlNumber},

KMFOID_CrlReason	 = {OID_EXTENSION_LENGTH+1, OID_CrlReason},

KMFOID_HoldInstructionCode = {OID_EXTENSION_LENGTH+1, OID_HoldInstructionCode},

KMFOID_InvalidityDate	 = {OID_EXTENSION_LENGTH+1, OID_InvalidityDate},

KMFOID_DeltaCrlIndicator = {OID_EXTENSION_LENGTH+1, OID_DeltaCrlIndicator},

KMFOID_IssuingDistributionPoints = {OID_EXTENSION_LENGTH+1,
	OID_IssuingDistributionPoints},

KMFOID_NameConstraints	 = {OID_EXTENSION_LENGTH+1,
	OID_NameConstraints},

KMFOID_CrlDistributionPoints = {OID_EXTENSION_LENGTH+1,
	OID_CrlDistributionPoints},

KMFOID_CertificatePolicies = {OID_EXTENSION_LENGTH+1,
	OID_CertificatePolicies},

KMFOID_PolicyMappings	 = {OID_EXTENSION_LENGTH+1, OID_PolicyMappings},

KMFOID_PolicyConstraints = {OID_EXTENSION_LENGTH+1, OID_PolicyConstraints},

KMFOID_AuthorityKeyIdentifier = {OID_EXTENSION_LENGTH+1,
	OID_AuthorityKeyIdentifier},

KMFOID_ExtendedKeyUsage	 = {OID_EXTENSION_LENGTH+1, OID_ExtKeyUsage},

KMFOID_PKIX_PQ_CPSuri	 = {OID_PKIX_QT_CPS_LENGTH, 	OID_QT_CPSuri},

KMFOID_PKIX_PQ_Unotice	 = {OID_PKIX_QT_UNOTICE_LENGTH,	OID_QT_Unotice},

/* Extended Key Usage OIDs */
KMFOID_PKIX_KP_ServerAuth = {OID_PKIX_KP_LENGTH + 1, OID_KP_ServerAuth},

KMFOID_PKIX_KP_ClientAuth = {OID_PKIX_KP_LENGTH + 1, OID_KP_ClientAuth},

KMFOID_PKIX_KP_CodeSigning = {OID_PKIX_KP_LENGTH + 1, OID_KP_CodeSigning},

KMFOID_PKIX_KP_EmailProtection	 = {OID_PKIX_KP_LENGTH + 1,
	OID_KP_EmailProtection},

KMFOID_PKIX_KP_IPSecEndSystem = {OID_PKIX_KP_LENGTH + 1, OID_KP_IPSecEndSystem},

KMFOID_PKIX_KP_IPSecTunnel = {OID_PKIX_KP_LENGTH + 1, OID_KP_IPSecTunnel},

KMFOID_PKIX_KP_IPSecUser = {OID_PKIX_KP_LENGTH + 1, OID_KP_IPSecUser},

KMFOID_PKIX_KP_TimeStamping = {OID_PKIX_KP_LENGTH + 1, OID_KP_TimeStamping},

KMFOID_PKIX_KP_OCSPSigning = {OID_PKIX_KP_LENGTH + 1, OID_KP_OCSPSigning};

static uint8_t
OID_OIW_SHA1[] = { OID_OIW_ALGORITHM, 26},
OID_OIW_DSA[] = { OID_OIW_ALGORITHM, 12  },
OID_OIW_DSAWithSHA1[] = { OID_OIW_ALGORITHM, 13 },
OID_RSAEncryption[] = { OID_PKCS_1, 1 },
OID_MD2WithRSA[]   = { OID_PKCS_1, 2 },
OID_MD5WithRSA[]   = { OID_PKCS_1, 4 },
OID_SHA1WithRSA[]  = { OID_PKCS_1, 5 },
OID_SHA256WithRSA[]  = { OID_PKCS_1, 11 },
OID_SHA384WithRSA[]  = { OID_PKCS_1, 12 },
OID_SHA512WithRSA[]  = { OID_PKCS_1, 13 },
OID_X9CM_DSA[] = { OID_X9CM_X9ALGORITHM, 1 },
OID_X9CM_DSAWithSHA1[] = { OID_X9CM_X9ALGORITHM, 3};

const KMF_OID
KMFOID_SHA1 = {OID_OIW_ALGORITHM_LENGTH+1, OID_OIW_SHA1},
KMFOID_RSA = {OID_PKCS_1_LENGTH+1, OID_RSAEncryption},
KMFOID_DSA = {OID_OIW_ALGORITHM_LENGTH+1, OID_OIW_DSA},
KMFOID_MD5WithRSA = {OID_PKCS_1_LENGTH+1, OID_MD5WithRSA},
KMFOID_MD2WithRSA = {OID_PKCS_1_LENGTH+1, OID_MD2WithRSA},
KMFOID_SHA1WithRSA = {OID_PKCS_1_LENGTH+1, OID_SHA1WithRSA},
KMFOID_SHA256WithRSA = {OID_PKCS_1_LENGTH+1, OID_SHA256WithRSA},
KMFOID_SHA384WithRSA = {OID_PKCS_1_LENGTH+1, OID_SHA384WithRSA},
KMFOID_SHA512WithRSA = {OID_PKCS_1_LENGTH+1, OID_SHA512WithRSA},
KMFOID_SHA1WithDSA  = {OID_OIW_ALGORITHM_LENGTH+1, OID_OIW_DSAWithSHA1},
KMFOID_X9CM_DSA = {OID_X9CM_X9ALGORITHM_LENGTH+1, OID_X9CM_DSA},
KMFOID_X9CM_DSAWithSHA1 = {OID_X9CM_X9ALGORITHM_LENGTH+1,
		OID_X9CM_DSAWithSHA1};

/*
 * New for PKINIT support.
 */
static uint8_t
OID_pkinit_san[] = { OID_KRB5_SAN },
OID_pkinit_san_upn[] = { OID_MS_KP_SC_LOGON_UPN },
OID_pkinit_kp_clientauth[] = { OID_KRB5_PKINIT_KPCLIENTAUTH },
OID_pkinit_kp_kdc[] = { OID_KRB5_PKINIT_KPKDC },
OID_pkinit_kp_sc_logon[] = { OID_MS_KP_SC_LOGON };

const KMF_OID
KMFOID_PKINIT_san = {OID_KRB5_SAN_LENGTH, OID_pkinit_san },
KMFOID_PKINIT_ClientAuth = {OID_KRB5_PKINIT_KPCLIENTAUTH_LENGTH,
    OID_pkinit_kp_clientauth},
KMFOID_PKINIT_Kdc = {OID_KRB5_PKINIT_KPKDC_LENGTH,
    OID_pkinit_kp_kdc},
KMFOID_MS_KP_SCLogon = {OID_MS_KP_SC_LOGON_LENGTH,
    OID_pkinit_kp_sc_logon},
KMFOID_MS_KP_SCLogon_UPN = {OID_MS_KP_SC_LOGON_UPN_LENGTH,
    OID_pkinit_san_upn};

/*
 * MD5
 * iso(1) member-body(2) us(840) rsadsi(113549)
 * digestAlgorithm(2) 5
 */
#define	RSADSI 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d
#define	OID_id_md5	RSADSI, 0x02, 0x05

/*
 * SHA2 OIDs
 */
#define	NIST_ALG 96, 134, 72, 1, 101, 3, 4
#define	NIST_HASH NIST_ALG, 2
#define	OID_id_sha256 NIST_HASH, 1
#define	OID_id_sha384 NIST_HASH, 2
#define	OID_id_sha512 NIST_HASH, 3
#define	OID_id_sha224 NIST_HASH, 4

#define	OID_id_dsa_with_sha224	NIST_ALG, 3, 1
#define	OID_id_dsa_with_sha256	NIST_ALG, 3, 2

/*
 * For ECC support.
 */
#define	CERTICOM_OID	0x2b, 0x81, 0x04
#define	SECG_OID	CERTICOM_OID, 0x00

#define	ANSI_X962_OID		0x2a, 0x86, 0x48, 0xce, 0x3d
#define	ANSI_X962_CURVE_OID	ANSI_X962_OID, 0x03
#define	ANSI_X962_GF2m_OID	ANSI_X962_CURVE_OID, 0x00
#define	ANSI_X962_GFp_OID	ANSI_X962_CURVE_OID, 0x01

#define	ANSI_X962_SIG_OID	ANSI_X962_OID, 0x04
#define	OID_ecdsa_with_sha224	ANSI_X962_SIG_OID, 3, 1
#define	OID_ecdsa_with_sha256	ANSI_X962_SIG_OID, 3, 2
#define	OID_ecdsa_with_sha384	ANSI_X962_SIG_OID, 3, 3
#define	OID_ecdsa_with_sha512	ANSI_X962_SIG_OID, 3, 4

static uint8_t
OID_secp112r1[] = { 0x6, 0x5, SECG_OID, 0x06 },
OID_secp112r2[] = { 0x6, 0x5, SECG_OID, 0x07 },
OID_secp128r1[] = { 0x6, 0x5, SECG_OID, 0x1c },
OID_secp128r2[] = { 0x6, 0x5, SECG_OID, 0x1d },
OID_secp160k1[] = { 0x6, 0x5, SECG_OID, 0x09 },
OID_secp160r1[] = { 0x6, 0x5, SECG_OID, 0x08 },
OID_secp160r2[] = { 0x6, 0x5, SECG_OID, 0x1e },
OID_secp192k1[] = { 0x6, 0x5, SECG_OID, 0x1f },
OID_secp224k1[] = { 0x6, 0x5, SECG_OID, 0x20 },
OID_secp224r1[] = { 0x6, 0x5, SECG_OID, 0x21 },
OID_secp256k1[] = { 0x6, 0x5, SECG_OID, 0x0a },
OID_secp384r1[] = { 0x6, 0x5, SECG_OID, 0x22 },
OID_secp521r1[] = { 0x6, 0x5, SECG_OID, 0x23 },
OID_sect113r1[] = { 0x6, 0x5, SECG_OID, 0x04 },
OID_sect113r2[] = { 0x6, 0x5, SECG_OID, 0x05 },
OID_sect131r1[] = { 0x6, 0x5, SECG_OID, 0x16 },
OID_sect131r2[] = { 0x6, 0x5, SECG_OID, 0x17 },
OID_sect163k1[] = { 0x6, 0x5, SECG_OID, 0x01 },
OID_sect163r1[] = { 0x6, 0x5, SECG_OID, 0x02 },
OID_sect163r2[] = { 0x6, 0x5, SECG_OID, 0x0f },
OID_sect193r1[] = { 0x6, 0x5, SECG_OID, 0x18 },
OID_sect193r2[] = { 0x6, 0x5, SECG_OID, 0x19 },
OID_sect233k1[] = { 0x6, 0x5, SECG_OID, 0x1a },
OID_sect233r1[] = { 0x6, 0x5, SECG_OID, 0x1b },
OID_sect239k1[] = { 0x6, 0x5, SECG_OID, 0x03 },
OID_sect283k1[] = { 0x6, 0x5, SECG_OID, 0x10 },
OID_sect283r1[] = { 0x6, 0x5, SECG_OID, 0x11 },
OID_sect409k1[] = { 0x6, 0x5, SECG_OID, 0x24 },
OID_sect409r1[] = { 0x6, 0x5, SECG_OID, 0x25 },
OID_sect571k1[] = { 0x6, 0x5, SECG_OID, 0x26 },
OID_sect571r1[] = { 0x6, 0x5, SECG_OID, 0x27 },
OID_c2pnb163v1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x01 },
OID_c2pnb163v2[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x02 },
OID_c2pnb163v3[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x03 },
OID_c2pnb176v1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x04 },
OID_c2tnb191v1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x05 },
OID_c2tnb191v2[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x06 },
OID_c2tnb191v3[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x07 },
OID_c2pnb208w1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x0a },
OID_c2tnb239v1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x0b },
OID_c2tnb239v2[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x0c },
OID_c2tnb239v3[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x0d },
OID_c2pnb272w1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x10 },
OID_c2pnb304w1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x11 },
OID_c2tnb359v1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x12 },
OID_c2pnb368w1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x13 },
OID_c2tnb431r1[] = { 0x6, 0x8, ANSI_X962_GF2m_OID, 0x14 },

OID_prime192v2[] = { 0x6, 0x8, ANSI_X962_GFp_OID, 0x02 },
OID_prime192v3[] = { 0x6, 0x8, ANSI_X962_GFp_OID, 0x03 },

OID_secp192r1[] = { 0x6, 0x8, ANSI_X962_GFp_OID, 0x01 },
OID_secp256r1[] = { 0x6, 0x8, ANSI_X962_GFp_OID, 0x07 };

const KMF_OID
KMFOID_ECC_secp112r1 = {sizeof (OID_secp112r1), OID_secp112r1},
KMFOID_ECC_secp112r2 = {sizeof (OID_secp112r2), OID_secp112r2},
KMFOID_ECC_secp128r1 = {sizeof (OID_secp128r1), OID_secp128r1},
KMFOID_ECC_secp128r2 = {sizeof (OID_secp128r2), OID_secp128r2},
KMFOID_ECC_secp160k1 = {sizeof (OID_secp160k1), OID_secp160k1},
KMFOID_ECC_secp160r1 = {sizeof (OID_secp160r1), OID_secp160r1},
KMFOID_ECC_secp160r2 = {sizeof (OID_secp160r2), OID_secp160r2},
KMFOID_ECC_secp192k1 = {sizeof (OID_secp192k1), OID_secp192k1},
KMFOID_ECC_secp224k1 = {sizeof (OID_secp224k1), OID_secp224k1},
KMFOID_ECC_secp224r1 = {sizeof (OID_secp224r1), OID_secp224r1},
KMFOID_ECC_secp256k1 = {sizeof (OID_secp256k1), OID_secp256k1},
KMFOID_ECC_secp384r1 = {sizeof (OID_secp384r1), OID_secp384r1},
KMFOID_ECC_secp521r1 = {sizeof (OID_secp521r1), OID_secp521r1},
KMFOID_ECC_sect113r1 = {sizeof (OID_sect113r1), OID_sect113r1},
KMFOID_ECC_sect113r2 = {sizeof (OID_sect113r2), OID_sect113r2},
KMFOID_ECC_sect131r1 = {sizeof (OID_sect131r1), OID_sect131r1},
KMFOID_ECC_sect131r2 = {sizeof (OID_sect131r2), OID_sect131r2},
KMFOID_ECC_sect163k1 = {sizeof (OID_sect163k1), OID_sect163k1},
KMFOID_ECC_sect163r1 = {sizeof (OID_sect163r1), OID_sect163r1},
KMFOID_ECC_sect163r2 = {sizeof (OID_sect163r2), OID_sect163r2},
KMFOID_ECC_sect193r1 = {sizeof (OID_sect193r1), OID_sect193r1},
KMFOID_ECC_sect193r2 = {sizeof (OID_sect193r2), OID_sect193r2},
KMFOID_ECC_sect233k1 = {sizeof (OID_sect233k1), OID_sect233k1},
KMFOID_ECC_sect233r1 = {sizeof (OID_sect233r1), OID_sect233r1},
KMFOID_ECC_sect239k1 = {sizeof (OID_sect239k1), OID_sect239k1},
KMFOID_ECC_sect283k1 = {sizeof (OID_sect283k1), OID_sect283k1},
KMFOID_ECC_sect283r1 = {sizeof (OID_sect283r1), OID_sect283r1},
KMFOID_ECC_sect409k1 = {sizeof (OID_sect409k1), OID_sect409k1},
KMFOID_ECC_sect409r1 = {sizeof (OID_sect409r1), OID_sect409r1},
KMFOID_ECC_sect571k1 = {sizeof (OID_sect571k1), OID_sect571k1},
KMFOID_ECC_sect571r1 = {sizeof (OID_sect571r1), OID_sect571r1},
KMFOID_ECC_c2pnb163v1 = {sizeof (OID_c2pnb163v1), OID_c2pnb163v1},
KMFOID_ECC_c2pnb163v2 = {sizeof (OID_c2pnb163v2), OID_c2pnb163v2},
KMFOID_ECC_c2pnb163v3 = {sizeof (OID_c2pnb163v3), OID_c2pnb163v3},
KMFOID_ECC_c2pnb176v1 = {sizeof (OID_c2pnb176v1), OID_c2pnb176v1},
KMFOID_ECC_c2tnb191v1 = {sizeof (OID_c2tnb191v1), OID_c2tnb191v1},
KMFOID_ECC_c2tnb191v2 = {sizeof (OID_c2tnb191v2), OID_c2tnb191v2},
KMFOID_ECC_c2tnb191v3 = {sizeof (OID_c2tnb191v3), OID_c2tnb191v3},
KMFOID_ECC_c2pnb208w1 = {sizeof (OID_c2pnb208w1), OID_c2pnb208w1},
KMFOID_ECC_c2tnb239v1 = {sizeof (OID_c2tnb239v1), OID_c2tnb239v1},
KMFOID_ECC_c2tnb239v2 = {sizeof (OID_c2tnb239v2), OID_c2tnb239v2},
KMFOID_ECC_c2tnb239v3 = {sizeof (OID_c2tnb239v3), OID_c2tnb239v3},
KMFOID_ECC_c2pnb272w1 = {sizeof (OID_c2pnb272w1), OID_c2pnb272w1},
KMFOID_ECC_c2pnb304w1 = {sizeof (OID_c2pnb304w1), OID_c2pnb304w1},
KMFOID_ECC_c2tnb359v1 = {sizeof (OID_c2tnb359v1), OID_c2tnb359v1},
KMFOID_ECC_c2pnb368w1 = {sizeof (OID_c2pnb368w1), OID_c2pnb368w1},
KMFOID_ECC_c2tnb431r1 = {sizeof (OID_c2tnb431r1), OID_c2tnb431r1},
KMFOID_ECC_prime192v2 = {sizeof (OID_prime192v2), OID_prime192v2},
KMFOID_ECC_prime192v3 = {sizeof (OID_prime192v3), OID_prime192v3},
KMFOID_ECC_secp192r1 = {sizeof (OID_secp192r1), OID_secp192r1},
KMFOID_ECC_secp256r1 = {sizeof (OID_secp256r1), OID_secp256r1};

static uint8_t
OID_EC_PUBLIC_KEY[] = {ANSI_X962_OID, 0x02, 0x01},
OID_ECDSA_SHA1[] = {ANSI_X962_OID, 0x04, 0x01},
OID_ECDSA_SHA224[] = {ANSI_X962_OID, 0x04, 0x03, 0x01},
OID_ECDSA_SHA256[] = {ANSI_X962_OID, 0x04, 0x03, 0x02},
OID_ECDSA_SHA384[] = {ANSI_X962_OID, 0x04, 0x03, 0x03},
OID_ECDSA_SHA512[] = {ANSI_X962_OID, 0x04, 0x03, 0x04},
OID_DSA_SHA224[] = {OID_id_dsa_with_sha224},
OID_DSA_SHA256[] = {OID_id_dsa_with_sha256},
OID_SHA224[] = {OID_id_sha224},
OID_SHA256[] = {OID_id_sha256},
OID_SHA384[] = {OID_id_sha384},
OID_SHA512[] = {OID_id_sha512},
OID_MD5[] = {OID_id_md5};

const KMF_OID
KMFOID_EC_PUBLIC_KEY = { sizeof (OID_EC_PUBLIC_KEY), OID_EC_PUBLIC_KEY},
KMFOID_SHA1WithECDSA = { sizeof (OID_ECDSA_SHA1), OID_ECDSA_SHA1},
KMFOID_SHA224WithECDSA = { sizeof (OID_ECDSA_SHA224), OID_ECDSA_SHA224},
KMFOID_SHA256WithECDSA = { sizeof (OID_ECDSA_SHA256), OID_ECDSA_SHA256},
KMFOID_SHA384WithECDSA = { sizeof (OID_ECDSA_SHA384), OID_ECDSA_SHA384},
KMFOID_SHA512WithECDSA = { sizeof (OID_ECDSA_SHA512), OID_ECDSA_SHA512},
KMFOID_SHA224WithDSA = { sizeof (OID_DSA_SHA224), OID_DSA_SHA224},
KMFOID_SHA256WithDSA = { sizeof (OID_DSA_SHA256), OID_DSA_SHA256},
KMFOID_SHA224 = { sizeof (OID_SHA224), OID_SHA224},
KMFOID_SHA256 = { sizeof (OID_SHA256), OID_SHA256},
KMFOID_SHA384 = { sizeof (OID_SHA384), OID_SHA384},
KMFOID_SHA512 = { sizeof (OID_SHA512), OID_SHA512},
KMFOID_MD5 = { sizeof (OID_MD5), OID_MD5};
