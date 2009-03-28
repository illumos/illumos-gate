/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

//----------------------------------------------------------------------------
//
//  File:       StatusCodeDefinitions.h
//
//  Notes:      This file contains the definitions of the status codes
//              as defined in the Intel® AMT Network Design Guide.
//
//----------------------------------------------------------------------------

#ifndef STATUS_CODE_DEFINITIONS_H
#define STATUS_CODE_DEFINITIONS_H

typedef unsigned int PT_STATUS;
typedef unsigned int AMT_STATUS;

//Request succeeded
#define PT_STATUS_SUCCESS  0x0
#define AMT_STATUS_SUCCESS  0x0

//An internal error in the Intel® AMT device has occurred
#define PT_STATUS_INTERNAL_ERROR  0x1
#define AMT_STATUS_INTERNAL_ERROR  0x1

//Intel® AMT device has not progressed far enough in its
//initialization to process the command.
#define PT_STATUS_NOT_READY  0x2
#define AMT_STATUS_NOT_READY  0x2

//Command is not permitted in current operating mode.
#define PT_STATUS_INVALID_PT_MODE  0x3
#define AMT_STATUS_INVALID_AMT_MODE  0x3

//Length field of header is invalid.
#define PT_STATUS_INVALID_MESSAGE_LENGTH  0x4
#define AMT_STATUS_INVALID_MESSAGE_LENGTH  0x4

//The requested hardware asset inventory table
//checksum is not available.
#define PT_STATUS_TABLE_FINGERPRINT_NOT_AVAILABLE  0x5
#define AMT_STATUS_TABLE_FINGERPRINT_NOT_AVAILABLE  0x5

//The Integrity Check Value field of the request
//message sent by Intel® AMT enabled device is invalid.
#define PT_STATUS_INTEGRITY_CHECK_FAILED  0x6
#define AMT_STATUS_INTEGRITY_CHECK_FAILED  0x6

//The specified ISV version is not supported
#define PT_STATUS_UNSUPPORTED_ISVS_VERSION  0x7
#define AMT_STATUS_UNSUPPORTED_ISVS_VERSION  0x7

//The specified queried application is not registered.
#define PT_STATUS_APPLICATION_NOT_REGISTERED  0x8
#define AMT_STATUS_APPLICATION_NOT_REGISTERED  0x8

//Either an invalid name or a not previously registered
//'Enterprise' name was specified
#define PT_STATUS_INVALID_REGISTRATION_DATA  0x9
#define AMT_STATUS_INVALID_REGISTRATION_DATA  0x9

//The application handle provided in the request
//message has never been allocated.
#define PT_STATUS_APPLICATION_DOES_NOT_EXIST  0xA
#define AMT_STATUS_APPLICATION_DOES_NOT_EXIST  0xA

//The requested number of bytes cannot be allocated in ISV storage.
#define PT_STATUS_NOT_ENOUGH_STORAGE  0xB
#define AMT_STATUS_NOT_ENOUGH_STORAGE  0xB

//The specified name is invalid.
#define PT_STATUS_INVALID_NAME  0xC
#define AMT_STATUS_INVALID_NAME  0xC

//The specified block does not exist.
#define PT_STATUS_BLOCK_DOES_NOT_EXIST  0xD
#define AMT_STATUS_BLOCK_DOES_NOT_EXIST  0xD

//The specified byte offset is invalid.
#define PT_STATUS_INVALID_BYTE_OFFSET  0xE
#define AMT_STATUS_INVALID_BYTE_OFFSET  0xE

//The specified byte count is invalid.
#define PT_STATUS_INVALID_BYTE_COUNT  0xF
#define AMT_STATUS_INVALID_BYTE_COUNT  0xF

//The requesting application is not
//permitted to request execution of the specified operation.
#define PT_STATUS_NOT_PERMITTED  0x10
#define AMT_STATUS_NOT_PERMITTED  0x10

//The requesting application is not the owner of the block
//as required for the requested operation.
#define PT_STATUS_NOT_OWNER  0x11
#define AMT_STATUS_NOT_OWNER  0x11

//The specified block is locked by another application.
#define PT_STATUS_BLOCK_LOCKED_BY_OTHER  0x12
#define AMT_STATUS_BLOCK_LOCKED_BY_OTHER  0x12

//The specified block is not locked.
#define PT_STATUS_BLOCK_NOT_LOCKED  0x13
#define AMT_STATUS_BLOCK_NOT_LOCKED  0x13

//The specified group permission bits are invalid.
#define PT_STATUS_INVALID_GROUP_PERMISSIONS  0x14
#define AMT_STATUS_INVALID_GROUP_PERMISSIONS  0x14

//The specified group does not exist.
#define PT_STATUS_GROUP_DOES_NOT_EXIST  0x15
#define AMT_STATUS_GROUP_DOES_NOT_EXIST  0x15

//The specified member count is invalid.
#define PT_STATUS_INVALID_MEMBER_COUNT  0x16
#define AMT_STATUS_INVALID_MEMBER_COUNT  0x16

//The request cannot be satisfied because a maximum
//limit associated with the request has been reached.
#define PT_STATUS_MAX_LIMIT_REACHED  0x17
#define AMT_STATUS_MAX_LIMIT_REACHED  0x17

//specified key algorithm is invalid.
#define PT_STATUS_INVALID_AUTH_TYPE  0x18
#define AMT_STATUS_INVALID_AUTH_TYPE  0x18

//Not Used
#define PT_STATUS_AUTHENTICATION_FAILED  0x19
#define AMT_STATUS_AUTHENTICATION_FAILED  0x19

//The specified DHCP mode is invalid.
#define PT_STATUS_INVALID_DHCP_MODE  0x1A
#define AMT_STATUS_INVALID_DHCP_MODE  0x1A

//The specified IP address is not a valid IP unicast address.
#define PT_STATUS_INVALID_IP_ADDRESS  0x1B
#define AMT_STATUS_INVALID_IP_ADDRESS  0x1B

//The specified domain name is not a valid domain name.
#define PT_STATUS_INVALID_DOMAIN_NAME  0x1C
#define AMT_STATUS_INVALID_DOMAIN_NAME  0x1C

//Not Used
#define PT_STATUS_UNSUPPORTED_VERSION  0x1D
#define AMT_STATUS_UNSUPPORTED_VERSION  0x1D

//The requested operation cannot be performed because a
//prerequisite request message has not been received.
#define PT_STATUS_REQUEST_UNEXPECTED  0x1E
#define AMT_STATUS_REQUEST_UNEXPECTED  0x1E

//Not Used
#define PT_STATUS_INVALID_TABLE_TYPE  0x1F
#define AMT_STATUS_INVALID_TABLE_TYPE  0x1F

//The specified provisioning mode code is undefined.
#define PT_STATUS_INVALID_PROVISIONING_STATE  0x20
#define AMT_STATUS_INVALID_PROVISIONING_STATE  0x20

//Not Used
#define PT_STATUS_UNSUPPORTED_OBJECT  0x21
#define AMT_STATUS_UNSUPPORTED_OBJECT  0x21

//The specified time was not accepted by the Intel® AMT device
//since it is earlier than the baseline time set for the device.
#define PT_STATUS_INVALID_TIME  0x22
#define AMT_STATUS_INVALID_TIME  0x22

//StartingIndex is invalid.
#define PT_STATUS_INVALID_INDEX  0x23
#define AMT_STATUS_INVALID_INDEX  0x23

//A parameter is invalid.
#define PT_STATUS_INVALID_PARAMETER  0x24
#define AMT_STATUS_INVALID_PARAMETER  0x24

//An invalid netmask was supplied
//(a valid netmask is an IP address in which all '1's are before
//the '0' - e.g. FFFC0000h is valid, FF0C0000h is invalid).
#define PT_STATUS_INVALID_NETMASK  0x25
#define AMT_STATUS_INVALID_NETMASK  0x25

//The operation failed because the Flash wear-out
//protection mechanism prevented a write to an NVRAM sector.
#define PT_STATUS_FLASH_WRITE_LIMIT_EXCEEDED  0x26
#define AMT_STATUS_FLASH_WRITE_LIMIT_EXCEEDED  0x26

//ME FW did not receive the entire image file.
#define PT_STATUS_INVALID_IMAGE_LENGTH  0x27
#define AMT_STATUS_INVALID_IMAGE_LENGTH  0x27

//ME FW received an image file with an invalid signature.
#define PT_STATUS_INVALID_IMAGE_SIGNATURE  0x28
#define AMT_STATUS_INVALID_IMAGE_SIGNATURE  0x28

//LME can not support the requested version.
#define	PT_STATUS_PROPOSE_ANOTHER_VERSION  0x29
#define	AMT_STATUS_PROPOSE_ANOTHER_VERSION  0x29

//The PID must be a 64 bit quantity made up of ASCII codes
//of some combination of 8 characters -
//capital alphabets (A-Z), and numbers (0-9).
#define	PT_STATUS_INVALID_PID_FORMAT  0x2A
#define	AMT_STATUS_INVALID_PID_FORMAT  0x2A

//The PID must be a 256 bit quantity made up of ASCII codes
//of some combination of 8 characters -
//capital alphabets (A-Z), and numbers (0-9).
#define	PT_STATUS_INVALID_PPS_FORMAT  0x2B
#define	AMT_STATUS_INVALID_PPS_FORMAT  0x2B

//Full BIST test has been blocked
#define PT_STATUS_BIST_COMMAND_BLOCKED  0x2C
#define AMT_STATUS_BIST_COMMAND_BLOCKED  0x2C

//A TCP/IP connection could not be opened on with the selected port.
#define PT_STATUS_CONNECTION_FAILED  0x2D
#define AMT_STATUS_CONNECTION_FAILED  0x2D

//Max number of connection reached.
//LME can not open the requested connection.
#define PT_STATUS_CONNECTION_TOO_MANY  0x2E
#define AMT_STATUS_CONNECTION_TOO_MANY  0x2E

// A process rng generation  started.
#define PT_STATUS_RNG_GENERATION_IN_PROGRESS  0x002F
#define AMT_STATUS_RNG_GENERATION_IN_PROGRESS  0x002F

//rng doesn't exist
#define PT_STATUS_RNG_NOT_READY  0x0030
#define AMT_STATUS_RNG_NOT_READY  0x0030

//Certificate doesn't exist
#define PT_STATUS_CERTIFICATE_NOT_READY  0x0031
#define AMT_STATUS_CERTIFICATE_NOT_READY  0x0031

//AMT doesn't grant remote access
//(AMT has a direct connection to enterprise network).
#define PT_STATUS_REMOTE_ACCESS_NOT_GRANTED 0x0200
#define AMT_STATUS_REMOTE_ACCESS_NOT_GRANTED 0x0200

//VPN is disabled (via the AMT Network Interface)
#define PT_STATUS_REMOTE_ACCESS_HOST_VPN_IS_DISABLED 0x0201
#define AMT_STATUS_REMOTE_ACCESS_HOST_VPN_IS_DISABLED 0x0201

//This code establishes a dividing line between
//status codes which are common to host interface and
//network interface and status codes which are used by
//network interface only.
#define PT_STATUS_NETWORK_IF_ERROR_BASE  0x800
#define AMT_STATUS_NETWORK_IF_ERROR_BASE  0x800

//The OEM number specified in the remote control
//command is not supported by the Intel® AMT device
#define PT_STATUS_UNSUPPORTED_OEM_NUMBER  0x801
#define AMT_STATUS_UNSUPPORTED_OEM_NUMBER  0x801

//The boot option specified in the remote control command
//is not supported by the Intel® AMT device
#define PT_STATUS_UNSUPPORTED_BOOT_OPTION  0x802
#define AMT_STATUS_UNSUPPORTED_BOOT_OPTION  0x802

//The command specified in the remote control command
//is not supported by the Intel® AMT device
#define PT_STATUS_INVALID_COMMAND  0x803
#define AMT_STATUS_INVALID_COMMAND  0x803

//The special command specified in the remote control command
//is not supported by the Intel® AMT device
#define PT_STATUS_INVALID_SPECIAL_COMMAND  0x804
#define AMT_STATUS_INVALID_SPECIAL_COMMAND  0x804

//The handle specified in the command is invalid
#define PT_STATUS_INVALID_HANDLE  0x805
#define AMT_STATUS_INVALID_HANDLE  0x805

//The password specified in the User ACL is invalid
#define PT_STATUS_INVALID_PASSWORD  0x806
#define AMT_STATUS_INVALID_PASSWORD  0x806

//The realm specified in the User ACL is invalid
#define PT_STATUS_INVALID_REALM  0x807
#define AMT_STATUS_INVALID_REALM  0x807

//The FPACL or EACL entry is used by an active
//registration and cannot be removed or modified.
#define PT_STATUS_STORAGE_ACL_ENTRY_IN_USE  0x808
#define AMT_STATUS_STORAGE_ACL_ENTRY_IN_USE  0x808

//Essential data is missing on CommitChanges command.
#define PT_STATUS_DATA_MISSING  0x809
#define AMT_STATUS_DATA_MISSING  0x809

//The parameter specified is a duplicate of an existing value.
//Returned for a case where duplicate entries are added to FPACL
//(Factory Partner Allocation Control List) or EACL
//(Enterprise Access Control List) lists.
#define PT_STATUS_DUPLICATE  0x80A
#define AMT_STATUS_DUPLICATE  0x80A

//Event Log operation failed due to the current freeze status of the log.
#define PT_STATUS_EVENTLOG_FROZEN  0x80B
#define AMT_STATUS_EVENTLOG_FROZEN  0x80B

//The device is missing private key material.
#define PT_STATUS_PKI_MISSING_KEYS  0x80C
#define AMT_STATUS_PKI_MISSING_KEYS  0x80C

//The device is currently generating a keypair.
//Caller may try repeating this operation at a later time.
#define PT_STATUS_PKI_GENERATING_KEYS  0x80D
#define AMT_STATUS_PKI_GENERATING_KEYS  0x80D

//An invalid Key was entered.
#define PT_STATUS_INVALID_KEY  0x80E
#define AMT_STATUS_INVALID_KEY  0x80E

//An invalid X.509 certificate was entered.
#define PT_STATUS_INVALID_CERT  0x80F
#define AMT_STATUS_INVALID_CERT  0x80F

//Certificate Chain and Private Key do not match.
#define PT_STATUS_CERT_KEY_NOT_MATCH  0x810
#define AMT_STATUS_CERT_KEY_NOT_MATCH  0x810

//The request cannot be satisfied because the maximum
//number of allowed Kerberos domains has been reached.
//(The domain is determined by the first 24 Bytes of the SID.)
#define PT_STATUS_MAX_KERB_DOMAIN_REACHED 0x811
#define AMT_STATUS_MAX_KERB_DOMAIN_REACHED 0x811

// The requested configuration is unsupported
#define PT_STATUS_UNSUPPORTED 0x812
#define AMT_STATUS_UNSUPPORTED 0x812

// A profile with the requested priority already exists
#define PT_STATUS_INVALID_PRIORITY 0x813
#define AMT_STATUS_INVALID_PRIORITY 0x813

// Unable to find specified element
#define PT_STATUS_NOT_FOUND 0x814
#define AMT_STATUS_NOT_FOUND 0x814

// Invalid User credentials
#define PT_STATUS_INVALID_CREDENTIALS 0x815
#define AMT_STATUS_INVALID_CREDENTIALS 0x815

// Passphrase is invalid
#define PT_STATUS_INVALID_PASSPHRASE 0x816
#define AMT_STATUS_INVALID_PASSPHRASE 0x816

//The application has identified an internal error
#define PTSDK_STATUS_INTERNAL_ERROR  0x1000

//An ISV operation was called while the library is not
//initialized
#define PTSDK_STATUS_NOT_INITIALIZED  0x1001

//The requested library I/F is not supported by the current library
//implementation.
#define PTSDK_STATUS_LIB_VERSION_UNSUPPORTED  0x1002

//One of the parameters is invalid (usually indicates a
//NULL pointer or an invalid session handle is specified)
#define PTSDK_STATUS_INVALID_PARAM  0x1003

//The SDK could not allocate sufficient resources to complete the operation.
#define PTSDK_STATUS_RESOURCES  0x1004

//The Library has identified a HW Internal error.
#define PTSDK_STATUS_HARDWARE_ACCESS_ERROR  0x1005

//The application that sent the request message is not registered.
//Usually indicates the registration timeout has elapsed.
//The caller should reregister with the Intel AMT enabled device.
#define PTSDK_STATUS_REQUESTOR_NOT_REGISTERED  0x1006

//A network error has occurred while processing the call.
#define PTSDK_STATUS_NETWORK_ERROR  0x1007

//Specified container can not hold the requested string
#define PTSDK_STATUS_PARAM_BUFFER_TOO_SHORT  0x1008

//For Windows only.
//ISVS_InitializeCOMinThread was not called by the current thread.
#define PTSDK_STATUS_COM_NOT_INITIALIZED_IN_THREAD  0x1009

//The URL parameter was not optional in current configuration.
#define PTSDK_STATUS_URL_REQUIRED	 0x100A

//Empty response from PTHI interface
#define PTHI_STATUS_EMPTY_RESPONSE  0x4000

#endif
