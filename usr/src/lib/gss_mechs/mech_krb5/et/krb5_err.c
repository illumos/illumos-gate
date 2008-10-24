/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <locale.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

const char *
krb5_error_table(long errorno) {

switch (errorno) {
	case 0:
		return (dgettext(TEXT_DOMAIN,
			"No error"));
	case 1:
		return (dgettext(TEXT_DOMAIN,
			"Client's entry in database has expired"));
	case 2:
		return (dgettext(TEXT_DOMAIN,
			"Server's entry in database has expired"));
	case 3:
		return (dgettext(TEXT_DOMAIN,
			"Requested protocol version not supported"));
	case 4:
		return (dgettext(TEXT_DOMAIN,
			"Client's key is encrypted in an old master key"));
	case 5:
		return (dgettext(TEXT_DOMAIN,
			"Server's key is encrypted in an old master key"));
	case 6:
		return (dgettext(TEXT_DOMAIN,
			"Client not found in Kerberos database"));
	case 7:
		return (dgettext(TEXT_DOMAIN,
			"Server not found in Kerberos database"));
	case 8:
		return (dgettext(TEXT_DOMAIN,
			"Principal has multiple entries in Kerberos database"));
	case 9:
		return (dgettext(TEXT_DOMAIN,
			"Client or server has a null key"));
	case 10:
		return (dgettext(TEXT_DOMAIN,
			"Ticket is ineligible for postdating"));
	case 11:
		return (dgettext(TEXT_DOMAIN,
		"Requested effective lifetime is negative or too short"));
	case 12:
		return (dgettext(TEXT_DOMAIN,
			"KDC policy rejects request"));
	case 13:
		return (dgettext(TEXT_DOMAIN,
			"KDC can't fulfill requested option"));
	case 14:
		return (dgettext(TEXT_DOMAIN,
			"KDC has no support for encryption type"));
	case 15:
		return (dgettext(TEXT_DOMAIN,
			"KDC has no support for checksum type"));
	case 16:
		return (dgettext(TEXT_DOMAIN,
			"KDC has no support for padata type"));
	case 17:
		return (dgettext(TEXT_DOMAIN,
			"KDC has no support for transited type"));
	case 18:
		return (dgettext(TEXT_DOMAIN,
			"Clients credentials have been revoked"));
	case 19:
		return (dgettext(TEXT_DOMAIN,
			"Credentials for server have been revoked"));
	case 20:
		return (dgettext(TEXT_DOMAIN,
			"TGT has been revoked"));
	case 21:
		return (dgettext(TEXT_DOMAIN,
			"Client not yet valid - try again later"));
	case 22:
		return (dgettext(TEXT_DOMAIN,
			"Server not yet valid - try again later"));
	case 23:
		return (dgettext(TEXT_DOMAIN,
			"Password has expired"));
	case 24:
		return (dgettext(TEXT_DOMAIN,
			"Preauthentication failed"));
	case 25:
		return (dgettext(TEXT_DOMAIN,
			"Additional pre-authentication required"));
	case 26:
		return (dgettext(TEXT_DOMAIN,
			"Requested server and ticket don't match"));
	case 27:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 27"));
	case 28:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 28"));
	case 29:
		return (dgettext(TEXT_DOMAIN,
			"A service is not available that is required to "
			"process the request"));
	case 30:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 30"));
	case 31:
		return (dgettext(TEXT_DOMAIN,
			"Decrypt integrity check failed"));
	case 32:
		return (dgettext(TEXT_DOMAIN,
			"Ticket expired"));
	case 33:
		return (dgettext(TEXT_DOMAIN,
			"Ticket not yet valid"));
	case 34:
		return (dgettext(TEXT_DOMAIN,
			"Request is a replay"));
	case 35:
		return (dgettext(TEXT_DOMAIN,
			"The ticket isn't for us"));
	case 36:
		return (dgettext(TEXT_DOMAIN,
			"Ticket/authenticator don't match"));
	case 37:
		return (dgettext(TEXT_DOMAIN,
			"Clock skew too great"));
	case 38:
		return (dgettext(TEXT_DOMAIN,
			"Incorrect net address"));
	case 39:
		return (dgettext(TEXT_DOMAIN,
			"Protocol version mismatch"));
	case 40:
		return (dgettext(TEXT_DOMAIN,
			"Invalid message type"));
	case 41:
		return (dgettext(TEXT_DOMAIN,
			"Message stream modified"));
	case 42:
		return (dgettext(TEXT_DOMAIN,
			"Message out of order"));
	case 43:
		return (dgettext(TEXT_DOMAIN,
			"Illegal cross-realm ticket"));
	case 44:
		return (dgettext(TEXT_DOMAIN,
			"Key version is not available"));
	case 45:
		return (dgettext(TEXT_DOMAIN,
			"Service key not available"));
	case 46:
		return (dgettext(TEXT_DOMAIN,
			"Mutual authentication failed"));
	case 47:
		return (dgettext(TEXT_DOMAIN,
			"Incorrect message direction"));
	case 48:
		return (dgettext(TEXT_DOMAIN,
			"Alternative authentication method required"));
	case 49:
		return (dgettext(TEXT_DOMAIN,
			"Incorrect sequence number in message"));
	case 50:
		return (dgettext(TEXT_DOMAIN,
			"Inappropriate type of checksum in message"));
	case 51:
		return (dgettext(TEXT_DOMAIN,
			"Policy rejects transited path"));
	case 52:
		return (dgettext(TEXT_DOMAIN,
			"Response too big for UDP, retry with TCP"));
	case 53:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 53"));
	case 54:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 54"));
	case 55:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 55"));
	case 56:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 56"));
	case 57:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 57"));
	case 58:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 58"));
	case 59:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 59"));
	case 60:
		return (dgettext(TEXT_DOMAIN,
			"Generic error (see e-text)"));
	case 61:
		return (dgettext(TEXT_DOMAIN,
			"Field is too long for this implementation"));
	case 62:
		return (dgettext(TEXT_DOMAIN,
			"Client not trusted"));
	case 63:
		return (dgettext(TEXT_DOMAIN,
			"KDC not trusted"));
	case 64:
		return (dgettext(TEXT_DOMAIN,
			"Invalid signature"));
	case 65:
		return (dgettext(TEXT_DOMAIN,
			"Key parameters not accepted"));
	case 66:
		return (dgettext(TEXT_DOMAIN,
			"Certificate mismatch"));
	case 67:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 67"));
	case 68:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 68"));
	case 69:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 69"));
	case 70:
		return (dgettext(TEXT_DOMAIN,
			"Can't verify certificate"));
	case 71:
		return (dgettext(TEXT_DOMAIN,
			"Invalid certificate"));
	case 72:
		return (dgettext(TEXT_DOMAIN,
			"Revoked certificate"));
	case 73:
		return (dgettext(TEXT_DOMAIN,
			"Revocation status unknown"));
	case 74:
		return (dgettext(TEXT_DOMAIN,
			"Revocation status unavailable"));
	case 75:
		return (dgettext(TEXT_DOMAIN,
			"Client name mismatch"));
	case 76:
		return (dgettext(TEXT_DOMAIN,
			"KDC name mismatch"));
	case 77:
		return (dgettext(TEXT_DOMAIN,
			"Inconsistent key purpose"));
	case 78:
		return (dgettext(TEXT_DOMAIN,
			"Digest in certificate not accepted"));
	case 79:
		return (dgettext(TEXT_DOMAIN,
			"Checksum must be included"));
	case 80:
		return (dgettext(TEXT_DOMAIN,
			"Digest in signed-data not accepted"));
	case 81:
		return (dgettext(TEXT_DOMAIN,
			"Public key encryption not supported"));
	case 82:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 82"));
	case 83:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 83"));
	case 84:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 84"));
	case 85:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 85"));
	case 86:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 86"));
	case 87:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 87"));
	case 88:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 88"));
	case 89:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 89"));
	case 90:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 90"));
	case 91:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 91"));
	case 92:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 92"));
	case 93:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 93"));
	case 94:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 94"));
	case 95:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 95"));
	case 96:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 96"));
	case 97:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 97"));
	case 98:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 98"));
	case 99:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 99"));
	case 100:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 100"));
	case 101:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 101"));
	case 102:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 102"));
	case 103:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 103"));
	case 104:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 104"));
	case 105:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 105"));
	case 106:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 106"));
	case 107:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 107"));
	case 108:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 108"));
	case 109:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 109"));
	case 110:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 110"));
	case 111:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 111"));
	case 112:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 112"));
	case 113:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 113"));
	case 114:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 114"));
	case 115:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 115"));
	case 116:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 116"));
	case 117:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 117"));
	case 118:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 118"));
	case 119:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 119"));
	case 120:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 120"));
	case 121:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 121"));
	case 122:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 122"));
	case 123:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 123"));
	case 124:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 124"));
	case 125:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 125"));
	case 126:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 126"));
	case 127:
		return (dgettext(TEXT_DOMAIN,
			"KRB5 error code 127"));
	case 128:
		return (
		"$Id: krb5_err.et,v 5.66 1999/12/06 21:45:03 raeburn Exp $");
	case 129:
		return (dgettext(TEXT_DOMAIN,
			"Invalid flag for file lock mode"));
	case 130:
		return (dgettext(TEXT_DOMAIN,
			"Cannot read password"));
	case 131:
		return (dgettext(TEXT_DOMAIN,
			"Password mismatch"));
	case 132:
		return (dgettext(TEXT_DOMAIN,
			"Password read interrupted"));
	case 133:
		return (dgettext(TEXT_DOMAIN,
			"Illegal character in component name"));
	case 134:
		return (dgettext(TEXT_DOMAIN,
			"Malformed representation of principal"));
	case 135:
		return (dgettext(TEXT_DOMAIN,
		"Can't open/find Kerberos /etc/krb5/krb5.conf configuration "
		"file"));
	case 136:
		return (dgettext(TEXT_DOMAIN,
	"Improper format of Kerberos /etc/krb5/krb5.conf configuration file"));
	case 137:
		return (dgettext(TEXT_DOMAIN,
			"Insufficient space to return complete information"));
	case 138:
		return (dgettext(TEXT_DOMAIN,
			"Invalid message type specified for encoding"));
	case 139:
		return (dgettext(TEXT_DOMAIN,
			"Credential cache name malformed"));
	case 140:
		return (dgettext(TEXT_DOMAIN,
			"Unknown credential cache type"));
	case 141:
		return (dgettext(TEXT_DOMAIN,
			"Matching credential not found"));
	case 142:
		return (dgettext(TEXT_DOMAIN,
			"End of credential cache reached"));
	case 143:
		return (dgettext(TEXT_DOMAIN,
			"Request did not supply a ticket"));
	case 144:
		return (dgettext(TEXT_DOMAIN,
			"Wrong principal in request"));
	case 145:
		return (dgettext(TEXT_DOMAIN,
			"Ticket has invalid flag set"));
	case 146:
		return (dgettext(TEXT_DOMAIN,
			"Requested principal and ticket don't match"));
	case 147:
		return (dgettext(TEXT_DOMAIN,
			"KDC reply did not match expectations"));
	case 148:
		return (dgettext(TEXT_DOMAIN,
			"Clock skew too great in KDC reply"));
	case 149:
		return (dgettext(TEXT_DOMAIN,
			"Client/server realm mismatch in initial ticket "
			"request"));
	case 150:
		return (dgettext(TEXT_DOMAIN,
			"Program lacks support for encryption type"));
	case 151:
		return (dgettext(TEXT_DOMAIN,
			"Program lacks support for key type"));
	case 152:
		return (dgettext(TEXT_DOMAIN,
			"Requested encryption type not used in message"));
	case 153:
		return (dgettext(TEXT_DOMAIN,
			"Program lacks support for checksum type"));
	case 154:
		return (dgettext(TEXT_DOMAIN,
			"Cannot find KDC for requested realm"));
	case 155:
		return (dgettext(TEXT_DOMAIN,
			"Kerberos service unknown"));
	case 156:
		return (dgettext(TEXT_DOMAIN,
			"Cannot contact any KDC for requested realm"));
	case 157:
		return (dgettext(TEXT_DOMAIN,
			"No local name found for principal name"));
	case 158:
		return (dgettext(TEXT_DOMAIN,
			"Mutual authentication failed"));
	case 159:
		return (dgettext(TEXT_DOMAIN,
			"Replay cache type is already registered"));
	case 160:
		return (dgettext(TEXT_DOMAIN,
			"No more memory to allocate (in replay cache code)"));
	case 161:
		return (dgettext(TEXT_DOMAIN,
			"Replay cache type is unknown"));
	case 162:
		return (dgettext(TEXT_DOMAIN,
			"Generic unknown RC error"));
	case 163:
		return (dgettext(TEXT_DOMAIN,
			"Message is a replay"));
	case 164:
		return (dgettext(TEXT_DOMAIN,
			"Replay I/O operation failed XXX"));
	case 165:
		return (dgettext(TEXT_DOMAIN,
			"Replay cache type does not support non-volatile "
			"storage"));
	case 166:
		return (dgettext(TEXT_DOMAIN,
			"Replay cache name parse/format error"));
	case 167:
		return (dgettext(TEXT_DOMAIN,
			"End-of-file on replay cache I/O"));
	case 168:
		return (dgettext(TEXT_DOMAIN,
			"No more memory to allocate (in replay cache I/O "
			"code)"));
	case 169:
		return (dgettext(TEXT_DOMAIN,
			"Permission denied in replay cache code"));
	case 170:
		return (dgettext(TEXT_DOMAIN,
			"I/O error in replay cache i/o code"));
	case 171:
		return (dgettext(TEXT_DOMAIN,
			"Generic unknown RC/IO error"));
	case 172:
		return (dgettext(TEXT_DOMAIN,
			"Insufficient system space to store replay "
			"information"));
	case 173:
		return (dgettext(TEXT_DOMAIN,
			"Can't open/find realm translation file"));
	case 174:
		return (dgettext(TEXT_DOMAIN,
			"Improper format of realm translation file"));
	case 175:
		return (dgettext(TEXT_DOMAIN,
			"Can't open/find lname translation database"));
	case 176:
		return (dgettext(TEXT_DOMAIN,
			"No translation available for requested principal"));
	case 177:
		return (dgettext(TEXT_DOMAIN,
			"Improper format of translation database entry"));
	case 178:
		return (dgettext(TEXT_DOMAIN,
			"Cryptosystem internal error"));
	case 179:
		return (dgettext(TEXT_DOMAIN,
			"Key table name malformed"));
	case 180:
		return (dgettext(TEXT_DOMAIN,
			"Unknown Key table type"));
	case 181:
		return (dgettext(TEXT_DOMAIN,
			"Key table entry not found"));
	case 182:
		return (dgettext(TEXT_DOMAIN,
			"End of key table reached"));
	case 183:
		return (dgettext(TEXT_DOMAIN,
			"Cannot write to specified key table"));
	case 184:
		return (dgettext(TEXT_DOMAIN,
			"Error writing to key table"));
	case 185:
		return (dgettext(TEXT_DOMAIN,
			"Cannot find ticket for requested realm"));
	case 186:
		return (dgettext(TEXT_DOMAIN,
			"DES key has bad parity"));
	case 187:
		return (dgettext(TEXT_DOMAIN,
			"DES key is a weak key"));
	case 188:
		return (dgettext(TEXT_DOMAIN,
			"Bad encryption type"));
	case 189:
		return (dgettext(TEXT_DOMAIN,
			"Key size is incompatible with encryption type"));
	case 190:
		return (dgettext(TEXT_DOMAIN,
			"Message size is incompatible with encryption type"));
	case 191:
		return (dgettext(TEXT_DOMAIN,
			"Credentials cache type is already registered."));
	case 192:
		return (dgettext(TEXT_DOMAIN,
			"Key table type is already registered."));
	case 193:
		return (dgettext(TEXT_DOMAIN,
			"Credentials cache I/O operation failed XXX"));
	case 194:
		return (dgettext(TEXT_DOMAIN,
			"Credentials cache file permissions incorrect"));
	case 195:
		return (dgettext(TEXT_DOMAIN,
			"No credentials cache file found"));
	case 196:
		return (dgettext(TEXT_DOMAIN,
			"Internal file credentials cache error"));
	case 197:
		return (dgettext(TEXT_DOMAIN,
			"Error writing to credentials cache file"));
	case 198:
		return (dgettext(TEXT_DOMAIN,
			"No more memory to allocate (in credentials cache "
			"code)"));
	case 199:
		return (dgettext(TEXT_DOMAIN,
			"Bad format in credentials cache"));
	case 200:
		return (dgettext(TEXT_DOMAIN,
			"No credentials found with supported encryption "
			"types"));
	case 201:
		return (dgettext(TEXT_DOMAIN,
			"Invalid KDC option combination (library internal "
			"error)"));
	case 202:
		return (dgettext(TEXT_DOMAIN,
			"Request missing second ticket"));
	case 203:
		return (dgettext(TEXT_DOMAIN,
			"No credentials supplied to library routine"));
	case 204:
		return (dgettext(TEXT_DOMAIN,
			"Bad sendauth version was sent"));
	case 205:
		return (dgettext(TEXT_DOMAIN,
			"Bad application version was sent (via sendauth)"));
	case 206:
		return (dgettext(TEXT_DOMAIN,
			"Bad response (during sendauth exchange)"));
	case 207:
		return (dgettext(TEXT_DOMAIN,
			"Server rejected authentication (during sendauth "
			"exchange)"));
	case 208:
		return (dgettext(TEXT_DOMAIN,
			"Unsupported preauthentication type"));
	case 209:
		return (dgettext(TEXT_DOMAIN,
			"Required preauthentication key not supplied"));
	case 210:
		return (dgettext(TEXT_DOMAIN,
			"Generic preauthentication failure"));
	case 211:
		return (dgettext(TEXT_DOMAIN,
			"Unsupported replay cache format version number"));
	case 212:
		return (dgettext(TEXT_DOMAIN,
			"Unsupported credentials cache format version number"));
	case 213:
		return (dgettext(TEXT_DOMAIN,
			"Unsupported key table format version number"));
	case 214:
		return (dgettext(TEXT_DOMAIN,
			"Program lacks support for address type"));
	case 215:
		return (dgettext(TEXT_DOMAIN,
			"Message replay detection requires rcache parameter"));
	case 216:
		return (dgettext(TEXT_DOMAIN,
			"Hostname cannot be canonicalized"));
	case 217:
		return (dgettext(TEXT_DOMAIN,
			"Cannot determine realm for host"));
	case 218:
		return (dgettext(TEXT_DOMAIN,
			"Conversion to service principal undefined for name "
			"type"));
	case 219:
		return (dgettext(TEXT_DOMAIN,
			"Initial Ticket response appears to be Version 4 "
			"error"));
	case 220:
		return (dgettext(TEXT_DOMAIN,
			"Cannot resolve network address for KDC in requested "
			"realm"));
	case 221:
		return (dgettext(TEXT_DOMAIN,
			"Requesting ticket can't get forwardable tickets"));
	case 222:
		return (dgettext(TEXT_DOMAIN,
			"Bad principal name while trying to forward "
			"credentials"));
	case 223:
		return (dgettext(TEXT_DOMAIN,
			"Looping detected inside krb5_get_in_tkt"));
	case 224:
		return (dgettext(TEXT_DOMAIN,
			"Configuration file does not specify default realm"));
	case 225:
		return (dgettext(TEXT_DOMAIN,
			"Bad SAM flags in obtain_sam_padata"));
	case 226: /* KRB5_SAM_INVALID_ETYPE */
		return (dgettext(TEXT_DOMAIN,
			"Invalid encryption type in SAM challenge"));
	case 227: /* KRB5_SAM_NO_CHECKSUM */
		return (dgettext(TEXT_DOMAIN,
			"Missing checksum in SAM challenge"));
	case 228: /* KRB5_SAM_BAD_CHECKSUM */
		return (dgettext(TEXT_DOMAIN,
			"Bad checksum in SAM challenge"));
	case 229: /* KRB5_KT_NAME_TOOLONG */
		return (dgettext(TEXT_DOMAIN,
			"Keytab name too long"));
	case 230: /* KRB5_KT_KVNONOTFOUND */
		return (dgettext(TEXT_DOMAIN,
			"Key version number for principal in key table is "
			"incorrect"));
	case 231: /* KRB5_APPL_EXPIRED */
		return (dgettext(TEXT_DOMAIN,
			"This application has expired"));
	case 232: /* KRB5_LIB_EXPIRED */
		return (dgettext(TEXT_DOMAIN,
			"This Krb5 library has expired"));
	case 233: /* KRB5_CHPW_PWDNULL */
		return (dgettext(TEXT_DOMAIN,
			"New password cannot be zero length"));
	case 234: /* KRB5_CHPW_FAIL */
		return (dgettext(TEXT_DOMAIN,
			"Password change failed"));
	case 235: /* KRB5_KT_FORMAT */
		return (dgettext(TEXT_DOMAIN,
			"Bad format in keytab"));
	case 236: /* KRB5_NOPERM_ETYPE */
		return (dgettext(TEXT_DOMAIN,
			"Encryption type not permitted"));
	case 237: /* KRB5_CONFIG_ETYPE_NOSUPP */
		return (dgettext(TEXT_DOMAIN,
			"No supported encryption types (config file error?)"));
	case 238: /* KRB5_OBSOLETE_FN */
		return (dgettext(TEXT_DOMAIN,
			"Program called an obsolete, deleted function"));
	case 239: /* KRB5_EAI_FAIL */
		return (dgettext(TEXT_DOMAIN,
			"unknown getaddrinfo failure"));
	case 240: /* KRB5_EAI_NODATA */
		return (dgettext(TEXT_DOMAIN,
			"no data available for host/domain name"));
	case 241: /* KRB5_EAI_NONAME */
		return (dgettext(TEXT_DOMAIN,
			"host/domain name not found"));
	case 242: /* KRB5_EAI_SERVICE */
		return (dgettext(TEXT_DOMAIN,
			"service name unknown"));
	case 243: /* KRB5_ERR_NUMERIC_REALM */
		return (dgettext(TEXT_DOMAIN,
			"Cannot determine realm for numeric host address"));
	case 244: /* KRB5_ERR_BAD_S2K_PARAMS */
		return (dgettext(TEXT_DOMAIN,
			"Invalid key generation parameters from KDC"));
	case 245: /* KRB5_ERR_NO_SERVICE */
		return (dgettext(TEXT_DOMAIN,
			"service not available"));
	case 246: /* KRB5_CC_READONLY */
		return (dgettext(TEXT_DOMAIN,
			"Ccache function not supported: read-only ccache "
			"type"));
	case 247: /* KRB5_CC_NOSUPP */
		return (dgettext(TEXT_DOMAIN,
			"Ccache function not supported: not implemented"));
	case 249: /* KRB5_RC_BADNAME */
		return (dgettext(TEXT_DOMAIN,
			"Bad replay cache name"));
	case 250: /* KRB5_CONF_NOT_CONFIGURED */
		return (dgettext(TEXT_DOMAIN,
			"krb5 conf file not configured"));
	case 251: /* PKCS_ERR */
		return (dgettext(TEXT_DOMAIN,
			"Error in the PKCS 11 library calls"));
	case 252: /* KRB5_DELTAT_BADFORMAT */
		return (dgettext(TEXT_DOMAIN,
			"Delta time bad format"));
	default:
		return ("unknown error");
	}
}
