/*
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
 
#include <locale.h>
const char *
kadm_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"Administrative service completed"));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Principal unknown"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Principal already exists"));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Memory allocation failure"));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Bad password"));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Protocol failure"));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Security failure"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Permission denied"));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"KADM err: Kerberos database update failed"));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 9"));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 10"));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 11"));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 12"));
	case 13:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 13"));
	case 14:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 14"));
	case 15:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 15"));
	case 16:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 16"));
	case 17:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 17"));
	case 18:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 18"));
	case 19:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 19"));
	case 20:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 20"));
	case 21:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 21"));
	case 22:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 22"));
	case 23:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 23"));
	case 24:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 24"));
	case 25:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 25"));
	case 26:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 26"));
	case 27:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 27"));
	case 28:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 28"));
	case 29:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 29"));
	case 30:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 30"));
	case 31:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 31"));
	case 32:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 32"));
	case 33:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 33"));
	case 34:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 34"));
	case 35:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 35"));
	case 36:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 36"));
	case 37:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 37"));
	case 38:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 38"));
	case 39:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 39"));
	case 40:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 40"));
	case 41:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 41"));
	case 42:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 42"));
	case 43:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 43"));
	case 44:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 44"));
	case 45:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 45"));
	case 46:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 46"));
	case 47:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 47"));
	case 48:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 48"));
	case 49:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 49"));
	case 50:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 50"));
	case 51:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 51"));
	case 52:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 52"));
	case 53:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 53"));
	case 54:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 54"));
	case 55:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 55"));
	case 56:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 56"));
	case 57:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 57"));
	case 58:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 58"));
	case 59:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 59"));
	case 60:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 60"));
	case 61:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 61"));
	case 62:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 62"));
	case 63:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 63"));
	case 64:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 64"));
	case 65:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 65"));
	case 66:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 66"));
	case 67:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 67"));
	case 68:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 68"));
	case 69:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 69"));
	case 70:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 70"));
	case 71:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 71"));
	case 72:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 72"));
	case 73:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 73"));
	case 74:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 74"));
	case 75:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 75"));
	case 76:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 76"));
	case 77:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 77"));
	case 78:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 78"));
	case 79:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 79"));
	case 80:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 80"));
	case 81:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 81"));
	case 82:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 82"));
	case 83:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 83"));
	case 84:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 84"));
	case 85:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 85"));
	case 86:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 86"));
	case 87:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 87"));
	case 88:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 88"));
	case 89:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 89"));
	case 90:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 90"));
	case 91:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 91"));
	case 92:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 92"));
	case 93:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 93"));
	case 94:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 94"));
	case 95:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 95"));
	case 96:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 96"));
	case 97:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 97"));
	case 98:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 98"));
	case 99:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 99"));
	case 100:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 100"));
	case 101:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 101"));
	case 102:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 102"));
	case 103:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 103"));
	case 104:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 104"));
	case 105:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 105"));
	case 106:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 106"));
	case 107:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 107"));
	case 108:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 108"));
	case 109:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 109"));
	case 110:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 110"));
	case 111:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 111"));
	case 112:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 112"));
	case 113:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 113"));
	case 114:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 114"));
	case 115:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 115"));
	case 116:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 116"));
	case 117:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 117"));
	case 118:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 118"));
	case 119:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 119"));
	case 120:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 120"));
	case 121:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 121"));
	case 122:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 122"));
	case 123:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 123"));
	case 124:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 124"));
	case 125:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 125"));
	case 126:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 126"));
	case 127:
		return(dgettext(TEXT_DOMAIN,
			"KADM error code 127"));
	case 128:
		return(
			"$Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/lib/krb5/error_tables/adm_err.et,v 5.1 1995/11/03 21:52:37 eichin Exp $");
	case 129:
		return(dgettext(TEXT_DOMAIN,
			"Cannot fetch local realm"));
	case 130:
		return(dgettext(TEXT_DOMAIN,
			"Unable to fetch credentials"));
	case 131:
		return(dgettext(TEXT_DOMAIN,
			"Bad key supplied"));
	case 132:
		return(dgettext(TEXT_DOMAIN,
			"Can't encrypt data"));
	case 133:
		return(dgettext(TEXT_DOMAIN,
			"Cannot encode/decode authentication info"));
	case 134:
		return(dgettext(TEXT_DOMAIN,
			"Principal attemping change is in wrong realm"));
	case 135:
		return(dgettext(TEXT_DOMAIN,
			"Packet is too large"));
	case 136:
		return(dgettext(TEXT_DOMAIN,
			"Version number is incorrect"));
	case 137:
		return(dgettext(TEXT_DOMAIN,
			"Checksum does not match"));
	case 138:
		return(dgettext(TEXT_DOMAIN,
			"Unsealing private data failed"));
	case 139:
		return(dgettext(TEXT_DOMAIN,
			"Unsupported operation"));
	case 140:
		return(dgettext(TEXT_DOMAIN,
			"Could not find administrating host"));
	case 141:
		return(dgettext(TEXT_DOMAIN,
			"Administrating host name is unknown"));
	case 142:
		return(dgettext(TEXT_DOMAIN,
			"Could not find service name in services database"));
	case 143:
		return(dgettext(TEXT_DOMAIN,
			"Could not create socket"));
	case 144:
		return(dgettext(TEXT_DOMAIN,
			"Could not connect to server"));
	case 145:
		return(dgettext(TEXT_DOMAIN,
			"Could not fetch local socket address"));
	case 146:
		return(dgettext(TEXT_DOMAIN,
			"Could not fetch master key"));
	case 147:
		return(dgettext(TEXT_DOMAIN,
			"Could not verify master key"));
	case 148:
		return(dgettext(TEXT_DOMAIN,
			"Entry already exists in database"));
	case 149:
		return(dgettext(TEXT_DOMAIN,
			"Database store error"));
	case 150:
		return(dgettext(TEXT_DOMAIN,
			"Database read error"));
	case 151:
		return(dgettext(TEXT_DOMAIN,
			"Insufficient access to perform requested operation"));
	case 152:
		return(dgettext(TEXT_DOMAIN,
			"Data is available for return to client"));
	case 153:
		return(dgettext(TEXT_DOMAIN,
			"No such entry in the database"));
	case 154:
		return(dgettext(TEXT_DOMAIN,
			"Memory exhausted"));
	case 155:
		return(dgettext(TEXT_DOMAIN,
			"Could not fetch system hostname"));
	case 156:
		return(dgettext(TEXT_DOMAIN,
			"Could not bind port"));
	case 157:
		return(dgettext(TEXT_DOMAIN,
			"Length mismatch problem"));
	case 158:
		return(dgettext(TEXT_DOMAIN,
			"Illegal use of wildcard"));
	case 159:
		return(dgettext(TEXT_DOMAIN,
			"Database is locked or in use--try again later"));
	case 160:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java array creation failed"));
	case 161:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java class lookup failed"));
	case 162:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java field lookup failed"));
	case 163:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java method lookup failed"));
	case 164:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java object lookup failed"));
	case 165:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java object field lookup failed"));
	case 166:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java string access failed"));
	case 167:
		return(dgettext(TEXT_DOMAIN,
			"JNI: Java string creation failed"));
	default:
		return("unknown error");
	}
}
