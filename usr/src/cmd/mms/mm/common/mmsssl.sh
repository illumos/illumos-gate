#!/bin/sh
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#
# MMS SSL Self-Signed Certificate Authority
#

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/sadm/bin:$PATH
LD_LIBRARY_PATH=/lib:/usr/lib:$LD_LIBRARY_PATH

umask 066 
PROG=`basename $0`


# Now setup directories
SSLDIR="/var/mms/ssl"
CADIR="$SSLDIR/ca"
PUBDIR="$SSLDIR/pub"
ROOT_CNF="$CADIR/mms_openssl.cnf"
CERTSDIR="$CADIR/certs"
DIR=

# DSA Parameters Prime Number Bit Length
PRIME_BITS=2048

# User
USER=""
MMS_USER="mms"

# Root files (CA)
SERIAL="$CADIR/serial"
INDEX="$CADIR/index.txt"
CRL="$PUBDIR/$MMS_USER""_crl.pem"
ROOT_CERT="$CADIR/$MMS_USER""_ca_cert.pem"
ROOT_KEY="$CADIR/$MMS_USER""_ca_key.pem"
PASSWD_FILE="$CADIR/$MMS_USER""_ca_pass"
ROOT_PEM="$CADIR/$MMS_USER""_ca.pem"
ROOT_CERT_PUB="$PUBDIR/$MMS_USER""_ca_cert.pem"
MMS_PEM="$PUBDIR/$MMS_USER.pem"
MMS_CERT="$PUBDIR/$MMS_USER""_cert.pem"
MMS_DH1024="$PUBDIR/$MMS_USER""_dh1024.pem"

root_user()
{
	user=`/bin/id | grep root | wc -l`
	if [ $user -eq 0 ]; then
		echo "Error, you must be root to run this script."
		exit 1
	fi
}

gen_password()
{
	pass_file="$1"

	echo
	echo "Generate private key password phrase"

	/bin/dd if=/dev/random bs=1 count=15 2>/dev/null | \
		openssl base64 > "$pass_file"
	if [ ! -f "$pass_file" ]; then
		exit 1
	fi
}

# setup mms as ca (certificate authority)
initialize()
{
	echo
	echo "Initialize certificate authority"

	# certificate serial number
	echo "01" > "$SERIAL"
	if [ ! -f "$SERIAL" ]; then
		exit 1
	fi

	# certificate database
	touch "$INDEX"
	if [ ! -f "$INDEX" ]; then
		exit 1
	fi

	# new certs dir
	mkdir $CERTSDIR
	if [ $? -ne 0 ]; then
		exit 1
	fi

	chmod 0700 $CERTSDIR
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# ca random password phrase
	gen_password "$PASSWD_FILE"
}

# generate crl (certificate revocation list) file
update_crl()
{
	echo
	echo "Update CRL"

	cmd="openssl ca -gencrl -out $CRL -config $ROOT_CNF"
	cmd="$cmd -passin file:$PASSWD_FILE"
	echo $cmd
	$cmd
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# publish the list, let everyone read the file
	chmod 0640 $CRL
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# tell mm to reload updated crl
	svcadm refresh mms:mm > /dev/null 2>&1
}

# compute public shared prime number p and generator g
dh_pem()
{
	echo
	echo "Generate Diffie-Hellman parameters"

	cmd="openssl dhparam -check -5 1024 -out $MMS_DH1024 -outform PEM"
	echo $cmd
	$cmd
	if [ $? -ne 0 ]; then
		exit 1
	fi

	chmod 0600 $MMS_DH1024
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

# rsa private key
rsa_key()
{
	rsa_key_file="$1"

	echo
	echo "Create RSA certificate with SHA-1 signature"

	cmd="openssl genrsa -out $rsa_key_file -des3"
	cmd="$cmd -passout file:$PASSWD_FILE"
	echo $cmd
	$cmd
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

# generate self signed root certificate and private key
rsa_cert()
{
	echo
	echo "Generate self-signed certificate authority"

	unset -v OPENSSL_CONF
	# gen self signed ca certificate
	cmd="openssl req -x509 -newkey rsa:$PRIME_BITS -out $ROOT_CERT"
	cmd="$cmd -keyout $ROOT_KEY -sha1 -outform PEM"
	cmd="$cmd -passout file:$PASSWD_FILE"
	echo $cmd
	$cmd
	if [ $? -ne 0 ]; then
		exit 1
	fi

	chmod 0600 "$ROOT_CERT"
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# mms_ca.pem
	cat $ROOT_CERT $ROOT_KEY > $ROOT_PEM
	if [ ! -f $ROOT_PEM ]; then
		exit 1
	fi

	# put ca certificate in public directory 
	cp $ROOT_CERT $ROOT_CERT_PUB
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# let everyone read public ca certificate
	chmod 0440 $ROOT_CERT_PUB
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# view certificate info
	openssl x509 -subject -issuer -noout -in $ROOT_CERT

	# initialize cert revocation list 
	update_crl
}

certificate_request()
{
	dir=$1
	mess=$2

	echo
	echo "Generate certificate request ($USER,$dir)"

	mkdir -p "$dir"
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# user password phrase
	pass_file="$dir/$USER""_pass"
	gen_password "$pass_file"

	# filenames
	req="$dir/$USER""_req.pem"

	key="$dir/$USER""_key.pem"

	# use default openssl configuration for certificate request
	unset -v OPENSSL_CONF

	# generate certificate request
	cmd="openssl req -newkey rsa:$PRIME_BITS -keyout $key -keyform PEM"
	cmd="$cmd -out $req -outform PEM -sha1 -passout file:$pass_file"
	echo $cmd
	$cmd
	if [ $? -ne 0 ]; then
		exit 1
	fi
	if [ $mess -eq 1 ]; then
		echo
		echo
		echo
		echo "Certificate request:  $req"
		echo "Private key:          $key"
		echo "Private key password: $pass_file"
		echo
		echo "Email certificate request file to MMS CA for signing."
		echo
	fi
}

ca_sign()
{
	echo
	echo "Sign certificate request"

	# filenames
	req="$PUBDIR/$USER""_req.pem"

	cert="$PUBDIR/$USER""_cert.pem"

	key="$PUBDIR/$USER""_key.pem"

	root_cert=`basename $ROOT_CERT`

	# root signs client certificate request
	cmd="openssl ca -in $req -out $cert -notext -cert $ROOT_CERT"
	cmd="$cmd -config $ROOT_CNF -md sha1 -passin file:$PASSWD_FILE"
	echo $cmd
	$cmd
	if [ $? -ne 0 ]; then
		exit 1
	fi

	if [ -f $key ]; then
		# combine certificate, private key and public root certificate
		pem="$PUBDIR/$USER.pem"
		cat $cert $key $ROOT_CERT_PUB > $pem
		if [ $? -ne 0 ]; then
			rm -f $pem
			echo "Error, create $pem"
		else
			echo
			echo "The combined certificate, private key and CA certificate file\n$pem"
			echo
		fi
	else
		user_cert=`basename $cert`
		user_key=`basename $key`
		# remote user without access to ssl public directory
		echo
		echo "Use the distinguished name email address to deliver"
		echo "the following files to the user:"
		echo "\t$cert"
		echo "\t$ROOT_CERT_PUB"
		echo
		echo "Instruct the user to do the following:"
		echo "\tcat $user_cert $user_key $root_cert > $USER.pem"
		echo
	fi
}

# revoke client's certificate
revoke_certificate()
{
	echo "Revoke certificate"

	# filename
	cert="$PUBDIR/$USER""_cert.pem"

	# revoke certificate
	cmd="openssl ca -revoke $cert -config $ROOT_CNF"
	cmd="$cmd -passin file:$PASSWD_FILE"
	echo $cmd
	$cmd
	if [ $? -ne 0 ]; then
		exit 1
	fi

	# add revoked cert to the list
	update_crl
}

check_client()
{
	if [ -z "$USER" ]; then
		echo "Error, missing user name."
		exit 1
	fi
}

usage()
{
    echo "usage: mmsssl.sh [ ca | req | crl ] [-v] [-n]"
    echo
    echo "mmsssl.sh ca -c                           configure mms ca"
    echo "mmsssl.sh ca -s -u user_name              sign certificate request"
    echo "mmsssl.sh ca -r -u user_name              revoke certificate"
    echo "mmsssl.sh req -u user_name [-d path]      certificate request"
    echo "mmsssl.sh crl                             revoked certificate list"
    echo
    echo "Examples:"
    echo "1. Create the MMS CA and MM RSA certificates:"
    echo "\t% mmsssl.sh ca -c"
    echo "\tRun the command only once on the host where the MM will execute."
    echo "\tDiffie-Hellman (DH) parameters are generated." 
    echo "\tYou will enter a DN (Distinguished Name) once for the CA and"
    echo "\tonce for the MM certificate. You will sign the MM certificate"
    echo "\tand commit the request."
    echo
    echo "2. MMS user certificate request:"
    echo "\t% mmsssl.sh req -u JohnQPublic"
    echo "\tEmail the JohnQPublic_req.pem to the MMS CA for signing." 
    echo
    echo "3. MMS CA signs user certificate request:"
    echo "\t% cp JohnQPublic_req.pem \\"
    echo "\t$PUBDIR/JohnQPublic_req.pem"
    echo "\tCopy certificate request into the MMS CA for signing."
    echo "\t% mmsssl.sh ca -s -u JohnQPublic"
    echo "\tYou will sign the MM certificate and commit the request."
    echo "\tEmail the JohnQPublic_cert.pem and mms_ca_cert.pem "\
					"files to the user."
    echo
    echo "4. MMS user creates single PEM file for MMS:"
    echo "\t% cat JohnQPublic_cert.pem JohnQPublic_key.pem \\"
    echo "\tmms_ca_cert.pem > JohnQPublic.pem"
    echo
    echo "5. MMS CA revokes user certificate:"
    echo "\t% mmsssl.sh ca -r -u JohnQPublic"
    echo "\tThe revoked certificate is added to the file"
    echo "\t$PUBDIR/mms_crl.pem"
    echo
    echo "6. MMS CA reviews CRL (Certificate Revocation List):"
    echo "\t% mmsssl.sh crl"
    echo "\tLists revoked certificate serial numbers."
    echo
    echo "Notes:"
    echo "1. user_name is one word i.e. John Q. Public is JohnQPublic"
    echo "2. one-way authentication is where only the server is configured"
    echo "   with a RSA certificate."
    echo "3. two-way authentication is when the server and client both have"
    echo "   a RSA certificate." 
    echo "4. MMS supports both one-way and two-way authentication."
    echo "5. The MMS CA can use a certificate request made by a tool"
    echo "   other than this script."
    echo "6. The crl.pem file contains the CRL for this MMS CA."
    echo "7. The MM, Watcher, LM (Library Manager) and DM (Drive Manager)"
    echo "   can use the same certificate."
    echo
    exit 2
}

#
# Main
#

if [ $# -eq 0 ]; then
	usage
fi

choice=$1
oper=""
shift
found=0
while getopts "csru:d:" opt; do
	found=0
	case $opt in
	c)
		# setup mms ca
		oper="configure"
		found=1
		;;
	s)	
		# Create Signed Certificate on this host.
		#
		# On remote hosts its a two step process:
		#	1. request certificate
		#	2. CA sign's certificate  
		oper="sign"
		found=1
		;;
	r)	
		# Revoke Certificate
		#
		# Update the MM CA CRL and put on all remote hosts
		# especially if you have one MM CA for multiple MMs.
		oper="revoke"
		found=1
		;;
	u)
		# User Name
		USER="$OPTARG"
		found=1
		;;
	d)
		# User directory
		DIR="$OPTARG"
		found=1
		;;
	esac

	if [ $found -eq 0 ]; then
		usage
	fi
done

case $choice in
ca)
	# setup non-root MMS client in /etc
	OPENSSL_CONF="$ROOT_CNF"
	HOME="$CADIR"
	root_user
	case $oper in
	configure)
		# setup MMS CA
		root_user
		initialize
		dh_pem
		rsa_cert

		# sign mms certificate request 
		USER=$MMS_USER
		certificate_request "$PUBDIR" 0
		ca_sign
		echo "Done"
		;;

	sign)	
		# sign certificate request
		check_client
		ca_sign
		echo "Done"
		;;

	revoke)	
		if [ -z "$USER" ]; then
			echo "Error, missing client user name."
			exit 1
		fi

		revoke_certificate	
		echo "Done"
		;;

	*)	usage
		;;
	esac
	;;

req)
	# certificate request
	check_client
	if [ "$DIR" = "" ]; then
		DIR="$HOME/mms"
	fi
	certificate_request "$DIR" 1
	echo "Done"
	;;

crl)
	# show certificate revocation list
	crl=$CRL
	root_cert=$ROOT_CERT
	openssl crl -in $crl -text -noout
	openssl crl -in $crl -noout -CAfile $root_cert
	echo "Done"
	;;

*)	usage
	;;
esac

exit 0
