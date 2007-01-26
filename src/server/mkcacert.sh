#!/bin/sh
##
##  mkcert.sh -- Make SSL Certificate Files for `make certificate' command
##  Copyright (c) 1998 Ralf S. Engelschall, All Rights Reserved. 
##

#   parameters

configdir="/var/kca/conf"		# Configuration directory
openssl="openssl"			# Path to the openssl program
extdir=`dirname $0`			# Directory where to find extfile.ca

proceed()
{
	echo -n "Proceed? [ y ] "
	read yorn
	if [ "$yorn" != "" -a "$yorn" != "y" -a "$yorn" != "yes" ]; then
		return 0
	fi
	return 1
}

if [ ".$openssl" = . ]; then
    echo "mkcert.sh:Error: mod_ssl/SSLeay has to be configured before using this utility." 1>&2
    echo "mkcert.sh:Hint:  Configure mod_ssl with --enable-module=ssl in APACI, first." 1>&2
    exit 1
fi

#   configuration

#   some optional terminal sequences
case $TERM in
    xterm|xterm*|vt220|vt220*)
        T_MD=`echo dummy | awk '{ printf("%c%c%c%c", 27, 91, 49, 109); }'`
        T_ME=`echo dummy | awk '{ printf("%c%c%c", 27, 91, 109); }'`
        ;;
    vt100|vt100*)
        T_MD=`echo dummy | awk '{ printf("%c%c%c%c%c%c", 27, 91, 49, 109, 0, 0); }'`
        T_ME=`echo dummy | awk '{ printf("%c%c%c%c%c", 27, 91, 109, 0, 0); }'`
        ;;
    default)
        T_MD=''
        T_ME=''
        ;;
esac

#   display header
echo ""
echo "SSL Certificate Generation Utility (mkcert.sh)"
echo "Copyright (c) 1998 Ralf S. Engelschall, All Rights Reserved."
echo ""

#   do some verification before proceeding...

if [ ! -d $configdir ]; then
	echo "'$configdir' isn't a directory.  Create it, or modify this script!"
	exit 1
fi

if [ -f $configdir/newcert.crt ]; then
	echo "'$configdir/newcert.crt' currently exists!  It will be overwritten!"
	proceed
	if [ $? -eq 0 ]; then
		echo "Not continuing..."
		exit 1
	fi
fi

if [ -f $configdir/newcert.key ]; then
	echo "'$configdir/newcert.key' currently exists!  It will be overwritten!"
	proceed
	if [ $? -eq 0 ]; then
		echo "Not continuing..."
		exit 1
	fi
fi

#   find some random files
#   (do not use /dev/random here, because this device 
#   doesn't work as expected on all platforms)
echo " + finding random files on your platform"
randfiles=''
for file in /var/log/messages /var/adm/messages \
            /kernel /vmunix /vmlinuz \
            /etc/hosts /etc/resolv.conf; do
    if [ -f $file ]; then
        if [ ".$randfiles" = . ]; then
            randfiles="$file"
        else
            randfiles="${randfiles}:$file"
        fi
    fi
done

        echo "______________________________________________________________________"
        echo ""
        echo "STEP 1: Generating RSA private key for new CA cert (1024 bit) [newcert.key]"
        if [ ! -f $HOME/.rnd ]; then
            touch $HOME/.rnd
        fi
        if [ ".$randfiles" != . ]; then
            $openssl genrsa -rand $randfiles \
                           -out $configdir/newcert.key \
                           1024
        else
            $openssl genrsa -out $configdir/newcert.key \
                           1024
        fi
        if [ $? -ne 0 ]; then
            echo "mkcert.sh:Error: Failed to generate RSA private key" 1>&2
            exit 1
        fi
        echo "______________________________________________________________________"
        echo ""
        echo "STEP 2: Generating X.509 certificate signing request for CA [newcert.csr]"

# C=US, ST=Michigan, L=Ann Arbor, O=University of Michigan, CN=TEST -- CITI Client CA v1

        cat >.mkcert.cfg <<EOT
[ req ]
default_bits                    = 1024
distinguished_name              = req_DN
[ req_DN ]
countryName                     = "1. Country Name             (2 letter code)"
countryName_default             = US
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = "2. State or Province Name   (full name)    "
stateOrProvinceName_default     = Michigan
localityName			= "3. Locality                 (eg, city)     "
localityName_default		= "Ann Arbor"
0.organizationName              = "4. Organization Name        (eg, company)  "
0.organizationName_default      = University of Michigan
commonName	          	= "5. Common Name              (eg, FQDN)     "
commonName_max                  = 64
commonName_default		= "FIX THIS!"
EOT
        $openssl req -config .mkcert.cfg \
                    -new \
                    -key $configdir/newcert.key \
                    -out $configdir/newcert.csr
        if [ $? -ne 0 ]; then
            echo "mkcert.sh:Error: Failed to generate certificate signing request" 1>&2
            exit 1
        fi
        rm -f .mkcert.cfg

        echo "______________________________________________________________________"
        echo ""
        echo "STEP 3: Generating X.509 certificate signed by own CA [newcert.crt]"

        if [ ! -f .mkcert.serial ]; then
            echo '02' >.mkcert.serial
        fi

        $openssl x509 \
		     -req \
		     -days 730 \
		     -signkey $configdir/newcert.key \
                     -in      $configdir/newcert.csr \
                     -out     $configdir/newcert.crt \
		     -extfile $extdir/extfile.ca

        if [ $? -ne 0 ]; then
            echo "mkcert.sh:Error: Failed to generate X.509 certificate" 1>&2
            exit 1
        fi

	# Don't need this certificate request around any more

	rm $configdir/newcert.csr

        echo "______________________________________________________________________"
        echo ""
        echo "STEP 4: Renaming the files"
	echo ""
	echo "The new private key and certificate are currently in"
	echo "$configdir/newcert.key and"
	echo "$configdir/newcert.crt respectively."
	newname=""
	while [ "$newname" = "" ]; do
		echo ""
		echo -n "Specify a name to replace 'newcert' : "
		read newname
	done
	echo "Will rename the files to"
	echo "$configdir/$newname.key and"
	echo "$configdir/$newname.crt respectively."
	proceed
	if [ $? = 0 ]; then
		echo "*NOT* renaming files.  Remember to move or"
		echo "rename them before re-running this script."
		exit 0
	fi

	if [ -f $configdir/$newname.key ]; then
		echo "$configdir/$newname.key already exists!  Will over-write it!"
		proceed
		if [ $? = 1 ]; then
			mv $configdir/newcert.key $configdir/$newname.key
			echo "The new private key is in $configdir/$newname.key"
		else
			echo "The new private key will remain in $configdir/newcert.key"
		fi	
	else
		mv $configdir/newcert.key $configdir/$newname.key
		echo "The new private key is in $configdir/$newname.key"
		
	fi

	if [ -f $configdir/$newname.crt ]; then
		echo "$configdir/$newname.crt already exists!  Will over-write it!"
		proceed
		if [ $? = 1 ]; then
			mv $configdir/newcert.crt $configdir/$newname.crt
			echo "The new certificate is in $configdir/$newname.crt"
		else
			echo "The new certificate will remain in $configdir/newcert.crt"
		fi	
	else
		mv $configdir/newcert.crt $configdir/$newname.crt
		echo "The new certificate is in $configdir/$newname.crt"
	fi

##EOF##
