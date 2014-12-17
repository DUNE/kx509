/*
** kx509/store_in_keychain -- add cert, and priv/pub key pair to kx509.keychain
*/

#import <Foundation/Foundation.h>
#import <Keychain/Certificate.h>
#import <Keychain/CertificateGeneration.h>
#import <Keychain/MutableKey.h>
#import <Keychain/CSSMDefaults.h>
#import <Keychain/Keychain.h>

#include <sys/syslog.h>
#include <pwd.h>

#define KEYCHAIN "Library/Keychains/kx509.keychain"
#define KEYSIZE 512

int
store_in_keychain (char *privkey, long privkeylen,
		   char *pubkey, long pubkeylen,
		   char *cert, long certlen)
{
        SecAccessRef accessRef = nil;
	CFMutableArrayRef trustedApplications = nil;
	SecTrustedApplicationRef myself = NULL, Safari = NULL, KeychainAccess = NULL;
	SecACLRef aclRef = NULL;
	CFArrayRef aclList = NULL;
	CFArrayRef appList = NULL;
	CFStringRef promptDescription = NULL;
	CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR promptSelector;

	CSSM_CSP_HANDLE rawcsp = NULL;
	CSSM_DATA certData = { certlen, cert };
	CSSM_KEY wrappedprivkey = { {CSSM_KEYHEADER_VERSION, {0, 0, 0,
			{0, 0, 0, 0, 0, 0, 0, 0}}, CSSM_KEYBLOB_RAW,
			CSSM_KEYBLOB_RAW_FORMAT_PKCS1, CSSM_ALGID_RSA,
			CSSM_KEYCLASS_PRIVATE_KEY, KEYSIZE,
			CSSM_KEYATTR_EXTRACTABLE, CSSM_KEYUSE_ANY,
			{{0, 0, 0, 0}, {0, 0}, {0, 0}}, {{0, 0, 0,
			0}, {0, 0}, {0, 0}}, 0, 0, 0}, { privkeylen,
			privkey }};
	CSSM_KEY wrappedpubkey = { {CSSM_KEYHEADER_VERSION, {0, 0, 0,
			{0, 0, 0, 0, 0, 0, 0, 0}}, CSSM_KEYBLOB_RAW,
			CSSM_KEYBLOB_RAW_FORMAT_PKCS1, CSSM_ALGID_RSA,
			CSSM_KEYCLASS_PUBLIC_KEY, KEYSIZE,
			CSSM_KEYATTR_EXTRACTABLE, CSSM_KEYUSE_ANY,
			{{0, 0, 0, 0}, {0, 0}, {0, 0}}, {{0, 0, 0,
			0}, {0, 0}, {0, 0}}, 0, 0, 0}, { pubkeylen,
			pubkey }};
	CSSM_KEY_SIZE keysize;
	SecCertificateRef certificate = NULL;
	SecKeychainRef keychain = NULL;
	SecKeychainItemRef itemRef = NULL;
	char *msg = NULL;
	int rc = 0;
	CFStringRef accessLabel = CFSTR("kx509 key");
	char path[ PATH_MAX ], *home = NULL;
	struct passwd *pw;

	/* find home directory */
	if ( !( pw = getpwuid( geteuid() ) ) || !( home = pw->pw_dir ) ) {
		msg = "getpwuid()";
		goto cleanup;
	}

	/* build path to keychain */
	snprintf( path, sizeof( path ) - 1, "%s/%s", home, KEYCHAIN );
	path[ sizeof( path ) - 1 ] = '\0';

	/* get reference to old keychain */
	rc = SecKeychainOpen( path, &keychain );
	if ( rc ) {
		msg = "SecKeychainOpen()";
		goto cleanup;
	}

	/* get rid of old keychain, ignore errors */
	SecKeychainDelete( keychain );
	CFRelease( keychain );
	keychain = NULL;

	/* build a list of trusted applications */
	trustedApplications = CFArrayCreateMutable(kCFAllocatorDefault,
		0, &kCFTypeArrayCallBacks);

	/* add the calling program */
	rc = SecTrustedApplicationCreateFromPath(NULL, &myself);
	if ( rc ) {
		msg = "SecTrustedApplicationCreateFromPath(NULL)";
		goto cleanup;
	}
	CFArrayAppendValue(trustedApplications, myself); 

	/* add the browser */
	rc = SecTrustedApplicationCreateFromPath("/Applications/Safari.app", &Safari);
	if ( rc ) {
		msg = "SecTrustedApplicationCreateFromPath(Safari.app)";
		goto cleanup;
	}
	CFArrayAppendValue(trustedApplications, Safari); 

	/* add keychain access */
	rc = SecTrustedApplicationCreateFromPath("/Applications/Utilities/Keychain Access.app",
		&KeychainAccess);
	if ( rc ) {
		msg = "SecTrustedApplicationCreateFromPath(Keychain Access.app)";
		goto cleanup;
	}
	CFArrayAppendValue(trustedApplications, KeychainAccess); 

	/* create the access from the list */
	rc = SecAccessCreate(accessLabel, (CFArrayRef)trustedApplications, &accessRef);
	if ( rc ) {
		msg = "SecAccessCreate";
		goto cleanup;
	}

	/* create new keychain */
	rc = SecKeychainCreate( path, 0, "", NO, accessRef, &keychain );
	if ( rc ) {
		msg = "SecKeychainCreate";
		goto cleanup;
	}

	/* and make it the default keychain */
	rc = SecKeychainSetDefault( keychain );
	if ( rc ) {
		msg = "SecKeychainSetDefault";
		goto cleanup;
	}

	/* create cert from, well, data */
	rc = SecCertificateCreateFromData(&certData, CSSM_CERT_X_509v3,
		CSSM_CERT_ENCODING_DER, &certificate);
	if ( rc ) {
		msg = "SecCertificateCreateFromData";
		goto cleanup;
	}

	/* add it */
	rc = SecCertificateAddToKeychain(certificate, keychain);
	if ( rc ) {
		msg = "SecCertificateAddToKeychain";
		goto cleanup;
	}

	/* import the keys using access */
	rc = SecKeyImportPair(keychain, &wrappedprivkey, &wrappedpubkey,
		accessRef, NULL, NULL);
	if ( rc ) {
		msg = "SecKeyImportPair";
		goto cleanup;
	}

	/* get the ACLs */
	rc = SecAccessCopySelectedACLList( accessRef,
		CSSM_ACL_AUTHORIZATION_DECRYPT, &aclList );
	if ( rc ) {
		msg = "SecAccessCopySelectedACLList";
		goto cleanup;
	}

	/* look at first ACL */
	aclRef = (SecACLRef)CFArrayGetValueAtIndex(aclList, 0);

	/* get its contents */
	rc = SecACLCopySimpleContents( aclRef, &appList,
		&promptDescription, &promptSelector );
	if ( rc ) {
		msg = "SecACLCopySimpleContents";
		goto cleanup;
	}

	/* set the "Confirm before allowing access" bit */
	promptSelector.flags |= CSSM_ACL_KEYCHAIN_PROMPT_REQUIRE_PASSPHRASE;

	/* and add trusted list to this ACL */
	rc = SecACLSetSimpleContents( aclRef, trustedApplications,
		promptDescription, &promptSelector );
	if ( rc ) {
		msg = "SecACLSetSimpleContents";
		goto cleanup;
	}

cleanup:
	if ( msg ) {
		printf("%s returned %d\n", msg, rc);
		syslog( LOG_ERR, "%s returned %d, home=\"%s\"\n", msg, rc, home );
	}
	if ( accessRef ) {
		CFRelease( accessRef );
		accessRef = NULL;
	}
	if ( certificate ) {
		CFRelease( certificate );
		certificate = NULL;
	}
	if ( itemRef ) {
		CFRelease( itemRef );
		itemRef = NULL;
	}
	if ( appList ) {
		CFRelease( appList );
		appList = NULL;
	}
	if ( promptDescription ) {
		CFRelease( promptDescription );
		promptDescription = NULL;
	}
	if ( rawcsp ) {
		CSSM_ModuleDetach( rawcsp );
		rawcsp = NULL;
	}

	return 0;
}
