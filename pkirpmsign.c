#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <termios.h>
#include <unistd.h>
#include <stdarg.h>
#include <libintl.h>
#include <locale.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <xmlsec/errors.h>

#include <openssl/pkcs12.h>

#define _(STRING) gettext(STRING)

#define MAX_P12_PASSWORD_SIZE 100
#define DEFAULT_P12_FILE "/etc/pki/rpm-keys/keystore.p12"

#define ERR_WRONG_NB_OF_ARGS _("Wrong number of arguments.\nUsage: %s <file-to-sign> <p12-file>\nOr (use default /etc/pki/rpm-keys/keystore.p12) : %s <file-to-sign>\n")
#define ERR_DEFAULT_KEYSTORE_NOT_FOUND _("Tried to load default keystore '%s' but file was not found. Please create this file or specify the path to a keystore.\n")
#define ERR_INPUT_KEYSTORE_NOT_FOUND _("Tried to load input keystore '%s' but file was not found.\n")
#define ERR_COULD_NOT_GENERATE_SIGNATURE _("Could not generate a signature.\n")
#define ERR_FILE_DELETE_FAIL _("Error deleting file '%s'\n")
#define ERR_XMLSEC_INIT_FAIL _("xmlsec initialization failed.\n")
#define ERR_XMLSEC_VERSION_INVALID _("Loaded xmlsec library version is not compatible.\n")
#define ERR_XMLSEC_CRYPTO_APP_INIT_FAIL _("Crypto initialization failed.\n")
#define ERR_XMLSEC_CRYPTO_INIT_FAIL _("xmlsec-crypto initialization failed.\n")
#define ERR_FILE_NOT_FOUND _("Unable to find file \"%s\"\n")
#define ERR_XML_TEMPLATE_PARSE_FAIL _("Unable to parse template\n")
#define ERR_XML_TEMPLATE_1ST_NODE_NOT_FOUND _("Start node not found in template\n")
#define ERR_CANNOT_OPEN_FILE _("Cannot open file %s\n")
#define ERR_P12_FILE_FORMAT_NOT_RECOGNIZED _("Keystore file unrecognized, are you sure %s is a valid p12 file?\n")
#define ERR_P12_WONT_OPEN_BECAUSE_INVALID_PASSWORD _("Could not access to keystore data, is the password valid?\n")
#define ERR_KEY_MANAGER_CREATION_FAILED _("Keys manager creation failed\n")
#define ERR_SIGNATURE_CONTEXT_CREATION_FAILED _("Failed to create signature context\n")
#define ERR_SIGNATURE_FAILED _("Signature failed\n")
#define ERR_KEY_MANAGER_ALREADY_INITIALIZED _("Keys manager already initialized.\n")
#define ERR_KEY_MANAGER_INITIALIZATION_FAILED _("Failed to initialize keys manager.\n")
#define ERR_FAILED_TO_LOAD_KEY_FROM_P12 _("Failed to load key from \"%s\"\n")
#define ERR_XMLSEC_KEY_LOAD_FAILED _("xmlSecCryptoAppKeyLoad failed: filename=%s\n")
#define ERR_XMLSEC_SET_KEY_NAME_FAILED _("xmlSecKeySetName failed: name=%s\n")
#define ERR_XMLSEC_ADD_KEY_TO_KEY_MANAGER_FAILED _("xmlSecCryptoAppDefaultKeysMngrAdoptKey failed\n")
#define ERR_INPUT_RPM_FORMAT_INVALID _("Unrecognized input rpm format.\n")
#define ERR_HEX_SIGNATURE_CORRUPTED _("Hex representation of signature corrupted.\n")
#define ERR_WRITING_TO_FILE_FAILED _("Something went wrong when writing to file : %s\n")
#define ERR_INPUT_PASSWORD_TOO_LONG _("Password is too long, it should not exceed %d characters.\n")

#define PROMPT_FOR_PASSWORD _("Please enter password for keystore (max %d characters)\n")
#define SIGNATURE_SUCCESS _("Signature successful!\n")
#define ERROR_PREFIX _("Error: ")

xmlSecKeysMngrPtr gKeysMngr = NULL;

struct StringWithSize {
	long size;
	char *content;
};

xmlDocPtr generateCrypto(char* file_to_sign, char* p12Path,  char* pwd);
xmlDocPtr signFile(char* file_to_sign, char* p12Path,  char* pwd);
static int xmlSecAppLoadKeys(char *p12Path, char *pwd);
int xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(xmlSecKeysMngrPtr mngr, const char *filename, const char* pwd, const char *name);
struct StringWithSize readFileAsByteArray(char *filename);
struct StringWithSize fromByteArrayToHex(struct StringWithSize bytes);
char *subArray(char *originalArray, int start, int end);
int checkHeaderMagic(char *header);
long hexToDec(char *hex);
long numberOfSubHeaders(char *headerDeclarationLine);
void listSignatureSubHeaders(char *rpmHex, int nbOfSignatureHeaders, char (*signatureHeaders)[33]);
long findEndOfSignatureRegion(char *signatureDeclarationLine, int nbOfHeaders);
char *string2hexString(char *input);
char *computeNullBytesNumber(long headerSectionOffset);
char *generateNewSignature(char *xmldsig, char *md5Value);
char *getEntry(char *codeToFind, char (*listOfStrings)[33], int listSize);
char *getMd5ofRpm(char *md5Header, char *hexRpm, int signatureHeaderNb);
char *fromHexToAscii(char *hex);
void writeTempFile(char *content, int size, char *filename);
char *tmpFilePath(char *filename);
int getPassword(char password[]);
void printErr(char *stringToPrint, ...);

int main(int argc, char **argv) {

    setlocale(LC_ALL, "");
    bindtextdomain("pkirpmsign", "/usr/share/locale/");
    textdomain("pkirpmsign");

    /**
    * VERIFY ARGUMENTS
    */
    assert(argc);
    assert(argv);
    // argc has to be either 2 or 3
    if (argc > 3 || argc < 2) {
        printErr(ERR_WRONG_NB_OF_ARGS, argv[0], argv[0]);
        return(1);
    }

    int res = 0;

    /**
    * READ ARGUMENTS INTO VARIABLES
    */
    char *p12FilePath;
    char *filename = argv[1];
    // if only 1 arg then it is the file to sign : use the default keystore (/etc/pki/rpm-keys/keystore.p12)
    if (argc == 2) {
        if (access(DEFAULT_P12_FILE, F_OK) == 0) {
            p12FilePath = DEFAULT_P12_FILE;
        } else {
            printErr(ERR_DEFAULT_KEYSTORE_NOT_FOUND, DEFAULT_P12_FILE);
            return(1);
        }
    // if 2 args, then second arg is the path to the keystore to use
    } else if (argc == 3) {
        if (access(argv[2], F_OK) == 0) {
            p12FilePath = argv[2];
        } else {
            printErr(ERR_INPUT_KEYSTORE_NOT_FOUND, argv[2]);
            return(1);
        }
    }

    /**
    * READ FILE TO SIGN & EXTRACT DATA FROM IT
    */
	struct StringWithSize file = readFileAsByteArray(filename);
	// extract lead
	char *lead = (char *)malloc(96 * sizeof(char));
	memcpy(lead, file.content, 96 * sizeof(char));
	// convert file to hex
	struct StringWithSize hexFile = fromByteArrayToHex(file);
	// extract first line of signature section
	char *signatureHeader = subArray(hexFile.content, 192, 224);

	if (checkHeaderMagic(signatureHeader) != 0) {
	    return(1);
	}

    // extract the list of signature headers (signature section of rpm contains headers)
	long nbOfSignatureHeaders = numberOfSubHeaders(signatureHeader);
	char signatureHeaders[nbOfSignatureHeaders][33];
	listSignatureSubHeaders(hexFile.content, nbOfSignatureHeaders, signatureHeaders);

	long endOfSignatureRegion = findEndOfSignatureRegion(signatureHeader, nbOfSignatureHeaders);
	free(signatureHeader);

    // extract header and payload sections, which is what should be signed.
	long headersAndPayloadSize = file.size - endOfSignatureRegion;
	char *headersAndPayload = subArray(file.content, endOfSignatureRegion, file.size);
	free(file.content);

    /**
    * CREATE A TMP FILE CONTAINING DATA TO SIGN
    * data to sign consist of the 2 last part of the input rpm file : headers & payload
    * first two parts (lead and signature) are not signed, just as in regular pgp rpm sign
    */
    char *headersAndPayloadTmpFilePath = tmpFilePath(filename);
	writeTempFile(headersAndPayload, headersAndPayloadSize, headersAndPayloadTmpFilePath);

    /**
    * GET PASSWORD FOR P12 FILE
    */
    char *password = malloc(MAX_P12_PASSWORD_SIZE * sizeof(char));
    printf(PROMPT_FOR_PASSWORD, MAX_P12_PASSWORD_SIZE);
    int passwordOk = getPassword(password);
    if (passwordOk != 0) {
        res = 1;
        goto cleanandreturn;
    }

    /**
    * GENERATE A SIGNATURE FOR THE TMP FILE
    */
    xmlDocPtr xmlSignature = signFile(headersAndPayloadTmpFilePath, p12FilePath, password);

    if (xmlSignature == NULL) {
        printErr(ERR_COULD_NOT_GENERATE_SIGNATURE);
        res = 1;
        goto cleanandreturn;
    }

    /**
    * GET VALUES FOR RPM SIGNATURE (RPMSIGTAG_MD5)
    * md5 header is mandatory, if not present in the signature section then rpm wont install
    * when reconstructing the signature section of the rpm, md5 has to be included in it
    */
	char *md5Header = getEntry("000003ec", signatureHeaders, nbOfSignatureHeaders);
	char *md5Value = getMd5ofRpm(md5Header, hexFile.content, nbOfSignatureHeaders);
	free(hexFile.content);

    /**
    * CONVERT xmlDoc SIGNATURE TO xmlChar TO INSERT IT INTO SIGNED RPM
    */
    xmlChar *signatureXmlString;
    int signatureXmlStringSize;
    xmlDocDumpMemory(xmlSignature, &signatureXmlString, &signatureXmlStringSize);//, 1);
    xmlFreeDoc(xmlSignature);

    /**
    * GENERATE SIGNATURE SECTION FOR SIGNED RPM
    * start with hex format and then convert it to bytes
    */
	char *newSignatureHex = generateNewSignature((char *)signatureXmlString, md5Value);
	free(md5Value);
	free(signatureXmlString);

	char *newSignature = fromHexToAscii(newSignatureHex);

    /**
    * COMPUTE SIGNED RPM SIZE
    */
	int newRpmSize = (96 + (strlen(newSignatureHex) / 2) + headersAndPayloadSize) * sizeof(char);
	char *newRpm = (char *)malloc(newRpmSize);

    /**
    * BUILD SIGNED RPM FROM ALL SECTIONS
    */
	memcpy(newRpm, lead, 96 * sizeof(char));
	memcpy(newRpm + 96, newSignature, (strlen(newSignatureHex) / 2) * sizeof(char));
	memcpy(newRpm + 96 + (strlen(newSignatureHex) / 2), headersAndPayload, headersAndPayloadSize * sizeof(char));
	free(newSignatureHex);
	free(lead);
	free(newSignature);
	free(headersAndPayload);

    /**
    * WRITE GENERATED SIGNED RPM, OVERRIDING ORIGINAL RPM FILE
    */
	FILE *newFile = fopen(filename, "wb");
	fwrite(newRpm, newRpmSize, 1, newFile);

	printf(SIGNATURE_SUCCESS);
	free(newRpm);
	fclose(newFile);

cleanandreturn:;

    /**
    * CLEAN TMP FILE CONTAINING DATA TO SIGN
    */
    int removedFile = remove(headersAndPayloadTmpFilePath);
    if (removedFile != 0) {
        printErr(ERR_FILE_DELETE_FAIL, headersAndPayloadTmpFilePath);
    }
    free(headersAndPayloadTmpFilePath);


// */

}

/**
* Inits signature library (xmlsec) and create the xmldsig
*/
xmlDocPtr signFile(char* file_to_sign, char* p12Path,  char* pwd) {

    xsltSecurityPrefsPtr xsltSecPrefs = NULL;

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
    xmlIndentTreeOutput = 1;

    /* Init libxslt */
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);

    /* Init xmlsec library */
    if (xmlSecInit() < 0) {
        printErr(ERR_XMLSEC_INIT_FAIL);
        return(NULL);
    }

    /* Check loaded library version */
    if (xmlSecCheckVersion() != 1) {
        printErr(ERR_XMLSEC_VERSION_INVALID);
        return(NULL);
    }

    /* Init crypto library */
    if (xmlSecCryptoAppInit(NULL) < 0) {
        printErr(ERR_XMLSEC_CRYPTO_APP_INIT_FAIL);
        return(NULL);
    }

    /* Init xmlsec-crypto library */
    if (xmlSecCryptoInit() < 0) {
        printErr(ERR_XMLSEC_CRYPTO_INIT_FAIL);
        return(NULL);
    }

    xmlDocPtr res = generateCrypto(file_to_sign, p12Path, pwd);

    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();

    xmlCleanupParser();

    return(res);
}

/**
* Creates a template for an xmldsig and use it with file to sign and p12 to generate the signature crypto
*/
xmlDocPtr generateCrypto(char* file_to_sign, char* p12Path, char* pwd) {

    assert(p12Path);
    assert(pwd);
    assert(file_to_sign);

    if (access(file_to_sign, F_OK) != 0) {
        printErr(ERR_FILE_NOT_FOUND, file_to_sign);
        goto done;
    }

    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;
    char *tmpBegin = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><ds:Reference URI=\"";
    char *tmpEnd = "\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509SubjectName/><ds:X509Certificate/></ds:X509Data></ds:KeyInfo></ds:Signature>";
    char actualpath [PATH_MAX];
    char *fileRealPath, *uriFilePrefix;
    uriFilePrefix = "file:";
    fileRealPath = realpath(file_to_sign, actualpath);
    char *fileUri = (char *) malloc((strlen(fileRealPath) + 5) * sizeof(char) + 1);
    strcpy(fileUri, uriFilePrefix);
    strcat(fileUri, fileRealPath);

    char *fullTemplate = (char *)malloc((strlen(tmpBegin) + strlen(tmpEnd) + strlen(fileUri) + 1) * sizeof(char));
    strcpy(fullTemplate, tmpBegin);
    strcat(fullTemplate, fileUri);
    strcat(fullTemplate, tmpEnd);
    free(fileUri);

    /* load template */
    doc = xmlParseDoc((xmlChar *)fullTemplate);
    free(fullTemplate);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        printErr(ERR_XML_TEMPLATE_PARSE_FAIL);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if (node == NULL) {
        printErr(ERR_XML_TEMPLATE_1ST_NODE_NOT_FOUND);
        goto done;
    }

    FILE *fp;
    if ((fp = fopen(p12Path, "rb")) == NULL) {
        printErr(ERR_CANNOT_OPEN_FILE, p12Path);
        goto done;
    }
    PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (p12 == NULL) {
        printErr(ERR_P12_FILE_FORMAT_NOT_RECOGNIZED, p12Path);
        goto done;
    }
    if (!PKCS12_parse(p12, pwd, NULL, NULL, NULL)) {
        printErr(ERR_P12_WONT_OPEN_BECAUSE_INVALID_PASSWORD);
        goto done;
    }
    PKCS12_free(p12);

    if (xmlSecAppLoadKeys(p12Path, pwd) < 0) {
        printErr(ERR_KEY_MANAGER_CREATION_FAILED);
        goto done;
    }

    dsigCtx = xmlSecDSigCtxCreate(gKeysMngr);
    if (dsigCtx == NULL) {
        printErr(ERR_SIGNATURE_CONTEXT_CREATION_FAILED);
        goto done;
    }

    if (xmlSecDSigCtxSign(dsigCtx, node) < 0) {
        printErr(ERR_SIGNATURE_FAILED);
        goto done;
    }

    xmlSecDSigCtxDestroy(dsigCtx);

    return doc;

done:
    /* cleanup */
    if (dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(NULL);
}

/**
* Inits key manager and load private key for signature
*/
static int xmlSecAppLoadKeys(char *p12Path, char *pwd) {

    if (gKeysMngr != NULL) {
        printErr(ERR_KEY_MANAGER_ALREADY_INITIALIZED);
        return(-1);
    }

    /* create and initialize keys manager */
    gKeysMngr = xmlSecKeysMngrCreate();
    if (gKeysMngr == NULL) {
        printErr(ERR_KEY_MANAGER_CREATION_FAILED);
        return(-1);
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(gKeysMngr) < 0) {
        printErr(ERR_KEY_MANAGER_INITIALIZATION_FAILED);
        return(-1);
    }

    if (xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(gKeysMngr, p12Path, pwd, NULL) < 0) {
        printErr(ERR_FAILED_TO_LOAD_KEY_FROM_P12, p12Path);
        free(pwd);
        return(-1);
    }
    free(pwd);

    return(0);
}

/**
* Loads private key for signature
*/
int xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(xmlSecKeysMngrPtr mngr, const char *filename, const char* pwd, const char *name) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    key = xmlSecCryptoAppKeyLoad(filename, xmlSecKeyDataFormatPkcs12, pwd,
                    xmlSecCryptoAppGetDefaultPwdCallback(), (void*)filename);
    if (key == NULL) {
        printErr(ERR_XMLSEC_KEY_LOAD_FAILED, xmlSecErrorsSafeString(filename));
        return(-1);
    }

    if (name != NULL) {
        ret = xmlSecKeySetName(key, BAD_CAST name);
        if (ret < 0) {
            printErr(ERR_XMLSEC_SET_KEY_NAME_FAILED, xmlSecErrorsSafeString(name));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }

    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if (ret < 0) {
        printErr(ERR_XMLSEC_ADD_KEY_TO_KEY_MANAGER_FAILED);
        xmlSecKeyDestroy(key);
        return(-1);
    }

    return(0);

}

/**
* Reads a file and return its content in a char* alongside with the file size
*/
struct StringWithSize readFileAsByteArray(char *filename) {

	FILE* file;
	char *buffer;
	long filelen;

	file = fopen(filename, "rb");      // Open the file in binary mode
	if (file == NULL) {
		printErr(ERR_CANNOT_OPEN_FILE, filename);
		exit(1);
	}
	fseek(file, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(file);             // Get the current byte offset in the file
	rewind(file);                      // Jump back to the beginning of the file

	buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the file
	fread(buffer, filelen, 1, file); // Read in the entire file
	fclose(file); // Close the file
	
	struct StringWithSize stringWithSize;
	stringWithSize.size = filelen;
	stringWithSize.content = buffer;

	return stringWithSize;

}

/**
* Converts bytes to hex, returning hex in a char* alongside with its size
*/
struct StringWithSize fromByteArrayToHex(struct StringWithSize bytes) {

	char *byteArray = bytes.content;
	long sizeOfFile = bytes.size;
	int i;
	long hexFileLength = 2 * sizeOfFile * sizeof(char); // Should not be useful since we now have a null terminated hex string but anyway
	char *hexFile = (char *)malloc(hexFileLength + 1);
	// 1 byte as hex (2 char) + 1 char for \0
	char *hexSingleByte = (char *)malloc(3 * sizeof(char));

	for (i = 0; i < sizeOfFile; i++) {
		sprintf(hexSingleByte, "%02x", (unsigned char) byteArray[i]);
		hexFile[i * 2] = hexSingleByte[0];
		hexFile[(i * 2) + 1] = hexSingleByte[1];
	}
	free(hexSingleByte);
	hexFile[2 * sizeOfFile] = '\0';

	struct StringWithSize stringWithSize;
	stringWithSize.size = hexFileLength;
	stringWithSize.content = hexFile;
	
	return stringWithSize;

}

/**
* Copies a part of an array and return it.
* Start is included, end is not
* Original array is not freed
*/
char *subArray(char *originalArray, int start, int end) {

	int size = end - start;
	char *substring = (char *)malloc(size + 1);
	memcpy(substring, &originalArray[start], size);
	substring[size] = '\0';

	return substring;

}

/**
* Asserts a char* starts with 8eade8 (which is the 'header magic' defined by RPM
* -> a string declaring the start of lead, signature or header section)
*/
int checkHeaderMagic(char *header) {
	if (strncmp("8eade8", header, 6) != 0) {
	    printErr(ERR_INPUT_RPM_FORMAT_INVALID);
	    return(1);
	}
	return(0);
}

/**
* Converts hex char* to decimal long. Input is not freed
*/
long hexToDec(char *hex) {
	return strtol(hex, NULL, 16);
}

/**
* Returns the number of sub-headers from a signature or a header section.
* 'Signature' and 'Header'  sections are structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* The number of sub-headers is defined in declaring line.
* This function takes this declaring line as input and outputs the number of sub-headers as long
*/
long numberOfSubHeaders(char *headerDeclarationLine) {
	char *headerNbHex = subArray(headerDeclarationLine, 16, 24);
	long dec = hexToDec(headerNbHex);
	free(headerNbHex);
	return dec;
}

/**
* Returns (in the input pointer 'signatureHeaders') the list of sub-headers from a signature section.
* 'Signature'  section is structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* With the number of sub-headers for the signature section and the whole rpm it is possible to retrieve the list of
* sub-headers.
* sub-headers are always exactly 16 bytes long (here 33 corresponds to the size as hex + null byte)
* They always start at index 224 (again, in hex), 224 being the size of the lead + size of the declaring line of the
* signature section.
*/
void listSignatureSubHeaders(char *rpmHex, int nbOfSignatureHeaders, char (*signatureHeaders)[33]) {

	char *header;
	int i, j;
	int indexOfNextHeader;

	for (i = 0; i < nbOfSignatureHeaders; i++) {
		// 32 being the size of each line (32 characters since it's hex) and 224 the offset of the lead + signature header declaration line
		indexOfNextHeader = i * 32 + 224;
		header = subArray(rpmHex, indexOfNextHeader, indexOfNextHeader + 32);
		for (j = 0; j < 32; j++) {
			signatureHeaders[i][j] = header[j];
		}
		signatureHeaders[i][32] = '\0';
	    free(header);
	}

}

/**
* Returns the index of the end of the signature section (in hex) as long
* 'Signature'  section is structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* This function uses data from declaring line and number of headers in the signature section to compute the index of the
* last byte of VALUES.
*/
long findEndOfSignatureRegion(char *signatureDeclarationLine, int nbOfHeaders) {

	char *signatureSizeHex = subArray(signatureDeclarationLine, 24, 32);
	long signatureHeaderValuesSize = hexToDec(signatureSizeHex);
	free(signatureSizeHex);
	long leadSize = 96;
	long signatureDeclarationLineSize = 16;
	long fourNullBytesSize = 4;
	long headersDeclarationOffset = nbOfHeaders * 16;
	
	return leadSize + signatureDeclarationLineSize + headersDeclarationOffset + signatureHeaderValuesSize + fourNullBytesSize;

}

/**
* Converts a string to its hex representation and return it as a char*
*/
char *string2hexString(char *input) {
	char *output;
	output = (char *) malloc((strlen(input) * 2 * sizeof(char)) + 1);
	int loop;
	int i; 

	i=0;
	loop=0;

	while(input[loop] != '\0') {
		sprintf((char *)(output+i),"%02x", input[loop]);
		loop+=1;
		i+=2;
	}
	//insert NULL at the end of the output string
	output[i++] = '\0';
	return output;
}

/**
* Computes the size of the padding following the VALUES of a signature section and returns the valid padding in char*.
* 'Signature'  section is structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* The last byte of padding puts an end to the signature section. Following bytes are the header section.
* For some reason this padding MUST end at index (in hex) 16k (k being any integer). Meanging if the index at which
* padding ends is not a multiple of 16, the rpm may not be recognized as valid.
*/
char *computeNullBytesNumber(long headerSectionOffset) {

	char *padding;
	int remainder, paddingSize;

	remainder = headerSectionOffset % 16;
	paddingSize = 16 - remainder;
	padding = (char *)malloc(paddingSize + 1);
	memset(padding, '0', paddingSize);
	padding[paddingSize] = '\0';
	
	return padding;

}

/**
* Generates the hex value of the signature section for an xmldsig signed rpm.
* 'Signature'  section is structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* These 4 parts are concatenated in a char* and returned.
*/
char *generateNewSignature(char *xmldsig, char *md5Value) {

	// Size of the xmldsig
	int xmldsigB64Length = strlen(xmldsig);
	// 8 + 1 for \0
	char *hexXmldsigSize = (char *)malloc(9 * sizeof(char));
	sprintf(hexXmldsigSize, "%08x", xmldsigB64Length);

	// Offset of the HEADERSIGNATURES (signature length + 16 bytes)
	int headerSignaturesOffset = xmldsigB64Length + 16;
	// 8 + 1 for \0
	char *hexHeaderSignaturesOffset = (char *)malloc(9 * sizeof(char));
	sprintf(hexHeaderSignaturesOffset, "%08x", headerSignaturesOffset);
	
	// Size of the signature values (excluding first line and signature sub headers) : first 16 is MD5 value and second 16 is HEADERSIGNATURES
	int signatureRegionSize = strlen(xmldsig) + 16 + 16;
	// 8 + 1 for \0
	char *hexSignatureRegionSize = (char *)malloc(9 * sizeof(char));
	sprintf(hexSignatureRegionSize, "%08x", signatureRegionSize);

	char *reservedSpaceValue;

	char tmpDeclaringLine[] = "8eade8010000000000000003";
	strcat(tmpDeclaringLine, hexSignatureRegionSize);
	free(hexSignatureRegionSize);
	char *declaringLine = (char *)malloc(strlen(tmpDeclaringLine) + 1);
	strcpy(declaringLine, tmpDeclaringLine);

	char tmpHeaderSignatures[] = "0000003e00000007";
	strcat(tmpHeaderSignatures, hexHeaderSignaturesOffset);
	free(hexHeaderSignaturesOffset);
	strcat(tmpHeaderSignatures, "00000010");
	char *headerSignatures = (char *)malloc(strlen(tmpHeaderSignatures) + 1);
	strcpy(headerSignatures, tmpHeaderSignatures);

	char *headerReservedSpace = (char *)malloc(33 * sizeof(char));
	strcpy(headerReservedSpace, "000003f00000000700000010");
	strcat(headerReservedSpace, hexXmldsigSize);
	free(hexXmldsigSize);

	char headerDigestMd5[] = "000003ec000000070000000000000010";

	char headerSignaturesValue[] = "0000003e00000007ffffffd000000010";
	
	reservedSpaceValue = string2hexString(xmldsig);
	
	long fullSignatureSize = strlen(declaringLine)
        + strlen(headerSignatures) + strlen(headerDigestMd5) + strlen(headerReservedSpace)
        + strlen(md5Value) + strlen(reservedSpaceValue)
        + strlen(headerSignaturesValue);
    
    // Apparently the magic number for the header section has to start at offset = 16 * k
    // (k being any integer)
    // Following function computes the number of null byte numbers to add as padding
    // (note that the lead is always a multiple of 16 bytes so we do not need to take it into account)
	char *nullBytes = computeNullBytesNumber(fullSignatureSize);
    char *error = "ERROR";
	
	if (strcmp(error, nullBytes) == 0) {
		printErr(ERR_HEX_SIGNATURE_CORRUPTED);
	}

    fullSignatureSize = fullSignatureSize + strlen(nullBytes) + 1;
	char *fullSignature = (char *)malloc(fullSignatureSize);

	strcpy(fullSignature, declaringLine);
	strcat(fullSignature, headerSignatures);
	strcat(fullSignature, headerDigestMd5);
	strcat(fullSignature, headerReservedSpace);
	strcat(fullSignature, md5Value);
	strcat(fullSignature, reservedSpaceValue);
	strcat(fullSignature, headerSignaturesValue);
	strcat(fullSignature, nullBytes);
	free(reservedSpaceValue);
	free(declaringLine);
	free(headerSignatures);
	free(headerReservedSpace);
	free(nullBytes);

	return fullSignature;

}

/**
* Returns the 16 bytes (in hex, so 32 + 1 with the null byte) of a sub-header which code is given in codeToFind.
* 'Signature' and 'Header'  sections are structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* This function returns one of the "SUB-HEADERS"
* 'SUB-HEADERS' are structured as follow :
*
* SUB-HEADER CODE (4 bytes)
* DATA-TYPE (4 bytes)
* OFFSET (4 bytes)
* COUNT (4 bytes)
*
* codeToFind input is the SUB-HEADER CODE (as hex) of the entry to return
* listOfStrings input is the list of subHeaders (as hex) which contains the entry to find
* listSize input is the number of entries in the listOfStrings list
*/
char *getEntry(char *codeToFind, char (*listOfStrings)[33], int listSize) {

	int i;

	for (i = 0; i < listSize; i++) {
	    char *identifier = subArray(listOfStrings[i], 0, 8);
		if (strcmp(codeToFind, identifier) == 0) {
		    free(identifier);
			return listOfStrings[i];
		}
		free(identifier);
	}
	
	return NULL;

}

/**
* Returns the 16 bytes (in hex, so 32 + 1 with the null byte) of the md5 mandatory value (RPMSIGTAG_MD5).
* 'Signature' and 'Header'  sections are structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* Using the total number of subheaders and the sub-header value for RPMSIGTAG_MD5 (the value to return), the position of
* RPMSIGTAG_MD5 VALUE is computed, and is returned as char*
*
* Note : this digest is computed on header/payload sections, since signing the file does not alter these sections the
*   value of this digest does not change, this is why it is simply copied from input rpm instead of computed again.
*/
char *getMd5ofRpm(char *md5Header, char *hexRpm, int signatureHeaderNb) {

	char *offsetofmd5value = subArray(md5Header, 16, 24);

	int md5Position = 96 + 16 + signatureHeaderNb * 16 + (int) hexToDec(offsetofmd5value);

	free(offsetofmd5value);
	
	return subArray(hexRpm, md5Position * 2, md5Position * 2 + 32);

}

/**
* Converts an hex string to its bytes value and returns it as char*
*/
char *fromHexToAscii(char *hex) {

	char *msg;

	size_t msgSize = strlen(hex) / 2;
	msg = (char *)malloc(msgSize * sizeof(char));

	memset(msg, '\0', msgSize);

	for (int i = 0; i < strlen(hex); i+=2) {
		char msb = (hex[i+0] <= '9' ? hex[i+0] - '0' : (hex[i+0] & 0x5F) - 'A' + 10);
		char lsb = (hex[i+1] <= '9' ? hex[i+1] - '0' : (hex[i+1] & 0x5F) - 'A' + 10);
		msg[i / 2] = (msb << 4) | lsb;
	}

	return msg;

}

/**
* Writes a file, path is specified in filename
*/
void writeTempFile(char *content, int size, char *filename) {

    FILE* pFile;

    /* Write buffer to disk. */
    pFile = fopen(filename, "wb");

    if (pFile) {
        fwrite(content, size, 1, pFile);
    }
    else {
        printErr(ERR_WRITING_TO_FILE_FAILED, filename);
    }

    fclose(pFile);

}

/**
* Data to sign must be in an external file so xmldsig can be DETACHED.
* This method returns the path of a tmp file containing header+payload sections of rpm to sign from the input file name.
*/
char *tmpFilePath(char *filename)  {
    char *fileBaseName = basename(filename);
    char* varTmpPath = "/var/tmp/";
    char* fileSuffix = ".rpmpkisign";
    char* filePath = malloc(strlen(varTmpPath) + strlen(fileBaseName) + strlen(fileSuffix) + 1);
    strcpy(filePath, varTmpPath);
    strcat(filePath, fileBaseName);
    strcat(filePath, fileSuffix);
    return filePath;
}

/**
* Prompts user for a password (returned in password[])
*/
int getPassword(char password[]) {

    static struct termios oldt, newt;
    int i = 0;
    int c;

    /*saving the old settings of STDIN_FILENO and copy settings for resetting*/
    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;

    /*setting the approriate bit in the termios struct*/
    newt.c_lflag &= ~(ECHO);

    /*setting the new bits*/
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    /*reading the password from the console*/
    while ((c = getchar()) != '\n' && c != EOF && i < MAX_P12_PASSWORD_SIZE + 1) {
        password[i++] = c;
    }
    if (i >= MAX_P12_PASSWORD_SIZE) {
        printErr(ERR_INPUT_PASSWORD_TOO_LONG, MAX_P12_PASSWORD_SIZE);
        return(1);
    }
    password[i] = '\0';

    /*resetting our old STDIN_FILENO*/
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

    return(0);

}

void printErr(char *stringToPrint, ...) {

    va_list args;
    va_start(args, stringToPrint);
    
    /*char *messageWithPrefix = (char *)malloc(strlen(stringToPrint) + strlen(ERROR_PREFIX) + 1);
    strcpy(messageWithPrefix, ERROR_PREFIX);
    strcat(messageWithPrefix, stringToPrint);
    vfprintf(stderr, messageWithPrefix, args);*/
    
    vfprintf(stderr, ERROR_PREFIX, args);
    vfprintf(stderr, stringToPrint, args);
    //free(messageWithPrefix);
    
    va_end(args);

}

