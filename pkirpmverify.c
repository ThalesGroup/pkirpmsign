#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <termios.h>
#include <unistd.h>
#include <stdbool.h>
#include <dirent.h>
#include <regex.h>

#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

#define MAX_CHAIN_LENGTH 20

#define CERT_SUBJECT 1
#define CERT_ISSUER 2

#define DEFAULT_TRUSTED_CERTS_DIR "/etc/pki/rpm-certs/"

#define ERR_WRONG_NB_OF_ARGS "Wrong number of arguments.\n\tUsage: %s <file-to-verify> <pem-cert-chain-file> ...\n\t(There can be as many pem-cert-chain-file as needed, and they can contain from a single certificate only to the full certificate chain)\n\tOr : %s <file-to-verify>\nThis option finds the certificate chain in /etc/pki/rpm-certs/ provided that the cert chain (except the signing cert) is present in this directory\n"
#define ERR_NO_XMLDSIG_IN_INPUT_RPM "Could not find xmldsig in input rpm file.\n"
#define ERR_CANNOT_VERIFY_SIGNATURE "Cannot verify signature, \033[1;31msignature cannot be trusted.\033[0m\n"
#define ERR_CANNOT_FIND_CERT_CHAIN "Could not find a certificate chain for signing certificate, \033[1;31msignature cannot be trusted.\033[0m\n"
#define ERR_FILE_DELETE_FAIL "Error deleting file '%s'\n"
#define ERR_CANNOT_OPEN_FILE "Cannot open file %s\n"
#define ERR_INPUT_RPM_FORMAT_INVALID "Unrecognized input rpm format.\n"
#define ERR_WRITING_TO_FILE_FAILED "Something went wrong when writing to file : %s\n"
#define ERR_XMLSEC_INIT_FAIL "xmlsec initialization failed.\n"
#define ERR_XMLSEC_CRYPTO_APP_INIT_FAIL "Crypto initialization failed.\n"
#define ERR_XMLSEC_CRYPTO_INIT_FAIL "xmlsec-crypto initialization failed.\n"
#define ERR_KEY_MANAGER_CREATION_FAILED "Keys manager creation failed\n"
#define ERR_KEY_MANAGER_INITIALIZATION_FAILED "Failed to initialize keys manager.\n"
#define ERR_CERT_NOT_IN_PEM_FORMAT "Input file \"%s\" does not seem to be in pem format\n"
#define ERR_FAILED_TO_LOAD_CERT_FILE "Failed to load pem certificate from \"%s\"\n"
#define ERR_FAILED_TO_LOAD_PEM_CERT "Failed to load pem certificate\n"
#define ERR_XML_TEMPLATE_PARSE_FAIL "Unable to parse file \"%s\"\n"
#define ERR_XML_TEMPLATE_1ST_NODE_NOT_FOUND "Start node not found in \"%s\"\n"
#define ERR_SIGNATURE_CONTEXT_CREATION_FAILED "Failed to create signature context\n"
#define ERR_UNKNOWN_VERIFICATION_FAILURE "Unknown signature verification error\n"
#define ERR_NO_SIGNING_CERT_IN_SIGNATURE "No signing certificate found, signature cannot be verified.\n"
#define ERR_MULTIPLE_SIGNING_CERT_IN_SIGNATURE "More than 1 signing certificate found, signature cannot be verified.\n"
#define ERR_UNABLE_TO_ADD_XML_NAMESPACES "Unable to add namespaces to list\n"
#define ERR_INVALID_NAMESPACE_LIST_FORMAT "Invalid namespaces list format\n"
#define ERR_UNABLE_TO_ADD_SPECIFIC_NAMESPACE "Unable to register NS with prefix=\"%s\" and href=\"%s\"\n"
#define ERR_FILE_NAME_CHANGED_SINCE_SIGNATURE "File name changed. When it was signed the file name was %s, now it is %s\n"
#define ERR_CANNOT_GET_CERT_SUBJECT "Cannot get subject from certificate"
#define ERR_CANNOT_GET_CERT_ISSUER "Cannot get issuer from certificate"
#define ERR_UNSUPPORTED_CERT_DATA_TO_PRINT "Unsupported data to print"
#define ERR_CERT_CHAIN_TOO_BIG "Cert chain length is too big, max chain length = %d\n"
#define ERR_CANNOT_COMPILE_REGEX "Could not compile regex\n"
#define ERR_REGEX_MATCH_FAIL "Regex match failed: %s\n"

#define SIGNATURE_OK "Signature is \033[1;32mOK\033[0m\n"
#define SIGNED_BY "Signed by :\n"
#define SIGNATURE_INVALID "Signature is \033[1;31mINVALID\033[0m\n"
#define ERROR_PREFIX "Error: "

struct certChainWithSize {
    int size;
    X509 *certChain[MAX_CHAIN_LENGTH];
    bool chainComplete;
};

struct StringWithSize {
	long size;
	char *content;
};

struct StringWithSize readFileAsByteArray(char *filename);
struct StringWithSize fromByteArrayToHex(struct StringWithSize file);
char *subArray(char *originalArray, int start, int end);
char *subArrayLong(char *originalArray, long start, long end);
void checkHeaderMagic(char *header);
long hexToDec(char *hex);
long numberOfSubHeaders(char *headerDeclarationLine);
void listSignatureSubHeaders(char *rpmHex, int nbOfSignatureHeaders, char (*signatureHeaders)[33]);
long findEndOfSignatureRegion(char *signatureDeclarationLine, int nbOfHeaders);
char *getEntry(char *codeToFind, char (*listOfStrings)[33], int listSize);
void writeTempFile(char *content, int size, char *filename);
char *tmpFilePath(char *filename);
int getSignatureStart(char *signatureHeader, int nbOfSignatureHeaders);
int getSignatureEnd(char *signatureHeader, int signatureStart);
char *getSignature(char *signatureHeader, char *rpmFile, int nbOfSignatureHeaders);
int initVerifyLibrary(xsltSecurityPrefsPtr xsltSecPrefs);
xmlSecKeysMngrPtr load_trusted_certs(char** certFiles, int filesSize);
int verifySignature(xmlSecKeysMngrPtr mngr, const char* xmlString, char* signingCert);
void cleanup(xmlSecKeysMngrPtr mngr, xsltSecurityPrefsPtr xsltSecPrefs);
char *getValuesFromXml(xmlNodeSetPtr nodes);
int register_namespaces(xmlXPathContextPtr xpathCtx, const xmlChar* nsList);
char *getCertPem(char *signature);
void printCertData(X509 *cert, int dataToPrint);
void populateCertChain(struct certChainWithSize *chainToBuild);
char *concatStrings(char *str1, char *str2);
X509* openPemFile(char* filename);
int regexMatch(char *inputToTest, char *regexString);
xmlSecKeysMngrPtr loadCertChain(struct certChainWithSize *certFullChain);
char *fromX509ToString(X509 *cert);
X509 *fromStringToX509(char *cert);
int computeNullBytesNumber(long headerSectionOffset);
int checkRpmFileNameInSignature(char *signature, char *rpmFileName);
void printErr(char *stringToPrint, ...);

int shouldXmlSecBeClosed = 0;

int main(int argc, char **argv) {

    /**
    * VERIFY ARGUMENTS
    */
    assert(argc);
    assert(argv);
    if (argc < 2) {
        printErr(ERR_WRONG_NB_OF_ARGS, argv[0], argv[0]);
        return(1);
    }

    int res = 0;
    xmlSecKeysMngrPtr mngr = NULL;
    char *signingCert = NULL;

    /**
    * READ ARGUMENTS INTO VARIABLES
    */
    char *filename = argv[1];
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;

    /**
    * READ FILE TO SIGN & EXTRACT DATA FROM IT
    */
	struct StringWithSize file = readFileAsByteArray(filename);
	struct StringWithSize hexFile = fromByteArrayToHex(file);
	// extract first line of signature section
	char *signatureHeader = subArray(hexFile.content, 192, 224);

	checkHeaderMagic(signatureHeader);

    // extract the list of signature headers (signature section of rpm contains headers)
    // for now there should always be 3 headers, but may change in the future
	long nbOfSignatureHeaders = numberOfSubHeaders(signatureHeader);
	char signatureHeaders[nbOfSignatureHeaders][33];
	listSignatureSubHeaders(hexFile.content, nbOfSignatureHeaders, signatureHeaders);

	long endOfSignatureRegion = findEndOfSignatureRegion(signatureHeader, nbOfSignatureHeaders);

    // extract header and payload sections, which is what should be signed.
	long headersAndPayloadSize = file.size - endOfSignatureRegion;
	char *headersAndPayload = subArray(file.content, endOfSignatureRegion, file.size);

    /**
    * CREATE A TMP FILE CONTAINING DATA TO VERIFY
    * data to verify consist of the 2 last part of the input rpm file : headers & payload
    * first two parts (lead and signature) are not signed, just as in regular pgp rpm sign
    */
    char *headersAndPayloadTmpFilePath = tmpFilePath(filename);
	writeTempFile(headersAndPayload, headersAndPayloadSize, headersAndPayloadTmpFilePath);
	free(headersAndPayload);

    /**
    * EXTRACT XMLDSIG FROM SIGNATURE SECTION
    * 000003f0 is the entry for 'reservedSpace' which is where we store our signature
    */
	char *pkiSignatureHeader = getEntry("000003f0", signatureHeaders, nbOfSignatureHeaders);
	if (NULL == pkiSignatureHeader) { // If entry is not present then it is not an xmldsig signed rpm file
        printErr(ERR_NO_XMLDSIG_IN_INPUT_RPM);
	    res = 1;
	    goto cleanandreturn;
	}

	char *signature = getSignature(pkiSignatureHeader, file.content, nbOfSignatureHeaders);
	// If entry does not start with xml tag then it is not an xmldsig signed rpm file
	if (strncmp("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", signature, 38) != 0) {
        printErr(ERR_NO_XMLDSIG_IN_INPUT_RPM);
	    res = 1;
	    goto cleanandreturn;
	}

    /**
    * VERIFY INPUT RPM FILE NAME IS EQUAL TO THE FILE NAME IN THE XMLDSIG INSIDE IT
    * If it is not equal it means the file name changed since signature
    */
    int filenameValidity = checkRpmFileNameInSignature(signature, filename);
    if (filenameValidity != 0) {
        printErr(ERR_CANNOT_VERIFY_SIGNATURE);
	    res = 1;
	    goto cleanandreturn;
    }

    /**
    * EXTRACT SIGNING CERT FROM XMLDSIG
    */
	signingCert = getCertPem(signature);

    /**
    * VERIFY THE SIGNATURE
    */
    if (initVerifyLibrary(xsltSecPrefs) != 0) {
        res = 1;
        goto cleanandreturn;
    }

    if (argc > 2) { // In case certificates paths are passed as parameters : use them
        // create keys manager and load trusted certificates
        mngr = load_trusted_certs(&(argv[2]), argc - 2);
    } else if (argc == 2) { // In case there is only 1 arg, then use default directory and look for certificates
        // Instantiation of cert chain
        struct certChainWithSize certFullChain;
        certFullChain.size = 1;
        certFullChain.certChain[0] = fromStringToX509(signingCert);
        certFullChain.chainComplete = false;
        // Find rest of the chain
        populateCertChain(&certFullChain);

        // Check the chain is complete (the full cert chain may not be found, in this case the signature is not trusted)
        if (certFullChain.chainComplete == false) {
            printErr(ERR_CANNOT_FIND_CERT_CHAIN);
            return(-1);
        }

        // If the cert chain is complete then add all certificates of the chain in the keymanager
        mngr = loadCertChain(&certFullChain);

        // The cert chain is stored in the keymanager, it can now be cleaned from certFullChain
        for (int i = 0; i < certFullChain.size; i++) {
            X509_free(certFullChain.certChain[i]);
        }
    }

    if (mngr == NULL) {
        printErr(ERR_CANNOT_VERIFY_SIGNATURE);
        return(-1);
    }
    if (verifySignature(mngr, signature, signingCert) < 0) {
        xmlSecKeysMngrDestroy(mngr);
        return(-1);
    }

cleanandreturn:

    /**
    * CLEANING UP
    */
    if (signingCert != NULL) {
        free(signingCert);
    }
	free(file.content);
	free(signatureHeader);
	free(hexFile.content);

    /**
    * CLEAN TMP FILE CONTAINING DATA TO VERIFY
    */
    int removedFile = remove(headersAndPayloadTmpFilePath);
    if (removedFile != 0) {
        printErr(ERR_FILE_DELETE_FAIL, headersAndPayloadTmpFilePath);
    }
    free(headersAndPayloadTmpFilePath);

	free(signature);
	cleanup(mngr, xsltSecPrefs);

	return(res);
//*/

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
* Copies a part of an array and return it.
* Start is included, end is not
* Original array is not freed
*/
char *subArrayLong(char *originalArray, long start, long end) {

	long size = end - start;
	char *substring = (char *)malloc(size + 1);
	memcpy(substring, &originalArray[start], size);
	substring[size] = '\0';

	return substring;

}

/**
* Asserts a char* starts with 8eade8 (which is the 'header magic' defined by RPM
* -> a string declaring the start of lead, signature or header section)
*/
void checkHeaderMagic(char *header) {
	if (strncmp("8eade8", header, 6) != 0) {
	    printErr(ERR_INPUT_RPM_FORMAT_INVALID);
	    exit(1);
	}
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
* Computes the size of the padding following the VALUES of a signature section and returns the valid padding in char*.
* 'Signature'  section is structured as follow :
*
* DECLARING LINE
* SUB-HEADERS
* VALUES
* (padding)
*
* The last byte of padding puts an end to the signature section. Following bytes are the header section.
* For some reason this padding MUST end at index (in hex) 8k (k being any integer). Meanging if the index at which
* padding ends is not a multiple of 8, the rpm may not be recognized as valid.
*/
int computeNullBytesNumber(long headerSectionOffset) {

	int remainder, paddingSize;

	remainder = headerSectionOffset % 8;
	paddingSize = 8 - remainder;

	return paddingSize;

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

	long headersDeclarationOffset = nbOfHeaders * 16;

	long fullSignatureSectionSizeWithoutPadding = leadSize + signatureDeclarationLineSize + headersDeclarationOffset
	    + signatureHeaderValuesSize;
	int padding = computeNullBytesNumber(fullSignatureSectionSizeWithoutPadding);

	return fullSignatureSectionSizeWithoutPadding + padding;

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
* Returns the index of the start of the signature in the signed rpm file
* The rpm file is used as is to compute this index, it is NOT the hex representation of the file
* the returned index value is in decimal.
*/
int getSignatureStart(char *signatureHeader, int nbOfSignatureHeaders) {
	char *signatureStart = subArray(signatureHeader, 16, 24);
	long signatureStartDec = hexToDec(signatureStart);
	free(signatureStart);
	// Add Lead (0x60), signature header declaration (0x10) and other signature headers (0x10 * nbOfSignatureHeaders) offset
	int signatureStartWithLeadAndHeaders = ((int) signatureStartDec) + 0x60 + 0x10 + (0x10 * nbOfSignatureHeaders);
	return signatureStartWithLeadAndHeaders;
}

/**
* Returns the index of the end of the signature in the signed rpm file
* The rpm file is used as is to compute this index, it is NOT an index for the hex representation of the file
* the returned index value is in decimal.
*/
int getSignatureEnd(char *signatureHeader, int signatureStart) {
	char *signatureLength = subArray(signatureHeader, 24, 32);
	long signatureLengthDec = hexToDec(signatureLength);
	free(signatureLength);
	int signatureEnd = ((int) signatureLengthDec) + signatureStart;
	return signatureEnd;
}

/**
* Returns the xmldsig contained in the signed rpm
*/
char *getSignature(char *signatureHeader, char *rpmFile, int nbOfSignatureHeaders) {
    int signatureStart = getSignatureStart(signatureHeader, nbOfSignatureHeaders);
    int signatureEnd = getSignatureEnd(signatureHeader, signatureStart);
    return subArray(rpmFile, signatureStart, signatureEnd);
}



/**
* Init the input xsltSecPrefs and check it was successful
*/
int initVerifyLibrary(xsltSecurityPrefsPtr xsltSecPrefs) {
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
    xmlIndentTreeOutput = 1;
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
    if (xmlSecInit() < 0) {
        printErr(ERR_XMLSEC_INIT_FAIL);
        return 1;
    }

    if (xmlSecCryptoAppInit(NULL) < 0) {
        printErr(ERR_XMLSEC_CRYPTO_APP_INIT_FAIL);
        return 1;
    }
    if (xmlSecCryptoInit() < 0) {
        printErr(ERR_XMLSEC_CRYPTO_INIT_FAIL);
        return 1;
    }

    shouldXmlSecBeClosed = 1;
    return 0;
}

/**
* Creates a key manager with trusted certificates loaded
*/
xmlSecKeysMngrPtr load_trusted_certs(char** certFiles, int filesSize) {

    xmlSecKeysMngrPtr mngr;
    int i;
    int nbOfCertFound = 0;

    assert(certFiles);
    assert(filesSize > 0);

    /* create and initialize keys manager, we use a simple list based
     * keys manager, implement your own xmlSecKeysStore klass if you need
     * something more sophisticated
     */
    mngr = xmlSecKeysMngrCreate();
    if (mngr == NULL) {
        printErr(ERR_KEY_MANAGER_CREATION_FAILED);
        return(NULL);
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        printErr(ERR_KEY_MANAGER_INITIALIZATION_FAILED);
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    for (i = 0; i < filesSize; ++i) {
        assert(certFiles[i]);
        struct StringWithSize pemFile = readFileAsByteArray(certFiles[i]);
        char *endOfCert;

        char *subPemFile = (char *)malloc((pemFile.size + 1) * sizeof(char));
        memcpy(subPemFile, pemFile.content, pemFile.size * sizeof(char));
        free(pemFile.content);
        subPemFile[pemFile.size] = '\0';

        if (strstr(subPemFile, "\n-----END CERTIFICATE-----") == 0) {
            printErr(ERR_CERT_NOT_IN_PEM_FORMAT, certFiles[i]);
            return NULL;
        }

        while ((endOfCert = strstr(subPemFile, "\n-----END CERTIFICATE-----")) != 0) {
            long endOfCertPlusFooter = ((uintptr_t) endOfCert + 26) - (uintptr_t) subPemFile;
            char *singleCert = subArrayLong(subPemFile, 0, endOfCertPlusFooter);
            memmove(subPemFile, subPemFile + endOfCertPlusFooter, 1 + strlen(subPemFile) - endOfCertPlusFooter);

            if (xmlSecCryptoAppKeysMngrCertLoadMemory(mngr, singleCert, strlen(singleCert), xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
                printErr(ERR_FAILED_TO_LOAD_CERT_FILE, certFiles[i]);
                xmlSecKeysMngrDestroy(mngr);
                return(NULL);
                free(singleCert);
            }
            free(singleCert);
        }
        free(subPemFile);

    }


    return(mngr);
}

/**
* Creates a key manager with trusted certificates loaded from a 'struct certChainWithSize'
*/
xmlSecKeysMngrPtr loadCertChain(struct certChainWithSize *certFullChain) {

    xmlSecKeysMngrPtr mngr;
    int i;

    assert(certFullChain);

    /* create and initialize keys manager, we use a simple list based
     * keys manager, implement your own xmlSecKeysStore klass if you need
     * something more sophisticated
     */
    mngr = xmlSecKeysMngrCreate();
    if (mngr == NULL) {
        printErr(ERR_KEY_MANAGER_CREATION_FAILED);
        return(NULL);
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        printErr(ERR_KEY_MANAGER_INITIALIZATION_FAILED);
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    for (i = 0; i < certFullChain->size; ++i) {
        assert(certFullChain->certChain[i]);
        struct StringWithSize pemFile;
        pemFile.content = fromX509ToString(certFullChain->certChain[i]);
        pemFile.size = strlen(pemFile.content);
        char *endOfCert;

        char *subPemFile = (char *)malloc((pemFile.size + 1) * sizeof(char));
        memcpy(subPemFile, pemFile.content, pemFile.size * sizeof(char));
        free(pemFile.content);
        subPemFile[pemFile.size] = '\0';

        while ((endOfCert = strstr(subPemFile, "\n-----END CERTIFICATE-----")) != 0) {
            long endOfCertPlusFooter = ((uintptr_t) endOfCert + 26) - (uintptr_t) subPemFile;
            char *singleCert = subArrayLong(subPemFile, 0, endOfCertPlusFooter);
            memmove(subPemFile, subPemFile + endOfCertPlusFooter, 1 + strlen(subPemFile) - endOfCertPlusFooter);

            if (xmlSecCryptoAppKeysMngrCertLoadMemory(mngr, singleCert, strlen(singleCert), xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
                printErr(ERR_FAILED_TO_LOAD_PEM_CERT);
                xmlSecKeysMngrDestroy(mngr);
                free(singleCert);
                free(pemFile.content);
                return(NULL);
            }
            free(singleCert);
        }
        free(subPemFile);

    }


    return(mngr);
}

/**
* Verifies the signature using the keymanager with trusted certificates, the signing certificate, and the xmldsig which
* contains the path to the file signed.
*/
int verifySignature(xmlSecKeysMngrPtr mngr, const char* xmlDSig, char* signingCert) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    assert(mngr);
    assert(xmlDSig);

    /* load file */
    doc = xmlParseDoc(xmlDSig);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        printErr(ERR_XML_TEMPLATE_PARSE_FAIL, xmlDSig);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if (node == NULL) {
        printErr(ERR_XML_TEMPLATE_1ST_NODE_NOT_FOUND, xmlDSig);
        goto done;
    }

    /* create signature context */
    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if (dsigCtx == NULL) {
        printErr(ERR_SIGNATURE_CONTEXT_CREATION_FAILED);
        goto done;
    }

    /* Verify signature */
    if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        printErr(ERR_UNKNOWN_VERIFICATION_FAILURE);
        goto done;
    }

    X509 *certificate = fromStringToX509(signingCert);

    char buf[1024];

    /* print verification result to stdout */
    if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
        fprintf(stdout, SIGNATURE_OK);
        fprintf(stdout, SIGNED_BY);
        printCertData(certificate, CERT_SUBJECT);
    } else {
        fprintf(stdout, SIGNATURE_INVALID);
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if (dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    X509_free(certificate);
    return(res);
}

/**
* Clean xmlsec and libxslt/libxml objects after signature verification
*/
void cleanup(xmlSecKeysMngrPtr mngr, xsltSecurityPrefsPtr xsltSecPrefs) {

    /* destroy keys manager */
    if (mngr != NULL) {
        xmlSecKeysMngrDestroy(mngr);
    }

    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /* Shutdown xmlsec library */
    if (shouldXmlSecBeClosed == 1) {
        xmlSecShutdown();
    }

    /* Shutdown libxslt/libxml */
    if (xsltSecPrefs != NULL) {
        xsltFreeSecurityPrefs(xsltSecPrefs);
    }
    xsltCleanupGlobals();
    xmlCleanupParser();

}

/**
* Returns values of specific xml node. Input has to be a single node containing a value
*/
char *getValuesFromXml(xmlNodeSetPtr nodes) {

    if (!nodes) {
        printErr(ERR_NO_SIGNING_CERT_IN_SIGNATURE);
    }
    if (nodes->nodeNr != 1) {
        printErr(ERR_MULTIPLE_SIGNING_CERT_IN_SIGNATURE);
    }

    xmlNodePtr cur = nodes->nodeTab[0];

    return cur->children->content;

}

/**
* Add namespaces to input xpathCtx
*/
int register_namespaces(xmlXPathContextPtr xpathCtx, const xmlChar* nsList) {
    xmlChar* nsListDup;
    xmlChar* prefix;
    xmlChar* href;
    xmlChar* next;

    assert(xpathCtx);
    assert(nsList);

    nsListDup = xmlStrdup(nsList);
    if (nsListDup == NULL) {
        printErr(ERR_UNABLE_TO_ADD_XML_NAMESPACES);
        return(-1);
    }

    next = nsListDup;
    while(next != NULL) {
        /* skip spaces */
        while((*next) == ' ') next++;
        if ((*next) == '\0') break;

        /* find prefix */
        prefix = next;
        next = (xmlChar*)xmlStrchr(next, '=');
        if (next == NULL) {
            printErr(ERR_INVALID_NAMESPACE_LIST_FORMAT);
            xmlFree(nsListDup);
            return(-1);
        }
        *(next++) = '\0';

        /* find href */
        href = next;
        next = (xmlChar*)xmlStrchr(next, ' ');
        if (next != NULL) {
            *(next++) = '\0';
        }

        /* do register namespace */
        if (xmlXPathRegisterNs(xpathCtx, prefix, href) != 0) {
            printErr(ERR_UNABLE_TO_ADD_SPECIFIC_NAMESPACE, prefix, href);
            xmlFree(nsListDup);
            return(-1);
        }
    }

    xmlFree(nsListDup);
    return(0);
}

/**
* Extracts signing certificate from xmldsig and returns it as char*
*/
char *getCertPem(char *signature) {

    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;

    xmlDocPtr doc = xmlParseDoc(signature);
    xpathCtx = xmlXPathNewContext(doc);

    register_namespaces(xpathCtx, "ds=http://www.w3.org/2000/09/xmldsig#");

    xpathObj = xmlXPathEvalExpression("//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", xpathCtx);

    char *cert = getValuesFromXml(xpathObj->nodesetval);

    xpathObj = xmlXPathEvalExpression("//ds:Signature/ds:SignedInfo/ds:Reference/@URI", xpathCtx);
    char *signatureUri = getValuesFromXml(xpathObj->nodesetval);

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);

    char *certPrefix = "-----BEGIN CERTIFICATE-----\n";
    char *certSuffix = "\n-----END CERTIFICATE-----";
    char *pemCert = (char *) malloc(strlen(certPrefix) + strlen(certSuffix) + strlen(signature));
    strcpy(pemCert, certPrefix);
    strcat(pemCert, cert);
    strcat(pemCert, certSuffix);
    xmlFreeDoc(doc);

    return pemCert;

}

int checkRpmFileNameInSignature(char *signature, char *rpmFileName) {

    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;

    xmlDocPtr doc = xmlParseDoc(signature);
    xpathCtx = xmlXPathNewContext(doc);

    register_namespaces(xpathCtx, "ds=http://www.w3.org/2000/09/xmldsig#");
    xpathObj = xmlXPathEvalExpression("//ds:Signature/ds:SignedInfo/ds:Reference/@URI", xpathCtx);
    char *signatureUri = getValuesFromXml(xpathObj->nodesetval);

    char *rpmBasename = basename(rpmFileName);

    char *valueToCompare = concatStrings("file:/var/tmp/", rpmBasename);
    valueToCompare = concatStrings(valueToCompare, ".rpmpkisign");

    if (strcmp(valueToCompare, signatureUri) != 0) {
        printErr(ERR_FILE_NAME_CHANGED_SINCE_SIGNATURE, signatureUri, valueToCompare);
        return(1);
    }

    return(0);

}

/**
* Prints data from a certificate. The data is identified with the dataToPrint variable
* it could for example be CERT_SUBJECT, or CERT_ISSUER
*/
void printCertData(X509 *cert, int dataToPrint) {

    X509_NAME *x509Name = NULL;
    X509_NAME *x509IssuerName = NULL;
    BIO *outbio = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    switch (dataToPrint) {
        case CERT_SUBJECT :
            if ((x509Name = X509_get_subject_name(cert)) == NULL) {
                BIO_printf(outbio, ERR_CANNOT_GET_CERT_SUBJECT);
            }
            X509_NAME_print_ex(outbio, x509Name, 4, 0);
            BIO_printf(outbio, "\n");
            break;
        case CERT_ISSUER :
            if ((x509IssuerName = X509_get_issuer_name(cert)) == NULL) {
                BIO_printf(outbio, ERR_CANNOT_GET_CERT_ISSUER);
            }
            X509_NAME_print_ex(outbio, x509IssuerName, 4, 0);
            BIO_printf(outbio, "\n");
            break;
        default :
            BIO_printf(outbio, ERR_UNSUPPORTED_CERT_DATA_TO_PRINT);
            BIO_printf(outbio, "\n");
    }

    BIO_free_all(outbio);

}

/**
* Finds the certificate chain for a signing certificate (input has to be instantiated with the signing cert)
* in order to find the certificates it looks inside DEFAULT_TRUSTED_CERTS_DIR
* The way it works is that it compares signing cert issuer with subject from certs inside DEFAULT_TRUSTED_CERTS_DIR
* If the certificate found is not self signed (if its issuer is not equals its subject) then it recursively tries to
* find its issuer
* There is a limit to the number of certificates in the chain : MAX_CHAIN_LENGTH (which prevents infinite loops)
* When the method returns, the input contains the cert chain.
* struct certChainWithSize contains a boolean field 'chainComplete', if it is true then the chain contains all certificates
* If it is still false then something went wrong and the certificate chain is not complete.
* This method only finds PEM certificates in files with '.pem' extension.
*/
void populateCertChain(struct certChainWithSize *chainToBuild) {

    chainToBuild->chainComplete = false;
    X509 *currentCert = chainToBuild->certChain[chainToBuild->size - 1];
    X509_NAME *comparedSubject;
    // TODO : this produces a Segmentation fault if input cert is corrupted. It should be possible to validate the cert
    // before calling X509_get_issuer_name. Once this is done, a proper error message can be displayed, and the test
    // 04_009_verify_ko_signing_cert_corrupted can be implemented.
    X509_NAME *currentIssuer = X509_get_issuer_name(currentCert);

    struct dirent *entry = NULL;
    DIR *dp = NULL;

    char *dir = DEFAULT_TRUSTED_CERTS_DIR;

    dp = opendir(dir);
    if (dp != NULL) {
        // As soon as chain to build is complete the loop stops
        // Or if the chain length is too long the loop stops
        while (chainToBuild->chainComplete == false && chainToBuild->size < MAX_CHAIN_LENGTH && (entry = readdir(dp))) {

            if (regexMatch(entry->d_name, ".*\\.pem$") == 0) { // If file is .pem
                char *pathToCert = concatStrings(dir, entry -> d_name);
                X509 *comparedCert = openPemFile(pathToCert);
                free(pathToCert);
                comparedSubject = X509_get_subject_name(comparedCert);
                // If cert is the one which issued current cert, then it is its parent in the chain
                if (X509_NAME_cmp(currentIssuer, comparedSubject) == 0) {
                    chainToBuild->certChain[chainToBuild->size] = comparedCert;
                    chainToBuild->size++;
                    // if Cert subject and issuer are equals then it is self signed : root has been reached
                    if (X509_NAME_cmp(comparedSubject, X509_get_issuer_name(comparedCert)) == 0) {
                        closedir(dp);
                        chainToBuild->chainComplete = true;
                        return;
                    } else if (chainToBuild->size >= MAX_CHAIN_LENGTH) {
                        closedir(dp);
                        printErr(ERR_CERT_CHAIN_TOO_BIG, MAX_CHAIN_LENGTH);
                        return;
                    }
                    populateCertChain(chainToBuild);
                    closedir(dp);
                    return;
                }
                X509_free(comparedCert);
            }
        }
    }
    closedir(dp);

}

/**
* Concats 2 strings and returns the resulting string
*/
char *concatStrings(char *str1, char *str2) {

    int size = strlen(str1) + strlen(str2) + 1;
    char *result = (char *)malloc(size);

    strcpy(result, str1);
    strcat(result, str2);
    result[size - 1] = '\0';

    return result;

}

/**
* Opens a pem certificate file from its path and returns the certificate as a X509*
*/
X509 *openPemFile(char* filename) {
    X509* cert = X509_new();
    BIO* bio_cert = BIO_new_file(filename, "rb");
    PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
    BIO_free_all(bio_cert);

    return cert;
}

/**
* Compares a string to a regex, returns 0 in case of match, 1 else, except in case of error, in which case it returns -1
*/
int regexMatch(char *inputToTest, char *regexString) {

    int result;
    regex_t regex;
    int reti;
    char msgbuf[100];

    reti = regcomp(&regex, regexString, 0);
    if (reti) {
        printErr(ERR_CANNOT_COMPILE_REGEX);
        exit(1);
    }

    reti = regexec(&regex, inputToTest, 0, NULL, 0);
    if (!reti) { // MATCH!
        result = 0;
    }
    else if (reti == REG_NOMATCH) { // Doesn't match
        result = 1;
    }
    else { // Error
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        printErr(ERR_REGEX_MATCH_FAIL, msgbuf);
        result = -1;
    }

    regfree(&regex);
    return result;

}

/**
* Converts X509* to char* (pem format)
*/
char *fromX509ToString(X509 *cert) {

    BIO *b64 = BIO_new (BIO_s_mem());
    PEM_write_bio_X509(b64, cert);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    int length = bptr->length;

    char *buf = (char *)malloc(length + 1);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BIO_read(bio, buf, length);
    buf[length] = '\0';
    BIO_free_all(b64);
    BIO_free_all(bio);

    return buf;

}

/**
* Converts pem certificate to X509*
*/
X509 *fromStringToX509(char *cert) {
    BIO *bio;
    X509 *certificate;

    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, cert);
    certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
    return certificate;
}

void printErr(char *stringToPrint, ...) {

    va_list args;
    va_start(args, stringToPrint);
    
    char *messageWithPrefix = (char *)malloc(strlen(stringToPrint) + strlen(ERROR_PREFIX) + 1);
    strcpy(messageWithPrefix, ERROR_PREFIX);
    strcat(messageWithPrefix, stringToPrint);
    vfprintf(stderr, messageWithPrefix, args);
    free(messageWithPrefix);
    
    va_end(args);

}

