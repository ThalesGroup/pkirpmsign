# Get started

pkirpmsign provides two commands for signing and verifying an rpm file, using a key with an enrolled certificate.
The signature is XMLDSig. In order to do so, any previous GPG signature is removed from the rpm and replaced by the new signature.
The rpm format remains valid, it can be installed the usual way. To verify the signature, pkirpmverify command must be used.

This section describes a quick way to test rpm xmldsig using a fake Public Key Infrastructure (PKI). It requires openssl.
Following steps are not a valid way of signing your certificate, you need to make a real certificate signing request to a real PKI to give your signature any value.
For more details please refer to next sections.

1) First we need to create a fake Certificate Authority (CA). The CA is going to deliver our certificate for our signing key, this certificate is what will make other users of the PKI trust our signatures.
```
    openssl req -new -newkey rsa:2048 -days 1825 -nodes -x509 -subj "/C=FR/ST=IDF/O=myOrg/CN=myCn/OU=myUnit/emailAddress=example@test.com" -keyout caKey.pem -out caCert.pem
```
2) We now have the key (`caKey.pem`) and the certificate (`caCert.pem`) for our fake PKI. Let's generate a key and a Certificate Signing Request (CSR) for our user.
```
    openssl req -new -newkey rsa:2048 -nodes -subj "/C=FR/ST=IDF/O=test/CN=testcn" -keyout userKey.pem -out userCsr.pem
```
3) Now let's sign the CSR.
```
    openssl x509 -req -CA caCert.pem -CAkey caKey.pem -in userCsr.pem -out userCert.pem -days 3650 -CAcreateserial
```
4) Csr is not needed anymore, we can delete it. We also don't need the serial file
```
    rm userCsr.pem caCert.srl
```
5) We have everything, now we simply change the user key and certificate format to the one expected by the signing command (which is pkcs12, a format that allows a single file to contain both the key and the certificate, and to protect the key with a password).
```
    openssl pkcs12 -export -in userCert.pem -inkey userKey.pem -out keystore.p12 -password pass:password
```
6) Let's compile the code, using the following command at the root of
```
    make
```
7) And we can use the sign and verify command. For the example we need a rpm file to sign, you can use the provided stash/hello-2.10-1.fc35.x86_64.rpm
```
    ./pkirpmsign hello-2.10-1.fc35.x86_64.rpm keystore.p12
```
The keystore parameter value can be skipped. In such a case, the software uses /etc/pki/rpm-keys/keystore.p12.

8) You are prompted for the keystore.p12 password, which is `password` (we set it in step `5.`), after entering the password hit Enter :
```
    Please enter password for keystore (max 100 characters)
    Signature successful!
```
9) Now we are going to verify the signature
```
    ./pkirpmverify hello-2.10-1.fc35.x86_64.rpm caCert.pem
```
Which returns
```
    Signature is OK
    Signed by :
    C=FR, ST=IDF, O=test, CN=testcn
```
And voilà! You signed a rpm using your user key and certificate from a PKI, and you verified the signature.

Again, pkirpmverify uses a default value that provides a solution to avoid entering a certificate PEM file name. By default, it will search all certificates needed in /etc/pki/rpm-certs/.

# Tests

A test suite is provided with the project. It is powered by docker.

To start the suite, the image has to be built :

    docker build . -t test-signrpm

This commands creates an image tagged `test-signrpm`, but you may name it the way you want.
Then to run the suite, use the command :

    docker run --rm test-signrpm

Note : `--rm` destroys the container after it stops. There is no reason to keep the container after it ran. If you need to run the tests a second time you probably need to rebuild the image first anyway (but you can still run it again, an other container will be created, at least you won't have dozens of dead containers on your computer).

The test suite displays clearly which test are ok (`[OK] : test success <test_name>`), gives details when a test is KO, and warns when tests are skipped.

A report gives a quick look to what happened :
Test suite ended

    ==== Test report ====
    Elapsed time : 00m 02s - 746ms
    Total number of test declared : 30
    Tests successes : 28    Tests failures : 0    Tests skipped : 2
    Success : 93%    Failure : 0%    Skipped : 6%

There are a couple of tests which are tagged 'TOREPAIR' (see `tests/TOREPAIR_04_009_verify_ko_signing_cert_corrupted` and `tests/TOREPAIR_04_015_verify_ko_custom_pem_cert_only_partial_chain`).
These require a modification of the code.

# Build pkirpmsign as a rpm

A spec file is provided to build an rpm from this project.

If you already have a packaging environment :
- make pkirpmsign.tar.gz in the delivery directory and copy it into your `SOURCES/` directory.
- copy `pkirpmsign.spec` into your `SPECS/` directory.

Then, in your `SPECS/` directory, run :
```
    rpmbuild -ba pkirpmsign.spec
```
The created rpm should then be in your `RPMS/` directory.

If you have no packaging environment, the Makefile will create everything for you. Just run make, then :
```
    make rpm
    cd SPECS
    rpmbuild -ba --define '_topdir <delivery directory>' pkirpmsign.spec
```

Note that you need following packages : xmlsec1-devel xmlsec1-openssl-devel libxml2-devel make

# Contributing

If you are interested in contributing to the pkirpmsign project, start by reading the [Contributing guide](/CONTRIBUTING.md).
