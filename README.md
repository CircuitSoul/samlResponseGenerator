SAML Response Generator
=============================================

This is a small utility program that makes it easy to generate SAML responses for testing.

Creating Private and Public Keys for Testing
--------------------------------------------

You will need to generate a private and public key to use for generating saml assertions. The following steps are used for creating the keys:
```
#create the keypair
openssl req -new -x509 -days 3652 -nodes -out saml.crt -keyout saml.pem

#convert the private key to pkcs8 format
openssl pkcs8 -topk8 -inform PEM -outform DER -in saml.pem -out saml.pkcs8 -nocrypt
```

Compiling the jar file
--------------------------------------------
```
$ git clone https://github.com/FroydCod3r/samlResponseGenerator.git
$ cd samlResponseGenerator
$ mvn package
```

Usage
--------------------------------------------
```
java -jar saml-generator-1.0.jar [-domain <arg>] [-issuer <arg>] [-privateKey <arg>] [-publicKey <arg>] [-roles <arg>] [-email <arg>] [-samlAssertionExpirationDays <arg>] [-subject <arg>]
```

```
-issuer
The URI of the issuer for the saml assertion.

-subject
The username of the federated user.

-domain
The domain ID for the federated user.

-roles
A comma separated list of role names for the federated user.

-email
The email address of the federated user.

-publicKey
THe path to the location of the public key to decrypt assertions

-privateKey
The path to the location of the private key to use to sign assertions

-samlAssertionExpirationDays
How long before the assertion is no longer valid
```

Example
--------------------------------------------
```
java -jar saml-generator-1.0.jar -domain 7719 -issuer 'http://company.com' -privateKey saml.pkcs8 -publicKey saml.crt -roles 'role1' -samlAssertionExpirationDays 5 -subject samlUser1
```

Output:
```
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="e1af8c40-8b45-4f25-a8c5-fd99df001c0e" IssueInstant="2014-06-17T20:47:33.381Z" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://test.rackspace.com</saml2:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#e1af8c40-8b45-4f25-a8c5-fd99df001c0e">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
          </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>fufQ5g8YHPZVT4tX6Xx4LfYO588=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>LlYniaVX8EXAZDvKP396IDpDm31mJf3T8HKh4NroTSPWqEjmcN2Wj32QBjSCpzXtE7bhVoRIQQRDRWzAbMjR0gjuy6NK0z1vBQDi4iwuRM6Y+sgsDAqB9wT4h4yi6J7cjnUdNi83VRVYF3F7zVjCq//mDQVkyp+rkhC0Lkxe2kM=</ds:SignatureValue>
  </ds:Signature>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="4ee2be6a-8075-40a2-ba89-cf0991880af2" IssueInstant="2014-06-17T20:47:33.379Z" Version="2.0">
    <saml2:Issuer>http://some.compnay.com</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">samlUser</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="2014-06-22T20:47:33.373Z"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:AuthnStatement AuthnInstant="2014-06-17T20:47:31.963Z">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="roles">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">role1</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="domain">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">14309</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
```
Install Maven on Kali Linux
--------------------------------------------

Download Binary Apache Maven on: https://maven.apache.org/download.cgi

Unzip on folder like /opt/apache-maven-3.X.X

The path of mvn binary like this: 
/opt/apache-maven-3.X.X/bin/mvn

Now, create a symbolic link for /usr/local/bin folder:
```
$ sudo ln -s /opt/apache-maven-3.8.1/bin/mvn /usr/local/bin
```

check the version:
```
$ mvn -version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Apache Maven 3.8.1 (05c21c65bdfed0f71a2f2ada8b84da59348c4c5d)
Maven home: /opt/apache-maven-3.8.1
Java version: 11.0.11-ea, vendor: Debian, runtime: /usr/lib/jvm/java-11-openjdk-amd64
Default locale: en_US, platform encoding: UTF-8
OS name: "linux", version: "5.10.0-kali7-amd64", arch: "amd64", family: "unix"
```

Commum build errors
--------------------------------------------
```
Error:
[ERROR] error: Source option 5 is no longer supported. Use 6 or later.
[ERROR] error: Target option 1.5 is no longer supported. Use 1.6 or later.

Fix:
Install Java Extension Pack of Visual Studio Code
```

![image](https://user-images.githubusercontent.com/9803476/120085958-944d4f80-c0aa-11eb-8ce0-f47266fa3aed.png)
