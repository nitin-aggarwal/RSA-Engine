/****

Name: Nitin Aggarwal
Student Id: 108266663

Description: RSA Engine with X509 certificates , compatible with Openssl.
Dependencies: GMP and Crypto++ libraries.
****/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <gmpxx.h>
#include <stdint.h>
#include <sys/time.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <cryptopp/sha.h>

using namespace std;

// For Debugging Purposes
bool DEBUG = false;

/***********************************************/
/********* Base64 Conversions ******************/
/***********************************************/
const string b64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

// Decode 4 '6-bit' characters into 3 '8-bit' characters
void base64_Octet( unsigned char *in, vector<char>& octets )
{   
	char c;
	c = (unsigned char ) (in[0] << 2 | in[1] >> 4);
	octets.push_back(c);
	c = (unsigned char ) (in[1] << 4 | in[2] >> 2);
   	octets.push_back(c);
	c = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
	octets.push_back(c);
}

// Encode 3 '8-bit' characters into 4 '6-bit' Base64 characters
void octet_Base64( unsigned char *in, vector<char>& base , int length)
{   
	char c;
	char eq = (unsigned char)(64);
	c = (unsigned char ) ((in[0] >> 2) & 0x3F);
	base.push_back(c);
	c = (unsigned char ) ((in[0] << 4 | in[1] >> 4) & 0x3F);
   	base.push_back(c);
	c = (unsigned char ) ((in[1] << 2 | in[2] >> 6) & 0x3F);
	if(length == 1)
		base.push_back(eq);
	else
   		base.push_back(c);
	c = (unsigned char ) (in[2] & 0x3F);
	if(length != 3)
		base.push_back(eq);
	else	
		base.push_back(c);
}

// Hex-Character to Hex-ASCII
// i.e. 0-9,a-z to char with ASCII value 0-15
char ascii_Hex(char c)
{
	int value;
	stringstream temp;
	temp << hex << c;
	temp >> value;
	unsigned char ch = value;
	return ch;
}

// Construct a vector of octets (i.e. DER) from a PEM file
void pem_Octets(FILE * file, vector<char>& octets)
{
	bool endFlag = false;
	int extrasCount = 0;
	unsigned char c;

	// Skip First line i.e. header of the PEM file
	while( (c = (char)fgetc(file)) != '\n');

	while(!feof(file) && !endFlag)
	{
		unsigned char in[4];
		for(int i = 0; i < 4; i++)
		{
			c = (unsigned char)fgetc(file);

			// Check for footer in PEM file
			if(c == '-')
				endFlag = true;

			// Check for new line
			if(c == '\n'){
				i--;
				continue;
			}
			else if(c == '/')
				in[i] = 63;
			else if(c == '+')
				in[i] = 62;
			else if(c == '=')	{
				in[i] = 0;
				extrasCount++;
			}
			else
				in[i] = b64.find_first_of(c);
		}
		if(!endFlag)
			base64_Octet(in, octets);
		else	{
			//Remove extra octets pushed in vector
			while(extrasCount-- > 0)
				octets.erase(octets.begin() + octets.size() - 1);
		}
	}
	cout << "\n";
}

// Construct PEM file from vector of octets
void octets_PEM(vector<char> octets, string text, string filename)
{
	vector<char> base;
	// Connvert Octets to Base64 characters
	vector<char>::iterator itr;
	unsigned char in[3];
	int i = 0;
	for(itr = octets.begin(); itr < octets.end(); itr++)
	{
		in[i] = *itr;
		if(i%3 == 2)
		{
			octet_Base64(in, base, 3);
			i = -1;
		}
		i++;
	}
	// If Incomplete Octet Triple
	if(i > 0)
	{
		if(i == 1)
			in[1] = 0;
		if(i >= 1)
			in[2] = 0;
		octet_Base64(in, base, i);
	}
	
	ofstream outfile;
	outfile.open(filename.c_str());

	if(!outfile)	{
		outfile.copyfmt(std::cout); 
		outfile.clear(std::cout.rdstate());
		outfile.basic_ios<char>::rdbuf(std::cout.rdbuf());   
	}
	if(!text.empty())
		outfile << "-----BEGIN " << text.c_str() << "-----\n";
	int count  = 0;
	for(itr = base.begin(); itr < base.end(); itr++)
	{
		outfile << b64[*itr];
		if(count%64 == 63)
			outfile << "\n";
		count++;
		
	}
	if(count%64 != 0)
		outfile << "\n";
	if(!text.empty())
		outfile << "-----END " << text.c_str() << "-----\n";
	outfile.close();
}

// Generate pseudo-random non-zero octets
char getRandomOctet()
{   
	int bits = 8; 
	char *random = (char *)malloc(bits * sizeof(char)); 
	
	// making sure they are big numbers
	for(int i = 0 ; i < bits ; i++ ){
		*(random + i) = (int)((unsigned int)(2*rand())/RAND_MAX) + 48 ;
	}
	*(random + bits) = '\0';
	char c = strtol(random, NULL, 2);
	if(c == 0)
		return getRandomOctet();
	return c;
}

/***********************************************/
/************ Data Structures ******************/
/***********************************************/

// Wrapper around mpz_class, to store length also
typedef struct mpzWrapper
{
	int length;		// Length In Octets
	mpz_class mpz;
}mpzWrapper;

// Structure for name information for X509 Certificate
typedef struct nameAttribute
{
	int typeLength;
	string type;
	int valueLength;
	string value;
}attribute;

// PKCS#1 for RSAPrivateKey
typedef struct RSAPrivateKey
{
	mpzWrapper version;
	mpzWrapper modulus;
	mpzWrapper publicExponent;
	mpzWrapper privateExponent;
	mpzWrapper prime1;
	mpzWrapper prime2;
	mpzWrapper exponent1;
	mpzWrapper exponent2;
	mpzWrapper coefficient;
	bool status;
}RSAPrivateKey;

// PKCS#8 for RSAPublicKey
typedef struct RSAPublicKey
{
	mpzWrapper algorithm;
	mpzWrapper params;
	mpzWrapper modulus;
	mpzWrapper exponent;
	bool status;
}RSAPublicKey;

// X.509 V3 Certificate
typedef struct Certificate
{
	mpzWrapper version;
	mpzWrapper serialNo;
	mpzWrapper tbsSignatureAlgo;
	mpzWrapper tbsSignatureParams;
	vector<attribute> issuer;
	mpzWrapper validityBefore;
	mpzWrapper validityAfter; 
	vector<attribute> subject;
	mpzWrapper subjectKeyAlgo;
	mpzWrapper subjectKeyParams;
	mpzWrapper modulus;
	mpzWrapper exponent;
	vector<attribute> extension;
	mpzWrapper signatureAlgo;
	mpzWrapper signatureParams;
	mpzWrapper signature;
	bool status;
}Certificate;

// PKCS#8 for X509 RSAPrivateKey
typedef struct X509RSAPrivateKey
{
	mpzWrapper version;
	mpzWrapper algorithm;
	mpzWrapper params;
	RSAPrivateKey rsaKey;
	bool status;
}X509RSAPrivateKey;

/***********************************************/
/********* Print Console Operations ************/
/***********************************************/

// Print Octets to console for a string of hexadecimal format
// length is in no. of octets
void printOctet(string mpz, int length, string text)
{
	cout << "\n" << text << ":\n" << "    ";
	int len = mpz.size();
	string data;
	int extra = length*2 - len;
	while(extra-- > 0)
		data.append("0");
	data.append(mpz);
	len = data.size();
	for(int index = 0; index < len; index++)
	{
		cout << data[index];
		if( (index < len-1) && (index%2 == 1) && (index > 0) )
			cout << ":";
		if( (index%30 == 29) && (index > 1) )
			cout << "\n" << "    ";
	}
}

// Wrapper for Print Octet form of big number to console
void printOctet(mpzWrapper mpz, string text)
{
	mpz_class num = mpz.mpz;
	string s = num.get_str(16);
	printOctet(s, mpz.length, text);
}

string getCharacter(string hex)
{
	string data;
	for(int i = 0; i < hex.length(); i=i+2)
	{
		unsigned char c;
		c = (int)(((ascii_Hex(hex[i]) << 4) & 0xF0) | (ascii_Hex(hex[i+1]) & 0x0F));
		data.append(1,c);
	}
	return data;
}

string getOID(string oid)
{
	if(oid == "550406")
		return "C";
	else if(oid == "550408")
		return "ST";
	else if(oid == "550407")
		return "L";
	else if(oid == "55040a")
		return "O";
	else if(oid == "55040b")
		return "OU";
	else if(oid == "550403")
		return "CN";
	else if(oid == "2a864886f70d010901")
		return "email";
	else
		return "";
}

// Print Octet form of big number to console
void printVectorContent(vector<attribute> data, string text, char seperator1, char seperator2 )
{
	cout << "\n" << text << ":  ";
	vector<attribute>::iterator itr;

	for(itr = data.begin(); itr < data.end(); itr++)
	{
		attribute temp = *itr;
		cout << getOID(temp.type);
		cout << seperator1;
		cout << getCharacter(temp.value);
		cout << seperator2;
	}
}
// Print RSA Private Keys
void printRSAPrivateKeys(RSAPrivateKey rsa, bool flag = true)
{
	if(!rsa.status)
		return;
	if(flag)
		cout << "\n*********** RSA Private Key: ******************\n";
	printOctet(rsa.version,"version");
	printOctet(rsa.modulus,"modulus");
	printOctet(rsa.publicExponent,"publicExponent");
	printOctet(rsa.privateExponent,"privateExponent");
	printOctet(rsa.prime1,"prime1");
	printOctet(rsa.prime2,"prime2");
	printOctet(rsa.exponent1,"exponent1");
	printOctet(rsa.exponent2,"exponent2");
	printOctet(rsa.coefficient,"coefficient");
	cout << "\n";
}

// Print RSA Public Keys
void printRSAPublicKeys(RSAPublicKey rsa)
{
	if(!rsa.status)
		return;
	
	cout << "\n************ RSA Public Key: ****************\n";
	printOctet(rsa.algorithm,"algorithm");
	printOctet(rsa.modulus,"modulus");
	printOctet(rsa.exponent,"exponent");
	cout << "\n";
}

// Print X509 Certificate
void printCertificate(Certificate certi)
{
	if(!certi.status)
		return;
	
	cout << "\n************ X509 Certificate: ***************\n";
	printOctet(certi.version, "version");
	printOctet(certi.serialNo, "serialNo");
	printOctet(certi.tbsSignatureAlgo,"Signature Algorithm");
	printVectorContent(certi.issuer,"Issuer",'=', ',');
	printOctet(certi.validityBefore,"Not Before");
	printOctet(certi.validityAfter,"Not After");
	printVectorContent(certi.subject,"Subject",'=',',');
	printOctet(certi.subjectKeyAlgo,"subject algo");
	printOctet(certi.subjectKeyParams,"params");
	printOctet(certi.modulus,"modulus");
	printOctet(certi.exponent,"exponent");
	//printVectorContent(certi.extension,"extension",':', '\n');
	printOctet(certi.signatureAlgo,"Signature Algorithm");
	printOctet(certi.signature,"Signature");
	cout << "\n";
}

// Print X509 Certificate Private Key
void printCertificatePrivateKey(X509RSAPrivateKey x509Key)
{
	if(!x509Key.status)
		return;
	
	cout << "\n************ X509 Certificate Private Key: ***************\n";
	printOctet(x509Key.version,"version");
	printOctet(x509Key.algorithm,"algorithm");
	printRSAPrivateKeys(x509Key.rsaKey, false);	
}
	
/***********************************************/
/******* Parsing PEM Format Key Files **********/
/***********************************************/

// Compute Length from Length Identifier
int getLength(vector<char>::iterator& itr)
{
	unsigned char c = *itr;
	unsigned int length = 0;
	int lengthForm = (c >> 7) & 0x01;
	
	if(lengthForm == 0)
		length = c & 0x7F;
	else
	{
		int lengthOctets = c & 0x7F;
		for(int k = 0; k < lengthOctets; ++k)
		{
			c = *(++itr);
			length = length*256 + (int)c;
		}
	}
	itr++;
	if(DEBUG)
		cout << "Length: " << length << endl;
	return length;
}

// Construct content string from content octets
string getContent(int length, vector<char>::iterator& itr)
{
	string content;
	unsigned char c;
	for(int k= 0; k < length; k++)
	{
		c = (unsigned char)(*itr);
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		content.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		content.append(1,temp2);
		itr++;
	}
	if(DEBUG)
		cout << "Content: " << content << endl;
	return content;
}

// Extract ASN tag name and type
void getASNIdentifier(int& tagType, int& tagNum, vector<char>::iterator& itr)
{
	unsigned char c = *itr;		
	tagType = (c >> 5) & 0x01;
	tagNum = c & 0x1F;	
	if(DEBUG)
	{
		cout << "Tag type: " << tagType << endl;
		cout << "Tag number: " << tagNum << endl;
	}
	itr++;
}

// Construct primitive type ASN object
int initializePrimitive(vector<char>::iterator& itr, mpzWrapper& object, bool lengthFlag = true, bool typeCheck = true)
{
	int length, tagType, tagNum;
	string content;

	if(typeCheck)	{
		getASNIdentifier(tagType, tagNum, itr);
		if(tagType != 0)
			{cout << "Here2";
		return 0;}
	}
	length = getLength(itr);
	content = getContent(length, itr);

	if(lengthFlag)
		object.length = ((length % 2) == 0)?length:(length-1);
	else
		object.length = length;
	object.mpz.set_str(content,16);
	return 1;
}

// Construct sequence type ASN object
int processStructured(vector<char>::iterator& itr, int expectedTagNum, bool ignoreTagType = false, bool checkType = true)
{
	int length, tagType, tagNum;
	string content;

	if(checkType)
	{
		getASNIdentifier(tagType, tagNum, itr);
		if(!ignoreTagType && tagType != 1)
		{cout << "Here3";
		return 0;}
		if(tagNum != expectedTagNum)
		{cout << "Here4";
		return 0;}
	}
	length = getLength(itr);
	return 1;
}

// Construct RSAPrivateKey structure from vector of octets
RSAPrivateKey octets_RSAPrivateKey(vector<char> octets)
{
	RSAPrivateKey privateKey;
	int validPEM = 1;
	vector<char>::iterator itr = octets.begin();
	
	// Read Octets to construct RSAPrivateKey Structure
	while(itr < octets.end())
	{
		validPEM *= processStructured(itr,16);
		
		// Check if tag type is structured sequence
		validPEM *= initializePrimitive(itr, privateKey.version, false);
		validPEM *= initializePrimitive(itr, privateKey.modulus);
		validPEM *= initializePrimitive(itr, privateKey.publicExponent, false);
		validPEM *= initializePrimitive(itr, privateKey.privateExponent);
		validPEM *= initializePrimitive(itr, privateKey.prime1);
		validPEM *= initializePrimitive(itr, privateKey.prime2);
		validPEM *= initializePrimitive(itr, privateKey.exponent1);
		validPEM *= initializePrimitive(itr, privateKey.exponent2);
		validPEM *= initializePrimitive(itr, privateKey.coefficient);
	}
	if(validPEM == 0)	{
		cout << "Incompatible Format for RSA Private Key" << endl;
		privateKey.status = false;
	}
	else
		privateKey.status = true;
	return privateKey;
}

// Construct RSAPrivateKey structure from PEM file
RSAPrivateKey pem_RSAPrivateKey(FILE *file)
{
	vector<char> octets;

	// Transform PEM content in char(8-bit) vector	
	pem_Octets(file, octets);

	// Read Octets to construct RSAPrivateKey Structure
	return octets_RSAPrivateKey(octets);
}


// Construct RSAPublicKey structure from PEM file
RSAPublicKey pem_RSAPublicKey(FILE *file)
{
	RSAPublicKey publicKey;
	int validPEM = 1;
	vector<char> octets;

	// Transform PEM content in char(8-bit) vector	
	pem_Octets(file, octets);

	vector<char>::iterator itr = octets.begin();
	
	// Read Octets to construct RSAPublicKey Structure
	while(itr < octets.end())
	{
		//Main Sequence
		validPEM *= processStructured(itr, 16);
		
		//AlgorithmIdentifier Sequence
		validPEM *= processStructured(itr, 16);
		validPEM *= initializePrimitive(itr, publicKey.algorithm, false);
		validPEM *= initializePrimitive(itr, publicKey.params, false);
		
		//Bit String
		validPEM *= processStructured(itr, 3, true, true);
		itr++;		// Ignore Unused Byte Count as zero
		validPEM *= processStructured(itr, 16);
		validPEM *= initializePrimitive(itr, publicKey.modulus);
		validPEM *= initializePrimitive(itr, publicKey.exponent);
	}
	if(validPEM == 0)	{
		cout << "Incompatible Format for RSA Public Key" << endl;
		publicKey.status = false;
	}
	else
		publicKey.status = true;
	return publicKey;
}

// Construct X509RSAPrivateKey structure from PEM file
X509RSAPrivateKey pem_X509RSAPrivateKey(FILE *file)
{
	X509RSAPrivateKey privateKey;
	int validPEM = 1;
	vector<char> octets;
	vector<char> rsaOctets;
	
	// Transform PEM content in char(8-bit) vector	
	pem_Octets(file, octets);

	vector<char>::iterator itr = octets.begin();
	
	// Read Octets to construct X509 RSAPrivateKey Structure
	while(itr < octets.end())
	{
		//Main Sequence
		validPEM *= processStructured(itr, 16);
		
		validPEM *= initializePrimitive(itr, privateKey.version, false);
		//AlgorithmIdentifier Sequence
		validPEM *= processStructured(itr, 16);
		validPEM *= initializePrimitive(itr, privateKey.algorithm, false);
		validPEM *= initializePrimitive(itr, privateKey.params, false);
		
		//Bit String
		processStructured(itr, 4, true, true);
		while(itr < octets.end())
		{
			rsaOctets.push_back(*itr);
			itr++;					
		}				
		privateKey.rsaKey = octets_RSAPrivateKey(rsaOctets);
	}
	if(validPEM == 0)	{
		cout << "Incompatible Format for X509 RSA Private Key" << endl;
		privateKey.status = false;
	}
	else
		privateKey.status = true;
	return privateKey;
}

// Construct X509 Certificate structure from PEM file
Certificate pem_Certificate(FILE *file)
{
	Certificate certi;
	int validPEM = 1;
	vector<char> octets;
	vector<char> rsaOctets;
	int tagType, tagNum, length;
	mpzWrapper type, value;

	// Transform PEM content in char(8-bit) vector	
	pem_Octets(file, octets);

	vector<char>::iterator itr = octets.begin();
	
	//Set Default value of version
	certi.version.length = 1;
	certi.version.mpz = "01";
	// Read Octets to construct X509 RSAPrivateKey Structure
	while(itr < octets.end())
	{
		//Main Sequence
		validPEM *= processStructured(itr, 16);
		
		//1. tbsAlgorithm Sequence
		validPEM *= processStructured(itr, 16);
		//validPEM *= processStructured(itr, 0);
		
		//validPEM *= initializePrimitive(itr, certi.version, false);
		validPEM *= initializePrimitive(itr, certi.serialNo, false);
		//AlgorithmIdentifier Sequence
		validPEM *= processStructured(itr, 16);
		validPEM *= initializePrimitive(itr, certi.tbsSignatureAlgo, false);
		validPEM *= initializePrimitive(itr, certi.tbsSignatureParams, false);
		//IssuerSequence
		validPEM *= processStructured(itr, 16);
		do
		{
			getASNIdentifier(tagType, tagNum, itr);
			if(tagNum == 17)
			{
				validPEM *= processStructured(itr, 17, false, false);
				validPEM *= processStructured(itr, 16);
				validPEM *= initializePrimitive(itr, type, false);
				validPEM *= initializePrimitive(itr, value, false);
				attribute attr;
				attr.typeLength = type.length;
				attr.type = type.mpz.get_str(16);
				attr.valueLength = value.length;
				attr.value = value.mpz.get_str(16);
				certi.issuer.push_back(attr);
			}
			
		}while(tagNum == 17);
		//Validity Dates
		validPEM *= processStructured(itr, 16, false, false);
		validPEM *= initializePrimitive(itr, certi.validityBefore, false);
		validPEM *= initializePrimitive(itr, certi.validityAfter, false);
		//SubjectSequence
		validPEM *= processStructured(itr, 16);
		do
		{
			getASNIdentifier(tagType, tagNum, itr);
			if(tagNum == 17)
			{
				validPEM *= processStructured(itr, 17, false, false);
				validPEM *= processStructured(itr, 16);
				validPEM *= initializePrimitive(itr, type, false);
				validPEM *= initializePrimitive(itr, value, false);
				attribute attr;
				attr.typeLength = type.length;
				attr.type = type.mpz.get_str(16);
				attr.valueLength = value.length;
				attr.value = value.mpz.get_str(16);
				certi.subject.push_back(attr);
			}
			
		}while(tagNum == 17);
		
		//SubjectPublicKey 
		validPEM *= processStructured(itr, 16,false, false);
		validPEM *= processStructured(itr, 16);
		validPEM *= initializePrimitive(itr, certi.subjectKeyAlgo, false);
		validPEM *= initializePrimitive(itr, certi.subjectKeyParams, false);
		validPEM *= processStructured(itr, 3, true, true);
		itr++;		// Ignore Unused Byte Count as zero
		validPEM *= processStructured(itr, 16);
		validPEM *= initializePrimitive(itr, certi.modulus);
		validPEM *= initializePrimitive(itr, certi.exponent, false);
		
		//Extensions
		/*validPEM *= processStructured(itr, 3);
		getASNIdentifier(tagType, tagNum, itr);
		length = getLength(itr);
		do
		{
			getASNIdentifier(tagType, tagNum, itr);
			if(tagNum == 16)
			{
				validPEM *= processStructured(itr, 16, false, false);
				//validPEM *= processStructured(itr, 4);
				validPEM *= initializePrimitive(itr, type, false);
				validPEM *= initializePrimitive(itr, value, false);
				attribute attr;
				attr.typeLength = type.length;
				attr.type = type.mpz.get_str(16);
				attr.valueLength = value.length;
				attr.value = value.mpz.get_str(16);
				certi.extension.push_back(attr);
				length -= (2 + type.length + value.length + 4); 
			}
			
		}while(length > 0);
		*/
		// 2. Signature Algorithm
		validPEM *= processStructured(itr, 16);
		validPEM *= initializePrimitive(itr, certi.signatureAlgo, false);
		validPEM *= initializePrimitive(itr, certi.signatureParams, false);
		
		// 3. Signature
		validPEM *= initializePrimitive(itr, certi.signature);
	}
	if(validPEM == 0)	{
		cout << "Incompatible Format for X509 Certifcate" << endl;
		certi.status = false;
	}
	else
		certi.status = true;
	return certi;
}

/***********************************************/
/************ Generate RSA Keys  ***************/
/***********************************************/

// Generate random numbers using C++ GMP Library
mpz_class generateRandom(int bits)
{
	mpz_class ran;
	gmp_randclass rr(gmp_randinit_default);
	rr.seed(time(NULL) + rand());
	ran =rr.get_z_bits(bits);
	long int random=ran.get_ui();
	return ran;
}

// Generate set of RSA Keys - openssl genrsa
RSAPrivateKey generateRSAKeys(int rsa_bits)
{
	RSAPrivateKey privateKey;
	privateKey.status = true;

	// Set the structure version
	privateKey.version.length = 1;
	privateKey.version.mpz = "00";	

	mpz_class random1, random2;
	mpz_class p, q, n, d, e, coeff;

	int key_bits = rsa_bits / 2;
	p = generateRandom(key_bits); 
	q = generateRandom(key_bits); 

	mpz_class temp;

	if(p < q)
	{
		temp = p;
		p = q;
		q = temp;
	}		

	// A. CALCULATE PRIMES	
	mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
	mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
	
	// Set the structure primes
	int lenOctets = (mpz_sizeinbase(p.get_mpz_t(), 16)+1)/2;
	privateKey.prime1.length = (lenOctets < (key_bits/8))?(key_bits/8):lenOctets;
	privateKey.prime1.mpz = p;
	lenOctets = (mpz_sizeinbase(q.get_mpz_t(), 16)+1)/2;
	privateKey.prime2.length = (lenOctets < (key_bits/8))?(key_bits/8):lenOctets;
	privateKey.prime2.mpz = q;
	
	// B. CALCULATE MODULUS n, p * q
	n = p * q;
	
	// Set the structure modulus
	lenOctets = (mpz_sizeinbase(n.get_mpz_t(), 16)+1)/2;
	privateKey.modulus.length = (lenOctets < (rsa_bits/8))?(rsa_bits/8):lenOctets;
	privateKey.modulus.mpz = n;
	
	// C. CALCULATE EXPONENTS (both pulic and private)
	mpz_class x, p_minus_1,q_minus_1, gcd;
	
	p_minus_1 = p - 1;
	q_minus_1 = q - 1;
	x = p_minus_1 * q_minus_1;

	//Choose an integer e such that 1 < e < x and greatest common divisor of (e, x) = 1
	unsigned long int e_start = 65537;
	while(1)
	{
		mpz_gcd_ui(gcd.get_mpz_t(),x.get_mpz_t(),e_start);

		if(mpz_cmp_ui(gcd.get_mpz_t(),(unsigned long int)1)==0)
	    		break;

		/* try the next odd integer... */
		e_start += 2;
	}
	e = e_start;

	//Compute unique d such that ed = 1(mod x)
	if(mpz_invert(d.get_mpz_t(),e.get_mpz_t(),x.get_mpz_t())==0)
	{
		cout << "Could not find Inverse! Computing d again...";
		generateRSAKeys(rsa_bits);
	}
	
	// Set the structure exponents	
	privateKey.publicExponent.length = (mpz_sizeinbase(e.get_mpz_t(), 16)+1)/2;
	privateKey.publicExponent.mpz = e;
	lenOctets = (mpz_sizeinbase(d.get_mpz_t(), 16)+1)/2;
	privateKey.privateExponent.length = (lenOctets < (rsa_bits/8))?(rsa_bits/8):lenOctets;
	privateKey.privateExponent.mpz = d;
	
	privateKey.exponent1.length = key_bits/8;
	privateKey.exponent1.mpz = d % (p - 1);
	privateKey.exponent2.length = key_bits/8;
	privateKey.exponent2.mpz = d % (q - 1);
	
	// D. Compute Coefficient
	if(mpz_invert(coeff.get_mpz_t(),q.get_mpz_t(), p.get_mpz_t()) == 0)
	{
		cout << "B. Could not find Inverse! Computing coeff again...";
		generateRSAKeys(rsa_bits);
	}

	// Set the structure coefficient
	lenOctets = (mpz_sizeinbase(coeff.get_mpz_t(), 16)+1)/2;
	privateKey.coefficient.length = (lenOctets < (key_bits/8))?(key_bits/8):lenOctets;
	privateKey.coefficient.mpz = coeff;
	
	return privateKey;
}

// Generate RSA public key from RSA private Key
RSAPublicKey privateKey_PublicKey(RSAPrivateKey privateKey)
{
	RSAPublicKey publicKey;
	publicKey.modulus = privateKey.modulus;
	publicKey.exponent = privateKey.publicExponent;
	
	publicKey.params.length = 0;
	publicKey.params.mpz = 0;

	// Construct Algorithm structure
	// (1 2 840 113549 1 1 1)
	publicKey.algorithm.length = 9;
	publicKey.algorithm.mpz.set_str("2a864886f70d010101",16);
	return publicKey;
}

// Generate X509 Certificate RSA private key from RSA private Key
X509RSAPrivateKey rsaAPrivateKey_X509PrivateKey(RSAPrivateKey privateKey)
{
	X509RSAPrivateKey x509PrivateKey;

	// Construct Version ASN	
	x509PrivateKey.version.length = 0;
	x509PrivateKey.version.mpz = 0;

	// Construct Algorithm ASN
	// (1 2 840 113549 1 1 1)
	x509PrivateKey.algorithm.length = 9;
	x509PrivateKey.algorithm.mpz.set_str("2a864886f70d010101",16);
	x509PrivateKey.params.length = 0;
	x509PrivateKey.params.mpz = 0;
	
	x509PrivateKey.rsaKey = privateKey;
	return x509PrivateKey;
}

// Generate X509 Certificate from RSA private Key
Certificate rsaPrivateKey_Certificate(RSAPrivateKey privateKey)
{
	Certificate certi;

	certi.version.length = 1;
	certi.version.mpz.set_str("01",16);

	// Should be randomly generated postive unique number
	string serial;
	for(int i=0; i < 9; i++)
	{
		char c = getRandomOctet();
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		serial.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		serial.append(1,temp2);
	}
	certi.serialNo.length = 9;
	certi.serialNo.mpz.set_str(serial,16);

	// Algo - sha1 with rsa encryption 	
	certi.tbsSignatureAlgo.length = 9;
	certi.tbsSignatureAlgo.mpz.set_str("2a864886f70d010105",16);
	certi.tbsSignatureParams.length = 0;
	certi.tbsSignatureParams.mpz = 0;
	
	// Set just the country for issuer and subject
	attribute attr;
	attr.typeLength = 3;
	attr.type = "550406";
	attr.valueLength = 2;
	attr.value = "5553";

	certi.issuer.push_back(attr);
	certi.subject.push_back(attr);

	// Validity Dates
	certi.validityBefore.length = 13;
	certi.validityAfter.length = 13; 
	string currentTime, afterTime;

	
	time_t t = time(0);
	struct tm * now = localtime( & t );
	string MM, DD, hh, mm, ss , Z;
	int YY;
	int year = now->tm_year;
	if(year >= 50 && year <=99)
		YY = year;
	else if(year > 100)
		YY = year - 100;
	else
		YY = year;
	
	stringstream stream, stream2;
	stream << hex << YY/10 + '0';
	stream << hex << YY%10 + '0';
	stream << hex << (now->tm_mon + 1)/10 + '0';
	stream << hex << (now->tm_mon + 1)%10 + '0';
	stream << now->tm_mday/10 + '0';
	stream << now->tm_mday%10 + '0';
	stream << now->tm_hour/10 + '0';
	stream << now->tm_hour%10 + '0';
	stream << now->tm_min/10 + '0';
	stream << now->tm_min%10 + '0';
	stream << now->tm_sec/10 + '0';
	stream << now->tm_sec%10 + '0';
	currentTime = stream.str();
	Z = "5a";
	currentTime = currentTime.append(Z);
	
	// 1 year validity
	YY++;
	stream2 << hex << YY/10 + '0';
	stream2 << hex << YY%10 + '0';
	stream2 << hex << (now->tm_mon + 1)/10 + '0';
	stream2 << hex << (now->tm_mon + 1)%10 + '0';
	stream2 << now->tm_mday/10 + '0';
	stream2 << now->tm_mday%10 + '0';
	stream2 << now->tm_hour/10 + '0';
	stream2 << now->tm_hour%10 + '0';
	stream2 << now->tm_min/10 + '0';
	stream2 << now->tm_min%10 + '0';
	stream2 << now->tm_sec/10 + '0';
	stream2 << now->tm_sec%10 + '0';
	afterTime = stream2.str();
	Z = "5a";
	afterTime = afterTime.append(Z);
	stream.clear();
 	 	
	certi.validityBefore.mpz.set_str(currentTime, 16);
	certi.validityAfter.mpz.set_str(afterTime, 16); 
	
	// Subject Key Algorihtm
	certi.subjectKeyAlgo.length = 9;
	certi.subjectKeyAlgo.mpz.set_str("2a864886f70d010101",16);
	certi.subjectKeyParams.length = 0;
	certi.subjectKeyParams.mpz = 0;

	// Public Key Modulus and exponent
	certi.modulus = privateKey.modulus;
	certi.exponent = privateKey.publicExponent;

	// Algo - sha1 with rsa encryption 	
	certi.signatureAlgo.length = 9;
	certi.signatureAlgo.mpz.set_str("2a864886f70d010105",16);
	certi.signatureParams.length = 0;
	certi.signatureParams.mpz = 0;
	
	// Signature for Certificate Verification
	certi.signature = privateKey.modulus;
	return certi;
}

/***********************************************/
/******* Generate PEM Format Key Files *********/
/***********************************************/

void key_Octet(vector<char>& octets, mpzWrapper mpz, int tagType, int tagNum, bool content = true)
{
	//Construct Identifier Octet - Always Single Octet
	unsigned char identifier;
	identifier = (unsigned char) ( ((tagType << 5) | tagNum) & 0x3F);
	octets.push_back(identifier);

	//Check Length Octet
	unsigned char length;
	int len = mpz.length;
	int lengthForm = (len > 127)?1:0;
	if(lengthForm == 0)
	{
		length = (unsigned char)(len & 0x7F);
		octets.push_back(length);
	}
	else
	{
		int lengthOctets = 1;
		int temp = len;
		while(temp >= 256)
		{
			temp = temp/256;
			lengthOctets++;
		}
		length = 0x80 | ((unsigned char)(lengthOctets));
		octets.push_back(length);
		
		unsigned char c;
		temp = len;		
		vector<char> reverse;
		for(int k = 0; k < lengthOctets; ++k)
		{
			c = (unsigned char)(temp % 256);
			temp = (unsigned char)(temp / 256);
			reverse.push_back(c);
		}
		vector<char>::reverse_iterator itr;
		for(itr = reverse.rbegin(); itr < reverse.rend(); itr++)
			octets.push_back(*itr);
	}
	// If Structured type no content to be added
	if(tagType == 0 && length != 0 && content)
	{
		string content = mpz.mpz.get_str(16);
		string data;
		int extra = len*2 - content.size();
		while(extra-- > 0)
			data.append("0");
		data.append(content);
		for(int index = 0; index < data.size(); index += 2)
		{
			unsigned char c;
			c = ascii_Hex(data[index]);
			c = (c << 4) | ascii_Hex(data[index + 1]);
			octets.push_back(c);
		}
	}
}

void attr_Octet(vector<char>& octets, int len, int tagNum, string content)
{
	unsigned char identifier;
	unsigned char length;
	
	// 1. Attribute Type	
	//Construct Identifier Octet - Always Single Octet
	identifier = (unsigned char) (tagNum & 0x3F);
	octets.push_back(identifier);

	//Check Length Octet
	int lengthForm = (len > 127)?1:0;
	if(lengthForm == 0)
	{
		length = (unsigned char)(len & 0x7F);
		octets.push_back(length);
	}
	else
	{
		int lengthOctets = 1;
		int temp = len;
		while(temp >= 256)
		{
			temp = temp/256;
			lengthOctets++;
		}
		length = 0x80 | ((unsigned char)(lengthOctets));
		octets.push_back(length);
		
		unsigned char c;
		temp = len;		
		vector<char> reverse;
		for(int k = 0; k < lengthOctets; ++k)
		{
			c = (unsigned char)(temp % 256);
			temp = (unsigned char)(temp / 256);
			reverse.push_back(c);
		}
		vector<char>::reverse_iterator itr;
		for(itr = reverse.rbegin(); itr < reverse.rend(); itr++)
			octets.push_back(*itr);
	}
	// If Structured type no content to be added
	if(length != 0)
	{
		// BIT STREAM acts as a constructed type
		if(tagNum == 3)
			return;

		string data;
		int extra = len*2 - content.size();
		while(extra-- > 0)
			data.append("0");
		data.append(content);
		for(int index = 0; index < data.size(); index += 2)
		{
			unsigned char c;
			c = ascii_Hex(data[index]);
			c = (c << 4) | ascii_Hex(data[index + 1]);
			octets.push_back(c);
		}
	}
}

// Construct PEM file from RSAPrivateKey structure
void rsaPrivateKey_PEM(RSAPrivateKey privateKey, string filename)
{
	FILE* file;
	vector<char> sequence;	
	vector<char> octets;
	
	key_Octet(octets, privateKey.version, 0, 2);
	key_Octet(octets, privateKey.modulus, 0, 2);
	key_Octet(octets, privateKey.publicExponent, 0, 2);
	key_Octet(octets, privateKey.privateExponent, 0, 2);
	key_Octet(octets, privateKey.prime1, 0, 2);
	key_Octet(octets, privateKey.prime2, 0, 2);
	key_Octet(octets, privateKey.exponent1, 0, 2);
	key_Octet(octets, privateKey.exponent2, 0, 2);
	key_Octet(octets, privateKey.coefficient, 0, 2);
	
	mpzWrapper seq;
	seq.length = octets.size();
	key_Octet(sequence,seq,1, 16);
	sequence.insert(sequence.end(), octets.begin(), octets.end());

	// Transform sequence to Base64 PEM content i.e. char(6-bit)	
	octets_PEM(sequence,"RSA PRIVATE KEY", filename.c_str());
}

// Construct PEM file from RSAPublicKey structure
void rsaPublicKey_PEM(RSAPublicKey publicKey, string filename)
{
	vector<char> mainSequence;
	mpzWrapper seq;
		
	vector<char> bits;
	vector<char> bitSequence;
	vector<char> algoSequence;
	vector<char> octets;
	
	// Construct a BIT STREAM Primitive
	char unused = 0;	
	key_Octet(octets, publicKey.modulus, 0, 2);
	key_Octet(octets, publicKey.exponent, 0, 2);
	
	seq.length = octets.size();
	key_Octet(bitSequence,seq,1, 16);
	bitSequence.insert(bitSequence.end(), octets.begin(), octets.end());
	octets.clear();
	
	seq.length = bitSequence.size()+1;
	key_Octet(bits,seq,0, 3, false);
	bits.insert(bits.end(), unused);
	bits.insert(bits.end(), bitSequence.begin(), bitSequence.end());
	bitSequence.clear();
	
	// Construct algorithm constructed type
	key_Octet(octets, publicKey.algorithm, 0, 6);
	key_Octet(octets, publicKey.params, 0, 5);
	seq.length = octets.size();
	key_Octet(algoSequence,seq,1, 16);
	algoSequence.insert(algoSequence.end(), octets.begin(), octets.end());
	octets.clear();
	
	
	// Construct RSAPublicKey sequence
	seq.length = algoSequence.size() + bits.size();
	key_Octet(mainSequence,seq,1, 16);
	mainSequence.insert(mainSequence.end(), algoSequence.begin(), algoSequence.end());
	mainSequence.insert(mainSequence.end(), bits.begin(), bits.end());
	
	// Transform sequence to Base64 PEM content i.e. char(6-bit)	
	octets_PEM(mainSequence,"PUBLIC KEY", filename.c_str());
}

// Construct PEM file from Certificate structure
void certificate_PEM(Certificate certi, string filename)
{
	FILE* file;

	vector<char> certiSequence;
	vector<char> mainSequence;
	mpzWrapper seq;
		
	vector<char> tbsSequence;
	vector<char> algoSequence;
	vector<char> issuerSequence;
	vector<char> bitSequence;
	vector<char> octets;
	vector<char> bits;

	vector<char> sequence;
	vector<char> set;
	
	key_Octet(octets, certi.serialNo, 0, 2);
	tbsSequence.insert(tbsSequence.end(), octets.begin(), octets.end());
	octets.clear();	
	
	// 2. Algorithm constructed type
	key_Octet(octets, certi.tbsSignatureAlgo, 0, 6);
	key_Octet(octets, certi.tbsSignatureParams, 0, 5);
	seq.length = octets.size();
	key_Octet(algoSequence,seq,1, 16);
	tbsSequence.insert(tbsSequence.end(), algoSequence.begin(), algoSequence.end());
	tbsSequence.insert(tbsSequence.end(), octets.begin(), octets.end());
	octets.clear();
	algoSequence.clear();
	
	// 3. Issuer
	vector<attribute>::iterator it;	
	for(it = certi.issuer.begin(); it < certi.issuer.end(); it++)
	{
		attribute attr = *it;
		attr_Octet(octets, attr.typeLength, 6, attr.type); 
		attr_Octet(octets, attr.valueLength, 19, attr.value); 
		seq.length = octets.size();
		key_Octet(set,seq, 1, 16);
		set.insert(set.end(), octets.begin(), octets.end());
		seq.length = set.size();	
		key_Octet(sequence, seq, 1 , 17);
		sequence.insert(sequence.end(), set.begin(), set.end());	
		set.clear();
	}
	// After all entities of Issuer (currently Just C=US)	
	seq.length = sequence.size();	
	key_Octet(issuerSequence, seq, 1 , 16);
	issuerSequence.insert(issuerSequence.end(), sequence.begin(), sequence.end());	
	tbsSequence.insert(tbsSequence.end(), issuerSequence.begin(), issuerSequence.end());
	octets.clear();
	sequence.clear();

	// 4. Date
	key_Octet(octets, certi.validityBefore, 0, 23);
	key_Octet(octets, certi.validityAfter, 0, 23);
	seq.length = octets.size();
	key_Octet(sequence,seq,1, 16);
	tbsSequence.insert(tbsSequence.end(), sequence.begin(), sequence.end());
	tbsSequence.insert(tbsSequence.end(), octets.begin(), octets.end());
	octets.clear();
	sequence.clear();

	// 5. Subject
	tbsSequence.insert(tbsSequence.end(), issuerSequence.begin(), issuerSequence.end());
	issuerSequence.clear();

	// 6. Subject Public Key
	// 6.1 AlgoIdentifier
	key_Octet(octets, certi.subjectKeyAlgo, 0, 6);
	key_Octet(octets, certi.subjectKeyParams, 0, 5);
	seq.length = octets.size();
	key_Octet(sequence,seq,1, 16);
	sequence.insert(sequence.end(), octets.begin(), octets.end());
	octets.clear();
	
	// 6.2 BIT STREAM Primitive
	char unused = 0;
	key_Octet(octets, certi.modulus, 0, 2);
	key_Octet(octets, certi.exponent, 0, 2);
	
	seq.length = octets.size();
	key_Octet(set,seq,1, 16);
	set.insert(set.end(), octets.begin(), octets.end());
	seq.length = set.size() + 1;
	key_Octet(bitSequence,seq,0, 3, false);
	bitSequence.push_back(unused);
	bitSequence.insert(bitSequence.end(), set.begin(), set.end());
	
	seq.length = bitSequence.size() + sequence.size();
	key_Octet(bits,seq,1, 16);
	bits.insert(bits.end(), sequence.begin(), sequence.end());
	bits.insert(bits.end(), bitSequence.begin(), bitSequence.end());
	octets.clear();
	bitSequence.clear();
	sequence.clear();
	
	tbsSequence.insert(tbsSequence.end(), bits.begin(), bits.end());
	bits.clear();
	
	seq.length = tbsSequence.size();
	key_Octet(mainSequence,seq,1, 16);
	mainSequence.insert(mainSequence.end(), tbsSequence.begin(), tbsSequence.end());
	
	/*****  Construct Signature Algo-Identifier ******/
	key_Octet(octets, certi.signatureAlgo, 0, 6);
	key_Octet(octets, certi.signatureParams, 0, 5);
	seq.length = octets.size();
	key_Octet(algoSequence,seq,1, 16);
	algoSequence.insert(algoSequence.end(), octets.begin(), octets.end());
	octets.clear();
	
	mainSequence.insert(mainSequence.end(), algoSequence.begin(), algoSequence.end());
	algoSequence.clear();

	/*****  Construct Signature ******/
	key_Octet(octets, certi.signature, 0, 3);
	
	mainSequence.insert(mainSequence.end(), octets.begin(), octets.end());
	octets.clear();
	
	// Construct Certificate sequence
	seq.length = mainSequence.size();
	key_Octet(certiSequence,seq,1, 16);
	certiSequence.insert(certiSequence.end(), mainSequence.begin(), mainSequence.end());
	
	// Transform sequence to Base64 PEM content i.e. char(6-bit)	
	octets_PEM(certiSequence,"CERTIFICATE", filename.c_str());
}

// Generate public PEM file from private PEM file
void privatePEM_PublicPEM(string privatePEMFile, string publicPEMFile)
{
	FILE* file;
	file = fopen(privatePEMFile.c_str(), "r");

	RSAPrivateKey privateKey = pem_RSAPrivateKey(file);
	RSAPublicKey publicKey = privateKey_PublicKey(privateKey);
	rsaPublicKey_PEM(publicKey, publicPEMFile);
}

/***********************************************/
/************ Extra Conversions  ***************/
/***********************************************/

// Construct DER file from a string
void string_DER(string str, string filename)
{
	ofstream outfile;
	outfile.open(filename.c_str());

	if(!outfile)
	{
		outfile.copyfmt(std::cout); 
		outfile.clear(std::cout.rdstate());
		outfile.basic_ios<char>::rdbuf(std::cout.rdbuf()); 
	}
	for(int i = 0; i < str.length(); i=i+2)
	{
		unsigned char c;
		c = (int)((ascii_Hex(str[i]) << 4) & 0xF0) | (ascii_Hex(str[i+1]) & 0x0F);
		outfile << c ;	
	}
	outfile.close();
}

// Construct string with data from file, on character basis
string getDataString(string filename)
{
	string data;

	ifstream in;
	in.open(filename.c_str());
	
	unsigned char c;
	int value;
	while(!in.eof())
	{
		c = (char)in.get();
		value = (int)c;
		data.append(1,c);
	}
	if((value == 255))
			data.erase(data.end()-1, data.end());
	return data;
}

// Construct file from a string
void stringOut(string str, string filename)
{
	ofstream outfile;
	outfile.open(filename.c_str());

	if(!outfile)
	{
		outfile.copyfmt(std::cout); 
		outfile.clear(std::cout.rdstate());
		outfile.basic_ios<char>::rdbuf(std::cout.rdbuf()); 
	}
	
	for(int i = 0; i < str.length(); i++)
	{
		unsigned char c = str[i];
		outfile << c ;	
	}
	outfile.close();
}

// Construct with data from file, could be crypted or encrypted
string getHEXDataString(string filename)
{
	string data;

	ifstream in;
	in.open(filename.c_str());
	
	unsigned char c;
	int value;
	while(!in.eof())
	{
		c = (char)in.get();
		value = (int)c;
		char temp1, temp2;
		sprintf(&temp1, "%x", ((value >> 4) & 0x0F));
		data.append(1,temp1);
		sprintf(&temp2, "%x", (value & 0x0F));
		data.append(1,temp2);
	}
	if(value == 255)
			data.erase(data.end()-2, data.end());	
	if(DEBUG)
	{
		cout << "Hex Input: " << data << endl;
		cout << "Hex Input length: " << data.length() << endl;
	}
	return data;
}

/***********************************************/
/********* Encryption and Decryption ***********/
/***********************************************/

// Encrypt the data using PKCS#1 V1.5
// If no destfile, print on console
// If no srcfile, use data as content
void encrypt(string data, RSAPublicKey publicKey, string srcfile = "", string destfile = "")
{
	// Each character of message is an octet
	string message;
	if(!srcfile.empty())
		message = getDataString(srcfile);
	else
		message = data;

	int mLen = message.length();
	int k = publicKey.modulus.length;
	if(mLen > (k-11))
	{
		cout << "\n ERROR: Message Too Long" << endl;
		return;
	}
	
	int encodingLen = k - mLen -3;
	string encoding;

	// Generate Padding String PS
	for(int i = 0; i < encodingLen; i++)
	{
		unsigned char c = getRandomOctet();
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		encoding.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		encoding.append(1,temp2);
	}
	encoding.insert(0,"0002");
	encoding.append("00");

	// Append Message
	for(int i = 0; i < message.length(); i++)
	{
		unsigned char c = message[i];
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		encoding.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		encoding.append(1,temp2);
	}
	if(DEBUG)
	{
		cout << "Encoding: " << encoding << endl;
		cout << "Encoding Length: " << encoding.length() << endl;
	}
	mpz_class m,c;
	m.set_str(encoding,16);
	mpz_powm(c.get_mpz_t(), m.get_mpz_t(), publicKey.exponent.mpz.get_mpz_t(), publicKey.modulus.mpz.get_mpz_t());
	string encryptedMessage = c.get_str(16);
	int diff = k*2 - encryptedMessage.length();
	while(diff-- > 0)
		encryptedMessage.insert(0,"0");		
	if(DEBUG)
	{
		cout << "Encrypted Text: " << encryptedMessage << endl; 
		cout << "Encrypted Text Length: " << encryptedMessage.length() << endl;
	}

	string_DER(encryptedMessage, destfile);
}

// Decrypt the data using PKCS#1 V1.5
void decrypt(string data, RSAPrivateKey privateKey, string srcfile = "", string destfile = "")
{
	// Each character of message is an octet
	string message;
	if(!srcfile.empty())
		message = getHEXDataString(srcfile);
	else
		message = data;

	int mLen = message.length()/2;
	int k = privateKey.modulus.length;
	if(DEBUG){	
	cout << "K: " << k << " mLen: " << mLen << endl;
	}
	// Check for length not equal to modulus
	if(mLen > k)
	{
		cout << "\n ERROR: Decryption Error 0" << endl;
		return;
	}
	
	// Decrypt text using private key
	mpz_class c, m;
	c.set_str(message,16);

	mpz_class m1, m2, h, temp;
	mpz_powm(m1.get_mpz_t(), c.get_mpz_t(), privateKey.exponent1.mpz.get_mpz_t(), privateKey.prime1.mpz.get_mpz_t());
	mpz_powm(m2.get_mpz_t(), c.get_mpz_t(), privateKey.exponent2.mpz.get_mpz_t(), privateKey.prime2.mpz.get_mpz_t());
	if(m1 < m2)
		temp = privateKey.coefficient.mpz * abs(m1 + privateKey.prime1.mpz - m2);
	else
		temp = privateKey.coefficient.mpz * abs(m1 - m2);
	h = temp % privateKey.prime1.mpz;
	m = m2 + (h * privateKey.prime2.mpz);
	string text = m.get_str(16);

	// Extend length to make equal to k octets
	int diff = k*2 - text.length();
	while(diff-- > 0)
		text.insert(0,"0");
	if(DEBUG)	{	
		cout << "Decrypted Text: " << text << endl;	
		cout << "Decrypted Text Length: " << text.length() << endl;	
	}
	// Check if correct padding
	size_t found1, found2;
	if((found1 = text.find("0002")) != 0)
	{
		cout << "\n ERROR: Decryption Error 1" << endl;
		return;
	}

	found1 = text.find("00",3);
	while((found1 % 2) == 1)
		found1 = text.find("00",found1+1);
	found2 = text.rfind("00");
		
	int differ = (int)(found2 - found1);
	if(differ > 2)
	{
		cout << found1 << ":" << found2 << endl;
		cout << "\n ERROR: Decryption Error 2 " << differ << endl;
		return;
	}
	
	// Extract Message Octet
	string textMessage = text.substr(found1 + 2);
	
	// Construct Character Message from octets
	string decryptedMessage;
	for(int j = 0; j < textMessage.length(); j=j+2)
	{
		int value;
		stringstream temp;
		temp << hex << textMessage.substr(j,2);
		temp >> value;
		char ch = value;
		decryptedMessage.append(1,ch);
	}

	stringOut(decryptedMessage, destfile);
}	

/***********************************************/
/********* Signature and Verification **********/
/***********************************************/

// Using Hash and DER for algorithm to encode
string signatureEncoder1(string message, int k)
{
	// Compute hash for the message
	CryptoPP::SHA1 hash;
	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	byte const* hashData = (byte *)message.data(); 
	hash.CalculateDigest(digest, hashData, message.length());

	// Construct digest octet sequence as DER
	vector<char> octets;
	vector<char> algoSequence;
	vector<char> octetSequence;
	vector<char> digestSequence;
	vector<char>::iterator itr;

	mpzWrapper algorithm;
	mpzWrapper params;
	mpzWrapper seq;

	// 1. Algorithm
	//#PKCS1-1 5 i.e. sha1rsaencryption
	algorithm.length = 9;
	algorithm.mpz.set_str("2a864886f70d010105",16);
	params.length = 0;

	key_Octet(octets, algorithm, 0, 6);
	key_Octet(octets, params, 0, 5);
	seq.length = octets.size();

	key_Octet(algoSequence,seq,1, 16);
	algoSequence.insert(algoSequence.end(), octets.begin(), octets.end());
	
	// 2. Digest Hash
	octets.clear();	
	for(int index = 0; index < CryptoPP::SHA1::DIGESTSIZE; index++)
	{
		octets.push_back((char)digest[index]);
	}
	seq.length = octets.size();
	octetSequence.push_back((int)4);	//Tag
	octetSequence.push_back((int)20);	//Length
	octetSequence.push_back((int)0);	//Unused bits
	octetSequence.insert(octetSequence.end(), octets.begin(), octets.end());
	seq.length = algoSequence.size() + octetSequence.size();
	key_Octet(digestSequence,seq,1, 16);
	digestSequence.insert(digestSequence.end(), algoSequence.begin(), algoSequence.end());
	digestSequence.insert(digestSequence.end(), octetSequence.begin(), octetSequence.end());
	
	int tLen = digestSequence.size();
	if(k < (tLen+11))
	{
		cout << "Error: Intended encoded message length too short" << endl;
		return "";
	}

	// Generate Hexadecimal octets for Digest
	string digestString;
	for(int i = 0; i < tLen; i++)
	{
		unsigned char c = digestSequence[i];
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		digestString.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		digestString.append(1,temp2);
	}
	
	int encodingLen = k - tLen -3;
	
	// Generate Hexadecimal octets for Padding String PS
	string encoding;
	for(int i = 0; i < encodingLen; i++)
	{
		unsigned char c = 255;;
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		encoding.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		encoding.append(1,temp2);
	}
	encoding.insert(0,"0001");
	encoding.append("00");

	// Append Message
	encoding.append(digestString);

	return encoding;
}

// Using just the original form message to encode
string signatureEncoder(string message, int k)
{
	int mLen = message.size();
	if(k < (mLen+11))
	{
		cout << "Error: Intended encoded message length too big" << endl;
		return "";
	}

	// Generate Hexadecimal octets for Digest
	string digestString;
	for(int i = 0; i < mLen; i++)
	{
		unsigned char c = message[i];
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		digestString.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		digestString.append(1,temp2);
	}
	
	int encodingLen = k - mLen -3;
	
	// Generate Hexadecimal octets for Padding String PS
	string encoding;
	for(int i = 0; i < encodingLen; i++)
	{
		unsigned char c = 255;;
		char temp1, temp2;
		sprintf(&temp1, "%x", ((c >> 4) & 0x0F));
		encoding.append(1,temp1);
		sprintf(&temp2, "%x", (c & 0x0F));
		encoding.append(1,temp2);
	}
	encoding.insert(0,"0001");
	encoding.append("00");

	// Append Message
	encoding.append(digestString);

	return encoding;
}

// Sign the data using SHA1 and certificate RSA private key
// If no destfile, print on console
// If no srcfile, use data as content
void sign(string data, RSAPrivateKey privateKey, string srcfile = "", string destfile = "")
{
	// Each character of message is an octet
	string message;
	if(!srcfile.empty())
		message = getDataString(srcfile);
	else
		message = data;

	int mLen = message.length();
	int k = privateKey.modulus.length;

	// Check for Message Octet Length for SHA1 size	
	if(mLen > 100000)
	{
		cout << "\n ERROR: Message Too Long" << endl;
		return;
	}
	string encoding = signatureEncoder(message, k);

	// Encrypt using RSAPrivate Key
	mpz_class m,c;
	c.set_str(encoding,16);
	mpz_class m1, m2, h, temp;
	mpz_powm(m1.get_mpz_t(), c.get_mpz_t(), privateKey.exponent1.mpz.get_mpz_t(), privateKey.prime1.mpz.get_mpz_t());
	mpz_powm(m2.get_mpz_t(), c.get_mpz_t(), privateKey.exponent2.mpz.get_mpz_t(), privateKey.prime2.mpz.get_mpz_t());
	if(m1 < m2)
		temp = privateKey.coefficient.mpz * abs(m1 + privateKey.prime1.mpz - m2);
	else
		temp = privateKey.coefficient.mpz * abs(m1 - m2);
	h = temp % privateKey.prime1.mpz;
	m = m2 + (h * privateKey.prime2.mpz);
	string signedMessage = m.get_str(16);
	int diff = k*2 - signedMessage.length();
	while(diff-- > 0)
		signedMessage.insert(0,"0");		
	
	string_DER(signedMessage, destfile);
}

// Verify the data using Certificate and original message
void verify1(Certificate certi, string signfile = "", string outputfile = "" , string msgfile = "")
{
	// Each character of message is an octet
	string message;
	if(!msgfile.empty())
		message = getDataString(msgfile);

	string messageData;
	if(!msgfile.empty())
		messageData = getHEXDataString(msgfile);
	
	string signedData;
	if(!signfile.empty())
		signedData = getHEXDataString(signfile);

	int sLen = signedData.length();
	int mLen = message.length();
	int k = certi.modulus.length;
	cout << "sLen: " << sLen << " mLen: " << mLen << " k: " << k << endl;

	if(sLen != (k*2))
	{
		cout << "\n ERROR: Invalid Signature" << endl;
		return;
	}
	
	mpz_class signature, m;
	signature.set_str(signedData,16);
	mpz_powm(m.get_mpz_t(), signature.get_mpz_t(), certi.exponent.mpz.get_mpz_t(), certi.modulus.mpz.get_mpz_t());
	
	string encoding1,encoding2;
	
	encoding1 = m.get_str(16);
	int diff = k*2 - encoding1.length();
	while(diff-- > 0)
		encoding1.insert(0,"0");		
	
	encoding2 = signatureEncoder(message, k);

	cout << "Encoding1: " << encoding1 << endl;
	cout << "Encoding2: " << encoding2 << endl;

	if(encoding1.compare(encoding2) == 0)
	{
		cout << "Valid Signature" << endl;
		cout << message << endl;
	}
	else
		cout << "Invalid Signature" << endl;
}

// Verify the data using just Certificate
void verify(Certificate certi, string signfile = "", string destfile = "")
{
	// Each character of message is an octet
	string signedData;
	if(!signfile.empty())
		signedData = getHEXDataString(signfile);

	int sLen = signedData.length();
	int k = certi.modulus.length;
	if(DEBUG)
		cout << "sLen: " << sLen << " k: " << k << endl;

	if(sLen != (k*2))
	{
		cout << "\n ERROR: Invalid Signature" << endl;
		return;
	}
	
	mpz_class signature, m;
	signature.set_str(signedData,16);
	mpz_powm(m.get_mpz_t(), signature.get_mpz_t(), certi.exponent.mpz.get_mpz_t(), certi.modulus.mpz.get_mpz_t());
	
	string encoding;
	
	encoding = m.get_str(16);
	int diff = k*2 - encoding.length();
	while(diff-- > 0)
		encoding.insert(0,"0");		
	
	if(DEBUG)
		cout << "Encoding: " << encoding << endl;

	// Check if correct padding
	size_t found1, found2;
	if((found1 = encoding.find("0001")) != 0)
	{
		cout << "\n ERROR: Invalid Signature Block 01" << endl;
		return;
	}

	found1 = encoding.find("00",3);
	while((found1 % 2) == 1)
		found1 = encoding.find("00",found1+1);
	found2 = encoding.rfind("00");
		
	int differ = (int)(found2 - found1);
	if(differ > 2)
	{
		cout << "\n ERROR: Invalid Signature" << differ << endl;
		return;
	}
	
	// Extract Message Octet
	string textMessage = encoding.substr(found1 + 2);
	
	cout << "Valid Signature" << endl;
	string_DER(textMessage, destfile);
}

int main(int argc, char **argv)
{
	FILE *file1, *file2, *file3, *file4;
	RSAPrivateKey privateKey;
	RSAPublicKey publicKey;
	Certificate certificate;
	X509RSAPrivateKey x509Key;
	string str = "";
	// Command Line arguments
	if(argc > 1)
	{
		string inputFile, outputFile, keyFile, keyOutFile;
		bool statusPubIn = false;
		bool statusPubOut = false;
		bool statusCert = false;
		bool statusText = false;
		bool reqStatus = false;
		string status;

		int rsa_bits = 512;
		for(int i = 1 ; i < argc ; i++)
		{
			string arg(argv[i]);
			// Input File			
			if(arg == "-in")
			{
				if(i >= argc){
					cout << "No Input File provided" << endl;
					return 0;
				}
				else
				{
					inputFile = argv[i+1];
					FILE* fp = fopen(inputFile.c_str(), "r");
					if(!fp)
					{
						cout << "File does not exist" << endl;
						return 0;
					}
				}
			}
			else if(arg == "-inkey")
			{
				if(i >= argc)
				{
					cout << "No Input Key file provided" << endl;
					return 0;
				}
				else
				{
					keyFile = argv[i+1];
					FILE* fp = fopen(keyFile.c_str(), "r");
					if(!fp)
					{
						cout << "File does not exist" << endl;
						return 0;
					}
				}
			}
			else if(arg == "-out")
			{
				if(i >= argc){
					cout << "No output File provided" << endl;
					return 0;
				}
				else
					outputFile = argv[i+1];
			}
			else if(arg == "-keyout")
			{
				if(i >= argc){
					cout << "No output File provided" << endl;
					return 0;
				}
				else
					keyOutFile = argv[i+1];
			}
			else if(arg == "-pubin")
				statusPubIn = true;
			else if(arg == "-pubout")
				statusPubOut = true;
			else if(arg == "-certin")
				statusCert = true;
			else if(arg == "-text")
				statusText = true;
			else if(arg == "-encrypt")
				status = "encrypt";
			else if(arg == "-decrypt")
				status = "decrypt";
			else if(arg == "-sign")
				status = "sign";
			else if(arg == "-verify")
				status = "verify";
			else if(arg == "req")
				reqStatus = true;
		}
		string cmd(argv[1]);
		FILE* file;
			file = fopen(inputFile.c_str(), "r");

		if(cmd == "genrsa")
		{
			cout << "Generating RSA Keys" << endl;
			if(argc > 2)
				rsa_bits = atoi(argv[argc-1]);
			privateKey = generateRSAKeys(rsa_bits);
			cout << "Writing RSA Key\n";	
			rsaPrivateKey_PEM(privateKey, outputFile);
		}
		else if(cmd == "x509")
		{
			cout << "Generating Certificate" << endl;
			if(reqStatus)
			{
				if(argc > 2)
					rsa_bits = atoi(argv[argc-1]);
				privateKey = generateRSAKeys(rsa_bits);
				certificate = rsaPrivateKey_Certificate(privateKey);

				cout << "Writing RSA Key\n";	
				rsaPrivateKey_PEM(privateKey, keyOutFile);
				certificate_PEM(certificate, outputFile);
			}
			else if(statusText)
			{
				certificate = pem_Certificate(file);
				printCertificate(certificate);
			}
			else if(inputFile != "")
			{
				certificate = pem_Certificate(file);
				certificate_PEM(certificate, outputFile);
			}
		}
		else if(cmd == "rsa")
		{
			cout << "Operations on RSA Keys" << endl;
			if(inputFile == "")		
			{
				cout << "No RSA Private Keys file provide" << endl;	
				return 0;

			}
			
			if(statusPubIn)
				publicKey = pem_RSAPublicKey(file);
			else
				privateKey = pem_RSAPrivateKey(file);
			if(statusPubOut)
			{
				//Generate Public Key
				publicKey = privateKey_PublicKey(privateKey);
				cout << "Writing RSA Key\n";	
				rsaPublicKey_PEM(publicKey, outputFile);
			}
			else if(statusText)
			{
				if(statusPubIn)
					printRSAPublicKeys(publicKey);
				else
					printRSAPrivateKeys(privateKey);
			}
			else
			{	
				if(statusPubIn)
					rsaPublicKey_PEM(publicKey, outputFile);
				else
					rsaPrivateKey_PEM(privateKey, outputFile);
			}
		}
		else if(cmd == "rsautl")
		{
			cout << "RSA Utilities " << endl;
			if(keyFile == "")		
			{
				cout << "No RSA Key or Certificate file provide" << endl;	
				return 0;
			}
			
			if(inputFile == "")
				cin >> str;

			FILE* file;
			file = fopen(keyFile.c_str(), "r");

			if(status == "encrypt")
			{
				publicKey = pem_RSAPublicKey(file);
				encrypt(str, publicKey, inputFile, outputFile);
			}
			else if(status == "decrypt")
			{
				privateKey = pem_RSAPrivateKey(file);
				decrypt(str, privateKey, inputFile, outputFile);
			}
			else if(status == "sign")
			{
				privateKey = pem_RSAPrivateKey(file);
				sign(str,privateKey,inputFile,outputFile);
			}
			else if(status == "verify")
			{
				certificate = pem_Certificate(file);
				verify(certificate,inputFile,outputFile);
			}
			else
				cout << "None";
		}
	}	
}
