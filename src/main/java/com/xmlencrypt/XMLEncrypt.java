package com.xmlencrypt;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;

public class XMLEncrypt {
	private static XMLEncrypt instance = null;
	public static XMLEncrypt getInstance(Certificate certificate) throws Exception {
		if(instance == null) return new XMLEncrypt(certificate) ;
		else return instance;
	}
	
	private Key keyEncryptKey = null;
	private XMLCipher xmlCipher = null;
	private Transformer transformer = null;
	private KeyGenerator keyGenerator = null;
	private Key symmetricKey = null;
	public static final String X509 = "X.509";

	public XMLEncrypt(Certificate certificate) throws Exception {
		org.apache.xml.security.Init.init();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		String algorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
		String symmetricKeyAlg = "AES";
		keyEncryptKey = (RSAPublicKey) certificate.getPublicKey();
		xmlCipher = XMLCipher.getInstance(algorithm);
		TransformerFactory factory = TransformerFactory.newInstance();
		transformer = factory.newTransformer();

		SecretKeySpec keySpec = new SecretKeySpec(pwdHandler(""), symmetricKeyAlg);
		symmetricKey = keySpec; 
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, keySpec);
	}
	
	private static byte[] pwdHandler(String password) throws UnsupportedEncodingException {
		byte[] data = null;
		if (password == null) {
			password = "";
		}
		StringBuffer sb = new StringBuffer(16);
		sb.append(password);
		while (sb.length() < 16) {
			sb.append("0");
		}
		if (sb.length() > 16) {
			sb.setLength(16);
		}

		data = sb.toString().getBytes("UTF-8");

		return data;
	}

	public String encrypt(String plainText) throws Exception {

		// parse file into document
		Document document = parseString(plainText);
		XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
		keyCipher.init(XMLCipher.WRAP_MODE, keyEncryptKey);

		// encrypt symmetric key
		EncryptedKey encryptedKey = keyCipher.encryptKey(document, symmetricKey);

		// add key info to encrypted data element
		EncryptedData encryptedDataElement = xmlCipher.getEncryptedData();
		org.apache.xml.security.keys.KeyInfo keyInfo = new org.apache.xml.security.keys.KeyInfo(document);
		keyInfo.add(encryptedKey);
		encryptedDataElement.setKeyInfo(keyInfo);

		// do the actual encryption encryptContentsOnly=false
//		xmlCipher.doFinal(document, document.getDocumentElement(), false);
		xmlCipher.doFinal(document, (Element) document.getElementsByTagName("dependencies").item(0), true);
		return writeEncryptedDocToString(document);
	}

	public Document parseString(String str) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();
		InputStream is = new ByteArrayInputStream(str.getBytes("UTF-8"));
		return db.parse(is);
	}

	public SecretKey GenerateSymmetricKey() throws Exception {
		return keyGenerator.generateKey();
	}

	public String writeEncryptedDocToString(Document doc) throws Exception {
		return XMLDecrypt.getString(doc, transformer);
	}

}

