package com.xmlencrypt;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.Key;
import java.security.Security;

public class XMLDecrypt {
    private static XMLDecrypt instance = null ;
    public static XMLDecrypt getInstance(Key key) throws Exception {
    	if(instance == null)
    	   return new XMLDecrypt(key);
    	else return instance ;
    }
	public static final String X509 = "X.509";

    private Key key = null;
	private XMLCipher decryptXmlCipher = null;
	private javax.xml.parsers.DocumentBuilderFactory dbf = null;
	private javax.xml.parsers.DocumentBuilder db = null;

	public XMLDecrypt(Key key) throws Exception {
		org.apache.xml.security.Init.init();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
			this.key = key;
			decryptXmlCipher = XMLCipher.getInstance();
			decryptXmlCipher.init(XMLCipher.DECRYPT_MODE, null);
			decryptXmlCipher.setKEK(key);
			dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			
			db = dbf.newDocumentBuilder();
		} catch (Exception e) {
			throw new Exception("Fail to Init the Decrypt Object." + e.getMessage());
		}
	}

	public Document parseFile(String fileName) throws Exception {
		return db.parse(fileName);
	}

	public Document parseString(String str) throws Exception {
		InputStream is = new ByteArrayInputStream(str.getBytes());
		return db.parse(is);

	}

	public String decrypt(String cryptograph) throws Exception {
		return decrypt(cryptograph, "utf8");
	}

	public String decrypt(String plainText, String charsetName)
			throws Exception {
		// load the encrypted file into a Document
		Document document = parseString(plainText);

//		// get the encrypted data element
//		Element encryptedDataElement = document.getDocumentElement();
//
//		// do the actual decryption
//		byte[] byteArr = decryptXmlCipher.decryptToByteArray(encryptedDataElement) ;


		// get the encrypted data element
		String namespaceURI = EncryptionConstants.EncryptionSpecNS;
		String localName = EncryptionConstants._TAG_ENCRYPTEDDATA;
		Element encryptedDataElement = (Element) document.getElementsByTagNameNS(namespaceURI, localName).item(0);

		// initialize cipher
		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);

		xmlCipher.setKEK(key);

		// do the actual decryption
		xmlCipher.doFinal(document, encryptedDataElement);

		// write the results to a file
		return writeDecryptedDocToString(document);

//		return new String(byteArr,charsetName);
	}

	public String writeDecryptedDocToString(Document doc) throws Exception {
		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer = factory.newTransformer();
		return getString(doc, transformer);
	}

	public static String getString(Document doc, Transformer transformer) throws TransformerException {
		DOMSource source = new DOMSource(doc);
		StringWriter stringWriter = new StringWriter();
		StreamResult result = new StreamResult(stringWriter);
		transformer.transform(source, result);
		String rr = stringWriter.getBuffer().toString() ;
		return rr.substring(rr.indexOf(">")+1);
	}

}

