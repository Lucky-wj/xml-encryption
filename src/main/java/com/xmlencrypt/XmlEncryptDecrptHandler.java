package com.xmlencrypt;

import org.bouncycastle.util.encoders.Base64;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


public class XmlEncryptDecrptHandler{
    /**
           * 证书路径
     */
    private String cerFilePath;
    private Certificate certificate ;
    private Key key;

	public XmlEncryptDecrptHandler() throws Exception {
		this.certificate = getPublicCertificate("/server.crt");
		this.key = getPrivateKey("/private_pkcs8.key");
	}

	public String getCerFilePath() {
		return cerFilePath;
	}

	public void setCerFilePath(String cerFilePath) {
		this.cerFilePath = cerFilePath;
	}

	private String encrypt(String xml) throws Exception {
		String rr = XMLEncrypt.getInstance(certificate).encrypt(xml) ;
		return rr ;
	}
	
	private String decrypt(String xml) throws Exception {
		String rr = XMLDecrypt.getInstance(key).decrypt(xml) ;
		return rr ;
	}
	
	private List<String> splitFpsXML(String xml) throws Exception {
		List<String> ls = new ArrayList<String>();
		String[] iii = xml.split("</ah:AppHdr>");
		String part1 = iii[0].trim();
		part1 += "</ah:AppHdr>"; 
		part1 += iii[1].substring(0,iii[1].indexOf(">")+1).trim();
		String part2 = iii[1].substring(iii[1].indexOf(">")+1,iii[1].indexOf("</doc:Document>")).trim();
		String part3 = "</doc:Document>" ;
		part3 += iii[1].split("</doc:Document>")[1].trim();
		ls.add(part1);
		ls.add(part2);
		ls.add(part3);
		return ls ;
	}

	public static void main(String[] args) throws Exception {
		XmlEncryptDecrptHandler handler = new XmlEncryptDecrptHandler();

		String xml = handler.readXML("/test.xml");
		System.out.println("encrypt before: \n" + xml);

		String encrypt = handler.encrypt(xml);
		System.out.println("encrypt after: \n" + encrypt);

		String decrypt = handler.decrypt(encrypt);
		System.out.println("decrypt after: \n" + decrypt);
	}

	private String readXML(String path) throws URISyntaxException, IOException {
		List<String> strings = Files.readAllLines(Paths.get(XmlEncryptDecrptHandler.class.getResource(path).toURI()));
		return strings.stream().collect(Collectors.joining());
	}

	private X509Certificate getPublicCertificate(String path) throws CertificateException, FileNotFoundException {
		/* 取出证书--从文件中取出 */
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate c = cf.generateCertificate(XmlEncryptDecrptHandler.class.getResourceAsStream(path));
		X509Certificate x509Cert = (X509Certificate) c;

		// JAVA程序中显示证书指定信息
		System.out.println("输出证书信息:"+c.toString());
		System.out.println("版本号:"+x509Cert.getVersion());
		System.out.println("序列号:"+x509Cert.getSerialNumber().toString(16));
		System.out.println("主体名："+x509Cert.getSubjectDN());
		System.out.println("签发者："+x509Cert.getIssuerDN());
		System.out.println("有效期："+x509Cert.getNotBefore());
		System.out.println("签名算法："+x509Cert.getSigAlgName());
		byte [] sig=x509Cert.getSignature();//签名值
		System.out.println("签名值："+ Arrays.toString(sig));
		PublicKey pk=x509Cert.getPublicKey();
		byte [] pkenc=pk.getEncoded();
		System.out.println("公钥");
		for (byte b : pkenc)
			System.out.print(b + ",");
		return x509Cert;
	}

	private PrivateKey getPrivateKey(String path) throws Exception {
		byte[] encoded = Base64.decode(Files.readAllBytes(Paths.get(XmlEncryptDecrptHandler.class.getResource(path).toURI())));

		PrivateKey privateKey = null;
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec pKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
			privateKey = keyFactory.generatePrivate(pKCS8EncodedKeySpec);
			System.out.println("-------------------------------");
			System.out.println("---+++:" + privateKey.toString() + "---++++");
			//Log.d("get",filename+"　;　"+privateKey.toString() );
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return privateKey;
	}
}
