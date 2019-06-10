package com.zygen.etax.repo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
//import com.zygen.etax.sats.TSAClient;
import com.zygen.etax.util.EtaxFileService;

public class EtaxSigner {

	private static final Logger log = LoggerFactory.getLogger(EtaxSigner.class);
	private PrivateKey privateKey;
	private Certificate certificate;
	private TSAClient tsaClient;
	private Certificate[] certificateChain;
	private KeyStore keyStore;
	private String providername;
	private X509Certificate x509Certificate;
	private KeyStore.PrivateKeyEntry keyStorePrivateKeyEntry;
	private KeyGenerator keyGen;
	private SecretKey desKey;

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}

	public void setTsaClient(TSAClient tsaClient) {
		this.tsaClient = tsaClient;
	}

	public void setCertificateChain(Certificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}

	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	public void setProvidername(String providername) {
		this.providername = providername;
	}

	public void setX509Certificate(X509Certificate x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

	public void setKeyStorePrivateKeyEntry(KeyStore.PrivateKeyEntry keyStorePrivateKeyEntry) {
		this.keyStorePrivateKeyEntry = keyStorePrivateKeyEntry;
	}

	public String signXML(InputStream inputXml, String tempPath) {
		log.info("signXML");
		String signedXmlContent = new String();
		String buffer = new String();
		String line = new String();
		String refUri = new String();
		try {
			FileOutputStream outputStream = new FileOutputStream(tempPath);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document sourceDoc = dbf.newDocumentBuilder().parse(inputXml);
			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
			Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
					Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
					null, null);
			SignedInfo si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
					fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));
			KeyInfoFactory kif = fac.getKeyInfoFactory();
			List x509Content = new ArrayList();
			x509Content.add(x509Certificate.getSubjectX500Principal().getName());
			x509Content.add(x509Certificate);
			X509Data xd = kif.newX509Data(x509Content);
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
			log.info("Get XML Signature");
			DOMSignContext dsc = new DOMSignContext(keyStorePrivateKeyEntry.getPrivateKey(), sourceDoc.getDocumentElement());
			log.info("Sign XML Signature");
			XMLSignature signature = fac.newXMLSignature(si, ki);
			signature.sign(dsc);
			log.info("XML Transformer to output");
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(sourceDoc), new StreamResult(outputStream));
			outputStream.close();
			FileInputStream fileIs = new FileInputStream(tempPath);
			BufferedReader buffReader = new BufferedReader(new InputStreamReader(fileIs, StandardCharsets.UTF_8));
			line = buffReader.readLine();
			while (line != null) {
				buffer += line;
				line = buffReader.readLine();
			}
			signedXmlContent = buffer;
			fileIs.close();
			EtaxFileService.deleteTempFile(tempPath);
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		return signedXmlContent;
	}

	public String signPDF(String pdfPath, String signedPdfPath) {
		log.info("signPDF");
		log.info(signedPdfPath);
		String signedPDF = new String();
		File inputFile = null;
		File outputFile = null;
		inputFile = new File(pdfPath);
		if (inputFile.exists()) {
			outputFile = new File(signedPdfPath);
			try {
				if (signPdf(inputFile, outputFile)) {
					log.info("signPdf success");
					InputStream isSignedPdf = new FileInputStream(outputFile);
					byte[] signedPdfByte = new byte[isSignedPdf.available()];
					isSignedPdf.read(signedPdfByte, 0, signedPdfByte.length);
					signedPDF = Base64.getEncoder().encodeToString(signedPdfByte);
					isSignedPdf.close();
				} else {
					log.info("signPdf not success");
				}
			} catch (Exception e) {
				log.error(e.getMessage());
			}
		}
		if (outputFile.exists()) {
			outputFile.delete();
			log.info(outputFile + " has been deleted");
		}
		return signedPDF;
	}

	private boolean signPdf(File pdfFile, File signedPdfFile)
			throws IOException, DocumentException, GeneralSecurityException {
		log.info("signPdf PDDcoument");
		OcspClient ocspClient = new OcspClientBouncyCastle();
		TSAClientBouncyCastle tsaClient = null;
		for (int i = 0; i < certificateChain.length; i++) {
			X509Certificate cert = (X509Certificate) certificateChain[i];
			String tsaUrl = CertificateUtil.getTSAURL(cert);
			if (tsaUrl != null) {
				log.info("TSA Url : " + tsaUrl);
				tsaClient = new TSAClientBouncyCastle(tsaUrl);
				break;
			}
		}
		List<CrlClient> crlList = new ArrayList<CrlClient>();
		crlList.add(new CrlClientOnline(certificateChain));
		char pdfVersion = '\0';
		PdfReader pdfReader = new PdfReader(pdfFile.getPath());
		FileOutputStream os = new FileOutputStream(signedPdfFile.getPath());
		PdfStamper stamper = PdfStamper.createSignature(pdfReader, os, pdfVersion);
		PdfSignatureAppearance signatureAppearance = stamper.getSignatureAppearance();
//        signatureAppearance.setReason("");
//        signatureAppearance.setLocation("");
//        signatureAppearance.setVisibleSignature(new Rectangle(36,748,144,780), 1, "Sig");
		// Creatring the signature
		ExternalSignature externalSignature = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256,
				providername);
		ExternalDigest externalDigest = new BouncyCastleDigest();
		MakeSignature.signDetached(signatureAppearance, externalDigest, externalSignature, certificateChain, crlList,
				ocspClient, tsaClient, 0, CryptoStandard.CMS);
		return true;

	}
	
   public void generateKeyStore( Provider p , String password , String key ) { 
	  
	   try {
		keyGen = KeyGenerator.getInstance("DES", p);
		keyGen.init(56);
		desKey = keyGen.generateKey();
		try {
			keyStore.setKeyEntry( key, desKey , null, (java.security.cert.Certificate[]) null);
			if (keyStore.containsAlias(key)) {
				try {
					privateKey = (PrivateKey) keyStore.getKey(key, password.toCharArray());
				} catch (UnrecoverableKeyException e) {
					// TODO Auto-generated catch block
					log.error(e.getMessage());
				}
				certificateChain = keyStore.getCertificateChain(key);
				certificate = keyStore.getCertificate(key);
				try {
					keyStorePrivateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(key,
							new KeyStore.PasswordProtection(password.toCharArray()));
				} catch (UnrecoverableEntryException e) {
					// TODO Auto-generated catch block
					log.error(e.getMessage());
				}
				x509Certificate = (X509Certificate) keyStorePrivateKeyEntry.getCertificate();
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			log.error(e.getMessage());
		}
		
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		log.error(e.getMessage());
	}
	   
   }
   
   public void deleteKeyEntry(String key) {
	   try {
		keyStore.deleteEntry(key);
	} catch (KeyStoreException e) {
		// TODO Auto-generated catch block
		log.error(e.getMessage());
	}
   }

}
