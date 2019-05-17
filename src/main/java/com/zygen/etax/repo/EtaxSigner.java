package com.zygen.etax.repo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.tls.CertificateURL;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
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
//import com.zygen.etax.sats.DssHelper;
//import com.zygen.etax.sats.TSAClient;
import com.zygen.etax.util.EtaxFileService;

import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.properties.DataObjectDesc;

public class EtaxSigner{

	private static final Logger log = LoggerFactory.getLogger(EtaxSigner.class);
	private XadesSigner xadesSigner;
	private PrivateKey privateKey;
	private Certificate certificate;
	private TSAClient tsaClient;
	private Certificate[] certificateChain;
	private KeyStore keyStore;
	private String providername;

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

	public void setXadesSigner(XadesSigner xadesSigner) {
		this.xadesSigner = xadesSigner;
	}
	
	public void setProvidername(String providername) {
		this.providername = providername;
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
			Document sourceDoc = dbf.newDocumentBuilder().parse(inputXml);
			Element elementToSign = sourceDoc.getDocumentElement();
			if (elementToSign.hasAttribute("Id")) {
				refUri = '#' + elementToSign.getAttribute("Id");
			} else {
				if (elementToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE) {
					outputStream.close();
					EtaxFileService.deleteTempFile(tempPath);
					throw new IllegalArgumentException("Element without Id must be the document root");
				}
				refUri = "";
			}
			DataObjectDesc dataObjRef = new DataObjectReference(refUri)
					.withTransform(new EnvelopedSignatureTransform());
			log.info("Create Signer Data Object");
			XadesSignatureResult result = xadesSigner.sign(new SignedDataObjects(dataObjRef),
					sourceDoc.getDocumentElement());
			log.info("Get XML Signature");
			XMLSignature signature = result.getSignature();
			Document docs = signature.getDocument();
			XMLUtils.outputDOM(docs, outputStream);
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
			log.info(e.getMessage());
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

	private boolean signPdf(File pdfFile, File signedPdfFile) throws IOException, DocumentException, GeneralSecurityException {
		log.info("signPdf PDDcoument");
		OcspClient ocspClient = new OcspClientBouncyCastle();
		TSAClientBouncyCastle tsaClient = null;
        for (int i = 0; i < certificateChain.length; i++) {
        	X509Certificate cert = (X509Certificate)certificateChain[i];
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
        //Creatring the signature
        ExternalSignature externalSignature = new PrivateKeySignature( privateKey, DigestAlgorithms.SHA256 , providername);
        ExternalDigest externalDigest = new BouncyCastleDigest();
        MakeSignature.signDetached(signatureAppearance, externalDigest, externalSignature,certificateChain, crlList, ocspClient,tsaClient,0,CryptoStandard.CMS);
		return true;
		
	}
	
}
