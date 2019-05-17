package com.zygen.etax.repo;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
import org.bouncycastle.mail.smime.handlers.pkcs7_mime;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

//import com.zygen.etax.sats.DssHelper;
//import com.zygen.etax.sats.TSAClient;
import com.zygen.etax.util.EtaxFileService;

import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.utils.XadesProfileResolutionException;

public class EtaxSigner implements SignatureInterface {

	private static final Logger log = LoggerFactory.getLogger(EtaxSigner.class);
	private XadesSigner xadesSigner;
	private PrivateKey privateKey;
	private Certificate certificate;
	private TSAClient tsaClient;
	private Certificate[] certificateChain;
	private KeyStore keyStore;

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

	// for XML
//	public void setXadesSigner(String lib, String provider, String slotId, String password)
//			throws NumberFormatException, KeyStoreException, XadesProfileResolutionException {
//		log.info("setXadesSigner");
//		AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx();
//		KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(lib, provider,
//				Integer.parseInt(slotId), new FirstCertificateSelector(), new DirectPasswordProvider(password), null,
//				false);
//		XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
//		p.withAlgorithmsProviderEx(ap);
//		xadesSigner = p.newSigner();
//	}

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

//	public void pdfGetKeyStore(String providername, String slot, String lib, String type, String password)
//			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
//			UnrecoverableKeyException {
//		log.info("pdfGetProvider");
//		StringBuilder cfg = new StringBuilder();
//		cfg.append("name=" + providername);
//		cfg.append(System.getProperty("line.separator"));
//		cfg.append("slot=" + slot);
//		cfg.append(System.getProperty("line.separator"));
//		cfg.append("library=" + lib);
//		InputStream isCfg = new ByteArrayInputStream(cfg.toString().getBytes(StandardCharsets.UTF_8));
//		Provider p = new sun.security.pkcs11.SunPKCS11(isCfg);
//		Security.addProvider(p);
//		keyStore = KeyStore.getInstance(type, p);
//		keyStore.load(null, password.toCharArray());
//		String alias = keyStore.aliases().nextElement();
//		privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
//		certificateChain = keyStore.getCertificateChain(alias);
//		certificate = keyStore.getCertificate(alias);
//	}

	public String signPDF(String pdfPath, String signedPdfPath) {
		log.info("signPDF");
		String signedPDF = new String();
		File inputFile = null;
		File outputFile = null;
		inputFile = new File(pdfPath);
		if (inputFile.exists()) {
			outputFile = new File(signedPdfPath);
			try {
				if (signPdf(inputFile, outputFile)) {
					InputStream isSignedPdf = new FileInputStream(outputFile);
					byte[] signedPdfByte = new byte[isSignedPdf.available()];
					isSignedPdf.read(signedPdfByte, 0, signedPdfByte.length);
					signedPDF = Base64.getEncoder().encodeToString(signedPdfByte);
					isSignedPdf.close();
					outputFile.delete();
				} else {
					if (inputFile.exists()) {
						inputFile.delete();
					}
					if (outputFile.exists()) {
						outputFile.delete();
					}
				}
			} catch (IOException e) {
				log.error(e.getMessage());
			}
		}
		return signedPDF;
	}

	private boolean signPdf(File pdfFile, File signedPdfFile) throws IOException {
		log.info("signPdf PDDcoument");
		PDDocument doc = null;
		try {
			doc = PDDocument.load(pdfFile);
			OutputStream fos = new FileOutputStream(signedPdfFile);
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setSignDate(Calendar.getInstance());

			COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
			catalogDict.setNeedToBeUpdated(true);

			// =========================== For LTV Enable ===========================
			byte[][] certs = new byte[certificateChain.length][];
			for (int i = 0; i < certificateChain.length; i++) {
				certs[i] = certificateChain[i].getEncoded();
			}

			List<CRL> crlList = new DssHelper().readCRLsFromCert((X509Certificate) certificateChain[0]);
			byte[][] crls = new byte[crlList.size()][];
			for (int i = 0; i < crlList.size(); i++) {
				crls[i] = ((X509CRL) crlList.get(i)).getEncoded();
			}

			Iterable<byte[]> certifiates = Arrays.asList(certs);
			COSDictionary dss = new DssHelper().createDssDictionary(certifiates, Arrays.asList(crls), null);
			catalogDict.setItem(COSName.getPDFName("DSS"), dss);
			// =========================== For LTV Enable =========================== */

			// For big certificate chain
			SignatureOptions signatureOptions = new SignatureOptions();
			signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
			doc.addSignature(signature, this, signatureOptions);
			doc.saveIncremental(fos);
			return true;
		} catch (Exception e) {
			log.error(e.getMessage());
			return false;
		} finally {
			if (doc != null) {
				doc.close();
			}
		}

	}

	@Override
	public byte[] sign(InputStream content) throws IOException {
		try {
			log.info("Sign");
			List<Certificate> certList = new ArrayList<>();
			certList.addAll(Arrays.asList(certificateChain));
			@SuppressWarnings("rawtypes")
			Store certStore = new JcaCertStore(certList);
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
					.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
			ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);

			gen.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
							.build(sha512Signer, new X509CertificateHolder(cert)));
			gen.addCertificates(certStore);

			CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
			CMSSignedData signedData = gen.generate(msg, false);
			return signedData.getEncoded();
		} catch (Exception e) {
			log.error(e.getMessage());
			return null;
		}
	}

}
