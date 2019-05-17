package com.zygen.etax.repo;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EtaxSignature implements SignatureInterface {
	
	private static final Logger log = LoggerFactory.getLogger(EtaxSignature.class);
	
	private Certificate certificate;
	private Certificate[] certificateChain;
	private PrivateKey privateKey;
	
	public EtaxSignature(Certificate certificate , Certificate[] certificateChain , PrivateKey privateKey) {
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.privateKey = privateKey;
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
