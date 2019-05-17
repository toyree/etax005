package com.zygen.etax.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;

@Component
public class EtaxToken {

	private static final Logger log = LoggerFactory.getLogger(EtaxToken.class);
	private PrivateKey privateKey;
	private Certificate certificate;
	private Certificate[] certificateChain;
	private KeyStore keyStore;
	private XadesSigner xadesSigner;

	@Autowired
	private EtaxProperties etaxProperties;

	@Autowired
	private ConfigurableApplicationContext ctx;

	@PostConstruct
	public void init() {

		log.info("EtaxToken Initiated");

		try {
			getConnection(etaxProperties.getCs11_provider_name(), etaxProperties.getCs11_slot_id(),
					etaxProperties.getCs11_lib_path(), etaxProperties.getType(), etaxProperties.getCs11_password());
		} catch (Exception e) {
			log.error(e.getMessage());
			ctx.close();
		}
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}

	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(Certificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	public EtaxProperties getEtaxProperties() {
		return etaxProperties;
	}

	public void setEtaxProperties(EtaxProperties etaxProperties) {
		this.etaxProperties = etaxProperties;
	}

	public XadesSigner getXadesSigner() {
		return xadesSigner;
	}

	public void setXadesSigner(XadesSigner xadesSigner) {
		this.xadesSigner = xadesSigner;
	}

	public void getConnection(String providername, String slot, String lib, String type, String password)
			throws Exception {
		log.info("pdfGetProvider");

		if (type.contains("PKCS11")) {
			// PDF
			StringBuilder cfg = new StringBuilder();
			cfg.append("name=" + providername);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("slot=" + slot);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("library=" + lib);
			InputStream isCfg = new ByteArrayInputStream(cfg.toString().getBytes(StandardCharsets.UTF_8));
			Provider p = new sun.security.pkcs11.SunPKCS11(isCfg);
			Security.addProvider(p);
			keyStore = KeyStore.getInstance(type, p);
			keyStore.load(null, password.toCharArray());
			String alias = keyStore.aliases().nextElement();
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			certificateChain = keyStore.getCertificateChain(alias);
			certificate = keyStore.getCertificate(alias);
			// XML
			AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx();
			KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(lib, providername,
					Integer.parseInt(slot), new FirstCertificateSelector(), new DirectPasswordProvider(password), null,
					false);
			XadesSigningProfile xadesSigningProfile = new XadesBesSigningProfile(keyingProvider);
			xadesSigningProfile.withAlgorithmsProviderEx(ap);
			xadesSigner = xadesSigningProfile.newSigner();
		} else {
			throw new Exception("PK Type Not support");
		}
	}

}
