package com.zygen.etax.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.annotation.PostConstruct;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

import sun.security.pkcs11.SunPKCS11;

@Component
public class EtaxToken {

	private static final Logger log = LoggerFactory.getLogger(EtaxToken.class);
//	private PrivateKey privateKey;
//	private Certificate certificate;
//	private Certificate[] certificateChain;
	private KeyStore keyStore;
//	private String providerName;
//	private KeyStore.PrivateKeyEntry keyStorePrivateKeyEntry;
//	private X509Certificate x509Certificate;
//	private AuthProvider authProvider;
	private Provider provider;
//	private String alias;

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

	public EtaxProperties getEtaxProperties() {
		return etaxProperties;
	}

	public void setEtaxProperties(EtaxProperties etaxProperties) {
		this.etaxProperties = etaxProperties;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}
	
	public Provider getProvider() {
		return provider;
	}

	public void setProvider(Provider provider) {
		this.provider = provider;
	}

	public void getConnection(String name, String slot, String lib, String type, String password) throws Exception {
		if (type.contains("PKCS11")) {
			StringBuilder cfg = new StringBuilder();
			cfg.append("name=" + name);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("slot=" + slot);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("library=" + lib);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("disabledMechanisms = {");
			cfg.append(System.getProperty("line.separator"));
			cfg.append("CKM_SHA1_RSA_PKCS");
			cfg.append(System.getProperty("line.separator"));
			cfg.append("}");
			InputStream isCfg = new ByteArrayInputStream(cfg.toString().getBytes());
			//Provider p = new SunPKCS11(isCfg);
			provider = new SunPKCS11(isCfg);
			provider.setProperty("pkcs11LibraryPath", lib);
			Security.addProvider(provider);
			keyStore = KeyStore.getInstance(type, provider);
			keyStore.load(null, password.toCharArray());

//			PKCS11 pkcs11 = PKCS11.getInstance(((sun.security.pkcs11.SunPKCS11) p).getProperty("pkcs11LibraryPath"),
//					null, null, true);
//			log.info("Set C_Finalize");
//			pkcs11.
//			pkcs11.C_Finalize(PKCS11Constants.NULL_PTR);
/*
			authProvider = (AuthProvider) keyStore.getProvider();
			//String alias = keyStore.aliases().nextElement();
			alias = keyStore.aliases().nextElement();
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			certificateChain = keyStore.getCertificateChain(alias);
			certificate = keyStore.getCertificate(alias);
			keyStorePrivateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
					new KeyStore.PasswordProtection(password.toCharArray()));
			x509Certificate = (X509Certificate) keyStorePrivateKeyEntry.getCertificate();
*/
		} else {
			throw new Exception("PK Type Not support");
		}
	}

	public class PasswordCallBackHandler implements CallbackHandler {

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			if (!(callbacks[0] instanceof PasswordCallback)) {
				throw new UnsupportedCallbackException(callbacks[0]);
			}
			PasswordCallback pc = (PasswordCallback) callbacks[0];
			pc.setPassword(etaxProperties.getCs11_password().toCharArray());
		}

	}

}
