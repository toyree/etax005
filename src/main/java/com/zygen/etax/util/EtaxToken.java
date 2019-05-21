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

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

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
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.SunPKCS11;

@Component
public class EtaxToken {

	private static final Logger log = LoggerFactory.getLogger(EtaxToken.class);
	private PrivateKey privateKey;
	private Certificate certificate;
	private Certificate[] certificateChain;
	private KeyStore keyStore;
	private String providerName;
	private XadesSigner xadesSigner;
	private KeyStore.PrivateKeyEntry keyStorePrivateKeyEntry;
	private X509Certificate x509Certificate;
	private AuthProvider authProvider;

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

	public String getProviderName() {
		return providerName;
	}

	public void setProviderName(String providerName) {
		this.providerName = providerName;
	}

	public KeyStore.PrivateKeyEntry getKeyStorePrivateKeyEntry() {
		return keyStorePrivateKeyEntry;
	}

	public void setKeyStorePrivateKeyEntry(KeyStore.PrivateKeyEntry keyStorePrivateKeyEntry) {
		this.keyStorePrivateKeyEntry = keyStorePrivateKeyEntry;
	}

	public X509Certificate getX509Certificate() {
		return x509Certificate;
	}

	public void setX509Certificate(X509Certificate x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

	public AuthProvider getAuthProvider() {
		return authProvider;
	}

	public void setAuthProvider(AuthProvider authProvider) {
		this.authProvider = authProvider;
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
//			log.info(cfg.toString());
			InputStream isCfg = new ByteArrayInputStream(cfg.toString().getBytes());
			Provider p = new SunPKCS11(isCfg);
			Security.addProvider(p);
//			PKCS11 pkcs11 = PKCS11.getInstance(((SunPKCS11) p).getProperty(lib),
//					null, null, true);
//			pkcs11.C_Finalize(PKCS11Constants.NULL_PTR);
			providerName = p.getName();
			keyStore = KeyStore.getInstance(type, p);
			keyStore.load(null, password.toCharArray());
			authProvider = (AuthProvider) keyStore.getProvider();
			authProvider.login(new Subject(), new PasswordCallBackHandler());
			log.info(authProvider.getName() + " Login success!!");
			String alias = keyStore.aliases().nextElement();
//			log.info("Alias : " + alias);
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
//			log.info("Algorithm : " + privateKey.getAlgorithm());
			certificateChain = keyStore.getCertificateChain(alias);
			certificate = keyStore.getCertificate(alias);
//			log.info(certificate.toString());
			keyStorePrivateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
					new KeyStore.PasswordProtection(password.toCharArray()));
			x509Certificate = (X509Certificate) keyStorePrivateKeyEntry.getCertificate();
			// XML
//			AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx();
//			KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(lib, providername,
//					Integer.parseInt(slot), new FirstCertificateSelector(), new DirectPasswordProvider(password), null,
//					false);
//			XadesSigningProfile xadesSigningProfile = new XadesBesSigningProfile(keyingProvider);
//			xadesSigningProfile.withAlgorithmsProviderEx(ap);
//			xadesSigner = xadesSigningProfile.newSigner();
//			List<X509Certificate> lstX509Cert = keyingProvider.getSigningCertificateChain();
//			for(int i = 0 ; i <= lstX509Cert.size();i++) {
//				X509Certificate certificate = lstX509Cert.get(i);
//				log.info(certificate.toString());
//			}
		} else {
			throw new Exception("PK Type Not support");
		}
	}
	
	@PreDestroy
	public void shutdown(){
		try {
			authProvider.logout();
			log.info(authProvider.getName() + " Logout success!!");
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			log.error(e.getMessage());
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
