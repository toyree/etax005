package com.zygen.etax.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

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
//	private String providerName;
//	private KeyStore.PrivateKeyEntry keyStorePrivateKeyEntry;
//	private X509Certificate x509Certificate;
//	private AuthProvider authProvider;
	private static Provider provider;
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

	public Provider getProvider() {
		return provider;
	}

	public void setProvider(Provider provider) {
		this.provider = provider;
	}

	public static void getConnection(String name, String slot, String lib, String type, String password)
			throws Exception {

		if (type.contains("PKCS11")) {
			StringBuilder cfg = new StringBuilder();
			cfg.append("name=" + name);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("slot=" + slot);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("library=" + lib);
			cfg.append(System.getProperty("line.separator"));
			cfg.append("description=Luna config");
			cfg.append(System.getProperty("line.separator"));
			cfg.append("attributes(*,*,*)= { CKA_TOKEN = true }");
			cfg.append(System.getProperty("line.separator"));
			cfg.append(
					"attributes(*,CKO_SECRET_KEY,*)= { CKA_CLASS=4 CKA_PRIVATE= true CKA_KEY_TYPE = 21 CKA_SENSITIVE= true CKA_ENCRYPT= true CKA_DECRYPT= true CKA_WRAP= true CKA_UNWRAP= true }");
			cfg.append(System.getProperty("line.separator"));
			cfg.append(
					"attributes(*,CKO_PRIVATE_KEY,*)= { CKA_CLASS=3 CKA_LABEL=true CKA_PRIVATE = true CKA_DECRYPT=true CKA_SIGN=true CKA_UNWRAP=true }");
			cfg.append(System.getProperty("line.separator"));
			cfg.append(
					"attributes(*,CKO_PUBLIC_KEY,*)= { CKA_CLASS=2 CKA_LABEL=true CKA_ENCRYPT = true CKA_VERIFY=true CKA_WRAP=true }");
			cfg.append(System.getProperty("line.separator"));
			cfg.append("disabledMechanisms = {");
			cfg.append(System.getProperty("line.separator"));
			cfg.append("CKM_SHA1_RSA_PKCS");
			cfg.append(System.getProperty("line.separator"));
			cfg.append("}");
			ByteArrayInputStream isCfg = new ByteArrayInputStream(cfg.toString().getBytes());
			provider = new SunPKCS11(isCfg);
			provider.setProperty("pkcs11LibraryPath", lib);
			Security.addProvider(provider);

			Provider[] providerList = Security.getProviders();
			for (int i = 0; i < providerList.length; i++) {
				log.info("[" + (i + 1) + "] - Provider name: " + providerList[i].getName());
				log.info("Provider version number: " + providerList[i].getVersion());
				log.info("Provider information:\n" + providerList[i].getInfo());
			}

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
