package com.zygen.etax.xades;

import java.io.InputStream;

public class XadesBesSign {

//	private static final Logger log = LoggerFactory.getLogger(XadesBesSign.class);
	private String sigingConfig;
//	private static Properties prop;
//	private static InputStream config;
//	private static String xmlInput;
//	private static String xmlOutput;
	private String pkType;
	private String pkcs11LibPath;
	private String pkcs11ProviderName;
	private int pkcs11SlotId;
	private String pkcs11Password;
	private String pkcs12Path;
	private String pkcs12Password;
	private String pkTempPath;
//	private static final String CONFIG_FILE_PATH = "src/main/resources/conf/etax-xades.properties";

	public XadesBesSign(String sigingConfig , XadesProperties properties) {
		this.sigingConfig = sigingConfig;
		this.pkType = properties.getType();
		this.pkcs11LibPath = properties.getCs11_lib_path();
		this.pkcs11ProviderName = properties.getCs11_provider_name();
		this.pkcs11SlotId       = Integer.parseInt(properties.getCs11_slot_id());
		this.pkcs11Password     = properties.getCs11_password();
		this.pkcs12Path         = properties.getCs12_path();
		this.pkcs12Password		= properties.getCs12_password();
		this.pkTempPath		 	= properties.getTemp_file_path();
//		loadConfig(CONFIG_FILE_PATH);
	}

//	private static void loadConfig(String configPath) {
//		try {
//			prop = new Properties();
//			config = new FileInputStream(configPath);
//			// load the properties file
//			prop.load(config);
//			xmlInput = prop.getProperty("SIGN_INPUT_PATH");
//			xmlOutput = prop.getProperty("SIGN_OUTPUT_PATH");
//			pkType = prop.getProperty("PK_TYPE");
//			pkcs11LibPath = prop.getProperty("PKCS11_LIB_PATH");
//			pkcs11ProviderName = prop.getProperty("PKCS11_PROVIDER_NAME");
//			pkcs11SlotId = Integer.parseInt(prop.getProperty("PKCS11_SLOT_ID"));
//			pkcs11Password = prop.getProperty("PKCS11_PASSWORD");
//			pkcs12Path = prop.getProperty("PKCS12_PATH");
//			pkcs12Password = prop.getProperty("PKCS12_PASSWORD");
//		} catch (IOException e) {
//			log.info(e.getMessage());
//		}
//	}

	public String getSigingConfig() {
		return sigingConfig;
	}

	public void setSigingConfig(String sigingConfig) {
		this.sigingConfig = sigingConfig;
	}

	public String getPkType() {
		return pkType;
	}

	public void setPkType(String pkType) {
		this.pkType = pkType;
	}

	public String getPkcs11LibPath() {
		return pkcs11LibPath;
	}

	public void setPkcs11LibPath(String pkcs11LibPath) {
		this.pkcs11LibPath = pkcs11LibPath;
	}

	public String getPkcs11ProviderName() {
		return pkcs11ProviderName;
	}

	public void setPkcs11ProviderName(String pkcs11ProviderName) {
		this.pkcs11ProviderName = pkcs11ProviderName;
	}

	public int getPkcs11SlotId() {
		return pkcs11SlotId;
	}

	public void setPkcs11SlotId(int pkcs11SlotId) {
		this.pkcs11SlotId = pkcs11SlotId;
	}

	public String getPkcs11Password() {
		return pkcs11Password;
	}

	public void setPkcs11Password(String pkcs11Password) {
		this.pkcs11Password = pkcs11Password;
	}

	public String getPkcs12Path() {
		return pkcs12Path;
	}

	public void setPkcs12Path(String pkcs12Path) {
		this.pkcs12Path = pkcs12Path;
	}

	public String getPkcs12Password() {
		return pkcs12Password;
	}

	public void setPkcs12Password(String pkcs12Password) {
		this.pkcs12Password = pkcs12Password;
	}
	
	public String getPkTempPath() {
		return pkTempPath;
	}

	public void setPkTempPath(String pkTempPath) {
		this.pkTempPath = pkTempPath;
	}

	public String signXML(InputStream inputXml) throws Exception {
		XadesBesSigner signer = new XadesBesSigner(pkTempPath);
		String outputXml      = new String();
		if (pkType.equals("PKCS11")) {
			// P11 signer
			signer.setSignerPkcs11(pkcs11LibPath, pkcs11ProviderName, pkcs11SlotId, pkcs11Password);
		} else if (pkType.equals("PKCS12")) {
			// P12 signer
			signer.setSignerPkcs12(pkcs12Path, pkcs12Password, pkType);
		} else {
			throw new Exception(this.sigingConfig + " PK_TYPE_not_supported");
		}
		try {
			outputXml = signer.signWithoutIDEnveloped(inputXml);
		} catch (Exception e) {
			throw e;
		}
		return outputXml;
	}
	
	public String signPdf(InputStream inputPdf)throws Exception{
		XadesBesSigner signer = new XadesBesSigner(pkTempPath);
		String outputPdf = new String();
		return outputPdf;
	}
	
}
