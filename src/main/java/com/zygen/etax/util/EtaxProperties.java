package com.zygen.etax.util;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pk")
public class EtaxProperties {
	
	private static final Logger log = LoggerFactory.getLogger(EtaxProperties.class);
	private String type;
	private String cs11_lib_path;
	private String cs11_slot_id;
	private String cs11_provider_name;
	private String cs11_password;
	private String cs12_path;
	private String cs12_password;
	private String verify_input_path;
	private String trust_store_type;
	private String trust_store_path;
	private String trust_store_password;
	private String cert_store_dir;
	private String temp_file_path;
	private String colorProfile;
	private String docType;
	private String docVersion;
	private String xmpTemplatePath;
	
	@PostConstruct
	public void init(){
		log.info("EtaxProperties Initiated");
		log.info(this.toString());
	}
	
	public String getType() {
		return type;
	}
	
	public void setType(String type) {
		this.type = type;
	}

	public String getCs11_lib_path() {
		return cs11_lib_path;
	}

	public void setCs11_lib_path(String cs11_lib_path) {
		this.cs11_lib_path = cs11_lib_path;
	}

	public String getCs11_slot_id() {
		return cs11_slot_id;
	}

	public void setCs11_slot_id(String cs11_slot_id) {
		this.cs11_slot_id = cs11_slot_id;
	}

	public String getCs11_provider_name() {
		return cs11_provider_name;
	}

	public void setCs11_provider_name(String cs11_provider_name) {
		this.cs11_provider_name = cs11_provider_name;
	}

	public String getCs11_password() {
		return cs11_password;
	}

	public void setCs11_password(String cs11_password) {
		this.cs11_password = cs11_password;
	}

	public String getCs12_path() {
		return cs12_path;
	}

	public void setCs12_path(String cs12_path) {
		this.cs12_path = cs12_path;
	}

	public String getCs12_password() {
		return cs12_password;
	}

	public void setCs12_password(String cs12_password) {
		this.cs12_password = cs12_password;
	}

	public String getVerify_input_path() {
		return verify_input_path;
	}

	public void setVerify_input_path(String verify_input_path) {
		this.verify_input_path = verify_input_path;
	}

	public String getTrust_store_type() {
		return trust_store_type;
	}

	public void setTrust_store_type(String trust_store_type) {
		this.trust_store_type = trust_store_type;
	}

	public String getTrust_store_path() {
		return trust_store_path;
	}

	public void setTrust_store_path(String trust_store_path) {
		this.trust_store_path = trust_store_path;
	}

	public String getTrust_store_password() {
		return trust_store_password;
	}

	public void setTrust_store_password(String trust_store_password) {
		this.trust_store_password = trust_store_password;
	}

	public String getCert_store_dir() {
		return cert_store_dir;
	}

	public void setCert_store_dir(String cert_store_dir) {
		this.cert_store_dir = cert_store_dir;
	}

	public String getTemp_file_path() {
		return temp_file_path;
	}

	public void setTemp_file_path(String temp_file_path) {
		this.temp_file_path = temp_file_path;
	}

	public String getColorProfile() {
		return colorProfile;
	}

	public void setColorProfile(String colorProfile) {
		this.colorProfile = colorProfile;
	}

	public String getDocType() {
		return docType;
	}

	public void setDocType(String docType) {
		this.docType = docType;
	}

	public String getDocVersion() {
		return docVersion;
	}

	public void setDocVersion(String docVersion) {
		this.docVersion = docVersion;
	}

	public String getXmpTemplatePath() {
		return xmpTemplatePath;
	}

	public void setXmpTemplatePath(String xmpTemplatePath) {
		this.xmpTemplatePath = xmpTemplatePath;
	}

	@Override
	public String toString() {
		return "EtaxProperties [type=" + type + ", cs11_lib_path=" + cs11_lib_path + ", cs11_slot_id=" + cs11_slot_id
				+ ", cs11_provider_name=" + cs11_provider_name + ", cs11_password=" + cs11_password + ", cs12_path="
				+ cs12_path + ", cs12_password=" + cs12_password + ", verify_input_path=" + verify_input_path
				+ ", trust_store_type=" + trust_store_type + ", trust_store_path=" + trust_store_path
				+ ", trust_store_password=" + trust_store_password + ", cert_store_dir=" + cert_store_dir
				+ ", temp_file_path=" + temp_file_path + ", colorProfile=" + colorProfile + ", docType=" + docType
				+ ", docVersion=" + docVersion + ", xmpTemplatePath=" + xmpTemplatePath + "]";
	}

}
