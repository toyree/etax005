//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.05.08 at 02:22:11 PM ICT 
//


package com.zygen.etax.model;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="SigningConfigName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PdfBase64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "signingConfigName",
    "pdfBase64"
})
@XmlRootElement(name = "SignPdfRequest")
public class SignPdfRequest {

    @XmlElementRef(name = "SigningConfigName", namespace = "http://model.etax.zygen.com/", type = JAXBElement.class, required = false)
    protected JAXBElement<String> signingConfigName;
    @XmlElementRef(name = "PdfBase64", namespace = "http://model.etax.zygen.com/", type = JAXBElement.class, required = false)
    protected JAXBElement<String> pdfBase64;

    /**
     * Gets the value of the signingConfigName property.
     * 
     * @return
     *     possible object is
     *     {@link JAXBElement }{@code <}{@link String }{@code >}
     *     
     */
    public JAXBElement<String> getSigningConfigName() {
        return signingConfigName;
    }

    /**
     * Sets the value of the signingConfigName property.
     * 
     * @param value
     *     allowed object is
     *     {@link JAXBElement }{@code <}{@link String }{@code >}
     *     
     */
    public void setSigningConfigName(JAXBElement<String> value) {
        this.signingConfigName = value;
    }

    /**
     * Gets the value of the pdfBase64 property.
     * 
     * @return
     *     possible object is
     *     {@link JAXBElement }{@code <}{@link String }{@code >}
     *     
     */
    public JAXBElement<String> getPdfBase64() {
        return pdfBase64;
    }

    /**
     * Sets the value of the pdfBase64 property.
     * 
     * @param value
     *     allowed object is
     *     {@link JAXBElement }{@code <}{@link String }{@code >}
     *     
     */
    public void setPdfBase64(JAXBElement<String> value) {
        this.pdfBase64 = value;
    }

}
