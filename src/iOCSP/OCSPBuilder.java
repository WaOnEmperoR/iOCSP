/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package iOCSP;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.Calendar;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.util.encoders.Hex;
import org.jasn.BitString;
import org.jasn.ObjectIdentifier;

/**
 *
 * @author Rachmawan
 */
public class OCSPBuilder {

    public OCSPBuilder() {

    }

    public void buildRequest(byte[] pub_key, byte[] issuer_name, BigInteger serialNumber) {
        //Add provider BC 
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        //Certificate Serial Number 
        ASN1Integer ASN1_SN = new ASN1Integer(serialNumber);
        //OID for SHA-1
        ASN1ObjectIdentifier myObjAlg = new ASN1ObjectIdentifier("1.3.14.3.2.26");
        AlgorithmIdentifier alg_id = new AlgorithmIdentifier(myObjAlg);

        try {
            
            
//            ASN1InputStream stream_issuer_name = new ASN1InputStream(issuer_name);
//            ASN1InputStream stream_public_key = new ASN1InputStream(pub_key);
           
            org.jasn.DerEncoder de_issuer_name = new org.jasn.DerEncoder();
            org.jasn.DerEncoder de_public_key = new org.jasn.DerEncoder();
            
            de_issuer_name.encodeBitString(issuer_name);
            de_public_key.encodeBitString(pub_key);
            
            ByteArrayOutputStream baos_1 = new ByteArrayOutputStream();
            de_issuer_name.writeTo(baos_1);
            byte[] der_byte_issuer_name = baos_1.toByteArray();
            
            ByteArrayOutputStream baos_2 = new ByteArrayOutputStream();
            de_public_key.writeTo(baos_2);
            byte[] der_byte_public_key = baos_2.toByteArray();
            
            ASN1InputStream stream_issuer_name = new ASN1InputStream(der_byte_issuer_name);
            ASN1InputStream stream_public_key = new ASN1InputStream(der_byte_public_key);
            
            ASN1OctetString octs_issuer_name = (ASN1OctetString) stream_issuer_name.readObject();
            ASN1OctetString octs_public_key = (ASN1OctetString) stream_public_key.readObject();
            
            CertID c1 = new CertID(alg_id, octs_issuer_name, octs_public_key, ASN1_SN);
            byte[] hasil = (c1.toASN1Primitive().getEncoded("DER"));

            Request r1 = new Request(c1, null);
            
            UUID uuid1 = UUID.randomUUID();

            try (FileOutputStream fileOuputStream = new FileOutputStream("Request_" + uuid1 + ".DER")) {
                fileOuputStream.write(r1.getEncoded("DER"));
            }
            System.out.println("==============================");
        } catch (IOException ex) {
            Logger.getLogger(OCSPBuilder.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    
}
