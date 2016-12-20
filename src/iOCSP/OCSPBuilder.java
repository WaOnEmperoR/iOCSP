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
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Rachmawan
 */
public class OCSPBuilder {

    public OCSPBuilder() {

    }

    public OCSPRequest buildRequest(byte[] pub_key, byte[] issuer_name, BigInteger serialNumber) {
        //Add provider BC 
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        //Certificate Serial Number 
        ASN1Integer ASN1_SN = new ASN1Integer(serialNumber);
        //OID for SHA-1
        ASN1ObjectIdentifier myObjAlg = new ASN1ObjectIdentifier("1.3.14.3.2.26");
        AlgorithmIdentifier alg_id = new AlgorithmIdentifier(myObjAlg);

        try {
            org.jasn.DerEncoder de_issuer_name = new org.jasn.DerEncoder();
            org.jasn.DerEncoder de_public_key = new org.jasn.DerEncoder();

            de_issuer_name.encodeOctetString(issuer_name);
            de_public_key.encodeOctetString(pub_key);

            ByteArrayOutputStream baos_1 = new ByteArrayOutputStream();
            de_issuer_name.writeTo(baos_1);
            byte[] der_byte_issuer_name = baos_1.toByteArray();

            ByteArrayOutputStream baos_2 = new ByteArrayOutputStream();
            de_public_key.writeTo(baos_2);
            byte[] der_byte_public_key = baos_2.toByteArray();

            ASN1InputStream stream_issuer_name = new ASN1InputStream(der_byte_issuer_name);
            ASN1InputStream stream_public_key = new ASN1InputStream(der_byte_public_key);

            ASN1Encodable asn1_issuer_name = (ASN1Encodable) stream_issuer_name.readObject();
            ASN1Encodable asn1_public_key = (ASN1Encodable) stream_public_key.readObject();

            ASN1Primitive prim_issuer_name = asn1_issuer_name.toASN1Primitive();
            ASN1Primitive prim_public_key = asn1_public_key.toASN1Primitive();

            ASN1OctetString octs_issuer_name = (ASN1OctetString) prim_issuer_name;
            ASN1OctetString octs_public_key = (ASN1OctetString) prim_public_key;

            CertID c1 = new CertID(alg_id, octs_public_key, octs_issuer_name, ASN1_SN);
            byte[] hasil = (c1.toASN1Primitive().getEncoded("DER"));

            Request r1 = new Request(c1, null);

            ASN1EncodableVector req_vector = new ASN1EncodableVector();
            req_vector.add(r1);

            ASN1Sequence req_seq = (ASN1Sequence) new DERSequence(req_vector);

            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

            ASN1ObjectIdentifier nonce_obj = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2");
            Extension[] ext_arr = new Extension[1];
            ext_arr[0] = new Extension(nonce_obj, false, Base64.encode(nonce.toByteArray()));

            Extensions exts = new Extensions(ext_arr);
            TBSRequest tbsRequest = new TBSRequest(null, req_seq, exts);
            OCSPRequest ocspReq = new OCSPRequest(tbsRequest, null);

            UUID uuid1 = UUID.randomUUID();
            System.out.println(uuid1);

            try (FileOutputStream fileOuputStream = new FileOutputStream("Request_" + uuid1 + ".DER")) {
                fileOuputStream.write(ocspReq.getEncoded("DER"));
            }
            System.out.println("==============================");
            
            return ocspReq;
        } catch (IOException ex) {
            Logger.getLogger(OCSPBuilder.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null;
    }

}
