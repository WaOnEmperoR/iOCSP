/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package iOCSP;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 *
 * @author Rachmawan
 */
public class IOtentikOCSP {

    private static final boolean debug = true;

    /**
     * @param args the command line arguments
     * @throws org.bouncycastle.cert.ocsp.OCSPException
     * @throws java.io.FileNotFoundException
     */
    public static void main(String[] args) throws OCSPException, FileNotFoundException {
        // TODO code application logic here
        //ReadP12("D:\\Tugas PTIK\\Certificate Authority\\Study PKI\\ajinorev_Backup.p12", "aji123456");
        ReadP12("D:\\Tugas PTIK\\Certificate Authority\\Study PKI\\ajirev.p12", "aji123456");
    }

    public static void ReadP12(String filename, String password) throws OCSPException, FileNotFoundException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String ocsp_str = "";
        PublicKey issuerPublicKey = null;
        
        byte[] issuerKeyHash = null, issuerNameHash = null;
        BigInteger serial_number = new BigInteger("0");

        KeyStore my_KS;
        try {
            my_KS = KeyStore.getInstance("PKCS12");
            File f = new File(filename);
            FileInputStream is = new FileInputStream(f);
            my_KS.load(is, password.toCharArray());

            BigInteger bi_serial = new BigInteger("0");
            Enumeration enumeration = my_KS.aliases();

            while (enumeration.hasMoreElements()) {
                String alias = (String) enumeration.nextElement();
                if (debug) {
                    System.out.println("alias name: " + alias);
                }

                PrivateKey key = (PrivateKey) my_KS.getKey(alias, password.toCharArray());

                java.security.cert.Certificate[] cchain = my_KS.getCertificateChain(alias);

                //Assuming that chaining is bottom-up, meaning that certificate[0] is user cert,
                //certificate[1] is issuer cert(intermediate CA), and certificate[2] is root CA cert
                int chain_idx = 0;
                for (Certificate chain_list : cchain) {
                    X509Certificate c = (X509Certificate) chain_list;
                    org.bouncycastle.asn1.x509.Certificate c2 = org.bouncycastle.asn1.x509.Certificate.getInstance(c.getEncoded());
                    
                    if (chain_idx == 0) {
                        serial_number = c.getSerialNumber();
                        ocsp_str = getOCSPPath(c);
                        
                        if (debug) {
                            System.out.println("Serial Number : " + serial_number);
                            System.out.println("OCSP : " + ocsp_str);
                        }
                    } else if (chain_idx == 1) {
                        issuerPublicKey = c.getPublicKey();

                        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(issuerPublicKey.getEncoded());

                        BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();
                        String algOID = "1.3.14.3.2.26"; // SHA-1
                        DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(algOID)));

                        X509CertificateHolder hold = new X509CertificateHolder(c2);
                        CertificateID id = new CertificateID(hashCalculator, hold, c.getSerialNumber());

                        issuerKeyHash = id.getIssuerKeyHash();
                        issuerNameHash = id.getIssuerNameHash();

                        if (debug) {
                            System.out.println("Issuer Key Hash : " + Hex.encodeHexString(id.getIssuerKeyHash()));
                            System.out.println("Issuter Name Hash : " + Hex.encodeHexString(id.getIssuerNameHash()));
                        }
                    } 
                    chain_idx++;
                }
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | OperatorCreationException | OCSPException ex) {
            Logger.getLogger(IOtentikOCSP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(IOtentikOCSP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(IOtentikOCSP.class.getName()).log(Level.SEVERE, null, ex);
        }

        OCSPBuilder ob = new OCSPBuilder();

        UUID uuid1 = UUID.randomUUID();
        if (debug)
        {
            System.out.println(uuid1);
        }
        
        OCSPRequest myRequest = ob.buildRequest(issuerNameHash, issuerKeyHash, serial_number, uuid1);

        OCSPReader reader = new OCSPReader();

        if (ocsp_str.equals(""))
        {
            ocsp_str = "http://rootca.bppt.go.id/ejbca/publicweb/status/ocsp";
        }
        byte[] ocspRep = reader.getEncoded(myRequest, ocsp_str, issuerPublicKey );
        
        try (FileOutputStream fileOuputStream = new FileOutputStream("Response_" + uuid1 + ".DER")) {
            fileOuputStream.write(ocspRep);
        }
        catch(IOException ex)
        {
            System.out.println(ex.getMessage());
        }
        System.out.println("==============================");
    }

    private static String getOCSPPath(X509Certificate cert) {
        String ocspPath = "";

        byte[] authInfoAccessExt = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");

        try {
            ASN1Sequence asn1Seq = (ASN1Sequence) X509ExtensionUtil.fromExtensionValue(authInfoAccessExt); // AuthorityInfoAccessSyntax
            Enumeration<?> objects = asn1Seq.getObjects();

            while (objects.hasMoreElements()) {
                ASN1Sequence obj = (ASN1Sequence) objects.nextElement();
                ASN1Encodable oid = obj.getObjectAt(0); // accessMethod
                DERTaggedObject location = (DERTaggedObject) obj.getObjectAt(1); // accessLocation

                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    DEROctetString uri = (DEROctetString) location.getObject();
                    ocspPath = new String(uri.getOctets());
                    if (oid.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                        return ocspPath;
                    }
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(IOtentikOCSP.class.getName()).log(Level.SEVERE, null, ex);
        }

        return ocspPath;
    }

}
