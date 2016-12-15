/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package iOCSP;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

/**
 *
 * @author Rachmawan
 */
public class IOtentikOCSP {

    private static final boolean debug = true; 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        ReadP12("D:\\Tugas PTIK\\Certificate Authority\\Study PKI\\ajinorev.p12", "aji123456");
    }
    
    public static void ReadP12(String filename, String password){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
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
                if (debug){
                    System.out.println("alias name: " + alias);
                }
                
                PrivateKey key = (PrivateKey) my_KS.getKey(alias, password.toCharArray());
                
                java.security.cert.Certificate[] cchain = my_KS.getCertificateChain(alias);
                
                int chain_idx = 0;
                for (Certificate chain_list : cchain) {
                    X509Certificate c = (X509Certificate) chain_list;
                    org.bouncycastle.asn1.x509.Certificate c2 = org.bouncycastle.asn1.x509.Certificate.getInstance(c.getEncoded());
                    Principal subject = c.getSubjectDN();
                    PublicKey the_PK = c.getPublicKey();
                    
                    if (chain_idx == 0)
                    {
                        serial_number = c.getSerialNumber();
                        
                        if (debug)
                        {
                            System.out.println("Serial Number : " + serial_number);
                        }
                    }
                    else if (chain_idx==1)
                    {
                        PublicKey rsaPk = c.getPublicKey();
                        
                        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(rsaPk.getEncoded());

                        BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();
                        String algOID = "1.3.14.3.2.26"; // SHA-1
                        DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(algOID)));

                        X509CertificateHolder hold = new X509CertificateHolder(c2);
                        CertificateID id = new CertificateID(hashCalculator, hold, c.getSerialNumber());
                        
                        issuerKeyHash = id.getIssuerKeyHash();
                        issuerNameHash = id.getIssuerNameHash();
                        
                        if (debug)
                        {
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
        
        ob.buildRequest(issuerNameHash, issuerKeyHash, serial_number);
    }
    
}