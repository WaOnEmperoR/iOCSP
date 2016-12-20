/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package iOCSP;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;

/**
 *
 * @author Rachmawan
 */
public class OCSPReader {

    private final String[] revocationReasons = {"unspecified", "keyCompromise", "CACompromise", "affiliationChanged",
    "superseded", "cessationOfOperation", "certificateHold", "UNUSED_REASON", "removeFromCRL", "privilegeWithdrawn", "AACompromise" }; 
    
    public OCSPReader() {

    }

    public byte[] getEncoded(OCSPRequest request, String url) throws OCSPException {
        byte[] array = null;
        try {
            array = request.getEncoded();
            URL urlt = new URL(url);
            HttpURLConnection con = (HttpURLConnection) urlt.openConnection();
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoOutput(true);
            OutputStream out = con.getOutputStream();
            try (DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out))) {
                dataOut.write(array);
                dataOut.flush();
            }
            if (con.getResponseCode() / 100 != 2) {
                throw new IOException(String.valueOf(con.getResponseCode()));
            }

            //Get Response 
            InputStream in = (InputStream) con.getContent();
            OCSPResp ocspResponse = new OCSPResp(in);

            if (ocspResponse.getStatus() != 0) {
                throw new IOException(String.valueOf(ocspResponse.getStatus()));
            }
            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
            if (basicResponse != null) {
                SingleResp[] responses = basicResponse.getResponses();
                if (responses.length == 1) {
                    SingleResp resp = responses[0];
                    Object status = resp.getCertStatus();

                    if (status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                        System.out.println("Certificate is Good");
                        return basicResponse.getEncoded();
                    } else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
                        org.bouncycastle.cert.ocsp.RevokedStatus mystat = (org.bouncycastle.cert.ocsp.RevokedStatus) status;
                        System.out.println("Certificate is Revoked, Reason : " + revocationReasons[mystat.getRevocationReason()]);
                        System.out.println("Revocation Time : " + mystat.getRevocationTime());
                        
                        throw new IOException("ocsp.status.is.revoked");
                    } else {
                        System.out.println("Certificate Status is Unknown");
                        throw new IOException("ocsp.status.is.unknown");
                    }
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(OCSPReader.class.getName()).log(Level.SEVERE, null, ex);
        }

        return array;
    }

}
