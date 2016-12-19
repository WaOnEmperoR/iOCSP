/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package iOCSP;

import java.util.Enumeration;

/**
 *
 * @author Rachmawan
 */

public class ASN1StringBuilder {
   
    private byte[] message;
    private EnumFormat choice;
        
    public ASN1StringBuilder(byte[] msg, EnumFormat myChoice)
    {
        this.message = msg;
        this.choice = myChoice;
    }
    
    public Object Convert()
    {
        return null;
    }
    
    
}
