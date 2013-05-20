package com.example.yuibkeypersonalization;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.security.rsa.RSAPrivateKey;
import iaik.security.rsa.RSAPublicKey;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.nfc.tech.NfcF;
import android.nfc.tech.NfcV;
import android.os.Bundle;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import com.example.yuibkeypersonalization.YubiKey;

public class YubikeyPersonalisation extends Activity {

	private byte[] cert_der = null;
	byte[] mod = null;
	byte[] priv_exp,pub_exp = null;
	KeyPair _keypair = null;
	
	private NfcAdapter mAdapter;
	private PendingIntent pendingIntent;
	private IntentFilter[] mFilters;
	private String[][] mTechLists;
	
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_yubikey_personalisation);
        
        mAdapter = NfcAdapter.getDefaultAdapter(this);
		pendingIntent = PendingIntent.getActivity(
		  this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
//		
//		 // Setup an intent filter for all MIME based dispatches
        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        try {
            ndef.addDataType("*/*");
        } catch (MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }
        IntentFilter td = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
        mFilters = new IntentFilter[] {
                ndef, td
        };
//
//        // Setup a tech list for all NfcF tags
        mTechLists = new String[][] { new String[] { 
                NfcV.class.getName(),
                NfcF.class.getName(),
                NfcA.class.getName(),
                NfcB.class.getName()
            } };

		
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.yubikey_personalisation, menu);
        return true;
    }
    
    public void clickedGenCert(View view){
    	 iaik.security.provider.IAIK iaik = new
 	    		iaik.security.provider.IAIK();
 	    iaik.addAsProvider(true);  
 	    KeyPairGenerator keyGen = null;
 		try {
 			keyGen = KeyPairGenerator.getInstance("RSA");
 		} catch (NoSuchAlgorithmException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
         keyGen.initialize(512);
         _keypair = keyGen.generateKeyPair();
         RSAPrivateKey privKey = (RSAPrivateKey) _keypair.getPrivate();
         RSAPublicKey pubKey = (RSAPublicKey) _keypair.getPublic();
         
         BigInteger mod_bi = privKey.getModulus();
         BigInteger exp_bi = privKey.getPrivateExponent();
         BigInteger exp_pub_bi = pubKey.getPublicExponent();
         //Remove sign bytes:
        
        
         mod = Arrays.copyOfRange(mod_bi.toByteArray(),1,mod_bi.toByteArray().length);
         
         priv_exp = Arrays.copyOfRange(exp_bi.toByteArray(),0,exp_bi.toByteArray().length);
         pub_exp = Arrays.copyOfRange(exp_pub_bi.toByteArray(),0,exp_pub_bi.toByteArray().length);
         
         System.out.println("Modulus length"+mod.length);
         System.out.println("Priv Exp length"+priv_exp.length);
         System.out.println("Pub Exp length"+pub_exp.length);
         
         Calendar expiry = Calendar.getInstance();
         expiry.add(Calendar.DAY_OF_YEAR, 360);
  
         Name user = new Name();
         user.addRDN(ObjectID.country, "AT");
         user.addRDN(ObjectID.commonName, "MyName");
         
         Name subject = new Name();
         subject.addRDN(ObjectID.commonName,"SubjectName");
         
         X509Certificate cert = new X509Certificate();
         cert.setSerialNumber(new BigInteger(new byte[]{1,2,3}));
         cert.setSubjectDN(subject);
         try {
 			cert.setPublicKey((java.security.PublicKey) pubKey);
 			cert.setIssuerDN(user);
 			GregorianCalendar date = new GregorianCalendar();
 			date.add(Calendar.DATE, -1);
 			cert.setValidNotBefore(date.getTime());    // not before yesterday
 			cert.setValidNotBefore(date.getTime());
 			
 			date.add(Calendar.MONTH, 6);
 			cert.setValidNotAfter(date.getTime());
 			
 			SubjectKeyIdentifier ski = new SubjectKeyIdentifier((java.security.PublicKey)pubKey);
 			if (ski != null)
 				cert.addExtension(ski);
 			
 			 // weitere Extensions werden hinzugefuegt
// 			if (extensions != null) {
// 				for (int i=0; i<extensions.length; i++)
// 					cert.addExtension(extensions[i]);
// 				}
 			
 			// und schließlich wird das Zertifikat signiert
 			 cert.sign(AlgorithmID.sha1WithRSAEncryption ,(java.security.PrivateKey) privKey);
 			 byte[] fp = cert.getFingerprint();
 			 Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding","IAIK");
 			 cipher.init(Cipher.ENCRYPT_MODE, privKey);

 			 System.out.println(cert.toString());
 			 cert_der = cert.toByteArray();
 			 
 			 System.out.println(new String(cert_der));
 			 
 			 
 		} catch (InvalidKeyException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (CertificateException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (NoSuchAlgorithmException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (X509ExtensionException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (CodingException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (NoSuchProviderException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (NoSuchPaddingException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		} catch (IllegalStateException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
    }
    
    @Override
    public void onResume()
    {
        super.onResume();
        if(mAdapter != null)
        	mAdapter.enableForegroundDispatch(this, pendingIntent, mFilters, mTechLists);
    }
    
    @Override
    public void onPause()
    {
        super.onPause();
        if(mAdapter != null)
        	mAdapter.disableForegroundDispatch(this);
    }
    
    @Override
    public void onNewIntent(Intent intent){
        // fetch the tag from the intent
        Tag tag = (Tag)intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        android.util.Log.v("NFC", "Discovered tag ["+tag+"] with intent: " + intent);
        android.util.Log.v("NFC", "{"+tag+"}");
        
        //here we could register a new tag
        
        
        try {

			YubiKey _yubikey = new YubiKey(tag);
			//_yubikey.SelectApp();
			int ret = _yubikey.personalize(cert_der);
			
			RSAPublicKey keybefore = _yubikey.getPublicRSAKey();
			//System.out.println("before Exponent: "+Utils.byteArrayToHexString(keybefore.getPublicExponent().toByteArray()));
			//System.out.println("before Modulus: "+Utils.byteArrayToHexString(keybefore.getModulus().toByteArray()));
			
			
			ret = _yubikey.setKeys(priv_exp,pub_exp,mod);
			
			short len = _yubikey.getCertificateLen();
			byte[] cert = _yubikey.getCertificate();
			X509Certificate certifcate = new X509Certificate(cert);
			
			//Log.d("skytrust", "cert len:"+len+"cert_der:"+cert_der.length);
			//System.out.println(certifcate.toString());
			
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			c.init(Cipher.ENCRYPT_MODE, certifcate.getPublicKey());
			byte[] cipher = c.doFinal("das ist ein test".getBytes());
			System.out.println("cipher jce: "+  Utils.byteArrayToHexString(cipher));
			
			//byte[] cip = _yubikey.encrypt("aaaabbbbaaaabbbbaaaabbbbaaaabbbb".getBytes()); 
			//System.out.println("cipher yubi: "+ Utils.byteArrayToHexString(cip));
			
			byte[] plain = _yubikey.decrypt(cipher);
			System.out.println("plain: "+new String(plain));
			
			//c.init(Cipher.DECRYPT_MODE, _keypair.getPrivate());
			//plain = c.doFinal(cip);
			//System.out.println("plain: "+new String(plain));
			
			//RSAPublicKey key = _yubikey.getPublicRSAKey();
			//System.out.println("after Exponent: "+Utils.byteArrayToHexString(key.getPublicExponent().toByteArray()));
			//System.out.println("after Modulus: "+Utils.byteArrayToHexString(key.getModulus().toByteArray()));
			
			//System.out.println("should be Exponent: "+Utils.byteArrayToHexString(priv_exp));
			//System.out.println("should be Modulus: "+Utils.byteArrayToHexString(mod));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			Log.e("NFC", "Creating Tag failed");
		}
        
    }
    
}
