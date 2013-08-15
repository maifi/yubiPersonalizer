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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.nfc.tech.NfcF;
import android.nfc.tech.NfcV;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

public class YubikeyPersonalisation extends Activity {

	private byte[] cert_der = null;
	byte[] mod = null;
	byte[] priv_exp,pub_exp = null;
	KeyPair _keypair = null;

	private NfcAdapter mAdapter;
	private PendingIntent pendingIntent;
	private IntentFilter[] mFilters;
	private String[][] mTechLists;

	private TextView tf_name,tf_company;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_yubikey_personalisation);

		tf_name = (TextView) findViewById(R.id.tf_name1);
		tf_company = (TextView) findViewById(R.id.tf_company);

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
		keyGen.initialize(1024);
		_keypair = keyGen.generateKeyPair();
		RSAPrivateKey privKey = (RSAPrivateKey) _keypair.getPrivate();
		RSAPublicKey pubKey = (RSAPublicKey) _keypair.getPublic();

		BigInteger mod_bi = privKey.getModulus();
		BigInteger exp_bi = privKey.getPrivateExponent();
		BigInteger exp_pub_bi = pubKey.getPublicExponent();
		//Remove sign bytes:

		mod = Arrays.copyOfRange(mod_bi.toByteArray(),1,mod_bi.toByteArray().length);

		byte[] temp = Arrays.copyOfRange(exp_bi.toByteArray(),0,exp_bi.toByteArray().length);
		
		if(temp.length == 129)//remove leading zero
			priv_exp = Arrays.copyOfRange(temp,1,temp.length);
		else
			priv_exp = Arrays.copyOfRange(temp,0,temp.length);
		
		pub_exp = Arrays.copyOfRange(exp_pub_bi.toByteArray(),0,exp_pub_bi.toByteArray().length);

		System.out.println("Modulus length"+mod.length);
		System.out.println("Priv Exp length"+priv_exp.length);
		System.out.println("Pub Exp length"+pub_exp.length);

		Calendar expiry = Calendar.getInstance();
		expiry.add(Calendar.DAY_OF_YEAR, 360);

		Name user = new Name();
		user.addRDN(ObjectID.country, "AT");
		user.addRDN(ObjectID.commonName, tf_name.getText().toString());
		user.addRDN(ObjectID.organization, tf_company.getText().toString());

		Name subject = new Name();
		subject.addRDN(ObjectID.country, "AT");
		subject.addRDN(ObjectID.commonName,tf_name.getText().toString());
		subject.addRDN(ObjectID.organization,tf_company.getText().toString());

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


			cert.sign(AlgorithmID.sha1WithRSAEncryption ,(java.security.PrivateKey) privKey);

			System.out.println(cert.toString());
			cert_der = cert.toByteArray();

			Toast.makeText(getApplicationContext(), "Certificate created, Touch Yubikey with Phone!", Toast.LENGTH_LONG).show();


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


		try {
			YubiKey _yubikey = new YubiKey(tag);
			int ret = _yubikey.personalize(cert_der);
			
			if(ret <0){
				Toast.makeText(getApplicationContext(), "Error sending Cert", Toast.LENGTH_LONG).show();
			}

			ret = _yubikey.setKeys(priv_exp,pub_exp,mod);
			if(ret <0){
				Toast.makeText(getApplicationContext(), "Error setting keys", Toast.LENGTH_LONG).show();
			}
			
			Toast.makeText(getApplicationContext(), "Yubikey initialized!", Toast.LENGTH_LONG).show();


		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			Log.e("NFC", "Creating Tag failed");
		}

	}
	
	public void clickedExportCert(View view){
		if(cert_der == null)
			return;
		
	    // Get the directory for the user's public pictures directory. 
	    File file = new File(Environment.getExternalStoragePublicDirectory(
	            Environment.DIRECTORY_DOWNLOADS), "yubikey.cert");
	    
	    try {
			BufferedOutputStream outstream = new BufferedOutputStream(new FileOutputStream(file));
			outstream.write(cert_der);
			outstream.flush();
			outstream.close();
			Toast.makeText(getApplicationContext(), "Certificate exported to Downloads/yubikey.cert", Toast.LENGTH_LONG).show();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	}
	
	public void clickedImportCert(View view){
		
	    // Get the directory for the user's public pictures directory. 
	    File file = new File(Environment.getExternalStoragePublicDirectory(
	            Environment.DIRECTORY_DOWNLOADS), "certificate_yubi.txt");
	    
	    int size = (int) file.length();
	    byte[] bytes = new byte[size];
	    try {
	        BufferedInputStream buf = new BufferedInputStream(new FileInputStream(file));
	        buf.read(bytes, 0, bytes.length);
	        buf.close();
	        
	        X509Certificate cert = new X509Certificate(bytes);
	        System.out.println(cert.toString());
	    } catch (FileNotFoundException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    } catch (IOException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    } catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	}

}
