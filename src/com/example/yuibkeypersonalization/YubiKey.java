package com.example.yuibkeypersonalization;

import iaik.security.dh.ESDHPublicKey;
import iaik.security.rsa.RSAPublicKey;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;

/***
 * 
 * 
 */
public class YubiKey implements IJavaCard {

	private IsoDep currentIsoDep;

	byte[] SELECT = {
			(byte) 0x00,
			// CLA
			(byte) 0xA4, // INS Instruction
			(byte) 0x04, // P1 Parameter 1
			(byte) 0x00, // P2 Parameter 2
			(byte) 0x07, // Length
			(byte) 0xD2,0x76,0x00,0x01,0x24,0x01,0x02
	};

	public YubiKey(Tag tag) throws Exception {
		this.currentIsoDep = IsoDep.get(tag);
		if (this.currentIsoDep == null) {
			throw new Exception("Tag does not support ISO-DEP.");
		}
		try {
			this.currentIsoDep.connect();
		} catch (IOException e) {
			throw new Exception("Could not connect to Tag.");
		}
	}

	public byte[] SelectApp(){
		byte[] response = null;
		try {
			response = this.currentIsoDep
					.transceive(SELECT);
		} catch (IOException e) {
			Log.e("NFC-CryptoTag", "NFC: IOException caught during transceive(): "
					+ e.getMessage());
			return null;
		}
		Log.d("YubiKey", "Select Applet sent");

		int retcode = Utils.bytesToInt(response[response.length-2], response[response.length-1]);

		if( retcode != 0x9000){
			Log.e("YubiKey", "SelectApp-ErrorCode: "+ retcode);
			return null;
		}
		return response;
	}

	public byte[] encrypt(byte[] plaintext){
		byte[] response = new byte[128];

		if(SelectApp() == null)
			return null;

		//byte le = 64;	//apdu length of return value

		byte[] ENCRYPT = {
				(byte) 0x00, // CLA
				(byte) 0x07, // INS Instruction //RSA
				(byte) 0x00, // P1 Parameter 1
				(byte) 0x00, // P2 Parameter 2
				(byte) plaintext.length, // Length
				//(byte) 1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,// load
				//16// retlength
		};

		//building the whole command
		byte[] cmd = new byte[ENCRYPT.length + plaintext.length+1];
		System.arraycopy(ENCRYPT, 0, cmd, 0, ENCRYPT.length);
		System.arraycopy(plaintext, 0, cmd, ENCRYPT.length, plaintext.length);
		cmd[cmd.length-1] = (byte) response.length;//return length

		try {
			response = this.currentIsoDep
					.transceive(cmd);
		} catch (IOException e) {
			Log.e("NFC-CryptoTag", "NFC: IOException caught during transceive(): "
					+ e.getMessage());
			return null;
		}
		Log.d("NFC-CryptoTag", "Encrypt sent");

		int retcode = Utils.bytesToInt(response[response.length-2], response[response.length-1]);

		if(retcode != 0x9000){
			Log.e("YubiKey", "Encrypt-ErrorCode: "+ retcode);
			return null;
		}

		byte[] response_no_retcode = null;

		//response without the returncode 
		response_no_retcode = Arrays.copyOf(response, response.length-2);

		return response_no_retcode;
	}

	public byte[] decrypt(byte[] ciphertext){
		byte[] response = new byte[64];
		//byte le = 16;

		if(SelectApp() == null)
			return null;

		byte[] DECRYPT = {
				(byte) 0x00, // CLA
				(byte) 0x08, // INS Instruction
				(byte) 0x00, // P1 Parameter 1
				(byte) 0x00, // P2 Parameter 2
				(byte)ciphertext.length, // Length
		};

		byte[] cmd = new byte[DECRYPT.length + ciphertext.length+1];
		System.arraycopy(DECRYPT, 0, cmd, 0, DECRYPT.length);
		System.arraycopy(ciphertext, 0, cmd, DECRYPT.length, ciphertext.length);
		cmd[cmd.length-1] = (byte) response.length;//return length

		System.out.println(Utils.byteArrayToHexString(ciphertext));

		try {
			response = this.currentIsoDep
					.transceive(cmd);
		} catch (IOException e) {
			Log.e("NFC-CryptoTag", "NFC: IOException caught during transceive(): "
					+ e.getMessage());
			return null;
		}
		Log.d("NFC-CryptoTag", "Decrypt sent");
		System.out.println(Utils.byteArrayToHexString(response));
		byte[] response_no_retcode = null;
		response_no_retcode = Arrays.copyOf(response, response.length-2);

		return response_no_retcode;
	}

	@Override
	public byte[] sign(byte[] data){
		byte[] response = new byte[256];

		byte[] SIGN = {
				(byte) 0x00,
				// CLA
				(byte) 0x05, // INS Instruction
				(byte) 0x00, // P1 Parameter 1
				(byte) 0x00, // P2 Parameter 2
				(byte) 0x10, // Length
				(byte) 1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,
				(byte) 0x10
		};

		try {
			response = this.currentIsoDep
					.transceive(SIGN);
		} catch (IOException e) {
			Log.e("NFC-CryptoTag", "NFC: IOException caught during transceive(): "
					+ e.getMessage());
			return null;
		}
		Log.d("NFC-CryptoTag", "SIGN sent");

		return response;
	}

	public RSAPublicKey getPublicRSAKey() {
		byte[] exponent = new byte[16];
		byte[] modulus = new byte[64];
		byte le = 16;
		byte lm = 64;

		if(SelectApp() == null)
			return null;

		byte[] GETEXPONENT = {
				(byte) 0x00, // CLA
				(byte) 0x09, // INS Instruction
				(byte) 0x00, // P1 Parameter 1
				(byte) 0x00, // P2 Parameter 2
				(byte) le // Length
		};

		byte[] GETMODULUS = {
				(byte) 0x00, // CLA
				(byte) 0x10, // INS Instruction
				(byte) 0x00, // P1 Parameter 1
				(byte) 0x00, // P2 Parameter 2
				(byte) lm // Length
		};

		try {
			exponent = this.currentIsoDep
					.transceive(GETEXPONENT);
			modulus = this.currentIsoDep
					.transceive(GETMODULUS);
	
			BigInteger bi_exp = new BigInteger(exponent);
			BigInteger bi_mod = new BigInteger(modulus);
			RSAPublicKey key = new RSAPublicKey(bi_mod, bi_exp);
			return key;
		} catch (IOException e) {
			Log.e("NFC-Yubikey", "NFC: IOException caught during transceive(): "
					+ e.getMessage());
		}

		return null;

	}

	public int personalize(byte[] cert){
		int cert_block_size = 120;
		if(SelectApp() == null)
			return -1;
		
		//we dont use extended apdus, so we have to split the cert
		boolean done = false;
		int cert_len = cert.length;
		int blocknumber = 0;
		byte[] cmd = null;
		byte[] CMD = {
				(byte) 0x00, // CLA
				(byte) 0x11, // INS Instruction //RSA
				(byte) blocknumber, // P1 Parameter 1 //used for BlockNumber here
				(byte) 0x00, // P2 Parameter 2
				0, // LC
		};
		while(done == false){
			CMD[2] = (byte) blocknumber;
			if(cert_len > cert_block_size){

				cmd = new byte[CMD.length + cert_block_size +1];//+1 for le
				cmd[cmd.length-1] = 2;
				//set lc
				CMD[4] = (byte)cert_block_size;
				System.arraycopy(CMD, 0, cmd, 0, CMD.length);
				System.arraycopy(cert, blocknumber*cert_block_size, cmd, CMD.length, cert_block_size);
				cert_len -=cert_block_size;

			}else{
				cmd = new byte[CMD.length + cert_len +1];
				cmd[cmd.length-1] = 2;
				CMD[4] = (byte) cert_len;
				System.arraycopy(CMD, 0, cmd, 0, CMD.length);
				System.arraycopy(cert, blocknumber*cert_block_size, cmd, CMD.length, cert_len);
				done = true;
			}
			if(cert_len == 0)
				done = true;
			blocknumber++;
			try {
				byte[] retval = this.currentIsoDep.transceive(cmd);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return -2;
			}
		}

		return blocknumber;
	}
	
	public short getCertificateLen(){
		
		byte[] GETLEN = {
				(byte) 0x00, // CLA
				(byte) 0x13, // INS Instruction
				(byte) 0x00, // P1 Parameter 1
				(byte) 0x00, // P2 Parameter 2
				(byte) 2 // Length
		};
		
	
			try {
				byte[] len = this.currentIsoDep.transceive(GETLEN);
				short length = (short) (len[0]<<8 & len[1]); 
				return (short)Utils.bytesToInt(len[0], len[1]);
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return -1;
	}
	
	public byte[] getCertificate(){
		
		if(SelectApp() == null)
			return null;
		
		short certlen = getCertificateLen();
		
		byte[] cert = new byte[certlen];
		byte blocknumber = 0;
		byte blocksize = 120;
		
		byte[] CMD = {
				(byte) 0x00, // CLA
				(byte) 0x12, // INS Instruction //RSA
				(byte) blocknumber, // P1 Parameter 1 //used for BlockNumber here
				(byte) 0x00, // P2 Parameter 2
				blocksize, // Le
		};
		
		try {
			boolean done = false;
			
			while(done == false){
				CMD[2] = blocknumber;
				if((blocknumber+1)*blocksize > certlen){
					CMD[4] = (byte) (certlen - blocknumber*blocksize);
					done = true;
				}
				//byte[] retval = new byte[120];
				byte[] retval = this.currentIsoDep.transceive(CMD);
				//System.out.println(Utils.byteArrayToHexString(retval)+"len array: "+retval.length);
				
				int retcode = Utils.bytesToInt(retval[retval.length-2], retval[retval.length-1]);
				System.out.println(Utils.byteArrayToHexString(retval)+"retcode: "+retcode);
				if(retcode!= 0x9000)
					return null;
				
				System.arraycopy(retval, 0, cert, blocknumber*blocksize, retval.length-2);//-2 because of the return code
				blocknumber+=1;
			}
			return cert;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public ESDHPublicKey getPublicKey() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] generateSharedAESKey(ESDHPublicKey otherPublicKey) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getUid() {
		// TODO Auto-generated method stub
		return null;
	}

	public int setKeys(byte[] priv_exp, byte[] pub_exp, byte[] mod) {
		
		if(SelectApp() == null)
			return -1;
		
		byte[] SET_EXP = {
				(byte) 0x00, // CLA
				(byte) 0x14, // SET_EXP
				(byte) 0x00, // P1 Parameter 1 //used for BlockNumber here
				(byte) 0x00, // P2 Parameter 2
				(byte) priv_exp.length
		};
		byte[] SET_MOD = {
				(byte) 0x00, // CLA
				(byte) 0x15, // SET_MOD
				(byte) 0x00, // P1 Parameter 1 //used for BlockNumber here
				(byte) 0x00, // P2 Parameter 2
				(byte) mod.length
		};
		byte[] SET_PUB_EXP = {
				(byte) 0x00, // CLA
				(byte) 0x16, // SET_PUBEXP
				(byte) 0x00, // P1 Parameter 1 //used for BlockNumber here
				(byte) 0x00, // P2 Parameter 2
				(byte) pub_exp.length
		};
		byte[] cmd_exp = new byte[SET_EXP.length+priv_exp.length];
		byte[] cmd_mod = new byte[SET_MOD.length+mod.length];
		byte[] cmd_pub_exp = new byte[SET_PUB_EXP.length+pub_exp.length];
		
		System.arraycopy(SET_EXP, 0, cmd_exp, 0, SET_EXP.length);
		System.arraycopy(priv_exp, 0, cmd_exp, SET_EXP.length, priv_exp.length);
		
		System.arraycopy(SET_PUB_EXP, 0, cmd_pub_exp, 0, SET_PUB_EXP.length);
		System.arraycopy(pub_exp, 0, cmd_pub_exp, SET_PUB_EXP.length, pub_exp.length);
		
		System.arraycopy(SET_MOD, 0, cmd_mod, 0, SET_MOD.length);
		System.arraycopy(mod, 0, cmd_mod, SET_MOD.length, mod.length);
		
		try {
			byte[] ret = this.currentIsoDep
					.transceive(cmd_exp);
			System.out.println("setexp: "+Utils.bytesToInt(ret[0], ret[1]));
			ret = this.currentIsoDep
					.transceive(cmd_pub_exp);
			System.out.println("setpubexp: "+Utils.bytesToInt(ret[0], ret[1]));
			ret = this.currentIsoDep
					.transceive(cmd_mod);
			System.out.println("setmod: "+Utils.bytesToInt(ret[0], ret[1]));
			return 0;
		} catch (IOException e) {
			Log.e("NFC-Yubikey", "NFC: IOException caught during transceive(): "
					+ e.getMessage());
		}
		
		return -1;
	}


}