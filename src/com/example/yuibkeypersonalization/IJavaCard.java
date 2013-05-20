package com.example.yuibkeypersonalization;

import iaik.security.dh.ESDHPublicKey;

/***
 *Interface for Tags, Smartcards and also virtual Tags
 * 
 */
public interface IJavaCard {
	
	public ESDHPublicKey getPublicKey();
	
	public byte[] generateSharedAESKey(ESDHPublicKey otherPublicKey);
	
	public byte[] getUid();

	public byte[] sign(byte[] data);
	
	

}
