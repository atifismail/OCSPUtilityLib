package com.dreamsecurity.ocsputility;

import java.util.HashMap;
import java.util.Map;

/**
 * Container for global enum/constants
 * @author dream
 *
 */
public class Constants {

	public final static String bc_provider = "BC";
	public final static String jcaos_provider = "JCAOS";	
	
	public enum ValidityType {
		DAY("DAY"),
		MONTH("MONTH"),
		YEAR("YEAR");
		
		private String validityType;
		
		private ValidityType(String validityType) {
			this.setValidityType(validityType);
		}

		public String getValidityType() {
			return validityType;
		}

		public void setValidityType(String validityType) {
			this.validityType = validityType;
		}
	}
	
	public enum CertificateType {
		CA("CA"),
		END_ENTITY("END_ENTITY");
		
		private String type;
		
		private CertificateType(String type) {
			this.type = type;
		}
		
		public String getCertificateType() {
			return this.type;
		}
	}
	
	public enum SigningAlgo
	{
		SHA1WITHRSA("SHA1withRSA"), 
		SHA256WITHRSA("SHA256withRSA"),
		SHA512WITHRSA("SHA512withRSA"),		
		SHA1WITHRSA_MGF1("SHA1withRSAandMGF1"),
		SHA256WITHRSA_MGF1("SHA256withRSAandMGF1"),
		SHA512WITHRSA_MGF1("SHA512withRSAandMGF1"),
		SHA1WITHECDSA("SHA1withECDSA"),
		SHA224WITHECDSA("SHA224withECDSA"),
		SHA256WITHECDSA("SHA256withECDSA"),
		SHA384WITHECDSA("SHA384withECDSA"),
		SHA512WITHECDSA("SHA512withECDSA"),	    
		SHA1WITHDSA("SHA1withDSA"),
		SHA256WITHDSA("SHA256withDSA");
				
	    private String algo;
	 
	    SigningAlgo(String algo) {
	        this.algo = algo;
	    }
	 
	    public String getAlgo() {
	        return this.algo;
	    }
	     
	    //****** Reverse Lookup Implementation************//
	 
	    //Lookup table
	    private static final Map<String, SigningAlgo> lookup = new HashMap<>();
	  
	    //Populate the lookup table on loading time
	    static
	    {
	        for(SigningAlgo algo : SigningAlgo.values())
	        {
	            lookup.put(algo.getAlgo(), algo);
	        }
	    }
	  
	    //This method can be used for reverse lookup purpose
	    public static SigningAlgo get(String algo)
	    {
	        return lookup.get(algo);
	    }
	} 
	
	public enum KeyAlgo
	{
		RSA("RSA"),		
		DSA("DSA"),
		EC("EC");
		
		private String algo;
		
		KeyAlgo(String algo) {
			this.algo = algo;
		}
		
		public String getValue() {
			return this.algo;
		}
	}
	
	public enum RSAKeyLength
	{
		RSA_1024(1024),
		RSA_2048(2048),
		RSA_3076(3076),
		RSA_4096(4096);
		
		private int keyLength;
		
		RSAKeyLength(int keylength) {
			this.keyLength = keylength;
		}
		
		public int getValue() {
			return this.keyLength;
		}
	}
	
	public enum DSAKeyLength
	{
		DSA_1024(1024),
		DSA_2048(2048),
		DSA_3076(3076),
		DSA_4096(4096);
		
		private int keyLength;
		
		DSAKeyLength(int keylength) {
			this.keyLength = keylength;
		}
		
		public int getValue() {
			return this.keyLength;
		}
	}
	
	public enum ECCurves
	{
		secp160r1("secp160r1"),
		secp192r1("secp192r1"),
		secp224r1("secp224r1"),
		secp256r1("secp256r1"),
		secp384r1("secp384r1"),
		secp521r1("secp521r1"),
		sect163r1("sect163r1"),
		sect193r1("sect193r1"),
		sect233r1("sect233r1"),
		sect283r1("sect283r1"),
		sect409r1("sect409r1"),
		sect571r1("sect571r1"),
		brainpoolP160r1("brainpoolP160r1"),
		brainpoolP192r1("brainpoolP192r1"),
		brainpoolP224r1("brainpoolP224r1"),
		brainpoolP256r1("brainpoolP256r1"),
		brainpoolP320r1("brainpoolP320r1"),
		brainpoolP384r1("brainpoolP384r1"),
		brainpoolP512r1("brainpoolP512r1");
		
		private String curve;
		
		ECCurves(String curve) {
			this.curve = curve;
		}
		
		public String getValue() {
			return this.curve;
		}
	}
	
	public enum HashAlgo {
		sha1("SHA-1"),
		sha256("SHA-256"),
		sha384("SHA-384"),
		sha512("SHA-512");
		
		private String hashAlgo;
		
		HashAlgo(String hashAlgo) {
			this.hashAlgo = hashAlgo;
		}
		
		public String getValue() {
			return this.hashAlgo;
		} 
	}
}
