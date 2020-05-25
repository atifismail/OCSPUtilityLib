package com.dreamsecurity.ocsputility;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/**
 * Generate ASymmetric key pair
 * @author dream
 *
 */
public class KeyGenerator {
	private static final Logger logger = LogManager.getLogger(KeyGenerator.class.getName());

	private static class LazyHolder {
		public static final KeyGenerator INSTANCE = new KeyGenerator();
	}

	public static KeyGenerator getInstance() {
		return LazyHolder.INSTANCE;
	}

	private KeyGenerator() {
	}

	/**
	 * Create a RSA key pair with the given key length
	 * 
	 * @param keylength
	 *            The bit length to use
	 * @return {@link KeyPair} The generated key pair
	 */
	public KeyPair generateRSAPair(int keylength) {
		KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance(Constants.KeyAlgo.RSA.getValue(), Constants.bc_provider);
			return generateKeyPair(generator, keylength);
		} catch (NoSuchAlgorithmException e) {
			logger.error("No suitable algorithm was found: " + e.getMessage());
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			logger.error("No suitable provider was found: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Create a DSA key pair with the given key length
	 * 
	 * @param keylength
	 *            The bit length to use
	 * @return {@link KeyPair} The generated key pair
	 */
	public KeyPair generateDSAPair(int keylength) {
		KeyPairGenerator generator = null;
		SecureRandom random = new SecureRandom();

		try {
			generator = KeyPairGenerator.getInstance(Constants.KeyAlgo.DSA.getValue(), Constants.bc_provider);
			if (keylength > 3072) {
				// workaround for internal BouncyCastle problem with DSA key
				// generation with more than 3072 bits
				int certainty = PrimeCertaintyCalculator.getDefaultCertainty(keylength);
				DSAParametersGenerator dsaParameterGenerator = new DSAParametersGenerator();
				dsaParameterGenerator.init(keylength, certainty, random);
				DSAParameters bcParams = dsaParameterGenerator.generateParameters();
				DSAParameterSpec params = new DSAParameterSpec(bcParams.getP(), bcParams.getQ(), bcParams.getG());
				generator.initialize(params, random);
			} else {
				generator.initialize(keylength, random);
			}

			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			logger.error("No suitable algorithm was found: " + e.getMessage());
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			logger.error("No suitable provider was found:" + e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error("No suitable algorithm parameter was found:" + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Create a DSA key pair using the given curve name
	 * 
	 * @param {@link
	 * 			String} curveName The name of the curve to use. Valid options
	 *            are:<br>
	 *            <ul>
	 *            <li>sect233k1</li>
	 *            <li>sect233r1</li>
	 *            <li>sect239k1</li>
	 *            <li>sect283k1</li>
	 *            <li>sect283r1</li>
	 *            <li>sect409k1</li>
	 *            <li>sect409r1</li>
	 *            <li>sect571k1</li>
	 *            <li>sect571r1</li>
	 *            <li>secp224k1</li>
	 *            <li>secp224r1</li>
	 *            <li>secp256k1</li>
	 *            <li>secp256r1</li>
	 *            <li>secp384r1</li>
	 *            <li>secp521r1</li>
	 *            <li>brainpoolP256r1</li>
	 *            <li>brainpoolP384r1</li>
	 *            <li>brainpoolP512r1</li>
	 *            </ul>
	 *            <br>
	 * @return {@link KeyPair} The generated key pair
	 */
	public KeyPair generateECPair(String curveName) {
		KeyPairGenerator generator = null;
		try {
			generator = KeyPairGenerator.getInstance(Constants.KeyAlgo.EC.getValue(), Constants.bc_provider);
			ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
			generator.initialize(ecSpec, new SecureRandom());
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			logger.error("No suitable algorithm was found: " + e.getMessage());
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			logger.error("No suitable provider was found:" + e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			logger.error("No suitable algorithm was found:" + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}

	// generate the key pair with the given length
	private KeyPair generateKeyPair(KeyPairGenerator generator, int keylength) {
		generator.initialize(keylength, new SecureRandom());
		KeyPair keyPair = generator.generateKeyPair();
		return keyPair;
	}
}