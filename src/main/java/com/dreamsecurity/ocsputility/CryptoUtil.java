package com.dreamsecurity.ocsputility;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

import sun.security.pkcs.PKCS7;
import sun.security.util.DerOutputStream;

/**
 * Contains functions related to general cryptography functions
 * 
 * @author dream
 *
 */
public class CryptoUtil {

	private static final Logger logger = LogManager.getLogger(CryptoUtil.class);

	public static boolean isUsingExportableCryptography() {
		boolean returnValue = true;
		try {
			final int keylen = Cipher.getMaxAllowedKeyLength("DES");

			if (keylen == Integer.MAX_VALUE) {
				returnValue = false;
			}
		} catch (NoSuchAlgorithmException e) {
			// NOPMD
		}
		return returnValue;
	}

	public static synchronized void installBCProviderIfNotAvailable() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			installBCProvider();
		}
	}

	public static synchronized void removeBCProvider() {
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
	}

	public static synchronized void installBCProvider() {
		if (Security.addProvider(new BouncyCastleProvider()) < 0) {
			if (Security.addProvider(new BouncyCastleProvider()) < 0) {
				throw new ProviderException("Failed to install BC provider");
			}
		}
	}

	public static byte[] PKCS7toByteArray(PKCS7 p7) {
		ByteArrayOutputStream bs = new DerOutputStream();
		try {
			p7.encodeSignedData(bs);
		} catch (IOException e) {
			logger.error("Error in encoding PKCS7 to byte array: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		return bs.toByteArray();
	}

	public static byte[] encryptUsingAES(byte[] data, String password) {
		byte[] encryptedIVAndText = null;

		// Generating IV.
		int ivSize = 16;
		byte[] iv = new byte[ivSize];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// Hashing key.
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(Constants.HashAlgo.sha256.getValue());

			digest.update(password.getBytes("UTF-8"));
			byte[] keyBytes = new byte[16];
			System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

			// Encrypt.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] encrypted = cipher.doFinal(data);

			// Combine IV and encrypted part.
			encryptedIVAndText = new byte[ivSize + encrypted.length];
			System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
			System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| NoSuchPaddingException e) {
			logger.error("Error in encrypting the data: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		return encryptedIVAndText;
	}

	public static byte[] decryptUsingAES(byte[] data, String password) {
		int ivSize = 16;
		int keySize = 16;
		byte[] decrypted = null;

		// Extract IV.
		byte[] iv = new byte[ivSize];
		System.arraycopy(data, 0, iv, 0, iv.length);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// Extract encrypted part.
		int encryptedSize = data.length - ivSize;
		byte[] encryptedBytes = new byte[encryptedSize];
		System.arraycopy(data, ivSize, encryptedBytes, 0, encryptedSize);

		// Hash key.
		byte[] keyBytes = new byte[keySize];
		MessageDigest md;
		try {
			md = MessageDigest.getInstance(Constants.HashAlgo.sha256.getValue());

			md.update(password.getBytes());
			System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

			// Decrypt.
			Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			decrypted = cipherDecrypt.doFinal(encryptedBytes);

		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException
				| InvalidKeyException | InvalidAlgorithmParameterException e) {
			logger.error("Error in decrypting the data: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		return decrypted;
	}

	/**
	 * Checks whether given X.509 certificate is self-signed.
	 */
	public static boolean isSelfSignedCert(X509Certificate cert) {
		try {
			// Try to verify certificate signature with its own public key
			PublicKey key = cert.getPublicKey();
			cert.verify(key);
			return true;
		} catch (SignatureException sigEx) {
			// Invalid signature -> not self-signed
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key -> not self-signed
			return false;
		} catch (java.security.cert.CertificateException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			logger.error("Algorithm not supported: ", e.getMessage());
			e.printStackTrace();
			return false;
		} catch (NoSuchProviderException e) {
			logger.error("No such provider exception: " + e.getMessage());
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * Attempts to build a certification chain for given certificate and to
	 * verify it. Relies on a set of root CA certificates (trust anchors) and a
	 * set of intermediate certificates (to be used as part of the chain).
	 * 
	 * @param cert
	 *            - certificate for validation
	 * @param trustedRootCerts
	 *            - set of trusted root CA certificates
	 * @param intermediateCerts
	 *            - set of intermediate certificates
	 * @return boolean
	 */
	public static boolean verifyCertificateBoolean(X509Certificate cert,
			List<X509Certificate> trustedRootCerts, List<X509Certificate> intermediateCerts) {
		
		if(verifyCertificateCertPath(cert, trustedRootCerts, intermediateCerts) == null) {
			return false;
		} else {
			return true;
		}
		
	}
	
	/**
	 * Attempts to build a certification chain for given certificate and to
	 * verify it. Relies on a set of root CA certificates (trust anchors) and a
	 * set of intermediate certificates (to be used as part of the chain).
	 * 
	 * @param cert
	 *            - certificate for validation
	 * @param trustedRootCerts
	 *            - set of trusted root CA certificates
	 * @param intermediateCerts
	 *            - set of intermediate certificates
	 * @return the certification chain (if verification is successful)
	 * 
	 */
	public static PKIXCertPathBuilderResult verifyCertificateCertPath(X509Certificate cert,
			List<X509Certificate> trustedRootCerts, List<X509Certificate> intermediateCerts) {

		// Create the selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(cert);

		// Create the trust anchors (set of root CA certificates)
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		for (X509Certificate trustedRootCert : trustedRootCerts) {
			trustAnchors.add(new TrustAnchor(trustedRootCert, null));
		}

		// Configure the PKIX certificate builder algorithm parameters
		PKIXBuilderParameters pkixParams;
		try {
			pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
		} catch (InvalidAlgorithmParameterException e) {
			logger.error("Error in getting PKIXBuilderParameters" + e.getMessage());
			e.printStackTrace();
			return null;
		}

		// Disable CRL checks (this is done manually as additional step)
		pkixParams.setRevocationEnabled(false);

		// Specify a list of intermediate certificates
		if (intermediateCerts != null && !intermediateCerts.isEmpty()) {
			CertStore intermediateCertStore;
			try {
				intermediateCertStore = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(intermediateCerts), Constants.bc_provider);
			} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
				logger.error("Error in converting intermediateCerts to cert store" + e.getMessage());
				e.printStackTrace();
				return null;
			}
			pkixParams.addCertStore(intermediateCertStore);
		} 
		
		// Build and verify the certification chain
		CertPathBuilder builder;
		try {
			builder = CertPathBuilder.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			logger.error("Error in creating CertPathBuilder" + e.getMessage());
			e.printStackTrace();
			return null;
		}
				
		PKIXCertPathBuilderResult result = null;
		try {
			result = (PKIXCertPathBuilderResult) builder.build(pkixParams);
		} catch (InvalidAlgorithmParameterException e) {
			logger.error("InvalidAlgorithmParameterException in building certificate path, " + e.getMessage());
			e.printStackTrace();
			return null;
		} catch (CertPathBuilderException e) {
			logger.error("Invalid certificate chain, " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		return result;
	}
	
	public static boolean verifyMasterListSignatures(byte[] encodedSignedData) {

		boolean result = false;
		
		CMSSignedData signedData;
		try {
			signedData = new CMSSignedData(encodedSignedData);
		} catch (CMSException e) {
			logger.error("Invalid signed data object: " + e.getMessage());
			e.printStackTrace();
			return false;
		}

		Store<X509CertificateHolder> certStore = signedData.getCertificates();
		SignerInformationStore signers = signedData.getSignerInfos();

		Collection<SignerInformation> signerInfos = signers.getSigners();

		if (signerInfos.size() == 0) {
			logger.error("Cannot perform verification, no signer information found");
			return false;
		} else if (signerInfos.size() > 1) {
			logger.warn("Number of signers is greater than recommended size i.e. 1, found: " + signerInfos.size());
		}

		Iterator<SignerInformation> it = signerInfos.iterator();

		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			logger.debug("Checking for signer having SubjectKeyIdentifier: "
					+ Hex.toHexString(signer.getSID().getSubjectKeyIdentifier()));

			X509CertificateHolderSelector sel = new X509CertificateHolderSelector(
					signer.getSID().getSubjectKeyIdentifier());

			@SuppressWarnings("unchecked")
			Collection<X509CertificateHolder> certCollection = certStore.getMatches(sel);

			if (certCollection.isEmpty()) {
				logger.error("Cannot find certificate in signed data with SubjectKeyIdentifier: "
						+ Hex.toHexString(signer.getSID().getSubjectKeyIdentifier()));
				result = false;
				break;
			}

			Iterator<X509CertificateHolder> certIt = certCollection.iterator();

			X509CertificateHolder signerCert = null;

			// get ml signer cert
			signerCert = (X509CertificateHolder) certIt.next();

			// check if issuer of ml signer is in ml
			CscaMasterList mlCertList = CscaMasterList.getInstance(signedData.getSignedContent().getContent());
			Certificate[] cscaCerts = mlCertList.getCertStructs();

			List<X509Certificate> x509CscaList = new ArrayList<X509Certificate>();

			JcaX509CertificateConverter conv = new JcaX509CertificateConverter();

			for (Certificate c : cscaCerts) {
				try {
					x509CscaList.add(conv.getCertificate(new X509CertificateHolder(c)));
				} catch (java.security.cert.CertificateException e) {
					logger.warn("Error in converting org.bouncycastle.asn1.x509.Certificate to "
							+ "java.security.cert.X509Certificate, cert serialNumber: " + c.getSerialNumber());
					e.printStackTrace();
				}
			}

			X509Certificate x509SignerCert = null;
			try {
				x509SignerCert = conv.getCertificate(signerCert);
			} catch (java.security.cert.CertificateException e) {
				logger.error("Error in coverting signer certificate to X509Certificate" + e.getMessage());
				e.printStackTrace();
				result = false;
				break;
			}

			// check cert path
			if(!CryptoUtil.verifyCertificateBoolean(x509SignerCert, x509CscaList, null) ) {
				logger.error("Error in finding issuer(CSCA certificate) for Master List Signer certificate in signed data");				
				result = false;
				break;
			}
			
			// check signature			
			SignerInformationVerifier signerInfoVerifier = null;
			
			try {
				signerInfoVerifier = new JcaSignerInfoVerifierBuilder(
						new JcaDigestCalculatorProviderBuilder().build()).build(signerCert);;
			} catch (OperatorCreationException | java.security.cert.CertificateException e) {
				System.err.println("Error in SignerInformationVerifier initialization: " + e.getMessage());
				e.printStackTrace();
				result = false;
				break;
			}
		
			try {
				result = signer.verify(signerInfoVerifier);
			} catch (CMSException e) {
				System.err.println("Error in signature verification with Master List Signer certificate, "
						+ "serialNumber: " + signerCert.getSerialNumber());
				e.printStackTrace();
				result = false;
				break;
			}
			
			/*try {
				result = signer
						.verify(new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(),
								new DefaultSignatureAlgorithmIdentifierFinder(),
								new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider())
										.build(signerCert));
			} catch (OperatorCreationException | CMSException e) {
				System.err.println("Error in signature verification with Master List Signer certificate, serialNumber: " + signerCert.getSerialNumber());
				e.printStackTrace();
				result = false;
				break;
			}*/
		}
		
		return result;
	}

	public static List<X509Certificate> getMasterListCertsList(byte[] encodedMasterList) {
		
		CMSSignedData signedData;
		try {
			signedData = new CMSSignedData(encodedMasterList);
		} catch (CMSException e) {
			logger.error("Invalid signed data object: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		
		CscaMasterList mlCertList = CscaMasterList.getInstance(signedData.getSignedContent().getContent());
		Certificate[] cscaCerts = mlCertList.getCertStructs();
		
		List<X509Certificate> x509CscaList = new ArrayList<X509Certificate>();

		JcaX509CertificateConverter conv = new JcaX509CertificateConverter();

		for (Certificate c : cscaCerts) {
			try {
				x509CscaList.add(conv.getCertificate(new X509CertificateHolder(c)));
			} catch (java.security.cert.CertificateException e) {
				logger.warn("Error in converting org.bouncycastle.asn1.x509.Certificate to "
						+ "java.security.cert.X509Certificate, cert serialNumber: " + c.getSerialNumber());
				e.printStackTrace();
			}
		}
		
		return x509CscaList;
	}
	
	public static X509Certificate byteToX509Certificate(byte[] certData) {
		CertificateFactory cf = null;
		
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (java.security.cert.CertificateException e) {
			logger.error("Error in creating CertificateFactory instance: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		
		try {
			return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certData));
		} catch (java.security.cert.CertificateException e) {
			logger.error("Error in generating certificate instance: " + e.getMessage());
			e.printStackTrace();
			return null;
		}		
	}
	
	public static X509CertificateHolder byteToX509HolderCertificate(byte[] certData) {
		try {
			return new X509CertificateHolder(certData);
		} catch (IOException e) {
			logger.error("Error in convertion encoded X509Certificate to X509CertificateHolder: "
					+ e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	public static CertificateID getOCSPCertId(byte[] issuerCert, BigInteger serialNumber) {

		X509Certificate cert = CryptoUtil.byteToX509Certificate(issuerCert);

		JcaCertificateID jcaCertId = null;

		try {
			jcaCertId = new JcaCertificateID(
					new JcaDigestCalculatorProviderBuilder().setProvider(Constants.bc_provider).build()
							.get(new DefaultDigestAlgorithmIdentifierFinder().find(Constants.HashAlgo.sha1.getValue())),
					cert, serialNumber);
			return new CertificateID(jcaCertId.toASN1Primitive());			
		} catch (CertificateEncodingException | OperatorCreationException | OCSPException e) {
			logger.error("Error in create CertificateID for the certificate: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	public static X509CertificateHolder X509ToHolder(X509Certificate cert) {
		try {
			return new X509CertificateHolder(cert.getEncoded());
		} catch (CertificateEncodingException | IOException e) {
			logger.error("Error in convertion X509Certificate to X509CertificateHolder: "
					+ e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	public static X509CertificateHolder[] X509ToHolder(X509Certificate[] cert) {
		List<X509CertificateHolder> certHolders = new ArrayList<>();
		for(X509Certificate c: cert) {
			try {
				certHolders.add(new X509CertificateHolder(c.getEncoded()));
			} catch (CertificateEncodingException | IOException e) {
				logger.error("Error in convertion X509Certificate to X509CertificateHolder: "
						+ e.getMessage());
				e.printStackTrace();				
			}
		}
		
		return (X509CertificateHolder[])certHolders.stream().toArray(X509CertificateHolder[]::new);
	}
	
	public static String getOcspAccessLocation(X509Certificate certificate)
			throws IOException {

		final byte[] extVal = certificate
				.getExtensionValue(Extension.authorityInfoAccess.getId());
		if (null == extVal) {
			return null;
		}

		AuthorityInformationAccess aia = AuthorityInformationAccess
				.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extVal));

		final AccessDescription[] accessDescriptions = aia
				.getAccessDescriptions();
		for (AccessDescription accessDescription : accessDescriptions) {

			final boolean correctAccessMethod = accessDescription
					.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
			if (!correctAccessMethod) {
				continue;
			}
			final GeneralName gn = accessDescription.getAccessLocation();
			if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
				// Not a uniform resource identifier
				continue;
			}
			final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn
					.toASN1Primitive()).getObject();
			final String accessLocation = str.getString();
			return accessLocation;
		}
		return null;
	}
	
	public static String getOcspAccessLocation(AuthorityInformationAccess aia)
			throws IOException {
		
		final AccessDescription[] accessDescriptions = aia
				.getAccessDescriptions();
		for (AccessDescription accessDescription : accessDescriptions) {

			final boolean correctAccessMethod = accessDescription
					.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
			if (!correctAccessMethod) {
				continue;
			}
			final GeneralName gn = accessDescription.getAccessLocation();
			if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
				// Not a uniform resource identifier
				continue;
			}
			final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn
					.toASN1Primitive()).getObject();
			final String accessLocation = str.getString();
			return accessLocation;
		}
		return null;
	}
	
	public static String SubjectDNtoString(Principal principal) {

	    String name = principal.getName().trim();

	    String[] RDN = name.trim().split(",");

	    StringBuffer buf = new StringBuffer(name.length());
	    for(int i = RDN.length - 1; i >= 0; i--){
	        if(i != RDN.length - 1)
	            buf.append(',');

	        buf.append(RDN[i].trim());
	    }

	    return buf.toString();
	}
	
	public static List<com.dreamsecurity.jcaos.x509.X509Certificate> JavaCertListToJcaos(List<X509Certificate> certList) {
		List<com.dreamsecurity.jcaos.x509.X509Certificate> jcaosList = new ArrayList<>();
		for (X509Certificate cert : certList) {
			try {
				jcaosList.add(com.dreamsecurity.jcaos.x509.X509Certificate.getInstance(cert.getEncoded()));
			} catch (CertificateEncodingException | IOException e) {
				System.out.println("Error in converting certifiate: " + e.getMessage());
				return null;
			}
		}
		
		return jcaosList;
	}
	
	public static com.dreamsecurity.jcaos.x509.X509Certificate JavaCertToJcaos(X509Certificate cert) {
		com.dreamsecurity.jcaos.x509.X509Certificate jcaosCert = null;
			try {
				jcaosCert = com.dreamsecurity.jcaos.x509.X509Certificate.getInstance(cert.getEncoded());
			} catch (IOException | CertificateEncodingException e) {
				System.out.println("Error in converting certifiate: " + e.getMessage());
				return null;
			}
		
		return jcaosCert;
	}
}

