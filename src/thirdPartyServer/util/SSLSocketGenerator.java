package thirdPartyServer.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

public class SSLSocketGenerator {

	private String alias = null;
	private String keyStore = null;
	private String trustStore = null;

	public SSLSocketGenerator (String alias, String keyStore, String trustStore) {
		if (alias == null)
			throw new IllegalArgumentException("The alias may not be null");
		this.alias = alias;
		this.keyStore = keyStore;
		this.trustStore = trustStore;
	}

	public SSLContext getSSLSocketFactory() throws IOException, GeneralSecurityException {
		// Retrieve the trust stores and key stores
		KeyManager[] keyManagers = getKeyManagers();
		TrustManager[] trustManagers = getTrustManagers();

		final X509KeyManager origKm = (X509KeyManager)keyManagers[0];
		
		X509KeyManager km = new X509KeyManager() {
			@Override
		    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		        return alias;
		    }

		    @Override
		    public X509Certificate[] getCertificateChain(String alias) {
		        return origKm.getCertificateChain(alias);
		    }

			@Override
			public String[] getClientAliases(String keyType, Principal[] issuers) {
				return origKm.getClientAliases(keyType, issuers);
			}

			@Override
			public String[] getServerAliases(String keyType, Principal[] issuers) {
				return origKm.getServerAliases(keyType, issuers);
			}

			@Override
			public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
				return origKm.chooseServerAlias(keyType, issuers, socket);
			}

			@Override
			public PrivateKey getPrivateKey(String alias) {
				return origKm.getPrivateKey(alias);
			}

		};

		// Initialize SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(new KeyManager[] { km }, trustManagers, null);

		return sslContext;
	}   

	public String getKeyStorePassword() {
		return "mcnsir6o29";
	}

	public String getTrustStorePassword() {
		return "ls72f9ubc3";
	}

	public String getKeyStore() {
		return keyStore;
	}

	public String getTrustStore() {
		return trustStore;
	}

	private KeyManager[] getKeyManagers() throws IOException, GeneralSecurityException {
		// Define a key manager factory
		String alg = KeyManagerFactory.getDefaultAlgorithm();
		KeyManagerFactory kmFact = KeyManagerFactory.getInstance(alg);

		// Load the key store
    	KeyStore keyStore = KeyStore.getInstance("JKS");
    	keyStore.load(new FileInputStream(getKeyStore()), getKeyStorePassword().toCharArray());

		// Init the key manager factory with the loaded key store
		kmFact.init(keyStore,  getKeyStorePassword().toCharArray());

		// Build the key manager array to return
		KeyManager[] kms = kmFact.getKeyManagers();

		return kms;
	}


	protected TrustManager[] getTrustManagers() throws IOException, GeneralSecurityException {
		// Define a trust manager factory
		String alg = TrustManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory tmFact = TrustManagerFactory.getInstance(alg);

		// Load the trust store
    	KeyStore trustStore = KeyStore.getInstance("JKS");
    	trustStore.load(new FileInputStream(getTrustStore()), getTrustStorePassword().toCharArray());

    	// Init the trust store factory with the loaded trust store
		tmFact.init(trustStore);

		// Build the trust manager array to return
		TrustManager[] tms=tmFact.getTrustManagers();
		return tms;
	}
}
