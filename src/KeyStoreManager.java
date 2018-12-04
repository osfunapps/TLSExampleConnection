import com.google.polo.ssl.SslUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.UUID;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/* compiled from: Unknown */
public final class KeyStoreManager {
    private static String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final boolean DEBUG = false;
    private static final String KEYSTORE_FILENAME = "atvremote.keystore";
    private static final char[] KEYSTORE_PASSWORD = "KeyStore_Password".toCharArray();
    private static final String LOCAL_IDENTITY_ALIAS = "atvremote-remote";
    private static final String REMOTE_IDENTITY_ALIAS_PATTERN = "atvremote-remote-%s";
    private static final String SERVER_IDENTITY_ALIAS = "atvremote-local";
    private static final String TAG = "KeyStoreManager";
    private DynamicTrustManager mDynamicTrustManager;
    public KeyStore mKeyStore;

    /* compiled from: Unknown */

    public static class DynamicTrustManager implements X509TrustManager {
        private X509TrustManager trustManager;

        public DynamicTrustManager(KeyStore keyStore) {
            reloadTrustManager(keyStore);
        }

        public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
            this.trustManager.checkClientTrusted(x509CertificateArr, str);
        }

        public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
            this.trustManager.checkServerTrusted(x509CertificateArr, str);
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void reloadTrustManager(KeyStore keyStore) {
            try {
                TrustManagerFactory instance = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                instance.init(keyStore);
                TrustManager[] trustManagers = instance.getTrustManagers();
                for (int i = 0; i < trustManagers.length; i++) {
                    if (trustManagers[i] instanceof X509TrustManager) {
                        this.trustManager = (X509TrustManager) trustManagers[i];
                        return;
                    }
                }
                throw new IllegalStateException("No trust manager found");
            } catch (NoSuchAlgorithmException e) {
            } catch (KeyStoreException e2) {
            }
        }
    }

    public KeyStoreManager() {
        mKeyStore = createKeyStore();
    }

    /* JADX WARNING: Removed duplicated region for block: B:17:0x003f  */

    /**
     * Loads key store from storage, or creates new one if storage is missing
     * key store or corrupted.
     */
    private void load() {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Unable to get default instance of KeyStore", e);
        }
      /*  try {
            File initialFile = new File("src/" + KEYSTORE_FILENAME);
            FileInputStream fis = new FileInputStream(initialFile);
            keyStore.load(fis, KEYSTORE_PASSWORD);
        } catch (IOException e) {
            keyStore = null;
        } catch (GeneralSecurityException e) {
            keyStore = null;
        }*/

        /*
         * No keys found: generate.
         */
        if (keyStore == null) {
            keyStore = createKeyStore();
        }

        mKeyStore = keyStore;
        store();
    }

    public KeyStore createKeyStore() {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            keyStore.load(null, KEYSTORE_PASSWORD);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    private boolean useAndroidKeyStore() {
        return true;
    }

    public boolean hasServerIdentityAlias() {
        return hasServerIdentityAlias(this.mKeyStore);
    }

    private boolean hasServerIdentityAlias(KeyStore keyStore) {
        try {
            return keyStore.containsAlias(SERVER_IDENTITY_ALIAS);
        } catch (KeyStoreException e) {
            return false;
        }
    }

    private void createIdentity(KeyStore keyStore) throws GeneralSecurityException {
        createIdentity(keyStore, SERVER_IDENTITY_ALIAS);
    }

    private void createIdentity(KeyStore keyStore, String str) throws GeneralSecurityException {
        createIdentity(keyStore, str, getUniqueId());
    }

    private void createIdentity(KeyStore keyStore, String str, String str2) throws GeneralSecurityException {
        Certificate[] certificateArr = new Certificate[]{SslUtil.generateX509V3Certificate(KeyPairGenerator.getInstance("RSA").generateKeyPair(), getCertificateName(str2))};
        keyStore.setKeyEntry(str, KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate(), null, certificateArr);
    }

    public void initializeKeyStore() {
        initializeKeyStore(getUniqueId());
    }

    public void initializeKeyStore(String str) {
        clearKeyStore();
        try {
            createIdentity(this.mKeyStore, LOCAL_IDENTITY_ALIAS, str);
            store();
        } catch (Throwable e) {
            throw new IllegalStateException("Unable to create identity KeyStore", e);
        }
    }

    private KeyStore createIdentityKeyStore() {
        KeyStore instance = null;
        try {
            if (useAndroidKeyStore()) {

                instance = KeyStore.getInstance("AndroidKeyStore");
                try {
                    instance.load(null);
                } catch (Throwable e) {
                    throw new GeneralSecurityException("Unable to create empty keyStore", e);
                }
            }
            instance = KeyStore.getInstance(KeyStore.getDefaultType());
            try {
                instance.load(null, KEYSTORE_PASSWORD);
            } catch (Throwable e2) {
                throw new GeneralSecurityException("Unable to create empty keyStore", e2);
            }

            createIdentity(instance);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return instance;
    }

    private void store(KeyStore keyStore) {
        try {
            File openFileOutput = new File("src/" + KEYSTORE_FILENAME);
            FileOutputStream fis = new FileOutputStream(openFileOutput);
            keyStore.store(fis, KEYSTORE_PASSWORD);
            fis.close();
        } catch (Throwable e) {
            throw new IllegalStateException("Unable to store keyStore", e);
        }
    }

    public void store() {
        if (this.mDynamicTrustManager == null)
            this.mDynamicTrustManager = new DynamicTrustManager(mKeyStore);
        this.mDynamicTrustManager.reloadTrustManager(this.mKeyStore);
        store(this.mKeyStore);
    }

    private static final String getCertificateName() {
        return getCertificateName(getUniqueId());
    }

    private static final String getCertificateName(String str) {
        return "CN=atvremote/" + "abcd" + "/" + "efgh" + "/" + "ijklm" + "/" + str;
    }

    /**
     * android tv method:
     * private static final String getCertificateName(String str) {
     * StringBuilder stringBuilder = new StringBuilder();
     * stringBuilder.append("CN=atvremote/");
     * stringBuilder.append(Build.PRODUCT);
     * stringBuilder.append("/");
     * stringBuilder.append(Build.DEVICE);
     * stringBuilder.append("/");
     * stringBuilder.append(Build.MODEL);
     * stringBuilder.append("/");
     * stringBuilder.append(str);
     * return stringBuilder.toString();
     * }
     */

    private static final String getUniqueId() {
        return UUID.randomUUID().toString();
    }

    public KeyManager[] getKeyManagers() {
        try {
            KeyManagerFactory instance = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            instance.init(this.mKeyStore, "".toCharArray());
            KeyManager[] mgers = instance.getKeyManagers();
            return mgers;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        throw new RuntimeException("lol");
        //return instance.getKeyManagers();
    }

    public TrustManager[] getTrustManagers() {
        try {
            return new DynamicTrustManager[]{};
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static String createAlias(String str) {
        return String.format(REMOTE_IDENTITY_ALIAS_PATTERN, new Object[]{str});
    }

    public void storeCertificate(Certificate certificate) {
        storeCertificate(certificate, Integer.toString(certificate.hashCode()));
    }


    public void storeCertificate(Certificate certificate, String str) {
        try {
            String createAlias = createAlias(str);
            String subjectDN = getSubjectDN(certificate);
            if (this.mKeyStore.containsAlias(createAlias)) {
                this.mKeyStore.deleteEntry(createAlias);
            }
            if (subjectDN != null) {
                Enumeration aliases = this.mKeyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String str2 = (String) aliases.nextElement();
                    String subjectDN2 = getSubjectDN(this.mKeyStore.getCertificate(str2));
                    if (subjectDN2 != null && subjectDN2.equals(subjectDN)) {
                        this.mKeyStore.deleteEntry(str2);
                    }
                }
            }
            this.mKeyStore.setCertificateEntry(createAlias, certificate);
            store();
        } catch (KeyStoreException e) {
        }
    }

    private static String getSubjectDN(Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            X500Principal subjectX500Principal = ((X509Certificate) certificate).getSubjectX500Principal();
            if (subjectX500Principal != null) {
                return subjectX500Principal.getName();
            }
        }
        return null;
    }


    public Certificate removeCertificate(String str) {
        try {
            String createAlias = createAlias(str);
            if (!this.mKeyStore.containsAlias(createAlias)) {
                return null;
            }
            Certificate certificate = this.mKeyStore.getCertificate(createAlias);
            this.mKeyStore.deleteEntry(createAlias);
            store();
            return certificate;
        } catch (KeyStoreException e) {
            return null;
        }
    }

    public void clear() {
        clearKeyStore();
        try {
            createIdentity(this.mKeyStore);
        } catch (GeneralSecurityException e) {
        }
        store();
    }

    private void clearKeyStore() {
        try {
            Enumeration aliases = this.mKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                this.mKeyStore.deleteEntry((String) aliases.nextElement());
            }
        } catch (KeyStoreException e) {
        }
        store();
    }


}
