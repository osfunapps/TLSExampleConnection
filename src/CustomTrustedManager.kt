import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.net.URL
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory

/**
 * Created by osapps on 29/11/2018.
 */
class CustomTrustedManager {

    fun gainTrustedManager(mKeyStoreManager: KeyStoreManager): Array<out TrustManager>? {
        // Load CAs from an InputStream
// (could be from a resource or ByteArrayInputStream or ...)
        //todo: also use bouncy castle
        val cf = CertificateFactory.getInstance("X.509")
// From https://www.washington.edu/itconnect/security/ca/load-der.crt
        //val caInput = BufferedInputStream(FileInputStream("load-der.crt"))
        val initialFile = File("src/tv_cert.crt")
        val caInput = FileInputStream(initialFile)

        val ca: Certificate
        try {
            ca = cf.generateCertificate(caInput)
            System.out.println("ca=" + (ca as X509Certificate).getSubjectDN())
        } finally {
            caInput.close()
        }

// Create a KeyStore containing our trusted CAs
        val keyStoreType = KeyStore.getDefaultType()
        val keyStore = KeyStore.getInstance(keyStoreType)
        keyStore.load(null, null)
        mKeyStoreManager.mKeyStore.setCertificateEntry("ca", ca)
        //keyStore.setCertificateEntry("ca", ca)

// Create a TrustManager that trusts the CAs in our KeyStore
        val tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm()
        val tmf = TrustManagerFactory.getInstance(tmfAlgorithm)
        tmf.init(mKeyStoreManager.mKeyStore)
        //tmf.init(keyStore)
        return tmf.getTrustManagers()
        /*val itk = KeyStore[]{keyStore}
        return Pair(KeyStore[1]{keyStore}, )

// Create an SSLContext that uses our TrustManager
        val context = SSLContext.getInstance("TLS")
        context.init(null, tmf.getTrustManagers(), null)

// Tell the URLConnection to use a SocketFactory from our SSLContext
        val url = URL("https://certs.cac.washington.edu/CAtest/")
        val urlConnection = url.openConnection() as HttpsURLConnection
        urlConnection.setSSLSocketFactory(context.getSocketFactory())
        val `in` = urlConnection.getInputStream()
        copyInputStreamToOutputStream(`in`, System.out)
*/
    }
}