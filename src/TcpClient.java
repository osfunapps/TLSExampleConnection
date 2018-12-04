import com.sun.corba.se.impl.protocol.giopmsgheaders.Message;
import com.sun.security.ntlm.Client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Map;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.security.auth.callback.Callback;

/* compiled from: Unknown */
class TcpClient {

    private static final String SSL_CONTEXT = "TLSv1.2";
    private KeyStoreManager mKeyStoreManager;


    public void connect() {
        try {
            //ProviderInstaller.installIfNeeded(mContext.getApplicationContext());
            this.mKeyStoreManager = new KeyStoreManager();
            CustomTrustedManager ctm = new CustomTrustedManager();
            KeyManager[] keyManagers = mKeyStoreManager.getKeyManagers();
            TrustManager[] trustManagers = ctm.gainTrustedManager(mKeyStoreManager);
            //TrustManager[] trustManagers = new CustomTrustedManager().gainTrustedManager(mKeyStoreManager,mContext);
            if (keyManagers.length != 0) {
                SSLContext instance = SSLContext.getInstance(SSL_CONTEXT);
                instance.init(keyManagers, trustManagers, new SecureRandom());
                SSLSocket sSLSocket = (SSLSocket) instance.getSocketFactory().createSocket("192.168.1.117", 6466);
                sSLSocket.setNeedClientAuth(true);
                sSLSocket.setUseClientMode(true);
                sSLSocket.setKeepAlive(true);
                sSLSocket.setTcpNoDelay(true);
                sSLSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                    public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent) {
                    }
                });

                sSLSocket.startHandshake();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
