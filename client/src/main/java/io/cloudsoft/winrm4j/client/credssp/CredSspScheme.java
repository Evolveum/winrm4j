/*
 * Copyright (c) 2017 Radovan Semancik
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cloudsoft.winrm4j.client.credssp;

import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Base64.Decoder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.xml.transform.OutputKeys;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.InvalidCredentialsException;
import org.apache.http.auth.KerberosCredentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.auth.NTCredentials;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.impl.auth.NTLMEngine;
import org.apache.http.message.BufferedHeader;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.CharArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is NOT GSS based. It should be. But there is no NTLM support in GSS.
 * 
 * @author semancik
 */
public class CredSspScheme extends AuthSchemeBase {
	
	private static final Logger LOG = LoggerFactory.getLogger(CredSspScheme.class);
	
	public static final String SCHEME_NAME = "CredSSP";
	
	enum State {
        UNINITIATED,
        TLS_HANDSHAKE,
        TLS_HANDSHAKE_FINISHED,
        NEGO_TOKEN_SENT,
        NEGO_TOKEN_RECEIVED,
        PUB_KEY_AUTH_SENT,
        PUB_KEY_AUTH_RECEIVED,
        FAILED,
    }

	private State state;
	private SSLEngine sslEngine;
	private NTLMEngine ntlmEngine;
	private TsRequest lastReceivedTsRequest;
	
    public CredSspScheme() {
    	state = State.UNINITIATED;
    	LOG.info("############ CredSSP auth provider created");
    	
    	// HACK HACK HACK
    	try {
			Class<?> c = Class.forName("org.apache.http.impl.auth.NTLMEngineImpl");
			Constructor<?> constructor = c.getDeclaredConstructor();
			constructor.setAccessible(true);
			ntlmEngine = (NTLMEngine) constructor.newInstance();
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e);
		}
    	LOG.info("############ NTLMEngine created: {}", ntlmEngine);
	}

	@Override
    public String getSchemeName() {
        return SCHEME_NAME;
    }

	@Override
	public String getParameter(String name) {
		return null;
	}

	@Override
	public String getRealm() {
		return null;
	}

	@Override
	public boolean isConnectionBased() {
		return true;
	}
	
	private SSLEngine getSSLEngine() {
		if (sslEngine == null) {
			SSLContext sslContext;
			try {
				sslContext = SSLContext.getInstance("TLS");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("Error creating SSL Context: "+e.getMessage(), e);
			}
			X509TrustManager tm = new X509TrustManager() {

				@Override
				public void checkClientTrusted(X509Certificate[] chain, String authType)
						throws CertificateException {
					// Nothing to do, accept all
				}

				@Override
				public void checkServerTrusted(X509Certificate[] chain, String authType)
						throws CertificateException {
					// Nothing to do, accept all
				}

				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
				
			};
			try {
				// TODO: check if this is local or global config
				sslContext.init(null, new TrustManager[] { tm }, null);
			} catch (KeyManagementException e) {
				throw new RuntimeException("SSL Context initialization error: "+e.getMessage(), e);
			}
			sslEngine = sslContext.createSSLEngine();
			sslEngine.setUseClientMode(true);
		}
		return sslEngine;
	}

	@Override
	protected void parseChallenge(CharArrayBuffer buffer, int beginIndex, int endIndex)
			throws MalformedChallengeException {
		
		LOG.info("####### PARSE CHALLENGE ###");
		
		String inputString = buffer.substringTrimmed(beginIndex, endIndex);
		LOG.info("############# << Received: {}", inputString);
		if (inputString.isEmpty()) {
			if (state == State.UNINITIATED) {
				// This is OK, just send out first message. That should start TLS handshake
			} else {
				LOG.error("############# Received unexpected empty input in state "+state);
				throw new MalformedChallengeException("Received unexpected empty input in state "+state);
			}
		}
		if (state == State.TLS_HANDSHAKE) {
			unwrapHandshake(inputString);
			LOG.info("############# TLS handshake status: {}", getSSLEngine().getHandshakeStatus());
			if (getSSLEngine().getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING) {
				LOG.info("############# TLS HANDSHAKE FINISHED");
				state = State.TLS_HANDSHAKE_FINISHED;
				try {
					Principal peerPrincipal = getSSLEngine().getSession().getPeerPrincipal();
					LOG.info("Peer principal: ({}) {}", peerPrincipal.getClass(), peerPrincipal);
					Certificate[] peerCertificates = getSSLEngine().getSession().getPeerCertificates();
					for (Certificate cert: peerCertificates) {
						LOG.info("Peer cert: ({}) {}", cert.getClass(), cert);
						PublicKey publicKey = cert.getPublicKey();
						LOG.info("Peer public key: ({}) {}", publicKey.getClass(), publicKey);
					}
				} catch (SSLPeerUnverifiedException e) {
					LOG.error("############# Error working with peer principal "+e.getMessage(), e);
					throw new MalformedChallengeException("Error working with peer principal "+e.getMessage(), e);
				}
				
			}
		}
		if (state == State.NEGO_TOKEN_SENT) {
			ByteBuffer buf = unwrap(inputString);
			LOG.info("Received(1) tsrequest(negotoken):\n{}", CredSSPUtil.dump(buf));
			state = State.NEGO_TOKEN_RECEIVED;
			lastReceivedTsRequest = TsRequest.createDecoded(buf);
			LOG.error("############# Received(1) TsRequest:\n"+lastReceivedTsRequest.debugDump());
		}
		if (state == State.PUB_KEY_AUTH_SENT) {
			ByteBuffer buf = unwrap(inputString);
			LOG.info("Received(2) tsrequest(negotoken):\n{}", CredSSPUtil.dump(buf));
			state = State.PUB_KEY_AUTH_RECEIVED;
			lastReceivedTsRequest = TsRequest.createDecoded(buf);
			LOG.error("############# Received(2) TsRequest:\n"+lastReceivedTsRequest.debugDump());
		}
	}
	
	@Override
    @Deprecated
    public Header authenticate(
            final Credentials credentials,
            final HttpRequest request) throws AuthenticationException {
        return authenticate(credentials, request, null);
    }

	@Override
    public Header authenticate(
            final Credentials credentials,
            final HttpRequest request,
            final HttpContext context) throws AuthenticationException {
		
		LOG.info("####### AUTHENTICATE ###");
		
		NTCredentials ntcredentials = null;
        try {
            ntcredentials = (NTCredentials) credentials;
        } catch (final ClassCastException e) {
            throw new InvalidCredentialsException(
             "Credentials cannot be used for NTLM authentication: "
              + credentials.getClass().getName());
        }
		
		String outputString = null;
		
		if (state == State.UNINITIATED) {
			beginHandshake();
			outputString = wrapHandshake();
			state = State.TLS_HANDSHAKE;
			
		} else if (state == State.TLS_HANDSHAKE) {
			outputString = wrapHandshake();
			
		} else if (state == State.TLS_HANDSHAKE_FINISHED) {
			
			ByteBuffer buf = allocateOutBuffer();
			String base64NtlmNego = ntlmEngine.generateType1Msg(
					ntcredentials.getDomain(), ntcredentials.getWorkstation());
			byte[] ntlmNego = Base64.getDecoder().decode(base64NtlmNego);
			TsRequest req = TsRequest.createNegoToken(ntlmNego);
			req.encode(buf);
			buf.flip();
			LOG.info("######## sending NEGO token:\n{}", CredSSPUtil.dump(buf));
			outputString = wrap(buf);
			state = State.NEGO_TOKEN_SENT;
			
		} else if (state == State.NEGO_TOKEN_RECEIVED) {
			ByteBuffer buf = allocateOutBuffer();
			String base64NtlmNego = ntlmEngine.generateType3Msg(
					ntcredentials.getUserName(), ntcredentials.getPassword(), 
					ntcredentials.getDomain(), ntcredentials.getWorkstation(),
					Base64.getEncoder().encodeToString(lastReceivedTsRequest.getNegoToken()));
			byte[] ntlmNego = Base64.getDecoder().decode(base64NtlmNego);
			TsRequest req = TsRequest.createNegoToken(ntlmNego);
			byte[] pubKeyAuth;
			try {
				pubKeyAuth = createPubKeyAuth();
				req.setPubKeyAuth(pubKeyAuth);
			} catch (SSLPeerUnverifiedException e) {
				throw new AuthenticationException(e.getMessage(), e);
			}
			req.encode(buf);
			buf.flip();
			LOG.info("######## sending pubKeyAuth token:\n{}", CredSSPUtil.dump(buf));
			outputString = wrap(buf);
			state = State.PUB_KEY_AUTH_SENT;
			
		} else {
			throw new AuthenticationException("Wrong state "+state);
		}
		
		LOG.info("############# >> Seding: {}", outputString);
		final CharArrayBuffer buffer = new CharArrayBuffer(32);
		if (isProxy()) {
            buffer.append(AUTH.PROXY_AUTH_RESP);
        } else {
            buffer.append(AUTH.WWW_AUTH_RESP);
        }
		buffer.append(": CredSSP ");
		buffer.append(outputString);
		return new BufferedHeader(buffer);
	}

	private byte[] createPubKeyAuth() throws SSLPeerUnverifiedException {
		for(Certificate peerCertificate: sslEngine.getSession().getPeerCertificates()) {
			LOG.info("CCCCC: peer certificate: ({})\n{}", peerCertificate.getClass(), peerCertificate);
			if (!(peerCertificate instanceof X509Certificate)) {
				continue;
			}
			X509Certificate peerX509Cerificate = (X509Certificate)peerCertificate;			
			if (peerX509Cerificate.getBasicConstraints() != -1) {
				LOG.debug("Skipping CA certificate {}", ((X509Certificate)peerCertificate).getSubjectDN());
				continue;
			}
			PublicKey publicKey = peerX509Cerificate.getPublicKey();
			LOG.info("CCCCC: peer public key: ({})\n{}", publicKey.getClass(), publicKey);
			byte[] encodedPubKey = publicKey.getEncoded();
			LOG.info("CCCCC: peer public key encoded:\n{}", CredSSPUtil.dump(encodedPubKey));
		}
		return null;
	}

	private void beginHandshake() throws AuthenticationException {
		try {
			getSSLEngine().beginHandshake();
		} catch (SSLException e) {
			throw new AuthenticationException("SSL Engine error: "+e.getMessage(), e);
		}
	}
	
	private ByteBuffer allocateOutBuffer() {
		SSLEngine sslEngine = getSSLEngine();
		SSLSession sslSession = sslEngine.getSession();
		return ByteBuffer.allocate(sslSession.getApplicationBufferSize());
	}
	
	private String wrapHandshake() throws AuthenticationException {
		ByteBuffer src = allocateOutBuffer();
		src.flip();
		SSLEngine sslEngine = getSSLEngine();
		SSLSession sslSession = sslEngine.getSession();
		// Needs to be twice the size as there may be two wraps during handshake.
		// Primitive and inefficient solution, but it works.
		ByteBuffer dst = ByteBuffer.allocate(sslSession.getPacketBufferSize() * 2);
		LOG.info("######### SSL Engine handshake status before before wrap: {}", sslEngine.getHandshakeStatus());
		while (sslEngine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
			wrap(src, dst);
		}
		LOG.info("######### SSL Engine handshake status after after wrap: {}", sslEngine.getHandshakeStatus());
		dst.flip();
		return encodeBase64(dst);
	}
	
	private String wrap(ByteBuffer src) throws AuthenticationException {
		SSLEngine sslEngine = getSSLEngine();
		SSLSession sslSession = sslEngine.getSession();
		ByteBuffer dst = ByteBuffer.allocate(sslSession.getPacketBufferSize());
		wrap(src,dst);
		dst.flip();
		LOG.info("######### Sending SSL encoded:\n{}", CredSSPUtil.dump(dst));
		return encodeBase64(dst);
	}
	
	private void wrap(ByteBuffer src, ByteBuffer dst) throws AuthenticationException {
		SSLEngine sslEngine = getSSLEngine();
		LOG.info("######### SSL Engine handshake status before wrap: {}", sslEngine.getHandshakeStatus());
		try {
			LOG.info("######### SSL Engine wrapping: {} to {}", src, dst);
			SSLEngineResult engineResult = sslEngine.wrap(src, dst);
			LOG.info("######### SSL Engine output {} (produced {} bytes): {}", 
					engineResult.getStatus(), engineResult.bytesProduced(), dst);
			if (engineResult.getStatus() != Status.OK) {
				LOG.error("########## SSL Engine error status: "+engineResult.getStatus());
				throw new AuthenticationException("SSL Engine error status: "+engineResult.getStatus());
			}
		} catch (SSLException e) {
			LOG.error("########### SSL Engine wrap error: "+e.getMessage(), e);
			throw new AuthenticationException("SSL Engine wrap error: "+e.getMessage(), e);
		}
		LOG.info("######### SSL Engine handshake status after wrap: {}", sslEngine.getHandshakeStatus());		
	}
	
	private void unwrapHandshake(String inputString) throws MalformedChallengeException {
		SSLEngine sslEngine = getSSLEngine();
		SSLSession sslSession = sslEngine.getSession();
		ByteBuffer src = decodeBase64(inputString);
		ByteBuffer dst = ByteBuffer.allocate(sslSession.getApplicationBufferSize());
		LOG.info("######### SSL Engine handshake status before before unwrap: {}", sslEngine.getHandshakeStatus());
		while (sslEngine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP) {
			unwrap(src, dst);
		}
		LOG.info("######### SSL Engine handshake status after after unwrap: {}", sslEngine.getHandshakeStatus());
	}
	
	private ByteBuffer unwrap(String inputString) throws MalformedChallengeException {
		SSLEngine sslEngine = getSSLEngine();
		SSLSession sslSession = sslEngine.getSession();
		ByteBuffer src = decodeBase64(inputString);
		ByteBuffer dst = ByteBuffer.allocate(sslSession.getApplicationBufferSize());
		unwrap(src, dst);
		dst.flip();
		return dst;
	}
	
	private void unwrap(ByteBuffer src, ByteBuffer dst) throws MalformedChallengeException {
		
		LOG.info("######### SSL Engine handshake status before unwrap: {}", sslEngine.getHandshakeStatus());
		try {
			LOG.info("######### SSL Engine unwrapping: {} to {}", src, dst);
			SSLEngineResult engineResult = sslEngine.unwrap(src, dst);
			LOG.info("######### SSL Engine output {} (produced {} bytes): {}", 
					engineResult.getStatus(), engineResult.bytesProduced(), dst);	
			if (engineResult.getHandshakeStatus() == HandshakeStatus.FINISHED) {
				LOG.info("######### SSL handshake finished (unwrap)");
			}
			if (engineResult.getStatus() != Status.OK) {
				throw new MalformedChallengeException("SSL Engine error status: "+engineResult.getStatus());
			}
			
			if (sslEngine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
				Runnable task = sslEngine.getDelegatedTask();
				LOG.info("######### SSL Engine running task: {}", task);
				task.run();
			}
			
		} catch (SSLException e) {
			LOG.error("########### SSL Engine unwrap error: "+e.getMessage(), e);
			throw new MalformedChallengeException("SSL Engine unwrap error: "+e.getMessage(), e);
		}
		LOG.info("######### SSL Engine handshake status after unwrap: {}", sslEngine.getHandshakeStatus());
	}
	
	private String encodeBase64(ByteBuffer buffer) {
		int limit = buffer.limit();
		byte[] bytes = new byte[limit];
		buffer.get(bytes);
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	private ByteBuffer decodeBase64(String inputString) {
		byte[] inputBytes = Base64.getDecoder().decode(inputString);
		ByteBuffer buffer = ByteBuffer.wrap(inputBytes);
		return buffer;
	}


	@Override
	public boolean isComplete() {
		return state == State.PUB_KEY_AUTH_RECEIVED;
	}


}
