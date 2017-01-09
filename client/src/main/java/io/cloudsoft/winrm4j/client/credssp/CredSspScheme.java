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

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Decoder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.xml.transform.OutputKeys;

import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.message.BufferedHeader;
import org.apache.http.util.CharArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredSspScheme extends AuthSchemeBase {
	
	private static final Logger LOG = LoggerFactory.getLogger(CredSspScheme.class);
	
	public static final String SCHEME_NAME = "CredSSP";
	
	enum State {
        UNINITIATED,
        TLS_HANDSHAKE,
        TLS_HANDSHAKE_FINISHED,
        FAILED,
    }

	private State state;
	private SSLEngine sslEngine;
	
    public CredSspScheme() {
    	state = State.UNINITIATED;
    	LOG.info("############ CredSSP auth provider created");
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
				sslContext = SSLContext.getDefault();
			} catch (NoSuchAlgorithmException e) {
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
			unwrap(inputString);
		}
		LOG.info("############# TLS handshake status: {}", getSSLEngine().getHandshakeStatus());
		if (getSSLEngine().getHandshakeStatus() == HandshakeStatus.FINISHED) {
			LOG.info("############# TLS HANDSHAKE FINISHED");
			state = State.TLS_HANDSHAKE_FINISHED;
		}
	}

	@Override
	public Header authenticate(Credentials credentials, HttpRequest request) throws AuthenticationException {
		
		String outputString = null;
		if (state == State.UNINITIATED) {
			beginHandshake();
			outputString = wrap();
			state = State.TLS_HANDSHAKE;
		} else if (state == State.TLS_HANDSHAKE) {
			outputString = wrap();
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

	private void beginHandshake() throws AuthenticationException {
		try {
			getSSLEngine().beginHandshake();
		} catch (SSLException e) {
			throw new AuthenticationException("SSL Engine error: "+e.getMessage(), e);
		}
	}
	
	private String wrap() throws AuthenticationException {
		SSLEngine sslEngine = getSSLEngine();
		SSLSession sslSession = sslEngine.getSession();
		ByteBuffer src = ByteBuffer.allocate(sslSession.getApplicationBufferSize());
		src.flip();
		ByteBuffer dst = ByteBuffer.allocate(sslSession.getPacketBufferSize());
		LOG.info("######### SSL Engine handshake status before wrap: {}", sslEngine.getHandshakeStatus());
		try {
			LOG.info("######### SSL Engine wrapping: {}", src);
			SSLEngineResult engineResult = sslEngine.wrap(src, dst);
			LOG.info("######### SSL Engine output {} (produced {} bytes): {}", 
					engineResult.getStatus(), engineResult.bytesProduced(), dst);
			if (engineResult.getStatus() != Status.OK) {
				throw new AuthenticationException("SSL Engine error status: "+engineResult.getStatus());
			}
		} catch (SSLException e) {
			LOG.error("########### SSL Engine wrap error: "+e.getMessage(), e);
			throw new AuthenticationException("SSL Engine wrap error: "+e.getMessage(), e);
		}
		LOG.info("######### SSL Engine handshake status after wrap: {}", sslEngine.getHandshakeStatus());
		return encode(dst);
	}
	
	private String unwrap(String inputString) throws MalformedChallengeException {
		SSLEngine sslEngine = getSSLEngine();
		SSLSession sslSession = sslEngine.getSession();
		ByteBuffer src = decode(inputString);
		ByteBuffer dst = ByteBuffer.allocate(sslSession.getApplicationBufferSize());
		LOG.info("######### SSL Engine handshake status before unwrap: {}", sslEngine.getHandshakeStatus());
		try {
			LOG.info("######### SSL Engine unwrapping: {}", src);
			SSLEngineResult engineResult = sslEngine.unwrap(src, dst);
			LOG.info("######### SSL Engine output {} (produced {} bytes): {}", 
					engineResult.getStatus(), engineResult.bytesProduced(), dst);			
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
		return encode(dst);
	}
	
	private String encode(ByteBuffer buffer) {
		buffer.flip();
		int limit = buffer.limit();
		byte[] bytes = new byte[limit];
		buffer.get(bytes);
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	private ByteBuffer decode(String inputString) {
		byte[] inputBytes = Base64.getDecoder().decode(inputString);
		ByteBuffer buffer = ByteBuffer.wrap(inputBytes);
		return buffer;
	}

	@Override
	public boolean isComplete() {
		return state == State.TLS_HANDSHAKE_FINISHED;
	}


//    @Override
//    public Header authenticate(Credentials credentials, HttpRequest request)
//            throws AuthenticationException {
//        Header hdr = super.authenticate(credentials, request);
//        return new BasicHeader(hdr.getName(), hdr.getValue().replace("NTLM", getSchemeName()));
//    }
}
