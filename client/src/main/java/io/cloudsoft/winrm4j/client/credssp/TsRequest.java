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
import java.util.Arrays;

import org.apache.http.auth.MalformedChallengeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TsRequest {
	
	private static final Logger LOG = LoggerFactory.getLogger(TsRequest.class);
	
	private static final int VERSION = 3;
	
	private byte[] negoToken;
	private byte[] authInfo;
	private byte[] pubKeyAuth;
	
	protected TsRequest() {
		super();
	}
	
	public static TsRequest createNegoToken(byte[] negoToken) {
		TsRequest req = new TsRequest();
		req.negoToken = negoToken;
		return req;
	}
	
	public static TsRequest createDecoded(ByteBuffer buf) throws MalformedChallengeException {
		TsRequest req = new TsRequest();
		req.decode(buf);
		return req;
	}
	
	public byte[] getNegoToken() {
		return negoToken;
	}

	public void setNegoToken(byte[] negoToken) {
		this.negoToken = negoToken;
	}

	public byte[] getAuthInfo() {
		return authInfo;
	}

	public void setAuthInfo(byte[] authInfo) {
		this.authInfo = authInfo;
	}

	public byte[] getPubKeyAuth() {
		return pubKeyAuth;
	}

	public void setPubKeyAuth(byte[] pubKeyAuth) {
		this.pubKeyAuth = pubKeyAuth;
	}

	public void decode(ByteBuffer buf) throws MalformedChallengeException {
		negoToken = null;
		authInfo = null;
		pubKeyAuth = null;
		
		getByteAndAssert(buf, 0x30, "initial sequence");
		parseLength(buf);
				
		while (buf.hasRemaining()) {		
			int contentTag = getAndAssertContentSpecificTag(buf, "content tag");
			parseLength(buf);
			switch (contentTag) {
				case 0:
					processVersion(buf);
					break;
				case 1:
					parseNegoTokens(buf);
					break;
				case 2:
					parseAuthInfo(buf);
					break;
				case 3:
					parsePubKeyAuth(buf);
					break;
				case 4:
					processErrorCode(buf);
					break;
				default:
					parseError(buf, "unexpected content tag "+contentTag);
			}
		}
	}

	private void processVersion(ByteBuffer buf) throws MalformedChallengeException {
		getByteAndAssert(buf, 0x02, "version type");
		getLengthAndAssert(buf, 1, "version length");
		getByteAndAssert(buf, VERSION, "wrong protocol version");
	}
	
	private void parseNegoTokens(ByteBuffer buf) throws MalformedChallengeException {
		getByteAndAssert(buf, 0x30, "negoTokens sequence");
		parseLength(buf);
		// there may be both 0x30LL encoding and 0x30LL0x30LL encoding. Accept both.
		byte bufByte = buf.get();
		if (bufByte == 0x30) {
			parseLength(buf);
			bufByte = buf.get();
		}
		if ((bufByte & 0xff) != 0xa0) {
			parseError(buf, "negoTokens: wrong content-specific tag "+String.format("%02X", bufByte));
		}
		parseLength(buf);
		getByteAndAssert(buf, 0x04, "negoToken type");
		
		LOG.info("PPPPPPPP: negoToken");
		int tokenLength = parseLength(buf);
		LOG.info("PPPPPPPP: negoToken len {}", tokenLength);
		negoToken = new byte[tokenLength];
		LOG.info("PPPPPPPP: before negoToken parse: pos={}", buf.position());
		buf.get(negoToken);
		LOG.info("PPPPPPPP: after negoToken parse: pos={}", buf.position());
	}
	
	private void parseAuthInfo(ByteBuffer buf) throws MalformedChallengeException {
		getByteAndAssert(buf, 0x04, "authInfo type");
		int length = parseLength(buf);
		authInfo = new byte[length];
		buf.get(authInfo);
	}
	
	private void parsePubKeyAuth(ByteBuffer buf) throws MalformedChallengeException {
		getByteAndAssert(buf, 0x04, "pubKeyAuth type");
		int length = parseLength(buf);
		pubKeyAuth = new byte[length];
		buf.get(pubKeyAuth);
	}

	private void processErrorCode(ByteBuffer buf) throws MalformedChallengeException {
		getLengthAndAssert(buf, 3, "error code length");
		getByteAndAssert(buf, 0x02, "error code type");
		getLengthAndAssert(buf, 1, "error code length");
		byte errorCode = buf.get();
		parseError(buf, "Error code " + errorCode);
	}

	private void getByteAndAssert(ByteBuffer buf, int expectedValue, String errorMessage) throws MalformedChallengeException {
		byte bufByte = buf.get();
		if (bufByte != expectedValue) {
			parseError(buf, errorMessage + expectMessage(expectedValue, bufByte));
		}
	}
	
	private String expectMessage(int expectedValue, int realValue) {
		return "(expected "+String.format("%02X", expectedValue)+", got "+String.format("%02X", realValue)+")";
	}
	
	private int parseLength(ByteBuffer buf) {
		byte bufByte = buf.get();
		LOG.info("LLL: {} bufByte={} ({})", buf.position(), bufByte, String.format("%02X", bufByte));
		if (bufByte == 0x80) {
			return -1; // infinite
		}
		LOG.info("LLLX: {} {} ({})", buf.position(), (bufByte & 0x80), String.format("%02X", (bufByte & 0x80)));
		if ((bufByte & 0x80) == 0x80) {
			int size = bufByte & 0x7f;
			LOG.info("LLL: size {}", size);
			int length = 0;
			for (int i = 0; i < size; i++) {
				bufByte = buf.get();
				length = (length << 8) + (bufByte & 0xff);
			}
			return length;
		} else {
			return bufByte;
		}
	}

	private void getLengthAndAssert(ByteBuffer buf, int expectedValue, String errorMessage) throws MalformedChallengeException {
		int bufLength = parseLength(buf);
		if (expectedValue != bufLength) {
			parseError(buf, errorMessage + expectMessage(expectedValue, bufLength));
		}
	}
	
	private int getAndAssertContentSpecificTag(ByteBuffer buf, String errorMessage) throws MalformedChallengeException {
		byte bufByte = buf.get();
		LOG.info("PPPPPPPP: {} bufByte={} ({})", buf.position(), bufByte, String.format("%02X", bufByte));
		if ((bufByte & 0xe0) != 0xa0) {
			parseError(buf, errorMessage+": wrong content-specific tag "+String.format("%02X", bufByte));
		}
		int tag = bufByte & 0x1f;
		LOG.info("PPPPPPPP: tag={}", tag);
		return tag;
	}	

	private void parseError(ByteBuffer buf, String errorMessage) throws MalformedChallengeException {
		throw new MalformedChallengeException("Error parsing TsRequest (position:"+buf.position()+"): "+errorMessage);
	}

	public void encode(ByteBuffer buf) {
		ByteBuffer inner = ByteBuffer.allocate(buf.capacity());
		
		// version tag [0]
		inner.put((byte)(0x00 | 0xa0));
		inner.put((byte)3); // length
		
		inner.put((byte)(0x02)); // INTEGER tag
		inner.put((byte)1); // length
		inner.put((byte)VERSION); // value
		
		if (negoToken != null) {
			inner.put((byte)(0x01 | 0xa0)); // negoData tag [1]
			inner.put(encodeLength(negoToken.length + 8)); // length
			
			inner.put((byte)(0x30)); // SEQUENCE tag
			inner.put(encodeLength(negoToken.length + 6)); // length
			
			inner.put((byte)(0x30)); // .. of SEQUENCE tag
			inner.put(encodeLength(negoToken.length + 4)); // length
			
			inner.put((byte)(0x00 | 0xa0)); // negoToken tag [0]
			inner.put(encodeLength(negoToken.length + 2)); // length
			
			inner.put((byte)(0x04)); // OCTET STRING tag
			inner.put(encodeLength(negoToken.length)); // length
			
			inner.put(negoToken);
		}
		
		if (authInfo != null) {
			byte[] authInfoEncodedLength = encodeLength(authInfo.length);
			
			inner.put((byte)(0x02 | 0xa0)); // authInfo tag [2]
			inner.put(encodeLength(1 + authInfoEncodedLength.length + authInfo.length)); // length
			
			inner.put((byte)(0x04)); // OCTET STRING tag
			inner.put(authInfoEncodedLength);
			inner.put(authInfo);
		}
		
		if (pubKeyAuth != null) {
			byte[] pubKeyAuthEncodedLength = encodeLength(pubKeyAuth.length);
			
			inner.put((byte)(0x03 | 0xa0)); // pubKeyAuth tag [3]
			inner.put(encodeLength(1 + pubKeyAuthEncodedLength.length + pubKeyAuth.length)); // length
			
			inner.put((byte)(0x04)); // OCTET STRING tag
			inner.put(pubKeyAuthEncodedLength);
			inner.put(pubKeyAuth);
		}
		
		inner.flip();
		
		// SEQUENCE tag
		buf.put((byte)(0x10 | 0x20));
		buf.put(encodeLength(inner.limit()));
		buf.put(inner);
	}

	private byte[] encodeLength(int length) {
		if (length < 128) {
			byte[] encoded = new byte[1];
			encoded[0] = (byte)length;
			return encoded;
		}
		
		int size = 1;

		int val = length;
		while ((val >>>= 8) != 0) {
			size++;
		}
		
		LOG.info("ELLLL: length={}, size={}", length, size);
		byte[] encoded = new byte[1 + size];
		encoded[0] = (byte)(size | 0x80);
		
		int shift = (size - 1) * 8;
		for (int i = 0; i < size; i++) {
			LOG.info("ELLLLis: i={} length={} shift={}", i, length, shift);
			encoded[i+1] = (byte)(length >> shift);
			shift -= 8;
			LOG.info("ELLLLie: i={} length={} shift={}", i, length, shift);
		}
		
		return encoded;
	}
	
	public String debugDump() {
		StringBuilder sb = new StringBuilder("TsRequest\n");
		sb.append("  negoToken:\n");
		sb.append("    ");
		CredSSPUtil.dump(sb, negoToken);
		sb.append("\n");
		sb.append("  authInfo:\n");
		sb.append("    ");
		CredSSPUtil.dump(sb, authInfo);
		sb.append("\n");
		sb.append("  pubKeyAuth:\n");
		sb.append("    ");
		CredSSPUtil.dump(sb, pubKeyAuth);
		return sb.toString();
	}

	@Override
	public String toString() {
		return "TsRequest(negoToken=" + Arrays.toString(negoToken) + ", authInfo="
				+ Arrays.toString(authInfo) + ", pubKeyAuth=" + Arrays.toString(pubKeyAuth) + ")";
	}
}
