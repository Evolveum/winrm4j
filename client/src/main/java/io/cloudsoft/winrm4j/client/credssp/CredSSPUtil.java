/**
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

/**
 * @author semancik
 *
 */
public class CredSSPUtil {

	public static String dump(ByteBuffer buf) {
		ByteBuffer dup = buf.duplicate();
		StringBuilder sb = new StringBuilder(dup.toString());
		sb.append(": ");
		while (dup.position() < dup.limit()) {
			sb.append(String.format("%02X ", dup.get()));
		}
		return sb.toString();
	}
	
	public static void dump(StringBuilder sb, byte[] bytes) {
		if (bytes == null) {
			sb.append("null");
			return;
		}
		for (byte b: bytes) {
			sb.append(String.format("%02X ", b));
		}
	}
	
	public static String dump(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		dump(sb, bytes);
		return sb.toString();
	}
	
}
