/*
 * Copyright (c) 2017 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cloudsoft.winrm4j.client;

import java.io.StringWriter;

public class Command {
	
	private WinRmClient client;
	private String commandId;
	private String lastOut;
	private String lastErr;
	
	Command(WinRmClient client, String commandId) {
		super();
		this.client = client;
		this.commandId = commandId;
	}
	
	public String getLastOut() {
		return lastOut;
	}

	public String getLastErr() {
		return lastErr;
	}

	public Integer receive() {
		StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();
		Integer exitCode = client.receiveCommandSingle(commandId, out, err);
		lastOut = out.toString();
		lastErr = err.toString();
		return exitCode;
	}
	
	public void send(String tx) {
		client.sendCommandSingle(commandId, tx);
	}

	public void release() {
		client.releaseCommand(commandId);
	}
}
