/**
 * Copyright (c) 2017 Evolveum
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
package io.cloudsoft.winrm4j.client.cxf;

import java.util.Map;

import org.apache.cxf.transport.http.asyncclient.AsyncHTTPConduitFactory;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;

/**
 * @author semancik
 *
 */
public class CustomAsyncHTTPConduitFactory extends AsyncHTTPConduitFactory {

	CustomAsyncHTTPConduitFactory() {
		super((Map<String, Object>)null);
	}

	@Override
	protected void adaptClientBuilder(HttpAsyncClientBuilder httpAsyncClientBuilder) {
		super.adaptClientBuilder(httpAsyncClientBuilder);
		AuthenticationStrategy targetAuthStrategy = new CustomTargetAuthenticationStrategy();
		httpAsyncClientBuilder.setTargetAuthenticationStrategy(targetAuthStrategy);
	}

	
	
}
