/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.cloudsoft.winrm4j.client.cxf;

import java.io.IOException;

import org.apache.cxf.Bus;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.HTTPConduitConfigurer;
import org.apache.cxf.transport.http.asyncclient.AsyncHTTPConduitFactory;
import org.apache.cxf.transport.http.asyncclient.AsyncHttpTransportFactory;
import org.apache.cxf.ws.addressing.EndpointReferenceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomAsyncHttpTransportFactory extends AsyncHttpTransportFactory {
	
	private static final Logger LOG = LoggerFactory.getLogger(CustomAsyncHttpTransportFactory.class);
	
	private AsyncHTTPConduitFactory conduitFactory = new CustomAsyncHTTPConduitFactory();
	
	protected AsyncHTTPConduitFactory getConduitFactory() {
		return conduitFactory;
	}
	
	// Copied from AsyncHttpTransportFactory. But there seems to be no better way how to
	// do this as there is no getter for conduit factory in AsyncHttpTransportFactory.
	@Override
    public Conduit getConduit(EndpointInfo endpointInfo, EndpointReferenceType target, Bus bus)
        throws IOException {
        
		LOG.info("########## creating conduit");
		
        HTTPConduit conduit = null;
        // need to updated the endpointInfo
        endpointInfo.setAddress(getAddress(endpointInfo));
        
        conduit = getConduitFactory().createConduit(bus, endpointInfo, target);

        // Spring configure the conduit.  
        String address = conduit.getAddress();
        if (address != null && address.indexOf('?') != -1) {
            address = address.substring(0, address.indexOf('?'));
        }
        HTTPConduitConfigurer c1 = bus.getExtension(HTTPConduitConfigurer.class);
        if (c1 != null) {
            c1.configure(conduit.getBeanName(), address, conduit);
        }
        configure(bus, conduit, conduit.getBeanName(), address);
        conduit.finalizeConfig();
        return conduit;
    }

}
