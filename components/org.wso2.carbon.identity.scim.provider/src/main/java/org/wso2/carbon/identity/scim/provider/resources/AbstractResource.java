/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim.provider.resources;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.scim.provider.util.JAXRSResponseBuilder;
import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;

import javax.ws.rs.core.Response;

public class AbstractResource {
    private static Log logger = LogFactory.getLog(AbstractResource.class);
    private Encoder defaultEncoder = new JSONEncoder();

    public String identifyOutputFormat(String format) {
        if (format == null || "*/*".equals(format) || format.startsWith(SCIMConstants.APPLICATION_JSON)) {
            return SCIMConstants.APPLICATION_JSON;
        } else {
            return format;
        }
    }

    public String identifyInputFormat(String format) {
        if (format == null || "*/*".equals(format) || format.startsWith(SCIMConstants.APPLICATION_JSON)) {
            return SCIMConstants.APPLICATION_JSON;
        } else {
            return format;
        }
    }

    /**
     * Build an error message for a Charon exception. Encoding format depends on the 'Accept' header. We go with the
     * JSON encoder as default if not specified.
     *
     * @param e CharonException
     * @param encoder
     * @return
     */
    protected Response handleCharonException(CharonException e, Encoder encoder) {
        if (logger.isDebugEnabled()) {
            logger.debug(e.getMessage(), e);
        }

        // if the encoder is null we go with the JSON encoder as the default encoder.
        if (encoder == null) {
            logger.error("No encoder found. Sending error response using default JSON encoder");
            encoder = defaultEncoder;
        }

        //create SCIM response with code as the same of exception and message as error message of the exception
        if (e.getCode() == -1) {
            e.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
        }
        return new JAXRSResponseBuilder().buildResponse(AbstractResourceEndpoint.encodeSCIMException(encoder, e));
    }

    /**
     * Build the error response if the requested input or output format is not supported. We go with JSON encoder as
     * the encoder for the error response.
     * @param e
     * @return
     */
    protected Response handleFormatNotSupportedException(FormatNotSupportedException e) {
        if (logger.isDebugEnabled()) {
            logger.debug(e.getMessage(), e);
        }

        // use the default JSON encoder to build the error response.
        return new JAXRSResponseBuilder().buildResponse(
                AbstractResourceEndpoint.encodeSCIMException(defaultEncoder, e));
    }
}
