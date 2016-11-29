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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.jaxrs.designator.PATCH;
import org.wso2.carbon.identity.scim.provider.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim.provider.util.JAXRSResponseBuilder;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.exceptions.BadRequestException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.extensions.UserManager;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.protocol.endpoints.UserResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class UserResource extends AbstractResource {
    private static Log logger = LogFactory.getLog(UserResource.class);

    @GET
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
                            @HeaderParam(SCIMConstants.AUTHENTICATION_TYPE_HEADER) String authMechanism,
                            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Encoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/json.
            format = identifyOutputFormat(format);
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder(SCIMConstants.identifyFormat(format));

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(
                    authorization);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();

            SCIMResponse scimResponse = userResourceEndpoint.get(id, format, userManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return new JAXRSResponseBuilder().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e,encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    public Response createUser(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                               @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
                               @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
                               String resourceString) {

        Encoder encoder = null;
        try {
            // obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }
            // identify input format
            inputFormat = identifyInputFormat(inputFormat);
            // set the format in which the response should be encoded, if not specified in the
            // request,
            // defaults to application/json.
            outputFormat = identifyOutputFormat(outputFormat);
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder(SCIMConstants.identifyFormat(outputFormat));

            // obtain the user store manager
            UserManager userManager = identitySCIMManager.getUserManager(authorization);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();

            SCIMResponse response = userResourceEndpoint.create(resourceString, inputFormat,
                    outputFormat, userManager);

            return new JAXRSResponseBuilder().buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @DELETE
    @Path("{id}")
    public Response deleteUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
                               @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {
        Encoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/json.
            if (format == null) {
                format = SCIMConstants.APPLICATION_JSON;
            }
            // set the format in which the response should be encoded, if not specified in the
            // request,
            // defaults to application/json.
            format = identifyOutputFormat(format);
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder(SCIMConstants.identifyFormat(format));

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(
                    authorization);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();

            SCIMResponse scimResponse = userResourceEndpoint.delete(id, userManager, format);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return new JAXRSResponseBuilder().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
                            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
                            @QueryParam("attributes") String searchAttribute, @QueryParam("filter") String filter,
                            @QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
                            @QueryParam("sortBy") String sortBy, @QueryParam("sortOrder") String sortOrder) {
        Encoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/json.
            format = identifyOutputFormat(format);
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder(SCIMConstants.identifyFormat(format));

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(
                    authorization);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            SCIMResponse scimResponse = null;
            if (filter != null || searchAttribute != null) {
                scimResponse = userResourceEndpoint.listByFilterAndAttribute(filter, searchAttribute, userManager,
                        format);
            } else if (startIndex == null && count == null && sortBy == null) {
                scimResponse = userResourceEndpoint.list(userManager, format);
            } else {
                // All other query parameters are not supported hence send a error message.
                // TODO Implement support for other parameters
                throw new BadRequestException(ResponseCodeConstants.DESC_BAD_REQUEST_GET);
            }

            return new JAXRSResponseBuilder().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        } catch (BadRequestException e) {
            if (logger.isDebugEnabled()) {
                logger.debug(e.getMessage(), e);
            }
            return new JAXRSResponseBuilder().buildResponse(AbstractResourceEndpoint
                    .encodeSCIMException(encoder, e));
        }
    }

    @PUT
    @Path("{id}")
    public Response updateUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                               @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
                               @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
                               String resourceString) {
        Encoder encoder = null;
        try {
            // obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }
            // identify input format
            inputFormat = identifyInputFormat(inputFormat);
            // set the format in which the response should be encoded, if not specified in the
            // request,
            // defaults to application/json.
            outputFormat = identifyOutputFormat(outputFormat);
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder(SCIMConstants.identifyFormat(outputFormat));

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(
                    authorization);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();

            SCIMResponse response = userResourceEndpoint.updateWithPUT(id, resourceString,
                    inputFormat, outputFormat, userManager);

            return new JAXRSResponseBuilder().buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PATCH
    @Path("{id}")
    public Response updateUserPATCH(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                                    @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
                                    @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
                                    @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
                                    String resourceString) {
        Encoder encoder = null;
        try {
            // obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (StringUtils.isEmpty(inputFormat)) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }
            // identify input format
            inputFormat = identifyInputFormat(inputFormat);
            // set the format in which the response should be encoded, if not specified in the
            // request,
            // defaults to application/json.
            outputFormat = identifyOutputFormat(outputFormat);
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder(SCIMConstants.identifyFormat(outputFormat));

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(
                    authorization);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();

            SCIMResponse response = userResourceEndpoint.updateWithPATCH(id, resourceString,
                    inputFormat, outputFormat, userManager);

            return new JAXRSResponseBuilder().buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @GET
    @Path("/me")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthorizedUser(
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {
        Encoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();
            String filter = "userName Eq " + MultitenantUtils.getTenantAwareUsername(authorization);

            // defaults to application/json.
            format = identifyOutputFormat(format);
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder(SCIMConstants.identifyFormat(format));

            // obtain the user store manager
            String SCIM_LIST_USER_PERMISSION = "/permission/admin/login";
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(
                    authorization, SCIM_LIST_USER_PERMISSION);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            SCIMResponse scimResponse = null;
            scimResponse = userResourceEndpoint.listByFilterAndAttribute(filter, null, userManager, format);

            // get scim id to retrieve user information
            String scimId;
            JSONObject responseObject = new JSONObject(scimResponse.getResponseMessage());
            JSONArray resourceArray = responseObject.getJSONArray(SCIMConstants.ListedResourcesConstants.RESOURCES);
            scimId = getAuthorizedDomainUserSCIMId(resourceArray);

            SCIMResponse userDataResponse = userResourceEndpoint.get(scimId, format, userManager);
            return new JAXRSResponseBuilder().buildResponse(userDataResponse);

        } catch (JSONException e) {
            logger.error("Error while processing the request", e);
            CharonException exception = new CharonException("Error while processing the request", e);
            exception.setCode(-1);
            return handleCharonException(exception, encoder);
        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    private String getAuthorizedDomainUserSCIMId(JSONArray resourceArray) throws JSONException {
        if (resourceArray.length() == 1) {
            return resourceArray.getJSONObject(0).getString(SCIMConstants.CommonSchemaConstants.ID);
        }
        String username = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        for (int i = 0; i < resourceArray.length(); i++) {
            if (username.equals(resourceArray.getJSONObject(i).getString(SCIMConstants.UserSchemaConstants.USER_NAME))) {
                return resourceArray.getJSONObject(i).getString(SCIMConstants.CommonSchemaConstants.ID);
            }
        }
        return resourceArray.getJSONObject(0).getString(SCIMConstants.CommonSchemaConstants.ID);
    }

}
