/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.scim.common.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityTenantMgtListener;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.scim.common.internal.SCIMCommonComponentHolder;
import org.wso2.carbon.identity.scim.common.utils.SCIMCommonUtils;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.util.ClaimsMgtUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.charon.core.schema.SCIMConstants;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


/**
 * This is an implementation of TenantMgtListener. This is used
 * to generate SCIM attributes for tenant admin users.
 */
public class SCIMTenantMgtListener extends AbstractIdentityTenantMgtListener {

    private static Log log = LogFactory.getLog(SCIMTenantMgtListener.class);

    @Override
    public void onTenantInitialActivation(int tenantId) throws StratosException {

        setTenantAdminSCIMAttributes(tenantId);
    }

    /**
     * Set tenant admins SCIM attributes on tenant initial activation.
     *
     * @param tenantId a tenantId
     */
    private void setTenantAdminSCIMAttributes(int tenantId) {

        try {
            UserStoreManager userStoreManager = (UserStoreManager) SCIMCommonComponentHolder.getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();

            if (userStoreManager.isSCIMEnabled()) {
                Map<String, String> claimsMap = new HashMap<String, String>();
                String adminUsername = ClaimsMgtUtil.getAdminUserNameFromTenantId(IdentityTenantUtil.getRealmService(),
                        tenantId);
                String id = UUID.randomUUID().toString();
                Date date = new Date();
                String createdDate = SCIMCommonUtils.formatDateTime(date);

                claimsMap.put(SCIMConstants.META_CREATED_URI, createdDate);
                claimsMap.put(SCIMConstants.USER_NAME_URI, adminUsername);
                claimsMap.put(SCIMConstants.META_LAST_MODIFIED_URI, createdDate);
                claimsMap.put(SCIMConstants.ID_URI, id);

                userStoreManager.setUserClaimValues(adminUsername, claimsMap,
                        UserCoreConstants.DEFAULT_PROFILE);

                SCIMCommonUtils.addAdminGroup(userStoreManager);
            }
        } catch (Exception e) {
            String msg = "Error while adding SCIM metadata to the tenant admin in tenant ID : " + tenantId;
            log.error(msg, e);
        }
    }
}
