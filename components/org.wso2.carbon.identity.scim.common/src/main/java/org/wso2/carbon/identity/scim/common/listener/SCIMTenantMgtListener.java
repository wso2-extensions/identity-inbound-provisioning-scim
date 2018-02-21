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
import org.wso2.carbon.identity.scim.common.utils.AdminAttributeUtil;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.user.core.UserStoreException;


/**
 * This is an implementation of TenantMgtListener. This is used
 * to generate SCIM attributes for tenant admin users.
 */
public class SCIMTenantMgtListener extends AbstractIdentityTenantMgtListener {

    private static Log log = LogFactory.getLog(SCIMTenantMgtListener.class);

    @Override
    public void onTenantInitialActivation(int tenantId) throws StratosException {
        //Update admin user attributes.
        try {
            AdminAttributeUtil.updateAdminUser(tenantId, false);
        } catch (UserStoreException e) {
            String msg = "Error occurred while updating admin user attributes";
            throw new StratosException(msg, e);
        }
        //Update admin group attributes.
        AdminAttributeUtil.updateAdminGroup(tenantId);
    }
}
