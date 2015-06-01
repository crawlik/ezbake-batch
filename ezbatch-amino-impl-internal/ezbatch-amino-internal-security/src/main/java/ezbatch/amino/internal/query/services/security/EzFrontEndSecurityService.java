/*   Copyright (C) 2013-2015 Computer Sciences Corporation
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
 * limitations under the License. */

package ezbatch.amino.internal.query.services.security;

import com._42six.amino.impl.query.services.security.SecurityService;
import com.google.common.collect.Sets;
import ezbake.base.thrift.EzSecurityPrincipal;
import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.security.client.EzSecurityTokenWrapper;
import ezbake.security.client.EzbakeSecurityClient;
import org.apache.thrift.TException;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class EzFrontEndSecurityService implements SecurityService {
    private EzbakeSecurityClient securityClient;

    public EzFrontEndSecurityService() throws EzConfigurationLoaderException {
        Properties props = new EzConfiguration().getProperties();
        securityClient = new EzbakeSecurityClient(props);
    }

    private EzSecurityPrincipal getUser() {
        try {
            return securityClient.clientDnFromRequest();
        } catch (EzSecurityTokenException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Set<String> getVisibility() {
        try {
            EzSecurityTokenWrapper tokenWrapper = securityClient.fetchTokenForProxiedUser();
            Set<String> completeList = new HashSet<>();
            completeList.addAll(tokenWrapper.getAuthorizations().getFormalAuthorizations());
            completeList.addAll(tokenWrapper.getAuthorizations().getExternalCommunityAuthorizations());
            return completeList;
        } catch (TException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getUserId() {
        return getUser().getPrincipal();
    }

    @Override
    public String getUserName() {
        return getUserId();
    }

    @Override
    public boolean isServerCert() {
        // TODO: notify Steve
        return false;
    }
}
