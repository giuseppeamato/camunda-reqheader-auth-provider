package it.pz8.camunda.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Giuseppe Amato
 *
 */
public class RequestHeaderAuthProvider extends AbstractHeaderAuthProvider {

    protected static final String USERNAME_DEFAULT_HEADER = "X-SSO-USERNAME";
    protected static final String GROUPS_DEFAULT_HEADER = "X-SSO-GROUPS";
    protected static final String TENANTS_DEFAULT_HEADER = "X-SSO-TENANTS";
    protected static final String USERNAME_HEADER_PARAM_KEY = "authprovider-usernameHeader";
    protected static final String GROUPS_HEADER_PARAM_KEY = "authprovider-groupsHeader";
    protected static final String TENANTS_HEADER_PARAM_KEY = "authprovider-tenantsHeader";
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RequestHeaderAuthProvider.class);

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {
        String usernameHeader = request.getServletContext().getInitParameter(USERNAME_HEADER_PARAM_KEY);
        String groupsHeader = request.getServletContext().getInitParameter(GROUPS_HEADER_PARAM_KEY);
        String tenantsHeader = request.getServletContext().getInitParameter(TENANTS_HEADER_PARAM_KEY);
        
        String username = request.getHeader((usernameHeader!=null && !usernameHeader.isEmpty())?usernameHeader:USERNAME_DEFAULT_HEADER);
        List<String> groups = getClaim(groupsHeader, GROUPS_DEFAULT_HEADER, isRolesAsList(request), getRolesDelimiter(request), request);
        List<String> tenants = getClaim(tenantsHeader, TENANTS_DEFAULT_HEADER, isTenantsAsList(request), getTenantsDelimiter(request), request);

        AuthenticationResult authenticationResult = (!username.isEmpty())?
                AuthenticationResult.successful(username):
                AuthenticationResult.unsuccessful();
        if (groups!=null && !groups.isEmpty()) {
            authenticationResult.setGroups(groups);
        }
        if (tenants!=null && !tenants.isEmpty()) {
            authenticationResult.setTenants(tenants);
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("Username: %s - Groups: %s - Tenants: %s", 
                    authenticationResult.getAuthenticatedUser(), authenticationResult.getGroups(), authenticationResult.getTenants()));
        }
        return authenticationResult;
    }

    @Override
    public void augmentResponseByAuthenticationChallenge(HttpServletResponse response, ProcessEngine engine) {
        // Do nothing.
    }

    private List<String> getClaim(String headerName, String defaultHeaderName, boolean isList, String delimiter, HttpServletRequest request) {
        String currentHeaderName = (headerName!=null && !headerName.isEmpty())?headerName:defaultHeaderName;
        List<String> results = null;
        if (isList) {
            results = Collections.list(request.getHeaders(currentHeaderName));
        } else {
            if (request.getHeader(currentHeaderName)!=null) {
                results = Arrays.asList(request.getHeader(currentHeaderName).split(delimiter));
            }
        }
        return results;
    }
}
