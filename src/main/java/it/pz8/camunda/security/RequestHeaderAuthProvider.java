package it.pz8.camunda.security;

import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationProvider;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RequestHeaderAuthProvider implements AuthenticationProvider {

    private static final String USERNAME_DEFAULT_HEADER = "X-SSO-USERNAME";
    private static final String GROUPS_DEFAULT_HEADER = "X-SSO-GROUPS";
    private static final String TENANTS_DEFAULT_HEADER = "X-SSO-TENANTS";
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RequestHeaderAuthProvider.class);

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {
        String usernameHeader = request.getServletContext().getInitParameter("authprovider-usernameHeader");
        String groupsHeader = request.getServletContext().getInitParameter("authprovider-groupsHeader");
        String tenantsHeader = request.getServletContext().getInitParameter("authprovider-tenantsHeader");
        String username = request.getHeader(usernameHeader!=null && !"".equalsIgnoreCase(usernameHeader)?usernameHeader:USERNAME_DEFAULT_HEADER);
        Enumeration<String> groups = request.getHeaders(groupsHeader!=null && !"".equalsIgnoreCase(groupsHeader)?groupsHeader:GROUPS_DEFAULT_HEADER);
        Enumeration<String> tenants = request.getHeaders(tenantsHeader!=null && !"".equalsIgnoreCase(tenantsHeader)?tenantsHeader:TENANTS_DEFAULT_HEADER);
        AuthenticationResult authenticationResult = (username!=null && !"".equalsIgnoreCase(username))?
                AuthenticationResult.successful(username):
                AuthenticationResult.unsuccessful();  
        if (groups!=null && groups.hasMoreElements()) {
            authenticationResult.setGroups(Collections.list(groups));
        }
        if (tenants!=null && tenants.hasMoreElements()) {
            authenticationResult.setTenants(Collections.list(tenants));
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("Username: %s - Groups: %s - Tenants: %s", authenticationResult.getAuthenticatedUser(), authenticationResult.getGroups(), authenticationResult.getTenants()));
        }
        return authenticationResult;
    }

    @Override
    public void augmentResponseByAuthenticationChallenge(HttpServletResponse response, ProcessEngine engine) {
        // Do nothing.
    }

}
