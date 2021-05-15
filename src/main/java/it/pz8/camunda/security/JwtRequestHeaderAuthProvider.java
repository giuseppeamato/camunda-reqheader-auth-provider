package it.pz8.camunda.security;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * @author Giuseppe Amato
 *
 */
public class JwtRequestHeaderAuthProvider extends AbstractHeaderAuthProvider {

    protected static final String JWT_DEFAULT_HEADER = "X-JWT-Assertion";    
    protected static final String JWT_HEADER_PARAM_KEY = "authprovider-jwtHeader";
    protected static final String USERNAME_IN_ATTRS_PARAM_KEY = "authprovider-usernameInAttributes";
    protected static final String USERNAME_ATTR_PARAM_KEY = "authprovider-usernameClaim";
    protected static final String ROLES_ATTR_PARAM_KEY = "authprovider-rolesClaim";
    protected static final String TENANTS_ATTR_PARAM_KEY = "authprovider-tenantsClaim";    
    protected static final String OIDC_SUBJECT_ATTRIBUTE = "sub";
    protected static final String OIDC_USERNAME_DEFAULT_ATTRIBUTE = "username";
    protected static final String OIDC_ROLES_DEFAULT_ATTRIBUTE = "groups";
    protected static final String OIDC_TENANTS_DEFAULT_ATTRIBUTE = "tenants";

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRequestHeaderAuthProvider.class);

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {
        String jwt = request.getHeader(getHeaderName(request));
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("X-JWT-Assertion: %s", jwt));
        }
        DecodedJWT decodedJwt = JWT.decode(jwt);
        Map<String, Claim> claims = decodedJwt.getClaims();

        Claim usernameClaim = claims.get(getUsernameAttribute(request));
        String username = (usernameClaim!=null)?usernameClaim.asString():null; 

        Claim roleClaim = claims.get(getRolesAttribute(request));
        List<String> groups = null;
        if (roleClaim!=null) {
            groups = isRolesAsList(request)?roleClaim.asList(String.class):Arrays.asList(roleClaim.asString().split(getRolesDelimiter(request)));
        }

        Claim tenantClaim = claims.get(getTenantsAttribute(request));
        List<String> tenants = null;
        if (tenantClaim!=null) {
            tenants = isTenantsAsList(request)?tenantClaim.asList(String.class):Arrays.asList(tenantClaim.asString().split(getTenantsDelimiter(request)));
        }

        AuthenticationResult authenticationResult = (username!=null && !"".equalsIgnoreCase(username))?
                AuthenticationResult.successful(username):
                AuthenticationResult.unsuccessful();  
        authenticationResult.setGroups(groups);
        authenticationResult.setTenants(tenants);

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

    private String getHeaderName(HttpServletRequest request) {
        String jwtHeader = request.getServletContext().getInitParameter(JWT_HEADER_PARAM_KEY);
        return request.getHeader((jwtHeader!=null && !"".equalsIgnoreCase(jwtHeader)?jwtHeader:JWT_DEFAULT_HEADER));        
    }
    
    private String getUsernameAttribute(HttpServletRequest request) {
        String usernameInAttrsParam = request.getServletContext().getInitParameter(USERNAME_IN_ATTRS_PARAM_KEY);
        boolean usernameInAttrs = Boolean.getBoolean(usernameInAttrsParam);
        String usernameAttr = request.getServletContext().getInitParameter(USERNAME_ATTR_PARAM_KEY);
        if (usernameInAttrs && !"".equalsIgnoreCase(usernameAttr)) {
            usernameAttr = OIDC_USERNAME_DEFAULT_ATTRIBUTE;
        }
        return (usernameInAttrs)?usernameAttr:OIDC_SUBJECT_ATTRIBUTE;        
    }

    private String getRolesAttribute(HttpServletRequest request) {
        String roleAttr = request.getServletContext().getInitParameter(ROLES_ATTR_PARAM_KEY);
        if (roleAttr!=null && !"".equalsIgnoreCase(roleAttr)) {
            roleAttr = OIDC_ROLES_DEFAULT_ATTRIBUTE;
        }
        return roleAttr;
    }

    private String getTenantsAttribute(HttpServletRequest request) {
        String tenantsAttr = request.getServletContext().getInitParameter(TENANTS_ATTR_PARAM_KEY);
        if (tenantsAttr!=null && !"".equalsIgnoreCase(tenantsAttr)) {
            tenantsAttr = OIDC_TENANTS_DEFAULT_ATTRIBUTE;
        }
        return tenantsAttr;
    }

}
