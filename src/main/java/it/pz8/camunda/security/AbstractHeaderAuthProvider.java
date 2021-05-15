package it.pz8.camunda.security;

import javax.servlet.http.HttpServletRequest;

import org.camunda.bpm.engine.rest.security.auth.AuthenticationProvider;

/**
 * @author Giuseppe Amato
 *
 */
public abstract class AbstractHeaderAuthProvider implements AuthenticationProvider {

    protected static final String DEFAULT_DELIMITER = ",";
    protected static final String ROLES_AS_LIST_PARAM_KEY = "authprovider-rolesAsList";
    protected static final String ROLES_DELIMITER = "authprovider-rolesDelimiter";
    protected static final String TENANTS_AS_LIST_PARAM_KEY = "authprovider-tenantsAsList";
    protected static final String TENANTS_DELIMITER = "authprovider-tenantsDelimiter";
    
    protected String getRolesDelimiter(HttpServletRequest request) {
        String roleDelimiter = request.getServletContext().getInitParameter(ROLES_DELIMITER);
        return (roleDelimiter!=null && !"".equalsIgnoreCase(roleDelimiter))?roleDelimiter:DEFAULT_DELIMITER;    
    }
    
    protected boolean isRolesAsList(HttpServletRequest request) {
        String rolesAsListParam = request.getServletContext().getInitParameter(ROLES_AS_LIST_PARAM_KEY);
        return Boolean.parseBoolean(rolesAsListParam);        
    }

    protected String getTenantsDelimiter(HttpServletRequest request) {
        String tenantsDelimiter = request.getServletContext().getInitParameter(TENANTS_DELIMITER);
        return (tenantsDelimiter!=null && !"".equalsIgnoreCase(tenantsDelimiter))?tenantsDelimiter:DEFAULT_DELIMITER;
    }
    
    protected boolean isTenantsAsList(HttpServletRequest request) {
        String tenantsAsListParam = request.getServletContext().getInitParameter(TENANTS_AS_LIST_PARAM_KEY);
        return Boolean.parseBoolean(tenantsAsListParam);
    }

}
