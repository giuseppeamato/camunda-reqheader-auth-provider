Camunda Request Header Auth Provider

# Overview

This custom auth provider allows to authenticate users in Camunda relying on information retrieved in the request header, as in the typical scenario of the system protected behind an API Gateway.

It comes in two flavors:
+ `RequestHeaderAuthProvider`: retrieves user info from separate request headers
+ `JwtRequestHeaderAuthProvider`: retrieves user info from a base64-encoded JWT in a single request header

The former is useful when an API gateway, i.e. a custom ballerina microgateway, pass username, groups membership and tenants of the logged user in separate request headers.

The latter, instead, is useful when an API gateway pass a more complex JWT, containing the claims of the logged user, to the camunda backend system in a single request header. Please note: this component doesn't verify signed JWTs.

>in both cases , it is extremely important that your backend system is configured properly to prevent an attacker from forging the headers. 

## Usage

Put the jar in `engine-rest/WEB-INF/lib` directory, configure `web.xml` and start Camunda.

# Configuration

The behavior of this component is controlled via web.xml file of engine-rest web application.  

First of all you have to set the full classname of the provider in the `authentication-provider` init parameter of `ProcessEngineAuthenticationFilter`, then you can optionally set other parameters as context-param.

**RequestHeaderAuthProvider** specific parameters:

+ `authprovider-usernameHeader`: the name of the request header containing the username, defaults to `X-SSO-USERNAME`.
+ `authprovider-groupsHeader`: the name of the request header containing the groups membership, defaults to `X-SSO-GROUPS`.
+ `authprovider-tenantsHeader`: the name of the request header containing the tenants, defaults to `X-SSO-TENANTS`.

**JwtRequestHeaderAuthProvider** specific parameters:

+ `authprovider-jwtHeader`: the name of the request header containing the JWT, defaults to `X-JWT-Assertion`.
+ `authprovider-usernameInAttributes`: if `false` the username is retrieved from `sub` claim, else from a specified attribute. Defaults to `false`.
+ `authprovider-usernameClaim`: the name of the claim attribute containing the username, defaults to `username`.
+ `authprovider-rolesClaim`: the name of the claim attribute containing the groups, defaults to `groups`.
+ `authprovider-tenantsClaim`: the name of the claim attribute containing the tenants, defaults to `tenants`.

Common parameters:

+ `authprovider-rolesAsList`: if `false` the groups are evaluated as a delimited string to split, else as a list (multiple values header or array value claim). Defaults to `false`.
+ `authprovider-rolesDelimiter`: the delimiter to use when `authprovider-rolesAsList` is set to `false`, defaults to `,`.
+ `authprovider-tenantsAsList`: if `false` the groups are evaluated as a delimited string to split, else as a list (multiple values header or array value claim). Defaults to `false`.
+ `authprovider-tenantsDelimiter`: the delimiter to use when `authprovider-tenantsAsList` is set to `false`, defaults to `,`.

Example:

```xml
  <context-param>
    <param-name>authprovider-usernameClaim</param-name>
    <param-value>preferred_username</param-value>
  </context-param>
  <context-param>
    <param-name>authprovider-rolesAsList</param-name>
    <param-value>true</param-value>
  </context-param>
  
  <filter>
    <filter-name>camunda-auth</filter-name>
    <filter-class>
      org.camunda.bpm.engine.rest.security.auth.ProcessEngineAuthenticationFilter
    </filter-class>
	<async-supported>true</async-supported>
    <init-param>
      <param-name>authentication-provider</param-name>
      <param-value>it.pz8.camunda.security.JwtRequestHeaderAuthProvider</param-value>
    </init-param>
    <init-param>
	    <param-name>rest-url-pattern-prefix</param-name>
	    <param-value></param-value>
	  </init-param> 
  </filter>
```

## Environment Restrictions
Built and tested against Camunda BPM version 7.14.0.
