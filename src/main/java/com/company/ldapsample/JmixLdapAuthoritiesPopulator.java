package com.company.ldapsample;

import com.company.ldapsample.security.FullAccessRole;
import io.jmix.security.authentication.RoleGrantedAuthority;
import io.jmix.security.model.ResourceRole;
import io.jmix.security.role.ResourceRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import java.util.Collection;
import java.util.Collections;

/**
 * Maps LDAP attributes to a collection of granted authorities.
 */
public class JmixLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {

    @Autowired
    protected ResourceRoleRepository resourceRoleRepository;

    @Override
    public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
        ResourceRole role = resourceRoleRepository.findRoleByCode(FullAccessRole.CODE);
        if (role != null) {
            GrantedAuthority authority = RoleGrantedAuthority.ofResourceRole(role);
            return Collections.singletonList(authority);
        }
        return Collections.emptyList();
    }
}
