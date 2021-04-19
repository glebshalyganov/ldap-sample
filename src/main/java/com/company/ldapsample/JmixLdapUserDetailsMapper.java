package com.company.ldapsample;

import io.jmix.core.DataManager;
import io.jmix.core.entity.EntityValues;
import io.jmix.core.security.UserRepository;
import io.jmix.security.authentication.AcceptsGrantedAuthorities;
import io.jmix.security.authentication.RoleGrantedAuthority;
import io.jmix.security.model.ResourceRole;
import io.jmix.security.role.ResourceRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

import java.util.Collection;

/**
 * Maps LDAP user to Jmix user.
 */
public class JmixLdapUserDetailsMapper<T extends UserDetails> extends LdapUserDetailsMapper {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private DataManager dataManager;

    @Autowired
    private ResourceRoleRepository resourceRoleRepository;

    private Class<? extends T> userClass;

    public void setUserClass(Class<? extends T> userClass) {
        this.userClass = userClass;
    }

    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
                                          Collection<? extends GrantedAuthority> authorities) {
        UserDetails ldapUserDetails = super.mapUserFromContext(ctx, username, authorities);
        return mapLdapUserDetailsToJmixUserDetails(ldapUserDetails, authorities);
    }

    protected UserDetails mapLdapUserDetailsToJmixUserDetails(UserDetails ldapUserDetails,
                                                              Collection<? extends GrantedAuthority> authorities) {
        UserDetails jmixUserDetails;
        try {
            jmixUserDetails = userRepository.loadUserByUsername(ldapUserDetails.getUsername());
        } catch (UsernameNotFoundException e) {
            jmixUserDetails = createJmixUser(ldapUserDetails);
        }

        if (jmixUserDetails instanceof AcceptsGrantedAuthorities) {
            ((AcceptsGrantedAuthorities) jmixUserDetails).setAuthorities(authorities);
        }

        return jmixUserDetails;
    }

    protected T createJmixUser(UserDetails ldapUserDetails) {
        T jmixUser = dataManager.create(userClass);
        EntityValues.setValue(jmixUser, "username", ldapUserDetails.getUsername());
        jmixUser = dataManager.save(jmixUser);
        return jmixUser;
    }
}
