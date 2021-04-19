package com.company.ldapsample;

import com.company.ldapsample.entity.User;
import io.jmix.core.JmixOrder;
import io.jmix.security.StandardSecurityConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

@Order(JmixOrder.HIGHEST_PRECEDENCE + 150)
@EnableWebSecurity
public class LdapSecurityConfiguration extends StandardSecurityConfiguration {

    @Autowired
    protected Environment environment;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(ldapAuthenticationProvider());
        super.configure(auth);
    }

    @Bean
    LdapAuthenticationProvider ldapAuthenticationProvider() {
        BindAuthenticator authenticator = new BindAuthenticator(ldapContextSource());
        authenticator.setUserDnPatterns(new String[]{environment.getProperty("ldap.user.dn.pattern")});
        LdapAuthenticationProvider ldapAuthenticationProvider =
                new LdapAuthenticationProvider(authenticator, ldapAuthoritiesPopulator());
        ldapAuthenticationProvider.setUserDetailsContextMapper(ldapUserDetailsMapper());
        return ldapAuthenticationProvider;
    }

    @Bean
    LdapContextSource ldapContextSource() {
        DefaultSpringSecurityContextSource contextSource =
                new DefaultSpringSecurityContextSource(environment.getProperty("ldap.urls")
                        + environment.getProperty("ldap.base.dn"));
        contextSource.setUserDn(environment.getProperty("ldap.username"));
        contextSource.setPassword(environment.getProperty("ldap.password"));
        return contextSource;
    }

    @Bean
    JmixLdapUserDetailsMapper<User> ldapUserDetailsMapper() {
        JmixLdapUserDetailsMapper<User> jmixLdapUserDetailsMapper = new JmixLdapUserDetailsMapper<>();
        jmixLdapUserDetailsMapper.setUserClass(User.class);
        return jmixLdapUserDetailsMapper;
    }

    @Bean
    LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        return new JmixLdapAuthoritiesPopulator();
    }
}
