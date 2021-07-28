package com.jason.shopping.admin.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import com.jason.shopping.security.config.SecurityConfig;
@Configuration
@EnableWebSecurity
public class ShoppingSecurityConfig extends SecurityConfig{

}
