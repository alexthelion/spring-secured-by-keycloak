package com.rsinnotech.keycloakdemo.web;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

@RestController
public class ApiController {

    @GetMapping(value = "/api/test/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    @PreAuthorize("hasRole('admin')")
    public Map<String, String> testApi(@PathVariable Long id, Principal principal) {
        return Collections.singletonMap("response", "API access granted");
    }

    @GetMapping(value = "/api/forbiddenTest/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    @PreAuthorize("hasRole('dummy_role')")
    public Map<String, String> forbiddenTest(@PathVariable Long id, Principal principal) {
        return Collections.singletonMap("response", "API access granted");
    }

}
