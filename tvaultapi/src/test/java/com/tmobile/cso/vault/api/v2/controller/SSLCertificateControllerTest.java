package com.tmobile.cso.vault.api.v2.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.service.SSLCertificateService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.servlet.http.HttpServletRequest;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
public class SSLCertificateControllerTest {
    @Mock
    public SSLCertificateService sslCertificateService;

    private MockMvc mockMvc;

    @Mock
    RequestProcessor reqProcessor;

    @InjectMocks
    public SSLCertificateController SslCertificateController;

    @Mock
    private SSLCertificateRequest sSLCertificateRequest;
    @Mock
    UserDetails userDetails;

    @Mock
    HttpServletRequest httpServletRequest;
    String token;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        this.mockMvc = MockMvcBuilders.standaloneSetup(SslCertificateController).build();
        token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        userDetails.setUsername("normaluser");
        userDetails.setAdmin(true);
        userDetails.setClientToken(token);
        userDetails.setSelfSupportToken(token);
    }


    @Test
    public void test_authenticate_successful() throws Exception {
        CertManagerLoginRequest certManagerLoginRequest = new CertManagerLoginRequest("testusername", "testpassword");
        when(sslCertificateService.authenticate(certManagerLoginRequest)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        assertEquals(HttpStatus.OK, SslCertificateController.authenticate(certManagerLoginRequest).getStatusCode());
    }

    @Test
    public void test_authenticate_Unauthorized() throws Exception {
        CertManagerLoginRequest certManagerLoginRequest = new CertManagerLoginRequest("testusername1", "testpassword1");
        when(sslCertificateService.authenticate(certManagerLoginRequest)).thenReturn(new ResponseEntity<>(HttpStatus.UNAUTHORIZED));
        assertEquals(HttpStatus.UNAUTHORIZED, SslCertificateController.authenticate(certManagerLoginRequest).getStatusCode());
    }

    @Test
    public void test_generateSSLCertificate_success() {
        TargetSystem targetSystem = new TargetSystem();
        targetSystem.setAddress("Target System address");
        targetSystem.setDescription("Target System Description");
        targetSystem.setName("Target Name");

        TargetSystemServiceRequest targetSystemServiceRequest = new TargetSystemServiceRequest();
        targetSystemServiceRequest.setHostname("Target System Service Host name");
        targetSystemServiceRequest.setName("Target System Service Name");
        targetSystemServiceRequest.setPort(443);
        targetSystemServiceRequest.setMultiIpMonitoringEnabled(false);
        targetSystemServiceRequest.setMonitoringEnabled(false);
        targetSystemServiceRequest.setDescription("Target Service Description");

        sSLCertificateRequest.setCertificateName("CertificateName");
        sSLCertificateRequest.setTargetSystem(targetSystem);
        sSLCertificateRequest.setTargetSystemServiceRequest(targetSystemServiceRequest);


       when(sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
       assertEquals(HttpStatus.OK, sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token).getStatusCode());
    }

    @Test
    public void test_generateSSLCertificate_success_Test() {
        TargetSystem targetSystem = new TargetSystem();
        targetSystem.setAddress("Target System address");
        targetSystem.setDescription("Target System Description");
        targetSystem.setName("Target Name");

        TargetSystemServiceRequest targetSystemServiceRequest = new TargetSystemServiceRequest();
        targetSystemServiceRequest.setHostname("Target System Service Host name");
        targetSystemServiceRequest.setName("Target System Service Name");
        targetSystemServiceRequest.setPort(443);
        targetSystemServiceRequest.setMultiIpMonitoringEnabled(false);
        targetSystemServiceRequest.setMonitoringEnabled(false);
        targetSystemServiceRequest.setDescription("Target Service Description");

        sSLCertificateRequest.setCertificateName("CertificateName");
        sSLCertificateRequest.setTargetSystem(targetSystem);
        sSLCertificateRequest.setTargetSystemServiceRequest(targetSystemServiceRequest);


        when(sslCertificateService.generateSSLCertificate(sSLCertificateRequest, userDetails, token)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        when(httpServletRequest.getAttribute("UserDetails")).thenReturn(userDetails);
        assertEquals(HttpStatus.OK, SslCertificateController.generateSSLCertificate(httpServletRequest, token, sSLCertificateRequest).getStatusCode());
    }


    @Test
    public void test_generateSSLCertificate_Error() {
        TargetSystem targetSystem = new TargetSystem();
        targetSystem.setAddress("Target System address");
        targetSystem.setDescription("Target System Description");
        targetSystem.setName("Target Name");

        TargetSystemServiceRequest targetSystemServiceRequest = new TargetSystemServiceRequest();
        targetSystemServiceRequest.setHostname("Target System Service Host name");
        targetSystemServiceRequest.setName("Target System Service Name");
        targetSystemServiceRequest.setPort(443);
        targetSystemServiceRequest.setMultiIpMonitoringEnabled(false);
        targetSystemServiceRequest.setMonitoringEnabled(false);
        targetSystemServiceRequest.setDescription("Target Service Description");

        sSLCertificateRequest.setCertificateName("CertificateName");
        sSLCertificateRequest.setTargetSystem(targetSystem);
        sSLCertificateRequest.setTargetSystemServiceRequest(targetSystemServiceRequest);

        when(sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token)).thenReturn(new ResponseEntity<>
             (HttpStatus.INTERNAL_SERVER_ERROR));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR,
                sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token).getStatusCode());

    }
    
    @Test
    public void test_addUsertoCertificate() throws Exception {
        String responseJson = "{\"messages\":[\"User is successfully associated \"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        UserDetails userDetails = getMockUser(false);
        CertificateUser certUser = new CertificateUser("testuser1","read", "CertificateName");

        String inputJson =new ObjectMapper().writeValueAsString(certUser);
        when(sslCertificateService.addUserToCertificate(eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(CertificateUser.class), eq(userDetails))).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.post("/v2/sslcert/user").requestAttr("UserDetails", userDetails)
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseJson)));
    }
    
    UserDetails getMockUser(boolean isAdmin) {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = new UserDetails();
        userDetails.setUsername("normaluser");
        userDetails.setAdmin(isAdmin);
        userDetails.setClientToken(token);
        userDetails.setSelfSupportToken(token);
        return userDetails;
    }

}
