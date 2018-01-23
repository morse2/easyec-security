package com.googlecode.easyec.security.test.base;

import com.googlecode.easyec.security.test.base.config.WebMvcConfig;
import com.googlecode.easyec.security.test.base.config.WebSecurityConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;
import org.springframework.test.context.transaction.TransactionalTestExecutionListener;
import org.springframework.test.context.web.ServletTestExecutionListener;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.testSecurityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { WebMvcConfig.class, WebSecurityConfig.class })
@WebAppConfiguration
@TestExecutionListeners(
    listeners = {
        ServletTestExecutionListener.class,
        DependencyInjectionTestExecutionListener.class,
        DirtiesContextTestExecutionListener.class,
        TransactionalTestExecutionListener.class,
        WithSecurityContextTestExecutionListener.class
    }
)
public class MockMvcMessageTest {

    @Autowired
    private WebApplicationContext context;
    @Autowired
    private Filter springSecurityFilterChain;

    private MockMvc mvc;

    @Before
    public void setup() {
        this.mvc = MockMvcBuilders
            .webAppContextSetup(context)
            .defaultRequest(get("/").with(testSecurityContext()))
            .addFilters(springSecurityFilterChain)
            .build();
    }

    @Test
    @WithMockUser(roles = { "ADMIN", "USER" })
    public void createMessage() throws Exception {
        MockHttpServletRequestBuilder createMessage = post("/message")
            .param("summary", "Spring Rocks")
            .param("text", "In case you didn't know, Spring Rocks!")
            .with(csrf());

        mvc.perform(createMessage)
            .andExpect(status().isOk());
        //.andExpect(status().is3xxRedirection())
        //.andExpect(redirectedUrl("/messages/123"));
    }
}
