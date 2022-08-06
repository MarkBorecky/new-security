package pl.maro.newsecurity.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class HelloControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void sayHelloWorld_shouldReturnString() throws Exception {
        this.mockMvc.perform(get("/api/hello/world"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(is("Hello, World!")));
    }

    @Test
    public void sayHelloWorld_shouldReturn401() throws Exception {
        this.mockMvc.perform(get("/api/hello/you"))
                .andDo(print())
                .andExpect(status().is(401));
    }

    @Test
    @WithMockUser(username="user",roles={"USER"})
    public void sayHelloYou_shouldReturnCommunicate() throws Exception {
        this.mockMvc.perform(get("/api/hello/you"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(is("Hello, You!")));
    }

    @Test
    @WithMockUser(username="user",roles={"USER"})
    public void sayHelloAdmin_shouldReturn401() throws Exception {
        this.mockMvc.perform(get("/api/hello/admin"))
                .andDo(print())
                .andExpect(status().is(403));
    }

    @Test
    @WithMockUser(username="admin",roles={"ADMIN"})
    public void sayHelloAdmin_shouldReturnCommunicate() throws Exception {
        this.mockMvc.perform(get("/api/hello/you"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(is("Hello, You!")));
    }
}