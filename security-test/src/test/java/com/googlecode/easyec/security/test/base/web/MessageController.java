package com.googlecode.easyec.security.test.base.web;

import com.googlecode.easyec.security.utils.SecurityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

@Controller
public class MessageController {


    @RequestMapping("/message")
    public void showMessage(HttpServletRequest request) {
        boolean b = SecurityUtils.isUriAllowed(
            request, "/WEB-INF/pages/jsp/admin/form.jsp"
        );

        System.out.println(b);
    }

    @RequestMapping("/admin")
    public void admin() {
        System.out.println("Hello admin.");
    }
}
