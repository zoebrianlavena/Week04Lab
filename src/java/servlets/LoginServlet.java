package servlets;

import java.io.*;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import models.*;

public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession();
        String logout = request.getParameter("logout");
        if(logout != null){
            session.removeAttribute("user");
            request.setAttribute("message","You have successfully logged out.");  
        }
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie: cookies){
            if(cookie.getName().equals("betty") || cookie.getName().equals("adam")){
                request.setAttribute("usernamevalue", cookie.getName());
                request.setAttribute("checked", true);
            }
        }
        getServletContext().getRequestDispatcher("/WEB-INF/login.jsp").forward(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        UserService userservice = new UserService();
        User user = userservice.login(username,password);
        
        HttpSession session = request.getSession();
        if(request.getParameter("rememberme").equals("true")){
            Cookie cookie = new Cookie(username,session.getId());
            response.addCookie(cookie);
        }
        if(user != null){
            response.sendRedirect("home");
            session.setAttribute("user", user.getUsername());
            return;
        }
        
        request.setAttribute("message", "Invalid username/password");
        getServletContext().getRequestDispatcher("/WEB-INF/login.jsp").forward(request, response);
    }

}
