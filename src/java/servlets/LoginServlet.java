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

        if (session.getAttribute("user") != null) {
            if (logout != null) {
                session.removeAttribute("user");
                request.setAttribute("message", "You have successfully logged out.");

                if (session.getAttribute("checkbox") != null) {
                    Cookie[] cookies = request.getCookies();
                    for (Cookie cookie : cookies) {
                        if (cookie.getName().equals("betty") || cookie.getName().equals("adam")) {
                            session.setAttribute("usernamevalue", cookie.getName());
                            session.setAttribute("checkbox", "checked");
                        }
                    }
                } else {
                    session.removeAttribute("usernamevalue");
                    session.removeAttribute("checkbox");
                }
                getServletContext().getRequestDispatcher("/WEB-INF/login.jsp").forward(request, response);

            } else {
                response.sendRedirect("home");
            }
        } else {
            getServletContext().getRequestDispatcher("/WEB-INF/login.jsp").forward(request, response);
        }

    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        UserService userservice = new UserService();
        User user = userservice.login(username, password);

        if (user != null) {
            HttpSession session = request.getSession();
            //create a session
            //if checkbox is checked, create cookie
            if (request.getParameter("rememberme") != null) {
                Cookie cookie = new Cookie(username, session.getId());
                cookie.setMaxAge(60 * 60 * 24 * 365 * 2);
                response.addCookie(cookie);
                session.setAttribute("checkbox", "checked");
                //if checkbox is not checked, and cookie exists, remove cookie
            } else if (request.getParameter("rememberme") == null) {
                Cookie[] cookies = request.getCookies();
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals("betty") || cookie.getName().equals("adam")) {
                        cookie.setMaxAge(0);
                        response.addCookie(cookie);
                        session.removeAttribute("checkbox");
                    }
                }
            }
            response.sendRedirect("home");
            session.setAttribute("user", user.getUsername());
            return;
        }

        //invalid inputs
        request.setAttribute("usernamevalue", username);
        request.setAttribute("message", "Invalid username/password");
        getServletContext().getRequestDispatcher("/WEB-INF/login.jsp").forward(request, response);
    }

}
