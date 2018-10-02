<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>My Login</title>
    </head>
    <body>
        <h1>Remember Me Login Page</h1>
        <form method="post" action="login">
            Username: <input type="text" name="username" value="${usernamevalue}"> <br>
            Password: <input type="password" name="password"> <br>
            <label><input type="checkbox" name="rememberme" ${checkbox}>Remember me</label> <br>
            <input type="submit" value="Login">        
        </form>
        <div>
            ${message}
        </div>
    </body>
</html>
