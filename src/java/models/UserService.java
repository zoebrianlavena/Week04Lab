package models;

/**
 *
 * @author 743953
 */
public class UserService {
    User user;
    String adam = "adam";
    String betty = "betty";

    public User login(String username, String password){
        if((username.equalsIgnoreCase(adam) || username.equalsIgnoreCase(betty)) &&
           password.equals("password")){
            this.user = new User(username,password);
            return user;
        }
        return null;
    }
    
}
