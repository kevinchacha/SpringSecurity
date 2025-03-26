package com.cursos.api.springsecuritycourse.dto;
import jakarta.validation.constraints.Size;
import java.io.Serializable;

public class SaveUser implements Serializable {
    @Size(min = 4)
    private String name;
    @Size(min = 4)
    private String username;
    @Size(min = 8)
    private String password;
    @Size(min = 8)
    private String repeatedPassword;

    public @Size(min = 4) String getName() {
        return name;
    }

    public void setName(@Size(min = 4) String name) {
        this.name = name;
    }

    public @Size(min = 4) String getUsername() {
        return username;
    }

    public void setUsername(@Size(min = 4) String username) {
        this.username = username;
    }

    public @Size(min = 8) String getPassword() {
        return password;
    }

    public void setPassword(@Size(min = 8) String password) {
        this.password = password;
    }

    public @Size(min = 8) String getRepeatedPassword() {
        return repeatedPassword;
    }

    public void setRepeatedPassword(@Size(min = 8) String repeatedPassword) {
        this.repeatedPassword = repeatedPassword;
    }
}
