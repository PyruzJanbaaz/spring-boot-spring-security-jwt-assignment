package com.egs.pyruz.models.domain;


import javax.validation.constraints.NotBlank;

public class UserChangePasswordRequest {
    @NotBlank
    private String oldPassword;
    @NotBlank
    private String password;
    @NotBlank
    private String confirmPassword;

    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}
