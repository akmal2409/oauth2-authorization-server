package com.akmal.oauth2authorizationserver.oauth2.web.model;

import com.akmal.oauth2authorizationserver.model.user.User;
import java.time.Instant;
import java.util.List;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignUpModel {
  @NotBlank(message = "Password must not be blank")
  @Length(min = 8, message = "Username must be at least 5 characters long")
  private String password;

  @NotBlank(message = "First name must not be blank")
  private String firstName;

  private String middleName;

  @NotBlank(message = "Last name must not be blank")
  private String lastName;

  @NotBlank(message = "Email must not be blank")
  @Email(message = "Email is invalid")
  private String email;

  public User toUser() {
    return new User(
        null,
        this.firstName + " " + this.lastName,
        this.password,
        this.firstName,
        this.middleName,
        this.lastName,
        null,
        null,
        null,
        Instant.now(),
        this.email,
        null,
        false,
        List.of(),
        List.of(),
        List.of()
    );
  }
}
