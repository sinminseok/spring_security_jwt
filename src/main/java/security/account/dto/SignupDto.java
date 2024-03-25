package security.account.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import security.account.domain.Role;

@Getter
@AllArgsConstructor
public class SignupDto {
    private final String email;

    private final String password;

    private final String nickName;

    private final Integer phoneNumber;

    private final String profileUrl;

    private final Integer age;

    private final Role role;

}