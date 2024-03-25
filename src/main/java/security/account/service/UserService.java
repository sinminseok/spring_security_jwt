package security.account.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.account.domain.User;
import security.account.dto.SignupDto;
import security.account.repository.UserRepository;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final String ALREADY_EXIST_EMAIL_ERROR = "이미 존재하는 이메일 입니다.";
    private static final String ALREADY_EXIST_NICKNAME_ERROR = "이미 존재하는 닉네임 입니다.";

    public void signUp(SignupDto signupDto) throws Exception {
        if(userRepository.findByEmail(signupDto.getEmail()).isPresent()){
            throw new Exception(ALREADY_EXIST_EMAIL_ERROR);
        }

        if(userRepository.findByNickName(signupDto.getNickName()).isPresent()){
            throw new Exception(ALREADY_EXIST_NICKNAME_ERROR);
        }

        User user = User.builder()
                .email(signupDto.getEmail())
                .password(signupDto.getPassword())
                .nickName(signupDto.getNickName())
                .role(signupDto.getRole())
                .build();

        user.passwordEncode(passwordEncoder);
        userRepository.save(user);
    }
}
