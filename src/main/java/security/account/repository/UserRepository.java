package security.account.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import security.account.domain.SocialType;
import security.account.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByNickName(String nickname);

    Optional<User> findByRefreshToken(String refreshToken);

    //Optional<User> findBySocialTypeAndSocialId(SocialType socialType, String socialId);

}
