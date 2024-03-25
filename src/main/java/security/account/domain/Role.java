package security.account.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    NORMAL("ROLE_NORMAL"),
    ADMIN("ROLE_ADMIN");

    private final String key;

}