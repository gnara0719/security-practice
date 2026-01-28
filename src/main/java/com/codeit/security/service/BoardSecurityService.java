package com.codeit.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class BoardSecurityService {

    public boolean checkAccess(Long boardId, String username) {
        // 복잡한 DB 조회 및 권한 체크 로직...

        return true;    // 접근 허용
    }
}
