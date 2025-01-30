package com.cupfeedeal.domain.Auth.controller;

import com.cupfeedeal.domain.Auth.dto.responseDto.KakaoUserInfoResponseDto;
import com.cupfeedeal.domain.Auth.dto.responseDto.LoginResponseDto;
import com.cupfeedeal.domain.Auth.security.JwtTokenProvider;
import com.cupfeedeal.domain.Auth.service.AuthService;
import com.cupfeedeal.domain.Auth.service.KakaoService;
import com.cupfeedeal.domain.User.entity.User;
import com.cupfeedeal.domain.User.repository.UserRepository;
import com.cupfeedeal.domain.UserSubscription.repository.UserSubscriptionRepository;
import com.cupfeedeal.global.common.response.CommonResponse;
import com.cupfeedeal.global.exception.ApplicationException;
import com.cupfeedeal.global.exception.ExceptionCode;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import com.cupfeedeal.domain.User.entity.CustomUserdetails;


@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final KakaoService kakaoService;
    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserSubscriptionRepository userSubscriptionRepository;

    @GetMapping("/callback")
    public CommonResponse<?> callback(@RequestParam("code") String code, @RequestParam("redirect_uri") String redirectUri) throws IOException {

        String accessToken = kakaoService.getAccessTokenFromKakao(code, redirectUri);


        KakaoUserInfoResponseDto userInfo = kakaoService.getUserInfo(accessToken);

        LoginResponseDto loginResponseDto = authService.login(userInfo);

        return new CommonResponse<>(loginResponseDto, "카카오 로그인에 성공했습니다.");
    }

    @GetMapping("/login/demo/{userId}")
    public CommonResponse<?> demoLogin(@PathVariable("userId") Integer userId) throws IOException {

        if(userId >=11 && userId <=14) {
            return forceLogin(userId);
        }

        return new CommonResponse<>(null, "카카오 로그인에 성공했습니다.");
    }

    private CommonResponse<?> forceLogin(Integer userId) {
        User user = userRepository.findByUserId(Long.valueOf(userId))
                .orElseThrow(() -> new ApplicationException(ExceptionCode.USER_NOT_FOUND));

        String token = jwtTokenProvider.createToken(user.getUserId());

        LoginResponseDto loginResponseDto = LoginResponseDto.builder()
                .username(user.getUsername())
                .token(token)
                .subscription_count(userSubscriptionRepository.findAllByUser(user).size())
                .is_first(false)
                .build();

        return new CommonResponse<>(loginResponseDto, "데모 계정 로그인 성공");
    }

    @DeleteMapping("/withdraw")
    public CommonResponse<?> withdraw(@AuthenticationPrincipal CustomUserdetails customUserDetails, HttpServletRequest request) {
        Long userId = customUserDetails.getUserId();

        authService.withdraw(userId);

        return new CommonResponse<>(null, "회원 탈퇴가 완료되었습니다.");
    }

    @GetMapping("/callback/backend")
    public CommonResponse<?> callbackBackend(@RequestParam("code") String code) throws IOException {

        String redirectUri = "https://api.cupfeedeal.xyz/api/v1/auth/callback/backend";
//        String redirectUri = "http://localhost:8080/api/v1/auth/callback/backend";

        String accessToken = kakaoService.getAccessTokenFromKakao(code, redirectUri);

        KakaoUserInfoResponseDto userInfo = kakaoService.getUserInfo(accessToken);

        LoginResponseDto loginResponseDto = authService.login(userInfo);

        return new CommonResponse<>(loginResponseDto, "카카오 로그인에 성공했습니다.");
    }


}
