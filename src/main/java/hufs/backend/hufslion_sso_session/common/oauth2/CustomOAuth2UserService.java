package hufs.backend.hufslion_sso_session.common.oauth2;

import java.util.Collections;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import hufs.backend.hufslion_sso_session.member.repository.MemberRepository;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Service
@Transactional
@Slf4j
public class CustomOAuth2UserService
	implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final MemberRepository memberRepository;
	private final HttpSession httpSession;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

		log.info("=================================");
		log.info("=== OAuth2 로그인 시작 ===");
		log.info("=================================");

		OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = delegate.loadUser(userRequest);

		// 현재 로그인 진행 중인 서비스를 구분하는 코드 (네이버 로그인인지 구글 로그인인지 구분)
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		log.info("소셜 제공자: {}", registrationId);

		String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
			.getUserInfoEndpoint().getUserNameAttributeName();
		log.info("userNameAttributeName: {}", userNameAttributeName);

		// 카카오에서 받은 원본 응답 로그
		log.info("=== 카카오 원본 응답 ===");
		log.info("전체 Attributes: {}", oAuth2User.getAttributes());

		// OAuth2UserService를 통해 가져온 OAuthUser의 attribute를 담을 클래스 ( 네이버 등 다른 소셜 로그인도 이 클래스 사용)
		OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName,
			oAuth2User.getAttributes());

		log.info("=== 파싱된 사용자 정보 ===");
		log.info("Name: {}", attributes.getName());
		log.info("Email: {}", attributes.getEmail());
		log.info("ProfileImage: {}", attributes.getProfileImage());
		log.info("SocialProvider: {}", attributes.getSocialProvider());
		log.info("SocialId: {}", attributes.getSocialId());

		Member member = saveOrUpdate(attributes);
		log.info("최종 사용자 엔티티 - ID: {}, Email: {}", member.getId(), member.getEmail());
		log.info("=== OAuth2 로그인 완료 ===");

		return new DefaultOAuth2User(
			Collections.singleton(new SimpleGrantedAuthority(member.getOauthId())),
			attributes.getAttributes(),
			attributes.getNameAttributeKey());
	}

	private Member saveOrUpdate(OAuthAttributes attributes) {
		Member userEntity = memberRepository.findByEmail(attributes.getEmail())
			.map(entity -> {
				log.info("기존 사용자 발견 - ID: {}, Email: {}", entity.getId(), entity.getEmail());
				return entity.update(attributes.getName());
			})
			.orElseGet(() -> {
				log.info("새 사용자 생성 - Email: {}", attributes.getEmail());
				return attributes.toEntity();
			});

		Member savedMember = memberRepository.save(userEntity);
		log.info("저장된 사용자 - ID: {}, Email: {}", savedMember.getId(), savedMember.getEmail());

		return savedMember;
	}
}