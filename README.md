# Security-OAuth2-Social-login-project
Social Login(Google, Naver Kakao) with RESTful Style using OAuth2 & JWT & Spring Security & Spring boot


## Project Spec
- java : 11
- Spring Boot : 2.7.8
- Gradle : 7.5.1
- jwt : 0.11.2
- h2 : 2.1.214
- mysql : 8.0.3


<br>
<hr>
<br>

[JWT 코드](https://github.com/OOOIOOOIO/Security-JWT-login-project)를 리팩토링하고 oauth-client 라이브러리 사용해 소셜로그인 구현!

### 나름 리팩토링
- Controller에서 HttpServletRequest를 통해 header에서 jwt를 받아와 유저 정보를 찾는 코드가 너무 많이 중복된다. 
  - resolver를 사용해 한 곳에서 처리하였다.(@UserInfoFromHeader)



<br>

- refresh token을 db에 저장하기 때문에 db IO가 많이 발생한다. 이제 이걸 redis를 써서 고쳐봐야겠다.
