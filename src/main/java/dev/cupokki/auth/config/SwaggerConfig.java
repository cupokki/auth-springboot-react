package dev.cupokki.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.responses.ApiResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("인증서버 API 문서")
                        .description("인증서버 Swagger 문서입니다.")
                        .version("1.0")
                )
                .components(new Components()
                        .addResponses("403", new ApiResponse().description("권한 없음"))
                        .addResponses("404", new ApiResponse().description("리소스 없음"))
                        .addResponses("201", new ApiResponse().description("리로스 생성"))
                        .addResponses("204", new ApiResponse().description("삭제 성공"))
                );
    }

}