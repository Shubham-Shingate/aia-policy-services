package com.tata.policyservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.service.VendorExtension;
import static springfox.documentation.builders.PathSelectors.regex;
import java.util.ArrayList;
import java.util.List;

@EnableSwagger2
@Configuration
public class SwaggerConfig {

	/*
	 * The Below commented code is to create swagger api documentation by seeing the
	 * controller rest endpoints(Code to documentation)
	 */

	@Bean
	public Docket productApi() {
		return new Docket(DocumentationType.SWAGGER_2).select()
				.apis(RequestHandlerSelectors.basePackage("com.tata.policyservice")).paths(regex("/policy-service.*")).build()
				.apiInfo(metaInfo());
	}

	private ApiInfo metaInfo() {
		List<VendorExtension> vendorExtensions = new ArrayList<>();
		ApiInfo apiInfo = new ApiInfo("Policy Project TATA AIA", "Swagger API documentation dashboard for project policy of TATA AIA",
				"1.0", "Terms of Service", new Contact("Shubham", "", "shubhamshingte2234@gmail.com"),
				"Apache License Version 2.0", "https://www.apache.org/licesen.html", vendorExtensions);

		return apiInfo;
	}

	/* The Below code is to create swagger documentation by reading a yaml file */
	/*
	 * @Bean public Docket swagger() { return new
	 * Docket(DocumentationType.SWAGGER_2) .select()
	 * .apis(RequestHandlerSelectors.any()) .paths(PathSelectors.any()) .build(); }
	 * 
	 * @Primary
	 * 
	 * @Bean public SwaggerResourcesProvider swaggerResourcesProvider(
	 * InMemorySwaggerResourcesProvider defaultResourcesProvider) { return () -> {
	 * List<SwaggerResource> resources = new ArrayList<>(); Arrays.asList("api1",
	 * "api2") .forEach(resourceName -> resources.add(loadResource(resourceName)));
	 * return resources; }; }
	 * 
	 * private SwaggerResource loadResource(String resource) { SwaggerResource
	 * wsResource = new SwaggerResource(); wsResource.setName(resource);
	 * wsResource.setSwaggerVersion("2.0");
	 * wsResource.setLocation("/"+resource+"/swagger-config.yml"); return
	 * wsResource; }
	 */

}