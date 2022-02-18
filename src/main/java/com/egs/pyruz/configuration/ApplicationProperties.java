package com.egs.pyruz.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.core.env.Environment;

import javax.annotation.Resource;

@Configuration
@PropertySources(
        {
                @PropertySource(name = "messages", value = "classpath:/message.properties", encoding = "UTF-8", ignoreResourceNotFound = true),
                @PropertySource(name = "application", value = "classpath:/application.properties", encoding = "UTF-8", ignoreResourceNotFound = true)
        }
)

public class ApplicationProperties {
    @Resource
    private Environment environment;

    public String getProperty(String name) {
        if (name.equalsIgnoreCase("username")) return "Username";
        else return environment.getProperty(name);
    }

}
