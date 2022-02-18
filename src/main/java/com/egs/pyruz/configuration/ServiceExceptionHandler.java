package com.egs.pyruz.configuration;

import com.egs.pyruz.models.dto.MessageDTO;
import com.egs.pyruz.models.dto.ServiceExceptionDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ServiceExceptionHandler {

    final ApplicationProperties applicationProperties;

    public ServiceExceptionHandler(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    // --> Custom exceptions
    @ExceptionHandler(ServiceExceptionDTO.class)
    public final ResponseEntity<?> handleServiceException(ServiceExceptionDTO ex) {
        return new ResponseEntity<>(new MessageDTO(ex.getMessage()), ex.getHttpStatus() == null ? HttpStatus.INTERNAL_SERVER_ERROR : ex.getHttpStatus());
    }

}
