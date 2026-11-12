package com.yashsomani.secure_file_transfer.exception;

import com.yashsomani.secure_file_transfer.service.FileValidationService;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Centralized exception handling for the REST API.
 *
 * <p>Produces consistent, machine-readable Problem Details responses
 * (RFC 9457) without leaking internal implementation details to clients.</p>
 *
 * <p>This handler deliberately does NOT expose {@link Throwable#getMessage()}
 * directly, because messages often contain internal paths, stack frames,
 * database identifiers, or other sensitive details.</p>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Application-level business/validation failures thrown by services.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleIllegalArgument(
            IllegalArgumentException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(400);
        detail.setTitle("Bad Request");
        detail.setDetail("Invalid request");
        detail.setProperty("reason", sanitize(ex.getMessage()));
        return ResponseEntity.badRequest().body(detail);
    }

    /**
     * Resource lookup failures (missing file, share, user).
     */
    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ProblemDetail> handleNoSuchElement(
            NoSuchElementException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(404);
        detail.setTitle("Not Found");
        detail.setDetail("The requested resource was not found");
        detail.setProperty("reason", sanitize(ex.getMessage()));
        return ResponseEntity.status(404).body(detail);
    }

    /**
     * Unauthorized access attempts.
     */
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ProblemDetail> handleSecurityException(
            SecurityException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(403);
        detail.setTitle("Forbidden");
        detail.setDetail("Access to this resource is denied");
        detail.setProperty("reason", sanitize(ex.getMessage()));
        return ResponseEntity.status(403).body(detail);
    }

    /**
     * Expired or otherwise invalid share references.
     */
    @ExceptionHandler(ShareExpiredException.class)
    public ResponseEntity<ProblemDetail> handleShareExpired(
            ShareExpiredException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(410);
        detail.setTitle("Share Expired");
        detail.setDetail("This share is no longer available");
        detail.setProperty("reason", sanitize(ex.getMessage()));
        return ResponseEntity.status(410).body(detail);
    }

    /**
     * Bean validation failures on request bodies (e.g. registration DTO).
     * Returns the individual field errors without echoing the rejected value.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidation(
            MethodArgumentNotValidException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(400);
        detail.setTitle("Bad Request");
        detail.setDetail("Validation failed");

        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(fieldError ->
                errors.put(fieldError.getField(), fieldError.getDefaultMessage()));

        detail.setProperty("errors", errors);
        return ResponseEntity.badRequest().body(detail);
    }

    /**
     * Malformed path variables or parameters (e.g. a non-numeric value where
     * a Long is expected). Returns 400 instead of leaking a 500.
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ProblemDetail> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(400);
        detail.setTitle("Bad Request");
        detail.setDetail("Invalid request parameter");
        // Only the parameter NAME is echoed back — the conversion-failure
        // message may contain type/internal details, so it is not exposed.
        detail.setProperty("parameter", ex.getName());
        return ResponseEntity.badRequest().body(detail);
    }

    /**
     * Missing or malformed request parameters.
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ProblemDetail> handleMissingParams(
            MissingServletRequestParameterException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(400);
        detail.setTitle("Bad Request");
        detail.setDetail("Missing required request parameter");
        detail.setProperty("parameter", ex.getParameterName());
        return ResponseEntity.badRequest().body(detail);
    }

    /**
     * File validation failures (size, type, filename, empty).
     */
    @ExceptionHandler(FileValidationService.FileValidationException.class)
    public ResponseEntity<ProblemDetail> handleFileValidation(
            FileValidationService.FileValidationException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(400);
        detail.setTitle("Bad Request");
        detail.setDetail("File validation failed");
        detail.setProperty("reason", sanitize(ex.getMessage()));
        return ResponseEntity.badRequest().body(detail);
    }

    /**
     * Oversized multipart uploads (Spring's default resolver maps this to 400).
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ProblemDetail> handleMaxUploadSize(
            MaxUploadSizeExceededException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(413);
        detail.setTitle("Payload Too Large");
        detail.setDetail("The uploaded file exceeds the maximum allowed size");
        detail.setProperty("maxUploadSize", ex.getMaxUploadSize());
        return ResponseEntity.status(413).body(detail);
    }

    /**
     * Missing static resources (e.g. unknown file download paths).
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ProblemDetail> handleNoResourceFound(
            NoResourceFoundException ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(404);
        detail.setTitle("Not Found");
        detail.setDetail("The requested resource was not found");
        return ResponseEntity.status(404).body(detail);
    }

    /**
     * Unexpected internal failures. Never forwards the raw exception message
     * or stack trace to the client.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(
            Exception ex, WebRequest request) {

        ProblemDetail detail = ProblemDetail.forStatus(500);
        detail.setTitle("Internal Server Error");
        detail.setDetail("An unexpected error occurred while processing the request");
        // Log internally for operators; the client only sees the generic message.
        org.slf4j.LoggerFactory.getLogger(GlobalExceptionHandler.class)
                .warn("Unhandled exception while processing request", ex);
        return ResponseEntity.status(500).body(detail);
    }

    /**
     * Strips anything that looks like an internal file path or stack frame
     * from exception messages before returning it to the client.
     */
    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "No additional detail available";
        }
        // Remove absolute paths (Windows and Unix) and stack-trace fragments.
        return message
                .replaceAll("(?i)([A-Za-z]:\\\\[^\\s]*|/[^\\s]*\\.java)", "[path redacted]")
                .replaceAll("com\\.yashsomani\\.[^\\s]*", "[internal]")
                .replaceAll("\\bat [^\\s]*", "[frame]")
                .trim();
    }
}