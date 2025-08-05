package io.vikunalabs.hmp.auth.shared;

import java.io.Serializable;

public record ApiResponse<T>(boolean success, T data, String error, String message) implements Serializable {

    public ApiResponse(boolean success, T data) {
        this(success, data, null, null);
    }

    public ApiResponse(boolean success, String error, String message) {
        this(success, null, error, message);
    }
}
