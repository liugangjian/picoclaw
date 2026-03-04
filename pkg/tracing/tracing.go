package tracing

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type contextKey string

const RequestIDKey contextKey = "request_id"

// GenerateRequestID 生成唯一的请求ID
func GenerateRequestID() string {
	return uuid.New().String()
}

// ContextWithRequestID 将请求ID添加到上下文
func ContextWithRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, reqID)
}

// RequestIDFromContext 从上下文中获取请求ID
func RequestIDFromContext(ctx context.Context) string {
	reqID, ok := ctx.Value(RequestIDKey).(string)
	if !ok {
		return ""
	}
	return reqID
}

// RequestIDMiddleware HTTP中间件，为每个请求生成和传递请求ID
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = GenerateRequestID()
		}

		// 将requestID添加到上下文中
		ctx := ContextWithRequestID(r.Context(), requestID)

		// 将requestID返回给客户端
		w.Header().Set("X-Request-ID", requestID)

		// 使用新的上下文继续处理请求
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
