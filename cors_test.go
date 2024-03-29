package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute/route"
	"github.com/stretchr/testify/assert"
)

func TestCORS(t *testing.T) {
	mux := route.NewServeMux()

	// Wildcard origin
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := mux.NewContext(req, rec)
	mw := New()
	mw(c, route.NotFoundHandler)
	assert.Equal(t, "*", rec.Header().Get(route.HeaderAccessControlAllowOrigin))

	// Allow origins
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = mux.NewContext(req, rec)
	mw = New(AllowOrigins([]string{"localhost"}))
	req.Header.Set(route.HeaderOrigin, "localhost")
	mw(c, route.NotFoundHandler)
	assert.Equal(t, "localhost", rec.Header().Get(route.HeaderAccessControlAllowOrigin))

	// Preflight request
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	rec = httptest.NewRecorder()
	c = mux.NewContext(req, rec)
	req.Header.Set(route.HeaderOrigin, "localhost")
	req.Header.Set(route.HeaderContentType, route.MIMEApplicationJSON)

	mw = New(
		AllowOrigins([]string{"localhost"}),
		AllowCredentials(true),
		MaxAge(3600),
	)
	mw(c, route.NotFoundHandler)

	assert.Equal(t, "localhost", rec.Header().Get(route.HeaderAccessControlAllowOrigin))
	assert.NotEmpty(t, rec.Header().Get(route.HeaderAccessControlAllowMethods))
	assert.Equal(t, "true", rec.Header().Get(route.HeaderAccessControlAllowCredentials))
	assert.Equal(t, "3600", rec.Header().Get(route.HeaderAccessControlMaxAge))

	// Preflight request with `AllowOrigins` *
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	rec = httptest.NewRecorder()
	c = mux.NewContext(req, rec)
	req.Header.Set(route.HeaderOrigin, "localhost")
	req.Header.Set(route.HeaderContentType, route.MIMEApplicationJSON)
	mw = New(
		AllowOrigins([]string{"*"}),
		AllowCredentials(true),
		MaxAge(3600),
	)
	mw(c, route.NotFoundHandler)

	assert.Equal(t, "localhost", rec.Header().Get(route.HeaderAccessControlAllowOrigin))
	assert.NotEmpty(t, rec.Header().Get(route.HeaderAccessControlAllowMethods))
	assert.Equal(t, "true", rec.Header().Get(route.HeaderAccessControlAllowCredentials))
	assert.Equal(t, "3600", rec.Header().Get(route.HeaderAccessControlMaxAge))
}
