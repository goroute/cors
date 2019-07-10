package cors

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/goroute/route"
)

type (
	// Options defines the config for CORS middleware.
	Options struct {
		// Skipper defines a function to skip middleware.
		Skipper route.Skipper

		// AllowOrigin defines a list of origins that may access the resource.
		// Optional. Default value []string{"*"}.
		AllowOrigins []string `yaml:"allow_origins"`

		// AllowMethods defines a list methods allowed when accessing the resource.
		// This is used in response to a preflight request.
		// Optional. Default value DefaultCORSConfig.AllowMethods.
		AllowMethods []string `yaml:"allow_methods"`

		// AllowHeaders defines a list of request headers that can be used when
		// making the actual request. This in response to a preflight request.
		// Optional. Default value []string{}.
		AllowHeaders []string `yaml:"allow_headers"`

		// AllowCredentials indicates whether or not the response to the request
		// can be exposed when the credentials flag is true. When used as part of
		// a response to a preflight request, this indicates whether or not the
		// actual request can be made using credentials.
		// Optional. Default value false.
		AllowCredentials bool `yaml:"allow_credentials"`

		// ExposeHeaders defines a whitelist headers that clients are allowed to
		// access.
		// Optional. Default value []string{}.
		ExposeHeaders []string `yaml:"expose_headers"`

		// MaxAge indicates how long (in seconds) the results of a preflight request
		// can be cached.
		// Optional. Default value 0.
		MaxAge int `yaml:"max_age"`
	}
)

var (
	// DefaultOptions is the default CORS middleware config.
	DefaultOptions = Options{
		Skipper:      route.DefaultSkipper,
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}
)

// New returns a CORS middleware.
func New(opts Options) route.MiddlewareFunc {
	// Defaults
	if opts.Skipper == nil {
		opts.Skipper = DefaultOptions.Skipper
	}
	if len(opts.AllowOrigins) == 0 {
		opts.AllowOrigins = DefaultOptions.AllowOrigins
	}
	if len(opts.AllowMethods) == 0 {
		opts.AllowMethods = DefaultOptions.AllowMethods
	}

	allowMethods := strings.Join(opts.AllowMethods, ",")
	allowHeaders := strings.Join(opts.AllowHeaders, ",")
	exposeHeaders := strings.Join(opts.ExposeHeaders, ",")
	maxAge := strconv.Itoa(opts.MaxAge)

	return func(next route.HandlerFunc) route.HandlerFunc {
		return func(c route.Context) error {
			if opts.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			res := c.Response()
			origin := req.Header.Get(route.HeaderOrigin)
			allowOrigin := ""

			// Check allowed origins
			for _, o := range opts.AllowOrigins {
				if o == "*" && opts.AllowCredentials {
					allowOrigin = origin
					break
				}
				if o == "*" || o == origin {
					allowOrigin = o
					break
				}
			}

			// Simple request
			if req.Method != http.MethodOptions {
				res.Header().Add(route.HeaderVary, route.HeaderOrigin)
				res.Header().Set(route.HeaderAccessControlAllowOrigin, allowOrigin)
				if opts.AllowCredentials {
					res.Header().Set(route.HeaderAccessControlAllowCredentials, "true")
				}
				if exposeHeaders != "" {
					res.Header().Set(route.HeaderAccessControlExposeHeaders, exposeHeaders)
				}
				return next(c)
			}

			// Preflight requestR
			res.Header().Add(route.HeaderVary, route.HeaderOrigin)
			res.Header().Add(route.HeaderVary, route.HeaderAccessControlRequestMethod)
			res.Header().Add(route.HeaderVary, route.HeaderAccessControlRequestHeaders)
			res.Header().Set(route.HeaderAccessControlAllowOrigin, allowOrigin)
			res.Header().Set(route.HeaderAccessControlAllowMethods, allowMethods)
			if opts.AllowCredentials {
				res.Header().Set(route.HeaderAccessControlAllowCredentials, "true")
			}
			if allowHeaders != "" {
				res.Header().Set(route.HeaderAccessControlAllowHeaders, allowHeaders)
			} else {
				h := req.Header.Get(route.HeaderAccessControlRequestHeaders)
				if h != "" {
					res.Header().Set(route.HeaderAccessControlAllowHeaders, h)
				}
			}
			if opts.MaxAge > 0 {
				res.Header().Set(route.HeaderAccessControlMaxAge, maxAge)
			}
			return c.NoContent(http.StatusNoContent)
		}
	}
}
