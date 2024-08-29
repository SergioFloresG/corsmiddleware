// Package corsmiddleware plugin.
package corsmiddleware

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	AllowCredentials bool     `json:"allowCredentials,omitempty"`
	AllowOrigins     []string `json:"allowOrigins,omitempty"`
	AllowMethods     []string `json:"allowMethods,omitempty"`
	AllowHeaders     []string `json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `json:"exposeHeaders,omitempty"`
	MaxAge           int64    `json:"maxAge,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		AllowCredentials: false,
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"OPTIONS", "GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{},
		ExposeHeaders:    []string{},
		MaxAge:           86400,
	}
}

// CORS structure for plugin execution.
type CORS struct {
	next        http.Handler
	name        string
	credentials bool

	origins []*regexp.Regexp
	methods []string
	headers []string
	exposed []string

	age int64
}

// New created a new Demo plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var err error

	var origins []*regexp.Regexp

	if Contains(config.AllowOrigins, "*") {
		all := regexp.MustCompile(".*")
		origins = []*regexp.Regexp{all}
	} else {
		origins, err = CompileOrigins(config.AllowOrigins)
		if err != nil {
			return nil, err
		}
	}

	defaultAllowHeaders := []string{
		"Content-Type", "Content-Length",
		"Accept-Encoding", "Authorization", "Accept", "Origin", "Referer", "Cache-Control",
	}
	defaultExposeHeaders := []string{
		"Content-Type", "Content-Length",
	}

	headers := MergeAndUniques(defaultAllowHeaders, config.AllowHeaders)
	exposed := MergeAndUniques(defaultExposeHeaders, config.ExposeHeaders)

	return &CORS{
		next: next,
		name: name,

		origins:     origins,
		headers:     headers,
		methods:     config.AllowMethods,
		exposed:     exposed,
		age:         config.MaxAge,
		credentials: config.AllowCredentials,
	}, nil
}

func (c *CORS) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	origin := req.Header.Get("Origin")
	if origin == "" || !AllowOrigin(c.origins, origin) {
		c.next.ServeHTTP(res, req)
		return
	}

	if req.Method == http.MethodOptions {
		c.injectOrigin(res, origin)
		res.Header().Set("Access-Control-Allow-Methods", strings.Join(c.methods, ", "))
		res.Header().Set("Access-Control-Max-Age", strconv.FormatInt(c.age, 10))
		res.WriteHeader(http.StatusNoContent)
		return
	}

	c.injectOrigin(res, origin)
	c.next.ServeHTTP(res, req)
}

func (c *CORS) injectOrigin(res http.ResponseWriter, origin string) {
	res.Header().Set("Access-Control-Allow-Origin", origin)
	res.Header().Set("Access-Control-Allow-Credentials", strconv.FormatBool(c.credentials))
	res.Header().Set("Access-Control-Allow-Headers", strings.Join(c.headers, ", "))
	res.Header().Set("Access-Control-Expose-Headers", strings.Join(c.exposed, ", "))
}
