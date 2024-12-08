module github.com/sloonz/woodpecker-signed-env

go 1.22.0

toolchain go1.22.3

require (
	github.com/go-ap/httpsig v0.0.0-20221203064646-3647b4d88fdf
	github.com/golang-jwt/jwt/v5 v5.2.1
	go.woodpecker-ci.org/woodpecker/v2 v2.5.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/robfig/cron v1.2.0 // indirect
