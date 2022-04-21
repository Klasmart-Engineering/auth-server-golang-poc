package env

import (
	"os"
	"strconv"
	"time"
)

func getEnv(envvar string, defaultVal string) string {
	if value, exist := os.LookupEnv(envvar); exist {
		return value
	}

	return defaultVal
}

func getTimeEnv(envvar string, defaultVal string) time.Duration {
	valueStr := getEnv(envvar, defaultVal)
	valueFloat, err := strconv.ParseFloat(valueStr, 0)
	if err != nil {
		panic(err)
	}
	value := time.Duration(valueFloat * float64(time.Second))

	return value
}

var Domain = getEnv("DOMAIN", "localhost")
var JwtIssuer = getEnv("JWT_ISSUER", "kidsloop")
var JwtAlgorithm = getEnv("JWT_ALGORITHM", "RS512")
var JwtAccessTokenDuration = getTimeEnv("JWT_ACCESS_TOKEN_DURATION", "900")
var JwtRefreshTokenDuration = getTimeEnv("JWT_ACCESS_REFRESH_DURATION", "1.206e+06")

// Azure B2C configuration
var AzureB2cEnabled = getEnv("AZURE_B2C_ENABLED", "true")
var AzureB2cClientId = getEnv("AZURE_B2C_CLIENT_ID", "926001fe-7853-485d-a15e-8c36bb4acaef")
var AzureB2cTenantId = getEnv("AZURE_B2C_TENANT_ID", "8d922fec-c1fc-4772-b37e-18d2ce6790df")
var AzureB2cDomain = getEnv("AZURE_B2C_DOMAIN", "login.loadtest.kidsloop.live")
var AzureB2cPolicyName = getEnv("AZURE_B2C_POLICY_NAME", "B2C_1A_RELYING_PARTY_SIGN_UP_LOG_IN")
var AzureB2cAuthority = getEnv("AZURE_B2C_AUTHORITY", "B2C_1A_RELYING_PARTY_SIGN_UP_LOG_IN")
var AzureB2cVersion = getEnv("AZURE_B2C_VERSION", "v2.0")
