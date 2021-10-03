# msidal

Microsoft Identity Authentication Library For Go

### Installation

Install the package with the following command.

```
go get github.com/alexandervantrijffel/msidal
```

#### Usage

Example calling code for verifying an JWT bearer token. This verifies the audience, signature and expiration validity of the token.

```
import (
    "github.com/alexandervantrijffel/msidal"
)

settings := AzureSettings{
  TenantID:                "Directory (tenant) ID",
  ClientID:                "Application (client) ID",
  ActiveDirectoryEndpoint: "https://login.microsoftonline.com/",
}
token, err := msidal.VerifyToken(&settings, "Bearer ey......")
```

Example for parsing claims from the returned oidc Token:

```
var claims struct {
  Name     string   `json:"name"`
  UserName string   `json:"preferred_username"`
}
token.Claims(&claims)
```
