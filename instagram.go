package instagram_go

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	InstagramOAuthUrl   = "https://api.instagram.com/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=%s"
	InstagramTokenUrl   = "https://api.instagram.com/oauth/access_token"
	InstagramOAuthScope = "basic+comments+relationships+likes"
)

type Config struct {
	ClientId            string
	ClientSecret        string
	Redirect            string
	InstagramOAuthUrl   string
	InstagramTokenUrl   string
	InstagramOAuthScope string
}

type Ig struct {
	Config Config
	Client *http.Client
}

type InstaAuthResponse struct {
	AccessToken string    `json:"access_token"`
	User        InstaUser `json:"user"`
}

type InstaUser struct {
	Id             string `json:"id"`
	UserName       string `json:"username"`
	ProfilePicture string `json:"profile_picture"`
}

func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// Useful for restricted api calls:
// http://instagram.com/developer/restrict-api-requests/
func Signature(ip, clientSecret string) string {
	return ip + "|" + computeHmac256(ip, clientSecret)
}

// Creates new Ig client with default http client and default instagram endpoints
func NewIg(config Config) *Ig {
	return &Ig{
		Client: &http.Client{},
		Config: config,
	}
}

func DefaultConfig(clientId, clientSecret, redirectUrl string) Config {
	return Config{
		ClientId:            clientId,
		ClientSecret:        clientSecret,
		Redirect:            redirectUrl,
		InstagramOAuthUrl:   InstagramOAuthUrl,
		InstagramTokenUrl:   InstagramTokenUrl,
		InstagramOAuthScope: InstagramOAuthScope,
	}
}

func (ig *Ig) SignIntoInstagram(code string) (*InstaAuthResponse, error) {

	vals := url.Values{
		"client_id":     {ig.Config.ClientId},
		"client_secret": {ig.Config.ClientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {ig.Config.Redirect},
		"code":          {code},
	}
	resp, err := ig.Client.PostForm(ig.Config.InstagramTokenUrl, vals)
	if err != nil {
		msg := fmt.Sprintf("error executing signin to ig with request %v, error: %v", vals, err)
		return nil, errors.New(msg)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("error parsing signin response to ig with request %v, error: %v", vals, err)
		return nil, errors.New(msg)
	}
	instaResp := &InstaAuthResponse{}
	err = json.Unmarshal(body, instaResp)
	if err != nil {
		msg := fmt.Sprintf("error unmarshalling signin response to ig with request %v, error: %v", vals, err)
		return nil, errors.New(msg)
	}
	return instaResp, nil
}

func (config *Config) InstaSignInUrl() string {
	return fmt.Sprintf(InstagramOAuthUrl,
		config.ClientId,
		config.Redirect,
		config.InstagramOAuthScope)
}
