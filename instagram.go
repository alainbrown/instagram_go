package instagram_go

import (
	"bytes"
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
	InstagramOAuthScope = "basic+public_content+follower_list+comments+relationships+likes"

	InstagramV1Users = "https://api.instagram.com/v1/users/%s/relationship?access_token=%s"
)

type Config struct {
	ClientId            string
	ClientSecret        string
	Redirect            string
	InstagramOAuthUrl   string
	InstagramTokenUrl   string
	InstagramOAuthScope string

	InstagramV1Users string
}

type Ig struct {
	Config      Config
	Client      *http.Client
	AccessToken string
	Signature   string
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
		InstagramV1Users:    InstagramV1Users,
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

func (ig *Ig) InstaSignInUrl() string {
	return fmt.Sprintf(ig.Config.InstagramOAuthUrl,
		ig.Config.ClientId,
		ig.Config.Redirect,
		ig.Config.InstagramOAuthScope)
}

func (ig *Ig) UserAction(action, id string) error {

	data := url.Values{"action": {action}}
	formatedUrl := fmt.Sprintf(ig.Config.InstagramV1Users, id, ig.AccessToken)
	req, err := http.NewRequest("POST", formatedUrl, bytes.NewBufferString(data.Encode()))
	if err != nil {
		msg := fmt.Sprintf("error creating request %v", err)
		return errors.New(msg)
	}
	req.Header.Add("X-Insta-Forwarded-For", ig.Signature)
	resp, err := ig.Client.Do(req)
	if err != nil {
		msg := fmt.Sprintf("error executing request %v", err)
		return errors.New(msg)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("error parsing response %v", err)
		return errors.New(msg)
	}
	if resp.StatusCode == 429 {
		return errors.New("reached restricted the api limit")
	}
	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("error response: %v", string(body))
		return errors.New(msg)
	}
	return nil
}
