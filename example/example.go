//Assumes you've set up a client at http://instagram.com/developer/clients/manage/
//recommend using localhost:8080/ for a test client:
// WEBSITE URL	http://localhost:8080
// REDIRECT URI	http://localhost:8080/callback
package main

import (
	"fmt"
	"github.com/alainbrown/instagram_go"
	"net/http"
)

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/callback", callback)
	http.HandleFunc("/main_page", main_page)
	http.ListenAndServe(":8080", nil)
}

// replace {client_id} and {client_secret}
var config = instagram_go.DefaultConfig("{client_id}", "{client_secret}", "http://localhost:8080/callback")

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<a href="%s">Sign into IG</a>`, config.InstaSignInUrl())
}

var users = map[string]*instagram_go.InstaAuthResponse{}

// you can store access token and user info in session
// storing in a crappy map for this example
func callback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	user, err := instagram_go.NewIg(config).SignIntoInstagram(code)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	users["{generate_on_your_own!}"] = user
	http.Redirect(w, r, "/main_page?session="+"{generate_on_your_own!}", http.StatusFound)
}

func main_page(w http.ResponseWriter, r *http.Request) {
	user := users[r.FormValue("session")]
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	userName := user.User.UserName
	fmt.Fprintf(w, `<p>Hi! <a href="http://instagram.com/%s">%s</a></p>`, userName, userName)
}
