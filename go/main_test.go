package main

import (
	"testing"
	"github.com/stretchr/testify/suite"

	"os" 

	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//Test suite type framework
type MinitwitTestSuite struct { 
    suite.Suite
    router   *chi.Mux
    dbFile   *os.File
    dbPath   string
}

// Set up blank database before each test
func (suite *MinitwitTestSuite) SetupTest() {
    dbFile, err := os.CreateTemp("", "minitwit-test-*.db")
    suite.Require().NoError(err)
    
    suite.dbFile = dbFile
    suite.dbPath = dbFile.Name()
    
    DATABASE = suite.dbPath
    
    err = InitDB()
	suite.Require().NoError(err)
    
    suite.router = chi.NewRouter()
    suite.router.Use(middleware.Logger)
    suite.router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Welcome"))
	})
}

// TearDownTest runs after each test, and deletes the temp db
func (suite *MinitwitTestSuite) TearDownTest() {
    if suite.dbFile != nil {
        suite.dbFile.Close()
        os.Remove(suite.dbPath)
    }
}


// helper functions:

//Makes a HTTP Request
func (suite *MinitwitTestSuite) makeHTTPRequest(method, path string, body string, contentType string, followRedirects bool) *httptest.ResponseRecorder {
    req := httptest.NewRequest(method, path, strings.NewReader(body))
    if contentType != "" {
        req.Header.Set("Content-Type", contentType)
    }
    
    w := httptest.NewRecorder()
    suite.router.ServeHTTP(w, req)
    
    if followRedirects {
        for w.Code >= 300 && w.Code < 400 {
            location := w.Header().Get("Location")
            req = httptest.NewRequest("GET", location, nil)
            w = httptest.NewRecorder()
            suite.router.ServeHTTP(w, req)
        }
    }
    
    return w
}

//Registers a user
func (suite *MinitwitTestSuite)(username string, password string, password2=nil, email=nil) Register(){
	if password2 == nil{
		password2 = password
	}
	if email == nil{
		email = username + "@example.com"
	}
	userData := suite.buildFormData(map[String]string{
		"username" : username,
		"password": password,
		"password2": password2,
		"email": email
	})
	w := suite.makeHTTPRequest("POST", "/register", userData, "application/x-www-form-urlencoded", true)
	return w.body.String()
}

//Logs in a user
func (suite *MinitwitTestSuite)(username string, password string) login(){
	userData := suite.buildFormData(Map[String]String{
		"username": username,
		"password": password
	})
	w := suite.makeHTTPRequest("POST", "/login", userData, "application/x-www-form-urlencoded", true)
	return w.body.String()
}

//Registers and logs in in one go
func (suite *MinitwitTestSuite)(username string, password string) register_and_login(){
	suite.register(username, password)
	return suite.login(username, password)
}

//Helper function to log out
func (suite *MinitwitTestSuite)logout(){
	w := suite.makeHTTPRequest("GET", "/logout", "", "", true)
	return w.body.String()
}

func (suite *MinitwitTestSuite, text string) add_message(){
	rv := makeHTTPRequest("POST", "/add_message", {"text" : text}, "application/x-www-form-urlencoded", true)
	if text{
		suite.Assert().Contains(rv, "Your message was recorded")
	}
	return rv
}

func (suite *MinitwitTestSuite) Test_register(){
	suite.Run("Succesful user registration", func() {
		rv := suite.Register("user1", "default", nil, nil)
		suite.Assert().Contains(rv, "You were successfully registered and can login now")
	})
	suite.Run("Can't register user if username is taken", func() {
		rv := suite.Register("user1", "default", nil, nil)
		suite.Assert().Contains(rv, "The username is already taken")
	})
	suite.Run("Can't register without username", func() {
		rv := suite.Register("", "default", nil, nil)
		suite.Assert().Contains(rv, "You have to enter a username")
	})
	suite.Run("Can't register without a password", func() {
		rv := suite.Register("meh", "", nil, nil)
		suite.Assert().Contains(rv, "You have to enter a password")
	})
	suite.Run("Can't register if passwords do not match", func() {
		rv := suite.Register("meh", "x", "y", nil)
		suite.Assert().Contains(rv, "The two passwords do not match")
	})
	suite.Run("Email adress has to be valid", func() {
		rv := suite.Register("meh", "foo", nil, "broken")
		suite.Assert().Contains(rv, "You have to enter a valid email")
	})
}

func (suite *MinitwitTestSuite) Test_login_logout(){
	suite.Run("Check logging in") func() {
		rv := suite.register_and_login("user1", "default")
		suite.Assert().Contains(rv, "You were logged in")
	}
	suite.Run("Check logout") func() {
		rv := suite.logout()
		suite.Assert().Contains(rv, "You were logged out")
	}
	suite.Run("Check if password is correct on login") func() {
		rv := suite.login("user1", "something_else")
		suite.Assert().Contains(rv, "Invalid password")
	}
	suite.Run("Check if username is correct on login") func() {
		rv:= suite.login("user2", "default")
		suite.Assert().Contains(rv, "Invalid username")
	}	
}

func (suite *MinitwitTestSuite) Test_message_recording() {
	suite.Run("Log in, record a message, check if messages are recorded correctly") func() {
		suite.register_and_login("foo", "default")
		suite.add_message("test message 1")
		suite.add_message("<test message 2>")
		rv := suite.makeHTTPRequest("GET", "/", "", "", false)
		suite.Assert().Contains(rv, "test message 1")
		suite.Assert().Contains(rv, "&lt;test message 2&gt;")
	}
}

func (suite *MinitwitTestSuite) Test_timelines(){
	suite.Run("Check that public timelines work") func(){
		suite.register_and_login("foo", "default")
		suite.add_message("the message by foo")
		suite.logout()
		suite.register_and_login("bar", "default")
		suite.add_message("the message by bar")
		rv := suite.makeHTTPRequest("GET", "/public", "", "", false)
		suite.Assert().Contains("the message by foo")
		suite.Assert().Contains("the message by bar")

		//bar's timeline should just show bar's message
		rv = suite.makeHTTPRequest("GET", "/", "", "", false)
		suite.Assert().Contains("the message by bar")
		suite.Assert().NotContains("the message by foo")

		//now let's follow foo
		rv = suite.makeHTTPRequest("GET", "/foo/follow", "", "", true)
		suite.Assert().Contains("You are now following &#34;foo&#34;")

		//we should now see foo's message
		rv = suite.makeHTTPRequest("GET", "/", "", "", false)
		suite.Assert().Contains("the message by bar")
		suite.Assert().Contains("the message by foo")

		//but on the user's page, we only want the user's message
		rv = suite.makeHTTPRequest("GET", "/bar", "", "", false)
		suite.Assert().Contains("the message by bar")
		suite.Assert().NotContains("the message by foo")
		rv = suite.makeHTTPRequest("GET", "/foo", "", "", false)
		suite.Assert().Contains("the message by bar")
		suite.Assert().NotContains("the message by foo")

		//now unfollow, and check if that worked
		rv = suite.makeHTTPRequest("GET", "/foo/unfollow", "", "", true)
		suite.Assert().Contains("You are no longer following &#34;foo&#34;")
		rv = suite.makeHTTPRequest("GET", "/", "", "", false)
		suite.Assert().Contains("the message by bar")
		suite.Assert().NotContains("the message by foo")
	}
}






