package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"net/http"
	"net/http/httptest"
	"net/url"

	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Test suite type framework
type MinitwitTestSuite struct {
	suite.Suite
	router *chi.Mux
	dbFile *os.File
	dbPath string
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

// Makes a HTTP Request
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

func (suite *MinitwitTestSuite) buildFormData(data map[string]string) string {
	form := url.Values{}
	for key, value := range data {
		form.Set(key, value)
	}
	return form.Encode()
}

// Registers a user
func (suite *MinitwitTestSuite) register(username string, password string, password2 *string, email *string) string {
	expectedPass2 := password
	if password2 != nil {
		expectedPass2 = *password2
	}
	expectedEmail := username + "@example.com"
	if email != nil {
		expectedEmail = *email
	}
	userData := suite.buildFormData(map[string]string{
		"username":  username,
		"password":  password,
		"password2": expectedPass2,
		"email":     expectedEmail,
	})
	w := suite.makeHTTPRequest("POST", "/register", userData, "application/x-www-form-urlencoded", true)
	return w.Body.String()
}

// Logs in a user
func (suite *MinitwitTestSuite) login(username string, password string) string {
	userData := suite.buildFormData(map[string]string{
		"username": username,
		"password": password,
	})
	w := suite.makeHTTPRequest("POST", "/login", userData, "application/x-www-form-urlencoded", true)
	return w.Body.String()
}

// Registers and logs in in one go
func (suite *MinitwitTestSuite) register_and_login(username string, password string) string {
	suite.register(username, password, nil, nil)
	return suite.login(username, password)
}

// Helper function to log out
func (suite *MinitwitTestSuite) logout() string {
	w := suite.makeHTTPRequest("GET", "/logout", "", "", true)
	return w.Body.String()
}

func (suite *MinitwitTestSuite) add_message(text string) *httptest.ResponseRecorder {
	data := suite.buildFormData(map[string]string{
		"text": text,
	})
	rv := suite.makeHTTPRequest("POST", "/add_message", data, "application/x-www-form-urlencoded", true)
	if text != "" {
		assert.Contains(rv.Body.String(), "Your message was recorded")
	}
	return rv
}

func (suite *MinitwitTestSuite) Test_register() {
	suite.Run("Succesful user registration", func() {
		rv := suite.register("user1", "default", nil, nil)
		assert.Equal(Contains(rv, "You were successfully registered and can login now"), true)
	})
	suite.T().Run("Can't register user if username is taken", func(t *testing.T) {
		rv := suite.register("user1", "default", nil, nil)
		assert.Contains(rv, "The username is already taken")
	})
	suite.T().Run("Can't register without username", func(t *testing.T) {
		rv := suite.register("", "default", nil, nil)
		assert.Contains(rv, "You have to enter a username")
	})
	suite.T().Run("Can't register without a password", func(t *testing.T) {
		rv := suite.register("meh", "", nil, nil)
		assert.Contains(rv, "You have to enter a password")
	})
	suite.T().Run("Can't register if passwords do not match", func(t *testing.T) {
		rv := suite.register("meh", "x", "y", nil)
		assert.Contains(rv, "The two passwords do not match")
	})
	suite.T().Run("Email adress has to be valid", func(t *testing.T) {
		rv := suite.register("meh", "foo", nil, "broken")
		assert.Contains(rv, "You have to enter a valid email")
	})
}

func (suite *MinitwitTestSuite) Test_login_logout() {
	suite.T().Run("Check logging in", func(t *testing.T) {
		rv := suite.register_and_login("user1", "default")
		assert.Contains(rv, "You were logged in")
	})

	suite.T().Run("Check logout", func(t *testing.T) {
		rv := suite.logout()
		assert.Contains(rv, "You were logged out")
	})

	suite.T().Run("Check if password is correct on login", func(t *testing.T) {
		rv := suite.login("user1", "something_else")
		assert.Contains(rv, "Invalid password")
	})

	suite.T().Run("Check if username is correct on login", func(t *testing.T) {
		rv := suite.login("user2", "default")
		assert.Contains(rv, "Invalid username")
	})
}

func (suite *MinitwitTestSuite) Test_message_recording() {
	suite.T().Run("Log in, record a message, check if messages are recorded correctly", func(t *testing.T) {
		suite.register_and_login("foo", "default")
		suite.add_message("test message 1")
		suite.add_message("<test message 2>")
		rv := suite.makeHTTPRequest("GET", "/", "", "", false)
		assert.Contains(rv, "test message 1")
		assert.Contains(rv, "&lt;test message 2&gt;")
	})
}

func (suite *MinitwitTestSuite) Test_timelines() {
	suite.T().Run("Check that public timelines work", func(t *testing.T) {
		suite.register_and_login("foo", "default")
		suite.add_message("the message by foo")
		suite.logout()
		suite.register_and_login("bar", "default")
		suite.add_message("the message by bar")
		rv := suite.makeHTTPRequest("GET", "/public", "", "", false)
		assert.Contains(rv, "the message by foo")
		assert.Contains(rv, "the message by bar")

		//bar's timeline should just show bar's message
		rv = suite.makeHTTPRequest("GET", "/", "", "", false)
		assert.Contains(rv, "the message by bar")
		assert.NotContains(rv, "the message by foo")

		//now let's follow foo
		rv = suite.makeHTTPRequest("GET", "/foo/follow", "", "", true)
		assert.Contains(rv, "You are now following &#34;foo&#34;")

		//we should now see foo's message
		rv = suite.makeHTTPRequest("GET", "/", "", "", false)
		assert.Contains(rv, "the message by bar")
		assert.Contains(rv, "the message by foo")

		//but on the user's page, we only want the user's message
		rv = suite.makeHTTPRequest("GET", "/bar", "", "", false)
		assert.Contains(rv, "the message by bar")
		assert.NotContains(rv, "the message by foo")
		rv = suite.makeHTTPRequest("GET", "/foo", "", "", false)
		assert.Contains(rv, "the message by bar")
		assert.NotContains(rv, "the message by foo")

		//now unfollow, and check if that worked
		rv = suite.makeHTTPRequest("GET", "/foo/unfollow", "", "", true)
		assert.Contains(rv, "You are no longer following &#34;foo&#34;")
		rv = suite.makeHTTPRequest("GET", "/", "", "", false)
		assert.Contains(rv, "the message by bar")
		assert.NotContains(rv, "the message by foo")
	})
}

func TestMinitwitTestSuite(t *testing.T) {
	suite.Run(t, new(MinitwitTestSuite))
}
