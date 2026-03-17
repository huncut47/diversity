package testing

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"net/http"
	/* "net/http/httptest"
	"net/url" */
	"minitwit/internal/models"
	"minitwit/internal/utils"
	"minitwit/internal/web"
	"os"

	"github.com/go-chi/chi/v5"
)

// Test suite type framework
type MinitwitTestSuite struct {
	suite.Suite
	router *chi.Mux
	dbFile *os.File
	dbPath string
	app web.App
	server *http.Server
	sqlDB *sql.DB
}

var funcMap = template.FuncMap{
	"gravatar": utils.GravatarURL,
	"datetime": utils.FormatDate,
}

func loadTemplate(files ...string) *template.Template {
	return template.Must(template.New("").Funcs(funcMap).ParseFiles(files...))
}

// Set up blank database before each test
func (suite *MinitwitTestSuite) SetupTest() {
	var err error
	dbFile, err := os.CreateTemp("", "minitwit-test-*.db")
	suite.Require().NoError(err)

	suite.dbFile = dbFile
	suite.dbPath = dbFile.Name()

	db, err := gorm.Open(sqlite.Open(suite.dbPath), &gorm.Config{})
	suite.Require().NoError(err)

	sqlDB, err := db.DB()
	suite.Require().NoError(err)
	suite.sqlDB = sqlDB
	

	err = db.AutoMigrate(&models.User{}, &models.Message{}, &models.Follower{})
	suite.Require().NoError(err)

	suite.app = web.App{
		DB:    db,
		Store: sessions.NewCookieStore(
			[]byte("12345678901234567890123456789012"),
			[]byte("12345678901234567890123456789012"),),
		Pages: map[string]*template.Template{
					"register": loadTemplate("templates/layout.html", "templates/register.html"),
					"login":    loadTemplate("templates/layout.html", "templates/login.html"),
					"timeline": loadTemplate("templates/layout.html", "templates/timeline.html"),
				},
	}

	suite.router = suite.app.NewRouter().(*chi.Mux)

	suite.server = &http.Server{
        Addr:    ":3000",
        Handler: suite.router,
    }

	go func() {
        if err := suite.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            suite.T().Fatalf("Server failed: %v", err)
        }
    }()

}
//Tear down after each test
func (suite *MinitwitTestSuite) TearDownTest() {
	if suite.server != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := suite.server.Shutdown(ctx); err != nil {
            suite.T().Fatalf("Server shutdown failed: %v", err)
        }
    }

    if suite.sqlDB != nil {
        suite.sqlDB.Close()
    }

    if suite.dbFile != nil {
        os.Remove(suite.dbPath)
    }
}

//Helper functions

func (suite *MinitwitTestSuite) DecodeBodyToString(r *http.Response) string{
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil{
		panic(err)
	}
	bodyString := string(bodyBytes)
	return bodyString
}

func (suite *MinitwitTestSuite) CallRegisterAPI(username string) *http.Response {
	jsonStr := []byte(fmt.Sprintf(`{"username": "%s","email":"%s@example.com","pwd":"%spass"}`, username, username, username))
	resp, err := http.Post("http://localhost:3000/register", "application/json", bytes.NewBuffer(jsonStr))
	if err != nil{
		panic(err)
	}
	defer resp.Body.Close()
	return resp
}


func (suite *MinitwitTestSuite) PostMessage(username string, msg string) *http.Response{
	jsonStr := []byte(fmt.Sprintf(`{"content": "%s"}`, msg))
	resp, err := http.Post(fmt.Sprintf("http://localhost:3000/msgs/%s", username), "application/json", bytes.NewBuffer(jsonStr))
	if err != nil{
		panic(err)
	}
	defer resp.Body.Close()
	return resp
}

//Tests
func (suite *MinitwitTestSuite) TestRegisterAPI(t *testing.T) {
	resp := suite.CallRegisterAPI("testuser")
	assert.True(t, resp.StatusCode == 204)
	
	resp, err := http.Get("http://localhost:3000/testuser")
	if err != nil {
		panic(err)
	}
	require.False(t, resp.StatusCode == 404)
}

func (suite *MinitwitTestSuite) TestMsgsUser(t *testing.T){
	resp := suite.CallRegisterAPI("testuser")
	require.True(t, resp.StatusCode == 204)

	//Test POST
	resp = suite.PostMessage("testuser", "this is a test message")
	assert.True(t, resp.StatusCode == 204)

	//Test GET
	resp, err := http.Get("http://localhost:3000/msgs/testuser")
	if err != nil{
		panic(err)
	}
	responseBody := suite.DecodeBodyToString(resp)
	assert.Contains(t, responseBody, "this is a test message")
	assert.True(t, resp.StatusCode == 200)
}
	
func (suite *MinitwitTestSuite) TestFllwsUser(t *testing.T){
	resp := suite.CallRegisterAPI("user1")
	require.True(t, resp.StatusCode == 204)
	resp = suite.CallRegisterAPI("user2")
	require.True(t, resp.StatusCode == 204)

	//Test POST Follow:
	jsonStr := []byte(`{"follow":"user2"}`)
	resp, err := http.Post("http://localhost:3000/fllws/user1", "application/json", bytes.NewBuffer(jsonStr))
	if err != nil{
		panic(err)
	}
	assert.True(t, resp.StatusCode == 204)

	//Test GET
	resp, err = http.Get("http://localhost:3000/fllws/user1)")
	if err!= nil{
		panic(err)
	}
	defer resp.Body.Close()

	var data struct {
		Follows string `json:"follows"`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil{
		panic(err)
	}
	assert.Contains(t, data.Follows, "user2")

	//Test POST Unfollow
	jsonStr = []byte(`{"unfollow":"user2"}`)
	resp, err = http.Post("http://localhost:3000/fllws/user1", "application/json", bytes.NewBuffer(jsonStr))
	if err != nil{
		panic(err)
	}
	assert.True(t, resp.StatusCode == 204)
	resp, err = http.Get("http://localhost:3000/fllws/user1)")
	if err!= nil{
		panic(err)
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil{
		panic(err)
	}
	assert.NotContains(t, data.Follows, "user2")
}

func (suite *MinitwitTestSuite) TestMsgs(t *testing.T) {
	resp := suite.CallRegisterAPI("testuser")
	require.True(t, resp.StatusCode == 204)

	resp = suite.PostMessage("testuser", "message1")
	assert.True(t, resp.StatusCode == 204)
	resp = suite.PostMessage("testuser", "message2")
	assert.True(t, resp.StatusCode == 204)
	resp = suite.PostMessage("testuser", "message3")
	assert.True(t, resp.StatusCode == 204)

	resp, err := http.Get("http://localhost:3000/msgs")
	if err != nil{
		panic(err)
	}
	assert.True(t, resp.StatusCode == 200)
	bodyText := suite.DecodeBodyToString(resp)
	assert.Contains(t, bodyText, "message1")
	assert.Contains(t, bodyText, "message2")
	assert.Contains(t, bodyText, "message3")
}

func (suite *MinitwitTestSuite) TestLatest(t *testing.T) {
	resp := suite.CallRegisterAPI("testuser")
	require.True(t, resp.StatusCode == 204)
	resp = suite.PostMessage("testuser", "test")
	require.True(t, resp.StatusCode == 204)

	resp, err := http.Get("http://localhost:3000/msgs?latest=45271")
	if err != nil{
		panic(err)
	}
	assert.True(t, resp.StatusCode == 200)

	var data struct {
		Latest int `json:"latest"`
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil{
		panic(err)
	}
	assert.True(t, data.Latest == 45271)
}

//Run the test script
func TestMinitwit(t *testing.T) {
    suite.Run(t, new(MinitwitTestSuite))
}