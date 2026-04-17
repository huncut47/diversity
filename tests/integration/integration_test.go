package testing

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"minitwit/internal/models"
	"minitwit/internal/utils"
	"minitwit/internal/web"

	"github.com/go-chi/chi/v5"
)

// Test suite type framework
type MinitwitTestSuite struct {
	suite.Suite
	router *chi.Mux
	dbFile *os.File
	dbPath string
	app    web.App
	server *http.Server
	sqlDB  *sql.DB
}

const apiAuth = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

var funcMap = template.FuncMap{
	"gravatar": utils.GravatarURL,
	"datetime": utils.FormatDate,
}

func loadTemplate(files ...string) *template.Template {
	return template.Must(template.New("").Funcs(funcMap).ParseFiles(files...))
}

func (suite *MinitwitTestSuite) waitForServer(url string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			err = resp.Body.Close()
			if err != nil {
				panic(err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	panic("server not ready after timeout")
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

	err = db.AutoMigrate(&models.User{}, &models.Message{}, &models.Follower{}, &models.AppState{})
	suite.Require().NoError(err)

	suite.app = web.App{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DB:     db,
		Store: sessions.NewCookieStore(
			[]byte(os.Getenv("SESSION_AUTH_KEY")),
			[]byte(os.Getenv("SESSION_ENCRYPTION_KEY")),
		),
		Pages: map[string]*template.Template{
			"register": loadTemplate("../../templates/layout.html", "../../templates/register.html"),
			"login":    loadTemplate("../../templates/layout.html", "../../templates/login.html"),
			"timeline": loadTemplate("../../templates/layout.html", "../../templates/timeline.html"),
		},
	}

	suite.router = suite.app.NewRouter().(*chi.Mux)

	suite.server = &http.Server{
		Addr:    ":3000",
		Handler: suite.router,
	}

	errCh := make(chan error, 1)

	go func() {
		if err := suite.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server failed: %w", err)
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			suite.T().Fatal(err)
		}
	case <-time.After(time.Second):
	}

	suite.waitForServer("http://localhost:3000", 2*time.Second)
}

// Tear down after each test
func (suite *MinitwitTestSuite) TearDownTest() {
	if suite.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := suite.server.Shutdown(ctx); err != nil {
			suite.T().Fatalf("Server shutdown failed: %v", err)
		}
	}

	if suite.sqlDB != nil {
		err := suite.sqlDB.Close()
		if err != nil {
			panic(err)
		}
	}

	if suite.dbFile != nil {
		err := os.Remove(suite.dbPath)
		if err != nil {
			panic(err)
		}
	}
}

// Helper functions
func (suite *MinitwitTestSuite) DecodeBodyToString(r *http.Response) string {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	bodyString := string(bodyBytes)
	return bodyString
}

func (suite *MinitwitTestSuite) CallRegisterAPI(username string) *http.Response {
	jsonStr := []byte(fmt.Sprintf(`{"username": "%s","email":"%s@example.com","pwd":"%spass"}`, username, username, username))
	req, err := http.NewRequest("POST", "http://localhost:3000/register", bytes.NewBuffer(jsonStr))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	return resp
}

func (suite *MinitwitTestSuite) PostMessage(username string, msg string) *http.Response {
	jsonStr := []byte(fmt.Sprintf(`{"content": "%s"}`, msg))
	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:3000/msgs/%s", username), bytes.NewBuffer(jsonStr))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	return resp
}

// Tests
func (suite *MinitwitTestSuite) TestRegisterAPI() {
	t := suite.T()
	resp := suite.CallRegisterAPI("testuser")
	assert.True(t, resp.StatusCode == 204)

	resp, err := http.Get("http://localhost:3000/testuser")
	if err != nil {
		panic(err)
	}
	require.False(t, resp.StatusCode == 404)
}

func (suite *MinitwitTestSuite) TestMsgsUser() {
	t := suite.T()
	resp := suite.CallRegisterAPI("testuser")
	require.True(t, resp.StatusCode == 204)

	// Test POST
	resp = suite.PostMessage("testuser", "this is a test message")
	assert.True(t, resp.StatusCode == 204)

	// Test GET
	req, err := http.NewRequest("GET", "http://localhost:3000/testuser", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	responseBody := suite.DecodeBodyToString(resp)
	assert.Contains(t, responseBody, "this is a test message")
	assert.True(t, resp.StatusCode == 200)
}

func (suite *MinitwitTestSuite) TestFllwsUser() {
	t := suite.T()
	resp := suite.CallRegisterAPI("user1")
	require.True(t, resp.StatusCode == 204)
	resp = suite.CallRegisterAPI("user2")
	require.True(t, resp.StatusCode == 204)

	// Test POST Follow:
	jsonStr := []byte(`{"follow":"user2"}`)
	req, err := http.NewRequest("POST", "http://localhost:3000/fllws/user1", bytes.NewBuffer(jsonStr))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	assert.True(t, resp.StatusCode == 204)

	// Test GET
	req, err = http.NewRequest("GET", "http://localhost:3000/fllws/user1", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	var data struct {
		Follows []string `json:"follows"`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		panic(err)
	}
	assert.Contains(t, data.Follows, "user2")

	// Test POST Unfollow
	jsonStr = []byte(`{"unfollow":"user2"}`)
	req, err = http.NewRequest("POST", "http://localhost:3000/fllws/user1", bytes.NewBuffer(jsonStr))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	assert.True(t, resp.StatusCode == 204)

	req, err = http.NewRequest("GET", "http://localhost:3000/fllws/user1", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		panic(err)
	}
	assert.NotContains(t, data.Follows, "user2")
}

func (suite *MinitwitTestSuite) TestMsgs() {
	t := suite.T()
	resp := suite.CallRegisterAPI("testuser")
	require.True(t, resp.StatusCode == 204)

	resp = suite.PostMessage("testuser", "message1")
	assert.True(t, resp.StatusCode == 204)
	resp = suite.PostMessage("testuser", "message2")
	assert.True(t, resp.StatusCode == 204)
	resp = suite.PostMessage("testuser", "message3")
	assert.True(t, resp.StatusCode == 204)

	req, err := http.NewRequest("GET", "http://localhost:3000/msgs", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	assert.True(t, resp.StatusCode == 200)
	bodyText := suite.DecodeBodyToString(resp)
	assert.Contains(t, bodyText, "message1")
	assert.Contains(t, bodyText, "message2")
	assert.Contains(t, bodyText, "message3")
}

func (suite *MinitwitTestSuite) TestLatest() {
	t := suite.T()
	resp := suite.CallRegisterAPI("testuser")
	require.True(t, resp.StatusCode == 204)
	resp = suite.PostMessage("testuser", "test")
	require.True(t, resp.StatusCode == 204)

	req, err := http.NewRequest("GET", "http://localhost:3000/msgs?latest=45271", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	assert.True(t, resp.StatusCode == 200)

	var data struct {
		Latest int `json:"latest"`
	}

	req, err = http.NewRequest("GET", "http://localhost:3000/latest", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiAuth)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	assert.True(t, resp.StatusCode == 200)

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		panic(err)
	}
	assert.True(t, data.Latest == 45271)
}

// Run the test script
func TestMinitwit(t *testing.T) {
	suite.Run(t, new(MinitwitTestSuite))
}
