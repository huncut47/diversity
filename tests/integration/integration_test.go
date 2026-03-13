package integration

import (
	//"strings"
	//"testing"

	//"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"net/http"
	/* "net/http/httptest"
	"net/url" */

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

	DATABASE := suite.dbPath

	err = InitDB()
	suite.Require().NoError(err)

	suite.router = chi.NewRouter()
	suite.router.Use(middleware.Logger)
	suite.router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome"))
	})
}