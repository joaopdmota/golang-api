package main

import (
	"api/configs"
	"api/internal/entity"
	"api/internal/infra/database"
	"api/internal/infra/webserver/handlers"
	"fmt"
	"log"
	"net/http"

	_ "api/docs"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	httpSwagger "github.com/swaggo/http-swagger"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// @title           Go Expert API Example
// @version         1.0
// @description     Product API with auhtentication
// @termsOfService  http://swagger.io/terms/

// @contact.name   Wesley Willians
// @contact.url    http://www.fullcycle.com.br
// @contact.email  atendimento@fullcycle.com.br

// @license.name   Full Cycle License
// @license.url    http://www.fullcycle.com.br

// @host      localhost:8080
// @BasePath  /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	configs, err := configs.LoadConfig("../../")
	if err != nil {
		panic(err)
	}
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	productDB := database.NewProduct(db)
	productHandler := handlers.NewProductHandler(productDB)
	userDB := database.NewUser(db)
	userHandler := handlers.NewUserHandler(userDB)

	db.AutoMigrate(&entity.Product{}, &entity.User{})

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(LogRequest)
	r.Use(middleware.Recoverer)
	r.Use(middleware.WithValue("jwt", configs.TokenAuth))
	r.Use(middleware.WithValue("expiresIn", configs.JwtExperesIn))

	r.Route("/products", func(r chi.Router) {
		r.Use(jwtauth.Verifier(configs.TokenAuth))
		r.Use(jwtauth.Authenticator)
		r.Post("/", productHandler.CreateProduct)
		r.Get("/{id}", productHandler.GetProduct)
		r.Get("/", productHandler.GetProducts)
		r.Put("/{id}", productHandler.UpdateProduct)
		r.Delete("/{id}", productHandler.DeleteProduct)
	})

	r.Get("/docs/*", httpSwagger.Handler(httpSwagger.URL("http://localhost:8080/docs/doc.json")))
	r.Post("/users", userHandler.CreateUser)
	r.Post("/users/generate_token", userHandler.GetJwt)
	fmt.Println("Running on port 8080...")
	http.ListenAndServe(":8080", r)
}

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %v", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
