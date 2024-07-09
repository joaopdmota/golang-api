package handlers

import (
	"api/internal/dto"
	"api/internal/entity"
	"api/internal/infra/database"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth"
)

type UserHandler struct {
	UserDB       database.UserDBIntercace
	Jwt          *jwtauth.JWTAuth
	JwtExpiresIn int
}

func NewUserHandler(db database.UserDBIntercace) *UserHandler {
	return &UserHandler{
		UserDB: db,
	}
}

// GetJWT godoc
// @Summary      Get a user JWT
// @Description  Get a user JWT
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        request   body     dto.GetJwtInput  true  "user credentials"
// @Success      200  {object}  dto.GetJwtOutput
// @Failure      404  {object}  dto.Error
// @Failure      500  {object}  dto.Error
// @Router       /users/generate_token [post]
func (h *UserHandler) GetJwt(w http.ResponseWriter, r *http.Request) {
	jwt := r.Context().Value("jwt").(*jwtauth.JWTAuth)
	jwtExpiresIn := r.Context().Value("expiresIn").(int)

	var jwtInput dto.GetJwtInput
	err := json.NewDecoder(r.Body).Decode(&jwtInput)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	u, err := h.UserDB.FindByEmail(jwtInput.Email)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		err := dto.Error{Message: err.Error()}
		json.NewEncoder(w).Encode(err)
		return
	}
	if !u.ValidatePassword((jwtInput.Password)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, tokenString, _ := jwt.Encode(map[string]interface{}{
		"sub": u.ID.String(),
		"exp": time.Now().Add(time.Second * time.Duration(jwtExpiresIn)).Unix(),
	})

	accessToken := dto.GetJwtOutput{
		AccessToken: tokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(accessToken)
}

// Create user godoc
// @Summary      Create user
// @Description  Create user
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        request     body      dto.CreateUserInput  true  "user request"
// @Success      201
// @Failure      500         {object}  dto.Error
// @Router       /users [post]
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user dto.CreateUserInput
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	u, err := entity.NewUser(user.Name, user.Email, user.Password)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		error := dto.Error{Message: err.Error()}
		json.NewEncoder(w).Encode(error)
		return
	}
	err = h.UserDB.Create(u)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		error := dto.Error{Message: err.Error()}
		json.NewEncoder(w).Encode(error)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
