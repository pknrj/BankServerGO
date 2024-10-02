package main

import (
	"encoding/json"
	"fmt"
	"os"
	"log"
	"net/http"
	"strconv"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

type APIServer struct {
	listenAdd string
	store Storage
}

func NewApiServer (listenAdd string , store Storage) *APIServer {
	return &APIServer{
		listenAdd : listenAdd,
		store: store ,
	}
}


func (s *APIServer) Run(){
	router := mux.NewRouter()
	
	router.HandleFunc("/login" , makeHttpHandleFunc(s.handleLogin))
	router.HandleFunc("/account" , makeHttpHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHttpHandleFunc(s.handleGetAccById), s.store))
	
	log.Println("Bank Server is running on port " , s.listenAdd)
	http.ListenAndServe(s.listenAdd , router)
}


func (s *APIServer) handleLogin(w http.ResponseWriter , r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed  %s" , r.Method)
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	acc , err := s.store.GetAccountByNumber(int(req.Number))
	if err != nil {
		return err 
	}

	if !acc.ValidPassword(req.Password) {
		return fmt.Errorf("invalid password or number")
	}

	token , err := createJWT(acc)
	if err != nil {
		return err 
	}

	resp := LoginResponse {
		Token: token,
		Number: acc.Number,
	}

	return WriteJson(w , http.StatusOK , resp)
}



func (s *APIServer) handleAccount(w http.ResponseWriter , r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w , r)
	}
	if r.Method == "POST" {
		return s.handleCreateAccount(w , r)
	}
	return fmt.Errorf("method not allowed %s " , r.Method)
}

func (s *APIServer) handleGetAccount(w http.ResponseWriter , r *http.Request) error {
	accounts , err := s.store.GetAccounts()
	if err != nil {
		return err 
	}
	return WriteJson(w , http.StatusOK , accounts)
}

func (s *APIServer) handleGetAccById(w http.ResponseWriter , r *http.Request) error{
	if r.Method == "GET" {
		idStr := mux.Vars(r)["id"]
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return fmt.Errorf("invalid id given %s", idStr)
		}
		acc , err := s.store.GetAccountByID(id)

		if err != nil {
			return err
		}
		return WriteJson(w , http.StatusOK , acc)
	}

	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w , r)
	}
	return fmt.Errorf("method not allowed %s " , r.Method)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter , r *http.Request) error {
	req := new(CreateAccountRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}
	account , err := NewAccount(req.FirstName , req.LastName , req.Password )
	if err != nil {
		return err
	}
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}
	resp := &CreateAccountResponse{
		Mssg: "Account created successfully",
		FirstName: account.FirstName,
		LastName : account.LastName,
		Number: account.Number,
		Balance: account.Balance,
		CreatedAt: account.CreatedAt,
	}
	return WriteJson(w , http.StatusOK , resp)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter , r *http.Request) error {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid id given %s", idStr)
	}
	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}
	return WriteJson(w , http.StatusOK , map[string]int {"account_deleted" : id})	 
}

func (s *APIServer) handleTransferAccount(w http.ResponseWriter , r *http.Request) error {
	return nil
}


func WriteJson(w http.ResponseWriter , status int , v any) error {
	w.Header().Add("Content-Type" , "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

type apiFunc func(http.ResponseWriter , *http.Request) error

type ApiError struct {
	Error string
}

func makeHttpHandleFunc(f apiFunc) http.HandlerFunc{
	return func(w http.ResponseWriter ,r *http.Request){
		if err := f(w , r); err != nil {
			WriteJson(w , http.StatusBadRequest , ApiError {
				Error: err.Error(),
			})
		}
	}
}

func permissionDenied(w http.ResponseWriter) {
	WriteJson(w , http.StatusForbidden , ApiError {Error: "permission denied"})
}

func createJWT(account *Account) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt":     15000,
		"accountNumber": account.Number,
	}

	privateKey := os.Getenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	fmt.Println("inside createJWT - token : " , token)
	return token.SignedString([]byte(privateKey))
}

func validateJWT(tokenString string) (*jwt.Token  , error){
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		privateKey := os.Getenv("JWT_SECRET")
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(privateKey), nil
	})
}

func withJWTAuth(handlerFunc http.HandlerFunc , s Storage)  http.HandlerFunc {
	return func (w http.ResponseWriter , r *http.Request) {
		fmt.Println("calling JWT auth middleware")
		tokenString := r.Header.Get("auth-token")

		fmt.Println("header : " , r.Header.Get("auth-token"))

		// if err := json.NewDecoder(r.Body).Decode(&tokenString); err != nil {
		// 	permissionDenied(w)
		// 	return
		// }
		token , err := validateJWT(tokenString)
		if err != nil {
			permissionDenied(w)
			return
		}
		if !token.Valid {
			permissionDenied(w) 
			return
		}

		idStr := mux.Vars(r)["id"]
		userID, err := strconv.Atoi(idStr)

		if err != nil {
			permissionDenied(w)
			return
		}
		account, err := s.GetAccountByID(userID)
		if err != nil {
			permissionDenied(w)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		if account.Number != int64(claims["accountNumber"].(float64)) {
			permissionDenied(w)
			return
		}

		handlerFunc(w, r)

	}	
}

