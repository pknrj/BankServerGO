package main

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)


type LoginRequest struct {
	Number   int64  `json:"number"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Number int64  `json:"number"`
	Token  string `json:"token"`
}

// type TransferRequest struct {
// 	ToAccount int `json:"toAccount"`
// 	Amount    int `json:"amount"`
// }

type CreateAccountRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
}

type CreateAccountResponse struct {
	Mssg string  			`json:"msg"`
	FirstName  	string      `json:"firstName"`
	LastName  	string      `json:"lastName"`
	Number 		int64       `json:"number"`
	Balance 	int64       `json:"balance"`
	CreatedAt	time.Time   `json:"createdAt"`
}

type Account struct {
	ID  		int 		`json:"id"`
	FirstName  	string      `json:"firstName"`
	LastName  	string      `json:"lastName"`
	Number 		int64       `json:"number"`
	EncryptedPassword string`json:"-"`
	Balance 	int64       `json:"balance"`
	CreatedAt	time.Time   `json:"createdAt"`
}

func NewAccount (FirstName , LastName , password string) (*Account , error){
	
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return nil, err
	}

	return &Account{
   		FirstName: FirstName , 
		LastName: LastName , 
		Number: int64(rand.Intn(1000000)),
		EncryptedPassword : string(encpw) ,
		CreatedAt: time.Now(),
	} , nil
}


func (a *Account) ValidPassword(pass string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.EncryptedPassword), []byte(pass)) == nil
}