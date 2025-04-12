package main

import (
	"fmt"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/config"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/models"
	"github.com/RyseUp/uniqora-nft-marketplace/backend/internal/repositories"
	"log"
	"net/http"
)

func main() {
	cfg := config.Load()
	db, err := config.ConnectDatabase(cfg,
		&models.User{},
		&models.UserRegister{},
	)

	if err != nil {
		log.Fatalf("db: %v", err)
	}

	userRepo := repositories.NewUserStore(db)
	fmt.Println(userRepo)

	mux := http.NewServeMux()
	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", mux)
}
