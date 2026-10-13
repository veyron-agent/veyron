package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// provider base url's
var (
	GroqBaseURL       string = "https://api.groq.com/openai/v1"
	OpenrouterBaseURL string = "https://openrouter.ai/api/v1"
)

var (
	DB_URL     string
	JWT_SECRET string
)

func Init() {

	err := godotenv.Load()

	if err != nil {
		fmt.Println("load .env file error")
		fmt.Println(err)
		os.Exit(1)
	}

	DB_URL = os.Getenv("DB_URL")

	if DB_URL == "" {
		fmt.Println("DB_URL is not set in .env")
		os.Exit(1)
	}

	JWT_SECRET = os.Getenv("JWT_SECRET")

	if JWT_SECRET == "" {
		fmt.Println("JWT_SECRET is not set in .env")
		os.Exit(1)
	}

}
